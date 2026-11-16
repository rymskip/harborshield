use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, ExitStatus, Stdio};

#[derive(Parser)]
#[command(name = "xtask", about = "HarborShield development tasks")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start dev container (for macOS development)
    Dev {
        /// Rebuild the Docker image
        #[arg(short, long)]
        build: bool,

        /// Run with test containers
        #[arg(short, long)]
        test: bool,
    },

    /// Open a shell in the dev container
    Shell,

    /// Build and run harborshield inside the dev container
    Run {
        /// Build in release mode
        #[arg(short, long)]
        release: bool,

        /// Use cargo-watch to auto-rebuild on changes
        #[arg(short, long)]
        watch: bool,
    },

    /// Run the tests that need no privileges (unit tests and the e2e crate's build)
    Test {
        /// Run only unit tests
        #[arg(short, long)]
        unit: bool,
    },

    /// Run the end-to-end suite, and the privileged unit tests, in a Docker-in-Docker sandbox
    E2e {
        /// Run only e2e tests whose name contains this filter (skips the privileged unit tests)
        filter: Option<String>,

        /// Docker's firewall backend inside the sandbox
        #[arg(long, value_enum, default_value_t = FirewallBackend::Iptables)]
        backend: FirewallBackend,

        /// Run the sandbox's dockerd without docker-proxy
        #[arg(long)]
        no_userland_proxy: bool,

        /// Run every backend and proxy combination, reporting all failures at the end
        #[arg(long, conflicts_with_all = ["backend", "no_userland_proxy"])]
        matrix: bool,
    },

    /// Check code quality (fmt, clippy, test)
    Check {
        /// Auto-fix issues where possible
        #[arg(short, long)]
        fix: bool,
    },

    /// Build release binary
    Build {
        /// Build for Linux (cross-compile)
        #[arg(short, long)]
        linux: bool,
    },

    /// Stop all dev containers
    Stop,

    /// Restart dev container (rebuilds image)
    Restart,

    /// Clean up Docker resources
    Clean {
        /// Also remove volumes
        #[arg(short, long)]
        volumes: bool,
    },

    /// Run database migrations
    Migrate,

    /// Generate SQL query cache for offline builds
    SqlxPrepare,

    /// Setup SSH config for Zed remote development
    SetupZed,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Dev { build, test } => cmd_dev(build, test),
        Commands::Shell => cmd_shell(),
        Commands::Run { release, watch } => cmd_run(release, watch),
        Commands::Test { unit } => cmd_test(unit),
        Commands::E2e {
            filter,
            backend,
            no_userland_proxy,
            matrix,
        } => {
            let modes = if matrix {
                SandboxMode::all()
            } else {
                vec![SandboxMode {
                    backend,
                    userland_proxy: !no_userland_proxy,
                }]
            };
            cmd_e2e(filter.as_deref(), &modes)
        }
        Commands::Check { fix } => cmd_check(fix),
        Commands::Build { linux } => cmd_build(linux),
        Commands::Stop => cmd_stop(),
        Commands::Restart => cmd_restart(),
        Commands::Clean { volumes } => cmd_clean(volumes),
        Commands::Migrate => cmd_migrate(),
        Commands::SqlxPrepare => cmd_sqlx_prepare(),
        Commands::SetupZed => cmd_setup_zed(),
    }
}

fn cmd_dev(build: bool, test: bool) -> Result<()> {
    println!("Starting development environment...");

    let mut args = vec!["compose", "-f", "docker-compose.dev.yml"];

    if test {
        args.extend(["--profile", "test"]);
    }

    args.push("up");

    if build {
        args.push("--build");
    }

    // Always run detached - use `cargo xtask shell` to interact
    args.push("-d");

    run_command("docker", &args)?;

    println!("\nDev container started!");
    println!("  - Open a shell:  cargo xtask shell");
    println!("  - Build and run: cargo xtask run");
    println!("  - Stop:          cargo xtask stop");
    Ok(())
}

fn cmd_shell() -> Result<()> {
    println!("Opening shell in dev container...");
    run_command_interactive("docker", &["exec", "-it", "harborshield-dev", "bash"])?;
    Ok(())
}

fn cmd_run(release: bool, watch: bool) -> Result<()> {
    let cmd = if watch {
        println!("Starting harborshield with auto-reload...");
        if release {
            "cargo watch -x 'build --release' -s './target/release/harborshield --data-dir /data --debug'"
        } else {
            "cargo watch -x 'build' -s './target/debug/harborshield --data-dir /data --debug'"
        }
    } else {
        println!("Building and running harborshield...");
        if release {
            "cargo build --release && ./target/release/harborshield --data-dir /data --debug"
        } else {
            "cargo build && ./target/debug/harborshield --data-dir /data --debug"
        }
    };

    run_command_interactive(
        "docker",
        &["exec", "-it", "harborshield-dev", "bash", "-c", cmd],
    )?;
    Ok(())
}

fn cmd_test(unit: bool) -> Result<()> {
    let mut args = vec!["test"];

    if unit {
        args.push("--lib");
        println!("Running unit tests...");
    } else {
        println!("Running all tests...");
    }

    run_command("cargo", &args)?;
    Ok(())
}

const E2E_SANDBOX_IMAGE: &str = "harborshield-e2e-sandbox";
const E2E_SANDBOX_LABEL: &str = "harborshield.e2e.sandbox";
const E2E_DOCKER_VOLUME: &str = "harborshield-e2e-docker";

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum FirewallBackend {
    Iptables,
    Nftables,
}

impl FirewallBackend {
    fn as_str(self) -> &'static str {
        match self {
            Self::Iptables => "iptables",
            Self::Nftables => "nftables",
        }
    }
}

/// How the sandbox's dockerd manages its firewall and published ports.
#[derive(Clone, Copy, Debug)]
struct SandboxMode {
    backend: FirewallBackend,
    userland_proxy: bool,
}

impl SandboxMode {
    fn all() -> Vec<Self> {
        [FirewallBackend::Iptables, FirewallBackend::Nftables]
            .into_iter()
            .flat_map(|backend| {
                [true, false].map(|userland_proxy| Self {
                    backend,
                    userland_proxy,
                })
            })
            .collect()
    }

    fn label(self) -> String {
        let proxy = if self.userland_proxy {
            "proxy"
        } else {
            "no-proxy"
        };
        format!("{}-{proxy}", self.backend.as_str())
    }
}

/// The last release that kept its rules in Docker's `ip filter` table; the upgrade test runs
/// it before the current build.
const LEGACY_REVISION: &str = "1f7e8e2";

/// Build the test binaries on the host, then run them inside a privileged sandbox with its
/// own dockerd and network namespace, once per mode, so the suite never touches the host
/// firewall. Every mode runs even when an earlier one fails.
fn cmd_e2e(filter: Option<&str>, modes: &[SandboxMode]) -> Result<()> {
    let root = project_root();
    let root_str = root
        .to_str()
        .context("project root path is not UTF-8")?
        .to_owned();

    // The sandbox's image cache volume cannot be shared by two dockerds.
    let running = Command::new("docker")
        .args([
            "ps",
            "--quiet",
            "--filter",
            &format!("label={E2E_SANDBOX_LABEL}"),
        ])
        .output()
        .context("Failed to list running e2e sandboxes")?;
    if !running.status.success() {
        anyhow::bail!(
            "docker ps failed: {}",
            String::from_utf8_lossy(&running.stderr).trim()
        );
    }
    if !running.stdout.is_empty() {
        anyhow::bail!("another e2e sandbox is already running; wait for it to finish");
    }

    println!("==> Building test binaries...");
    let (unit_exe, e2e_exe) = build_test_binaries()?;

    println!("\n==> Building the previous release ({LEGACY_REVISION}) for the upgrade test...");
    let legacy_bin = build_legacy_binary(&root)?;

    println!("\n==> Building sandbox image...");
    let images = format!("{root_str}/tests/e2e/images");
    run_command(
        "docker",
        &[
            "build",
            "--quiet",
            "--tag",
            E2E_SANDBOX_IMAGE,
            "--file",
            &format!("{images}/sandbox.Dockerfile"),
            &images,
        ],
    )?;

    let e2e_dir = root.join("target").join("e2e");
    let logs_root = e2e_dir.join("logs");
    if logs_root.exists() {
        fs::remove_dir_all(&logs_root)
            .with_context(|| format!("Failed to reset {}", logs_root.display()))?;
    }
    let e2e_dir = e2e_dir.to_str().context("e2e dir is not UTF-8")?.to_owned();
    let owner = invoking_owner()?;

    let mut failed = Vec::new();
    for mode in modes {
        let log_dir = logs_root.join(mode.label());
        fs::create_dir_all(&log_dir)
            .with_context(|| format!("Failed to create {}", log_dir.display()))?;
        let log_dir = log_dir.to_str().context("log dir is not UTF-8")?.to_owned();

        // Run the privileged unit tests, then the e2e suite; report failure if either failed.
        let script = r#"unit=0
if [ -n "$1" ]; then "$1" --ignored --test-threads=1 || unit=$?; fi
shift
"$@" || exit $?
exit "$unit""#;
        let unit_arg = if filter.is_some() {
            String::new()
        } else {
            unit_exe.clone()
        };
        let mut args = vec![
            "run".to_owned(),
            "--rm".to_owned(),
            "--privileged".to_owned(),
            "--name".to_owned(),
            format!("harborshield-e2e-{}", std::process::id()),
            "--label".to_owned(),
            E2E_SANDBOX_LABEL.to_owned(),
            // Docker disables IPv6 in containers on IPv4-only networks; the inner dockerd needs
            // it for the dual-stack scenarios.
            "--sysctl".to_owned(),
            "net.ipv6.conf.all.disable_ipv6=0".to_owned(),
            "--sysctl".to_owned(),
            "net.ipv6.conf.default.disable_ipv6=0".to_owned(),
            "--volume".to_owned(),
            format!("{root_str}:{root_str}:ro"),
            "--volume".to_owned(),
            format!("{e2e_dir}:{e2e_dir}"),
            "--volume".to_owned(),
            format!("{E2E_DOCKER_VOLUME}:/var/lib/docker"),
            "--env".to_owned(),
            format!("HARBORSHIELD_E2E_LOG_DIR={log_dir}"),
            "--env".to_owned(),
            format!("HARBORSHIELD_E2E_IMAGES={images}"),
            "--env".to_owned(),
            format!("HARBORSHIELD_E2E_OWNER={owner}"),
            "--env".to_owned(),
            format!(
                "HARBORSHIELD_E2E_FIREWALL_BACKEND={}",
                mode.backend.as_str()
            ),
            "--env".to_owned(),
            format!("HARBORSHIELD_E2E_USERLAND_PROXY={}", mode.userland_proxy),
            "--env".to_owned(),
            format!("HARBORSHIELD_E2E_LEGACY_BIN={legacy_bin}"),
            "--env".to_owned(),
            "RUST_BACKTRACE=1".to_owned(),
            "--workdir".to_owned(),
            root_str.clone(),
            E2E_SANDBOX_IMAGE.to_owned(),
            "sh".to_owned(),
            "-c".to_owned(),
            script.to_owned(),
            "sh".to_owned(),
            unit_arg,
            e2e_exe.clone(),
            "--ignored".to_owned(),
            "--test-threads=1".to_owned(),
        ];
        if let Some(filter) = filter {
            args.push(filter.to_owned());
        }

        println!(
            "\n==> Running in sandbox, {} (logs: {log_dir})...",
            mode.label()
        );
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        if let Err(failure) = run_command("docker", &borrowed) {
            println!("==> {} failed: {failure}", mode.label());
            failed.push(mode.label());
        }
    }

    if failed.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("e2e failed in: {}", failed.join(", "))
    }
}

/// Build the previous release from git, cached under target/e2e, and return its binary.
fn build_legacy_binary(root: &std::path::Path) -> Result<String> {
    let source = root.join("target").join("e2e").join("legacy-src");
    let target_dir = root.join("target").join("e2e").join("legacy-target");
    if !source.join("Cargo.toml").exists() {
        fs::create_dir_all(&source)
            .with_context(|| format!("Failed to create {}", source.display()))?;
        let archive = Command::new("git")
            .args(["archive", "--format=tar", LEGACY_REVISION])
            .current_dir(root)
            .output()
            .context("Failed to run git archive")?;
        if !archive.status.success() {
            anyhow::bail!(
                "git archive {LEGACY_REVISION} failed: {}",
                String::from_utf8_lossy(&archive.stderr).trim()
            );
        }
        let mut tar = Command::new("tar")
            .arg("-x")
            .arg("-C")
            .arg(&source)
            .stdin(Stdio::piped())
            .spawn()
            .context("Failed to run tar")?;
        tar.stdin
            .take()
            .context("tar has no stdin")?
            .write_all(&archive.stdout)
            .context("Failed to feed the archive to tar")?;
        let status = tar.wait().context("Failed to wait for tar")?;
        if !status.success() {
            anyhow::bail!("tar failed with {status}");
        }
    }
    let status = Command::new("cargo")
        .args(["build", "--bin", "harborshield"])
        .current_dir(&source)
        .env("CARGO_TARGET_DIR", &target_dir)
        .env("SQLX_OFFLINE", "true")
        .status()
        .context("Failed to build the previous release")?;
    if !status.success() {
        anyhow::bail!("building the previous release failed with {status}");
    }
    target_dir
        .join("debug")
        .join("harborshield")
        .to_str()
        .context("legacy binary path is not UTF-8")
        .map(str::to_owned)
}

/// `uid:gid` of the user running xtask, so the root sandbox can hand its logs back.
fn invoking_owner() -> Result<String> {
    let id = |flag: &str| -> Result<String> {
        let output = Command::new("id")
            .arg(flag)
            .output()
            .with_context(|| format!("Failed to run id {flag}"))?;
        if !output.status.success() {
            anyhow::bail!("id {flag} failed with {}", output.status);
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    };
    Ok(format!("{}:{}", id("-u")?, id("-g")?))
}

/// Compile the library unit tests and the e2e crate, returning both executables.
fn build_test_binaries() -> Result<(String, String)> {
    let output = Command::new("cargo")
        .args([
            "test",
            "--lib",
            "--test",
            "e2e",
            "--no-run",
            "--message-format=json-render-diagnostics",
        ])
        .current_dir(project_root())
        .stderr(Stdio::inherit())
        .output()
        .context("Failed to run cargo test --no-run")?;
    if !output.status.success() {
        anyhow::bail!("building the test binaries failed with {}", output.status);
    }

    let mut unit = None;
    let mut e2e = None;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let message: CargoMessage = serde_json::from_str(line)
            .with_context(|| format!("cargo printed a non-JSON message: {line}"))?;
        let (Some(target), Some(executable)) = (message.target, message.executable) else {
            continue;
        };
        if target.kind.iter().any(|kind| kind == "test") && target.name == "e2e" {
            e2e = Some(executable);
        } else if target.kind.iter().any(|kind| kind == "lib") && target.name == "harborshield" {
            unit = Some(executable);
        }
    }
    Ok((
        unit.context("cargo reported no unit test executable")?,
        e2e.context("cargo reported no e2e executable")?,
    ))
}

/// The fields of a cargo JSON message needed to find test executables; other message kinds and
/// fields are ignored on purpose.
#[derive(serde::Deserialize)]
struct CargoMessage {
    target: Option<CargoTarget>,
    executable: Option<String>,
}

#[derive(serde::Deserialize)]
struct CargoTarget {
    name: String,
    kind: Vec<String>,
}

fn cmd_check(fix: bool) -> Result<()> {
    println!("Checking code quality...\n");

    // Format check
    println!("==> Checking formatting...");
    if fix {
        run_command("cargo", &["fmt"])?;
    } else {
        run_command("cargo", &["fmt", "--check"])?;
    }

    // Clippy
    println!("\n==> Running clippy...");
    let mut clippy_args = vec!["clippy", "--all-targets", "--all-features"];
    if fix {
        clippy_args.extend(["--fix", "--allow-dirty"]);
    }
    clippy_args.extend(["--", "-D", "warnings"]);
    run_command("cargo", &clippy_args)?;

    // Tests
    println!("\n==> Running tests...");
    run_command("cargo", &["test"])?;

    println!("\nAll checks passed!");
    Ok(())
}

fn cmd_build(linux: bool) -> Result<()> {
    if linux {
        println!("Building for Linux (x86_64)...");
        println!("Note: Requires `rustup target add x86_64-unknown-linux-gnu`");
        run_command(
            "cargo",
            &["build", "--release", "--target", "x86_64-unknown-linux-gnu"],
        )?;
        println!("\nBinary at: target/x86_64-unknown-linux-gnu/release/harborshield");
    } else {
        println!("Building release binary...");
        run_command("cargo", &["build", "--release"])?;
        println!("\nBinary at: target/release/harborshield");
    }
    Ok(())
}

fn cmd_stop() -> Result<()> {
    println!("Stopping dev containers...");
    run_command(
        "docker",
        &["compose", "-f", "docker-compose.dev.yml", "down"],
    )?;
    Ok(())
}

fn cmd_restart() -> Result<()> {
    println!("Restarting dev container...\n");

    println!("==> Stopping...");
    // Nothing to stop is fine; the rebuild below reports any real problem.
    if let Err(failure) = run_command_silent(
        "docker",
        &["compose", "-f", "docker-compose.dev.yml", "down"],
    ) {
        println!("    (stop skipped: {failure})");
    }

    println!("==> Rebuilding and starting...");
    run_command(
        "docker",
        &[
            "compose",
            "-f",
            "docker-compose.dev.yml",
            "up",
            "--build",
            "-d",
        ],
    )?;

    println!("\nDev container restarted!");
    println!(
        "Reconnect in Zed: Cmd+Shift+P -> 'Connect to Remote Server via SSH' -> harborshield-dev"
    );
    Ok(())
}

fn cmd_clean(volumes: bool) -> Result<()> {
    println!("Cleaning up Docker resources...");
    let mut args = vec!["compose", "-f", "docker-compose.dev.yml", "down"];
    if volumes {
        args.push("-v");
    }
    run_command("docker", &args)?;

    // Also clean up any orphaned harborshield containers; absent ones are fine.
    match run_command_silent("docker", &["rm", "-f", "harborshield-dev", "test-nginx"]) {
        Ok(status) if !status.success() => println!("    (no orphaned containers to remove)"),
        Ok(_) => {}
        Err(failure) => println!("    (orphan cleanup skipped: {failure})"),
    }

    println!("Cleanup complete.");
    Ok(())
}

fn cmd_migrate() -> Result<()> {
    println!("Running database migrations...");
    run_command("cargo", &["sqlx", "migrate", "run"])?;
    Ok(())
}

fn cmd_sqlx_prepare() -> Result<()> {
    println!("Generating SQLx query cache...");
    run_command("cargo", &["sqlx", "prepare"])?;
    println!("\nSQLx cache generated in .sqlx/");
    Ok(())
}

fn cmd_setup_zed() -> Result<()> {
    println!("Setting up SSH config for Zed remote development...\n");

    let ssh_config_entry = r#"
# HarborShield dev container
Host harborshield-dev
    HostName localhost
    Port 2222
    User root
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
"#;

    let home = std::env::var("HOME").context("Could not find HOME directory")?;
    let ssh_dir = format!("{}/.ssh", home);
    let ssh_config_path = format!("{}/config", ssh_dir);

    // Ensure .ssh directory exists
    fs::create_dir_all(&ssh_dir).context("Failed to create .ssh directory")?;

    // Check if entry already exists
    let entry_exists = match fs::File::open(&ssh_config_path) {
        Ok(file) => {
            let mut found = false;
            for line in BufReader::new(file).lines() {
                let line = line.with_context(|| format!("Failed to read {ssh_config_path}"))?;
                if line.contains("Host harborshield-dev") {
                    found = true;
                    break;
                }
            }
            found
        }
        Err(failure) if failure.kind() == std::io::ErrorKind::NotFound => false,
        Err(failure) => {
            return Err(failure).with_context(|| format!("Failed to open {ssh_config_path}"));
        }
    };

    if entry_exists {
        println!("SSH config entry already exists in ~/.ssh/config");
    } else {
        // Append to config file
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&ssh_config_path)
            .context("Failed to open ~/.ssh/config")?;

        file.write_all(ssh_config_entry.as_bytes())
            .context("Failed to write to ~/.ssh/config")?;

        println!("Added SSH config entry to ~/.ssh/config");
    }

    println!("\nSetup complete! To connect with Zed:");
    println!("  1. Start the dev container:  cargo xtask dev --build");
    println!("  2. In Zed: Cmd+Shift+P -> 'Connect to Remote Server via SSH'");
    println!("  3. Enter: harborshield-dev");
    println!("  4. Password: dev");
    println!("  5. Open folder: /app");
    println!("\nRust-analyzer will use the container's Linux toolchain.");

    Ok(())
}

fn run_command(cmd: &str, args: &[&str]) -> Result<ExitStatus> {
    let status = Command::new(cmd)
        .args(args)
        .current_dir(project_root())
        .status()
        .with_context(|| format!("Failed to run: {} {}", cmd, args.join(" ")))?;

    if !status.success() {
        anyhow::bail!("Command failed with status: {}", status);
    }

    Ok(status)
}

fn run_command_interactive(cmd: &str, args: &[&str]) -> Result<ExitStatus> {
    let status = Command::new(cmd)
        .args(args)
        .current_dir(project_root())
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("Failed to run: {} {}", cmd, args.join(" ")))?;

    Ok(status)
}

fn run_command_silent(cmd: &str, args: &[&str]) -> Result<ExitStatus> {
    let status = Command::new(cmd)
        .args(args)
        .current_dir(project_root())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("Failed to run: {} {}", cmd, args.join(" ")))?;

    Ok(status)
}

fn project_root() -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // Go up from xtask/ to project root
    path
}
