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

    /// Run the full test suite
    Test {
        /// Run ignored (integration) tests
        #[arg(short, long)]
        ignored: bool,

        /// Run only unit tests
        #[arg(short, long)]
        unit: bool,
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
        Commands::Test { ignored, unit } => cmd_test(ignored, unit),
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

    let mut args = vec![
        "compose",
        "-f",
        "docker-compose.dev.yml",
    ];

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
    run_command_interactive(
        "docker",
        &["exec", "-it", "harborshield-dev", "bash"],
    )?;
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

fn cmd_test(ignored: bool, unit: bool) -> Result<()> {
    let mut args = vec!["test"];

    if unit {
        args.push("--lib");
        println!("Running unit tests...");
    } else if ignored {
        args.extend(["--", "--ignored"]);
        println!("Running integration tests...");
    } else {
        println!("Running all tests...");
    }

    run_command("cargo", &args)?;
    Ok(())
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
    let _ = run_command_silent(
        "docker",
        &["compose", "-f", "docker-compose.dev.yml", "down"],
    );

    println!("==> Rebuilding and starting...");
    run_command(
        "docker",
        &["compose", "-f", "docker-compose.dev.yml", "up", "--build", "-d"],
    )?;

    println!("\nDev container restarted!");
    println!("Reconnect in Zed: Cmd+Shift+P -> 'Connect to Remote Server via SSH' -> harborshield-dev");
    Ok(())
}

fn cmd_clean(volumes: bool) -> Result<()> {
    println!("Cleaning up Docker resources...");
    let mut args = vec!["compose", "-f", "docker-compose.dev.yml", "down"];
    if volumes {
        args.push("-v");
    }
    run_command("docker", &args)?;

    // Also clean up any orphaned harborshield containers
    let _ = run_command_silent(
        "docker",
        &["rm", "-f", "harborshield-dev", "test-nginx"],
    );

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
    let entry_exists = if let Ok(file) = fs::File::open(&ssh_config_path) {
        let reader = BufReader::new(file);
        reader
            .lines()
            .any(|line| line.map(|l| l.contains("Host harborshield-dev")).unwrap_or(false))
    } else {
        false
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
