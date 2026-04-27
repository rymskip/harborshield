use bon::bon;
use nix::libc;
use std::collections::HashMap;
use std::io::BufRead;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

#[derive(Debug, Clone)]
pub struct Container {
    pub id: String,
    pub name: String,
    pub ip_address: Option<String>, // TODO: Remove this once all code is migrated to use networks
    pub networks: HashMap<String, ContainerNetwork>,
    pub state: String,
    pub labels: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct ContainerNetwork {
    pub name: String,
    pub ip_address: String,
}

#[derive(Debug, Clone)]
pub struct Network {
    pub id: String,
    pub name: String,
    pub subnet: Option<String>,
    pub gateway: Option<String>,
}

pub struct TestEnvironment {
    compose_file: PathBuf,
    project_name: String,
    temp_dir: Arc<TempDir>,
    db_path: PathBuf,
    harborshield_process: Option<std::process::Child>,
    test_name: String,
    verdict_chains: Vec<String>,
    /// `127.0.0.1:<port>` where harborshield's --health-server is bound for this test.
    /// Used to poll readiness instead of fixed sleeps.
    health_addr: Option<String>,
}

impl Clone for TestEnvironment {
    fn clone(&self) -> Self {
        Self {
            compose_file: self.compose_file.clone(),
            project_name: self.project_name.clone(),
            temp_dir: self.temp_dir.clone(),
            db_path: self.db_path.clone(),
            harborshield_process: None,
            test_name: self.test_name.clone(),
            verdict_chains: self.verdict_chains.clone(),
            health_addr: self.health_addr.clone(),
        }
    }
}

/// Block on an async future from sync test setup code, using a temporary tokio runtime.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime for readiness probe")
        .block_on(future)
}

#[bon]
impl TestEnvironment {
    #[builder]
    pub fn new(
        compose_file: Option<PathBuf>,
        start_harborshield: bool,
        restart_harborshield: Option<bool>,
        test_name: Option<String>,
        verdict_chains: Option<Vec<String>>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Check for clean environment before starting
        let should_restart = restart_harborshield.unwrap_or(true);
        Self::check_and_cleanup_environment(should_restart)?;

        let temp_dir = TempDir::new()?;
        let db_path = temp_dir.path().join("test.db");
        let project_name = format!("harborshield-test-{}", uuid::Uuid::new_v4());

        let use_compose = compose_file.is_some();
        let compose_file = compose_file.unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/common/resources/docker-compose.test.yml")
        });

        let mut env = Self {
            compose_file,
            project_name,
            temp_dir: Arc::new(temp_dir),
            db_path,
            harborshield_process: None,
            test_name: test_name.unwrap_or_else(|| "unknown_test".to_string()),
            verdict_chains: verdict_chains.unwrap_or_default(),
            health_addr: None,
        };

        // If we have a compose file provided, use it; otherwise create a default network
        if use_compose {
            if start_harborshield {
                // Start compose and harborshield together with chained command
                env.start_compose_and_harborshield()?;
            } else {
                env.start_compose()?;
                env.wait_for_compose_ready(Duration::from_secs(60))?;
            }
        } else {
            // Create a default network for individual test containers
            env.create_default_network()?;
            if start_harborshield {
                env.start_harborshield()?;
            }
        }

        Ok(env)
    }

    pub fn db_path(&self) -> &PathBuf {
        &self.db_path
    }

    pub fn project_name(&self) -> &str {
        &self.project_name
    }

    pub fn get_test_name(&self) -> &str {
        &self.test_name
    }

    pub fn temp_dir_path(&self) -> &std::path::Path {
        self.temp_dir.path()
    }

    fn create_verdict_chains(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Check if running as root
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            eprintln!("⚠️  Not running as root, skipping verdict chain creation");
            return Ok(());
        }

        eprintln!("🔗 Creating test verdict chains...");
        for chain in &self.verdict_chains {
            eprintln!("  - Creating verdict chain: {}", chain);

            // Create the chain in the filter table
            let output = Command::new("nft")
                .args(&["add", "chain", "ip", "filter", chain])
                .output()?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                // Chain might already exist, which is okay
                if !stderr.contains("already exists") {
                    return Err(
                        format!("Failed to create verdict chain '{}': {}", chain, stderr).into(),
                    );
                } else {
                    eprintln!("    ℹ️  Chain {} already exists", chain);
                }
            } else {
                eprintln!("    ✅ Created chain: {}", chain);
            }
        }
        Ok(())
    }

    fn start_compose_and_harborshield(
        &mut self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Create verdict chains before starting compose/harborshield
        if !self.verdict_chains.is_empty() {
            self.create_verdict_chains()?;
        }

        eprintln!("🐳 Starting Docker Compose services and harborshield together...");

        // Build harborshield first if needed
        let harborshield_binary = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("debug")
            .join("harborshield");

        if !harborshield_binary.exists() {
            eprintln!("📦 Building harborshield...");
            let mut cmd = Command::new("cargo");
            cmd.args(&["build", "--bin", "harborshield"]);
            cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
            let output = cmd.output()?;
            if !output.status.success() {
                return Err("Failed to build harborshield".into());
            }
        }

        // Create log file for harborshield stderr in permanent location
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let test_name = self.get_test_name();
        let log_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/common/logs")
            .join(test_name);

        // Clear existing log files in the directory
        if log_dir.exists() {
            if let Err(e) = std::fs::remove_dir_all(&log_dir) {
                eprintln!(
                    "⚠️  Warning: Failed to clear log directory {}: {}",
                    log_dir.display(),
                    e
                );
            }
        }

        std::fs::create_dir_all(&log_dir)?;
        let log_file_path = log_dir.join(format!("harborshield_compose_{}.log", timestamp));

        // Allocate a port for harborshield's health server so we can poll readiness.
        let health_port = crate::common::pick_free_port()?;
        let health_addr = format!("127.0.0.1:{}", health_port);
        self.health_addr = Some(health_addr.clone());

        // Create a shell command that runs compose and then harborshield, redirecting harborshield's stderr to log file
        eprintln!(
            "📝 Harborshield logs will be saved to: {}",
            log_file_path.display()
        );
        let full_command = format!(
            "docker compose -f {} -p {} up -d --build && echo '✅ Docker Compose services started' && docker compose -f {} -p {} ps && {} --data-dir {} --debug --health-server {} 2>{}",
            self.compose_file.to_str().unwrap(),
            self.project_name,
            self.compose_file.to_str().unwrap(),
            self.project_name,
            harborshield_binary.to_str().unwrap(),
            self.temp_dir.path().to_str().unwrap(),
            health_addr,
            log_file_path.to_str().unwrap()
        );

        eprintln!("Running: {}", full_command);

        // Also create a separate log for the shell command output
        let shell_log_path = log_dir.join(format!("harborshield_compose_shell_{}.log", timestamp));
        eprintln!(
            "📝 Shell output will be saved to: {}",
            shell_log_path.display()
        );

        let child = Command::new("sh")
            .arg("-c")
            .arg(&full_command)
            .env("RUST_BACKTRACE", "1")
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or_else(|_| "harborshield=trace".to_string()),
            )
            .stdout(std::fs::File::create(&shell_log_path)?)
            .stderr(Stdio::piped())
            .spawn()?;

        self.harborshield_process = Some(child);

        // Poll readiness instead of sleeping a fixed duration.
        self.wait_for_compose_ready(Duration::from_secs(60))?;
        self.wait_for_harborshield_ready(Duration::from_secs(60))?;

        Ok(())
    }

    fn wait_for_compose_ready(
        &self,
        timeout: Duration,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let compose_file = self.compose_file.clone();
        let project = self.project_name.clone();
        block_on(async move {
            crate::common::wait_for_compose_services(&compose_file, &project, timeout).await
        })
        .map_err(|e| format!("compose readiness probe failed: {}", e).into())
    }

    fn wait_for_harborshield_ready(
        &self,
        timeout: Duration,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let Some(addr) = self.health_addr.clone() else {
            // No health server configured for this test variant — fall back to a brief settle.
            thread::sleep(Duration::from_secs(1));
            return Ok(());
        };
        block_on(async move {
            crate::common::wait_for_harborshield_health(&addr, timeout).await
        })
        .map_err(|e| format!("harborshield readiness probe failed: {}", e).into())
    }

    fn start_compose(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        eprintln!("🐳 Starting Docker Compose services...");

        let mut cmd = Command::new("docker");
        cmd.args(&[
            "compose",
            "-f",
            self.compose_file.to_str().unwrap(),
            "-p",
            &self.project_name,
            "up",
            "-d",
            "--build",
        ]);

        // Show Docker output to user
        cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());

        let output = cmd.output()?;

        if !output.status.success() {
            return Err("Failed to start docker-compose".into());
        }

        eprintln!("✅ Docker Compose services started");

        Ok(())
    }

    fn stop_compose(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut cmd = Command::new("docker");
        cmd.args(&[
            "compose",
            "-f",
            self.compose_file.to_str().unwrap(),
            "-p",
            &self.project_name,
            "down",
            "-v",
            "--remove-orphans",
        ]);

        // Suppress output during cleanup
        cmd.stdout(Stdio::null()).stderr(Stdio::null());

        let output = cmd.output()?;

        if !output.status.success() {
            eprintln!("Warning: Failed to stop docker-compose cleanly");
        }

        Ok(())
    }

    pub fn start_harborshield(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Path to debug binary
        let harborshield_binary = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("debug")
            .join("harborshield");

        // Check if debug binary exists
        if !harborshield_binary.exists() {
            eprintln!("📦 Debug binary not found, building harborshield...");

            // Build harborshield binary in debug mode
            let mut cmd = Command::new("cargo");
            cmd.args(&["build", "--bin", "harborshield"]);
            cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());

            let output = cmd.output()?;

            if !output.status.success() {
                return Err("Failed to build harborshield".into());
            }

            eprintln!("✅ Build complete");
        } else {
            eprintln!("📦 Using existing debug binary");
        }

        eprintln!("🚀 Starting harborshield process...");

        // Create log file for harborshield stderr in permanent location
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let test_name = self.get_test_name();
        let log_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/common/logs")
            .join(test_name);

        // Clear existing log files in the directory
        if log_dir.exists() {
            if let Err(e) = std::fs::remove_dir_all(&log_dir) {
                eprintln!(
                    "⚠️  Warning: Failed to clear log directory {}: {}",
                    log_dir.display(),
                    e
                );
            }
        }

        std::fs::create_dir_all(&log_dir)?;
        let log_file_path = log_dir.join(format!("harborshield_compose_{}.log", timestamp));
        let log_file = std::fs::File::create(&log_file_path)?;

        let health_port = crate::common::pick_free_port()?;
        let health_addr = format!("127.0.0.1:{}", health_port);
        self.health_addr = Some(health_addr.clone());

        let child = Command::new(&harborshield_binary)
            .args([
                "--data-dir",
                self.temp_dir.path().to_str().unwrap(),
                "--debug",
                "--health-server",
                &health_addr,
            ])
            .env("RUST_BACKTRACE", "1")
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or_else(|_| "harborshield=trace".to_string()),
            )
            .stdout(Stdio::piped())
            .stderr(log_file)
            .spawn()?;

        self.harborshield_process = Some(child);

        // Poll the health endpoint instead of sleeping.
        self.wait_for_harborshield_ready(Duration::from_secs(60))?;

        Ok(())
    }

    pub fn stop_harborshield(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let Some(mut process) = self.harborshield_process.take() else {
            return Ok(());
        };

        #[cfg(unix)]
        {
            use nix::sys::signal;
            use nix::unistd::Pid;
            let _ = signal::kill(Pid::from_raw(process.id() as i32), signal::Signal::SIGTERM);
        }

        // Poll for graceful exit up to 10s, checking every 100ms.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let exited = loop {
            if let Some(status) = process.try_wait()? {
                if !status.success() {
                    eprintln!("Harborshield exited with status: {}", status);
                }
                break true;
            }
            if std::time::Instant::now() >= deadline {
                break false;
            }
            thread::sleep(Duration::from_millis(100));
        };

        if !exited {
            eprintln!("Harborshield did not exit within 10s; sending SIGKILL");
            process.kill()?;
            process.wait()?;
        }

        self.health_addr = None;
        Ok(())
    }

    pub fn get_harborshield_logs_and_rules(
        &self,
    ) -> (
        Result<String, Box<dyn std::error::Error + Send + Sync>>,
        Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>>,
    ) {
        (self.get_harborshield_logs(), self.get_harborshield_rules())
    }

    pub fn get_harborshield_logs(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // Read logs from permanent log directory - find the most recent log file
        let test_name = self.get_test_name();
        let log_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/common/logs")
            .join(test_name);

        if log_dir.exists() {
            let mut entries: Vec<_> = std::fs::read_dir(&log_dir)?
                .filter_map(Result::ok)
                .filter(|e| {
                    e.path().extension() == Some(std::ffi::OsStr::new("log"))
                        && e.file_name()
                            .to_string_lossy()
                            .starts_with("harborshield_compose_")
                })
                .collect();

            // Sort by modification time to get the most recent
            entries.sort_by_key(|e| e.metadata().ok().and_then(|m| m.modified().ok()));

            if let Some(latest) = entries.last() {
                match std::fs::read_to_string(latest.path()) {
                    Ok(contents) => {
                        if !contents.is_empty() {
                            return Ok(contents);
                        }
                    }
                    Err(e) => eprintln!("Failed to read log file: {}", e),
                }
            }
        }

        // Check if harborshield is still running without mutation
        if let Some(ref child) = self.harborshield_process {
            let pid = child.id();

            // Use kill with signal 0 to check if process exists
            #[cfg(unix)]
            {
                use std::process::Command;

                // Use kill -0 to check if process exists
                let output = Command::new("kill")
                    .args(&["-0", &pid.to_string()])
                    .output();

                match output {
                    Ok(result) if result.status.success() => {
                        return Ok("Harborshield is still running (check log file for details)"
                            .to_string());
                    }
                    _ => {
                        return Ok("Harborshield process has exited".to_string());
                    }
                }
            }

            #[cfg(not(unix))]
            {
                // On non-Unix systems, we can't easily check without mutation
                return Ok("Harborshield process status unknown (check log file)".to_string());
            }
        }

        Ok("No harborshield process found".to_string())
    }

    pub fn exec_in_container(
        &self,
        container: &str,
        command: &[&str],
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let output = Command::new("docker")
            .args(&["exec", container])
            .args(command)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Command failed: {}", stderr).into());
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    pub fn get_container_info(
        &self,
        container: &str,
    ) -> Result<Container, Box<dyn std::error::Error + Send + Sync>> {
        let output = Command::new("docker")
            .args(&["inspect", container])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Failed to inspect container: {}", stderr).into());
        }

        let json: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        let container_data = &json[0];

        let id = container_data["Id"].as_str().unwrap_or("").to_string();
        let name = container_data["Name"]
            .as_str()
            .unwrap_or("")
            .trim_start_matches('/')
            .to_string();
        let state = container_data["State"]["Status"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();

        let mut ip_address = None;
        let mut networks_map = HashMap::new();

        if let Some(networks) = container_data["NetworkSettings"]["Networks"].as_object() {
            for (network_name, network_data) in networks {
                if let Some(ip) = network_data["IPAddress"].as_str() {
                    if !ip.is_empty() {
                        // Keep first IP for backward compatibility
                        if ip_address.is_none() {
                            ip_address = Some(ip.to_string());
                        }

                        // Add to networks map
                        networks_map.insert(
                            network_name.clone(),
                            ContainerNetwork {
                                name: network_name.clone(),
                                ip_address: ip.to_string(),
                            },
                        );
                    }
                }
            }
        }

        let mut labels = HashMap::new();
        if let Some(labels_obj) = container_data["Config"]["Labels"].as_object() {
            for (key, value) in labels_obj {
                if let Some(val_str) = value.as_str() {
                    labels.insert(key.to_string(), val_str.to_string());
                }
            }
        }

        Ok(Container {
            id,
            name,
            ip_address,
            networks: networks_map,
            state,
            labels,
        })
    }

    pub fn get_container_ip(
        &self,
        container: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let info = self.get_container_info(container)?;
        info.ip_address
            .ok_or_else(|| format!("Container {} has no IP address", container).into())
    }

    pub fn list_containers(
        &self,
    ) -> Result<Vec<Container>, Box<dyn std::error::Error + Send + Sync>> {
        let output = Command::new("docker")
            .args(&[
                "ps",
                "-a",
                "--filter",
                &format!("label=com.docker.compose.project={}", self.project_name),
                "--format",
                "{{.ID}}",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Failed to list containers: {}", stderr).into());
        }

        let mut containers = Vec::new();
        let container_ids = String::from_utf8_lossy(&output.stdout);

        for id in container_ids.lines() {
            if !id.trim().is_empty() {
                if let Ok(info) = self.get_container_info(id.trim()) {
                    containers.push(info);
                }
            }
        }

        Ok(containers)
    }

    pub fn check_connectivity(
        &self,
        from_container: &str,
        to_host: &str,
        port: u16,
        protocol: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let timeout_flag = "-w";
        let timeout_value = "2";

        let result = match protocol.to_lowercase().as_str() {
            "tcp" => self.exec_in_container(
                from_container,
                &[
                    "nc",
                    "-zv",
                    timeout_flag,
                    timeout_value,
                    to_host,
                    &port.to_string(),
                ],
            ),
            "udp" => self.exec_in_container(
                from_container,
                &[
                    "nc",
                    "-zuv",
                    timeout_flag,
                    timeout_value,
                    to_host,
                    &port.to_string(),
                ],
            ),
            _ => return Err(format!("Unsupported protocol: {}", protocol).into()),
        };

        Ok(result.is_ok())
    }

    /// Create a test network and container for security testing
    pub fn create_test_attacker(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        eprintln!("🔒 Creating test attacker network and container...");

        // Create a separate network for the attacker
        let attacker_network = format!("{}_attacker", self.project_name);
        let output = Command::new("docker")
            .args(&["network", "create", &attacker_network])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Ignore if network already exists
            if !stderr.contains("already exists") {
                return Err(format!("Failed to create attacker network: {}", stderr).into());
            }
        }

        // Create an attacker container on this network
        let attacker_name = format!("{}_attacker", self.project_name);
        let output = Command::new("docker")
            .args(&[
                "run",
                "-d",
                "--name",
                &attacker_name,
                "--network",
                &attacker_network,
                "--label",
                &format!("com.docker.compose.project={}", self.project_name),
                "alpine:latest",
                "sleep",
                "infinity",
            ])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Ignore if container already exists
            if !stderr.contains("already exists") && !stderr.contains("is already in use") {
                return Err(format!("Failed to create attacker container: {}", stderr).into());
            }
        }

        // Install network testing tools in the attacker container
        let output = Command::new("docker")
            .args(&[
                "exec",
                &attacker_name,
                "sh",
                "-c",
                "apk add --no-cache netcat-openbsd curl wget nmap",
            ])
            .output()?;

        if !output.status.success() {
            eprintln!("⚠️  Failed to install tools in attacker container, but continuing...");
        }

        eprintln!("✅ Test attacker container created on isolated network");
        Ok(())
    }

    /// Test that all containers properly deny unauthorized access from the attacker
    pub fn test_security_isolation(
        &self,
    ) -> Result<Vec<(String, u16, bool)>, Box<dyn std::error::Error + Send + Sync>> {
        eprintln!("🔍 Testing security isolation from attacker container...");

        let attacker_name = format!("{}_attacker", self.project_name);
        let containers = self.list_containers()?;
        let mut results = Vec::new();

        // Filter out the attacker container itself
        let target_containers: Vec<_> = containers
            .iter()
            .filter(|c| !c.name.contains("attacker"))
            .collect();

        eprintln!(
            "   Testing access to {} containers",
            target_containers.len()
        );

        for container in target_containers {
            // Get all ports exposed by this container
            let ports = self.get_container_ports(&container.id)?;

            for port in ports {
                // Try to connect from attacker to each IP of the target container
                for network in container.networks.values() {
                    eprintln!(
                        "   Testing {}:{} from attacker...",
                        network.ip_address, port
                    );

                    let connected =
                        self.check_connectivity(&attacker_name, &network.ip_address, port, "tcp")?;

                    results.push((container.name.clone(), port, connected));

                    if connected {
                        eprintln!(
                            "   ⚠️  WARNING: Attacker can reach {}:{}",
                            container.name, port
                        );
                    } else {
                        eprintln!("   ✅ Access denied to {}:{}", container.name, port);
                    }
                }
            }
        }

        Ok(results)
    }

    /// Get exposed ports for a container
    fn get_container_ports(
        &self,
        container_id: &str,
    ) -> Result<Vec<u16>, Box<dyn std::error::Error + Send + Sync>> {
        let output = Command::new("docker")
            .args(&["inspect", container_id])
            .output()?;

        if !output.status.success() {
            return Err(format!(
                "Failed to inspect container: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }

        let json: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        let mut ports = Vec::new();

        if let Some(exposed_ports) = json[0]["Config"]["ExposedPorts"].as_object() {
            for (port_proto, _) in exposed_ports {
                if let Some(port_str) = port_proto.split('/').next() {
                    if let Ok(port) = port_str.parse::<u16>() {
                        ports.push(port);
                    }
                }
            }
        }

        Ok(ports)
    }

    /// Clean up attacker container and network
    fn cleanup_attacker(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let attacker_name = format!("{}_attacker", self.project_name);
        let attacker_network = format!("{}_attacker", self.project_name);

        // Remove attacker container
        let _ = Command::new("docker")
            .args(&["rm", "-f", &attacker_name])
            .output();

        // Remove attacker network
        let _ = Command::new("docker")
            .args(&["network", "rm", &attacker_network])
            .output();

        Ok(())
    }

    pub fn check_nftables_rules(
        &self,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        // Use nftables-rs get_current_ruleset_raw function which returns JSON
        let args = vec!["list", "ruleset"];
        match nftables::helper::get_current_ruleset_raw::<&str, &str, _>(None, &args) {
            Ok(ruleset) => serde_json::from_str(&ruleset)
                .map_err(|e| format!("Failed to parse nftables JSON: {}", e).into()),
            Err(e) => Err(format!("Failed to list nftables rules: {:?}", e).into()),
        }
    }

    pub fn get_harborshield_rules(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        let parsed = self.check_nftables_rules()?;
        let mut harborshield_rules = Vec::new();

        // Look for inet harborshield table in the JSON
        if let Some(nftables) = parsed.get("nftables").and_then(|n| n.as_array()) {
            let mut found_harborshield_table = false;

            for item in nftables {
                if let Some(table) = item.get("table") {
                    if table.get("family").and_then(|f| f.as_str()) == Some("inet")
                        && table.get("name").and_then(|n| n.as_str()) == Some("harborshield")
                    {
                        found_harborshield_table = true;
                        harborshield_rules.push("table inet harborshield {".to_string());
                    }
                } else if found_harborshield_table {
                    // Add chains and rules from harborshield table
                    if let Some(chain) = item.get("chain") {
                        if let Some(name) = chain.get("name").and_then(|n| n.as_str()) {
                            harborshield_rules.push(format!("\tchain {} {{", name));
                        }
                    }
                }
            }
        }

        Ok(harborshield_rules)
    }

    pub fn get_docker_filter_rules(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        let parsed = self.check_nftables_rules()?;
        let mut filter_rules = Vec::new();

        // Look for chains in the ip filter table
        if let Some(nftables) = parsed.get("nftables").and_then(|n| n.as_array()) {
            for item in nftables {
                if let Some(chain) = item.get("chain") {
                    if let (Some(family), Some(table), Some(name)) = (
                        chain.get("family").and_then(|f| f.as_str()),
                        chain.get("table").and_then(|t| t.as_str()),
                        chain.get("name").and_then(|n| n.as_str()),
                    ) {
                        if family == "ip" && table == "filter" {
                            // Format as "chain <name> {" to match the text pattern expectations
                            filter_rules.push(format!("\tchain {} {{", name));
                        }
                    }
                }
            }
        }

        Ok(filter_rules)
    }

    pub fn get_chain_rules_structured(
        &self,
        family: &str,
        table: &str,
        chain: &str,
    ) -> Result<nftables::schema::Nftables<'static>, Box<dyn std::error::Error + Send + Sync>> {
        // Use nftables-rs get_current_ruleset_with_args function with specific chain
        let args = vec![
            "list".to_string(),
            "chain".to_string(),
            family.to_string(),
            table.to_string(),
            chain.to_string(),
        ];

        match nftables::helper::get_current_ruleset_with_args::<String, String, _>(None, &args) {
            Ok(ruleset) => Ok(ruleset),
            Err(e) => Err(format!("Failed to get chain rules: {:?}", e).into()),
        }
    }

    pub fn get_table_structured(
        &self,
        family: &str,
        table: &str,
    ) -> Result<nftables::schema::Nftables<'static>, Box<dyn std::error::Error + Send + Sync>> {
        // Use nftables-rs get_current_ruleset_with_args function with specific table
        let args = vec![
            "list".to_string(),
            "table".to_string(),
            family.to_string(),
            table.to_string(),
        ];

        match nftables::helper::get_current_ruleset_with_args::<String, String, _>(None, &args) {
            Ok(ruleset) => Ok(ruleset),
            Err(e) => Err(format!("Failed to get table: {:?}", e).into()),
        }
    }

    pub fn get_full_ruleset_structured(
        &self,
    ) -> Result<nftables::schema::Nftables<'static>, Box<dyn std::error::Error + Send + Sync>> {
        // Use nftables-rs get_current_ruleset_with_args function
        let args = vec!["list".to_string(), "ruleset".to_string()];

        match nftables::helper::get_current_ruleset_with_args::<String, String, _>(None, &args) {
            Ok(ruleset) => Ok(ruleset),
            Err(e) => Err(format!("Failed to get ruleset: {:?}", e).into()),
        }
    }

    pub fn wait_for_container_state(
        &self,
        container: &str,
        expected_state: &str,
        timeout: Duration,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let start = std::time::Instant::now();

        loop {
            let info = self.get_container_info(container)?;
            if info.state == expected_state {
                return Ok(());
            }

            if start.elapsed() > timeout {
                return Err(format!(
                    "Timeout waiting for container {} to reach state {}",
                    container, expected_state
                )
                .into());
            }

            thread::sleep(Duration::from_millis(500));
        }
    }

    fn create_default_network(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let network_name = format!("{}_default", self.project_name);

        // Check if network already exists
        let check_output = Command::new("docker")
            .args(&[
                "network",
                "ls",
                "--filter",
                &format!("name={}", network_name),
                "-q",
            ])
            .output()?;

        if check_output.status.success() && !check_output.stdout.is_empty() {
            // Network already exists
            return Ok(());
        }

        // Create the network
        eprintln!("🌐 Creating Docker network: {}", network_name);

        let output = Command::new("docker")
            .args(&["network", "create", &network_name])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Failed to create network: {}", stderr).into());
        }

        eprintln!("✅ Network created successfully");

        Ok(())
    }

    pub fn create_test_container(
        &self,
        name: &str,
        image: &str,
        labels: HashMap<String, String>,
        ports: Vec<String>,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let mut cmd = Command::new("docker");
        cmd.args(&["run", "-d", "--name", name]);

        // Add network
        cmd.args(&["--network", &format!("{}_default", self.project_name)]);

        // Add labels
        for (key, value) in labels {
            cmd.args(&["--label", &format!("{}={}", key, value)]);
        }

        // Add ports
        for port in ports {
            cmd.args(&["-p", &port]);
        }

        cmd.arg(image);

        eprintln!("🐳 Creating container: {}", name);

        let output = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Failed to create container: {}", stderr).into());
        }

        let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
        eprintln!("✅ Container {} created", name);
        Ok(container_id)
    }

    pub fn stop_container(
        &self,
        container: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let output = Command::new("docker")
            .args(&["stop", container])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Failed to stop container: {}", stderr).into());
        }

        Ok(())
    }

    pub fn remove_container(
        &self,
        container: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let output = Command::new("docker")
            .args(&["rm", "-f", container])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Failed to remove container: {}", stderr).into());
        }

        Ok(())
    }

    pub fn get_container_logs(
        &self,
        container: &str,
        lines: Option<usize>,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let mut cmd = Command::new("docker");
        cmd.args(&["logs"]);

        if let Some(n) = lines {
            cmd.args(&["--tail", &n.to_string()]);
        }

        cmd.arg(container);

        let output = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).output()?;

        // Docker logs outputs to stderr by default
        let logs = if output.stdout.is_empty() {
            String::from_utf8_lossy(&output.stderr).to_string()
        } else {
            String::from_utf8_lossy(&output.stdout).to_string()
        };

        Ok(logs)
    }

    pub fn get_network_info(
        &self,
        network: &str,
    ) -> Result<Network, Box<dyn std::error::Error + Send + Sync>> {
        let output = Command::new("docker")
            .args(&["network", "inspect", network])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Failed to inspect network: {}", stderr).into());
        }

        let json: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        let network_data = &json[0];

        let id = network_data["Id"].as_str().unwrap_or("").to_string();
        let name = network_data["Name"].as_str().unwrap_or("").to_string();

        let mut subnet = None;
        let mut gateway = None;

        if let Some(ipam) = network_data["IPAM"]["Config"].as_array() {
            if let Some(config) = ipam.first() {
                subnet = config["Subnet"].as_str().map(|s| s.to_string());
                gateway = config["Gateway"].as_str().map(|s| s.to_string());
            }
        }

        Ok(Network {
            id,
            name,
            subnet,
            gateway,
        })
    }

    fn cleanup_test_containers(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Stop all containers with test- prefix
        let output = Command::new("docker")
            .args(&["ps", "-q", "--filter", "name=test-"])
            .output()?;

        if output.status.success() && !output.stdout.is_empty() {
            let container_ids = String::from_utf8_lossy(&output.stdout);
            for id in container_ids.lines() {
                if !id.is_empty() {
                    let _ = Command::new("docker").args(&["stop", id]).output();
                    let _ = Command::new("docker").args(&["rm", "-f", id]).output();
                }
            }
        }

        // Also cleanup harborshield-test-* containers
        let output = Command::new("docker")
            .args(&["ps", "-q", "--filter", "name=harborshield-test-"])
            .output()?;

        if output.status.success() && !output.stdout.is_empty() {
            let container_ids = String::from_utf8_lossy(&output.stdout);
            for id in container_ids.lines() {
                if !id.is_empty() {
                    let _ = Command::new("docker").args(&["stop", id]).output();
                    let _ = Command::new("docker").args(&["rm", "-f", id]).output();
                }
            }
        }

        Ok(())
    }

    fn cleanup_nftables(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Check if running as root
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            // Not root, skip nftables cleanup
            return Ok(());
        }

        // Try to remove harborshield table
        let _ = Command::new("nft")
            .args(&["delete", "table", "inet", "harborshield"])
            .output();

        // Clean up Harborshield chains from Docker filter table
        self.cleanup_harborshield_filter_chains()?;

        // Clean up test verdict chains
        self.cleanup_verdict_chains()?;

        Ok(())
    }

    fn cleanup_verdict_chains(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.verdict_chains.is_empty() {
            return Ok(());
        }

        eprintln!("🧹 Cleaning up test verdict chains...");
        for chain in &self.verdict_chains {
            // First flush the chain
            let _ = Command::new("nft")
                .args(&["flush", "chain", "ip", "filter", chain])
                .output();

            // Then delete the chain
            let output = Command::new("nft")
                .args(&["delete", "chain", "ip", "filter", chain])
                .output()?;

            if output.status.success() {
                eprintln!("  ✅ Deleted chain: {}", chain);
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                eprintln!(
                    "  ⚠️  Warning: Failed to delete chain {}: {}",
                    chain, stderr
                );
            }
        }
        Ok(())
    }

    fn cleanup_harborshield_filter_chains(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Get list of chains in filter table
        let list_output = Command::new("nft")
            .args(&["-j", "list", "table", "ip", "filter"])
            .output()?;

        if !list_output.status.success() {
            // Filter table might not exist, that's OK
            return Ok(());
        }

        let output_str = String::from_utf8_lossy(&list_output.stdout);

        // Parse JSON to find chains starting with "hs-"
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&output_str) {
            if let Some(nftables) = json.get("nftables").and_then(|n| n.as_array()) {
                let mut chains_to_delete = Vec::new();

                for item in nftables {
                    if let Some(chain) = item.get("chain") {
                        if let Some(name) = chain.get("name").and_then(|n| n.as_str()) {
                            if name.starts_with("hs-") {
                                chains_to_delete.push(name.to_string());
                            }
                        }
                    }
                }

                // Delete each Harborshield chain
                for chain_name in chains_to_delete {
                    // First flush the chain
                    let _ = Command::new("nft")
                        .args(&["flush", "chain", "ip", "filter", &chain_name])
                        .output();

                    // Then delete the chain
                    let _ = Command::new("nft")
                        .args(&["delete", "chain", "ip", "filter", &chain_name])
                        .output();
                }
            }
        }

        Ok(())
    }

    fn check_and_cleanup_environment(
        restart_harborshield: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Check for leftover test containers
        let output = Command::new("docker")
            .args(&[
                "ps",
                "-a",
                "--filter",
                "name=test-",
                "--filter",
                "name=harborshield-test-",
                "-q",
            ])
            .output()?;

        if output.status.success() && !output.stdout.is_empty() {
            let count = output.stdout.lines().count();
            eprintln!("⚠️  Found {} leftover test containers!", count);
            eprintln!("🧹 Attempting automatic cleanup...");

            // Try to clean up
            Self::force_cleanup_containers()?;

            eprintln!("✅ Cleanup successful, continuing with test");
        }

        // Also clean up leftover harborshield processes
        Self::force_cleanup_harborshield_processes()?;

        // Check for leftover nftables rules (if root)
        let euid = unsafe { libc::geteuid() };
        if euid == 0 {
            let output = Command::new("nft")
                .args(&["list", "table", "inet", "harborshield"])
                .output();

            if let Ok(output) = output {
                if output.status.success() {
                    eprintln!("⚠️  Found leftover nftables rules!");
                    eprintln!("🧹 Cleaning up nftables...");

                    let _ = Command::new("nft")
                        .args(&["delete", "table", "inet", "harborshield"])
                        .output();
                }
            }

            // Also clean up Harborshield chains from filter table
            Self::cleanup_harborshield_filter_chains_static()?;
        }

        // Check if harborshield is already running
        let output = Command::new("pgrep")
            .args(&["-f", "harborshield.*--data-dir"])
            .output();

        if let Ok(output) = output {
            if output.status.success() && !output.stdout.is_empty() {
                eprintln!("⚠️  Found running harborshield process!");

                if restart_harborshield {
                    eprintln!("🔔 Attempting to stop it...");

                    // Try to kill the processes
                    let pids = String::from_utf8_lossy(&output.stdout);
                    for pid in pids.lines() {
                        if !pid.is_empty() {
                            let _ = Command::new("kill").args(&["-TERM", pid.trim()]).output();
                        }
                    }

                    // Wait a bit and check again
                    std::thread::sleep(std::time::Duration::from_secs(2));

                    let check_output = Command::new("pgrep")
                        .args(&["-f", "harborshield.*--data-dir"])
                        .output();

                    if let Ok(output) = check_output {
                        if output.status.success() && !output.stdout.is_empty() {
                            // Try harder with SIGKILL
                            let pids = String::from_utf8_lossy(&output.stdout);
                            for pid in pids.lines() {
                                if !pid.is_empty() {
                                    let _ =
                                        Command::new("kill").args(&["-KILL", pid.trim()]).output();
                                }
                            }
                            std::thread::sleep(std::time::Duration::from_secs(1));

                            // Final check
                            let final_check = Command::new("pgrep")
                                .args(&["-f", "harborshield.*--data-dir"])
                                .output();

                            if let Ok(output) = final_check {
                                if output.status.success() && !output.stdout.is_empty() {
                                    panic!(
                                        "❌ Failed to stop harborshield process. Please stop it manually."
                                    );
                                }
                            }
                        }
                    }
                } else {
                    eprintln!("✅ Keeping existing harborshield process running");
                }
            }
        }

        Ok(())
    }

    fn cleanup_harborshield_filter_chains_static()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Get list of chains in filter table
        let list_output = Command::new("nft")
            .args(&["-j", "list", "table", "ip", "filter"])
            .output()?;

        if !list_output.status.success() {
            // Filter table might not exist, that's OK
            return Ok(());
        }

        let output_str = String::from_utf8_lossy(&list_output.stdout);

        // Parse JSON to find chains starting with "hs-"
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&output_str) {
            if let Some(nftables) = json.get("nftables").and_then(|n| n.as_array()) {
                let mut chains_to_delete = Vec::new();

                for item in nftables {
                    if let Some(chain) = item.get("chain") {
                        if let Some(name) = chain.get("name").and_then(|n| n.as_str()) {
                            if name.starts_with("hs-") {
                                chains_to_delete.push(name.to_string());
                            }
                        }
                    }
                }

                if !chains_to_delete.is_empty() {
                    eprintln!(
                        "🧹 Found {} Harborshield chains to clean up",
                        chains_to_delete.len()
                    );
                }

                // Delete each Harborshield chain
                for chain_name in chains_to_delete {
                    // First flush the chain
                    let _ = Command::new("nft")
                        .args(&["flush", "chain", "ip", "filter", &chain_name])
                        .output();

                    // Then delete the chain
                    let _ = Command::new("nft")
                        .args(&["delete", "chain", "ip", "filter", &chain_name])
                        .output();
                }
            }
        }

        Ok(())
    }

    fn force_cleanup_harborshield_processes() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Kill all harborshield test processes
        let output = Command::new("pgrep")
            .args(&["-f", "harborshield.*--data-dir"])
            .output()?;

        if output.status.success() && !output.stdout.is_empty() {
            let pids = String::from_utf8_lossy(&output.stdout);
            let pid_list: Vec<&str> = pids.lines().filter(|p| !p.is_empty()).collect();

            eprintln!(
                "🧹 Found {} harborshield test processes to clean up",
                pid_list.len()
            );

            // First try SIGTERM
            for pid in &pid_list {
                let _ = Command::new("kill").args(&["-TERM", pid]).output();
            }

            // Wait a bit
            std::thread::sleep(std::time::Duration::from_secs(2));

            // Check if any are still running and use SIGKILL
            let check_output = Command::new("pgrep")
                .args(&["-f", "harborshield.*--data-dir"])
                .output()?;

            if check_output.status.success() && !check_output.stdout.is_empty() {
                let remaining_pids = String::from_utf8_lossy(&check_output.stdout);
                for pid in remaining_pids.lines() {
                    if !pid.is_empty() {
                        let _ = Command::new("kill").args(&["-KILL", pid]).output();
                    }
                }
            }

            eprintln!("✅ Cleaned up harborshield test processes");
        }

        Ok(())
    }

    fn force_cleanup_containers() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Stop and remove all test containers
        let patterns = vec!["test-", "harborshield-test-"];

        for pattern in patterns {
            // Get container IDs
            let output = Command::new("docker")
                .args(&["ps", "-a", "--filter", &format!("name={}", pattern), "-q"])
                .output()?;

            if output.status.success() && !output.stdout.is_empty() {
                let container_ids = String::from_utf8_lossy(&output.stdout);
                let ids: Vec<&str> = container_ids.lines().filter(|id| !id.is_empty()).collect();

                if !ids.is_empty() {
                    // Stop containers (ignore errors)
                    let _ = Command::new("docker").arg("stop").args(&ids).output();

                    // Remove containers forcefully
                    let _ = Command::new("docker")
                        .arg("rm")
                        .arg("-f")
                        .args(&ids)
                        .output();
                }
            }
        }

        // Clean up any docker compose projects
        let output = Command::new("docker")
            .args(&["compose", "ls", "-q"])
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                let projects = String::from_utf8_lossy(&output.stdout);
                for project in projects.lines() {
                    if project.starts_with("harborshield-test-") {
                        let _ = Command::new("docker")
                            .args(&["compose", "-p", project, "down", "-v", "--remove-orphans"])
                            .output();
                    }
                }
            }
        }

        // Clean up Docker networks
        let output = Command::new("docker")
            .args(&["network", "ls", "--filter", "name=harborshield-test-", "-q"])
            .output();

        if let Ok(output) = output {
            if output.status.success() && !output.stdout.is_empty() {
                let network_ids = String::from_utf8_lossy(&output.stdout);
                for id in network_ids.lines() {
                    if !id.is_empty() {
                        let _ = Command::new("docker")
                            .args(&["network", "rm", id.trim()])
                            .output();
                    }
                }
            }
        }

        Ok(())
    }
}

impl Drop for TestEnvironment {
    fn drop(&mut self) {
        // Stop harborshield first
        if let Err(e) = self.stop_harborshield() {
            eprintln!("Failed to stop harborshield in cleanup: {:?}", e);
        }

        // Then stop docker compose
        if let Err(e) = self.stop_compose() {
            eprintln!("Failed to stop docker-compose in cleanup: {:?}", e);
        }

        // Clean up any individual test containers
        if let Err(e) = self.cleanup_test_containers() {
            eprintln!("Failed to cleanup test containers: {:?}", e);
        }

        // Clean up nftables rules if running as root
        if let Err(e) = self.cleanup_nftables() {
            eprintln!("Failed to cleanup nftables: {:?}", e);
        }
        // Clean up attacker resources
        if let Err(e) = self.cleanup_attacker() {
            eprintln!("Failed to cleanup attacker resources: {:?}", e);
        }

        // Clean up the default network if we created one
        let network_name = format!("{}_default", self.project_name);
        let _ = Command::new("docker")
            .args(&["network", "rm", &network_name])
            .output();
    }
}
