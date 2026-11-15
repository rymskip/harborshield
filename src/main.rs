use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use harborshield::{Harborshield, VERSION, check_kernel_version, parse_duration, shutdown_signal};
use tracing::{error, info};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

#[derive(Parser, Debug)]
#[command(author, version, about = "Automate management of firewall rules for Docker containers", long_about = None)]
struct Args {
    /// Remove all firewall rules created by harborshield
    #[arg(long)]
    clear: bool,

    /// Directory to store state in
    #[arg(short = 'd', long, env = "DATA_DIR", default_value = ".")]
    data_dir: PathBuf,

    /// Log at debug level instead of info (RUST_LOG, when set, takes precedence)
    #[arg(long)]
    debug: bool,

    /// Path to log to (use "stdout" or "stderr" for console output)
    #[arg(short = 'l', long, env = "LOG_PATH", default_value = "stdout")]
    log_path: String,

    /// Timeout for Docker API requests
    #[arg(short = 't', long, env = "TIMEOUT", default_value = "10s", value_parser = parse_duration)]
    timeout: Duration,

    /// Enable health check server on specified address (e.g., "127.0.0.1:8080")
    #[arg(long, env = "HEALTH_SERVER_ADDR")]
    health_server: Option<String>,

    /// Print version and build information and exit
    #[arg(long = "version-info")]
    version_info: bool,
}

fn main() -> ExitCode {
    // A missing .env is normal; any other problem with it is worth reporting.
    if let Err(failure) = dotenvy::dotenv()
        && !failure.not_found()
    {
        eprintln!("could not load .env: {failure}");
    }

    let args = Args::parse();
    if args.version_info {
        println!("harborshield {VERSION}");
        println!("harborshield-rust (Rust port)");
        return ExitCode::SUCCESS;
    }

    let data_dir = match args.data_dir.canonicalize() {
        Ok(data_dir) => data_dir,
        Err(failure) => {
            eprintln!(
                "data directory {} is unusable: {failure}",
                args.data_dir.display()
            );
            return ExitCode::FAILURE;
        }
    };
    let log_file = match args.log_path.as_str() {
        "stdout" | "stderr" => None,
        path => Some(PathBuf::from(path)),
    };

    // Confine before any thread exists: the logging worker and the runtime's threads must all
    // start inside the sandbox.
    #[cfg(target_os = "linux")]
    {
        if let Err(failure) = harborshield::security::check_capabilities() {
            eprintln!("{failure}");
            return ExitCode::FAILURE;
        }
        if let Err(failure) =
            harborshield::security::apply_restrictions(&data_dir, log_file.as_deref())
        {
            eprintln!("could not apply security restrictions: {failure}");
            return ExitCode::FAILURE;
        }
    }

    // Held until exit: dropping it stops the file writer from flushing.
    let _log_guard = match init_logging(&args) {
        Ok(guard) => guard,
        Err(failure) => {
            eprintln!("could not set up logging: {failure}");
            return ExitCode::FAILURE;
        }
    };
    check_kernel_version();

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(failure) => {
            error!(%failure, "could not start the async runtime");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(args, data_dir.join("db.sqlite"))) {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            error!(%failure, "harborshield failed");
            ExitCode::FAILURE
        }
    }
}

fn init_logging(args: &Args) -> Result<Option<WorkerGuard>, Box<dyn std::error::Error>> {
    let filter = match std::env::var("RUST_LOG") {
        Ok(directives) => EnvFilter::try_new(directives)?,
        Err(_unset) => EnvFilter::new(if args.debug { "debug" } else { "info" }),
    };
    let registry = tracing_subscriber::registry().with(filter);
    match args.log_path.as_str() {
        "stdout" => {
            registry.with(fmt::layer()).try_init()?;
            Ok(None)
        }
        "stderr" => {
            registry
                .with(fmt::layer().with_writer(std::io::stderr))
                .try_init()?;
            Ok(None)
        }
        path => {
            let (writer, guard) =
                tracing_appender::non_blocking(tracing_appender::rolling::never("", path));
            registry
                .with(fmt::layer().with_writer(writer).with_ansi(false))
                .try_init()?;
            Ok(Some(guard))
        }
    }
}

async fn run(args: Args, db_path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let daemon = Harborshield::builder()
        .db_path(&db_path)
        .timeout(args.timeout)
        .maybe_health_server_addr(args.health_server.as_deref())
        .build()
        .await?;

    if args.clear {
        daemon.clear().await?;
        return Ok(());
    }

    info!("Starting harborshield v{VERSION}");
    let daemon = daemon.start().await?;
    let signal = shutdown_signal().await;
    info!("Shutting down");
    daemon.stop().await;
    signal?;
    Ok(())
}
