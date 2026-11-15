use std::process::ExitStatus;
use std::time::Duration;

use tokio::process::Command;

use super::failure::{Failure, TestResult};

pub struct CommandOutput {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

/// Run a command to completion within `limit`, killing it if the limit passes.
pub async fn run(program: &str, args: &[&str], limit: Duration) -> TestResult<CommandOutput> {
    let rendered = render(program, args);
    let output = tokio::time::timeout(
        limit,
        Command::new(program).args(args).kill_on_drop(true).output(),
    )
    .await
    .map_err(|elapsed| Failure::context(format!("`{rendered}` exceeded {limit:?}"), elapsed))?
    .map_err(|error| Failure::context(format!("could not spawn `{rendered}`"), error))?;

    Ok(CommandOutput {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

/// Run a command that must succeed, returning its stdout.
pub async fn run_ok(program: &str, args: &[&str], limit: Duration) -> TestResult<String> {
    let output = run(program, args, limit).await?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(Failure::new(format!(
            "`{}` failed with {}: {}",
            render(program, args),
            output.status,
            output.stderr.trim()
        )))
    }
}

fn render(program: &str, args: &[&str]) -> String {
    std::iter::once(program)
        .chain(args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ")
}
