use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use super::command::run;
use super::failure::{Failure, TestResult};
use super::sandbox::Sandbox;
use super::time::deadline_in;

/// Long enough for socat's 3 s connect timeout plus process start-up.
const PROBE_LIMIT: Duration = Duration::from_secs(15);
/// How long an allowed path may take to open after the state change that should open it.
const CONVERGE_LIMIT: Duration = Duration::from_secs(20);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// Where a probe originates.
#[derive(Clone, Debug)]
pub enum Origin<'a> {
    /// Inside a container, by name.
    Container(&'a str),
    /// The Docker host itself, the path `mapped_ports.localhost` governs.
    Localhost,
    /// The simulated outside machine, from one of its source addresses.
    External {
        sandbox: &'a Sandbox,
        source: IpAddr,
    },
    /// A network namespace a test created, outside Docker.
    Namespace(&'a str),
}

impl fmt::Display for Origin<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Container(name) => write!(formatter, "container {name}"),
            Self::Localhost => formatter.write_str("localhost"),
            Self::External { source, .. } => write!(formatter, "external host {source}"),
            Self::Namespace(name) => write!(formatter, "namespace {name}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// A banner server answered; the banner is `hs-e2e <name> <port>`.
    Connected { banner: String },
    /// The peer refused: an RST or ICMP unreachable came back.
    Refused,
    /// Nothing came back: the packets were dropped.
    TimedOut,
    /// A TCP connection opened but nothing answered on it.
    Silent,
}

pub async fn probe(
    origin: &Origin<'_>,
    proto: Proto,
    host: IpAddr,
    port: u16,
) -> TestResult<Verdict> {
    let host = host.to_string();
    let port = port.to_string();
    let output = match origin {
        Origin::Container(name) => {
            run(
                "docker",
                &["exec", name, "hs-probe", proto.as_str(), &host, &port],
                PROBE_LIMIT,
            )
            .await?
        }
        Origin::Localhost => run("hs-probe", &[proto.as_str(), &host, &port], PROBE_LIMIT).await?,
        Origin::Namespace(name) => {
            run(
                "ip",
                &[
                    "netns",
                    "exec",
                    name,
                    "hs-probe",
                    proto.as_str(),
                    &host,
                    &port,
                ],
                PROBE_LIMIT,
            )
            .await?
        }
        Origin::External { sandbox, source } => {
            let source = source.to_string();
            run(
                "ip",
                &[
                    "netns",
                    "exec",
                    &sandbox.external_netns,
                    "hs-probe",
                    proto.as_str(),
                    &host,
                    &port,
                    &source,
                ],
                PROBE_LIMIT,
            )
            .await?
        }
    };

    let line = output.stdout.lines().next().unwrap_or_default().trim();
    let verdict = if let Some(banner) = line.strip_prefix("CONNECTED ") {
        Verdict::Connected {
            banner: banner.to_owned(),
        }
    } else if line == "REFUSED" {
        Verdict::Refused
    } else if line == "TIMEOUT" {
        Verdict::TimedOut
    } else if line == "SILENT" {
        Verdict::Silent
    } else {
        return Err(Failure::new(format!(
            "probe from {origin} to {host}:{port}/{} gave no verdict (status {}): stdout {:?} stderr {:?}",
            proto.as_str(),
            output.status,
            output.stdout.trim(),
            output.stderr.trim()
        )));
    };
    Ok(verdict)
}

/// One expected path: who connects where, and which service must answer.
pub struct Path<'a> {
    pub origin: Origin<'a>,
    pub proto: Proto,
    pub host: IpAddr,
    pub port: u16,
}

impl Path<'_> {
    fn describe(&self) -> String {
        format!(
            "{} -> {}:{}/{}",
            self.origin,
            self.host,
            self.port,
            self.proto.as_str()
        )
    }

    /// Wait until the path connects and `expected_name` answers on `served_port`.
    ///
    /// The served port differs from the probed one when probing a published port.
    pub async fn expect_connected(&self, expected_name: &str, served_port: u16) -> TestResult {
        let expected_banner = format!("hs-e2e {expected_name} {served_port}");
        let deadline = deadline_in(CONVERGE_LIMIT);
        loop {
            let verdict = probe(&self.origin, self.proto, self.host, self.port).await?;
            match &verdict {
                Verdict::Connected { banner } if *banner == expected_banner => return Ok(()),
                Verdict::Connected { banner } => {
                    return Err(Failure::new(format!(
                        "{} reached the wrong service: expected {expected_banner:?}, got {banner:?}",
                        self.describe()
                    )));
                }
                Verdict::Refused | Verdict::TimedOut | Verdict::Silent => {}
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(Failure::new(format!(
                    "{} should connect to {expected_name} but was {verdict:?} after {CONVERGE_LIMIT:?}",
                    self.describe()
                )));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// Wait until the path is dropped, for a runtime change (network connect, unpause) that
    /// harborshield applies asynchronously; once dropped it must stay dropped.
    pub async fn expect_dropped_eventually(&self) -> TestResult {
        let deadline = deadline_in(CONVERGE_LIMIT);
        loop {
            let verdict = probe(&self.origin, self.proto, self.host, self.port).await?;
            if self.is_drop(&verdict) {
                return self.expect_dropped().await;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(Failure::new(format!(
                    "{} should become dropped but was {verdict:?} after {CONVERGE_LIMIT:?}",
                    self.describe()
                )));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// Assert the path is dropped. Callers first converge the scenario (rules applied), so a
    /// single probe is authoritative; a refusal means something answered instead of dropping.
    pub async fn expect_dropped(&self) -> TestResult {
        let verdict = probe(&self.origin, self.proto, self.host, self.port).await?;
        if self.is_drop(&verdict) {
            Ok(())
        } else {
            Err(Failure::new(format!(
                "{} should be dropped but was {verdict:?}",
                self.describe()
            )))
        }
    }

    /// From the Docker host, published ports are reached through docker-proxy, which accepts
    /// the connection itself; a dropped backend then shows as silence rather than a timeout.
    fn is_drop(&self, verdict: &Verdict) -> bool {
        match verdict {
            Verdict::TimedOut => true,
            Verdict::Silent => matches!(self.origin, Origin::Localhost),
            Verdict::Connected { .. } | Verdict::Refused => false,
        }
    }
}

pub fn tcp<'a>(origin: Origin<'a>, host: impl Into<IpAddr>, port: u16) -> Path<'a> {
    Path {
        origin,
        proto: Proto::Tcp,
        host: host.into(),
        port,
    }
}

pub fn udp<'a>(origin: Origin<'a>, host: impl Into<IpAddr>, port: u16) -> Path<'a> {
    Path {
        origin,
        proto: Proto::Udp,
        host: host.into(),
        port,
    }
}
