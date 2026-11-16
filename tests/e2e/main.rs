//! End-to-end suite: the real harborshield binary against a real Docker daemon and kernel
//! firewall, with every expectation checked by sending traffic. It runs only inside the
//! privileged sandbox that `cargo xtask e2e` starts.

mod support;

mod coexistence;
mod compose;
mod isolation;
mod lifecycle;
mod mapped_ports;
mod output_rules;
mod persistence;
mod scale;
mod startup;
mod upgrade;
mod verdicts;
