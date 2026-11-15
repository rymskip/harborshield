# HarborShield

⚠️ **Work in Progress** - This crate is under active development and not yet ready for production use.

A Rust port of Whalewall, providing automated management of firewall rules for Docker containers using nftables. Why? I don't really know. Learning experience I guess. You probably should use the Go version


## How it enforces rules

Containers labelled `harborshield.enabled=true` are denied all traffic except what their
`harborshield.rules` label grants. Unknown keys in the rules are rejected, and a container whose
rules do not parse stays fully denied.

harborshield keeps everything in two tables of its own and never writes into Docker's. The
`inet harborshield` table filters routed traffic (published ports, traffic between networks,
and traffic to and from the host) on the forward, input and output hooks. The
`bridge harborshield` table filters traffic between containers on the same network, which a
bridge switches without routing; this works without loading `br_netfilter`. Every change
rebuilds both tables in one atomic nft transaction, and rules stay in force while the daemon is
stopped. `harborshield --clear` deletes both tables, along with any objects older versions
left in Docker's `ip filter` table.

A `verdict.chain` must name a chain that exists in harborshield's tables: in
`inet harborshield` for published-port and cross-network traffic, and also in
`bridge harborshield` for traffic between containers on one network. Create the tables and
chains before starting harborshield. A rule whose chain is missing from a table is left out of
that table, so it fails closed. `--clear` deletes those chains along with the tables.

## Testing

`cargo xtask test` runs the unprivileged tests. `cargo xtask e2e` runs the end-to-end suite in
a Docker-in-Docker sandbox; see [docs/e2e.md](docs/e2e.md).

## License

MIT
