# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

HarborShield is a Rust port of Whalewall - a tool that automates management of firewall rules for Docker containers using nftables. It monitors Docker events and applies firewall rules based on container labels.

## Development Commands

All development uses xtask. Run `cargo xtask --help` for full details.

### Development Environment (Docker-based, required for Linux-specific nftables)

```bash
cargo xtask dev --build      # Start dev container (first time/rebuild)
cargo xtask dev              # Start dev container
cargo xtask shell            # Open bash shell in container
cargo xtask run              # Build and run harborshield in container
cargo xtask run --watch      # Auto-rebuild on file changes
cargo xtask stop             # Stop dev containers
```

### Testing

```bash
cargo xtask test             # Run all tests
cargo xtask test --unit      # Run only unit tests (--lib)
cargo xtask test --ignored   # Run integration tests
```

### Code Quality

```bash
cargo xtask check            # Run fmt check, clippy, tests
cargo xtask check --fix      # Auto-fix formatting/clippy issues
```

### Database

```bash
cargo xtask migrate          # Run SQLx migrations
cargo xtask sqlx-prepare     # Generate offline query cache (commit .sqlx/ changes)
```

## Architecture

### Core Components

- **`src/lib.rs`**: `Harborshield` struct - main orchestrator that manages Docker client, nftables client, database, and event handling lifecycle
- **`src/docker/`**: Docker API integration via bollard crate
  - `mod.rs`: `DockerClient` for container inspection, event streaming, network operations
  - `config/`: Rule configuration parsing from container labels (`harborshield.rules`)
  - `container/`: Container state tracking and dependency resolution
- **`src/nftables/`**: Firewall rule management
  - `mod.rs`: `NftablesClient` integrating with Docker's filter table
  - `transaction.rs`: Atomic rule application
  - `docker.rs`: Docker-specific chain creation (DOCKER-USER, harborshield)
- **`src/database/`**: SQLite persistence via SQLx
  - `operations.rs`: `DbOp` enum for type-safe database operations
  - `models.rs`: Container and waiting rule models
- **`src/handlers/`**: Docker event processing
  - `mod.rs`: Event listener spawning and container lifecycle handling
  - `crud.rs`: Container rule creation/deletion
  - `cleanup/`: Orphaned rule cleanup with tracking

### Key Patterns

- **Builder pattern**: Uses `bon` crate for struct construction (e.g., `Harborshield::builder().db_path(&path).build()`)
- **Container labels**: `harborshield.enabled=true` and `harborshield.rules` YAML for configuration
- **Chain naming**: Container chains use format `hs-{container_name}-{id_prefix}`
- **Verdict maps**: IP-to-chain routing in main `harborshield` chain

### Linux-Only Features

Security hardening modules (`src/security/`) only compile on Linux:
- Landlock filesystem sandboxing
- Seccomp syscall filtering
- Capability dropping

## Database

SQLite with SQLx. Migrations in `migrations/`. Queries are compile-time verified - run `cargo xtask sqlx-prepare` after changing queries.

## Testing Notes

Integration tests require the Docker dev environment with nftables support. Unit tests can run anywhere but may skip Linux-specific functionality.
