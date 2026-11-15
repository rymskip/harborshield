//! Filesystem sandbox: once applied, harborshield may read only what it and `nft` need, write
//! only its data directory, its log file and /tmp, and execute only `nft`.

use std::path::{Path, PathBuf};

use landlock::{
    ABI, Access, AccessFs, BitFlags, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreated,
    RulesetCreatedAttr, RulesetStatus,
};
use tracing::{debug, info, warn};

use super::{Result, SecurityError};

const ABI_VERSION: ABI = ABI::V1;

/// Read-only files the C library and `nft` consult.
const SYSTEM_FILES: &[&str] = &[
    "/etc/protocols",
    "/etc/services",
    "/etc/localtime",
    "/etc/nsswitch.conf",
    "/etc/resolv.conf",
    "/etc/hosts",
];

/// Shared libraries `nft` loads.
const LIBRARY_DIRS: &[&str] = &["/lib", "/lib64", "/usr/lib", "/usr/lib64"];

/// Read-only trees `nft` and the runtime read.
const READABLE: &[&str] = &[
    "/proc",
    "/dev/null",
    "/dev/urandom",
    "/dev/random",
    "/var/run",
    "/run",
    "/sys/fs/cgroup",
    "/etc/nftables",
    "/etc/nftables.conf",
    "/usr/share/nftables",
];

const NFT_BINARIES: &[&str] = &["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"];

/// Confine the calling thread and every thread or process it starts afterwards, so call this
/// before any other thread exists. Returns how fully the kernel enforced it.
pub fn apply_landlock_rules(data_dir: &Path, log_path: Option<&Path>) -> Result<RulesetStatus> {
    let read = AccessFs::ReadFile | AccessFs::ReadDir;
    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(ABI_VERSION))?
        .create()?;

    // SQLite creates and removes its journal files beside the database.
    ruleset = allow(
        ruleset,
        data_dir,
        read | AccessFs::WriteFile | AccessFs::MakeReg | AccessFs::RemoveFile,
    )?;
    if let Some(log_path) = log_path {
        // The rule needs the file to exist; the logger appends to it afterwards.
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .map_err(|source| SecurityError::FileAccess {
                path: log_path.to_path_buf(),
                source,
            })?;
        ruleset = allow(ruleset, log_path, AccessFs::WriteFile.into())?;
    }
    ruleset = allow(
        ruleset,
        Path::new("/tmp"),
        read | AccessFs::WriteFile | AccessFs::MakeReg | AccessFs::RemoveFile,
    )?;
    for library in LIBRARY_DIRS {
        ruleset = allow(ruleset, Path::new(library), read | AccessFs::Execute)?;
    }
    for path in READABLE {
        ruleset = allow(ruleset, Path::new(path), read)?;
    }
    for file in SYSTEM_FILES {
        ruleset = allow(ruleset, Path::new(file), AccessFs::ReadFile.into())?;
    }
    if let Some(nft) = NFT_BINARIES
        .iter()
        .map(Path::new)
        .find(|path| path.exists())
    {
        ruleset = allow(ruleset, nft, AccessFs::ReadFile | AccessFs::Execute)?;
    } else {
        warn!("no nft binary found; harborshield will not be able to apply rules");
    }

    let status = ruleset.restrict_self()?;
    match status.ruleset {
        RulesetStatus::FullyEnforced => info!("landlock rules fully enforced"),
        RulesetStatus::PartiallyEnforced => info!("landlock rules partially enforced"),
        RulesetStatus::NotEnforced => {
            warn!("landlock rules not enforced; the kernel lacks support")
        }
    }
    Ok(status.ruleset)
}

/// Grant `access` beneath `path`. Paths absent on this system are skipped.
fn allow(
    ruleset: RulesetCreated,
    path: &Path,
    access: BitFlags<AccessFs>,
) -> Result<RulesetCreated> {
    let exists = path
        .try_exists()
        .map_err(|source| SecurityError::FileAccess {
            path: path.to_path_buf(),
            source,
        })?;
    if !exists {
        debug!(path = %path.display(), "not present; no landlock rule needed");
        return Ok(ruleset);
    }
    let descriptor = PathFd::new(path).map_err(|source| SecurityError::LandlockPath {
        path: PathBuf::from(path),
        source,
    })?;
    Ok(ruleset.add_rule(PathBeneath::new(descriptor, access))?)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::process::Command;

    use landlock::RulesetStatus;

    use super::apply_landlock_rules;

    const DIRS: &str = "HARBORSHIELD_LANDLOCK_TEST_DIRS";
    const TEST: &str = "security::landlock::tests::confines_writes_to_the_allowed_paths";

    /// Re-runs itself in a child, which confines itself to a data directory and must then be
    /// unable to write beside it.
    #[test]
    #[ignore = "requires Landlock; runs in the e2e sandbox"]
    fn confines_writes_to_the_allowed_paths() {
        if let Ok(dirs) = std::env::var(DIRS) {
            let (data, outside) = dirs.split_once(':').expect("two directories");
            let status = apply_landlock_rules(data.as_ref(), None).expect("apply landlock");
            assert_ne!(status, RulesetStatus::NotEnforced);
            std::fs::write(PathBuf::from(data).join("db.sqlite-wal"), b"ok")
                .expect("write the data dir");
            let denied = std::fs::write(PathBuf::from(outside).join("escape"), b"no");
            assert_eq!(
                denied.map_err(|failure| failure.kind()),
                Err(std::io::ErrorKind::PermissionDenied)
            );
            return;
        }
        // Outside /tmp, which the sandbox leaves writable for SQLite's temporary files.
        let root = PathBuf::from("/var/tmp");
        let data = tempfile::tempdir_in(&root).expect("data dir");
        let outside = tempfile::tempdir_in(&root).expect("outside dir");
        let status = Command::new(std::env::current_exe().expect("test binary"))
            .args(["--exact", TEST, "--ignored", "--test-threads=1"])
            .env(
                DIRS,
                format!("{}:{}", data.path().display(), outside.path().display()),
            )
            .status()
            .expect("run child");
        assert!(status.success(), "confined child failed: {status}");
    }
}
