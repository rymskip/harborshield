//! A seccomp denylist: syscalls neither harborshield nor the `nft` it runs ever need, chosen
//! because they let a compromised process escape or tamper with the host. Everything else is
//! allowed, so the runtime, SQLite and `nft` keep working across kernel and libc versions.

use std::collections::BTreeMap;

use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch, apply_filter_all_threads};
use tracing::info;

use crate::security::error::{Result, SecurityError};

/// Denied syscalls fail with this errno rather than killing the process.
const DENIED_ERRNO: u32 = 1; // EPERM

/// Mounting, module loading, kexec, tracing other processes, entering or creating namespaces,
/// changing time or identity of the host, kernel keyrings, eBPF and perf.
const DENIED: &[(&str, libc::c_long)] = &[
    ("mount", libc::SYS_mount),
    ("umount2", libc::SYS_umount2),
    ("pivot_root", libc::SYS_pivot_root),
    ("open_tree", libc::SYS_open_tree),
    ("move_mount", libc::SYS_move_mount),
    ("fsopen", libc::SYS_fsopen),
    ("fsconfig", libc::SYS_fsconfig),
    ("fsmount", libc::SYS_fsmount),
    ("fspick", libc::SYS_fspick),
    ("init_module", libc::SYS_init_module),
    ("finit_module", libc::SYS_finit_module),
    ("delete_module", libc::SYS_delete_module),
    ("kexec_load", libc::SYS_kexec_load),
    ("kexec_file_load", libc::SYS_kexec_file_load),
    ("reboot", libc::SYS_reboot),
    ("swapon", libc::SYS_swapon),
    ("swapoff", libc::SYS_swapoff),
    ("acct", libc::SYS_acct),
    ("ptrace", libc::SYS_ptrace),
    ("process_vm_readv", libc::SYS_process_vm_readv),
    ("process_vm_writev", libc::SYS_process_vm_writev),
    ("setns", libc::SYS_setns),
    ("unshare", libc::SYS_unshare),
    ("open_by_handle_at", libc::SYS_open_by_handle_at),
    ("name_to_handle_at", libc::SYS_name_to_handle_at),
    ("settimeofday", libc::SYS_settimeofday),
    ("clock_settime", libc::SYS_clock_settime),
    ("clock_adjtime", libc::SYS_clock_adjtime),
    ("adjtimex", libc::SYS_adjtimex),
    ("sethostname", libc::SYS_sethostname),
    ("setdomainname", libc::SYS_setdomainname),
    ("quotactl", libc::SYS_quotactl),
    ("add_key", libc::SYS_add_key),
    ("request_key", libc::SYS_request_key),
    ("keyctl", libc::SYS_keyctl),
    ("bpf", libc::SYS_bpf),
    ("perf_event_open", libc::SYS_perf_event_open),
    ("userfaultfd", libc::SYS_userfaultfd),
];

fn target_arch() -> Result<TargetArch> {
    if cfg!(target_arch = "x86_64") {
        Ok(TargetArch::x86_64)
    } else if cfg!(target_arch = "aarch64") {
        Ok(TargetArch::aarch64)
    } else if cfg!(target_arch = "riscv64") {
        Ok(TargetArch::riscv64)
    } else {
        Err(SecurityError::UnsupportedArch(std::env::consts::ARCH))
    }
}

/// Install the denylist on every thread of the process. Child processes inherit it.
pub fn apply_seccomp_filters() -> Result<()> {
    let rules = DENIED
        .iter()
        .map(|(_, number)| (*number, Vec::new()))
        .collect::<BTreeMap<_, _>>();
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(DENIED_ERRNO),
        target_arch()?,
    )?;
    let program: BpfProgram = filter.try_into()?;
    // Any thread that already exists, such as a logging worker, must be filtered too.
    apply_filter_all_threads(&program)?;
    info!(
        denied = DENIED.len(),
        "seccomp denylist applied to all threads"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::sync::mpsc;

    use nix::errno::Errno;
    use nix::sched::{CloneFlags, unshare};

    use super::{DENIED, apply_seccomp_filters};

    const MODE: &str = "HARBORSHIELD_SECCOMP_TEST_MODE";
    const TEST: &str = "security::seccomp::tests::denylist_blocks_every_thread";

    #[test]
    fn denied_syscalls_are_unique() {
        let mut numbers: Vec<_> = DENIED.iter().map(|(_, number)| *number).collect();
        numbers.sort_unstable();
        numbers.dedup();
        assert_eq!(numbers.len(), DENIED.len());
    }

    /// Runs as root: as a control child `unshare` must work unfiltered, and as a filtered
    /// child it must fail with EPERM on a thread that existed before the filter.
    #[test]
    #[ignore = "requires root; runs in the e2e sandbox"]
    fn denylist_blocks_every_thread() {
        match std::env::var(MODE).as_deref() {
            Ok("control") => {
                unshare(CloneFlags::CLONE_NEWUTS).expect("unshare works without the filter");
            }
            Ok("filtered") => {
                let (go, wait) = mpsc::channel::<()>();
                let earlier = std::thread::spawn(move || {
                    wait.recv().expect("signal from the main thread");
                    unshare(CloneFlags::CLONE_NEWUTS)
                });
                apply_seccomp_filters().expect("apply the filter");
                assert_eq!(unshare(CloneFlags::CLONE_NEWUTS), Err(Errno::EPERM));
                go.send(()).expect("wake the earlier thread");
                let result = earlier.join().expect("earlier thread");
                assert_eq!(result, Err(Errno::EPERM));
                // Ordinary work still runs under the filter.
                std::fs::read_to_string("/proc/self/status").expect("read a file");
            }
            _ => {
                for mode in ["control", "filtered"] {
                    let status = Command::new(std::env::current_exe().expect("test binary"))
                        .args(["--exact", TEST, "--ignored", "--test-threads=1"])
                        .env(MODE, mode)
                        .status()
                        .expect("run child");
                    assert!(status.success(), "{mode} child failed: {status}");
                }
            }
        }
    }
}
