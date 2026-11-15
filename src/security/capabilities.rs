use caps::{CapSet, Capability};
use tracing::{debug, warn};

use super::{Result, SecurityError};

/// Fail unless CAP_NET_ADMIN is both permitted and effective.
pub fn check_required_capabilities() -> Result<()> {
    if let Err(failure) = check_capability(Capability::CAP_NET_ADMIN) {
        warn!("current process capabilities:\n{}", describe_capabilities());
        return Err(failure);
    }
    debug!("all required capabilities are present");
    Ok(())
}

fn check_capability(capability: Capability) -> Result<()> {
    for (set, set_name, remediation) in [
        (
            CapSet::Permitted,
            "permitted",
            "Grant it with `sudo setcap 'cap_net_admin=+ep' /path/to/harborshield`, or run as root.",
        ),
        (
            CapSet::Effective,
            "effective",
            "It is permitted but not effective; keep it effective when dropping privileges.",
        ),
    ] {
        let present = caps::has_cap(None, set, capability).map_err(|source| {
            SecurityError::CapabilityCheck {
                set: set_name,
                source,
            }
        })?;
        if !present {
            return Err(SecurityError::MissingCapability {
                capability: format!("{capability:?}"),
                set: set_name,
                remediation,
            });
        }
    }
    Ok(())
}

/// The process's capability sets, for diagnosing a failed check.
pub fn describe_capabilities() -> String {
    [
        ("Permitted", CapSet::Permitted),
        ("Effective", CapSet::Effective),
        ("Inheritable", CapSet::Inheritable),
    ]
    .iter()
    .map(|(name, set)| match caps::read(None, *set) {
        Ok(held) if held.is_empty() => format!("{name} capabilities: (none)"),
        Ok(held) => {
            let names: Vec<String> = held
                .iter()
                .map(|capability| format!("{capability:?}"))
                .collect();
            format!("{name} capabilities: {}", names.join(", "))
        }
        Err(failure) => format!("{name} capabilities: (could not read: {failure})"),
    })
    .collect::<Vec<_>>()
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::{SecurityError, check_required_capabilities, describe_capabilities};

    #[test]
    fn describes_each_capability_set() {
        let description = describe_capabilities();
        for set in ["Permitted", "Effective", "Inheritable"] {
            assert!(
                description.contains(&format!("{set} capabilities:")),
                "{description}"
            );
        }
    }

    #[test]
    #[ignore = "requires root or CAP_NET_ADMIN; runs in the e2e sandbox"]
    fn passes_with_cap_net_admin() {
        check_required_capabilities().expect("CAP_NET_ADMIN is held");
    }

    #[test]
    fn a_failed_check_names_what_is_missing() {
        // Unprivileged runs must fail with a capability error; privileged runs pass.
        if let Err(failure) = check_required_capabilities() {
            assert!(matches!(
                failure,
                SecurityError::MissingCapability { .. } | SecurityError::CapabilityCheck { .. }
            ));
        }
    }
}
