use caps::{CapSet, Capability};
use tracing::{debug, warn};

use super::{Result, SecurityError};

/// Check if the current process has the required capabilities
pub fn check_required_capabilities() -> Result<()> {
    debug!("Checking for required capabilities");

    // Check for CAP_NET_ADMIN capability
    if let Err(e) = check_capability(Capability::CAP_NET_ADMIN) {
        // Log current capabilities for debugging
        if let Ok(cap_list) = list_current_capabilities() {
            warn!("Current process capabilities:\n{}", cap_list);
        }
        return Err(e);
    }

    debug!("All required capabilities are present");
    Ok(())
}

/// Check if a specific capability is available in both permitted and effective sets
fn check_capability(cap: Capability) -> Result<()> {
    let cap_name = format!("{:?}", cap);

    // Check if the capability is in the permitted set
    let has_permitted = caps::has_cap(None, CapSet::Permitted, cap).map_err(|e| {
        SecurityError::CapabilityCheck {
            capability: cap_name.clone(),
            message: format!("Failed to check permitted capabilities: {}", e),
        }
    })?;

    if !has_permitted {
        return Err(SecurityError::MissingCapability {
            capability: cap_name.clone(),
            capability_set: "Permitted".to_string(),
            remediation: format!(
                "Grant the capability using: sudo setcap 'cap_net_admin=+ep' /path/to/harborshield\n\
                 Or run with appropriate privileges (e.g., as root or with sudo)"
            ),
        });
    }

    // Check if the capability is in the effective set
    let has_effective = caps::has_cap(None, CapSet::Effective, cap).map_err(|e| {
        SecurityError::CapabilityCheck {
            capability: cap_name.clone(),
            message: format!("Failed to check effective capabilities: {}", e),
        }
    })?;

    if !has_effective {
        return Err(SecurityError::MissingCapability {
            capability: cap_name.clone(),
            capability_set: "Effective".to_string(),
            remediation: format!(
                "The capability is in the permitted set but not in the effective set.\n\
                 This might be due to the process dropping privileges.\n\
                 Ensure the capability is preserved when dropping privileges."
            ),
        });
    }

    debug!(
        "Capability {} is present in both permitted and effective sets",
        cap_name
    );
    Ok(())
}

/// Get a human-readable list of all current capabilities
pub fn list_current_capabilities() -> Result<String> {
    let mut output = String::new();

    // List all capability sets
    let sets = [
        ("Permitted", CapSet::Permitted),
        ("Effective", CapSet::Effective),
        ("Inheritable", CapSet::Inheritable),
    ];

    for (name, set) in &sets {
        match caps::read(None, *set) {
            Ok(caps) => {
                output.push_str(&format!("{} capabilities: ", name));
                if caps.is_empty() {
                    output.push_str("(none)");
                } else {
                    let cap_names: Vec<String> = caps.iter().map(|c| format!("{:?}", c)).collect();
                    output.push_str(&cap_names.join(", "));
                }
                output.push('\n');
            }
            Err(e) => {
                output.push_str(&format!("{} capabilities: (error reading: {})\n", name, e));
            }
        }
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_current_capabilities_returns_ok() {
        // This test verifies that list_current_capabilities can be called
        // and returns a valid result (the content depends on the execution context)
        let result = list_current_capabilities();
        assert!(result.is_ok());
        let output = result.unwrap();
        // The output should contain the capability set names
        assert!(output.contains("Permitted capabilities:"));
        assert!(output.contains("Effective capabilities:"));
        assert!(output.contains("Inheritable capabilities:"));
    }

    #[test]
    fn test_list_current_capabilities_format() {
        let result = list_current_capabilities().unwrap();
        // Should have newlines between each capability set
        let lines: Vec<&str> = result.lines().collect();
        assert!(lines.len() >= 3);
    }

    #[test]
    #[ignore = "Requires root or CAP_NET_ADMIN capability"]
    fn test_check_required_capabilities_with_cap_net_admin() {
        // This test only passes when run with CAP_NET_ADMIN
        let result = check_required_capabilities();
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_required_capabilities_error_type() {
        // When running without CAP_NET_ADMIN, we should get a MissingCapability error
        // or a CapabilityCheck error if we can't read capabilities at all
        let result = check_required_capabilities();
        if result.is_err() {
            let err = result.unwrap_err();
            assert!(matches!(
                err,
                SecurityError::MissingCapability { .. } | SecurityError::CapabilityCheck { .. }
            ));
        }
        // If it succeeds, the test is running with elevated privileges
    }
}
