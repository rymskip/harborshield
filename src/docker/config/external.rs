use bon::Builder;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, Default, Serialize, Builder)]
pub struct ExternalRules {
    #[serde(default)]
    #[builder(default)]
    pub allow: bool,
    #[serde(default)]
    #[builder(default)]
    pub log_prefix: String,
    #[serde(default)]
    #[builder(default)]
    pub ips: Vec<super::AddrOrRange>,
    #[serde(default)]
    #[builder(default)]
    pub verdict: super::ConfigVerdict,
}

// Custom Deserialize for ExternalRules with validation
impl<'de> Deserialize<'de> for ExternalRules {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct TempExternalRules {
            #[serde(default)]
            allow: bool,
            #[serde(default)]
            log_prefix: String,
            #[serde(default)]
            ips: Vec<super::AddrOrRange>,
            #[serde(default)]
            verdict: super::ConfigVerdict,
        }

        let temp = TempExternalRules::deserialize(deserializer)?;

        // Validate log prefix if present
        if temp.allow && temp.log_prefix.len() > 64 {
            return Err(serde::de::Error::custom(
                super::ValidationError::InvalidFieldValue {
                    field: "log_prefix".to_string(),
                    reason: "Log prefix too long (max 64 characters)".to_string(),
                    value: temp.log_prefix.clone(),
                    expected_format: Some("String with max 64 characters".to_string()),
                },
            ));
        }

        Ok(ExternalRules {
            allow: temp.allow,
            log_prefix: temp.log_prefix,
            ips: temp.ips,
            verdict: temp.verdict,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::ExternalRules;

    #[test]
    fn test_external_rules_default() {
        let rules: ExternalRules = serde_saphyr::from_str("{}").unwrap();
        assert!(!rules.allow);
        assert!(rules.log_prefix.is_empty());
        assert!(rules.ips.is_empty());
    }

    #[test]
    fn test_external_rules_allow_true() {
        let rules: ExternalRules = serde_saphyr::from_str("allow: true").unwrap();
        assert!(rules.allow);
    }

    #[test]
    fn test_external_rules_log_prefix_valid() {
        let rules: ExternalRules =
            serde_saphyr::from_str("allow: true\nlog_prefix: 'test-prefix'").unwrap();
        assert_eq!(rules.log_prefix, "test-prefix");
    }

    #[test]
    fn test_external_rules_log_prefix_too_long() {
        let long_prefix = "a".repeat(65);
        let yaml = format!("allow: true\nlog_prefix: '{}'", long_prefix);
        let result: std::result::Result<ExternalRules, _> = serde_saphyr::from_str(&yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_external_rules_with_single_ip() {
        let rules: ExternalRules =
            serde_saphyr::from_str("allow: true\nips:\n  - 192.168.1.1").unwrap();
        assert_eq!(rules.ips.len(), 1);
    }

    #[test]
    fn test_external_rules_with_multiple_ips() {
        let rules: ExternalRules =
            serde_saphyr::from_str("allow: true\nips:\n  - 192.168.1.1\n  - 10.0.0.1").unwrap();
        assert_eq!(rules.ips.len(), 2);
    }

    #[test]
    fn test_external_rules_with_cidr() {
        let rules: ExternalRules =
            serde_saphyr::from_str("allow: true\nips:\n  - 192.168.0.0/24").unwrap();
        assert_eq!(rules.ips.len(), 1);
        assert!(matches!(rules.ips[0], super::super::AddrOrRange::Net(_)));
    }

    #[test]
    fn test_external_rules_reject_unknown_fields() {
        // A misspelt allowlist must not silently open the port to every source.
        let result: std::result::Result<ExternalRules, _> =
            serde_saphyr::from_str("allow: true\nip:\n  - 192.168.0.1");
        assert!(result.is_err());
    }
}
