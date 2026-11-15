use bon::Builder;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, Default, Serialize, Builder)]
pub struct LocalRules {
    #[serde(default)]
    #[builder(default)]
    pub allow: bool,
    #[serde(default)]
    #[builder(default)]
    pub log_prefix: String,
    #[serde(default)]
    #[builder(default)]
    pub verdict: super::ConfigVerdict,
    #[serde(default = "default_true")]
    #[builder(default = true)]
    pub include_gateway_ips: bool,
}

// Custom Deserialize for LocalRules with validation
impl<'de> Deserialize<'de> for LocalRules {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct TempLocalRules {
            #[serde(default)]
            allow: bool,
            #[serde(default)]
            log_prefix: String,
            #[serde(default)]
            verdict: super::ConfigVerdict,
            #[serde(default = "super::default_true")]
            include_gateway_ips: bool,
        }

        let temp = TempLocalRules::deserialize(deserializer)?;

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

        Ok(LocalRules {
            allow: temp.allow,
            log_prefix: temp.log_prefix,
            verdict: temp.verdict,
            include_gateway_ips: temp.include_gateway_ips,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::LocalRules;

    #[test]
    fn test_local_rules_default() {
        let rules: LocalRules = serde_saphyr::from_str("{}").unwrap();
        assert!(!rules.allow);
        assert!(rules.log_prefix.is_empty());
        assert!(rules.include_gateway_ips);
    }

    #[test]
    fn test_local_rules_allow_true() {
        let rules: LocalRules = serde_saphyr::from_str("allow: true").unwrap();
        assert!(rules.allow);
    }

    #[test]
    fn test_local_rules_log_prefix_valid() {
        let rules: LocalRules =
            serde_saphyr::from_str("allow: true\nlog_prefix: 'test-prefix'").unwrap();
        assert_eq!(rules.log_prefix, "test-prefix");
    }

    #[test]
    fn test_local_rules_log_prefix_too_long() {
        let long_prefix = "a".repeat(65);
        let yaml = format!("allow: true\nlog_prefix: '{}'", long_prefix);
        let result: std::result::Result<LocalRules, _> = serde_saphyr::from_str(&yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_local_rules_include_gateway_ips_false() {
        let rules: LocalRules = serde_saphyr::from_str("include_gateway_ips: false").unwrap();
        assert!(!rules.include_gateway_ips);
    }

    #[test]
    fn test_local_rules_reject_unknown_fields() {
        let result: std::result::Result<LocalRules, _> = serde_saphyr::from_str("alow: true");
        assert!(result.is_err());
    }
}
