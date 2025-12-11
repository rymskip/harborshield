use bon::Builder;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, Default, Serialize, Builder)]
pub struct ConfigVerdict {
    #[serde(default)]
    #[builder(default)]
    pub chain: String,
    #[serde(default)]
    #[builder(default)]
    pub queue: u16,
    #[serde(default)]
    #[builder(default)]
    pub input_est_queue: u16,
    #[serde(default)]
    #[builder(default)]
    pub output_est_queue: u16,

    #[serde(skip)]
    #[builder(default = false)]
    pub drop: bool,
}
// Custom Deserialize for ConfigVerdict with validation
impl<'de> Deserialize<'de> for ConfigVerdict {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct TempConfigVerdict {
            #[serde(default)]
            chain: String,
            #[serde(default)]
            queue: u16,
            #[serde(default)]
            input_est_queue: u16,
            #[serde(default)]
            output_est_queue: u16,
            #[serde(skip)]
            drop: bool,
        }

        let temp = TempConfigVerdict::deserialize(deserializer)?;

        // Validate verdict configuration
        if !temp.chain.is_empty() && temp.queue != 0 {
            return Err(serde::de::Error::custom(
                super::ValidationError::InvalidFieldValue {
                    field: "verdict".to_string(),
                    reason: "'chain' and 'queue' are mutually exclusive".to_string(),
                    value: format!("chain: '{}', queue: {}", temp.chain, temp.queue),
                    expected_format: Some("Either 'chain' or 'queue', not both".to_string()),
                },
            ));
        }

        if temp.queue == 0 && temp.input_est_queue != 0 {
            return Err(serde::de::Error::custom(
                super::ValidationError::MissingRequiredField {
                    field: "queue".to_string(),
                    context: "verdict with input_est_queue set".to_string(),
                },
            ));
        }

        if temp.queue == 0 && temp.output_est_queue != 0 {
            return Err(serde::de::Error::custom(
                super::ValidationError::MissingRequiredField {
                    field: "queue".to_string(),
                    context: "verdict with output_est_queue set".to_string(),
                },
            ));
        }

        if temp.input_est_queue == 0 && temp.output_est_queue != 0 {
            return Err(serde::de::Error::custom(
                super::ValidationError::InvalidFieldValue {
                    field: "verdict".to_string(),
                    reason: "'input_est_queue' must be set when 'output_est_queue' is set"
                        .to_string(),
                    value: format!("output_est_queue: {}", temp.output_est_queue),
                    expected_format: Some(
                        "Both input_est_queue and output_est_queue, or neither".to_string(),
                    ),
                },
            ));
        }

        if temp.output_est_queue == 0 && temp.input_est_queue != 0 {
            return Err(serde::de::Error::custom(
                super::ValidationError::InvalidFieldValue {
                    field: "verdict".to_string(),
                    reason: "'output_est_queue' must be set when 'input_est_queue' is set"
                        .to_string(),
                    value: format!("input_est_queue: {}", temp.input_est_queue),
                    expected_format: Some(
                        "Both input_est_queue and output_est_queue, or neither".to_string(),
                    ),
                },
            ));
        }

        Ok(ConfigVerdict {
            chain: temp.chain,
            queue: temp.queue,
            input_est_queue: temp.input_est_queue,
            output_est_queue: temp.output_est_queue,
            drop: temp.drop,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verdict_default() {
        let verdict: ConfigVerdict = serde_yaml::from_str("{}").unwrap();
        assert!(verdict.chain.is_empty());
        assert_eq!(verdict.queue, 0);
        assert_eq!(verdict.input_est_queue, 0);
        assert_eq!(verdict.output_est_queue, 0);
    }

    #[test]
    fn test_verdict_chain_only() {
        let verdict: ConfigVerdict = serde_yaml::from_str("chain: my-chain").unwrap();
        assert_eq!(verdict.chain, "my-chain");
        assert_eq!(verdict.queue, 0);
    }

    #[test]
    fn test_verdict_queue_only() {
        let verdict: ConfigVerdict = serde_yaml::from_str("queue: 100").unwrap();
        assert!(verdict.chain.is_empty());
        assert_eq!(verdict.queue, 100);
    }

    #[test]
    fn test_verdict_chain_and_queue_exclusive() {
        let result: Result<ConfigVerdict, _> = serde_yaml::from_str("chain: test\nqueue: 100");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("mutually exclusive"));
    }

    #[test]
    fn test_verdict_input_est_requires_queue() {
        let result: Result<ConfigVerdict, _> = serde_yaml::from_str("input_est_queue: 200");
        assert!(result.is_err());
    }

    #[test]
    fn test_verdict_output_est_requires_queue() {
        let result: Result<ConfigVerdict, _> = serde_yaml::from_str("output_est_queue: 200");
        assert!(result.is_err());
    }

    #[test]
    fn test_verdict_symmetric_est_queues_both_required() {
        // Only input_est_queue without output_est_queue should fail
        let result: Result<ConfigVerdict, _> = serde_yaml::from_str("queue: 100\ninput_est_queue: 200");
        assert!(result.is_err());
    }

    #[test]
    fn test_verdict_full_queue_config() {
        let verdict: ConfigVerdict = serde_yaml::from_str("queue: 100\ninput_est_queue: 200\noutput_est_queue: 300").unwrap();
        assert_eq!(verdict.queue, 100);
        assert_eq!(verdict.input_est_queue, 200);
        assert_eq!(verdict.output_est_queue, 300);
    }
}
