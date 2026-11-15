use std::collections::HashMap;

use tracing::warn;

pub const COMPOSE_PROJECT_LABEL: &str = "com.docker.compose.project";
pub const COMPOSE_SERVICE_LABEL: &str = "com.docker.compose.service";
pub const COMPOSE_CONTAINER_NUMBER_LABEL: &str = "com.docker.compose.container-number";

/// What Docker Compose's labels say about a container.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ComposeInfo {
    pub project: Option<String>,
    pub service: Option<String>,
    pub container_number: Option<u32>,
}

impl ComposeInfo {
    pub fn from_labels(labels: &HashMap<String, String>) -> Self {
        let container_number = labels
            .get(COMPOSE_CONTAINER_NUMBER_LABEL)
            .and_then(|raw| match raw.parse() {
                Ok(number) => Some(number),
                Err(error) => {
                    warn!(%raw, %error, "unparseable compose container number; ignoring it");
                    None
                }
            });
        Self {
            project: labels.get(COMPOSE_PROJECT_LABEL).cloned(),
            service: labels.get(COMPOSE_SERVICE_LABEL).cloned(),
            container_number,
        }
    }

    /// Names rules may use for this container: the service, and its project-qualified and
    /// numbered forms.
    pub fn generate_aliases(&self) -> Vec<String> {
        let Some(service) = &self.service else {
            return Vec::new();
        };
        let mut aliases = vec![service.clone()];
        if let Some(project) = &self.project {
            aliases.push(format!("{service}.{project}"));
            aliases.push(format!("{project}_{service}"));
        }
        if let Some(number) = self.container_number.filter(|number| *number > 1) {
            aliases.push(format!("{service}_{number}"));
            if let Some(project) = &self.project {
                aliases.push(format!("{project}_{service}_{number}"));
            }
        }
        aliases
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{
        COMPOSE_CONTAINER_NUMBER_LABEL, COMPOSE_PROJECT_LABEL, COMPOSE_SERVICE_LABEL, ComposeInfo,
    };

    fn labels(entries: &[(&str, &str)]) -> HashMap<String, String> {
        entries
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn reads_project_service_and_number() {
        let info = ComposeInfo::from_labels(&labels(&[
            (COMPOSE_PROJECT_LABEL, "shop"),
            (COMPOSE_SERVICE_LABEL, "web"),
            (COMPOSE_CONTAINER_NUMBER_LABEL, "2"),
        ]));
        assert_eq!(
            info,
            ComposeInfo {
                project: Some("shop".to_owned()),
                service: Some("web".to_owned()),
                container_number: Some(2),
            }
        );
    }

    #[test]
    fn an_unparseable_number_is_ignored() {
        let info = ComposeInfo::from_labels(&labels(&[(COMPOSE_CONTAINER_NUMBER_LABEL, "two")]));
        assert_eq!(info.container_number, None);
    }

    #[test]
    fn aliases_cover_service_project_and_number() {
        let info = ComposeInfo {
            project: Some("shop".to_owned()),
            service: Some("web".to_owned()),
            container_number: Some(2),
        };
        assert_eq!(
            info.generate_aliases(),
            vec!["web", "web.shop", "shop_web", "web_2", "shop_web_2"]
        );
    }

    #[test]
    fn the_first_replica_gets_no_numbered_alias() {
        let info = ComposeInfo {
            project: Some("shop".to_owned()),
            service: Some("db".to_owned()),
            container_number: Some(1),
        };
        assert_eq!(info.generate_aliases(), vec!["db", "db.shop", "shop_db"]);
    }

    #[test]
    fn a_container_outside_compose_has_no_aliases() {
        assert!(ComposeInfo::default().generate_aliases().is_empty());
    }
}
