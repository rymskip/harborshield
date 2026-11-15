use bon::Builder;
use serde::{Deserialize, Serialize};

/// A managed container as persisted: its id and current name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Builder)]
pub struct ContainerIdentifiers {
    pub id: String,
    pub name: String,
}
