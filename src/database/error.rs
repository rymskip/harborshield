use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("could not open the database at {}", path.display())]
    Open {
        path: PathBuf,
        #[source]
        source: sqlx::Error,
    },

    #[error("could not migrate the database")]
    Migrate(#[from] sqlx::migrate::MigrateError),

    #[error("database query failed: {operation}")]
    Query {
        operation: &'static str,
        #[source]
        source: sqlx::Error,
    },
}
