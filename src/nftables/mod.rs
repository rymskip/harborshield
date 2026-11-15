//! harborshield's firewall: a dedicated `inet harborshield` table, rebuilt from the desired
//! state in one atomic nft transaction per change.
//!
//! [`rules`] and [`plan`] are pure: they turn managed containers into an nft batch.
//! [`kernel`] is the impure boundary that reads the current state and applies batches.

pub mod error;
pub mod kernel;
pub mod plan;
pub mod rules;
