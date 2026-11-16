//! CDP wire types, cancellable transport and per-command observation deadlines.
pub mod client;
pub mod types;
pub mod observation_progress;
pub const SENSITIVE_OUTPUT_UNSUPPORTED: &str = "SENSITIVE_OUTPUT_UNSUPPORTED";
