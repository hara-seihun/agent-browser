//! Browser runtime and command semantics, independent of CLI presentation.
// Daemon cancellation and protected observation compose deeply nested async futures.
#![recursion_limit = "256"]
pub mod ca_bundle;
pub mod color;
pub mod commands;
pub mod connection;
pub mod flags;
pub mod install;
pub mod native;
pub mod plugins;
pub mod read;
pub mod validation;
#[cfg(test)]
mod test_utils;
