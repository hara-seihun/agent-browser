#[allow(dead_code)]
pub(crate) mod a11y;
#[allow(dead_code)]
pub(crate) mod actions;
#[allow(dead_code)]
pub(crate) mod auth;
pub(crate) mod auth_export;
#[cfg(test)]
mod auth_export_tests;
#[allow(dead_code)]
pub(crate) mod auth_fill;
#[allow(dead_code)]
pub(crate) mod browser;
#[allow(dead_code)]
pub mod cdp;
#[allow(dead_code)]
pub(crate) mod cookies;
#[allow(dead_code)]
pub mod daemon;
#[allow(dead_code)]
pub(crate) mod diff;
#[cfg(test)]
mod disabled_click_tests;
pub(crate) mod downloads;
#[allow(dead_code)]
pub(crate) mod element;
#[allow(dead_code)]
pub(crate) mod inspect_server;
#[allow(dead_code)]
pub(crate) mod interaction;
#[allow(dead_code)]
pub(crate) mod network;
pub(crate) mod payment_errors;
#[allow(dead_code)]
pub(crate) mod policy;
#[allow(dead_code)]
pub(crate) mod providers;
#[allow(dead_code)]
pub(crate) mod react;
#[allow(dead_code)]
pub mod recording;
#[allow(dead_code)]
pub(crate) mod screenshot;
#[cfg(test)]
mod observation_inventory_tests;
#[allow(dead_code)]
pub(crate) mod snapshot;
#[allow(dead_code)]
pub mod state;
#[allow(dead_code)]
pub(crate) mod storage;
#[allow(dead_code)]
pub mod stream;
#[allow(dead_code)]
pub(crate) mod tab_binding;
#[allow(dead_code)]
pub(crate) mod tab_state;
#[cfg(test)]
mod tab_state_tests;
#[allow(dead_code)]
pub(crate) mod tracing;
#[allow(dead_code)]
pub(crate) mod webdriver;
#[allow(dead_code)]
pub(crate) mod webmcp;

#[cfg(test)]
mod e2e_tests;
#[cfg(test)]
mod lifecycle_fixture;
#[cfg(test)]
mod parity_tests;
#[cfg(test)]
mod work_readiness_tests;
