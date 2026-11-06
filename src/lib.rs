//! Bounded, offline prototype. No production trust root or scanner is implemented.
pub mod contract;
pub mod evaluation;
pub mod execution_witness;
#[cfg(target_os = "linux")]
pub mod inert_pipeline;
pub mod gitleaks_adapter;
pub mod gitleaks_fixture;
pub mod reconcile;
pub mod trust;
