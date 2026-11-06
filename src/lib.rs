//! Bounded, offline prototype. No production trust root or scanner is implemented.
pub mod contract;
pub mod evaluation;
pub mod execution_witness;
pub mod gitleaks_adapter;
pub mod gitleaks_fixture;
#[cfg(target_os = "linux")]
pub mod inert_pipeline;
pub mod reconcile;
pub mod trust;
