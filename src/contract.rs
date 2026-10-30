use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const MAX_INPUT: usize = 65_536;
pub const MAX_CHECKS: usize = 64;
pub const MAX_TEXT: usize = 128;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Repository {
    pub provider: String,
    pub id: String,
    pub commit: String,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRef {
    pub id: String,
    pub digest: String,
    pub sequence: u64,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Stage {
    pub id: String,
    pub attempt: u32,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub timeout_seconds: u32,
    pub output_bytes: u32,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    pub repository: Repository,
    pub run_id: String,
    pub plan_id: String,
    pub mode: String,
    pub policy: PolicyRef,
    pub categories: Vec<String>,
    pub expected_checks: Vec<String>,
    pub stage: Stage,
    pub target_scope: String,
    pub limits: Limits,
    pub authorization_refs: Vec<String>,
    pub evidence_version: u32,
}
fn token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_TEXT
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn list(items: &[String]) -> bool {
    !items.is_empty()
        && items.len() <= MAX_CHECKS
        && items.iter().all(|s| token(s))
        && items.iter().collect::<BTreeSet<_>>().len() == items.len()
}
impl Manifest {
    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > MAX_INPUT {
            return Err("INPUT_TOO_LARGE");
        }
        let m: Self = serde_json::from_slice(bytes).map_err(|_| "INVALID_JSON_OR_SCHEMA")?;
        if m.version != 1 || m.evidence_version != 1 {
            return Err("UNSUPPORTED_VERSION");
        }
        if m.repository.provider != "github"
            || m.repository.id.is_empty()
            || m.repository.id.len() > 20
            || m.repository.id.starts_with('0')
            || !m.repository.id.bytes().all(|b| b.is_ascii_digit())
            || !hex(&m.repository.commit, 40)
        {
            return Err("INVALID_REPOSITORY_IDENTITY");
        }
        if !token(&m.run_id)
            || !token(&m.plan_id)
            || !token(&m.stage.id)
            || m.stage.attempt == 0
            || !token(&m.policy.id)
            || !hex(&m.policy.digest, 64)
            || m.policy.sequence == 0
        {
            return Err("INVALID_BINDING");
        }
        if !["CI", "LOCAL", "HYBRID"].contains(&m.mode.as_str())
            || !list(&m.categories)
            || !list(&m.expected_checks)
            || !list(&m.authorization_refs)
            || !token(&m.target_scope)
            || m.limits.timeout_seconds == 0
            || m.limits.timeout_seconds > 3600
            || m.limits.output_bytes == 0
            || m.limits.output_bytes > 1_048_576
        {
            return Err("INVALID_SCOPE_OR_LIMITS");
        }
        Ok(m)
    }
}
pub fn input_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
