//! Nonproduction verification of DSSE PAE bytes under an explicitly supplied fixture root.
//! No root enrollment or operational authorization exists in this module.
use crate::contract::{MAX_INPUT, input_digest};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;

pub const POLICY_TYPE: &str = "application/vnd.sar.synthetic-policy.v1+json";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyStatement {
    pub version: u32,
    pub purpose: String,
    pub issuer: String,
    pub role: String,
    pub provider: String,
    pub repository_id: String,
    pub policy_id: String,
    pub policy_digest: String,
    pub sequence: u64,
    pub not_before: u64,
    pub expires: u64,
}

/// Values must originate from controlled fixture setup, never from the request being verified.
pub struct SyntheticTrust<'a> {
    pub key: Option<&'a VerifyingKey>,
    pub issuer: &'a str,
    pub repository_id: &'a str,
    pub policy_id: &'a str,
    pub minimum_sequence: u64,
    pub now: u64,
    pub freshness_current: bool,
    pub revoked: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    MissingRoot,
    StaleFreshness,
    Revoked,
    InvalidSignature,
    WrongType,
    InvalidStatement,
    UnsupportedVersion,
    WrongPurpose,
    WrongIssuer,
    WrongRepository,
    WrongPolicy,
    OldSequence,
    OutsideValidity,
}

#[derive(Debug)]
pub struct SyntheticVerifiedPolicy {
    pub(crate) statement: PolicyStatement,
}
impl SyntheticVerifiedPolicy {
    pub fn test_only(&self) -> bool {
        true
    }
}

/// DSSE v1 pre-authentication encoding: lengths are UTF-8 byte lengths.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut encoded = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    )
    .into_bytes();
    encoded.extend_from_slice(payload);
    encoded
}

/// Verify exact payload bytes with a preconfigured test context. No key is read from the payload.
pub fn verify_synthetic_policy(
    context: &SyntheticTrust<'_>,
    payload_type: &str,
    payload: &[u8],
    signature: &[u8],
    policy_bytes: &[u8],
) -> Result<SyntheticVerifiedPolicy, Refusal> {
    let key = context.key.ok_or(Refusal::MissingRoot)?;
    if !context.freshness_current {
        return Err(Refusal::StaleFreshness);
    }
    if context.revoked {
        return Err(Refusal::Revoked);
    }
    if payload_type != POLICY_TYPE {
        return Err(Refusal::WrongType);
    }
    if payload.len() > MAX_INPUT || policy_bytes.len() > MAX_INPUT {
        return Err(Refusal::InvalidStatement);
    }
    let sig = Signature::from_slice(signature).map_err(|_| Refusal::InvalidSignature)?;
    if key.is_weak()
        || key
            .verify_strict(&pae(payload_type, payload), &sig)
            .is_err()
    {
        return Err(Refusal::InvalidSignature);
    }
    let s: PolicyStatement =
        serde_json::from_slice(payload).map_err(|_| Refusal::InvalidStatement)?;
    if s.version != 1 {
        return Err(Refusal::UnsupportedVersion);
    }
    if s.purpose != "policy" {
        return Err(Refusal::WrongPurpose);
    }
    if s.role != "owner" || s.issuer != context.issuer {
        return Err(Refusal::WrongIssuer);
    }
    if s.provider != "github" || s.repository_id != context.repository_id {
        return Err(Refusal::WrongRepository);
    }
    if s.policy_id != context.policy_id || s.policy_digest != input_digest(policy_bytes) {
        return Err(Refusal::WrongPolicy);
    }
    if s.sequence < context.minimum_sequence || s.sequence == 0 {
        return Err(Refusal::OldSequence);
    }
    if s.not_before >= s.expires || context.now < s.not_before || context.now >= s.expires {
        return Err(Refusal::OutsideValidity);
    }
    Ok(SyntheticVerifiedPolicy { statement: s })
}
