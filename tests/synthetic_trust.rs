//! Synthetic nonproduction keys; these bytes are public test data, never operational secrets.
use ed25519_dalek::{Signer, SigningKey};
use security_assurance_runner::{
    contract::input_digest,
    trust::{POLICY_TYPE, Refusal, SyntheticTrust, pae, verify_synthetic_policy},
};
use serde_json::{Value, json};

fn policy() -> Value {
    json!({"version":1,"purpose":"policy","issuer":"fixture-owner","role":"owner","provider":"github","repository_id":"123","policy_id":"p1","policy_digest":input_digest(b"synthetic policy"),"sequence":2,"not_before":10,"expires":200})
}
fn key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}
fn sign(value: &Value, signer: &SigningKey) -> (Vec<u8>, Vec<u8>) {
    let bytes = serde_json::to_vec(value).unwrap();
    let sig = signer.sign(&pae(POLICY_TYPE, &bytes)).to_bytes().to_vec();
    (bytes, sig)
}
fn verify(value: &Value, signer: &SigningKey, trusted: bool) -> Result<(), Refusal> {
    let owner = key().verifying_key();
    let (bytes, sig) = sign(value, signer);
    let ctx = SyntheticTrust {
        key: trusted.then_some(&owner),
        issuer: "fixture-owner",
        repository_id: "123",
        policy_id: "p1",
        minimum_sequence: 2,
        now: 100,
        freshness_current: true,
        revoked: false,
    };
    verify_synthetic_policy(&ctx, POLICY_TYPE, &bytes, &sig, b"synthetic policy")
        .map(|v| assert!(v.test_only))
}
#[test]
fn dsse_pae_known_vector() {
    assert_eq!(pae("a", b"hello"), b"DSSEv1 1 a 5 hello");
}
#[test]
fn fixture_policy_verifies_and_untrusted_key_pair_fails() {
    assert_eq!(verify(&policy(), &key(), true), Ok(()));
    assert_eq!(verify(&policy(), &key(), false), Err(Refusal::MissingRoot));
    assert_eq!(
        verify(&policy(), &SigningKey::from_bytes(&[8; 32]), true),
        Err(Refusal::InvalidSignature)
    );
}
#[test]
fn wrong_claims_are_rejected_even_when_signed() {
    for (field, value, reason) in [
        ("purpose", json!("active"), Refusal::WrongPurpose),
        ("role", json!("agent"), Refusal::WrongIssuer),
        ("issuer", json!("attacker"), Refusal::WrongIssuer),
        ("repository_id", json!("124"), Refusal::WrongRepository),
        ("policy_digest", json!("bad"), Refusal::WrongPolicy),
        ("version", json!(2), Refusal::UnsupportedVersion),
        ("sequence", json!(1), Refusal::OldSequence),
        ("not_before", json!(101), Refusal::OutsideValidity),
        ("expires", json!(100), Refusal::OutsideValidity),
    ] {
        let mut p = policy();
        p[field] = value;
        assert_eq!(verify(&p, &key(), true), Err(reason), "{field}");
    }
}
#[test]
fn signatures_types_freshness_and_duplicate_fields_are_rejected() {
    let vk = key().verifying_key();
    let (bytes, sig) = sign(&policy(), &key());
    let mut c = SyntheticTrust {
        key: Some(&vk),
        issuer: "fixture-owner",
        repository_id: "123",
        policy_id: "p1",
        minimum_sequence: 2,
        now: 100,
        freshness_current: true,
        revoked: false,
    };
    assert_eq!(
        verify_synthetic_policy(&c, "other", &bytes, &sig, b"synthetic policy").unwrap_err(),
        Refusal::WrongType
    );
    assert_eq!(
        verify_synthetic_policy(&c, POLICY_TYPE, &bytes, &[0; 64], b"synthetic policy")
            .unwrap_err(),
        Refusal::InvalidSignature
    );
    let mut changed = bytes.clone();
    changed.push(b' ');
    assert_eq!(
        verify_synthetic_policy(&c, POLICY_TYPE, &changed, &sig, b"synthetic policy").unwrap_err(),
        Refusal::InvalidSignature
    );
    c.revoked = true;
    assert_eq!(
        verify_synthetic_policy(&c, POLICY_TYPE, &bytes, &sig, b"synthetic policy").unwrap_err(),
        Refusal::Revoked
    );
    c.revoked = false;
    c.freshness_current = false;
    assert_eq!(
        verify_synthetic_policy(&c, POLICY_TYPE, &bytes, &sig, b"synthetic policy").unwrap_err(),
        Refusal::StaleFreshness
    );
    c.freshness_current = true;
    let duplicate = String::from_utf8(bytes)
        .unwrap()
        .replacen("\"version\":1", "\"version\":1,\"version\":1", 1)
        .into_bytes();
    let signed = key().sign(&pae(POLICY_TYPE, &duplicate)).to_bytes();
    assert_eq!(
        verify_synthetic_policy(&c, POLICY_TYPE, &duplicate, &signed, b"synthetic policy")
            .unwrap_err(),
        Refusal::InvalidStatement
    );
}
