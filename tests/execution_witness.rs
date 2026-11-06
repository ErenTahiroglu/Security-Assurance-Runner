//! Public, deterministic synthetic keys, never operational trust material.
use ed25519_dalek::{Signer, SigningKey};
use security_assurance_runner::{
    contract::input_digest,
    evaluation::Decision,
    execution_witness::{PLAN_TYPE, Refusal, TestContext, WITNESS_TYPE, verify_test_execution},
    trust::pae,
};
use serde_json::{Value, json};

fn report(file: &str) -> Vec<u8> {
    json!([{"RuleID":"rule-a","File":file,"Fingerprint":"inert","StartLine":1,"EndLine":1,"StartColumn":1,"EndColumn":2,"Secret":"INERT_PRIVATE_MARKER","Match":"INERT_PRIVATE_MARKER"}]).to_string().into_bytes()
}
fn binding() -> Value {
    json!({"repository_id":"123","source_sha":"a".repeat(40),"run_id":"run","stage_id":"stage","attempt":1,"tool_version":"8.30.1","binary_digest":"b".repeat(64),"input_digest":"c".repeat(64),"config_digest":"d".repeat(64)})
}
fn plan() -> Value {
    json!({"version":1,"purpose":"execution-plan","issuer":"owner-fixture","role":"plan-approver","not_before":10,"expires":200,"binding":binding(),"scope":["src/file.txt"],"rules":["rule-a","rule-b"]})
}
fn witness(p: &Value, data: &[u8]) -> Value {
    let plan_bytes = serde_json::to_vec(p).unwrap();
    json!({"version":1,"purpose":"execution-witness","issuer":"observer-fixture","role":"test-observer","not_before":10,"expires":200,"plan_digest":input_digest(&plan_bytes),"binding":binding(),"report_digest":input_digest(data),"report_size":data.len(),"started":true,"execution":"COMPLETE","exit_code":23,"timed_out":false,"errors_or_skips":false})
}
fn check(
    p: &Value,
    w: &Value,
    data: &[u8],
    wrong_key: bool,
    revoked: bool,
) -> Result<security_assurance_runner::execution_witness::TestWitnessReceipt, Refusal> {
    let owner = SigningKey::from_bytes(&[7; 32]);
    let observer = SigningKey::from_bytes(&[8; 32]);
    let attacker = SigningKey::from_bytes(&[9; 32]);
    let vk = owner.verifying_key();
    let ov = observer.verifying_key();
    let pb = serde_json::to_vec(p).unwrap();
    let wb = serde_json::to_vec(w).unwrap();
    let pin = input_digest(&pb);
    let ps = owner.sign(&pae(PLAN_TYPE, &pb)).to_bytes();
    let ws = if wrong_key {
        attacker.sign(&pae(WITNESS_TYPE, &wb))
    } else {
        observer.sign(&pae(WITNESS_TYPE, &wb))
    }
    .to_bytes();
    let context = TestContext {
        plan_key: &vk,
        witness_key: &ov,
        plan_issuer: "owner-fixture",
        witness_issuer: "observer-fixture",
        expected_plan_digest: &pin,
        now: 100,
        freshness_current: true,
        revoked,
    };
    verify_test_execution(&context, &pb, &ps, &wb, &ws, data)
}
#[test]
fn synthetic_signatures_never_establish_operational_authority() {
    let data = report("src/file.txt");
    let p = plan();
    let w = witness(&p, &data);
    let r = check(&p, &w, &data, false, false).unwrap();
    assert!(
        r.test_only
            && r.plan_statement_verified_by_test_root
            && r.witness_statement_verified_by_test_root
    );
    assert!(
        !r.process_execution_independently_established
            && !r.rule_execution_verified
            && !r.coverage_verified
            && !r.policy_authority_verified
    );
    assert_eq!(r.policy_decision, Decision::Indeterminate);
    assert_eq!(r.matched_test_scope_claims, 1);
    assert!(!format!("{r:?}").contains("INERT_PRIVATE_MARKER"));
    assert!(
        !serde_json::to_string(&r)
            .unwrap()
            .contains("INERT_PRIVATE_MARKER")
    );
}
#[test]
fn bound_mutations_and_untrusted_keys_refuse() {
    let data = report("src/file.txt");
    let p = plan();
    let w = witness(&p, &data);
    assert!(matches!(
        check(&p, &w, &data, true, false),
        Err(Refusal::InvalidSignature)
    ));
    assert!(matches!(
        check(&p, &w, &data, false, true),
        Err(Refusal::StaleOrRevoked)
    ));
    for field in [
        "repository_id",
        "source_sha",
        "run_id",
        "stage_id",
        "tool_version",
        "binary_digest",
        "input_digest",
        "config_digest",
    ] {
        let mut bad = w.clone();
        bad["binding"][field] = json!("modified");
        assert!(
            matches!(
                check(&p, &bad, &data, false, false),
                Err(Refusal::BindingMismatch)
            ),
            "{field}"
        );
    }
    let mut bad = w.clone();
    bad["binding"]["attempt"] = json!(2);
    assert!(matches!(
        check(&p, &bad, &data, false, false),
        Err(Refusal::BindingMismatch)
    ));
    let mut replay = w.clone();
    replay["plan_digest"] = json!("f".repeat(64));
    assert!(matches!(
        check(&p, &replay, &data, false, false),
        Err(Refusal::WrongPlan)
    ));
    let mut wrong = w.clone();
    wrong["purpose"] = json!("policy");
    assert!(matches!(
        check(&p, &wrong, &data, false, false),
        Err(Refusal::WrongAuthority)
    ));
    assert!(matches!(
        check(&p, &w, b"[]", false, false),
        Err(Refusal::ReportMismatch)
    ));
    let mut expired = w.clone();
    expired["expires"] = json!(100);
    assert!(matches!(
        check(&p, &expired, &data, false, false),
        Err(Refusal::OutsideValidity)
    ));
}
#[test]
fn scope_and_incomplete_claims_are_limited() {
    for path in [
        "../outside",
        "/absolute",
        "elsewhere/file.txt",
        "src/%2e%2e/file",
    ] {
        let data = report(path);
        let p = plan();
        let w = witness(&p, &data);
        let r = check(&p, &w, &data, false, false).unwrap();
        assert_eq!(r.matched_test_scope_claims, 0);
        assert_eq!(r.outside_test_scope_claims, 1);
        assert!(!r.coverage_verified);
    }
    let data = report("src/file.txt");
    let p = plan();
    let w = witness(&p, &data);
    for (field, value) in [
        ("execution", json!("CANCELLED")),
        ("timed_out", json!(true)),
        ("errors_or_skips", json!(true)),
        ("started", json!(false)),
    ] {
        let mut bad = w.clone();
        bad[field] = value;
        assert!(matches!(
            check(&p, &bad, &data, false, false),
            Err(Refusal::IncompleteExecution)
        ));
    }
    let mut wrong = w.clone();
    wrong["exit_code"] = json!(0);
    assert!(matches!(
        check(&p, &wrong, &data, false, false),
        Err(Refusal::InvalidReport)
    ));
}

#[test]
fn missing_signature_wrong_root_and_unpinned_plan_refuse() {
    let data = report("src/file.txt");
    let p = plan();
    let w = witness(&p, &data);
    let owner = SigningKey::from_bytes(&[7; 32]);
    let observer = SigningKey::from_bytes(&[8; 32]);
    let attacker = SigningKey::from_bytes(&[9; 32]);
    let vk = owner.verifying_key();
    let ov = observer.verifying_key();
    let pb = serde_json::to_vec(&p).unwrap();
    let wb = serde_json::to_vec(&w).unwrap();
    let pin = input_digest(&pb);
    let ps = owner.sign(&pae(PLAN_TYPE, &pb)).to_bytes();
    let ws = observer.sign(&pae(WITNESS_TYPE, &wb)).to_bytes();
    let mut ctx = TestContext {
        plan_key: &vk,
        witness_key: &ov,
        plan_issuer: "owner-fixture",
        witness_issuer: "observer-fixture",
        expected_plan_digest: &pin,
        now: 100,
        freshness_current: true,
        revoked: false,
    };
    assert!(matches!(
        verify_test_execution(&ctx, &pb, &[], &wb, &ws, &data),
        Err(Refusal::InvalidSignature)
    ));
    let attacker_sig = attacker.sign(&pae(WITNESS_TYPE, &wb)).to_bytes();
    assert!(matches!(
        verify_test_execution(&ctx, &pb, &ps, &wb, &attacker_sig, &data),
        Err(Refusal::InvalidSignature)
    ));
    ctx.expected_plan_digest = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    assert!(matches!(
        verify_test_execution(&ctx, &pb, &ps, &wb, &ws, &data),
        Err(Refusal::WrongPlan)
    ));
    ctx.expected_plan_digest = &pin;
    ctx.freshness_current = false;
    assert!(matches!(
        verify_test_execution(&ctx, &pb, &ps, &wb, &ws, &data),
        Err(Refusal::StaleOrRevoked)
    ));
}

#[test]
fn partial_report_wrong_length_and_unsupported_versions_refuse() {
    let data = report("src/file.txt");
    let p = plan();
    let w = witness(&p, &data);
    assert!(matches!(
        check(&p, &w, b"", false, false),
        Err(Refusal::MissingEvidence)
    ));
    assert!(matches!(
        check(&p, &w, b"[", false, false),
        Err(Refusal::ReportMismatch)
    ));
    let truncated = b"[";
    let truncated_witness = witness(&p, truncated);
    assert!(matches!(
        check(&p, &truncated_witness, truncated, false, false),
        Err(Refusal::InvalidReport)
    ));
    let mut bad = w.clone();
    bad["report_size"] = json!(data.len() + 1);
    assert!(matches!(
        check(&p, &bad, &data, false, false),
        Err(Refusal::ReportMismatch)
    ));
    let mut bad = w.clone();
    bad["version"] = json!(2);
    assert!(matches!(
        check(&p, &bad, &data, false, false),
        Err(Refusal::InvalidStatement)
    ));
    let mut bad = w.clone();
    bad["role"] = json!("owner");
    assert!(matches!(
        check(&p, &bad, &data, false, false),
        Err(Refusal::WrongAuthority)
    ));
    let mut supplied_root = w.clone();
    supplied_root["verification_key"] = json!("claimant-controlled");
    assert!(matches!(
        check(&p, &supplied_root, &data, false, false),
        Err(Refusal::InvalidStatement)
    ));
    let mut new_plan = p.clone();
    new_plan["binding"]["run_id"] = json!("other-run");
    assert!(matches!(
        check(&new_plan, &w, &data, false, false),
        Err(Refusal::WrongPlan)
    ));
    let mut bad_plan = p.clone();
    bad_plan["scope"] = json!(["../outside"]);
    let bad_witness = witness(&bad_plan, &data);
    assert!(matches!(
        check(&bad_plan, &bad_witness, &data, false, false),
        Err(Refusal::InvalidStatement)
    ));
}

#[test]
fn duplicate_findings_and_empty_results_never_prove_rule_coverage() {
    let single: Value = serde_json::from_slice(&report("src/file.txt")).unwrap();
    let data = serde_json::to_vec(&json!([single[0].clone(), single[0].clone()])).unwrap();
    let p = plan();
    let w = witness(&p, &data);
    let r = check(&p, &w, &data, false, false).unwrap();
    assert_eq!(r.adapter.unique_catalog_rules_seen, 1);
    assert_eq!(r.adapter.required_rules_without_findings, Some(1));
    assert!(!r.rule_execution_verified && !r.coverage_verified);
    let empty = b"[]";
    let mut w = witness(&p, empty);
    w["exit_code"] = json!(0);
    let r = check(&p, &w, empty, false, false).unwrap();
    assert_eq!(r.adapter.unique_catalog_rules_seen, 0);
    assert!(!r.rule_execution_verified && !r.coverage_verified);
}
