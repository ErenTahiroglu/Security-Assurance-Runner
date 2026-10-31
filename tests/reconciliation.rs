use ed25519_dalek::{Signer, SigningKey};
use security_assurance_runner::{
    contract::input_digest,
    evaluation::{Decision, Execution},
    reconcile::{
        Binding, CheckRecord, ExpectedStage, Report, StageInput, SyntheticPlan, SyntheticReceipt,
        plan_intent_digest, reconcile as reconcile_raw,
    },
    trust::{POLICY_TYPE, SyntheticTrust, pae, verify_synthetic_policy},
};
use std::collections::BTreeMap;
// Independently computed from the documented canonical JSON using Python hashlib.
const TRUSTED_PLAN: &str = "39c44666f3c9c81e5fbdfe09f4d319992f8398e0d0bacff49148c7963097c08c";

fn reconcile(plan: &SyntheticPlan, inputs: &[StageInput]) -> SyntheticReceipt {
    reconcile_with_trust(plan, inputs, Some(TRUSTED_PLAN), None)
}

fn reconcile_with_trust(
    plan: &SyntheticPlan,
    inputs: &[StageInput],
    trusted: Option<&str>,
    pins: Option<&BTreeMap<String, String>>,
) -> SyntheticReceipt {
    let key = SigningKey::from_bytes(&[7; 32]);
    let verification_key = key.verifying_key();
    let payload =
        serde_json::json!({"version":1,"purpose":"policy","issuer":"fixture-owner","role":"owner",
        "provider":"github","repository_id":"123","policy_id":"policy",
        "policy_digest":input_digest(b"{\"version\":1,\"mandatory_checks\":[\"required\"]}"),"sequence":2,"not_before":10,"expires":200})
        .to_string()
        .into_bytes();
    let signature = key.sign(&pae(POLICY_TYPE, &payload)).to_bytes();
    let context = SyntheticTrust {
        key: Some(&verification_key),
        issuer: "fixture-owner",
        repository_id: "123",
        policy_id: "policy",
        minimum_sequence: 2,
        now: 100,
        freshness_current: true,
        revoked: false,
    };
    let verified = verify_synthetic_policy(
        &context,
        POLICY_TYPE,
        &payload,
        &signature,
        b"{\"version\":1,\"mandatory_checks\":[\"required\"]}",
    )
    .unwrap();
    reconcile_raw(plan, inputs, Some(&verified), trusted, pins)
}

fn fixture() -> (SyntheticPlan, Vec<StageInput>) {
    let mut binding = Binding {
        provider: "github".into(),
        repository_id: "123".into(),
        commit: "a".repeat(40),
        policy_id: "policy".into(),
        policy_digest: input_digest(b"{\"version\":1,\"mandatory_checks\":[\"required\"]}"),
        policy_sequence: 2,
        run_id: "run-1".into(),
        plan_id: "plan-1".into(),
        plan_digest: "c".repeat(64),
    };
    let mut stage = ExpectedStage {
        id: "s1".into(),
        attempt: 1,
        mode: "CI".into(),
        location: "fixture".into(),
        artifact_id: "report".into(),
        artifact_digest: "0".repeat(64),
        mandatory: true,
        checks: vec!["required".into()],
        category: "source".into(),
        status_source: "fixture-app".into(),
    };
    binding.plan_digest = plan_intent_digest(&SyntheticPlan {
        binding: binding.clone(),
        stages: vec![stage.clone()],
    })
    .unwrap();
    let report = Report {
        version: 1,
        binding: binding.clone(),
        stage_id: "s1".into(),
        attempt: 1,
        mode: "CI".into(),
        location: "fixture".into(),
        artifact_id: "report".into(),
        status_source: "fixture-app".into(),
        execution: Execution::Complete,
        checks: vec![CheckRecord {
            id: "required".into(),
            status: "COMPLETE".into(),
            blocking_finding: false,
        }],
    };
    let bytes = serde_json::to_vec(&report).unwrap();
    stage.artifact_digest = input_digest(&bytes);
    (
        SyntheticPlan {
            binding,
            stages: vec![stage],
        },
        vec![StageInput {
            stage_id: "s1".into(),
            artifact: bytes,
        }],
    )
}
fn replace(plan: &mut SyntheticPlan, input: &mut StageInput, edit: impl FnOnce(&mut Report)) {
    let mut report: Report = serde_json::from_slice(&input.artifact).unwrap();
    edit(&mut report);
    input.artifact = serde_json::to_vec(&report).unwrap();
    plan.stages[0].artifact_digest = input_digest(&input.artifact);
}
#[test]
fn valid_synthetic_report_produces_only_labeled_fixture_pass() {
    let (plan, inputs) = fixture();
    assert_eq!(plan.binding.plan_digest, TRUSTED_PLAN);
    let r = reconcile(&plan, &inputs);
    assert!(r.test_only);
    assert_eq!(r.policy_decision, Decision::Pass);
    assert_eq!(r.execution, Execution::Complete);
    assert_eq!(r.verification, "SYNTHETIC_ONLY");
    assert_eq!(
        reconcile_raw(&plan, &inputs, None, Some(&plan.binding.plan_digest), None).policy_decision,
        Decision::Indeterminate
    );
}
#[test]
fn missing_corrupt_duplicate_and_malformed_are_indeterminate() {
    let (mut plan, mut inputs) = fixture();
    assert_eq!(
        reconcile(&plan, &[]).policy_decision,
        Decision::Indeterminate
    );
    assert_eq!(
        reconcile(&plan, &[inputs[0].clone(), inputs[0].clone()]).policy_decision,
        Decision::Indeterminate
    );
    inputs[0].artifact.push(0);
    assert_eq!(
        reconcile(&plan, &inputs).policy_decision,
        Decision::Indeterminate
    );
    inputs[0].artifact = b"{broken".to_vec();
    plan.stages[0].artifact_digest = input_digest(&inputs[0].artifact);
    assert_eq!(
        reconcile(&plan, &inputs).policy_decision,
        Decision::Indeterminate
    );
}
#[test]
fn wrong_binding_and_stage_identity_cannot_be_reused() {
    for field in 0..10 {
        let (mut plan, mut inputs) = fixture();
        replace(&mut plan, &mut inputs[0], |r| match field {
            0 => r.binding.repository_id = "124".into(),
            1 => r.binding.commit = "d".repeat(40),
            2 => r.binding.policy_id = "other".into(),
            3 => r.binding.policy_digest = "d".repeat(64),
            4 => r.binding.policy_sequence = 1,
            5 => r.binding.run_id = "old-run".into(),
            6 => r.binding.plan_id = "old-plan".into(),
            7 => r.binding.plan_digest = "d".repeat(64),
            8 => r.attempt = 2,
            _ => r.status_source = "forged-app".into(),
        });
        assert_eq!(
            reconcile(&plan, &inputs).policy_decision,
            Decision::Indeterminate,
            "field {field}"
        );
    }
}
#[test]
fn missing_skipped_or_duplicate_checks_do_not_pass() {
    for field in 0..5 {
        let (mut plan, mut inputs) = fixture();
        replace(&mut plan, &mut inputs[0], |r| match field {
            0 => r.checks.clear(),
            1 => r.checks[0].status = "SKIPPED".into(),
            2 => r.checks[0].id = "misspelled".into(),
            3 => r.checks.push(r.checks[0].clone()),
            _ => r.execution = Execution::Cancelled,
        });
        assert_eq!(
            reconcile(&plan, &inputs).policy_decision,
            Decision::Indeterminate,
            "field {field}"
        );
    }
}
#[test]
fn optional_cannot_substitute_required_and_active_is_rejected() {
    let (mut plan, inputs) = fixture();
    let mut optional = plan.stages[0].clone();
    optional.id = "optional".into();
    optional.mandatory = false;
    optional.checks = vec!["optional-check".into()];
    let mut report: Report = serde_json::from_slice(&inputs[0].artifact).unwrap();
    report.stage_id = "optional".into();
    report.checks[0].id = "optional-check".into();
    let artifact = serde_json::to_vec(&report).unwrap();
    optional.artifact_digest = input_digest(&artifact);
    plan.stages.push(optional);
    assert_eq!(
        reconcile(
            &plan,
            &[StageInput {
                stage_id: "optional".into(),
                artifact
            }]
        )
        .policy_decision,
        Decision::Indeterminate
    );
    plan.stages[0].category = "dast".into();
    assert_eq!(
        reconcile(&plan, &inputs).policy_decision,
        Decision::Indeterminate
    );
}

#[test]
fn cancelled_failed_and_unknown_success_assertion_are_not_pass() {
    for (state, expected) in [
        (Execution::Cancelled, Execution::Cancelled),
        (Execution::Failed, Execution::Failed),
    ] {
        let (mut plan, mut inputs) = fixture();
        replace(&mut plan, &mut inputs[0], |r| r.execution = state);
        let result = reconcile(&plan, &inputs);
        assert_eq!(result.execution, expected);
        assert_eq!(result.policy_decision, Decision::Indeterminate);
    }
    let (mut plan, mut inputs) = fixture();
    let raw = String::from_utf8(inputs[0].artifact.clone())
        .unwrap()
        .replacen("{", "{\"success\":true,", 1);
    inputs[0].artifact = raw.into_bytes();
    plan.stages[0].artifact_digest = input_digest(&inputs[0].artifact);
    assert_eq!(
        reconcile(&plan, &inputs).policy_decision,
        Decision::Indeterminate
    );
}
#[test]
fn valid_blocking_finding_and_order_independence() {
    let (mut plan, mut inputs) = fixture();
    replace(&mut plan, &mut inputs[0], |r| {
        r.checks[0].blocking_finding = true
    });
    assert_eq!(reconcile(&plan, &inputs).policy_decision, Decision::Block);
    let extra = StageInput {
        stage_id: "unknown".into(),
        artifact: vec![],
    };
    let a = serde_json::to_string(&reconcile(&plan, &[inputs[0].clone(), extra.clone()])).unwrap();
    let b = serde_json::to_string(&reconcile(&plan, &[extra, inputs[0].clone()])).unwrap();
    assert_eq!(a, b);
}

#[test]
fn stage_modes_and_location_are_bound_to_the_fixture_plan() {
    for mode in ["LOCAL", "HYBRID"] {
        let (mut plan, mut inputs) = fixture();
        plan.stages[0].mode = mode.into();
        plan.binding.plan_digest = plan_intent_digest(&plan).unwrap();
        let trusted = plan.binding.plan_digest.clone();
        let binding = plan.binding.clone();
        replace(&mut plan, &mut inputs[0], |r| {
            r.mode = mode.into();
            r.binding = binding;
        });
        assert_eq!(
            reconcile_with_trust(&plan, &inputs, Some(&trusted), None).policy_decision,
            Decision::Pass
        );
        replace(&mut plan, &mut inputs[0], |r| {
            r.location = "different".into()
        });
        assert_eq!(
            reconcile_with_trust(&plan, &inputs, Some(&trusted), None).policy_decision,
            Decision::Indeterminate
        );
    }
}

#[test]
fn signed_mandatory_inventory_cannot_be_replaced_by_plan() {
    let (mut plan, mut inputs) = fixture();
    plan.stages[0].checks = vec!["replacement".into()];
    replace(&mut plan, &mut inputs[0], |r| {
        r.checks[0].id = "replacement".into()
    });
    assert_eq!(
        reconcile(&plan, &inputs).policy_decision,
        Decision::Indeterminate
    );
}

#[test]
fn stale_plan_digest_cannot_authorize_stage_substitution() {
    let (mut plan, mut inputs) = fixture();
    plan.stages[0].id = "s2".into();
    replace(&mut plan, &mut inputs[0], |r| r.stage_id = "s2".into());
    inputs[0].stage_id = "s2".into();
    assert_eq!(
        reconcile(&plan, &inputs).policy_decision,
        Decision::Indeterminate
    );
}

#[test]
fn plan_attempt_mode_and_recomputed_self_digest_need_independent_approval() {
    for choice in 0..3 {
        let (mut plan, mut inputs) = fixture();
        let trusted = plan.binding.plan_digest.clone();
        if choice == 0 {
            plan.stages[0].attempt = 2;
            replace(&mut plan, &mut inputs[0], |r| r.attempt = 2);
        }
        if choice == 1 {
            plan.stages[0].mode = "LOCAL".into();
            replace(&mut plan, &mut inputs[0], |r| r.mode = "LOCAL".into());
        }
        if choice == 2 {
            plan.stages[0].id = "s2".into();
            plan.binding.plan_digest = plan_intent_digest(&plan).unwrap();
            let new_binding = plan.binding.clone();
            replace(&mut plan, &mut inputs[0], |r| {
                r.stage_id = "s2".into();
                r.binding = new_binding;
            });
            inputs[0].stage_id = "s2".into();
        }
        assert_eq!(
            reconcile_with_trust(&plan, &inputs, Some(&trusted), None).policy_decision,
            Decision::Indeterminate
        );
    }
}

#[test]
fn missing_plan_anchor_and_substituted_pinned_artifact_are_rejected() {
    let (mut plan, mut inputs) = fixture();
    let trusted = plan.binding.plan_digest.clone();
    let missing_anchor = reconcile_with_trust(&plan, &inputs, None, None);
    assert_eq!(missing_anchor.policy_decision, Decision::Indeterminate);
    assert!(missing_anchor.artifact_digests.is_empty());
    let pins = BTreeMap::from([("s1".to_string(), input_digest(&inputs[0].artifact))]);
    assert_eq!(
        reconcile_with_trust(&plan, &inputs, Some(&trusted), Some(&pins)).policy_decision,
        Decision::Pass
    );
    replace(&mut plan, &mut inputs[0], |r| {
        r.checks[0].blocking_finding = true
    });
    assert_eq!(
        reconcile_with_trust(&plan, &inputs, Some(&trusted), Some(&pins)).policy_decision,
        Decision::Indeterminate
    );
}

#[test]
fn missing_optional_stage_preserves_mandatory_scope_coverage() {
    let (mut plan, mut inputs) = fixture();
    let mut optional = plan.stages[0].clone();
    optional.id = "optional".into();
    optional.mandatory = false;
    optional.checks = vec!["optional-check".into()];
    plan.stages.push(optional);
    plan.binding.plan_digest = plan_intent_digest(&plan).unwrap();
    let trusted = plan.binding.plan_digest.clone();
    let binding = plan.binding.clone();
    replace(&mut plan, &mut inputs[0], |r| r.binding = binding);
    let receipt = reconcile_with_trust(&plan, &inputs, Some(&trusted), None);
    assert_eq!(receipt.policy_decision, Decision::Pass);
    assert_eq!(receipt.coverage, "COMPLETE_SYNTHETIC_SCOPE");
    assert_eq!(receipt.missing_optional_stages, vec!["optional"]);
}

#[test]
fn canonical_intent_is_order_independent_and_excludes_report_digests() {
    let (mut plan, _) = fixture();
    let mut optional = plan.stages[0].clone();
    optional.id = "optional".into();
    optional.mandatory = false;
    optional.checks = vec!["b".into(), "a".into()];
    plan.stages.push(optional);
    let original = plan_intent_digest(&plan).unwrap();
    plan.stages.reverse();
    plan.stages[0].checks.reverse();
    plan.stages[0].artifact_digest = "f".repeat(64);
    assert_eq!(plan_intent_digest(&plan).unwrap(), original);
    plan.stages[0].attempt += 1;
    assert_ne!(plan_intent_digest(&plan).unwrap(), original);
}
