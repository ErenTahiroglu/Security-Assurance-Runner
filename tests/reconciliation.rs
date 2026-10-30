use ed25519_dalek::{Signer, SigningKey};
use security_assurance_runner::{
    contract::input_digest,
    evaluation::{Decision, Execution},
    reconcile::{
        Binding, CheckRecord, ExpectedStage, Report, StageInput, SyntheticPlan, SyntheticReceipt,
        reconcile as reconcile_raw,
    },
    trust::{POLICY_TYPE, SyntheticTrust, pae, verify_synthetic_policy},
};

fn reconcile(plan: &SyntheticPlan, inputs: &[StageInput]) -> SyntheticReceipt {
    let key = SigningKey::from_bytes(&[7; 32]);
    let verification_key = key.verifying_key();
    let payload =
        serde_json::json!({"version":1,"purpose":"policy","issuer":"fixture-owner","role":"owner",
        "provider":"github","repository_id":"123","policy_id":"policy",
        "policy_digest":input_digest(b"fixture policy"),"sequence":2,"not_before":10,"expires":200})
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
        b"fixture policy",
    )
    .unwrap();
    reconcile_raw(plan, inputs, Some(&verified))
}

fn fixture() -> (SyntheticPlan, Vec<StageInput>) {
    let binding = Binding {
        provider: "github".into(),
        repository_id: "123".into(),
        commit: "a".repeat(40),
        policy_id: "policy".into(),
        policy_digest: input_digest(b"fixture policy"),
        policy_sequence: 2,
        run_id: "run-1".into(),
        plan_id: "plan-1".into(),
        plan_digest: "c".repeat(64),
    };
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
    let stage = ExpectedStage {
        id: "s1".into(),
        attempt: 1,
        mode: "CI".into(),
        location: "fixture".into(),
        artifact_id: "report".into(),
        artifact_digest: input_digest(&bytes),
        mandatory: true,
        checks: vec!["required".into()],
        category: "source".into(),
        status_source: "fixture-app".into(),
    };
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
    let r = reconcile(&plan, &inputs);
    assert!(r.test_only);
    assert_eq!(r.policy_decision, Decision::Pass);
    assert_eq!(r.execution, Execution::Complete);
    assert_eq!(r.verification, "SYNTHETIC_ONLY");
    assert_eq!(
        reconcile_raw(&plan, &inputs, None).policy_decision,
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
        replace(&mut plan, &mut inputs[0], |r| r.mode = mode.into());
        assert_eq!(reconcile(&plan, &inputs).policy_decision, Decision::Pass);
        replace(&mut plan, &mut inputs[0], |r| {
            r.location = "different".into()
        });
        assert_eq!(
            reconcile(&plan, &inputs).policy_decision,
            Decision::Indeterminate
        );
    }
}
