//! Docker-dependent integration suite, explicitly executed by Ubuntu preflight CI.
#![cfg(target_os = "linux")]
use ed25519_dalek::{Signer, SigningKey};
use security_assurance_runner::{
    contract::input_digest,
    evaluation::Decision,
    execution_witness::{PLAN_TYPE, Refusal, TestContext, WITNESS_TYPE},
    inert_pipeline::{InertCoordinator, PipelineRefusal, TestMode},
    trust::pae,
};
use serde_json::json;
use std::process::{Command, Stdio};
use std::time::Duration;

struct Fixture {
    plan: Vec<u8>,
    plan_sig: [u8; 64],
    witness: Vec<u8>,
    witness_sig: [u8; 64],
    pin: String,
}
fn fixture(
    runner: &InertCoordinator,
    owner: &SigningKey,
    observer: &SigningKey,
    attempt: u32,
    binary_override: Option<&str>,
    scope_override: Option<&str>,
) -> Fixture {
    let binding = json!({
        "repository_id":"123","source_sha":"a".repeat(40),
        "run_id":"inert-test-run","stage_id":"inert-stage","attempt":attempt,
        "tool_version":"8.30.1",
        "binary_digest":binary_override.unwrap_or(runner.binary_digest()),
        "input_digest":runner.input_digest(),"config_digest":runner.config_digest()
    });
    let plan = json!({
        "version":1,"purpose":"execution-plan","issuer":"owner-fixture",
        "role":"plan-approver","not_before":10,"expires":200,
        "binding":binding,"scope":[scope_override.unwrap_or("src/file.txt")],
        "rules":["rule-a","rule-b"]
    });
    let report = runner.expected_inert_report();
    let plan_bytes = serde_json::to_vec(&plan).unwrap();
    let pin = input_digest(&plan_bytes);
    let witness = json!({
        "version":1,"purpose":"execution-witness","issuer":"observer-fixture",
        "role":"test-observer","not_before":10,"expires":200,
        "plan_digest":pin,"binding":binding,
        "report_digest":input_digest(report),"report_size":report.len(),
        "started":true,"execution":"COMPLETE","exit_code":23,
        "timed_out":false,"errors_or_skips":false
    });
    let wb = serde_json::to_vec(&witness).unwrap();
    let ps = owner.sign(&pae(PLAN_TYPE, &plan_bytes)).to_bytes();
    let ws = observer.sign(&pae(WITNESS_TYPE, &wb)).to_bytes();
    Fixture {
        plan: plan_bytes,
        plan_sig: ps,
        witness: wb,
        witness_sig: ws,
        pin,
    }
}
fn run(
    runner: &mut InertCoordinator,
    ctx: &TestContext<'_>,
    f: &Fixture,
    mode: TestMode,
    timeout: Duration,
) -> Result<security_assurance_runner::inert_pipeline::InertPipelineReceipt, PipelineRefusal> {
    runner.run(
        ctx,
        &f.plan,
        &f.plan_sig,
        &f.witness,
        &f.witness_sig,
        mode,
        timeout,
    )
}
fn gone(runner: &InertCoordinator) {
    if let Some(name) = runner.last_container_name() {
        let status = Command::new("docker")
            .args(["inspect", name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(!status.success(), "container not cleaned up");
    }
}
fn context<'a>(
    owner: &'a ed25519_dalek::VerifyingKey,
    observer: &'a ed25519_dalek::VerifyingKey,
    pin: &'a str,
) -> TestContext<'a> {
    TestContext {
        plan_key: owner,
        witness_key: observer,
        plan_issuer: "owner-fixture",
        witness_issuer: "observer-fixture",
        expected_plan_digest: pin,
        now: 100,
        freshness_current: true,
        revoked: false,
    }
}
#[test]
#[ignore = "requires GitHub-hosted Ubuntu Docker; scanner is NEVER executed"]
fn isolated_inert_helper_end_to_end_and_fail_closed_cases() {
    let mut runner = InertCoordinator::prepare().expect("Docker static inert helper preparation");
    let owner = SigningKey::from_bytes(&[7; 32]);
    let observer = SigningKey::from_bytes(&[8; 32]);
    let ok = owner.verifying_key();
    let wv = observer.verifying_key();
    let max = Duration::from_secs(5);

    let f = fixture(&runner, &owner, &observer, 1, None, None);
    let ctx = context(&ok, &wv, &f.pin);
    let receipt = run(&mut runner, &ctx, &f, TestMode::Normal, max).unwrap();
    assert!(receipt.test_only && receipt.inert_helper_process_observed);
    assert!(!receipt.actual_gitleaks_executed && !receipt.production_process_attested);
    assert!(!receipt.operational_pass);
    assert_eq!(receipt.policy_decision, Decision::Indeterminate);
    assert_eq!(receipt.observed_inert_exit_code, 23);
    assert_eq!(receipt.output_size, runner.expected_inert_report().len());
    assert!(receipt.witness.test_only && !receipt.witness.coverage_verified);
    assert!(!format!("{receipt:?}").contains("INERT_PRIVATE_MARKER"));
    assert!(
        !serde_json::to_string(&receipt)
            .unwrap()
            .contains("INERT_PRIVATE_MARKER")
    );
    gone(&runner);

    assert!(matches!(
        run(&mut runner, &ctx, &f, TestMode::Normal, max),
        Err(PipelineRefusal::Replayed)
    ));
    gone(&runner);
    let mut bad_sig = fixture(&runner, &owner, &observer, 2, None, None);
    bad_sig.witness_sig = [0; 64];
    let sig_ctx = context(&ok, &wv, &bad_sig.pin);
    assert!(matches!(
        run(&mut runner, &sig_ctx, &bad_sig, TestMode::Normal, max),
        Err(PipelineRefusal::Plan(Refusal::InvalidSignature))
    ));
    gone(&runner);

    // Independent observed exit 23 must reject a separately signed, but wrong,
    // exit_code=1 witness. This is intentionally a FULL Docker execution test.
    let mut wrong_exit = fixture(&runner, &owner, &observer, 10, None, None);
    let mut wrong_value: serde_json::Value =
        serde_json::from_slice(&wrong_exit.witness).unwrap();
    wrong_value["exit_code"] = json!(1);
    wrong_exit.witness = serde_json::to_vec(&wrong_value).unwrap();
    wrong_exit.witness_sig = observer
        .sign(&pae(WITNESS_TYPE, &wrong_exit.witness))
        .to_bytes();
    let wrong_exit_ctx = context(&ok, &wv, &wrong_exit.pin);
    assert!(matches!(
        run(&mut runner, &wrong_exit_ctx, &wrong_exit, TestMode::Normal, max),
        Err(PipelineRefusal::WitnessExitMismatch)
    ));
    gone(&runner);

    let unexpected_digest = "f".repeat(64);
    let wrong = fixture(
        &runner,
        &owner,
        &observer,
        3,
        Some(&unexpected_digest),
        None,
    );
    let wrong_ctx = context(&ok, &wv, &wrong.pin);
    assert!(matches!(
        run(&mut runner, &wrong_ctx, &wrong, TestMode::Normal, max),
        Err(PipelineRefusal::WrongInertIdentity)
    ));
    gone(&runner);

    let outside = fixture(&runner, &owner, &observer, 4, None, Some("../escape"));
    let outside_ctx = context(&ok, &wv, &outside.pin);
    assert!(matches!(
        run(&mut runner, &outside_ctx, &outside, TestMode::Normal, max),
        Err(PipelineRefusal::Plan(Refusal::InvalidStatement))
    ));
    gone(&runner);

    for (attempt, mode, expect) in [
        (5, TestMode::Failure, "exit"),
        (6, TestMode::Partial, "output"),
        (7, TestMode::Oversize, "output"),
    ] {
        let f = fixture(&runner, &owner, &observer, attempt, None, None);
        let ctx = context(&ok, &wv, &f.pin);
        let result = run(&mut runner, &ctx, &f, mode, max);
        if expect == "exit" {
            assert!(matches!(result, Err(PipelineRefusal::UnexpectedExit)));
        } else {
            assert!(matches!(
                result,
                Err(PipelineRefusal::InvalidOrUnboundedOutput)
            ));
        }
        gone(&runner);
    }
    let sleep = fixture(&runner, &owner, &observer, 8, None, None);
    let sleep_ctx = context(&ok, &wv, &sleep.pin);
    assert!(matches!(
        run(
            &mut runner,
            &sleep_ctx,
            &sleep,
            TestMode::Timeout,
            Duration::from_millis(400)
        ),
        Err(PipelineRefusal::Timeout)
    ));
    gone(&runner);

    let cancel = fixture(&runner, &owner, &observer, 9, None, None);
    let cancel_ctx = context(&ok, &wv, &cancel.pin);
    assert!(matches!(
        run(&mut runner, &cancel_ctx, &cancel, TestMode::Cancelled, max),
        Err(PipelineRefusal::Cancelled)
    ));
    gone(&runner);

    // Controlled failure injection deliberately suppresses the FIRST cleanup
    // command. Coordinator must expose CleanupFailed, attempt recovery, and
    // leave no container, including when execution itself already failed.
    let cleanup_success = fixture(&runner, &owner, &observer, 11, None, None);
    let cleanup_success_ctx = context(&ok, &wv, &cleanup_success.pin);
    assert!(matches!(
        run(
            &mut runner,
            &cleanup_success_ctx,
            &cleanup_success,
            TestMode::CleanupFailure,
            max
        ),
        Err(PipelineRefusal::CleanupFailed)
    ));
    gone(&runner);

    let cleanup_error = fixture(&runner, &owner, &observer, 12, None, None);
    let cleanup_error_ctx = context(&ok, &wv, &cleanup_error.pin);
    assert!(matches!(
        run(
            &mut runner,
            &cleanup_error_ctx,
            &cleanup_error,
            TestMode::ErrorCleanupFailure,
            max
        ),
        Err(PipelineRefusal::CleanupFailed)
    ));
    gone(&runner);
    println!("GOV_02_PIPELINE_01_ISOLATED_INERT_HELPER_PASS");
}
