use security_assurance_runner::contract::input_digest;
use security_assurance_runner::evaluation::{Decision, Execution};
use security_assurance_runner::gitleaks_adapter::{ExecutionClaim, Plan, ReportState, assess};

const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIG: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const OTHER: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const MARKER: &str = "INERT_MARKER_NEVER_A_CREDENTIAL";
fn plan() -> Plan<'static> {
    Plan {
        version: 1,
        repository_id: "123",
        source_sha: SHA,
        run_id: "run",
        stage_id: "stage",
        attempt: 1,
        tool_version: "8.30.1",
        binary_digest: DIG,
        input_digest: DIG,
        config_digest: DIG,
        required_rules: &["rule-a", "rule-b"],
    }
}
fn claim<'a>(hash: &'a str, size: usize) -> ExecutionClaim<'a> {
    ExecutionClaim {
        version: 1,
        repository_id: "123",
        source_sha: SHA,
        run_id: "run",
        stage_id: "stage",
        attempt: 1,
        tool_version: "8.30.1",
        binary_digest: DIG,
        input_digest: DIG,
        config_digest: DIG,
        started: true,
        execution: Execution::Complete,
        exit_code: Some(0),
        report_digest: Some(hash),
        report_size: Some(size),
        errors_or_skips: false,
    }
}
fn finding() -> Vec<u8> {
    format!(r#"[{{"RuleID":"rule-a","File":"../{MARKER}","Fingerprint":"{MARKER}","Secret":"{MARKER}","Match":"{MARKER}","StartLine":1,"EndLine":1,"StartColumn":1,"EndColumn":2}}]"#).into_bytes()
}

#[test]
fn format_states_and_no_authority() {
    for (bytes, state) in [
        (None, ReportState::Missing),
        (Some(b"null".as_slice()), ReportState::Null),
        (Some(b"[]".as_slice()), ReportState::Empty),
        (Some(b"[".as_slice()), ReportState::Invalid),
        (Some(b"\xff".as_slice()), ReportState::Invalid),
    ] {
        let r = assess(bytes, None, None);
        assert_eq!(r.report, state);
        assert_eq!(r.policy_decision, Decision::Indeterminate);
        assert!(
            !r.operational_pass
                && !r.coverage_verified
                && !r.execution_verified
                && !r.policy_authority_verified
        );
    }
    assert_eq!(
        assess(Some(&vec![b' '; 65537]), None, None).report,
        ReportState::Invalid
    );
    assert_eq!(
        assess(Some(br#"[{"RuleID":"x","RuleID":"y"}]"#), None, None).report,
        ReportState::Invalid
    );
}
#[test]
fn findings_and_claims_never_authenticate_or_leak() {
    let data = finding();
    let hash = input_digest(&data);
    let c = claim(&hash, data.len());
    let r = assess(Some(&data), Some(&plan()), Some(&c));
    assert_eq!(r.report, ReportState::Findings);
    assert_eq!(r.profile_usable, 1);
    assert_eq!(r.unique_catalog_rules_seen, 1);
    assert_eq!(r.required_rules_without_findings, Some(1));
    assert!(r.inconsistencies.contains(&"EXIT_REPORT_INCONSISTENT"));
    assert!(!format!("{r:?}").contains(MARKER));
    assert!(!serde_json::to_string(&r).unwrap().contains(MARKER));
    assert!(!r.scanner_identity_verified && !r.operational_pass);
}
#[test]
fn mismatches_and_partial_scans_fail_closed() {
    let data = finding();
    let hash = input_digest(&data);
    let mut c = claim(&hash, data.len());
    c.source_sha = "wrong";
    c.run_id = "stale";
    c.attempt = 2;
    c.tool_version = "fake";
    c.binary_digest = OTHER;
    c.config_digest = OTHER;
    c.input_digest = OTHER;
    c.execution = Execution::Incomplete;
    c.exit_code = Some(1);
    c.errors_or_skips = true;
    let r = assess(Some(&data), Some(&plan()), Some(&c));
    for reason in [
        "SOURCE_OR_INPUT_MISMATCH",
        "RUN_OR_STAGE_MISMATCH",
        "TOOL_IDENTITY_MISMATCH",
        "CONFIG_IDENTITY_MISMATCH",
        "EXECUTION_NOT_COMPLETE",
        "NONZERO_EXIT_UNRESOLVED",
        "ERRORS_OR_SKIPPED_SCOPE",
    ] {
        assert!(r.inconsistencies.contains(&reason));
    }
    assert_eq!(r.policy_decision, Decision::Indeterminate);
    assert_eq!(r.parsed_elements, 1);
    c.execution = Execution::Cancelled;
    assert_eq!(
        assess(Some(&data), Some(&plan()), Some(&c)).claimed_execution,
        Some(Execution::Cancelled)
    );
    c.started = false;
    assert!(
        assess(Some(&data), Some(&plan()), Some(&c))
            .inconsistencies
            .contains(&"PROCESS_NOT_STARTED_CLAIM")
    );
}
#[test]
fn replay_and_duplicate_rules_do_not_prove_coverage() {
    let item = String::from_utf8(finding()).unwrap();
    let data = format!(
        "[{},{}]",
        &item[1..item.len() - 1],
        &item[1..item.len() - 1]
    )
    .into_bytes();
    let c = claim(OTHER, data.len());
    let r = assess(Some(&data), Some(&plan()), Some(&c));
    assert!(r.inconsistencies.contains(&"REPORT_BINDING_MISMATCH"));
    assert_eq!(r.parsed_elements, 2);
    assert_eq!(r.unique_catalog_rules_seen, 1);
    assert_eq!(r.required_rules_without_findings, Some(1));
    assert!(!r.coverage_verified);
}
#[test]
fn unknown_rule_and_missing_report_remain_unknown() {
    let data=br#"[{"RuleID":"unapproved","File":"file","Fingerprint":"x","StartLine":1,"EndLine":1,"StartColumn":1,"EndColumn":2}]"#;
    let hash = input_digest(data);
    let c = claim(&hash, data.len());
    let r = assess(Some(data), Some(&plan()), Some(&c));
    assert_eq!(r.unknown_rule_claims, Some(1));
    assert_eq!(r.unique_catalog_rules_seen, 0);
    assert_eq!(r.required_rules_without_findings, Some(2));
    assert!(
        assess(None, Some(&plan()), Some(&c))
            .inconsistencies
            .contains(&"REPORT_MISSING")
    );
}
