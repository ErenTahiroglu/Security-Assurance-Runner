//! Offline native-report assessment. All execution and plan inputs are caller claims.
use crate::contract::input_digest;
use crate::evaluation::{Decision, Execution};
use crate::gitleaks_fixture::{
    CollectionKind, FixtureImportError, MAX_INPUT_BYTES, interpret_gitleaks_fixture_v2,
};
use serde::Serialize;
use std::collections::BTreeSet;

/// Caller-declared plan; this type does not confer approval or authenticate identity.
pub struct Plan<'a> {
    pub version: u32,
    pub repository_id: &'a str,
    pub source_sha: &'a str,
    pub run_id: &'a str,
    pub stage_id: &'a str,
    pub attempt: u32,
    pub tool_version: &'a str,
    pub binary_digest: &'a str,
    pub input_digest: &'a str,
    pub config_digest: &'a str,
    pub required_rules: &'a [&'a str],
}

/// Caller-supplied observations, not independent attestations; do not log this object.
pub struct ExecutionClaim<'a> {
    pub version: u32,
    pub repository_id: &'a str,
    pub source_sha: &'a str,
    pub run_id: &'a str,
    pub stage_id: &'a str,
    pub attempt: u32,
    pub tool_version: &'a str,
    pub binary_digest: &'a str,
    pub input_digest: &'a str,
    pub config_digest: &'a str,
    pub started: bool,
    pub execution: Execution,
    pub exit_code: Option<i32>,
    pub report_digest: Option<&'a str>,
    pub report_size: Option<usize>,
    pub errors_or_skips: bool,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReportState {
    Missing,
    Null,
    Empty,
    Findings,
    Invalid,
}

#[derive(Debug, Serialize)]
pub struct AdapterReceipt {
    pub schema: &'static str,
    pub report: ReportState,
    pub parsed_elements: usize,
    pub profile_usable: usize,
    pub unique_catalog_rules_seen: usize,
    pub required_rules_without_findings: Option<usize>,
    pub unknown_rule_claims: Option<usize>,
    pub claimed_execution: Option<Execution>,
    pub claimed_exit: &'static str,
    pub inconsistencies: Vec<&'static str>,
    pub policy_decision: Decision,
    pub scanner_identity_verified: bool,
    pub execution_verified: bool,
    pub coverage_verified: bool,
    pub policy_authority_verified: bool,
    pub operational_pass: bool,
    pub limitations: &'static str,
}

fn digest(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}
fn plan_valid(p: &Plan<'_>) -> bool {
    p.version == 1
        && token(p.repository_id)
        && digest(p.source_sha, 40)
        && token(p.run_id)
        && token(p.stage_id)
        && p.attempt > 0
        && p.tool_version == "8.30.1"
        && digest(p.binary_digest, 64)
        && digest(p.input_digest, 64)
        && digest(p.config_digest, 64)
        && !p.required_rules.is_empty()
        && p.required_rules.len() <= 64
        && p.required_rules.iter().all(|r| token(r))
        && p.required_rules.iter().collect::<BTreeSet<_>>().len() == p.required_rules.len()
}

/// Inspect bounded report bytes without network, filesystem, execution or enrolled authority.
pub fn assess(
    report: Option<&[u8]>,
    plan: Option<&Plan<'_>>,
    claim: Option<&ExecutionClaim<'_>>,
) -> AdapterReceipt {
    let mut r = AdapterReceipt {
        schema: "gitleaks-adapter-receipt-v1",
        report: ReportState::Missing,
        parsed_elements: 0,
        profile_usable: 0,
        unique_catalog_rules_seen: 0,
        required_rules_without_findings: None,
        unknown_rule_claims: None,
        claimed_execution: claim.map(|c| c.execution),
        claimed_exit: match claim.and_then(|c| c.exit_code) {
            None => "NOT_DECLARED",
            Some(0) => "ZERO",
            Some(_) => "NONZERO_AMBIGUOUS",
        },
        inconsistencies: Vec::new(),
        policy_decision: Decision::Indeterminate,
        scanner_identity_verified: false,
        execution_verified: false,
        coverage_verified: false,
        policy_authority_verified: false,
        operational_pass: false,
        limitations: "All plan and execution metadata are caller claims; no independent provenance, coverage or operational authority.",
    };
    let valid_plan = plan.filter(|p| plan_valid(p));
    if valid_plan.is_none() {
        r.inconsistencies.push("MISSING_OR_INVALID_PLAN");
    }
    if claim.is_none() {
        r.inconsistencies.push("MISSING_EXECUTION_CLAIM");
    }
    if let Some(bytes) = report {
        match interpret_gitleaks_fixture_v2(bytes, valid_plan.map(|p| p.required_rules)) {
            Ok(parsed) => {
                r.parsed_elements = parsed.parsed_elements;
                r.profile_usable = parsed.usable_fixture_findings;
                r.unknown_rule_claims = parsed.unknown_fixture_rule_ids;
                let rules: BTreeSet<_> = parsed.matched_catalog_indexes.into_iter().collect();
                r.unique_catalog_rules_seen = rules.len();
                if let Some(p) = valid_plan {
                    r.required_rules_without_findings =
                        Some(p.required_rules.len().saturating_sub(rules.len()));
                }
                r.report = match parsed.collection {
                    CollectionKind::Null => ReportState::Null,
                    CollectionKind::Array if parsed.parsed_elements == 0 => ReportState::Empty,
                    CollectionKind::Array => ReportState::Findings,
                };
                if parsed.insufficient_fixture_findings > 0 {
                    r.inconsistencies.push("INSUFFICIENT_FINDING_PROFILE");
                }
            }
            Err(FixtureImportError::MissingEvidence) => {
                r.report = ReportState::Missing;
            }
            Err(_) => {
                r.report = ReportState::Invalid;
                r.inconsistencies.push("INVALID_OR_UNSUPPORTED_REPORT");
            }
        }
    }
    if let Some(c) = claim {
        if c.version != 1 {
            r.inconsistencies.push("UNSUPPORTED_CLAIM_VERSION");
        }
        if let Some(p) = valid_plan {
            if c.repository_id != p.repository_id
                || c.source_sha != p.source_sha
                || c.input_digest != p.input_digest
            {
                r.inconsistencies.push("SOURCE_OR_INPUT_MISMATCH");
            }
            if c.run_id != p.run_id || c.stage_id != p.stage_id || c.attempt != p.attempt {
                r.inconsistencies.push("RUN_OR_STAGE_MISMATCH");
            }
            if c.tool_version != p.tool_version || c.binary_digest != p.binary_digest {
                r.inconsistencies.push("TOOL_IDENTITY_MISMATCH");
            }
            if c.config_digest != p.config_digest {
                r.inconsistencies.push("CONFIG_IDENTITY_MISMATCH");
            }
        }
        if c.errors_or_skips {
            r.inconsistencies.push("ERRORS_OR_SKIPPED_SCOPE");
        }
        if !c.started {
            r.inconsistencies.push("PROCESS_NOT_STARTED_CLAIM");
        }
        if c.execution != Execution::Complete {
            r.inconsistencies.push("EXECUTION_NOT_COMPLETE");
        }
        if c.exit_code.is_some_and(|code| code != 0) {
            r.inconsistencies.push("NONZERO_EXIT_UNRESOLVED");
        }
        if let Some(bytes) = report {
            if bytes.len() > MAX_INPUT_BYTES
                || c.report_size != Some(bytes.len())
                || c.report_digest != Some(input_digest(bytes).as_str())
            {
                r.inconsistencies.push("REPORT_BINDING_MISMATCH");
            }
        } else {
            r.inconsistencies.push("REPORT_MISSING");
        }
        // v8.30.1 default code 1 can mean findings or errors; never infer successful execution.
        if c.execution == Execution::Complete
            && (c.exit_code.is_none() || (c.exit_code == Some(0) && r.parsed_elements > 0))
        {
            r.inconsistencies.push("EXIT_REPORT_INCONSISTENT");
        }
    }
    r
}
