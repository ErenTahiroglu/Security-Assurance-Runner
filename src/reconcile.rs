//! Offline synthetic reconciliation. No external provider or scanner is authenticated.
use crate::contract::{MAX_CHECKS, MAX_INPUT, input_digest};
use crate::evaluation::{Decision, Execution};
use crate::trust::SyntheticVerifiedPolicy;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub provider: String,
    pub repository_id: String,
    pub commit: String,
    pub policy_id: String,
    pub policy_digest: String,
    pub policy_sequence: u64,
    pub run_id: String,
    pub plan_id: String,
    pub plan_digest: String,
}
#[derive(Clone, Debug)]
pub struct ExpectedStage {
    pub id: String,
    pub attempt: u32,
    pub mode: String,
    pub location: String,
    pub artifact_id: String,
    pub artifact_digest: String,
    pub mandatory: bool,
    pub checks: Vec<String>,
    pub category: String,
    pub status_source: String,
}
#[derive(Clone, Debug)]
pub struct SyntheticPlan {
    pub binding: Binding,
    pub stages: Vec<ExpectedStage>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckRecord {
    pub id: String,
    pub status: String,
    pub blocking_finding: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub version: u32,
    pub binding: Binding,
    pub stage_id: String,
    pub attempt: u32,
    pub mode: String,
    pub location: String,
    pub artifact_id: String,
    pub status_source: String,
    pub execution: Execution,
    pub checks: Vec<CheckRecord>,
}
#[derive(Clone, Debug)]
pub struct StageInput {
    pub stage_id: String,
    pub artifact: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct SyntheticReceipt {
    pub schema_version: u32,
    pub test_only: bool,
    pub verification: &'static str,
    pub binding: Binding,
    pub observed_stages: Vec<String>,
    pub missing_stages: Vec<String>,
    pub missing_optional_stages: Vec<String>,
    pub invalid_stages: Vec<String>,
    pub artifact_digests: BTreeMap<String, String>,
    pub expected_checks: Vec<String>,
    pub observed_checks: Vec<String>,
    pub missing_checks: Vec<String>,
    pub execution: Execution,
    pub coverage: &'static str,
    pub policy_decision: Decision,
    pub limitations: Vec<&'static str>,
}

fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_:.".contains(&b))
}
fn hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_binding(b: &Binding) -> bool {
    b.provider == "github"
        && !b.repository_id.starts_with('0')
        && !b.repository_id.is_empty()
        && b.repository_id.len() <= 20
        && b.repository_id.bytes().all(|x| x.is_ascii_digit())
        && hex(&b.commit, 40)
        && identifier(&b.policy_id)
        && hex(&b.policy_digest, 64)
        && b.policy_sequence > 0
        && identifier(&b.run_id)
        && identifier(&b.plan_id)
        && hex(&b.plan_digest, 64)
}

/// SHA-256 of a bounded canonical JSON array, version 1. Stage and check order
/// are sorted; report digests and the self-declared plan digest are excluded.
pub fn plan_intent_digest(plan: &SyntheticPlan) -> Result<String, &'static str> {
    let b = &plan.binding;
    if !valid_binding(b) || plan.stages.is_empty() || plan.stages.len() > MAX_CHECKS {
        return Err("INVALID_PLAN");
    }
    let mut ids = BTreeSet::new();
    let mut all_checks = BTreeSet::new();
    let mut stages = Vec::new();
    for s in &plan.stages {
        if !identifier(&s.id)
            || !ids.insert(&s.id)
            || s.attempt == 0
            || !["CI", "LOCAL", "HYBRID"].contains(&s.mode.as_str())
            || !identifier(&s.location)
            || !identifier(&s.artifact_id)
            || s.category != "source"
            || !identifier(&s.status_source)
            || s.checks.len() > MAX_CHECKS
            || (s.mandatory && s.checks.is_empty())
        {
            return Err("INVALID_PLAN");
        }
        let mut checks = s.checks.clone();
        checks.sort();
        for check in &checks {
            if !identifier(check) || !all_checks.insert(check.clone()) {
                return Err("INVALID_PLAN");
            }
        }
        stages.push((
            &s.id,
            s.attempt,
            &s.mode,
            &s.location,
            &s.artifact_id,
            "application/json",
            s.mandatory,
            checks,
            &s.category,
            &s.status_source,
        ));
    }
    stages.sort_by(|a, b| a.0.cmp(b.0));
    let bytes = serde_json::to_vec(&(
        "SAR_SYNTHETIC_PLAN_INTENT",
        1u32,
        &b.provider,
        &b.repository_id,
        &b.commit,
        &b.policy_id,
        &b.policy_digest,
        b.policy_sequence,
        &b.run_id,
        &b.plan_id,
        stages,
    ))
    .map_err(|_| "INVALID_PLAN")?;
    if bytes.len() > MAX_INPUT {
        return Err("INVALID_PLAN");
    }
    Ok(input_digest(&bytes))
}
/// Plan is a synthetic test fixture, not an authenticated policy or run authorization.
pub fn reconcile(
    plan: &SyntheticPlan,
    inputs: &[StageInput],
    policy: Option<&SyntheticVerifiedPolicy>,
    trusted_plan_digest: Option<&str>,
    fixture_artifact_pins: Option<&BTreeMap<String, String>>,
) -> SyntheticReceipt {
    let mut observed = BTreeSet::new();
    let mut invalid = BTreeSet::new();
    let mut checks = BTreeSet::new();
    let mut digests = BTreeMap::new();
    let mut complete = BTreeSet::new();
    let mut blocking = false;
    let mut failed = false;
    let mut cancelled = false;
    let mut stages = BTreeMap::new();
    let mut all_checks = BTreeSet::new();
    let mut bad_plan =
        !valid_binding(&plan.binding) || plan.stages.is_empty() || plan.stages.len() > MAX_CHECKS;
    match (plan_intent_digest(plan), trusted_plan_digest) {
        (Ok(computed), Some(expected))
            if hex(expected, 64)
                && computed == expected
                && plan.binding.plan_digest == expected => {}
        _ => bad_plan = true,
    }
    match policy {
        Some(p)
            if p.statement.provider == plan.binding.provider
                && p.statement.repository_id == plan.binding.repository_id
                && p.statement.policy_id == plan.binding.policy_id
                && p.statement.policy_digest == plan.binding.policy_digest
                && p.statement.sequence == plan.binding.policy_sequence => {}
        _ => bad_plan = true,
    }
    let mut expected_checks = BTreeSet::new();
    for stage in plan.stages.iter().take(MAX_CHECKS + 1) {
        if !identifier(&stage.id)
            || stage.attempt == 0
            || !["CI", "LOCAL", "HYBRID"].contains(&stage.mode.as_str())
            || !identifier(&stage.location)
            || !identifier(&stage.artifact_id)
            || !hex(&stage.artifact_digest, 64)
            || stage.category != "source"
            || !identifier(&stage.status_source)
            || stage.checks.len() > MAX_CHECKS
            || (stage.mandatory && stage.checks.is_empty())
            || stages.insert(stage.id.clone(), stage).is_some()
        {
            bad_plan = true;
        }
        for check in stage.checks.iter().take(MAX_CHECKS + 1) {
            if !identifier(check) {
                bad_plan = true;
                continue;
            }
            if !all_checks.insert(check.clone()) {
                bad_plan = true;
            }
            if stage.mandatory {
                expected_checks.insert(check.clone());
            }
        }
    }
    if policy.is_none_or(|p| p.mandatory_checks != expected_checks) {
        bad_plan = true;
    }
    if inputs.len() > MAX_CHECKS {
        bad_plan = true;
    }
    if bad_plan {
        let missing_stages = plan
            .stages
            .iter()
            .take(MAX_CHECKS + 1)
            .filter(|s| s.mandatory)
            .map(|s| s.id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let missing_optional_stages = plan
            .stages
            .iter()
            .take(MAX_CHECKS + 1)
            .filter(|s| !s.mandatory)
            .map(|s| s.id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let expected: Vec<String> = expected_checks.into_iter().collect();
        return SyntheticReceipt {
            schema_version: 1,
            test_only: true,
            verification: "SYNTHETIC_ONLY",
            binding: plan.binding.clone(),
            observed_stages: vec![],
            missing_stages,
            missing_optional_stages,
            invalid_stages: vec!["INVALID_PLAN".into()],
            artifact_digests: BTreeMap::new(),
            expected_checks: expected.clone(),
            observed_checks: vec![],
            missing_checks: expected,
            execution: Execution::Incomplete,
            coverage: "INCOMPLETE",
            policy_decision: Decision::Indeterminate,
            limitations: vec![
                "Synthetic fixtures only; no operational trust or scanner",
                "Provider identity and host integrity are not authenticated",
            ],
        };
    }
    let mut counts = BTreeMap::new();
    for input in inputs.iter().take(MAX_CHECKS + 1) {
        *counts.entry(&input.stage_id).or_insert(0usize) += 1;
    }
    for input in inputs.iter().take(MAX_CHECKS + 1) {
        if !identifier(&input.stage_id) {
            invalid.insert("INVALID_STAGE_ID".into());
            continue;
        }
        observed.insert(input.stage_id.clone());
        let Some(stage) = stages.get(&input.stage_id) else {
            invalid.insert(input.stage_id.clone());
            continue;
        };
        if counts[&input.stage_id] != 1 || input.artifact.len() > MAX_INPUT {
            invalid.insert(input.stage_id.clone());
            continue;
        }
        let digest = input_digest(&input.artifact);
        digests.insert(input.stage_id.clone(), digest.clone());
        if fixture_artifact_pins.is_some_and(|pins| pins.get(&input.stage_id) != Some(&digest)) {
            invalid.insert(input.stage_id.clone());
            continue;
        }
        let report: Report = match serde_json::from_slice(&input.artifact) {
            Ok(r) => r,
            Err(_) => {
                invalid.insert(input.stage_id.clone());
                continue;
            }
        };
        if digest != stage.artifact_digest
            || report.version != 1
            || report.binding != plan.binding
            || report.stage_id != stage.id
            || report.attempt != stage.attempt
            || report.mode != stage.mode
            || report.location != stage.location
            || report.artifact_id != stage.artifact_id
            || report.status_source != stage.status_source
            || report.checks.len() > MAX_CHECKS
        {
            invalid.insert(input.stage_id.clone());
            continue;
        }
        let mut report_checks = BTreeSet::new();
        if stage.mandatory {
            failed |= report.execution == Execution::Failed;
            cancelled |= report.execution == Execution::Cancelled;
        }
        let mut valid = report.execution == Execution::Complete;
        for check in &report.checks {
            if !identifier(&check.id)
                || !report_checks.insert(check.id.clone())
                || !stage.checks.contains(&check.id)
                || check.status != "COMPLETE"
            {
                valid = false;
            }
        }
        if report_checks.len() != stage.checks.len() {
            valid = false;
        }
        if !valid {
            invalid.insert(input.stage_id.clone());
            continue;
        }
        for check in &report.checks {
            checks.insert(check.id.clone());
            blocking |= check.blocking_finding;
        }
        complete.insert(stage.id.clone());
    }
    let missing: Vec<String> = plan
        .stages
        .iter()
        .take(MAX_CHECKS + 1)
        .filter(|s| s.mandatory && !complete.contains(&s.id))
        .map(|s| s.id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let missing_optional_stages = plan
        .stages
        .iter()
        .take(MAX_CHECKS + 1)
        .filter(|s| !s.mandatory && !complete.contains(&s.id))
        .map(|s| s.id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if bad_plan {
        invalid.insert("INVALID_PLAN".into());
    }
    let all_complete = !bad_plan
        && missing.is_empty()
        && invalid.is_empty()
        && plan.stages.iter().any(|s| s.mandatory);
    let missing_checks = expected_checks.difference(&checks).cloned().collect();
    SyntheticReceipt {
        schema_version: 1,
        test_only: true,
        verification: "SYNTHETIC_ONLY",
        binding: plan.binding.clone(),
        observed_stages: observed.into_iter().collect(),
        missing_stages: missing,
        missing_optional_stages,
        invalid_stages: invalid.into_iter().collect(),
        artifact_digests: digests,
        expected_checks: expected_checks.into_iter().collect(),
        observed_checks: checks.into_iter().collect(),
        missing_checks,
        execution: if failed {
            Execution::Failed
        } else if cancelled {
            Execution::Cancelled
        } else if all_complete {
            Execution::Complete
        } else {
            Execution::Incomplete
        },
        coverage: if all_complete {
            "COMPLETE_SYNTHETIC_SCOPE"
        } else {
            "INCOMPLETE"
        },
        policy_decision: if bad_plan {
            Decision::Indeterminate
        } else if blocking {
            Decision::Block
        } else if all_complete {
            Decision::Pass
        } else {
            Decision::Indeterminate
        },
        limitations: vec![
            "Synthetic fixtures only; no operational trust or scanner",
            "Provider identity and host integrity are not authenticated",
        ],
    }
}
