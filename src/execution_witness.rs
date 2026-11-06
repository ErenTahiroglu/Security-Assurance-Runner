//! Test-root-bound statements only: signatures do not establish actual process execution.
use crate::contract::{MAX_CHECKS, MAX_INPUT, input_digest};
use crate::evaluation::{Decision, Execution};
use crate::gitleaks_adapter::{self, AdapterReceipt, ExecutionClaim, Plan};
use crate::gitleaks_fixture::{MAX_INPUT_BYTES, safe_relative, synthetic_scope_counts};
use crate::trust::pae;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const PLAN_TYPE: &str = "application/vnd.sar.test-execution-plan.v1+json";
pub const WITNESS_TYPE: &str = "application/vnd.sar.test-execution-witness.v1+json";

/// Trust and expected plan digest are supplied out of band; never load them from statements.
pub struct TestContext<'a> {
    pub plan_key: &'a VerifyingKey,
    pub witness_key: &'a VerifyingKey,
    pub plan_issuer: &'a str,
    pub witness_issuer: &'a str,
    pub expected_plan_digest: &'a str,
    pub now: u64,
    pub freshness_current: bool,
    pub revoked: bool,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub repository_id: String,
    pub source_sha: String,
    pub run_id: String,
    pub stage_id: String,
    pub attempt: u32,
    pub tool_version: String,
    pub binary_digest: String,
    pub input_digest: String,
    pub config_digest: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanStatement {
    pub version: u32,
    pub purpose: String,
    pub issuer: String,
    pub role: String,
    pub not_before: u64,
    pub expires: u64,
    pub binding: Binding,
    pub scope: Vec<String>,
    pub rules: Vec<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessStatement {
    pub version: u32,
    pub purpose: String,
    pub issuer: String,
    pub role: String,
    pub not_before: u64,
    pub expires: u64,
    pub plan_digest: String,
    pub binding: Binding,
    pub report_digest: String,
    pub report_size: usize,
    pub started: bool,
    pub execution: Execution,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub errors_or_skips: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    MissingEvidence,
    InvalidSignature,
    InvalidStatement,
    WrongAuthority,
    StaleOrRevoked,
    OutsideValidity,
    WrongPlan,
    BindingMismatch,
    ReportMismatch,
    IncompleteExecution,
    InvalidReport,
    Replay,
    ReplayCapacity,
}

#[derive(Debug, Serialize)]
pub struct TestWitnessReceipt {
    pub schema: &'static str,
    pub test_only: bool,
    pub plan_statement_verified_by_test_root: bool,
    pub witness_statement_verified_by_test_root: bool,
    pub process_execution_independently_established: bool,
    pub matched_test_scope_claims: usize,
    pub outside_test_scope_claims: usize,
    pub rule_execution_verified: bool,
    pub coverage_verified: bool,
    pub policy_authority_verified: bool,
    pub policy_decision: Decision,
    pub adapter: AdapterReceipt,
}

/// In-memory fixture receipt consumption; no cross-process or production replay guarantee.
#[derive(Default)]
pub struct TestReceiptConsumer {
    consumed: BTreeSet<(String, String, String, u32)>,
}

impl TestReceiptConsumer {
    /// Only a same-instance prelaunch replay check; not durable.
    pub(crate) fn contains_binding(&self, b: &Binding) -> bool {
        self.consumed.contains(&(
            b.repository_id.clone(),
            b.run_id.clone(),
            b.stage_id.clone(),
            b.attempt,
        ))
    }
    pub fn verify_and_consume(
        &mut self,
        ctx: &TestContext<'_>,
        plan_bytes: &[u8],
        plan_sig: &[u8],
        witness_bytes: &[u8],
        witness_sig: &[u8],
        report: &[u8],
    ) -> Result<TestWitnessReceipt, Refusal> {
        let receipt = verify_test_execution(
            ctx,
            plan_bytes,
            plan_sig,
            witness_bytes,
            witness_sig,
            report,
        )?;
        let plan = verify_test_plan(ctx, plan_bytes, plan_sig)?;
        let b = plan.statement.binding;
        let identity = (b.repository_id, b.run_id, b.stage_id, b.attempt);
        if self.consumed.contains(&identity) {
            return Err(Refusal::Replay);
        }
        if self.consumed.len() >= 256 {
            return Err(Refusal::ReplayCapacity);
        }
        self.consumed.insert(identity);
        Ok(receipt)
    }
}

fn verify(key: &VerifyingKey, typ: &str, bytes: &[u8], signature: &[u8]) -> Result<(), Refusal> {
    if bytes.len() > MAX_INPUT {
        return Err(Refusal::InvalidStatement);
    }
    let sig = Signature::from_slice(signature).map_err(|_| Refusal::InvalidSignature)?;
    if key.is_weak() || key.verify_strict(&pae(typ, bytes), &sig).is_err() {
        return Err(Refusal::InvalidSignature);
    }
    Ok(())
}
fn token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_binding(b: &Binding) -> bool {
    !b.repository_id.is_empty()
        && b.repository_id.len() <= 20
        && !b.repository_id.starts_with('0')
        && b.repository_id.bytes().all(|x| x.is_ascii_digit())
        && hex(&b.source_sha, 40)
        && token(&b.run_id)
        && token(&b.stage_id)
        && b.attempt > 0
        && b.tool_version == "8.30.1"
        && hex(&b.binary_digest, 64)
        && hex(&b.input_digest, 64)
        && hex(&b.config_digest, 64)
}

/// An authenticated fixture statement, never an operational authorization.
pub struct VerifiedTestPlan {
    statement: PlanStatement,
}

impl VerifiedTestPlan {
    pub fn binding(&self) -> &Binding { &self.statement.binding }
    pub fn scope(&self) -> &[String] { &self.statement.scope }
    pub fn rules(&self) -> &[String] { &self.statement.rules }
}

/// Validate a purpose-bound plan before any test process is considered for execution.
pub fn verify_test_plan(
    ctx: &TestContext<'_>,
    plan_bytes: &[u8],
    plan_sig: &[u8],
) -> Result<VerifiedTestPlan, Refusal> {
    if !ctx.freshness_current || ctx.revoked {
        return Err(Refusal::StaleOrRevoked);
    }
    verify(ctx.plan_key, PLAN_TYPE, plan_bytes, plan_sig)?;
    let p: PlanStatement =
        serde_json::from_slice(plan_bytes).map_err(|_| Refusal::InvalidStatement)?;
    if p.version != 1 {
        return Err(Refusal::InvalidStatement);
    }
    if p.purpose != "execution-plan" || p.role != "plan-approver" || p.issuer != ctx.plan_issuer {
        return Err(Refusal::WrongAuthority);
    }
    if p.not_before >= p.expires || ctx.now < p.not_before || ctx.now >= p.expires {
        return Err(Refusal::OutsideValidity);
    }
    if !hex(ctx.expected_plan_digest, 64) || input_digest(plan_bytes) != ctx.expected_plan_digest {
        return Err(Refusal::WrongPlan);
    }
    if !valid_binding(&p.binding) {
        return Err(Refusal::BindingMismatch);
    }
    if p.scope.is_empty()
        || p.scope.len() > MAX_CHECKS
        || p.scope.iter().any(|s| !safe_relative(s))
        || p.scope.iter().collect::<BTreeSet<_>>().len() != p.scope.len()
        || p.rules.is_empty()
        || p.rules.len() > MAX_CHECKS
        || p.rules.iter().any(|s| !token(s))
        || p.rules.iter().collect::<BTreeSet<_>>().len() != p.rules.len()
    {
        return Err(Refusal::InvalidStatement);
    }
    Ok(VerifiedTestPlan { statement: p })
}

/// Verifies two purpose-separated signed statements against separately supplied synthetic roots.
/// Anti-replay is limited to matching the externally pinned plan and all signed run bindings.
pub fn verify_test_execution(
    ctx: &TestContext<'_>,
    plan_bytes: &[u8],
    plan_sig: &[u8],
    witness_bytes: &[u8],
    witness_sig: &[u8],
    report: &[u8],
) -> Result<TestWitnessReceipt, Refusal> {
    if !ctx.freshness_current || ctx.revoked {
        return Err(Refusal::StaleOrRevoked);
    }
    if report.is_empty() {
        return Err(Refusal::MissingEvidence);
    }
    if report.len() > MAX_INPUT_BYTES {
        return Err(Refusal::InvalidReport);
    }
    let p = verify_test_plan(ctx, plan_bytes, plan_sig)?.statement;
    verify(ctx.witness_key, WITNESS_TYPE, witness_bytes, witness_sig)?;
    let w: WitnessStatement =
        serde_json::from_slice(witness_bytes).map_err(|_| Refusal::InvalidStatement)?;
    if w.version != 1 {
        return Err(Refusal::InvalidStatement);
    }
    if w.purpose != "execution-witness"
        || w.role != "test-observer"
        || w.issuer != ctx.witness_issuer
    {
        return Err(Refusal::WrongAuthority);
    }
    if w.not_before >= w.expires || ctx.now < w.not_before || ctx.now >= w.expires {
        return Err(Refusal::OutsideValidity);
    }
    let plan_digest = input_digest(plan_bytes);
    if w.plan_digest != plan_digest {
        return Err(Refusal::WrongPlan);
    }
    if p.binding != w.binding {
        return Err(Refusal::BindingMismatch);
    }
    if w.report_size != report.len() || w.report_digest != input_digest(report) {
        return Err(Refusal::ReportMismatch);
    }
    if !w.started
        || w.execution != Execution::Complete
        || w.timed_out
        || w.errors_or_skips
        || w.exit_code.is_none()
    {
        return Err(Refusal::IncompleteExecution);
    }
    let b = &p.binding;
    let rules: Vec<&str> = p.rules.iter().map(String::as_str).collect();
    let plan = Plan {
        version: 1,
        repository_id: &b.repository_id,
        source_sha: &b.source_sha,
        run_id: &b.run_id,
        stage_id: &b.stage_id,
        attempt: b.attempt,
        tool_version: &b.tool_version,
        binary_digest: &b.binary_digest,
        input_digest: &b.input_digest,
        config_digest: &b.config_digest,
        required_rules: &rules,
    };
    let claim = ExecutionClaim {
        version: 1,
        repository_id: &w.binding.repository_id,
        source_sha: &w.binding.source_sha,
        run_id: &w.binding.run_id,
        stage_id: &w.binding.stage_id,
        attempt: w.binding.attempt,
        tool_version: &w.binding.tool_version,
        binary_digest: &w.binding.binary_digest,
        input_digest: &w.binding.input_digest,
        config_digest: &w.binding.config_digest,
        started: w.started,
        execution: w.execution,
        exit_code: w.exit_code,
        report_digest: Some(&w.report_digest),
        report_size: Some(w.report_size),
        errors_or_skips: w.errors_or_skips,
        timed_out: w.timed_out,
    };
    let adapter = gitleaks_adapter::assess(Some(report), Some(&plan), Some(&claim));
    if matches!(
        adapter.report,
        gitleaks_adapter::ReportState::Invalid
            | gitleaks_adapter::ReportState::Missing
            | gitleaks_adapter::ReportState::Null
    ) {
        return Err(Refusal::InvalidReport);
    }
    if !adapter.inconsistencies.is_empty()
        && !(adapter.inconsistencies.len() == 1
            && adapter.inconsistencies[0] == "NONZERO_EXIT_UNRESOLVED")
    {
        return Err(Refusal::InvalidReport);
    }
    let (matched, outside) =
        synthetic_scope_counts(report, &p.scope).map_err(|_| Refusal::InvalidReport)?;
    Ok(TestWitnessReceipt {
        schema: "sar-test-witness-receipt-v1",
        test_only: true,
        plan_statement_verified_by_test_root: true,
        witness_statement_verified_by_test_root: true,
        process_execution_independently_established: false,
        matched_test_scope_claims: matched,
        outside_test_scope_claims: outside,
        rule_execution_verified: false,
        coverage_verified: false,
        policy_authority_verified: false,
        policy_decision: Decision::Indeterminate,
        adapter,
    })
}
