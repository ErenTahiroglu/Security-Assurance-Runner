# Security policy model

**OWNER-APPROVED REQUIREMENT:** Critical and High findings may block CI only under an explicitly defined enforcement policy. A successful workflow is not proof of merge protection; repository branch rules and required checks are separate administrative controls.

**ARCHITECTURAL PROPOSAL:** A policy is trusted only when its exact version is obtained from an owner-approved authority source and its approval provenance is verified independently of the run request. A digest alone is not authorization. If the trusted policy source, approval, or required-check set is absent, conflicting, expired, or unrecognized, the policy result is `INDETERMINATE`; there is no permissive default. Operator-supplied policy and matching digests remain untrusted data.

Keep these axes independent:
1. **Finding:** rule/tool, native severity, normalized severity, confidence, location, evidence, status and disposition.
2. **Execution:** expected checks, pass/fail/error/cancelled/skipped/unsupported, tool/database identity.
3. **Coverage:** tested scope, excluded scope, unsupported input and known limits.
4. **Policy:** policy digest, thresholds, required evidence, exception matching and outcome.
5. **Verification:** source-declared, machine-observed, independently reviewed; verifier identity and limits.
6. **Human authorization:** reviewer, reason, scope, expiry and owner decision.

### Minimal proposed semantics

The trusted policy, not a run requester, declares each expected check mandatory or optional, defines required scope/coverage and sets an applicable vulnerability-data freshness limit. If no trusted check baseline can be resolved, the result cannot be PASS.

| Condition | Execution / coverage result | Policy decision |
|---|---|---|
| All mandatory checks ran successfully; reports parsed and were not truncated; required databases meet the trusted freshness rule; required scope is covered; no unexcepted finding meets a blocking threshold | Complete within declared scope | PASS |
| A valid, in-scope, non-excepted finding meets a trusted blocking threshold | Preserve actual execution and coverage states | BLOCK, even if another required check is incomplete |
| Any mandatory check is missing, skipped, failed, cancelled, unsupported, malformed, truncated, or bound to stale/conflicting evidence; required vulnerability data is stale; required target/scope is unsupported or coverage incomplete | Incomplete/failed/cancelled as applicable | INDETERMINATE unless a known blocking finding already requires BLOCK |
| Optional check is skipped or unsupported, and trusted policy explicitly classifies it optional | Complete only for policy-required scope; limitation remains visible | May be PASS if all mandatory conditions otherwise hold |
| Optional check fails, is cancelled, or emits a malformed/truncated report, and trusted policy explicitly classifies it optional | Preserve its actual non-success state and the resulting coverage limitation | May be PASS only for policy-required scope; never report the optional check as successful or imply its coverage |
| Required scanner succeeds with zero findings | Successful execution; does not establish no vulnerabilities exist | PASS only if every other mandatory evidence/coverage condition holds |
| Policy or authorization source is untrusted, missing, expired, or conflicting | Refused or incomplete | INDETERMINATE; required CI gate must return non-success |

Precedence for a final policy decision: (1) BLOCK when valid evidence already establishes an unexcepted threshold violation; otherwise (2) INDETERMINATE when a required input/check/coverage condition is unresolved; otherwise (3) PASS. CI enforcement must treat both BLOCK and INDETERMINATE as a non-success for a required gate. A PASS is limited to the exact trusted policy and declared scope; it is not an independent verification, release approval, or framework compliance claim.

An exception requires a designated authorized reviewer, exact repository and commit, finding identity or explicit narrow selector, reason, decision time and expiry. It can change treatment only for the named finding(s), remains visible in the report, and cannot waive mandatory checks, evidence freshness, scope or target authorization. A PASS with any applied exception must visibly say so. Expired, conflicting, or broadened exceptions are invalid. Finding false-positive disposition and policy exception are separate records.

Run states `COMPLETE`, `INCOMPLETE`, `FAILED`, `CANCELLED`; policy decisions `PASS`, `BLOCK`, `INDETERMINATE`; coverage, independent verification and human authorization remain separate. A finding status is never a run status.

### Adversarial examples

- Required scanner is disabled and remaining scanners find nothing: result is INCOMPLETE/INDETERMINATE, not PASS.
- Scanner emits malformed JSON then exits zero: parse failure remains visible; no clean result.
- High finding is marked false positive without reviewer/expiry: exception is invalid; policy may block.
- CI result belongs to parent commit rather than current candidate: stale/mismatched evidence cannot satisfy required checks.
- ECE verifies report digest and commit metadata: that supports integrity/source claims only; it does not establish vulnerability coverage.
- GitHub Actions is green but no required-check ruleset exists: do not claim merge blocking is enforced.
- A mandatory scanner is omitted while optional scanners return zero findings: INDETERMINATE, not PASS; the optional results cannot fill the mandatory check slot.

**UNRESOLVED DECISION:** Numeric severity thresholds, severity mapping, confidence handling, freshness values, accepted policy/authorization evidence mechanisms, exception reviewer delegation, and policy language.

**REQUIRED FUTURE TEST:** property-based policy cases, missing/skip/cancel paths, exception expiry and scope creep, tampered policy digest, severity source preservation, stale-run replay.
