# Security policy model

**OWNER-APPROVED REQUIREMENT:** Critical and High findings may block CI only under an explicitly defined enforcement policy. A successful workflow is not proof of merge protection; repository branch rules and required checks are separate administrative controls.

**ARCHITECTURAL PROPOSAL:** A policy is trusted only when its exact version is obtained from an owner-approved authority source and its approval provenance is verified independently of the run request. A digest alone is not authorization. If the trusted policy source, approval, or required-check set is absent, conflicting, expired, or unrecognized before execution, refuse to start (`REFUSED`); there is no policy decision and no permissive default. If required evidence is lost after execution begins, retain the applicable execution state and use policy `INDETERMINATE`, unless valid evidence independently establishes a blocking finding. Operator-supplied policy and matching digests remain untrusted data.

The proposed trust-root enrollment, signed statement purposes, sequence/expiry behavior, and authority rules are defined in [trust bootstrap and policy authority](TRUST_BOOTSTRAP_AND_POLICY_AUTHORITY.md). If the trust anchor or policy approval is missing or invalid before a run, the action is `REFUSED` and no trusted policy evaluation begins. `REFUSED` is not a policy `BLOCK` and is never PASS. A run already underway that loses required trust/freshness or evidence is `INCOMPLETE` and policy `INDETERMINATE` unless valid evidence independently establishes a blocking finding.

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
| Trusted policy/authorization is untrusted, missing, expired, or conflicting before execution | No run began; `REFUSED` | No policy decision; required CI gate must return non-success |
| Required trust/freshness/evidence becomes unavailable after execution begins | `INCOMPLETE` (or applicable failed/cancelled state) | `INDETERMINATE` unless a valid blocking finding under trusted policy already requires `BLOCK` |

Precedence for a final policy decision: (1) BLOCK when valid evidence under a trusted policy establishes an unexcepted threshold violation; otherwise (2) INDETERMINATE when a required input/check/coverage condition is unresolved; otherwise (3) PASS. CI enforcement must treat both BLOCK and INDETERMINATE as a non-success for a required gate. A PASS is limited to the exact trusted policy and declared scope; it is not an independent verification, release approval, or framework compliance claim.

An exception requires a designated authorized reviewer, exact repository and commit, finding identity or explicit narrow selector, reason, decision time and expiry. It can change treatment only for the named finding(s), remains visible in the report, and cannot waive mandatory checks, evidence freshness, scope or target authorization. A PASS with any applied exception must visibly say so. Expired, conflicting, or broadened exceptions are invalid. Finding false-positive disposition and policy exception are separate records.

Execution states `COMPLETE`, `INCOMPLETE`, `FAILED`, `CANCELLED`; preflight disposition `REFUSED` means no authorized run began; policy decisions `PASS`, `BLOCK`, `INDETERMINATE`. Coverage, independent verification and human authorization remain separate. A finding status is never an execution state or policy decision.

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
