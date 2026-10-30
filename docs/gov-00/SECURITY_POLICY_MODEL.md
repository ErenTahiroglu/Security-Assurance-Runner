# Security policy model

**OWNER-APPROVED REQUIREMENT:** Critical and High findings may block CI only under an explicitly defined enforcement policy. A successful workflow is not proof of merge protection; repository branch rules and required checks are separate administrative controls.

**ARCHITECTURAL PROPOSAL:** Keep these axes independent:
1. **Finding:** rule/tool, native severity, normalized severity, confidence, location, evidence, status and disposition.
2. **Execution:** expected checks, pass/fail/error/cancelled/skipped/unsupported, tool/database identity.
3. **Coverage:** tested scope, excluded scope, unsupported input and known limits.
4. **Policy:** policy digest, thresholds, required evidence, exception matching and outcome.
5. **Verification:** source-declared, machine-observed, independently reviewed; verifier identity and limits.
6. **Human authorization:** reviewer, reason, scope, expiry and owner decision.

Suggested run states: `COMPLETE`, `INCOMPLETE`, `FAILED`, `CANCELLED`. Suggested decision: `PASS`, `BLOCK`, `INDETERMINATE`. These are distinct; a finding status is never a run status. Missing required checks, stale evidence, parse errors and unavailable databases cannot silently become PASS. Failed checks stay visible. False-positive dispositions require reason, actor, scope and traceable history. Exceptions are narrow, time-bounded, reviewed and expire fail-closed.

### Adversarial examples

- Required scanner is disabled and remaining scanners find nothing: result is INCOMPLETE/INDETERMINATE, not PASS.
- Scanner emits malformed JSON then exits zero: parse failure remains visible; no clean result.
- High finding is marked false positive without reviewer/expiry: exception is invalid; policy may block.
- CI result belongs to parent commit rather than current candidate: stale/mismatched evidence cannot satisfy required checks.
- ECE verifies report digest and commit metadata: that supports integrity/source claims only; it does not establish vulnerability coverage.
- GitHub Actions is green but no required-check ruleset exists: do not claim merge blocking is enforced.

**UNRESOLVED DECISION:** Threshold semantics, severity mapping, confidence handling, baselines, exception authority and policy language.

**REQUIRED FUTURE TEST:** property-based policy cases, missing/skip/cancel paths, exception expiry and scope creep, tampered policy digest, severity source preservation, stale-run replay.
