# GOV-00 R2 Red Team response

**Status:** Author remediation handoff for independent review. GOV-00 is **not accepted**. This report does not authorize GOV-01 or claim any trust control is implemented.

**R2 scope:** Documentation and architecture only, resolving the owner-requested RT01 trust-bootstrap questions. No keys, signatures, runtime code, dependencies, scanner, real target test, AI agent, ECE/ATM change, repository setting, or `main` update is part of R2.

**Baseline:** R1 `development` SHA `4f0e4adbee4e75495b3917845d1558dfcdd6b85e`; `main` remains bootstrap SHA `956ae354e0e02e05154acc71a0158f5bf96f02fa`. The final R2 candidate SHA is recorded in the Issue #1 author handoff after commit.

## R2 concern dispositions

Each disposition below is an author assessment of the documentation response only. `FIXED` means the requested design or provenance clarification is present; it does not mean an executable control is implemented or independently accepted.

### R2-01 — Independent initial trust bootstrap

- **Original concern:** How does SAR distinguish owner-approved policy from a self-approved policy/key pair delivered by an untrusted repository, workflow, AI agent, or operator?
- **Correction:** [TRUST_BOOTSTRAP_AND_POLICY_AUTHORITY.md](TRUST_BOOTSTRAP_AND_POLICY_AUTHORITY.md), “Architecture alternatives,” “Trust bootstrap and policy lifecycle,” and “Initial enrollment,” recommends an independently enrolled owner verification root, external to the scanned tree, with a fingerprint checked through a separate owner-authenticated channel. It explicitly rejects self-signed key + policy manifests, trust-on-first-use, hash-as-approval, and fallback to project files. Missing/unrecognized anchor is `REFUSED`.
- **Source evidence:** [SLSA v1.2 verification](../SOURCE_PROVENANCE.md) recommends verifier-preconfigured trust roots and expectations; DSSE binds payload type and bytes but does not enroll keys; GitHub OIDC requires a relying party to validate identity claims.
- **Verification performed:** Compared the proposed enrollment path against Options A/B/C and confirmed that both key and fingerprint must not derive solely from the same untrusted source. Checked the `REFUSED` behavior against policy and execution documents.
- **Remaining limitation:** Owner has not selected the independent fingerprint channel, trust-store delivery, SAR executable verification, or key custody. No enrollment or signature verification is implemented.
- **Proposed disposition:** `PARTIALLY_FIXED` — bootstrap is concretely proposed; owner decision and implementation evidence remain open.

### R2-02 — Policy approval, scope, and exact signed bytes

- **Original concern:** A digest, Git commit, GitHub identity or valid signature without a pretrusted issuer and purpose does not prove owner approval. Policy authority must bind to project and check requirements.
- **Correction:** The trust design defines a typed, versioned signed-policy statement containing provider/repository ID, policy byte digest, sequence/version, applicability rule, complete mandatory/optional checks, coverage, allowed modes/categories, issuer role, timestamps, approval reference and delegation limits. It recommends a bounded repository-specific applicability window with the exact source commit bound per run; it compares this with per-commit approval. A hash identifies bytes only. DSSE-style payload-type binding is a candidate; its `keyid` is explicitly not an authority claim.
- **Source evidence:** DSSE current source at pinned repository revision and TUF v1.0.37 are recorded in [SOURCE_PROVENANCE.md](../SOURCE_PROVENANCE.md). RFC 8032 is an algorithm specification; Ed25519 and its API are research candidates only, with no algorithm/library selected.
- **Verification performed:** Cross-checked the policy fields and binding against `SECURITY_POLICY_MODEL.md`, `EXECUTION_AND_AUTHORIZATION.md` and the receipt contract. Confirmed policy digest and owner approval are represented separately.
- **Remaining limitation:** Envelope serialization, schema, canonical byte handling, accepted algorithm/API, issuer enrollment and policy lifetime are not implemented or owner-approved.
- **Proposed disposition:** `PARTIALLY_FIXED` — the record and authority semantics are specified for review; no authenticated policy runtime exists.

### R2-03 — Separate authorities, delegation, and purpose confusion

- **Original concern:** Policy approval, run request, target authorization, finding exception, independent review and release authorization must not be interchangeable.
- **Correction:** Added separate statement types and a role matrix for repository owner, policy issuer/delegate, security reviewer, requester, target owner, local process, CI workflow, Red Team reviewer, ECE, ATM and future AI. Delegation is owner-authenticated, purpose/repository/expiry bounded and non-transitive by default. Target consent is a separate record. Finding exceptions are finding/repository/commit specific and cannot waive execution. A policy PASS does not promote `development` to `main`. AI has no approval authority.
- **Source evidence:** GitHub ruleset/status-check/OIDC and Sigstore pages are used only for their documented identity/governance claims; no such claim is treated as owner approval. Exact sources are registered in [SOURCE_PROVENANCE.md](../SOURCE_PROVENANCE.md).
- **Verification performed:** Reviewed every listed actor's allowed and prohibited actions and checked that signed statement purposes cannot be substituted for each other.
- **Remaining limitation:** Human identity/delegation proof and target-owner control proof need an owner-selected operational mechanism and future tests. AI remains unimplemented and out of v1.
- **Proposed disposition:** `FIXED` for the separation-of-authority design; operational authentication remains a future blocker.

### R2-04 — Rotation, revocation, expiry, rollback, and offline limits

- **Original concern:** Explain how keys/policies are updated or revoked and what offline SAR can and cannot know, including clock and restored-backup limitations.
- **Correction:** The trust design defines increasing root/policy versions, a persisted local sequence floor, authenticated normal root transitions, out-of-band recovery after root compromise/loss, expiry/freshness decisions, cancellation/incomplete handling for newly learned revocation, and explicit limitations when clock or stored state is untrusted. It does not claim perfect offline revocation or anti-rollback; a full TUF implementation is not proposed.
- **Source evidence:** TUF specification 1.0.37 describes root roles, threshold/version/expiry and update anti-rollback/freeze mechanisms. Its specific guarantees are not attributed to SAR. The TUF version and source SHA are in [SOURCE_PROVENANCE.md](../SOURCE_PROVENANCE.md).
- **Verification performed:** Reviewed normal rotation, compromised-root recovery, lost key, revoked delegate, expired policy, stale offline cache, time uncertainty and whole-store rollback paths. Cross-checked `REFUSED`, `INCOMPLETE`, `INDETERMINATE` and `BLOCK` distinctions.
- **Remaining limitation:** Durable monotonic storage, trusted time, live revocation freshness and key custody depend on future host/deployment choices. Whole-host rollback or compromise can defeat local sequence state.
- **Proposed disposition:** `PARTIALLY_FIXED` — behavior and limits are proposed; no freshness, rotation or revocation mechanism is implemented.

### R2-05 — CI, LOCAL, HYBRID, GitHub trust boundaries

- **Original concern:** Execution identity and cross-mode stages must bind consistently; skipped/forged checks and workflow identity must not become policy approval.
- **Correction:** Added mode-specific trust rules binding repository ID, exact commit, workflow/run/attempt, immutable parent plan, approved policy/sequence, expected jobs, stage identity, target scope/expiry and artifacts. Required checks are reconciled against actual jobs because GitHub documents that conditional skipped jobs may report success. OIDC is execution identity, not issuer authority. Artifact attestations are provenance, not scan correctness. Privileged execution of untrusted pull-request code is prohibited by proposal. Stage mismatch or absence prevents complete/PASS.
- **Source evidence:** Official GitHub status, skipped-job, OIDC, artifact-attestation, `GITHUB_TOKEN` and `pull_request_target` sources are listed with 2026-10-30 retrieval date in [SOURCE_PROVENANCE.md](../SOURCE_PROVENANCE.md).
- **Verification performed:** Cross-checked execution mode rules against policy result states and findings/evidence stage receipts. Queried SAR GitHub branches/rulesets/workflows: `main` is `956ae354e0e02e05154acc71a0158f5bf96f02fa`, `development` is `4f0e4adbee4e75495b3917845d1558dfcdd6b85e`, both branches report `protected=false`, ruleset count is 0, Actions run count is 0.
- **Remaining limitation:** SAR has no CI workflow, GitHub evidence adapter, stage reconciler, target isolation or egress enforcement. Branch policy remains human process; Issue #10 remains open.
- **Proposed disposition:** `PARTIALLY_FIXED` — identity rules are documented, not enforced or validated.

### R2-06 — SAR, ECE and GitHub authority separation

- **Original concern:** Do not treat ECE verification or GitHub provenance as SAR policy authority, scan adequacy, or a stable external interface.
- **Correction:** Updated SAR architecture and source provenance to distinguish ECE frozen historical `main` bootstrap `bead6837e1ec03c8fe1ac3c8d09fd374fb8b0e02`; limited independently accepted offline GOV-01 verifier `415990746d5bbd3756f743b4b5a7673b36228567`; and later changing ECE `development` at `4cf9f2245f31d04c9c9699d9d1c998b0e658c7e7`. The current development includes GitHub adapter work and a follow-up after the earlier `ccde36586a4df170db38f018d6eb8a8a653de99f` candidate received required changes. Issue #4 remains open; no independent acceptance of current head or stable SAR-facing contract was observed. ECE checks do not prove scan adequacy. GitHub context/attestations do not approve policy.
- **Source evidence:** Requeried SAR and ECE repository IDs, branch heads, protection flags, rulesets, workflows, ECE Issue #3 acceptance comment, Issue #4 and comparison from accepted ECE SHA to current development. Exact source links and scope are in [SOURCE_PROVENANCE.md](../SOURCE_PROVENANCE.md).
- **Verification performed:** Confirmed SAR REST repository ID `1439402924`; confirmed ECE REST repository ID `1432704795`; compared ECE accepted GOV-01 SHA to current development; read current Issue #4 and its independent review status.
- **Remaining limitation:** ECE development can change. Recheck exact SHA and acceptance before GOV-05. No ECE interface is selected for SAR.
- **Proposed disposition:** `FIXED` for the source/status distinction in this R2 snapshot; integration remains unresolved.

### R2-07 — GOV-01 proof-of-concept prerequisites and boundaries

- **Original concern:** Avoid a circular architecture in which SAR trusts itself to install its own initial trust root; distinguish a demonstrator from deployable security tooling.
- **Correction:** The trust design lists requirements before any trusted PASS, synthetic-only fixtures, and deferred work. It states the root must be independently enrolled before SAR evaluates policy and that a signed policy cannot make a compromised executable trustworthy. Rust-first GOV-01 remains bounded, reversible and separately owner-authorized. DAST/fuzz, real scanners, network enforcement, authenticated external GitHub ingestion, production key integrations, ECE and AI remain deferred.
- **Verification performed:** Cross-checked `ROADMAP_AND_ACCEPTANCE_GATES.md`, existing R1 Rust-first proposal and GOV-01 issue #3 status. No GOV-01 work or dependency installation was started.
- **Remaining limitation:** Owner has not accepted GOV-00 or authorized GOV-01. A real trusted root, verifier integrity model and runtime test plan remain prerequisites.
- **Proposed disposition:** `FIXED` as a scope and dependency proposal only.

### R2-08 — Required negative specifications RT01-A through RT01-J

- **Original concern:** Provide falsifiable cases for self-approval, key substitution, branch-supplied trust, skipped/forged CI, exposed signing keys, stale policy replay, target misuse, cross-repository reuse and compromised runners.
- **Correction:** `TRUST_BOOTSTRAP_AND_POLICY_AUTHORITY.md`, “Required synthetic negative tests,” specifies attacker input, boundary, invalid claim, expected outcome, proposed control, milestone and residual limitation for all ten stable IDs. These are specifications, not executed tests.
- **Verification performed:** Checked each test ID and oracle against the authority model, policy states and CI/local/hybrid binding. Confirmed RT01-J records compromised runner as an assurance limitation rather than a claim signatures can cure.
- **Remaining limitation:** All tests require a separately authorized GOV-01 or later implementation; no key or test fixture was generated in R2.
- **Proposed disposition:** `FIXED` as documentation; runtime proof remains open.

### R2-09 — Branch governance and milestone tracking

- **Original concern:** Keep `main` frozen, retain `development` for active work, acknowledge absent controls and reconcile roadmap wording with owner's later instruction to maintain Issues #1–#11.
- **Correction:** Kept all R2 work on `development`; did not modify repository settings or `main`. Updated the roadmap to identify Issue #11 as authoritative tracker, supersede the obsolete “do not pre-open future issues” text, and direct maintainers to update existing issues without duplicates. Confirmed #10 remains an open, unconfigured-controls gate.
- **Source evidence:** Live SAR branch refs and ruleset count rechecked on 2026-10-30; Issue #10 and #11 current contents reviewed.
- **Verification performed:** `main` remains at bootstrap; `development` began at the expected R1 SHA; GitHub reported both branches unprotected, zero rulesets and zero Actions runs before R2 edits.
- **Remaining limitation:** Branch governance is not technically enforced. Owner must review #10 and authorize any future ruleset changes separately.
- **Proposed disposition:** `FIXED` for roadmap/branch documentation; administrative enforcement remains open.

## Changed-document map

| File | R2 purpose |
|---|---|
| `docs/gov-00/TRUST_BOOTSTRAP_AND_POLICY_AUTHORITY.md` | Primary trust-root design, alternatives, signed statement semantics, authority matrix, revocation/offline limits, execution modes, GOV-01 prerequisites, RT01-A–J. |
| `docs/gov-00/EXECUTION_AND_AUTHORIZATION.md` | Link R1 trust precedence to the proposed independently enrolled root and clarify refusal vs incomplete assessment. |
| `docs/gov-00/SECURITY_POLICY_MODEL.md` | Clarify untrusted policy input and pre-run `REFUSED` versus policy `BLOCK`/`INDETERMINATE`. |
| `docs/gov-00/TRUST_BOUNDARIES.md` | Add trust-root, policy-approval, CI identity and compromised-host boundaries. |
| `docs/gov-00/FINDINGS_AND_EVIDENCE_CONTRACT.md` | Add trust-root/sequence/typed approval evidence fields and separate authority purposes. |
| `docs/gov-00/ARCHITECTURE_AND_SCOPE.md` | Recheck and correct ECE current development/acceptance status; keep ECE outside SAR authority. |
| `docs/gov-00/THREAT_MODEL.md` | Add T-25 trust bootstrap/policy substitution/replay threat linked to RT01-A–J. |
| `docs/gov-00/ROADMAP_AND_ACCEPTANCE_GATES.md` | Make trust bootstrap a GOV-01 gate and align milestone issue guidance with owner-directed Issue #11. |
| `docs/gov-00/INDEPENDENT_REDTEAM_HANDOFF.md` | Add R2 review path and trust-specific review questions. |
| `docs/SOURCE_PROVENANCE.md` | Recheck ECE current SHA and add dated official GitHub, SLSA, DSSE, TUF, RFC and Sigstore source facts. |
| `docs/gov-00/GOV_00_R2_REDTEAM_RESPONSE.md` | This focused findings-to-fixes and source-evidence report. |

No new ADR was created: the architecture alternatives and explicit owner-decision gate are in the primary trust document, and marking an ADR accepted would overstate authority.

## Validation record

Validation commands and observed results:

- Reviewed the full changed-file set: **11 Markdown files** (9 modified, 2 added), with no unrelated files. Cross-document review aligned `REFUSED`, `INCOMPLETE`, `INDETERMINATE`, `BLOCK` and `PASS` semantics, authority scopes, ECE limits, AI-off scope, and GOV-01 authorization gates.
- `git diff --check` and `git diff --cached --check` — exit 0. The new documents also received a separate trailing-whitespace scan, with no matches.
- Relative Markdown link check (read-only; same command logic used for the recorded 23/39/0 result):

  ```sh
  python3 -c 'import pathlib,re,sys; root=pathlib.Path("."); files=list(root.glob("**/*.md")); broken=[]; n=0; rx=re.compile(r"\]\(([^)]+)\)")
  for f in files:
   for raw in rx.findall(f.read_text()):
    target=raw.strip().strip("<>")
    if target.startswith(("http://","https://","mailto:","#")): continue
    target=target.split("#",1)[0].split("?",1)[0]
    if not target: continue
    n+=1
    if not (f.parent/target).resolve().exists(): broken.append((str(f),raw))
  print(f"Markdown files={len(files)} relative links={n} broken={len(broken)}")
  for f,u in broken: print(f"BROKEN {f}: {u}")
  sys.exit(bool(broken))'
  ```

  Output: `Markdown files=23 relative links=39 broken=0`; exit 0. The macOS Python launcher emitted `xcrun` cache-creation (`Operation not permitted`) and file-event-stream warnings in the restricted environment; the Python check itself completed successfully. External sources were checked against the official pages and exact repository references in [`SOURCE_PROVENANCE.md`](../SOURCE_PROVENANCE.md); this is not a continuing uptime guarantee.
- Secret/private-path scan used `rg -n --` across all 11 changed Markdown files for private-key headers, common GitHub token formats, and local absolute-path prefixes; it returned no matches (expected `rg` exit 1). A trailing-whitespace scan of the two added documents also returned no matches.
- `git diff --exit-code -- LICENSE.md README.md .gitignore SECURITY.md docs/BRANCH_GOVERNANCE.md docs/THIRD_PARTY_CODE_REGISTER.md docs/THIRD_PARTY_NOTICES.md` — exit 0. No executable sources, workflow, dependency manifest, generated trust material or third-party code were added. No third-party implementation code was copied.
- GitHub checks before editing confirmed SAR REST repo ID `1439402924`, default `main`, `main` SHA `956ae354e0e02e05154acc71a0158f5bf96f02fa`, and `development` SHA `4f0e4adbee4e75495b3917845d1558dfcdd6b85e`; both branches were unprotected, ruleset count was 0, and Actions run count was 0. Local preflight found no stashes and one SAR worktree.
- Initial R2 content push: `git push origin development:development` — exit 0. A sandbox `git ls-remote` attempt then failed DNS resolution (`Could not resolve host: github.com`); rerunning with network escalation succeeded and returned `development=916bd39eeaaac912c170761f308c052a34a2e452`, `main=956ae354e0e02e05154acc71a0158f5bf96f02fa`. A follow-up documentation-only commit records the exact validation command and this observed limitation; its final candidate SHA and synchronization are recorded in the latest Issue #1 handoff. No force push was used.
- GitHub CI was **not run**. No security scanner, active test, cryptographic test or GOV-01 code was run or implemented.

## Independent handoff

Review the exact R2 commit on `development`, especially the trust design's bootstrap independence, owner decision boundaries, statement purpose separation, offline/key-compromise limits and RT01-A–J oracles. Reassess the live ECE/SAR source facts before relying on them. Confirm the proposed design is sufficient to begin a separately authorized proof-of-concept, or identify the remaining blockers. Issue #1 stays open; Issue #3 stays blocked; Issue #10 stays open; Issue #11 remains the canonical roadmap index. Only the owner decides GOV-00 acceptance and any GOV-01 authorization.
