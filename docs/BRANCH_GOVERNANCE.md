# Branch governance

**OWNER-APPROVED REQUIREMENT:** The two long-lived branches are `main` and `development`.

- `main` is the last independently accepted and explicitly owner-authorized stable baseline/release. Current `main` is only the BOOTSTRAP-00 placeholder, not a functioning stable product or accepted release.
- `development` is the active branch for ordinary architecture and engineering work, including GOV-00.

Minimum promotion gate: exact candidate SHA; relevant actual validation evidence; independent Red Team acceptance; recorded residual risks; explicit owner authorization; and verification that the intended candidate is the one promoted. Author self-review, a green workflow, policy PASS, or documentation alone is insufficient.

**VERIFIED SOURCE FACT (2026-10-30):** SAR Issue #10 is open and records owner-governed protection work. GitHub reports `protected=false` for both branches, no repository rulesets, and zero Actions workflows. Therefore the branch policy is not technically enforced; a maintainer with write access could move or modify branches outside the documented promotion gate.

**RESIDUAL RISK:** Until protection is configured and bypass behavior verified under separate owner authorization, branch governance relies on human process and repository write permissions. This R1 work does not change protection, rulesets, default branch, or administrative permissions. Before any stable release, the owner should review #10, configure appropriate controls separately, and require evidence that they actually enforce the required promotion path.
