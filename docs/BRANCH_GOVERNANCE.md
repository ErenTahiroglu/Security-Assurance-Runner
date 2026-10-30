# Branch governance

**OWNER-APPROVED REQUIREMENT:** The two long-lived branches are `main` and `development`.

- `main` is the last independently reviewed and explicitly owner-authorized baseline only after actual acceptance exists. Its initial commit is a bootstrap placeholder, not a validated release.
- `development` is the exclusive branch for ordinary architecture and engineering work, including GOV-00.

Promotion requires an exact candidate SHA, relevant actual validation evidence, independent Red Team review, recorded residual risks, and explicit owner authorization. Author self-review does not satisfy independent review. GOV-00 is not promoted in this milestone.

Recommended for later owner review: protect `main` against force pushes and deletion; require pull requests, designated reviews and owner-selected checks; restrict bypass permissions; consider CODEOWNERS. These are recommendations only. No repository ruleset or administrative setting is configured here.
