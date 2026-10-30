# Project charter

**OWNER-APPROVED REQUIREMENT:** SAR is intended to orchestrate appropriate security tools, normalize and interpret findings, and evaluate evidence-aware policy. It is not intended to replace Semgrep, CodeQL, ZAP, DefectDojo, or GUAC. Owner: Eren Tahiroğlu. License: PolyForm Noncommercial License 1.0.0.

## Scope

Proposed v1 includes SAST, SCA, secret/configuration and supply-chain assessment; explicitly authorized isolated DAST and fuzzing; control mapping; structured findings and reports; policy evaluation; CI/LOCAL/HYBRID execution; and evidence export. Proposed v2 adds opt-in AI review and separately authorized adversarial evaluation of AI agents. AI capabilities are not v1 requirements.

## Status vocabulary

Documents label claims **OWNER-APPROVED REQUIREMENT**, **VERIFIED SOURCE FACT**, **ARCHITECTURAL PROPOSAL**, **UNRESOLVED DECISION**, **REQUIRED FUTURE TEST**, or **IMPLEMENTED/TESTED FACT**. A proposal is not a control. A source fact establishes only what its cited source says. No security engine is implemented or independently validated by this charter.

## Non-goals

SAR is not a general-purpose scanner, vulnerability-management database, autonomous remediation agent, compliance certification, or ECE replacement. GOV-00 authorizes no runtime, scanner, real-target testing, tool installation, AI call, or production deployment.
