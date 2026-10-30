# GOV-01 security boundaries

**Status:** implementation boundary for the owner-authorized GOV-01 proof of concept; independent review pending. Accepted GOV-00 R2 architecture and its limitations remain the baseline.

## P2-RT01: executable identity and policy authority

SAR executable/build provenance, the independently enrolled target-project verification root, the target project's approved policy, and the target repository plus its exact source commit are four distinct identities. Trust in a SAR source commit or binary does not enroll a target-project authority. A valid policy signature does not establish the honesty of the executable or host. A SHA-256 digest alone authenticates neither. No production trust enrollment has occurred in this prototype.

## P2-RT02: publisher and target owners

The SAR software publisher distributes SAR; the operator requests a run. Each target repository policy owner establishes and approves that project's policy authority. The active-test target owner or controller separately authorizes its own target, scope and test categories. A security reviewer may review findings within separately granted authority; an independent Red Team reviews a candidate; an evidence verifier evaluates evidence within its own capabilities; and the stable-release authorizer makes a separate release decision. These roles may be held by one person in the pilot, but their authorities remain distinct. The SAR publisher has no universal right to approve another project's policy or active target. No universal publisher key is enrolled by default.

## Boundaries for implementation

A project manifest is untrusted and cannot enroll its own root, authorize an active test, or promote a release. Synthetic keys and verification fixtures are nonproduction; they cannot establish real owner approval or operational security PASS. Missing authority must refuse an authorized evaluation. The prototype does not implement scanners, active testing, real enrollment, ECE verification, provider identity verification, or host isolation. GitHub PR head/test-merge/merge-group identity is deferred to GOV-04.
