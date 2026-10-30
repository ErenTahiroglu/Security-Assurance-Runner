# Third-party code register

**Current status:** No DefectDojo or GUAC implementation code is copied. GOV-01 declares external Cargo dependencies; see [dependency provenance](gov-01/GOV_01_IMPLEMENTATION_REPORT.md) and [notices](THIRD_PARTY_NOTICES.md).

| Project | Reference SHA | License stated by project | Files copied | Status |
|---|---|---|---|---|
| DefectDojo | `c360df03a9399cbe6b26138bd0289949c27eb732`; reviewed `dojo/tools/sarif/parser.py`, `dojo/tools/semgrep/parser.py`, `dojo/finding/deduplication.py` | BSD-3-Clause | None | REFERENCE_ONLY |
| GUAC | `a3f0a4df51abcf271221cf9c400de3158d9c20fa`; reviewed `pkg/ingestor/ingestor.go` and assembler package boundaries | Apache-2.0 | None | REFERENCE_ONLY |

Before approval of any reuse, add exact file/module and commit, copyright owner, license text and NOTICE obligations, behavior, dependency/transitive dependencies, architectural coupling, security/maintenance assessment, rationale versus independent adapter, review decision, and verification evidence. Do not remove upstream notices. See [reuse assessment](gov-00/THIRD_PARTY_REUSE_ASSESSMENT.md).
