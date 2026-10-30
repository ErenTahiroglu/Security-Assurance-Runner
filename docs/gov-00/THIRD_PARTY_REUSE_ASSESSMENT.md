# Third-party reuse assessment

**Status:** REVIEW ONLY. No third-party implementation code copied or approved for incorporation.

| Candidate | Exact source | Reuse assessment | Classification |
|---|---|---|---|
| DefectDojo | `DefectDojo/django-DefectDojo`, `c360df03a9399cbe6b26138bd0289949c27eb732`, BSD-3-Clause | Read-only source review: `dojo/tools/sarif/parser.py`, `dojo/tools/semgrep/parser.py`, `dojo/finding/deduplication.py`. Parsers map source severity, locations, rule IDs, suppression/fingerprint data and define field-based dedupe inputs; central deduplication batches ORM records and uses Django/database/task infrastructure. Useful behavior patterns, but parser outputs and dedupe identity are tool-specific and should not be copied as universal truth. Prefer independent adapters and stable SAR identity rules. | REFERENCE_ONLY |
| GUAC | `guacsec/guac`, `a3f0a4df51abcf271221cf9c400de3158d9c20fa`, Apache-2.0 | Read-only source review: `pkg/ingestor/ingestor.go` composes document processing, format ingestion, collector-submission emission and assembler calls; `pkg/assembler/` has graph backends. Useful staged-pipeline separation, artifact identity, dependency/provenance relationships and backend seams. The GraphQL endpoint, collector service, graph assemblers and storage backends introduce distributed/database scope not justified for an initial CLI. Prefer a small in-process pipeline and standard SBOM/provenance payloads. | REFERENCE_ONLY |

The SHAs were independently resolved through GitHub commit metadata. DefectDojo parser and deduplication files and GUAC ingestor were read at those exact SHAs. DefectDojo's repository identifies BSD 3-Clause; GUAC source carries Apache-2.0 headers. Exact file-level terms and NOTICE obligations must be rechecked at the selected source revision before any reuse.

No source file or code snippet was copied. No dependencies were selected. Direct incorporation requires a later reviewed decision, source-file-level provenance, license compatibility analysis, preservation of copyright/license notices, applicable Apache NOTICE/patent terms, and updates to the code register and notices. SAR's PolyForm license does not replace or erase rights/conditions attached to third-party components.

**UNRESOLVED DECISION:** Whether a specific parser or library would reduce complexity versus a small adapter. Revisit only with concrete candidate, file, exact SHA, dependency tree and legal review where needed.
