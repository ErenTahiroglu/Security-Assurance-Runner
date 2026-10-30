# Third-party reuse assessment

**Status:** REVIEW ONLY. No third-party implementation code copied or approved for incorporation.

| Candidate | Exact source | Reuse assessment | Classification |
|---|---|---|---|
| DefectDojo | `DefectDojo/django-DefectDojo`, `c360df03a9399cbe6b26138bd0289949c27eb732`, BSD-3-Clause | Useful patterns: importer/adapter boundaries, source-aware finding normalization, deduplication, lifecycle, false-positive/risk acceptance, recurring scan context and report interfaces. Large Django application, broad parser set and database model are coupled to vulnerability-management product; adopting architecture wholesale adds weight. Prefer independent small adapter contracts and cite upstream behavior. | REFERENCE_ONLY |
| GUAC | `guacsec/guac`, `a3f0a4df51abcf271221cf9c400de3158d9c20fa`, Apache-2.0 | Useful patterns: collectors separated from ingestion/parsing, artifact/package identity, dependency/provenance relationships, component boundaries and storage abstraction. Graph-centric distributed system, NATS, GraphQL, Kubernetes and database layers exceed initial CLI need. Prefer selected data concepts and interoperable SBOM/provenance formats. | REFERENCE_ONLY |

The SHAs were independently resolved through GitHub commit metadata. DefectDojo's repository identifies BSD 3-Clause; GUAC source carries Apache-2.0 headers and repository licensing. Exact file-level terms and NOTICE obligations must be rechecked at the selected source revision before any reuse.

No source file or code snippet was copied. No dependencies were selected. Direct incorporation requires a later reviewed decision, source-file-level provenance, license compatibility analysis, preservation of copyright/license notices, applicable Apache NOTICE/patent terms, and updates to the code register and notices. SAR's PolyForm license does not replace or erase rights/conditions attached to third-party components.

**UNRESOLVED DECISION:** Whether a specific parser or library would reduce complexity versus a small adapter. Revisit only with concrete candidate, file, exact SHA, dependency tree and legal review where needed.
