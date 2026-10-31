# GOV-02 R1 — fixture-only test matrix

All inputs are invented nonfunctional bytes; no scanner, credential or target is involved. Tests are integration tests in `tests/gitleaks_fixture.rs`; expected outcomes below must be verified against actual Cargo/CI results in Issue #4. The importer deliberately omits all native text and raw digest from ordinary output; `Debug` and JSON results expose only fixed labels, booleans and bounded coordinates.

| Test | Cases and future threat mapping | Classification / limit |
|---|---|---|
| `fabricated_finding_is_redacted_and_unverified` | Invented finding, marker in Secret/Match/Description/File/Link, output/debug redaction; all trust and PASS flags false; G02-RT08/15. | EXECUTED_INTEGRATION, SYNTHETIC_ONLY; no real provenance. |
| `empty_array_null_and_missing_are_distinct` | `[]`, `null`, missing bytes; G02-RT03/04/15. | EXECUTED_INTEGRATION; no scanner coverage. |
| `malformed_truncated_utf8_and_top_level_are_rejected` | malformed/truncated/UTF-8/object/string/number; G02-RT06/14. | EXECUTED_INTEGRATION. |
| `duplicate_and_unknown_fields_are_rejected_without_echo` | duplicate RuleID/Secret, Line, future field; G02-RT06/14. | EXECUTED_INTEGRATION; unknown native versions need separate adapter revision. |
| `bounds_are_enforced`, `exact_limits_are_accepted_without_granting_coverage` | input/findings/string/tag limit and deep nesting; G02-RT06/14. | EXECUTED_INTEGRATION; finite 64 KiB input; serde_json recursion guard. |
| `native_types_and_fragment_are_restricted` | malformed native types, unsupported nested Fragment, null Tags and omitted fields; G02-RT06/14. | EXECUTED_INTEGRATION; deliberately narrow producer subset. |
| `all_untrusted_text_is_omitted_from_debug_and_json` | Marker in all accepted strings and invalid input; G02-RT08. | EXECUTED_INTEGRATION; no assurance about other processes. |
| `path_like_inputs_are_inert_and_never_returned` | traversal, Unix/Windows/UNC, encoded, URL/control strings; G02-RT07/17. | EXECUTED_INTEGRATION plus STATIC_INVARIANT; paths discarded, no OS isolation claim. |
| `duplicate_finding_identities_are_not_silently_merged` | same fingerprint twice retained; G02-RT12. | EXECUTED_INTEGRATION; fingerprints withheld from output. |
| `fabricated_metadata_does_not_create_provenance_or_decision` | repeated fabricated source/fingerprint cannot yield authority; G02-RT05/15/16. | EXECUTED_INTEGRATION; no actual stage replay or provider check. |

G02-RT01, 02, 09–11, 13, 18–20 require future real identity/configuration, scanner, network, DB, or policy infrastructure and remain DEFERRED. G02-RT17 real symlink/archive containment and G02-RT15/16 authenticated provenance are DEFERRED even though inert string cases are modeled. CLI stderr testing is NOT APPLICABLE: no fixture CLI was added. The importer cannot decide operational PASS/BLOCK, execute a scanner or establish rule coverage.
