# GOV-02 — negative test specifications

**NOT EXECUTED.** Every case uses invented, nonfunctional data and isolated local fixtures; no real credential, scanner, target or network is authorized in DESIGN R0. Common future oracle: inspect versioned receipt, assertion on independent state dimensions, captured redacted output and scope sentinel; a missing or invalid mandatory element must not yield trusted PASS. Limits below and the common compromised-host/provider/unknown-scanner-coverage limit remain after a successful fixture test. `I` = separately authorized GOV-02 fixture-only increment; `X` = separately authorized later real execution/containment increment; `P` = GOV-04 provider evidence; `D` = later SCA/data update increment. No milestone is implemented by this plan.

| ID | Attacker control / boundary | Fixture and expected result / future oracle | Gate and residual limit |
|---|---|---|---|
| G02-RT01 | Replaces binary / executable identity | Expected digest from trusted fixture differs from executable bytes; REFUSED before spawn; assert no process receipt. | X; host can lie. |
| G02-RT02 | Adds project config / policy boundary | Hostile config disables rule or injects command; reject or ignore only if tool-specific behavior proven; required rule still expected, else INDETERMINATE. | I for model, X for binary; configs may have unknown channels. |
| G02-RT03 | Supplies exit 0 / report boundary | Missing mandatory report with exit 0 => INCOMPLETE + INDETERMINATE; no empty-result synthesis. | I; exit claim is synthetic. |
| G02-RT04 | Supplies valid empty JSON / coverage boundary | Report lacks required-rule execution proof => INDETERMINATE; oracle required-vs-observed inventory. | I; tools may not report per-rule execution. |
| G02-RT05 | Changes repo/SHA / identity boundary | Wrong declared repository or full commit => reject binding; no PASS. | I; strings are not provider authentication. |
| G02-RT06 | Truncates output / parser boundary | Invalid/truncated UTF-8 or JSON => error + INCOMPLETE; bounded parser never returns empty success. | I; parser implementation not yet present. |
| G02-RT07 | Supplies traversal path / filesystem boundary | `../` or absolute/out-of-scope location => reject/quarantine, no follow-up file read; assert neighbor sentinel. | I for parser, X for OS; symlink races remain. |
| G02-RT08 | Places simulated credential in raw report / disclosure boundary | Inert fake secret in Match/Secret/Line must not appear in stdout, stderr, normal JSON, URL or Markdown; restricted raw hash/access tested separately. | I; synthetic strings do not prove absence of all leak channels. |
| G02-RT09 | Supplies stale/missing DB / freshness boundary | Missing DB, expired snapshot or unknown clock => INDETERMINATE; assert DB hash/freshness recorded. | D; offline cannot know unseen updates. |
| G02-RT10 | Supplies optional success / policy boundary | Optional success with failed required scanner => incomplete and no PASS. | I; no real processes. |
| G02-RT11 | Substitutes tool/config/rules / authorization boundary | Wrong binary/version/config hash or ruleset versus approved plan => REFUSED or INDETERMINATE; assert mismatch recorded. | I/X; checksum alone is not authority. |
| G02-RT12 | Crafts competing fingerprints / normalization boundary | Two outputs share text but incompatible native fingerprints => preserve separate findings, no silent merge. | I; equality cannot prove shared root cause. |
| G02-RT13 | Project requests network / capability boundary | Fake project metadata requests registry or remote validation => denied/refused; egress sentinel sees no connection in later sandbox test. | I for model, X for actual egress; host compromise. |
| G02-RT14 | Uses incompatible report schema / parser boundary | Unknown format/version => UNSUPPORTED_SCHEMA and INDETERMINATE, not empty findings. | I; schema version may not be explicit upstream. |
| G02-RT15 | Supplies syntactically valid report / provenance boundary | Valid bytes but no authenticated execution evidence => provenance UNVERIFIED, no operational PASS. | I/P; independent provider verification deferred. |
| G02-RT16 | Replays artifact / run identity boundary | Change parent run, plan, stage or attempt while preserving other fields => mismatch and no PASS. | I; trusted plan expectation must be external. |
| G02-RT17 | Places symlink/archive / scope boundary | Synthetic escape fixture => no neighbor read; unsupported containment => REFUSED. | X; OS-specific races and archive complexity remain. |
| G02-RT18 | Changes remote rule/plugin / configuration boundary | Different ruleset digest, implicit registry lookup or plugin => REFUSED; assert no fetch. | I/X; independently authenticate approved digest. |
| G02-RT19 | Adds ignore/exception / disposition authority | Unapproved suppression of high finding => retain finding or mark coverage uncertain; no PASS from suppression. | I/X; tool may suppress before report, requiring independent config proof. |
| G02-RT20 | Supplies stale cache success / data boundary | Cache claims success without timestamp/source/freshness => UNKNOWN or stale, INDETERMINATE. | D; timestamps and host state can be forged. |

The fixture-only proposal does not execute OS isolation or prove actual binary behavior; execution-only oracles remain deferred. Independent Red Team must verify later implementation against each oracle and report actual results, not infer success from this design.
