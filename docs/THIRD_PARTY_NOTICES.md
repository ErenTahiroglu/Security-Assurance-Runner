# Third-party notices

The GOV-01 prototype declares Rust dependencies in `Cargo.lock`. Direct dependencies are serde, serde_json and sha2 (MIT OR Apache-2.0), and ed25519-dalek (BSD-3-Clause). Transitive dependencies have their own licenses; metadata and sources are summarized in the [GOV-01 report](gov-01/GOV_01_IMPLEMENTATION_REPORT.md). The lockfile records versions and registry checksums.

These crates retain their respective copyright and license terms. A future binary or source distribution must include applicable third-party license texts, copyright notices and any required attribution for the exact resolved dependencies; this repository does not yet provide a completed distribution notice bundle. The SAR PolyForm license does not replace those terms.

DefectDojo and GUAC are cited as read-only architecture references in [source provenance](SOURCE_PROVENANCE.md). Citation does not incorporate their code. If code or dependencies are later approved, reproduce the applicable license texts and notices here or in the required distribution location, preserve file-level notices, and record provenance before distribution.
