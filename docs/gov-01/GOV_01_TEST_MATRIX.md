# GOV-01 R1 test matrix

All executable security cases use synthetic inputs. Their passing local results are author observations; exact candidate CI evidence belongs in Issue #3. No fixture verifies an owner, real provider, scanner or host.

| Case | Function, test and expected outcome | Classification and limit |
|---|---|---|
| RT01-A | `verify_synthetic_policy`, `fixture_policy_verifies_and_untrusted_key_pair_fails`: missing root returns MissingRoot. | EXECUTED_INTEGRATION, SYNTHETIC_ONLY; no real enrollment. |
| RT01-B | Same test signs replacement policy with an unknown fixture key; strict verification fails. | EXECUTED_INTEGRATION, SYNTHETIC_ONLY. |
| RT01-C | `Manifest::parse`, `bounded_and_strict_manifest`: project trust-key field is rejected. | EXECUTED_INTEGRATION; production trust-store mutation is absent. |
| RT01-D | `reconcile`, `missing_skipped_or_duplicate_checks_do_not_pass`: skipped required check is INDETERMINATE. | EXECUTED_INTEGRATION, SYNTHETIC_ONLY; GitHub job ingestion deferred. |
| RT01-E | `wrong_binding_and_stage_identity_cannot_be_reused`: different synthetic status source is rejected. | EXECUTED_INTEGRATION, SYNTHETIC_ONLY; live provider authentication deferred. |
| RT01-F | Runtime CLI and CI workflow have no signing-key injection; test signing key is public fixture material. | STATIC_INVARIANT; compromised-process secret theft cannot be excluded. |
| RT01-G | `wrong_claims_are_rejected_even_when_signed` and `signatures_types_freshness_and_duplicate_fields_are_rejected`: old sequence, expiry, stale freshness and revoked key fail. | EXECUTED_INTEGRATION, SYNTHETIC_ONLY; no trusted clock or rollback-proof store. |
| RT01-H | `wrong_claims_are_rejected_even_when_signed` rejects active purpose; `optional_cannot_substitute_required_and_active_is_rejected` rejects active stage. | EXECUTED_INTEGRATION, SYNTHETIC_ONLY; active execution does not exist. |
| RT01-I | Signed wrong repository and mismatched stage repository are rejected in the tests above. | EXECUTED_INTEGRATION, SYNTHETIC_ONLY; repository identity is not authenticated externally. |
| RT01-J | Authentic policy does not establish runner integrity. | ASSURANCE_LIMITATION; no compromised-host detector. |

Other tests: DSSE PAE vector, unknown root and signature, modified payload, typed claims, input size/version/duplicate fields and identity, missing/corrupt/duplicate artifacts, wrong policy/run/plan/attempt, absent/misspelled/duplicate checks, cancelled/failed execution, invalid success assertion, optional stage substitution, order independence, synthetic BLOCK and CLI refusal. The synthetic report parser supports its own limited schema, not scanner report formats. No target was scanned.
