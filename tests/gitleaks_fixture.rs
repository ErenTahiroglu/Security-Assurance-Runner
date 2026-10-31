use security_assurance_runner::gitleaks_fixture::{
    CollectionKind, FixtureImportError, MAX_FINDINGS, MAX_INPUT_BYTES, MAX_STRING_BYTES, MAX_TAGS,
    parse_gitleaks_fixture,
};
use serde_json::json;

const MARKER: &str = "INERT_FIXTURE_MARKER_DO_NOT_USE";

#[test]
fn fabricated_finding_is_redacted_and_unverified() {
    let input=json!([{"RuleID":"rule-id","Fingerprint":"fp","StartLine":1,"EndLine":2,"StartColumn":3,"EndColumn":4,"Secret":MARKER,"Match":MARKER,"Description":MARKER,"File":MARKER,"Link":MARKER}]).to_string();
    let r = parse_gitleaks_fixture(input.as_bytes()).unwrap();
    assert_eq!(r.findings.len(), 1);
    assert!(r.findings[0].rule_id_present);
    assert!(r.findings[0].fingerprint_present);
    assert_eq!(r.findings[0].start_line, 1);
    assert!(r.test_only);
    assert!(
        !r.scanner_executed
            && !r.provider_authenticated
            && !r.tool_binary_verified
            && !r.coverage_verified
            && !r.policy_authority_verified
            && !r.operational_pass
    );
    assert!(!serde_json::to_string(&r).unwrap().contains(MARKER));
    assert!(!format!("{r:?}").contains(MARKER));
}
#[test]
fn empty_array_null_and_missing_are_distinct() {
    let empty = parse_gitleaks_fixture(b"[]").unwrap();
    let nil = parse_gitleaks_fixture(b"null").unwrap();
    assert_eq!(empty.collection, CollectionKind::Array);
    assert_eq!(nil.collection, CollectionKind::Null);
    assert!(empty.findings.is_empty() && nil.findings.is_empty());
    assert!(!empty.coverage_verified && !nil.operational_pass);
    assert_eq!(
        parse_gitleaks_fixture(b"").unwrap_err(),
        FixtureImportError::MissingEvidence
    );
}
#[test]
fn malformed_truncated_utf8_and_top_level_are_rejected() {
    for input in [
        b"[".as_slice(),
        b"[{\"Secret\":\"x".as_slice(),
        b"{}".as_slice(),
        b"1".as_slice(),
        b"\"x\"".as_slice(),
        b"[\xff]".as_slice(),
    ] {
        assert_eq!(
            parse_gitleaks_fixture(input).unwrap_err(),
            FixtureImportError::InvalidFormat
        );
    }
}
#[test]
fn duplicate_and_unknown_fields_are_rejected_without_echo() {
    for input in [
        br#"[{"RuleID":"x","RuleID":"y"}]"#.as_slice(),
        br#"[{"Line":"ignored"}]"#.as_slice(),
        br#"[{"FutureField":"value"}]"#.as_slice(),
        br#"[{"Secret":"x","Secret":"y"}]"#.as_slice(),
    ] {
        assert_eq!(
            parse_gitleaks_fixture(input).unwrap_err(),
            FixtureImportError::InvalidFormat
        );
    }
}
#[test]
fn bounds_are_enforced() {
    assert_eq!(
        parse_gitleaks_fixture(&vec![b' '; MAX_INPUT_BYTES + 1]).unwrap_err(),
        FixtureImportError::TooLarge
    );
    let entries = vec![json!({}); MAX_FINDINGS + 1];
    assert_eq!(
        parse_gitleaks_fixture(json!(entries).to_string().as_bytes()).unwrap_err(),
        FixtureImportError::LimitExceeded
    );
    let oversized = json!([{"Secret":"x".repeat(MAX_STRING_BYTES+1)}]).to_string();
    assert_eq!(
        parse_gitleaks_fixture(oversized.as_bytes()).unwrap_err(),
        FixtureImportError::LimitExceeded
    );
    let tags = json!([{"Tags":vec!["x";MAX_TAGS+1]}]).to_string();
    assert_eq!(
        parse_gitleaks_fixture(tags.as_bytes()).unwrap_err(),
        FixtureImportError::LimitExceeded
    );
    let nested = format!("[{{\"Fragment\":{}{}}}]", "[".repeat(200), "]".repeat(200));
    assert!(parse_gitleaks_fixture(nested.as_bytes()).is_err());
}

#[test]
fn exact_limits_are_accepted_without_granting_coverage() {
    let entries = vec![json!({}); MAX_FINDINGS];
    let result = parse_gitleaks_fixture(json!(entries).to_string().as_bytes()).unwrap();
    assert_eq!(result.findings.len(), MAX_FINDINGS);
    let input =
        json!([{"Secret":"x".repeat(MAX_STRING_BYTES),"Tags":vec!["x";MAX_TAGS]}]).to_string();
    assert!(
        !parse_gitleaks_fixture(input.as_bytes())
            .unwrap()
            .coverage_verified
    );
    let mut max = vec![b' '; MAX_INPUT_BYTES - 2];
    max.extend_from_slice(b"[]");
    assert_eq!(
        parse_gitleaks_fixture(&max).unwrap().collection,
        CollectionKind::Array
    );
}
#[test]
fn native_types_and_fragment_are_restricted() {
    for value in [
        json!([{"RuleID":42}]),
        json!([{"StartLine":-1}]),
        json!([{"Entropy":"x"}]),
        json!([{"Tags":[1]}]),
        json!([{"Secret":null}]),
    ] {
        assert_eq!(
            parse_gitleaks_fixture(value.to_string().as_bytes()).unwrap_err(),
            FixtureImportError::InvalidFormat
        );
    }
    assert_eq!(
        parse_gitleaks_fixture(br#"[{"Fragment":{"x":"y"}}]"#).unwrap_err(),
        FixtureImportError::UnsupportedFragment
    );
    assert!(parse_gitleaks_fixture(br#"[{"Tags":null}]"#).is_ok());
    assert!(parse_gitleaks_fixture(br#"[{}]"#).is_ok());
    assert_eq!(
        parse_gitleaks_fixture(br#"[{"Entropy":1e100}]"#).unwrap_err(),
        FixtureImportError::LimitExceeded
    );
}
#[test]
fn all_untrusted_text_is_omitted_from_debug_and_json() {
    for field in [
        "RuleID",
        "Fingerprint",
        "Secret",
        "Match",
        "Description",
        "File",
        "SymlinkFile",
        "Commit",
        "Link",
        "Author",
        "Email",
        "Date",
        "Message",
    ] {
        let mut item = json!({});
        item[field] = json!(MARKER);
        let input = json!([item]).to_string();
        let receipt = parse_gitleaks_fixture(input.as_bytes()).unwrap();
        assert!(!serde_json::to_string(&receipt).unwrap().contains(MARKER));
        assert!(!format!("{receipt:?}").contains(MARKER));
    }
    let input = format!("[{{\"Secret\":\"{MARKER}\"");
    let err = parse_gitleaks_fixture(input.as_bytes()).unwrap_err();
    assert!(!format!("{err:?}").contains(MARKER));
}
#[test]
fn path_like_inputs_are_inert_and_never_returned() {
    for path in [
        "../neighbor",
        "/absolute/file",
        "C:\\secret",
        "\\\\server\\share",
        "a%2fb",
        "https://example.invalid/?token=INERT",
        "x\ny",
    ] {
        let input = json!([{"File":path,"Link":path,"SymlinkFile":path}]).to_string();
        let receipt = parse_gitleaks_fixture(input.as_bytes()).unwrap();
        let output = serde_json::to_string(&receipt).unwrap();
        assert!(!output.contains(path));
        assert!(!receipt.coverage_verified && !receipt.operational_pass);
    }
}
#[test]
fn duplicate_finding_identities_are_not_silently_merged() {
    let input = br#"[{"RuleID":"r","Fingerprint":"same"},{"RuleID":"r","Fingerprint":"same"}]"#;
    let receipt = parse_gitleaks_fixture(input).unwrap();
    assert_eq!(receipt.findings.len(), 2);
    assert!(!receipt.scanner_executed);
}
#[test]
fn fabricated_metadata_does_not_create_provenance_or_decision() {
    let input =
        json!([{"RuleID":"r","File":"repo/file","Commit":"a".repeat(40),"Fingerprint":"r:1"}])
            .to_string();
    for _ in 0..2 {
        let r = parse_gitleaks_fixture(input.as_bytes()).unwrap();
        assert_eq!(r.provenance, "UNVERIFIED");
        assert!(
            !r.coverage_verified
                && !r.provider_authenticated
                && !r.scanner_executed
                && !r.tool_binary_verified
                && !r.policy_authority_verified
                && !r.operational_pass
        );
    }
}
