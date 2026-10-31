use security_assurance_runner::gitleaks_fixture::{
    FixtureImportError, interpret_gitleaks_fixture_v2,
};

#[test]
fn sparse_elements_are_not_usable_findings() {
    let r = interpret_gitleaks_fixture_v2(br#"[{}]"#, None).unwrap();
    assert_eq!(r.parsed_elements, 1);
    assert_eq!(r.usable_fixture_findings, 0);
    assert_eq!(r.insufficient_fixture_findings, 1);
    assert!(!r.operational_pass);
}

#[test]
fn caller_fixture_catalog_maps_only_exact_known_rules() {
    let input = br#"[{"RuleID":"example-rule","File":"example","Fingerprint":"fp","StartLine":1,"EndLine":1,"StartColumn":1,"EndColumn":2}]"#;
    let r = interpret_gitleaks_fixture_v2(input, Some(&["example-rule"])).unwrap();
    assert_eq!(r.usable_fixture_findings, 1);
    assert_eq!(r.fixture_catalog_matches, 1);
    assert!(!r.coverage_verified && !r.native_report_authenticated);
    assert_eq!(
        interpret_gitleaks_fixture_v2(input, None)
            .unwrap()
            .fixture_catalog_matches,
        0
    );
}

#[test]
fn invalid_input_remains_rejected() {
    assert!(matches!(
        interpret_gitleaks_fixture_v2(b"", None),
        Err(FixtureImportError::MissingEvidence)
    ));
    assert!(interpret_gitleaks_fixture_v2(b"[{", None).is_err());
}

#[test]
fn insufficient_and_bad_coordinates_are_never_usable() {
    for input in [
        r#"[{"RuleID":"r"}]"#,
        r#"[{"RuleID":"r","File":"x","Fingerprint":"f","StartLine":2,"EndLine":1,"StartColumn":1,"EndColumn":1}]"#,
        r#"[{"RuleID":"r","File":"x","Fingerprint":"f","StartLine":1,"EndLine":1,"StartColumn":3,"EndColumn":2}]"#,
    ] {
        assert_eq!(
            interpret_gitleaks_fixture_v2(input.as_bytes(), None)
                .unwrap()
                .usable_fixture_findings,
            0
        );
    }
    assert!(interpret_gitleaks_fixture_v2(br#"[{"StartLine":4294967296}]"#, None).is_err());
}

#[test]
fn identities_are_private_and_caller_catalog_is_not_authority() {
    const MARKER: &str = "INERT_FIXTURE_MARKER_DO_NOT_USE";
    let input = format!(
        r#"[{{"RuleID":"{MARKER}","Fingerprint":"{MARKER}","File":"{MARKER}","Link":"https://example.invalid/{MARKER}","StartLine":1,"EndLine":1,"StartColumn":1,"EndColumn":1}}]"#
    );
    let unknown = interpret_gitleaks_fixture_v2(input.as_bytes(), Some(&["expected"])).unwrap();
    assert_eq!(unknown.unknown_fixture_rule_ids, Some(1));
    assert_eq!(unknown.fixture_catalog_matches, 0);
    let attacker = interpret_gitleaks_fixture_v2(input.as_bytes(), Some(&[MARKER])).unwrap();
    assert_eq!(attacker.fixture_catalog_matches, 1);
    assert!(attacker.catalog_is_caller_declared && attacker.test_only);
    assert!(
        !attacker.native_report_authenticated
            && !attacker.scanner_executed
            && !attacker.coverage_verified
            && !attacker.policy_authority_verified
            && !attacker.operational_pass
    );
    assert!(!format!("{attacker:?}").contains(MARKER));
    assert!(!serde_json::to_string(&attacker).unwrap().contains(MARKER));
    let err = interpret_gitleaks_fixture_v2(format!("[{{\"Secret\":\"{MARKER}").as_bytes(), None)
        .unwrap_err();
    assert!(!format!("{err:?}").contains(MARKER));
}

#[test]
fn fingerprint_equality_is_local_and_absence_is_explicit() {
    let input = br#"[{"Fingerprint":"a"},{"Fingerprint":"a"},{"Fingerprint":"b"},{}]"#;
    let r = interpret_gitleaks_fixture_v2(input, None).unwrap();
    assert_eq!(r.duplicate_fingerprint_claims, 1);
    assert_eq!(r.missing_fingerprint_claims, 1);
    assert_eq!(r.parsed_elements, 4);
}

#[test]
fn empty_null_missing_and_oversize_remain_distinct() {
    use security_assurance_runner::gitleaks_fixture::{CollectionKind, MAX_INPUT_BYTES};
    assert_eq!(
        interpret_gitleaks_fixture_v2(b"[]", None)
            .unwrap()
            .collection,
        CollectionKind::Array
    );
    assert_eq!(
        interpret_gitleaks_fixture_v2(b"null", None)
            .unwrap()
            .collection,
        CollectionKind::Null
    );
    assert!(matches!(
        interpret_gitleaks_fixture_v2(b"", None),
        Err(FixtureImportError::MissingEvidence)
    ));
    assert!(matches!(
        interpret_gitleaks_fixture_v2(&vec![b' '; MAX_INPUT_BYTES + 1], None),
        Err(FixtureImportError::TooLarge)
    ));
}
