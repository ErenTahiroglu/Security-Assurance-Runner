use security_assurance_runner::contract::{MAX_CHECKS, MAX_INPUT, Manifest};
use serde_json::{Value, json};

fn manifest() -> Value {
    json!({"version":1,"repository":{"provider":"github","id":"123","commit":"0123456789abcdef0123456789abcdef01234567"},"run_id":"run","plan_id":"plan","mode":"CI","policy":{"id":"policy","digest":"a".repeat(64),"sequence":2},"categories":["source"],"expected_checks":["mandatory"],"stage":{"id":"one","attempt":1},"target_scope":"source","limits":{"timeout_seconds":10,"output_bytes":1024},"authorization_refs":["approval"],"evidence_version":1})
}
fn parse(v: &Value) -> Result<Manifest, &'static str> {
    Manifest::parse(&serde_json::to_vec(v).unwrap())
}
#[test]
fn bounded_and_strict_manifest() {
    assert!(parse(&manifest()).is_ok());
    assert_eq!(
        Manifest::parse(&vec![b' '; MAX_INPUT + 1]).unwrap_err(),
        "INPUT_TOO_LARGE"
    );
    assert!(Manifest::parse(br#"{"version":1,"version":1}"#).is_err());
    let nested = serde_json::to_string(&manifest()).unwrap().replace(
        "\"provider\":\"github\"",
        "\"provider\":\"github\",\"provider\":\"github\"",
    );
    assert!(Manifest::parse(nested.as_bytes()).is_err());
    let mut v = manifest();
    v["version"] = json!(2);
    assert!(parse(&v).is_err());
    let mut v = manifest();
    v["repository"]["commit"] = json!("1234");
    assert!(parse(&v).is_err());
    let mut v = manifest();
    v["policy"]["digest"] = json!("g".repeat(64));
    assert!(parse(&v).is_err());
    let mut v = manifest();
    v["trust_key"] = json!("attacker");
    assert!(parse(&v).is_err());
    let mut v = manifest();
    v["expected_checks"] = json!(
        (0..=MAX_CHECKS)
            .map(|n| format!("check{n}"))
            .collect::<Vec<_>>()
    );
    assert!(parse(&v).is_err());
    let mut v = manifest();
    v["expected_checks"] = json!(["same", "same"]);
    assert!(parse(&v).is_err());
    let deep = format!("{}0{}", "[".repeat(200), "]".repeat(200));
    assert!(Manifest::parse(deep.as_bytes()).is_err());
}
