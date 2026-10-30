use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn inspect_refuses_without_an_enrolled_root() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_security-assurance-runner"))
        .arg("inspect")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let input = serde_json::json!({"version":1,"repository":{"provider":"github","id":"123","commit":"a".repeat(40)},
        "run_id":"r","plan_id":"p","mode":"CI","policy":{"id":"p","digest":"a".repeat(64),"sequence":1},
        "categories":["source"],"expected_checks":["c"],"stage":{"id":"s","attempt":1},"target_scope":"source",
        "limits":{"timeout_seconds":1,"output_bytes":1},"authorization_refs":["a"],"evidence_version":1});
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert_eq!(result.status.code(), Some(3));
    let output: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(output["preflight"], "REFUSED");
    assert_eq!(output["reason"], "NO_ENROLLED_AUTHORITY");
    assert_eq!(output["policy_decision"], "INDETERMINATE");
}
