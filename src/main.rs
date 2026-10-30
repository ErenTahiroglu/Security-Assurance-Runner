use security_assurance_runner::contract::{MAX_INPUT, Manifest, input_digest};
use serde_json::json;
use std::io::{self, Read};
use std::process::ExitCode;
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 && args[1] == "version" {
        println!("security-assurance-runner 0.1.0 contract 1; NONPRODUCTION");
        return ExitCode::SUCCESS;
    }
    if args.len() != 2 || args[1] != "inspect" {
        eprintln!("usage: security-assurance-runner version | inspect < manifest.json");
        return ExitCode::from(2);
    }
    let mut data = Vec::new();
    if io::stdin()
        .lock()
        .take((MAX_INPUT + 1) as u64)
        .read_to_end(&mut data)
        .is_err()
    {
        eprintln!("INPUT_READ_ERROR");
        return ExitCode::from(5);
    }
    match Manifest::parse(&data) {
        Err(reason) => {
            println!(
                "{}",
                json!({"schema_version":1,"preflight":"REFUSED","reason":reason,"test_only":false,"independent_verification":"NOT_IMPLEMENTED"})
            );
            ExitCode::from(2)
        }
        Ok(m) => {
            println!(
                "{}",
                json!({"schema_version":1,"preflight":"REFUSED","reason":"NO_ENROLLED_AUTHORITY","repository_declared":m.repository,"run_id":m.run_id,"plan_id":m.plan_id,"stage":m.stage,"mode":m.mode,"policy_declared":m.policy,"input_sha256":input_digest(&data),"execution":"INCOMPLETE","policy_decision":"INDETERMINATE","test_only":false,"independent_verification":"NOT_IMPLEMENTED","limitations":["No owner trust enrollment or security checks implemented","Repository identity is caller-declared","No independent host verification"]})
            );
            ExitCode::from(3)
        }
    }
}
