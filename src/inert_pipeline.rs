//! Linux-only, test-controlled inert Docker process. NEVER launches Gitleaks.
//! Docker is a test confinement boundary, not a production execution attestation.
use crate::contract::input_digest;
use crate::evaluation::Decision;
use crate::execution_witness::{
    Refusal, TestContext, TestReceiptConsumer, TestWitnessReceipt, WitnessStatement,
    verify_test_execution, verify_test_plan,
};
use crate::gitleaks_fixture::MAX_INPUT_BYTES;
use serde::Serialize;
use serde_json::Value;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const TEMPLATE: &[u8] = br#"[{"RuleID":"rule-a","File":"src/file.txt","Fingerprint":"inert","StartLine":1,"EndLine":1,"StartColumn":1,"EndColumn":2,"Secret":"INERT_PRIVATE_MARKER","Match":"INERT_PRIVATE_MARKER"}]"#;
const CONFIG: &[u8] = b"SAR_INERT_PIPELINE_CONFIG\n";
const DOCKERFILE: &str =
    "FROM scratch\nCOPY helper /probe\nUSER 65532:65532\nENTRYPOINT [\"/probe\"]\n";
const HELPER_C: &str = include_str!("../scripts/gov02/pipeline01/helper.c");
static SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestMode {
    Normal,
    Partial,
    Oversize,
    Failure,
    Timeout,
    Cancelled,
    /// Test-only simulated removal-command failure after a successful helper exit.
    CleanupFailure,
    /// Test-only simulated removal-command failure on an early helper error.
    ErrorCleanupFailure,
}
impl TestMode {
    fn command(self) -> Option<&'static str> {
        match self {
            Self::Normal => Some("copy"),
            Self::Partial => Some("partial"),
            Self::Oversize => Some("oversize"),
            Self::Failure => Some("fail"),
            Self::Timeout => Some("sleep"),
            Self::Cancelled => None,
            Self::CleanupFailure => Some("copy"),
            Self::ErrorCleanupFailure => Some("fail"),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum PipelineRefusal {
    Plan(Refusal),
    WrongInertIdentity,
    Replayed,
    Cancelled,
    HelperUnavailable,
    IsolationNotVerified,
    Timeout,
    UnexpectedExit,
    WitnessExitMismatch,
    InvalidOrUnboundedOutput,
    CleanupFailed,
    Receipt(Refusal),
}

#[derive(Debug, Serialize)]
pub struct InertPipelineReceipt {
    pub schema: &'static str,
    pub test_only: bool,
    pub inert_helper_process_observed: bool,
    pub actual_gitleaks_executed: bool,
    pub production_process_attested: bool,
    pub observed_inert_exit_code: i32,
    pub output_size: usize,
    pub operational_pass: bool,
    pub policy_decision: Decision,
    pub witness: TestWitnessReceipt,
}

fn run_limited(command: &mut Command, max: Duration) -> Result<i32, PipelineRefusal> {
    command.stdin(Stdio::null()).stderr(Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|_| PipelineRefusal::HelperUnavailable)?;
    let began = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status.code().unwrap_or(-1)),
            Ok(None) if began.elapsed() < max => thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(PipelineRefusal::Timeout);
            }
        }
    }
}
fn docker(args: &[&str], max: Duration) -> Result<i32, PipelineRefusal> {
    let mut command = Command::new("docker");
    command.args(args).stdout(Stdio::null());
    run_limited(&mut command, max)
}
fn docker_inspect(name: &str, destination: &Path) -> Result<Value, PipelineRefusal> {
    let file = File::create(destination).map_err(|_| PipelineRefusal::HelperUnavailable)?;
    let mut command = Command::new("docker");
    command.args(["inspect", name]).stdout(Stdio::from(file));
    if run_limited(&mut command, Duration::from_secs(8))? != 0 {
        return Err(PipelineRefusal::IsolationNotVerified);
    }
    let metadata = fs::metadata(destination).map_err(|_| PipelineRefusal::IsolationNotVerified)?;
    if metadata.len() > 65536 {
        return Err(PipelineRefusal::IsolationNotVerified);
    }
    let bytes = fs::read(destination).map_err(|_| PipelineRefusal::IsolationNotVerified)?;
    let a: Vec<Value> =
        serde_json::from_slice(&bytes).map_err(|_| PipelineRefusal::IsolationNotVerified)?;
    if a.len() != 1 {
        return Err(PipelineRefusal::IsolationNotVerified);
    }
    Ok(a.into_iter().next().expect("checked one element"))
}
fn verify_spec(value: &Value, root: &Path, name: &str, mode: &str) -> bool {
    let host = &value["HostConfig"];
    let cfg = &value["Config"];
    if value["Name"].as_str() != Some(format!("/{name}").as_str())
        || host["NetworkMode"].as_str() != Some("none")
        || host["ReadonlyRootfs"].as_bool() != Some(true)
        || host["Privileged"].as_bool() != Some(false)
        || host["PidsLimit"].as_i64() != Some(32)
        || host["Memory"].as_u64() != Some(134217728)
        || host["MemorySwap"].as_u64() != Some(134217728)
        || host["NanoCpus"].as_i64() != Some(500000000)
        || !host["Binds"].is_null()
        || cfg["User"].as_str() != Some("65532:65532")
        || cfg["Entrypoint"] != serde_json::json!(["/probe"])
        || cfg["Cmd"] != serde_json::json!([mode])
    {
        return false;
    }
    let caps = host["CapDrop"].as_array();
    if !caps.is_some_and(|a| a.iter().any(|v| v.as_str() == Some("ALL"))) {
        return false;
    }
    let security = host["SecurityOpt"].as_array();
    if !security.is_some_and(|a| {
        a.iter()
            .any(|v| v.as_str() == Some("no-new-privileges:true"))
    }) {
        return false;
    }
    if cfg["Env"].as_array().is_some_and(|env| {
        env.iter().filter_map(Value::as_str).any(|s| {
            ["GITHUB_", "GH_", "AWS_", "AZURE_", "GOOGLE_", "HOME="]
                .iter()
                .any(|p| s.starts_with(p))
        })
    }) {
        return false;
    }
    let mounts = match host["Mounts"].as_array() {
        Some(mounts) if mounts.len() == 3 => mounts,
        _ => return false,
    };
    let mut observed = std::collections::BTreeSet::new();
    for mount in mounts {
        let target = match mount["Target"].as_str() {
            Some(v) => v,
            None => return false,
        };
        let (dir, readonly) = match target {
            "/input" => ("input", true),
            "/config" => ("config", true),
            "/output" => ("output", false),
            _ => return false,
        };
        if !observed.insert(target)
            || mount["Type"].as_str() != Some("bind")
            || mount["Source"].as_str() != root.join(dir).to_str()
            || mount["ReadOnly"].as_bool().unwrap_or(false) != readonly
        {
            return false;
        }
    }
    true
}

struct Workspace {
    root: PathBuf,
    image: String,
}
impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = docker(&["image", "rm", "-f", &self.image], Duration::from_secs(8));
        let _ = fs::remove_dir_all(&self.root);
    }
}
struct ContainerGuard {
    name: String,
    created: bool,
}
impl ContainerGuard {
    /// Check cleanup even after an execution failure. A deliberately injected
    /// failure simulates a failed removal command; recovery is best-effort and
    /// NEVER converts the failure into a successful execution receipt.
    fn finish(self, inject_removal_failure: bool) -> Result<(), PipelineRefusal> {
        let removed = if inject_removal_failure {
            Ok(17) // Inert injected docker-rm failure; no shell or real scanner.
        } else {
            docker(&["rm", "-f", &self.name], Duration::from_secs(8))
        };
        let inspect = docker(&["inspect", &self.name], Duration::from_secs(8));
        let daemon = docker(&["ps", "-q"], Duration::from_secs(8));
        let gone = inspect == Ok(1) && daemon == Ok(0);
        let complete = gone && (!self.created || removed == Ok(0));
        if !complete || inject_removal_failure {
            // Recover an intentionally failed or genuine failed first removal.
            // A cleanup failure remains explicitly observable regardless of retry.
            let _ = docker(&["rm", "-f", &self.name], Duration::from_secs(8));
            return Err(PipelineRefusal::CleanupFailed);
        }
        Ok(())
    }
}
impl Drop for ContainerGuard {
    fn drop(&mut self) {
        let _ = docker(&["rm", "-f", &self.name], Duration::from_secs(8));
    }
}

pub struct InertCoordinator {
    workspace: Workspace,
    binary_digest: String,
    consumer: TestReceiptConsumer,
    last_container: Option<String>,
}
impl InertCoordinator {
    pub fn prepare() -> Result<Self, PipelineRefusal> {
        let uid = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let id = format!("{}-{uid}", std::process::id());
        let root = std::env::temp_dir().join(format!("sar-inert-pipeline-{id}"));
        fs::create_dir(&root).map_err(|_| PipelineRefusal::HelperUnavailable)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .map_err(|_| PipelineRefusal::HelperUnavailable)?;
        let image = format!("sar-pipeline-test:inert-{id}");
        let workspace = Workspace { root, image };
        for part in ["image", "input", "config", "output"] {
            fs::create_dir(workspace.root.join(part))
                .map_err(|_| PipelineRefusal::HelperUnavailable)?;
        }
        fs::set_permissions(
            workspace.root.join("output"),
            fs::Permissions::from_mode(0o777),
        )
        .map_err(|_| PipelineRefusal::HelperUnavailable)?;
        fs::write(workspace.root.join("input/report-template.json"), TEMPLATE)
            .map_err(|_| PipelineRefusal::HelperUnavailable)?;
        fs::write(workspace.root.join("config/approved.txt"), CONFIG)
            .map_err(|_| PipelineRefusal::HelperUnavailable)?;
        fs::write(workspace.root.join("image/helper.c"), HELPER_C)
            .map_err(|_| PipelineRefusal::HelperUnavailable)?;
        fs::write(workspace.root.join("image/Dockerfile"), DOCKERFILE)
            .map_err(|_| PipelineRefusal::HelperUnavailable)?;
        let exec = workspace.root.join("image/helper");
        let mut compile = Command::new("cc");
        compile
            .args([
                "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-static", "-o",
            ])
            .arg(&exec)
            .arg(workspace.root.join("image/helper.c"))
            .stdout(Stdio::null());
        if run_limited(&mut compile, Duration::from_secs(35))? != 0 {
            return Err(PipelineRefusal::HelperUnavailable);
        }
        let binary = fs::read(&exec).map_err(|_| PipelineRefusal::HelperUnavailable)?;
        if binary.len() < 1000 || binary.len() > 3_000_000 {
            return Err(PipelineRefusal::HelperUnavailable);
        }
        let binary_digest = input_digest(&binary);
        let root_str = workspace.root.join("image");
        let mut build = Command::new("docker");
        build
            .args([
                "build",
                "--network",
                "none",
                "--pull=false",
                "-q",
                "-t",
                &workspace.image,
            ])
            .arg(&root_str)
            .stdout(Stdio::null());
        if run_limited(&mut build, Duration::from_secs(65))? != 0 {
            return Err(PipelineRefusal::HelperUnavailable);
        }
        Ok(Self {
            workspace,
            binary_digest,
            consumer: TestReceiptConsumer::default(),
            last_container: None,
        })
    }
    pub fn binary_digest(&self) -> &str {
        &self.binary_digest
    }
    pub fn input_digest(&self) -> String {
        input_digest(TEMPLATE)
    }
    pub fn config_digest(&self) -> String {
        input_digest(CONFIG)
    }
    pub fn expected_inert_report(&self) -> &'static [u8] {
        TEMPLATE
    }
    pub fn last_container_name(&self) -> Option<&str> {
        self.last_container.as_deref()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run(
        &mut self,
        ctx: &TestContext<'_>,
        plan_bytes: &[u8],
        plan_sig: &[u8],
        witness_bytes: &[u8],
        witness_sig: &[u8],
        mode: TestMode,
        timeout: Duration,
    ) -> Result<InertPipelineReceipt, PipelineRefusal> {
        let checked = verify_test_plan(ctx, plan_bytes, plan_sig).map_err(PipelineRefusal::Plan)?;
        let binding = checked.binding();
        if binding.binary_digest != self.binary_digest
            || binding.input_digest != self.input_digest()
            || binding.config_digest != self.config_digest()
            || checked.scope().len() != 1
            || checked.scope()[0] != "src/file.txt"
            || !checked.rules().iter().any(|v| v == "rule-a")
        {
            return Err(PipelineRefusal::WrongInertIdentity);
        }
        // Precheck only rejects bad signed fixtures before launch. It proves no process ran.
        verify_test_execution(
            ctx,
            plan_bytes,
            plan_sig,
            witness_bytes,
            witness_sig,
            TEMPLATE,
        )
        .map_err(PipelineRefusal::Plan)?;
        if self.consumer.contains_binding(binding) {
            return Err(PipelineRefusal::Replayed);
        }
        let argv = mode.command().ok_or(PipelineRefusal::Cancelled)?;
        if timeout.is_zero() || timeout > Duration::from_secs(8) {
            return Err(PipelineRefusal::HelperUnavailable);
        }
        let id = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = format!("sar-inert-exec-{}-{id}", std::process::id());
        self.last_container = Some(name.clone());
        let input = self.workspace.root.join("input");
        let config = self.workspace.root.join("config");
        let output = self.workspace.root.join("output");
        // Failed attempt output can never be reused.
        let _ = fs::remove_file(output.join("report.json"));
        let in_mount = format!(
            "type=bind,source={},target=/input,readonly",
            input.display()
        );
        let conf_mount = format!(
            "type=bind,source={},target=/config,readonly",
            config.display()
        );
        let out_mount = format!("type=bind,source={},target=/output", output.display());
        // Install the cleanup guard BEFORE create: even a failed/timed-out Docker CLI
        // can have created a named container.
        let mut container = ContainerGuard {
            name: name.clone(),
            created: false,
        };
        let result = (|| -> Result<Vec<u8>, PipelineRefusal> {
            let create = docker(
                &[
                    "create",
                    "--name",
                    &container.name,
                    "--network",
                    "none",
                    "--read-only",
                    "--user",
                    "65532:65532",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges:true",
                    "--memory",
                    "128m",
                    "--memory-swap",
                    "128m",
                    "--cpus",
                    "0.5",
                    "--pids-limit",
                    "32",
                    "--mount",
                    &in_mount,
                    "--mount",
                    &conf_mount,
                    "--mount",
                    &out_mount,
                    &self.workspace.image,
                    argv,
                ],
                Duration::from_secs(12),
            )?;
            if create != 0 {
                return Err(PipelineRefusal::HelperUnavailable);
            }
            container.created = true;
            let inspected =
                docker_inspect(&container.name, &self.workspace.root.join("inspect.json"))?;
            if !verify_spec(&inspected, &self.workspace.root, &container.name, argv) {
                return Err(PipelineRefusal::IsolationNotVerified);
            }
            let status = docker(&["start", "-a", &container.name], timeout)?;
            // Docker start -a may propagate the container exit code or return 0.
            let ended =
                docker_inspect(&container.name, &self.workspace.root.join("finished.json"))?;
            let exit = ended["State"]["ExitCode"].as_i64();
            if ended["State"]["Running"].as_bool() != Some(false)
                || ended["State"]["OOMKilled"].as_bool() != Some(false)
                || ended["State"]["Error"].as_str() != Some("")
                || exit != Some(23)
                || !(status == 0 || status == 23)
            {
                return Err(PipelineRefusal::UnexpectedExit);
            }
            // The signature was verified before launch. Bind its declared process
            // outcome to Docker's observed termination instead of trusting claims.
            let signed: WitnessStatement = serde_json::from_slice(witness_bytes)
                .map_err(|_| PipelineRefusal::WitnessExitMismatch)?;
            if signed.exit_code != Some(23) || signed.exit_code.map(i64::from) != exit {
                return Err(PipelineRefusal::WitnessExitMismatch);
            }
            // Refuse an output symlink before opening any report bytes.
            if !fs::symlink_metadata(output.join("report.json"))
                .map_err(|_| PipelineRefusal::InvalidOrUnboundedOutput)?
                .file_type()
                .is_file()
            {
                return Err(PipelineRefusal::InvalidOrUnboundedOutput);
            }
            let f = File::open(output.join("report.json"))
                .map_err(|_| PipelineRefusal::InvalidOrUnboundedOutput)?;
            let mut bytes = Vec::new();
            f.take(MAX_INPUT_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| PipelineRefusal::InvalidOrUnboundedOutput)?;
            if bytes != TEMPLATE {
                return Err(PipelineRefusal::InvalidOrUnboundedOutput);
            }
            Ok(bytes)
        })();
        // Cleanup runs for EVERY post-guard error, including create/inspect,
        // timeout, unexpected exit, malformed output and witness disagreement.
        let injected_cleanup_fault = matches!(
            mode,
            TestMode::CleanupFailure | TestMode::ErrorCleanupFailure
        );
        let cleanup = container.finish(injected_cleanup_fault);
        if let Err(error) = cleanup {
            return Err(error);
        }
        let bytes = result?;
        let size = bytes.len();
        let witness = self
            .consumer
            .verify_and_consume(
                ctx,
                plan_bytes,
                plan_sig,
                witness_bytes,
                witness_sig,
                &bytes,
            )
            .map_err(PipelineRefusal::Receipt)?;
        Ok(InertPipelineReceipt {
            schema: "sar-inert-execution-pipeline-v1",
            test_only: true,
            inert_helper_process_observed: true,
            actual_gitleaks_executed: false,
            production_process_attested: false,
            observed_inert_exit_code: 23,
            output_size: size,
            operational_pass: false,
            policy_decision: Decision::Indeterminate,
            witness,
        })
    }
}
