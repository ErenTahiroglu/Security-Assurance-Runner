//! Nonproduction interpretation of untrusted Gitleaks-shaped fixture bytes.
use serde::{Deserialize, Serialize};

pub const MAX_INPUT_BYTES: usize = 65_536;
pub const MAX_FINDINGS: usize = 256;
pub const MAX_STRING_BYTES: usize = 4_096;
pub const MAX_TAGS: usize = 64;

#[derive(Debug, PartialEq, Eq)]
pub enum FixtureImportError {
    MissingEvidence,
    TooLarge,
    InvalidFormat,
    UnsupportedFragment,
    LimitExceeded,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CollectionKind {
    Array,
    Null,
}

#[derive(Debug, Serialize)]
pub struct FixtureFinding {
    pub rule_id_present: bool,
    pub fingerprint_present: bool,
    pub start_line: u32,
    pub end_line: u32,
    pub start_column: u32,
    pub end_column: u32,
}

#[derive(Debug, Serialize)]
pub struct FixtureImportReceipt {
    pub format: &'static str,
    pub collection: CollectionKind,
    pub findings: Vec<FixtureFinding>,
    pub test_only: bool,
    pub scanner_executed: bool,
    pub provider_authenticated: bool,
    pub tool_binary_verified: bool,
    pub coverage_verified: bool,
    pub policy_authority_verified: bool,
    pub operational_pass: bool,
    pub provenance: &'static str,
}

// Never derive Debug or Serialize: every native string is potentially sensitive.
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "PascalCase")]
struct NativeFinding {
    #[serde(rename = "RuleID")]
    rule_id: String,
    description: String,
    start_line: u32,
    end_line: u32,
    start_column: u32,
    end_column: u32,
    r#match: String,
    secret: String,
    file: String,
    symlink_file: String,
    commit: String,
    link: String,
    entropy: f64,
    author: String,
    email: String,
    date: String,
    message: String,
    tags: Option<Vec<String>>,
    fingerprint: String,
    fragment: Option<serde_json::Value>,
}

/// Parse fixture bytes without retaining or returning any native text or digest.
pub fn parse_gitleaks_fixture(input: &[u8]) -> Result<FixtureImportReceipt, FixtureImportError> {
    if input.is_empty() {
        return Err(FixtureImportError::MissingEvidence);
    }
    if input.len() > MAX_INPUT_BYTES {
        return Err(FixtureImportError::TooLarge);
    }
    let parsed: Option<Vec<NativeFinding>> =
        serde_json::from_slice(input).map_err(|_| FixtureImportError::InvalidFormat)?;
    let collection = if parsed.is_some() {
        CollectionKind::Array
    } else {
        CollectionKind::Null
    };
    let native = parsed.unwrap_or_default();
    if native.len() > MAX_FINDINGS {
        return Err(FixtureImportError::LimitExceeded);
    }
    let mut findings = Vec::with_capacity(native.len());
    for f in native {
        if f.fragment.is_some() {
            return Err(FixtureImportError::UnsupportedFragment);
        }
        let strings = [
            &f.rule_id,
            &f.description,
            &f.r#match,
            &f.secret,
            &f.file,
            &f.symlink_file,
            &f.commit,
            &f.link,
            &f.author,
            &f.email,
            &f.date,
            &f.message,
            &f.fingerprint,
        ];
        if strings.iter().any(|v| v.len() > MAX_STRING_BYTES)
            || f.tags.as_ref().is_some_and(|tags| {
                tags.len() > MAX_TAGS || tags.iter().any(|v| v.len() > MAX_STRING_BYTES)
            })
            || !f.entropy.is_finite()
            || f.entropy.abs() > f64::from(f32::MAX)
        {
            return Err(FixtureImportError::LimitExceeded);
        }
        findings.push(FixtureFinding {
            rule_id_present: !f.rule_id.is_empty(),
            fingerprint_present: !f.fingerprint.is_empty(),
            start_line: f.start_line,
            end_line: f.end_line,
            start_column: f.start_column,
            end_column: f.end_column,
        });
    }
    Ok(FixtureImportReceipt {
        format: "gitleaks-json-v8.30.1-fixture",
        collection,
        findings,
        test_only: true,
        scanner_executed: false,
        provider_authenticated: false,
        tool_binary_verified: false,
        coverage_verified: false,
        policy_authority_verified: false,
        operational_pass: false,
        provenance: "UNVERIFIED",
    })
}
