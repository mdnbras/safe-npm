use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{fmt, io::Read};
use tar::Archive;

const MAX_FILE_SIZE: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity { Low, Medium, High, Critical }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum RiskLevel { Low, Medium, High, Critical }

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            Self::Low => "LOW", Self::Medium => "MEDIUM",
            Self::High => "HIGH", Self::Critical => "CRITICAL",
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule: String,
    pub severity: Severity,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanReport {
    pub package: String,
    pub version: String,
    pub score: u8,
    pub risk_level: RiskLevel,
    pub files_scanned: usize,
    pub findings: Vec<Finding>,
}

struct Rule {
    id: &'static str,
    severity: Severity,
    description: &'static str,
    regex: Regex,
}

fn rules() -> Vec<Rule> {
    vec![
        Rule { id: "process-execution", severity: Severity::High,
            description: "Process execution API detected (child_process/exec/spawn).",
            regex: Regex::new(r#"(?i)(child_process|\.execSync\s*\(|\.exec\s*\(|\.spawn\s*\()"#).unwrap() },
        Rule { id: "dynamic-code", severity: Severity::High,
            description: "Dynamic code execution detected (eval/new Function).",
            regex: Regex::new(r#"(?i)(\beval\s*\(|new\s+Function\s*\()"#).unwrap() },
        Rule { id: "credential-access", severity: Severity::Critical,
            description: "Possible access to credentials, tokens, SSH keys, npmrc or cloud secrets.",
            regex: Regex::new(r#"(?i)(\.npmrc|\.ssh|id_rsa|NPM_TOKEN|GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)"#).unwrap() },
        Rule { id: "environment-enumeration", severity: Severity::Medium,
            description: "Environment-variable access detected.",
            regex: Regex::new(r#"process\.env"#).unwrap() },
        Rule { id: "network-access", severity: Severity::Medium,
            description: "Network-capable API or URL detected.",
            regex: Regex::new(r#"(?i)(https?://|require\s*\(\s*['\"]https?['\"]|fetch\s*\(|axios\.)"#).unwrap() },
        Rule { id: "shell-command", severity: Severity::High,
            description: "Shell command pattern detected.",
            regex: Regex::new(r#"(?i)(/bin/(ba)?sh|powershell(?:\.exe)?|cmd\.exe|curl\s+|wget\s+)"#).unwrap() },
        Rule { id: "encoded-payload", severity: Severity::Medium,
            description: "Possible encoded/obfuscated payload detected.",
            regex: Regex::new(r#"(?i)(fromCharCode\s*\(|Buffer\.from\s*\([^\n]{0,200}base64|atob\s*\()"#).unwrap() },
    ]
}

pub fn scan_tarball(package: &str, version: &str, bytes: &[u8]) -> Result<ScanReport> {
    let decoder = GzDecoder::new(bytes);
    let mut archive = Archive::new(decoder);
    let rules = rules();
    let mut findings = Vec::new();
    let mut files_scanned = 0usize;

    for item in archive.entries().context("invalid npm tarball")? {
        let mut entry = item?;
        if !entry.header().entry_type().is_file() || entry.size() > MAX_FILE_SIZE {
            continue;
        }

        let path = entry.path()?.to_string_lossy().to_string();
        let interesting = path.ends_with(".js") || path.ends_with(".cjs") ||
            path.ends_with(".mjs") || path.ends_with(".ts") || path.ends_with("package.json");
        if !interesting { continue; }

        let mut content = String::new();
        if entry.read_to_string(&mut content).is_err() { continue; }
        files_scanned += 1;

        if path.ends_with("package.json") {
            scan_package_json(&content, &path, &mut findings);
        }

        for rule in &rules {
            if rule.regex.is_match(&content) {
                findings.push(Finding {
                    rule: rule.id.into(),
                    severity: rule.severity.clone(),
                    description: rule.description.into(),
                    path: Some(path.clone()),
                });
            }
        }
    }

    let score = calculate_score(&findings);
    let risk_level = match score {
        0..=19 => RiskLevel::Low,
        20..=44 => RiskLevel::Medium,
        45..=74 => RiskLevel::High,
        _ => RiskLevel::Critical,
    };

    Ok(ScanReport {
        package: package.into(), version: version.into(), score,
        risk_level, files_scanned, findings,
    })
}

fn scan_package_json(content: &str, path: &str, findings: &mut Vec<Finding>) {
    let Ok(json) = serde_json::from_str::<Value>(content) else { return };
    let Some(scripts) = json.get("scripts").and_then(Value::as_object) else { return };

    for lifecycle in ["preinstall", "install", "postinstall", "prepare"] {
        if let Some(command) = scripts.get(lifecycle).and_then(Value::as_str) {
            findings.push(Finding {
                rule: format!("lifecycle-{lifecycle}"),
                severity: Severity::High,
                description: format!("Lifecycle script can execute during installation: {command}"),
                path: Some(path.into()),
            });
        }
    }
}

fn calculate_score(findings: &[Finding]) -> u8 {
    let total: u16 = findings.iter().map(|f| match f.severity {
        Severity::Low => 3, Severity::Medium => 10,
        Severity::High => 25, Severity::Critical => 40,
    }).sum();
    total.min(100) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_is_capped() {
        let findings = (0..4).map(|_| Finding {
            rule: "x".into(), severity: Severity::Critical,
            description: "x".into(), path: None,
        }).collect::<Vec<_>>();
        assert_eq!(calculate_score(&findings), 100);
    }

    #[test]
    fn detects_lifecycle_script() {
        let mut findings = vec![];
        scan_package_json(r#"{"scripts":{"postinstall":"node setup.js"}}"#, "package/package.json", &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "lifecycle-postinstall");
    }
}
