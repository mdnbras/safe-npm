use crate::scanner::{RiskLevel, ScanReport};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::{fs, path::Path};

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Policy {
    pub block_at: RiskLevel,
    pub deny_rules: Vec<String>,
    pub allow_packages: Vec<String>,
    pub max_depth: usize,
    pub max_packages: usize,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            block_at: RiskLevel::High,
            deny_rules: vec![],
            allow_packages: vec![],
            max_depth: 8,
            max_packages: 500,
        }
    }
}
impl Policy {
    pub fn load(path: Option<&str>) -> Result<Self> {
        let chosen = path.map(str::to_owned).or_else(|| {
            Path::new(".safe-npm.toml")
                .exists()
                .then(|| ".safe-npm.toml".into())
        });
        match chosen {
            Some(p) => Ok(toml::from_str(
                &fs::read_to_string(&p).with_context(|| format!("failed to read policy {p}"))?,
            )
            .with_context(|| format!("invalid policy {p}"))?),
            None => Ok(Self::default()),
        }
    }
    pub fn blocks(&self, report: &ScanReport) -> bool {
        if self.allow_packages.iter().any(|p| p == &report.package) {
            return false;
        }
        risk_rank(&report.risk_level) >= risk_rank(&self.block_at)
            || report
                .findings
                .iter()
                .any(|f| self.deny_rules.iter().any(|r| r == &f.rule))
    }
}
fn risk_rank(r: &RiskLevel) -> u8 {
    match r {
        RiskLevel::Low => 0,
        RiskLevel::Medium => 1,
        RiskLevel::High => 2,
        RiskLevel::Critical => 3,
    }
}
