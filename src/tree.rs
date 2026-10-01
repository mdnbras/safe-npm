use crate::registry::RegistryClient;
use crate::scanner::{self, RiskLevel, ScanReport};
use anyhow::Result;
use serde::Serialize;
use std::collections::{HashSet, VecDeque};

#[derive(Clone, Copy)]
pub struct TreeOptions { pub max_depth: usize, pub max_packages: usize }

#[derive(Debug, Serialize)]
pub struct PackageNode { pub depth: usize, pub requested: String, pub report: ScanReport }

#[derive(Debug, Serialize)]
pub struct TreeReport {
    pub root: ScanReport,
    pub risk_level: RiskLevel,
    pub packages_scanned: usize,
    pub files_scanned: usize,
    pub packages: Vec<PackageNode>,
    pub errors: Vec<String>,
}

pub fn scan_dependency_tree(spec: &str, options: TreeOptions) -> Result<TreeReport> {
    let registry=RegistryClient::new()?;
    let mut queue=VecDeque::from([(spec.to_owned(),0usize)]);
    let mut seen=HashSet::new();
    let mut packages=Vec::new();
    let mut errors=Vec::new();

    while let Some((requested,depth))=queue.pop_front() {
        if depth>options.max_depth || packages.len()>=options.max_packages { continue; }
        let artifact=match registry.resolve(&requested) {
            Ok(v)=>v, Err(e)=>{errors.push(format!("{requested}: {e:#}"));continue;}
        };
        let key=format!("{}@{}",artifact.name,artifact.version);
        if !seen.insert(key){continue;}

        let dependencies=artifact.dependencies.clone();
        match registry.download(&artifact)
            .and_then(|b|scanner::scan_tarball(&artifact.name,&artifact.version,&b)) {
            Ok(report)=>{
                packages.push(PackageNode{depth,requested:requested.clone(),report});
                if depth<options.max_depth {
                    for (name,range) in dependencies {
                        // npm aliases, git/file/http dependencies are deliberately not fetched in v0.2.
                        if range.starts_with("git") || range.starts_with("file:") || range.starts_with("http") {
                            errors.push(format!("{name}@{range}: unsupported dependency source"));
                            continue;
                        }
                        let spec=if range.starts_with("npm:") {
                            range.trim_start_matches("npm:").to_owned()
                        } else { format!("{name}@{range}") };
                        queue.push_back((spec,depth+1));
                    }
                }
            }
            Err(e)=>errors.push(format!("{}@{}: {e:#}",artifact.name,artifact.version)),
        }
    }

    let root=packages.first().map(|p|p.report.clone())
        .ok_or_else(||anyhow::anyhow!("root package could not be scanned"))?;
    let risk_level=packages.iter().map(|p|p.report.risk_level.clone())
        .max_by_key(risk_rank).unwrap_or(RiskLevel::Low);
    let files_scanned=packages.iter().map(|p|p.report.files_scanned).sum();
    Ok(TreeReport{root,risk_level,packages_scanned:packages.len(),files_scanned,packages,errors})
}

fn risk_rank(level:&RiskLevel)->u8 {
    match level { RiskLevel::Low=>0,RiskLevel::Medium=>1,RiskLevel::High=>2,RiskLevel::Critical=>3 }
}
