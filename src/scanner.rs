use crate::registry::RegistrySignals;
use crate::behavior;
use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{fmt, io::Read};
use tar::Archive;

const MAX_FILE_SIZE:u64=2*1024*1024;
const POPULAR_PACKAGES:[&str;20]=["react","react-dom","lodash","express","axios","typescript","webpack","next","vue","chalk","commander","dotenv","debug","uuid","moment","rxjs","eslint","prettier","jest","vite"];

#[derive(Debug,Clone,Serialize,Deserialize,PartialEq)]
#[serde(rename_all="UPPERCASE")]
pub enum Severity{Low,Medium,High,Critical}
impl fmt::Display for Severity{fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result{write!(f,"{}",match self{Self::Low=>"LOW",Self::Medium=>"MEDIUM",Self::High=>"HIGH",Self::Critical=>"CRITICAL"})}}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq)]
#[serde(rename_all="UPPERCASE")]
pub enum RiskLevel{Low,Medium,High,Critical}
impl fmt::Display for RiskLevel{fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result{write!(f,"{}",match self{Self::Low=>"LOW",Self::Medium=>"MEDIUM",Self::High=>"HIGH",Self::Critical=>"CRITICAL"})}}

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct Finding{pub rule:String,pub severity:Severity,pub description:String,#[serde(skip_serializing_if="Option::is_none")]pub path:Option<String>}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct ScanReport{pub package:String,pub version:String,pub score:u8,pub risk_level:RiskLevel,pub files_scanned:usize,pub findings:Vec<Finding>}

struct Rule{id:&'static str,severity:Severity,description:&'static str,regex:Regex}
fn rules()->Vec<Rule>{vec![
    Rule{id:"process-execution",severity:Severity::High,description:"Process execution API detected.",regex:Regex::new(r#"(?i)(child_process|\.execSync\s*\(|\.exec\s*\(|\.spawn\s*\()"#).unwrap()},
    Rule{id:"dynamic-code",severity:Severity::High,description:"Dynamic code execution detected.",regex:Regex::new(r#"(?i)(\beval\s*\(|new\s+Function\s*\()"#).unwrap()},
    Rule{id:"credential-access",severity:Severity::Critical,description:"Possible credential/token/key access.",regex:Regex::new(r#"(?i)(\.npmrc|\.ssh|id_rsa|NPM_TOKEN|GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)"#).unwrap()},
    Rule{id:"environment-enumeration",severity:Severity::Medium,description:"Environment-variable access detected.",regex:Regex::new(r#"process\.env"#).unwrap()},
    Rule{id:"network-access",severity:Severity::Medium,description:"Network-capable API or URL detected.",regex:Regex::new(r#"(?i)(https?://|require\s*\(\s*['\"]https?['\"]|fetch\s*\(|axios\.)"#).unwrap()},
    Rule{id:"shell-command",severity:Severity::High,description:"Shell command pattern detected.",regex:Regex::new(r#"(?i)(/bin/(ba)?sh|powershell(?:\.exe)?|cmd\.exe|curl\s+|wget\s+)"#).unwrap()},
    Rule{id:"encoded-payload",severity:Severity::Medium,description:"Possible encoded/obfuscated payload detected.",regex:Regex::new(r#"(?i)(fromCharCode\s*\(|Buffer\.from\s*\([^\n]{0,200}base64|atob\s*\()"#).unwrap()},
]}

pub fn scan_tarball_with_signals(package:&str,version:&str,bytes:&[u8],signals:Option<&RegistrySignals>)->Result<ScanReport>{
    let decoder=GzDecoder::new(bytes);let mut archive=Archive::new(decoder);let rules=rules();
    let mut findings=metadata_findings(package,signals);let mut files_scanned=0usize;
    for item in archive.entries().context("invalid npm tarball")?{
        let mut entry=item?;if !entry.header().entry_type().is_file()||entry.size()>MAX_FILE_SIZE{continue;}
        let path=entry.path()?.to_string_lossy().to_string();
        let interesting=[".js",".cjs",".mjs",".ts"].iter().any(|e|path.ends_with(e))||path.ends_with("package.json");
        if !interesting{continue;}
        let mut content=String::new();if entry.read_to_string(&mut content).is_err(){continue;}files_scanned+=1;
        if path.ends_with("package.json"){scan_package_json(&content,&path,&mut findings);}
        for rule in &rules{if rule.regex.is_match(&content){findings.push(Finding{rule:rule.id.into(),severity:rule.severity.clone(),description:rule.description.into(),path:Some(path.clone())});}}
        scan_obfuscation(&content,&path,&mut findings);
    }
    let score=calculate_score(&findings);let risk_level=risk_from_score(score);
    Ok(ScanReport{package:package.into(),version:version.into(),score,risk_level,files_scanned,findings})
}

fn metadata_findings(package:&str,signals:Option<&RegistrySignals>)->Vec<Finding>{
    let mut out=Vec::new();let bare=package.rsplit('/').next().unwrap_or(package).to_ascii_lowercase();
    for popular in POPULAR_PACKAGES{
        let d=levenshtein(&bare,popular);
        if d==1 && bare!=popular{
            out.push(Finding{rule:"possible-typosquatting".into(),severity:Severity::High,
                description:format!("Package name is one edit away from popular package '{popular}'."),path:None});break;
        }
    }
    if let Some(s)=signals{
        if s.deprecated{out.push(Finding{rule:"deprecated-package".into(),severity:Severity::Medium,description:"This package version is marked deprecated in the npm registry.".into(),path:None});}
        if s.maintainers==0{out.push(Finding{rule:"no-maintainers".into(),severity:Severity::Medium,description:"Registry metadata lists no maintainers.".into(),path:None});}
        if s.version_count<=1{out.push(Finding{rule:"very-low-version-history".into(),severity:Severity::Low,description:"Package has one or fewer published versions; review maturity and provenance.".into(),path:None});}
    }
    out
}

fn scan_obfuscation(content:&str,path:&str,findings:&mut Vec<Finding>){
    if content.len()<1000{return;}
    let lines=content.lines().count().max(1);let avg=content.len()/lines;
    let hex_escapes=content.matches("\\x").count()+content.matches("\\u00").count();
    if avg>5000 || hex_escapes>40{
        findings.push(Finding{rule:"obfuscation-density".into(),severity:Severity::Medium,
            description:format!("Dense/minified or escaped code detected (avg line {avg} chars, {hex_escapes} hex/unicode escapes)."),path:Some(path.into())});
    }
}

fn scan_package_json(content:&str,path:&str,findings:&mut Vec<Finding>){
    let Ok(json)=serde_json::from_str::<Value>(content) else{return};
    if let Some(scripts)=json.get("scripts").and_then(Value::as_object){
        for lifecycle in ["preinstall","install","postinstall","prepare"]{
            if let Some(command)=scripts.get(lifecycle).and_then(Value::as_str){findings.push(Finding{rule:format!("lifecycle-{lifecycle}"),severity:Severity::High,description:format!("Lifecycle script can execute during installation: {command}"),path:Some(path.into())});}
        }
    }
}

fn levenshtein(a:&str,b:&str)->usize{
    let mut costs:(Vec<usize>)=(0..=b.chars().count()).collect();
    for (i,ca) in a.chars().enumerate(){let mut last=i;costs[0]=i+1;for (j,cb) in b.chars().enumerate(){let old=costs[j+1];costs[j+1]=if ca==cb{last}else{1+last.min(old).min(costs[j])};last=old;}}
    costs[b.chars().count()]
}
fn calculate_score(findings:&[Finding])->u8{findings.iter().map(|f|match f.severity{Severity::Low=>3,Severity::Medium=>10,Severity::High=>25,Severity::Critical=>40}).sum::<u16>().min(100) as u8}
fn risk_from_score(score:u8)->RiskLevel{match score{0..=19=>RiskLevel::Low,20..=44=>RiskLevel::Medium,45..=74=>RiskLevel::High,_=>RiskLevel::Critical}}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]fn edit_distance(){assert_eq!(levenshtein("lodahs","lodash"),2);assert_eq!(levenshtein("lodas","lodash"),1);}
    #[test]fn typo_signal(){assert!(metadata_findings("expres",None).iter().any(|f|f.rule=="possible-typosquatting"));}
    #[test]fn obfuscation_signal(){let mut f=vec![];scan_obfuscation(&format!("{}{}", "\\x41".repeat(50),"a".repeat(1000)),"x.js",&mut f);assert!(!f.is_empty());}
}