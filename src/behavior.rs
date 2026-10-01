use crate::scanner::{Finding, Severity};
use std::collections::{HashMap, HashSet};

pub fn correlate(findings:&mut Vec<Finding>){
    let mut by_path:HashMap<String,HashSet<String>>=HashMap::new();
    for f in findings.iter(){
        if let Some(path)=&f.path{by_path.entry(path.clone()).or_default().insert(f.rule.clone());}
    }
    for (path,rules) in by_path{
        let credential=rules.contains("credential-access")||rules.contains("environment-enumeration");
        let network=rules.contains("network-access");
        let execution=rules.contains("process-execution")||rules.contains("shell-command")||rules.contains("dynamic-code");
        if credential&&network{
            findings.push(Finding{rule:"behavior-secret-exfiltration".into(),severity:Severity::Critical,
                description:"Correlated behavior: credential/environment access and network capability occur in the same file.".into(),path:Some(path.clone()),evidence:None,ai_validation:None});
        }
        if network&&execution{
            findings.push(Finding{rule:"behavior-download-execute".into(),severity:Severity::Critical,
                description:"Correlated behavior: network capability and command/dynamic execution occur in the same file.".into(),path:Some(path),evidence:None,ai_validation:None});
        }
    }
}
