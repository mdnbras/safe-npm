use crate::tree::TreeReport;
use serde_json::{json, Value};

pub fn from_tree(report:&TreeReport)->Value{
    let results:Vec<Value>=report.packages.iter().flat_map(|node|{
        node.report.findings.iter().map(move |f|{
            let level=match f.severity{crate::scanner::Severity::Low=>"note",crate::scanner::Severity::Medium=>"warning",_=>"error"};
            let uri=f.path.clone().unwrap_or_else(||format!("npm://{}@{}",node.report.package,node.report.version));
            json!({"ruleId":f.rule,"level":level,"message":{"text":format!("{}: {}",node.report.package,f.description)},
                "locations":[{"physicalLocation":{"artifactLocation":{"uri":uri}}}]})
        })
    }).collect();
    json!({"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{
        "tool":{"driver":{"name":"safe-npm","version":env!("CARGO_PKG_VERSION"),"informationUri":"https://github.com/mdnbras/safe-npm"}},
        "results":results
    }]})
}
