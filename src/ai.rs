use crate::scanner::{Finding, Severity};
use anyhow::{bail, Context, Result};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiValidation {
    pub verdict: String,
    pub confidence: f32,
    pub reason: String,
}

pub fn validate_findings(findings: &mut [Finding], model: &str) -> Result<()> {
    let key = env::var("OPENAI_API_KEY").context("OPENAI_API_KEY is required when --ai is enabled")?;
    let client = Client::new();
    for finding in findings.iter_mut().filter(|f| matches!(f.severity, Severity::Medium | Severity::High | Severity::Critical)) {
        let Some(evidence) = finding.evidence.as_deref() else {
            finding.ai_validation = Some(AiValidation {
                verdict: "not_analyzed".into(),
                confidence: 0.0,
                reason: "No contextual evidence was captured for this finding.".into(),
            });
            continue;
        };
        let input = format!(
            "Review this static npm security finding. Classify only the supplied evidence. Rule: {}. Path: {}. Evidence:\n{}",
            finding.rule,
            finding.path.as_deref().unwrap_or("unknown"),
            evidence
        );
        let body = json!({
            "model": model,
            "instructions": "You are validating a static-analysis finding in an npm package. Decide whether the evidence supports a real security-relevant behavior or is likely a false positive. Do not assume malware. Return compact JSON only: {\"verdict\":\"confirmed|false_positive|uncertain\",\"confidence\":0.0,\"reason\":\"...\"}.",
            "input": input,
            "max_output_tokens": 180
        });
        let response: Value = client.post("https://api.openai.com/v1/responses")
            .bearer_auth(&key).json(&body).send().context("OpenAI request failed")?
            .error_for_status().context("OpenAI API returned an error")?.json()?;
        let text = response.get("output").and_then(Value::as_array)
            .and_then(|o| o.iter().find_map(|item| item.get("content")?.as_array()?.iter()
                .find_map(|c| c.get("text")?.as_str()))).context("OpenAI response did not contain text")?;
        let clean=text.trim().trim_start_matches("```json").trim_start_matches("```").trim_end_matches("```").trim();
        let validation:AiValidation=serde_json::from_str(clean).context("invalid AI validation JSON")?;
        finding.ai_validation=Some(validation);
    }
    Ok(())
}

pub fn apply_ai_verdicts(findings:&mut Vec<Finding>) {
    findings.retain(|f| !matches!(f.ai_validation.as_ref().map(|v|v.verdict.as_str()),Some("false_positive")) ||
        f.ai_validation.as_ref().is_some_and(|v|v.confidence < 0.80));
}

pub fn require_supported_model(model:&str)->Result<()> {
    if model.trim().is_empty(){bail!("AI model cannot be empty");}
    Ok(())
}
