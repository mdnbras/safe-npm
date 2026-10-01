use crate::scanner::{Finding, RiskLevel, ScanReport, Severity};
use anyhow::{Context, Result};
use std::fs;

pub fn write_scan_report(report: &ScanReport, path: &str) -> Result<()> {
    fs::write(path, render_scan_report(report))
        .with_context(|| format!("failed to write HTML report to {path}"))
}

pub fn render_scan_report(report: &ScanReport) -> String {
    let low = count_severity(&report.findings, Severity::Low);
    let medium = count_severity(&report.findings, Severity::Medium);
    let high = count_severity(&report.findings, Severity::High);
    let critical = count_severity(&report.findings, Severity::Critical);
    let ai_validated = report
        .findings
        .iter()
        .filter(|finding| finding.ai_validation.is_some())
        .count();

    let mut findings_html = String::new();
    if report.findings.is_empty() {
        findings_html.push_str(
            r#"<div class="empty-state"><h3>No findings</h3><p>The scanner did not produce findings for this package.</p></div>"#,
        );
    } else {
        for (index, finding) in report.findings.iter().enumerate() {
            findings_html.push_str(&render_finding(index + 1, finding));
        }
    }

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>safe-npm report - {package}@{version}</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #090c12;
      --panel: #111722;
      --panel-2: #151d2a;
      --border: #273247;
      --text: #edf2f7;
      --muted: #9ba8ba;
      --low: #44c77b;
      --medium: #eabf4d;
      --high: #f08a4b;
      --critical: #ed5d6b;
      --accent: #7f8cff;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: radial-gradient(circle at top, #172037 0, var(--bg) 38rem);
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.5;
    }}
    main {{ max-width: 1120px; margin: 0 auto; padding: 48px 24px 72px; }}
    header {{ margin-bottom: 28px; }}
    .brand {{ font-size: 14px; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; color: var(--accent); }}
    h1 {{ margin: 8px 0 6px; font-size: clamp(30px, 5vw, 48px); line-height: 1.05; }}
    .subtitle {{ margin: 0; color: var(--muted); }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 14px; margin: 28px 0; }}
    .metric, .finding, .summary {{
      border: 1px solid var(--border);
      background: rgba(17, 23, 34, .92);
      border-radius: 16px;
      box-shadow: 0 10px 30px rgba(0,0,0,.18);
    }}
    .metric {{ padding: 18px; }}
    .metric .label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .07em; }}
    .metric .value {{ display: block; margin-top: 5px; font-size: 26px; font-weight: 800; }}
    .summary {{ padding: 22px; margin-bottom: 24px; }}
    .summary-row {{ display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }}
    .pill {{ border: 1px solid var(--border); border-radius: 999px; padding: 5px 10px; font-size: 12px; font-weight: 800; }}
    .low {{ color: var(--low); }}
    .medium {{ color: var(--medium); }}
    .high {{ color: var(--high); }}
    .critical {{ color: var(--critical); }}
    .findings-title {{ margin: 34px 0 14px; font-size: 22px; }}
    .finding {{ padding: 20px; margin-bottom: 14px; }}
    .finding-head {{ display: flex; gap: 12px; align-items: flex-start; justify-content: space-between; flex-wrap: wrap; }}
    .rule {{ font-size: 18px; font-weight: 800; }}
    .description {{ margin: 8px 0 0; color: #d7dee9; }}
    .meta {{ margin-top: 14px; display: grid; gap: 10px; }}
    .meta-block {{ background: var(--panel-2); border: 1px solid var(--border); border-radius: 12px; padding: 13px; }}
    .meta-title {{ color: var(--muted); text-transform: uppercase; letter-spacing: .06em; font-size: 11px; font-weight: 800; margin-bottom: 6px; }}
    pre {{ margin: 0; white-space: pre-wrap; overflow-wrap: anywhere; font: 12px/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
    .ai-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 10px; }}
    .empty-state {{ padding: 36px; text-align: center; border: 1px dashed var(--border); border-radius: 16px; color: var(--muted); }}
    footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid var(--border); color: var(--muted); font-size: 12px; }}
  </style>
</head>
<body>
<main>
  <header>
    <div class="brand">safe-npm security report</div>
    <h1>{package}@{version}</h1>
    <p class="subtitle">Static npm package analysis generated before installation. A finding is a review signal, not proof of malware.</p>
  </header>

  <section class="grid">
    <div class="metric"><span class="label">Risk</span><span class="value {risk_class}">{risk}</span></div>
    <div class="metric"><span class="label">Score</span><span class="value">{score}/100</span></div>
    <div class="metric"><span class="label">Files scanned</span><span class="value">{files}</span></div>
    <div class="metric"><span class="label">Findings</span><span class="value">{findings}</span></div>
    <div class="metric"><span class="label">AI validations</span><span class="value">{ai_validated}</span></div>
  </section>

  <section class="summary">
    <div class="meta-title">Severity summary</div>
    <div class="summary-row">
      <span class="pill low">LOW {low}</span>
      <span class="pill medium">MEDIUM {medium}</span>
      <span class="pill high">HIGH {high}</span>
      <span class="pill critical">CRITICAL {critical}</span>
    </div>
  </section>

  <h2 class="findings-title">Detailed findings</h2>
  {findings_html}

  <footer>
    Generated by safe-npm. Review findings together with package provenance, lockfiles, npm audit and runtime controls.
  </footer>
</main>
</body>
</html>
"#,
        package = escape_html(&report.package),
        version = escape_html(&report.version),
        risk = report.risk_level,
        risk_class = risk_class(&report.risk_level),
        score = report.score,
        files = report.files_scanned,
        findings = report.findings.len(),
        ai_validated = ai_validated,
        low = low,
        medium = medium,
        high = high,
        critical = critical,
        findings_html = findings_html,
    )
}

fn render_finding(index: usize, finding: &Finding) -> String {
    let path = finding
        .path
        .as_deref()
        .map(escape_html)
        .unwrap_or_else(|| "Not available".to_string());
    let evidence = finding
        .evidence
        .as_deref()
        .map(|value| {
            format!(
                r#"<div class="meta-block"><div class="meta-title">Evidence</div><pre>{}</pre></div>"#,
                escape_html(value)
            )
        })
        .unwrap_or_else(|| {
            r#"<div class="meta-block"><div class="meta-title">Evidence</div><div>Not captured for this finding.</div></div>"#
                .to_string()
        });
    let ai = finding
        .ai_validation
        .as_ref()
        .map(|validation| {
            format!(
                r#"<div class="meta-block">
  <div class="meta-title">AI validation</div>
  <div class="ai-grid">
    <div><strong>Verdict</strong><br>{verdict}</div>
    <div><strong>Confidence</strong><br>{confidence:.2}</div>
  </div>
  <p>{reason}</p>
</div>"#,
                verdict = escape_html(&validation.verdict),
                confidence = validation.confidence,
                reason = escape_html(&validation.reason),
            )
        })
        .unwrap_or_default();

    format!(
        r#"<article class="finding">
  <div class="finding-head">
    <div>
      <div class="rule">#{index} {rule}</div>
      <p class="description">{description}</p>
    </div>
    <span class="pill {severity_class}">{severity}</span>
  </div>
  <div class="meta">
    <div class="meta-block"><div class="meta-title">Path</div><code>{path}</code></div>
    {evidence}
    {ai}
  </div>
</article>"#,
        index = index,
        rule = escape_html(&finding.rule),
        description = escape_html(&finding.description),
        severity = finding.severity,
        severity_class = severity_class(&finding.severity),
        path = path,
        evidence = evidence,
        ai = ai,
    )
}

fn count_severity(findings: &[Finding], severity: Severity) -> usize {
    findings
        .iter()
        .filter(|finding| finding.severity == severity)
        .count()
}

fn severity_class(severity: &Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn risk_class(risk: &RiskLevel) -> &'static str {
    match risk {
        RiskLevel::Low => "low",
        RiskLevel::Medium => "medium",
        RiskLevel::High => "high",
        RiskLevel::Critical => "critical",
    }
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace(''', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report_with_finding() -> ScanReport {
        ScanReport {
            package: "example<&".into(),
            version: "1.0.0".into(),
            score: 25,
            risk_level: RiskLevel::Medium,
            files_scanned: 12,
            findings: vec![Finding {
                rule: "network-access".into(),
                severity: Severity::Medium,
                description: "Network <request> detected.".into(),
                path: Some("package/index.js".into()),
                evidence: Some("fetch(\"https://example.test?a=1&b=2\")".into()),
                ai_validation: None,
            }],
        }
    }

    #[test]
    fn renders_complete_report() {
        let html = render_scan_report(&report_with_finding());
        assert!(html.contains("example&lt;&amp;@1.0.0"));
        assert!(html.contains("25/100"));
        assert!(html.contains("network-access"));
        assert!(html.contains("fetch(&quot;https://example.test?a=1&amp;b=2&quot;)"));
    }

    #[test]
    fn escapes_html_sensitive_characters() {
        assert_eq!(
            escape_html("<script data-x=\"a&b\">'x'</script>"),
            "&lt;script data-x=&quot;a&amp;b&quot;&gt;&#39;x&#39;&lt;/script&gt;"
        );
    }
}
