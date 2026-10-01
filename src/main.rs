mod registry;
mod scanner;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use std::process::Command;

use scanner::{RiskLevel, ScanReport};

#[derive(Parser)]
#[command(name = "safe-npm", version, about = "Scan npm packages before installing them")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Download the npm tarball without executing it and scan its contents.
    Scan {
        /// Package spec, e.g. lodash, express@5.1.0, @scope/pkg@1.2.3
        package: String,
        /// Print the report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Scan first and run npm install only when policy allows it.
    Install {
        package: String,
        /// Install even when HIGH/CRITICAL findings are detected.
        #[arg(long)]
        allow_risk: bool,
        /// Allow npm lifecycle scripts after the scan. Disabled by default.
        #[arg(long)]
        allow_scripts: bool,
    },
}

fn scan_package(spec: &str) -> Result<ScanReport> {
    let resolved = registry::fetch_package(spec)?;
    scanner::scan_tarball(&resolved.name, &resolved.version, &resolved.tarball)
}

fn print_report(report: &ScanReport) {
    let level = match report.risk_level {
        RiskLevel::Low => report.risk_level.to_string().green(),
        RiskLevel::Medium => report.risk_level.to_string().yellow(),
        RiskLevel::High | RiskLevel::Critical => report.risk_level.to_string().red().bold(),
    };

    println!("{} {}@{}", "Package:".bold(), report.package, report.version);
    println!("{} {}/100 ({})", "Risk:".bold(), report.score, level);
    println!("{} {}", "Files scanned:".bold(), report.files_scanned);

    if report.findings.is_empty() {
        println!("{}", "No suspicious indicators found by the current ruleset.".green());
        return;
    }

    println!();
    for finding in &report.findings {
        println!(
            "{} [{}] {}{}",
            "!".red().bold(),
            finding.severity,
            finding.rule,
            finding.path.as_ref().map(|p| format!(" — {p}")).unwrap_or_default()
        );
        println!("  {}", finding.description);
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { package, json } => {
            let report = scan_package(&package)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_report(&report);
            }
        }
        Commands::Install { package, allow_risk, allow_scripts } => {
            let report = scan_package(&package)?;
            print_report(&report);

            if matches!(report.risk_level, RiskLevel::High | RiskLevel::Critical) && !allow_risk {
                bail!(
                    "installation blocked: risk is {}. Review findings or pass --allow-risk.",
                    report.risk_level
                );
            }

            let mut cmd = Command::new("npm");
            cmd.arg("install").arg(&package);
            if !allow_scripts {
                cmd.arg("--ignore-scripts");
                println!(
                    "\n{}",
                    "Lifecycle scripts will remain disabled. Pass --allow-scripts to enable them."
                        .yellow()
                );
            }

            let status = cmd.status().context("failed to start npm")?;
            if !status.success() {
                bail!("npm install failed with status {status}");
            }
        }
    }

    Ok(())
}
