mod behavior;
mod policy;
mod registry;
mod sarif;
mod scanner;
mod tree;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use std::process::Command;
use scanner::{RiskLevel, ScanReport};
use tree::{TreeOptions, TreeReport};

#[derive(Parser)]
#[command(name="safe-npm", version, about="Scan npm packages before installing them")]
struct Cli { #[command(subcommand)] command: Commands }

#[derive(Subcommand)]
enum Commands {
    /// Scan one package tarball only.
    Scan { package: String, #[arg(long)] json: bool, #[arg(long)] policy: Option<String> },
    /// Scan the package and its transitive production dependencies.
    Tree {
        package: String,
        #[arg(long, default_value_t=8)] max_depth: usize,
        #[arg(long, default_value_t=500)] max_packages: usize,
        #[arg(long)] json: bool,
        #[arg(long)] sarif: bool,
        #[arg(long)] policy: Option<String>,
    },
    /// Scan the dependency tree, then install only when policy allows it.
    Install {
        package: String,
        #[arg(long)] allow_risk: bool,
        #[arg(long)] allow_scripts: bool,
        #[arg(long, default_value_t=8)] max_depth: usize,
        #[arg(long, default_value_t=500)] max_packages: usize,
        #[arg(long)] policy: Option<String>,
    },
}

fn scan_package(spec: &str) -> Result<ScanReport> {
    let registry = registry::RegistryClient::new()?;
    let artifact = registry.resolve(spec)?;
    let bytes = registry.download(&artifact)?;
    scanner::scan_tarball_with_signals(&artifact.name, &artifact.version, &bytes, Some(&artifact.signals))
}

fn scan_tree(spec: &str, max_depth: usize, max_packages: usize) -> Result<TreeReport> {
    tree::scan_dependency_tree(spec, TreeOptions { max_depth, max_packages })
}

fn print_report(report: &ScanReport) {
    println!("{} {}@{}  {} {}/100 ({})", "Package:".bold(), report.package, report.version,
        "Risk:".bold(), report.score, color_level(&report.risk_level));
    for finding in &report.findings {
        println!("{} [{}] {}{}", "!".red().bold(), finding.severity, finding.rule,
            finding.path.as_ref().map(|p| format!(" — {p}")).unwrap_or_default());
    }
}

fn print_tree(report: &TreeReport) {
    println!("{} {}@{}", "Root:".bold(), report.root.package, report.root.version);
    println!("{} {}  {} {}  {} {}", "Packages:".bold(), report.packages_scanned,
        "Files:".bold(), report.files_scanned, "Risk:".bold(), color_level(&report.risk_level));
    for node in &report.packages {
        println!("{} {}@{} depth={} score={}/100 ({})", "•".bold(), node.report.package,
            node.report.version, node.depth, node.report.score, node.report.risk_level);
    }
    if !report.errors.is_empty() {
        println!("{} {}", "Resolution warnings:".yellow(), report.errors.len());
    }
}

fn color_level(level: &RiskLevel) -> colored::ColoredString {
    match level {
        RiskLevel::Low => level.to_string().green(),
        RiskLevel::Medium => level.to_string().yellow(),
        RiskLevel::High | RiskLevel::Critical => level.to_string().red().bold(),
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan { package, json, policy } => {
            let report=scan_package(&package)?;
            let policy=policy::Policy::load(policy.as_deref())?;
            if json { println!("{}", serde_json::to_string_pretty(&report)?); } else { print_report(&report); }
            if policy.blocks(&report) { bail!("scan blocked by policy"); }
        }
        Commands::Tree { package, max_depth, max_packages, json, sarif, policy } => {
            let policy=policy::Policy::load(policy.as_deref())?;
            let report=scan_tree(&package,max_depth.min(policy.max_depth),max_packages.min(policy.max_packages))?;
            if sarif { println!("{}",serde_json::to_string_pretty(&sarif::from_tree(&report))?); }
            else if json { println!("{}",serde_json::to_string_pretty(&report)?); } else { print_tree(&report); }
        }
        Commands::Install { package, allow_risk, allow_scripts, max_depth, max_packages, policy } => {
            let policy=policy::Policy::load(policy.as_deref())?;
            let report=scan_tree(&package,max_depth.min(policy.max_depth),max_packages.min(policy.max_packages))?;
            print_tree(&report);
            if report.packages.iter().any(|n|policy.blocks(&n.report)) && !allow_risk {
                bail!("installation blocked: dependency-tree risk is {}. Review findings or pass --allow-risk.",report.risk_level);
            }
            let mut cmd=Command::new("npm");
            cmd.arg("install").arg(&package);
            if !allow_scripts { cmd.arg("--ignore-scripts"); }
            let status=cmd.status().context("failed to start npm")?;
            if !status.success(){ bail!("npm install failed with status {status}"); }
        }
    }
    Ok(())
}
