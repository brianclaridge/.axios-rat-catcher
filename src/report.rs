use crate::scanner::npm::{NpmSource, ScanTargets};
use colored::Colorize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Global scan statistics.
pub static DIRS_SCANNED: AtomicUsize = AtomicUsize::new(0);
pub static PACKAGE_JSONS_SCANNED: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Severity::Info => "INFO    ",
            Severity::Warning => "WARNING ",
            Severity::Critical => "CRITICAL",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub category: String,
    pub path: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

impl Finding {
    pub fn critical(category: &str, path: &str, detail: &str) -> Self {
        Self {
            severity: Severity::Critical,
            category: category.to_string(),
            path: path.to_string(),
            detail: detail.to_string(),
            hash: None,
        }
    }

    pub fn warning(category: &str, path: &str, detail: &str) -> Self {
        Self {
            severity: Severity::Warning,
            category: category.to_string(),
            path: path.to_string(),
            detail: detail.to_string(),
            hash: None,
        }
    }

    pub fn with_hash(mut self, hash: &str) -> Self {
        self.hash = Some(hash.to_string());
        self
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let severity_str = match self.severity {
            Severity::Critical => format!("[{}]", self.severity).red().bold().to_string(),
            Severity::Warning => format!("[{}]", self.severity).yellow().bold().to_string(),
            Severity::Info => format!("[{}]", self.severity).cyan().to_string(),
        };
        write!(f, "{} {}: {}", severity_str, self.category, self.detail)?;
        write!(f, "\n    -> {}", self.path)?;
        if let Some(h) = &self.hash {
            write!(f, "\n    SHA-256: {}", h)?;
        }
        Ok(())
    }
}

/// Print a rich tree view of all discovered npm projects, grouped by drive/root.
pub fn print_tree(targets: &ScanTargets, findings: &[Finding]) {
    // Build a set of paths that have findings for highlighting
    let finding_paths: std::collections::HashSet<&str> =
        findings.iter().map(|f| f.path.as_str()).collect();

    // Group projects by drive root (first path component)
    let mut by_drive: BTreeMap<String, Vec<&NpmSource>> = BTreeMap::new();
    for src in &targets.npm_sources {
        let drive = drive_root(&src.path);
        by_drive.entry(drive).or_default().push(src);
    }

    println!(
        "\n{}\n",
        "npm/node project tree".bold().underline()
    );

    for (drive, projects) in &by_drive {
        println!("{}", format!("{drive}").bold().cyan());
        let count = projects.len();
        for (i, src) in projects.iter().enumerate() {
            let is_last = i == count - 1;
            let connector = if is_last { "  \u{2514}\u{2500}" } else { "  \u{251C}\u{2500}" };
            let pipe = if is_last { "   " } else { "  \u{2502}" };

            // Project name + path
            let name_display = src.name.as_deref().unwrap_or("(unnamed)");
            let rel_path = src
                .path
                .strip_prefix(drive)
                .unwrap_or(&src.path)
                .display()
                .to_string();

            // Check if this project has any findings
            let path_str = src.path.display().to_string();
            let has_finding = finding_paths.iter().any(|fp| fp.starts_with(&path_str));

            let name_str = if has_finding {
                format!("{name_display}").red().bold().to_string()
            } else {
                format!("{name_display}").green().to_string()
            };

            println!("{connector} {name_str} {}", rel_path.dimmed());

            // Details line
            let mut details = Vec::new();
            if let Some(lt) = &src.lockfile_type {
                details.push(format!("lock:{lt}"));
            } else {
                details.push("no lockfile".dimmed().to_string());
            }
            if src.has_node_modules {
                details.push("node_modules".to_string());
            }
            if has_finding {
                details.push("INFECTED".red().bold().to_string());
            }
            println!("{pipe}  {}", details.join(" \u{2502} "));
        }
        println!();
    }
}

fn drive_root(path: &Path) -> String {
    let s = path.display().to_string();
    // Windows: "C:\" or "D:\"
    if s.len() >= 3 && s.as_bytes()[1] == b':' {
        s[..3].to_string()
    // Unix: first path component like "/Volumes/X" or "/"
    } else {
        let components: Vec<_> = path.components().take(2).collect();
        let p: PathBuf = components.into_iter().collect();
        p.display().to_string()
    }
}

pub fn print_summary(findings: &[Finding], elapsed: std::time::Duration) {
    let crits = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let warns = findings.iter().filter(|f| f.severity == Severity::Warning).count();
    let infos = findings.iter().filter(|f| f.severity == Severity::Info).count();

    // Print findings sorted by severity (critical first)
    let mut sorted: Vec<&Finding> = findings.iter().collect();
    sorted.sort_by(|a, b| b.severity.cmp(&a.severity));
    for f in &sorted {
        println!("{f}\n");
    }

    println!("{}", "=".repeat(60));
    println!(
        "Scan complete in {:.1}s -- {} critical, {} warning, {} info",
        elapsed.as_secs_f64(),
        crits,
        warns,
        infos,
    );
    println!(
        "Scanned: {} package.json files, {} directories",
        PACKAGE_JSONS_SCANNED.load(Ordering::Relaxed),
        DIRS_SCANNED.load(Ordering::Relaxed),
    );

    if crits > 0 {
        println!(
            "\n{}",
            "!! CRITICAL: Evidence of axios RAT compromise detected.".red().bold()
        );
        println!("   1. Isolate this machine from the network immediately");
        println!("   2. Preserve forensic artifacts before remediation");
        println!("   3. Rotate ALL credentials accessed from this machine");
        println!("   4. See: https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all");
    } else {
        println!("\n{}", "No evidence of compromise found.".green().bold());
    }
}

/// Write a plain-text REPORT.txt with all findings and affected paths.
pub fn write_report(findings: &[Finding], elapsed: std::time::Duration, report_path: &std::path::Path) {
    use std::io::Write;

    let mut f = match std::fs::File::create(report_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to write report: {e}");
            return;
        }
    };

    let crits = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let warns = findings.iter().filter(|f| f.severity == Severity::Warning).count();
    let infos = findings.iter().filter(|f| f.severity == Severity::Info).count();

    writeln!(f, "AXIOS RAT SCAN REPORT").ok();
    writeln!(f, "=====================").ok();
    writeln!(f, "Scan complete in {:.1}s", elapsed.as_secs_f64()).ok();
    writeln!(f, "Scanned: {} package.json files, {} directories",
        PACKAGE_JSONS_SCANNED.load(Ordering::Relaxed),
        DIRS_SCANNED.load(Ordering::Relaxed),
    ).ok();
    writeln!(f, "Findings: {} critical, {} warning, {} info", crits, warns, infos).ok();
    writeln!(f).ok();

    if crits > 0 {
        writeln!(f, "!! CRITICAL: Evidence of axios RAT compromise detected.").ok();
        writeln!(f, "   See: https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all").ok();
        writeln!(f).ok();
    }

    // Group findings by severity
    let mut sorted: Vec<&Finding> = findings.iter().collect();
    sorted.sort_by(|a, b| b.severity.cmp(&a.severity));

    writeln!(f, "FINDINGS").ok();
    writeln!(f, "--------").ok();
    for finding in &sorted {
        writeln!(f, "[{}] {}: {}", finding.severity, finding.category, finding.detail).ok();
        writeln!(f, "    path: {}", finding.path).ok();
        if let Some(h) = &finding.hash {
            writeln!(f, "    sha256: {h}").ok();
        }
        writeln!(f).ok();
    }

    // Deduplicated list of affected paths for easy copy/paste
    let mut affected: Vec<&str> = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .map(|f| f.path.as_str())
        .collect();
    affected.sort();
    affected.dedup();

    if !affected.is_empty() {
        writeln!(f, "AFFECTED PATHS (copy/paste ready)").ok();
        writeln!(f, "---------------------------------").ok();
        for path in &affected {
            writeln!(f, "{path}").ok();
        }
        writeln!(f).ok();
    }

    writeln!(f, "REMEDIATION").ok();
    writeln!(f, "-----------").ok();
    writeln!(f, "1. Isolate this machine from the network immediately").ok();
    writeln!(f, "2. Preserve forensic artifacts before remediation").ok();
    writeln!(f, "3. Rotate ALL credentials accessed from this machine").ok();
    writeln!(f, "4. Downgrade axios to 1.14.0 or 0.30.3").ok();
    writeln!(f, "5. Remove plain-crypto-js from node_modules").ok();
    writeln!(f, "6. Block egress to sfrclak.com / 142.11.206.73").ok();
}
