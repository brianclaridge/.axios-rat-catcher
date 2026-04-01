mod iocs;
mod report;
mod scanner;

use clap::Parser;
use colored::Colorize;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use report::Finding;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(
    name = "axios-rat-scan",
    about = "Scan for the axios supply chain RAT (2026-03-31)",
    version
)]
struct Cli {
    /// Directories to scan (default: all mounted drives)
    paths: Vec<PathBuf>,

    /// Output findings as JSON
    #[arg(long)]
    json: bool,

    /// Stop after the first CRITICAL finding
    #[arg(long)]
    fast: bool,

    /// Skip process and network checks (filesystem only)
    #[arg(long)]
    no_process: bool,

    /// Hide the project tree view
    #[arg(long)]
    no_tree: bool,

    /// Path to write npm_sources_map.yml (default: ./npm_sources_map.yml)
    #[arg(long, default_value = "npm_sources_map.yml")]
    sources_map: PathBuf,
}

fn enumerate_drives() -> Vec<PathBuf> {
    let mut drives = Vec::new();

    #[cfg(windows)]
    for letter in b'A'..=b'Z' {
        let path = format!("{}:\\", letter as char);
        let p = PathBuf::from(&path);
        if p.exists() {
            drives.push(p);
        }
    }

    #[cfg(target_os = "macos")]
    {
        drives.push(PathBuf::from("/"));
        if let Ok(entries) = std::fs::read_dir("/Volumes") {
            for entry in entries.flatten() {
                drives.push(entry.path());
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
            let skip_fs = [
                "proc", "sysfs", "devtmpfs", "tmpfs", "devpts", "cgroup",
                "cgroup2", "pstore", "securityfs", "debugfs", "hugetlbfs",
                "mqueue", "fusectl", "configfs", "binfmt_misc", "autofs",
                "efivarfs", "tracefs", "bpf", "overlay",
            ];
            for line in mounts.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 && !skip_fs.contains(&parts[2]) {
                    drives.push(PathBuf::from(parts[1]));
                }
            }
        }
        if drives.is_empty() {
            drives.push(PathBuf::from("/"));
        }
    }

    drives
}

fn spinner_style() -> ProgressStyle {
    ProgressStyle::with_template(
        "  {spinner:.cyan} {prefix:.bold} {wide_msg}"
    )
    .unwrap()
    .tick_strings(&[
        "\u{2591}\u{2591}\u{2591}",
        "\u{2593}\u{2591}\u{2591}",
        "\u{2588}\u{2593}\u{2591}",
        "\u{2591}\u{2588}\u{2593}",
        "\u{2591}\u{2591}\u{2588}",
        "\u{2591}\u{2591}\u{2593}",
        "\u{2588}\u{2588}\u{2588}",
    ])
}

fn bar_style() -> ProgressStyle {
    ProgressStyle::with_template(
        "  {spinner:.cyan} {prefix:.bold} [{bar:30.green/dim}] {pos}/{len} {wide_msg}"
    )
    .unwrap()
    .progress_chars("\u{2588}\u{2593}\u{2591}")
}

fn main() {
    let cli = Cli::parse();
    let start = Instant::now();
    let quiet = cli.json;

    let roots = if cli.paths.is_empty() {
        let drives = enumerate_drives();
        if !quiet {
            let drive_list = drives
                .iter()
                .map(|d| d.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            println!(
                "\n{} {}\n",
                "\u{26A1} axios-rat-scan".bold().cyan(),
                "v0.1.0".dimmed()
            );
            println!(
                "  {} {}",
                "Drives:".bold(),
                drive_list.yellow()
            );
        }
        drives
    } else {
        if !quiet {
            println!(
                "\n{} {}\n",
                "\u{26A1} axios-rat-scan".bold().cyan(),
                "v0.1.0".dimmed()
            );
        }
        cli.paths.clone()
    };

    let mp = MultiProgress::new();
    let mut findings: Vec<Finding> = Vec::new();

    // ── Phase 0: Host-level checks ──────────────────────────────
    if !quiet {
        println!("  {} {}", "\u{2500}\u{2500}".dimmed(), "Host checks".bold());
    }

    let pb_host = if !quiet {
        let pb = mp.add(ProgressBar::new_spinner());
        pb.set_style(spinner_style());
        pb.set_prefix("artifacts");
        pb.set_message("checking RAT files...");
        pb.enable_steady_tick(Duration::from_millis(80));
        Some(pb)
    } else {
        None
    };

    scanner::filesystem::scan(&mut findings);
    if let Some(pb) = &pb_host {
        pb.set_message("done".green().to_string());
        pb.finish();
    }

    #[cfg(windows)]
    {
        let pb_reg = if !quiet {
            let pb = mp.add(ProgressBar::new_spinner());
            pb.set_style(spinner_style());
            pb.set_prefix("registry");
            pb.set_message("checking persistence keys...");
            pb.enable_steady_tick(Duration::from_millis(80));
            Some(pb)
        } else {
            None
        };
        scanner::registry::scan(&mut findings);
        if let Some(pb) = &pb_reg {
            pb.set_message("done".green().to_string());
            pb.finish();
        }
    }

    if !cli.no_process {
        let pb_proc = if !quiet {
            let pb = mp.add(ProgressBar::new_spinner());
            pb.set_style(spinner_style());
            pb.set_prefix("processes");
            pb.set_message("inspecting running processes...");
            pb.enable_steady_tick(Duration::from_millis(80));
            Some(pb)
        } else {
            None
        };
        scanner::process::scan(&mut findings);
        if let Some(pb) = &pb_proc {
            pb.set_message("done".green().to_string());
            pb.finish();
        }

        let pb_net = if !quiet {
            let pb = mp.add(ProgressBar::new_spinner());
            pb.set_style(spinner_style());
            pb.set_prefix("network");
            pb.set_message("checking C2 connections...");
            pb.enable_steady_tick(Duration::from_millis(80));
            Some(pb)
        } else {
            None
        };
        scanner::network::scan(&mut findings);
        if let Some(pb) = &pb_net {
            pb.set_message("done".green().to_string());
            pb.finish();
        }
    }

    // Early exit
    if cli.fast && findings.iter().any(|f| f.severity == report::Severity::Critical) {
        let elapsed = start.elapsed();
        if cli.json {
            println!("{}", serde_json::to_string_pretty(&findings).unwrap());
        } else {
            report::print_summary(&findings, elapsed);
        }
        std::process::exit(1);
    }

    // ── Phase 1: Discovery ──────────────────────────────────────
    if !quiet {
        println!("\n  {} {}", "\u{2500}\u{2500}".dimmed(), "Discovery".bold());
    }

    let pb_discover = if !quiet {
        let pb = mp.add(ProgressBar::new_spinner());
        pb.set_style(spinner_style());
        pb.set_prefix("walking");
        pb.set_message("scanning filesystem...");
        pb.enable_steady_tick(Duration::from_millis(80));
        Some(pb)
    } else {
        None
    };

    // Run discovery in a thread so we can update progress
    let roots_clone = roots.clone();
    let discover_handle = std::thread::spawn(move || {
        scanner::npm::discover(&roots_clone)
    });

    // Poll progress while discovery runs
    if let Some(pb) = &pb_discover {
        loop {
            let dirs = report::DIRS_SCANNED.load(Ordering::Relaxed);
            let pkgs = report::PACKAGE_JSONS_SCANNED.load(Ordering::Relaxed);
            pb.set_message(format!(
                "{} dirs | {} package.json",
                dirs.to_string().cyan(),
                pkgs.to_string().green(),
            ));
            if discover_handle.is_finished() {
                break;
            }
            std::thread::sleep(Duration::from_millis(60));
        }
    }

    let targets = discover_handle.join().expect("discovery thread panicked");

    if let Some(pb) = &pb_discover {
        let dirs = report::DIRS_SCANNED.load(Ordering::Relaxed);
        pb.set_message(format!(
            "{} dirs | {} projects found",
            dirs.to_string().cyan(),
            targets.npm_sources.len().to_string().green().bold(),
        ));
        pb.finish();
    }

    scanner::npm::write_sources_map(&targets, &cli.sources_map);

    // ── Tree view ───────────────────────────────────────────────
    if !cli.no_tree && !quiet {
        report::print_tree(&targets, &[]);
    }

    // ── Phase 2: IOC scan ───────────────────────────────────────
    if !quiet {
        println!("  {} {}", "\u{2500}\u{2500}".dimmed(), "IOC scan".bold());
    }

    let total_targets = targets.package_jsons.len()
        + targets.lockfiles.len()
        + targets.yarn_locks.len()
        + targets.node_modules_dirs.len();

    let pb_scan = if !quiet {
        let pb = mp.add(ProgressBar::new(total_targets as u64));
        pb.set_style(bar_style());
        pb.set_prefix("scanning");
        pb.enable_steady_tick(Duration::from_millis(80));
        Some(pb)
    } else {
        None
    };

    let npm_findings = scanner::npm::scan_targets_with_progress(&targets, &pb_scan);
    findings.extend(npm_findings);

    if let Some(pb) = &pb_scan {
        pb.set_message("complete".green().to_string());
        pb.finish();
    }

    // ── Results ─────────────────────────────────────────────────
    let elapsed = start.elapsed();

    if quiet {
        println!("{}", serde_json::to_string_pretty(&findings).unwrap());
        let has_critical = findings.iter().any(|f| f.severity == report::Severity::Critical);
        std::process::exit(if has_critical { 1 } else { 0 });
    }

    println!();
    report::print_summary(&findings, elapsed);
    let has_critical = findings.iter().any(|f| f.severity == report::Severity::Critical);
    std::process::exit(if has_critical { 1 } else { 0 });
}
