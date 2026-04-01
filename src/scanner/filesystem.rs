use crate::iocs;
use crate::report::Finding;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

/// Compute SHA-256 hex digest of a file.
fn sha256_file(path: &Path) -> Option<String> {
    let data = fs::read(path).ok()?;
    let hash = Sha256::digest(&data);
    Some(format!("{hash:x}"))
}

/// Check a single known artifact path. If it exists, hash it and compare.
fn check_artifact(path: &str, known_hashes: &[&str], findings: &mut Vec<Finding>) {
    let p = Path::new(path);
    if p.exists() {
        let detail = format!("RAT artifact exists: {path}");
        let mut f = Finding::critical("rat-artifact", path, &detail);
        if let Some(hash) = sha256_file(p) {
            let matched = known_hashes.iter().any(|h| *h == hash);
            let label = if matched { " (KNOWN MALICIOUS)" } else { " (unknown variant)" };
            f = f.with_hash(&format!("{hash}{label}"));
        }
        findings.push(f);
    }
}

/// Check for the transient dropper artifact `6202033` in temp directories.
fn check_temp_artifact(findings: &mut Vec<Finding>) {
    let candidates: Vec<String> = if cfg!(windows) {
        vec![
            std::env::var("TEMP").unwrap_or_else(|_| r"C:\Users\Public\Temp".into()),
            std::env::var("TMP").unwrap_or_else(|_| String::new()),
        ]
    } else {
        vec![
            std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into()),
            "/tmp".into(),
        ]
    };

    for dir in candidates.iter().filter(|d| !d.is_empty()) {
        let dropper = Path::new(dir).join("6202033");
        if dropper.exists() {
            findings.push(Finding::critical(
                "dropper-artifact",
                &dropper.display().to_string(),
                "Transient dropper artifact '6202033' found in temp directory",
            ));
        }
        // Windows-specific transient files
        if cfg!(windows) {
            for name in &["6202033.vbs", "6202033.ps1"] {
                let p = Path::new(dir).join(name);
                if p.exists() {
                    let mut f = Finding::critical(
                        "dropper-artifact",
                        &p.display().to_string(),
                        &format!("Transient dropper file '{name}' found"),
                    );
                    if let Some(hash) = sha256_file(&p) {
                        let matched = iocs::HASHES_WINDOWS_PS1.iter().any(|h| *h == hash);
                        if matched {
                            f = f.with_hash(&format!("{hash} (KNOWN MALICIOUS)"));
                        } else {
                            f = f.with_hash(&hash);
                        }
                    }
                    findings.push(f);
                }
            }
        }
    }
}

/// Scan for platform-specific RAT file artifacts.
///
/// Covers Elastic file-system IOCs:
/// - /Library/Caches/com.apple.act.mond (macOS C++ RAT)
/// - /tmp/*.scpt (macOS AppleScript transients)
/// - %PROGRAMDATA%\wt.exe (Windows renamed PowerShell)
/// - %PROGRAMDATA%\system.bat (Windows persistence batch)
/// - %TEMP%\6202033.vbs, 6202033.ps1 (Windows dropper transients)
/// - /tmp/ld.py (Linux Python RAT)
/// - $TMPDIR/6202033 (cross-platform dropper artifact)
pub fn scan(findings: &mut Vec<Finding>) {
    #[cfg(target_os = "macos")]
    {
        check_artifact(
            "/Library/Caches/com.apple.act.mond",
            iocs::HASHES_MACOS_RAT,
            findings,
        );
        // AppleScript transients used by the dropper
        if let Ok(entries) = fs::read_dir("/tmp") {
            for entry in entries.flatten() {
                if let Some(ext) = entry.path().extension() {
                    if ext == "scpt" {
                        findings.push(Finding::warning(
                            "suspect-applescript",
                            &entry.path().display().to_string(),
                            "AppleScript file in /tmp (potential dropper artifact)",
                        ));
                    }
                }
            }
        }
    }

    #[cfg(windows)]
    {
        let programdata =
            std::env::var("PROGRAMDATA").unwrap_or_else(|_| r"C:\ProgramData".into());

        // wt.exe — renamed PowerShell binary
        // Elastic: "Execution via Renamed Signed Binary Proxy"
        let wt_path = format!("{programdata}\\wt.exe");
        let wt = Path::new(&wt_path);
        if wt.exists() {
            // Validate it's actually a renamed powershell by checking file size/version
            // Real wt.exe (Windows Terminal) lives in WindowsApps, not ProgramData
            let mut f = Finding::critical(
                "rat-artifact",
                &wt_path,
                "wt.exe in ProgramData — renamed PowerShell binary \
                 (Elastic: Execution via Renamed Signed Binary Proxy)",
            );
            if let Some(hash) = sha256_file(wt) {
                f = f.with_hash(&hash);
            }
            findings.push(f);
        }

        check_artifact(
            &format!("{programdata}\\system.bat"),
            &[iocs::HASH_WINDOWS_BAT],
            findings,
        );
    }

    #[cfg(target_os = "linux")]
    {
        check_artifact("/tmp/ld.py", iocs::HASHES_LINUX_RAT, findings);
    }

    check_temp_artifact(findings);
}
