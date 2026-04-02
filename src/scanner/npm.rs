use crate::iocs;
use crate::report::{Finding, DIRS_SCANNED, PACKAGE_JSONS_SCANNED};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use walkdir::WalkDir;

/// Get the user's home directory without adding a dependency.
fn home_dir() -> Option<std::path::PathBuf> {
    #[cfg(windows)]
    {
        std::env::var("USERPROFILE").ok().map(std::path::PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        std::env::var("HOME").ok().map(std::path::PathBuf::from)
    }
}

/// Parse a semver string into (major, minor, patch).
fn parse_version(v: &str) -> Option<(&str, &str, &str)> {
    let clean = v.trim().trim_start_matches(|c: char| !c.is_ascii_digit());
    let mut parts = clean.splitn(3, '.');
    Some((parts.next()?, parts.next()?, parts.next()?))
}

fn is_compromised_version(version: &str) -> bool {
    if let Some((ma, mi, pa)) = parse_version(version) {
        // Patch might have trailing metadata like "-beta"
        let pa_clean = pa.split_once(|c: char| !c.is_ascii_digit()).map_or(pa, |(n, _)| n);
        iocs::COMPROMISED_AXIOS
            .iter()
            .any(|(a, b, c)| *a == ma && *b == mi && *c == pa_clean)
    } else {
        false
    }
}

fn sha256_file(path: &Path) -> Option<String> {
    let data = fs::read(path).ok()?;
    Some(format!("{:x}", Sha256::digest(&data)))
}

/// Extract dependency names from a parsed package.json value.
fn get_deps(data: &serde_json::Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for key in &[
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(obj) = data.get(key).and_then(|v| v.as_object()) {
            for (k, v) in obj {
                out.push((k.clone(), v.as_str().unwrap_or("").to_string()));
            }
        }
    }
    out
}

/// Read a JSON file with size limit to prevent OOM on malicious inputs.
fn read_json_safe(path: &Path) -> Option<serde_json::Value> {
    let meta = fs::metadata(path).ok()?;
    if meta.len() > iocs::MAX_JSON_SIZE {
        return None;
    }
    let content = fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Scan a single package.json for IOCs.
fn scan_package_json(path: &Path) -> Vec<Finding> {
    PACKAGE_JSONS_SCANNED.fetch_add(1, Ordering::Relaxed);
    let mut findings = Vec::new();

    let data = match read_json_safe(path) {
        Some(v) => v,
        None => return findings,
    };

    let path_str = path.display().to_string();
    let deps = get_deps(&data);

    for (name, version) in &deps {
        // Malicious packages
        if iocs::MALICIOUS_PACKAGES.contains(&name.as_str()) {
            findings.push(Finding::critical(
                "malicious-dep",
                &path_str,
                &format!("Malicious package '{name}@{version}' in dependencies"),
            ));
        }
        // Secondary vectors
        if iocs::SECONDARY_PACKAGES.contains(&name.as_str()) {
            findings.push(Finding::critical(
                "secondary-vector",
                &path_str,
                &format!("Secondary attack package '{name}@{version}' in dependencies"),
            ));
        }
        // Compromised axios
        if name == "axios" && is_compromised_version(version) {
            findings.push(Finding::critical(
                "compromised-axios",
                &path_str,
                &format!("Compromised axios@{version} in dependencies"),
            ));
        }
    }

    // Check install hooks
    if let Some(scripts) = data.get("scripts").and_then(|v| v.as_object()) {
        for hook in iocs::SUSPICIOUS_HOOKS {
            if let Some(cmd) = scripts.get(*hook).and_then(|v| v.as_str()) {
                let cmd_lower = cmd.to_lowercase();
                if cmd_lower.contains("setup.js") || cmd_lower.contains("plain-crypto") {
                    findings.push(Finding::critical(
                        "malicious-hook",
                        &path_str,
                        &format!("Suspicious '{hook}' script: {cmd}"),
                    ));
                }
            }
        }
    }

    // Check for compromised maintainer email in author field
    if let Some(author) = data.get("author") {
        let author_str = match author {
            serde_json::Value::String(s) => s.to_lowercase(),
            serde_json::Value::Object(obj) => {
                obj.get("email")
                    .and_then(|e| e.as_str())
                    .unwrap_or("")
                    .to_lowercase()
            }
            _ => String::new(),
        };
        if author_str.contains(iocs::COMPROMISED_MAINTAINER_EMAIL) {
            findings.push(Finding::warning(
                "compromised-maintainer",
                &path_str,
                &format!(
                    "Package author contains compromised maintainer email '{}'",
                    iocs::COMPROMISED_MAINTAINER_EMAIL
                ),
            ));
        }
    }

    findings
}

/// Scan a lockfile (package-lock.json or npm-shrinkwrap.json) for IOCs.
fn scan_lockfile(path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    let data = match read_json_safe(path) {
        Some(v) => v,
        None => return findings,
    };

    let path_str = path.display().to_string();

    // Check both "packages" (v2/v3) and "dependencies" (v1) sections
    for section_key in &["packages", "dependencies"] {
        if let Some(obj) = data.get(section_key).and_then(|v| v.as_object()) {
            for (name, info) in obj {
                let base = name
                    .rsplit_once("node_modules/")
                    .map_or(name.as_str(), |(_, b)| b);
                let version = info
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if base == "axios" && is_compromised_version(version) {
                    findings.push(Finding::critical(
                        "locked-compromised-axios",
                        &path_str,
                        &format!("Lockfile pins axios@{version}"),
                    ));
                }
                if iocs::MALICIOUS_PACKAGES.contains(&base) {
                    findings.push(Finding::critical(
                        "locked-malicious-dep",
                        &path_str,
                        &format!("Malicious '{base}@{version}' in lockfile"),
                    ));
                }
                if iocs::SECONDARY_PACKAGES.contains(&base) {
                    findings.push(Finding::critical(
                        "locked-secondary-vector",
                        &path_str,
                        &format!("Secondary vector '{base}@{version}' in lockfile"),
                    ));
                }

                // Check integrity/resolved fields for known compromised shasums
                for field in &["integrity", "resolved"] {
                    if let Some(val) = info.get(field).and_then(|v| v.as_str()) {
                        let val_lower = val.to_lowercase();
                        for shasum in iocs::COMPROMISED_SHASUMS {
                            if val_lower.contains(shasum) {
                                findings.push(Finding::critical(
                                    "compromised-integrity",
                                    &path_str,
                                    &format!(
                                        "Lockfile '{field}' for '{base}' matches compromised shasum {shasum}"
                                    ),
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    findings
}

/// Scan a pnpm-lock.yaml for compromised versions (plain text search).
fn scan_pnpm_lock(path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return findings,
    };
    let path_str = path.display().to_string();

    // pnpm lockfile uses format like: /axios@1.14.1: or axios@1.14.1:
    for (ma, mi, pa) in iocs::COMPROMISED_AXIOS {
        let patterns = [
            format!("axios@{ma}.{mi}.{pa}"),
            format!("/axios/{ma}.{mi}.{pa}"),
        ];
        for pattern in &patterns {
            if content.contains(pattern) {
                findings.push(Finding::critical(
                    "pnpm-compromised-axios",
                    &path_str,
                    &format!("pnpm-lock.yaml resolves axios to compromised version {ma}.{mi}.{pa}"),
                ));
            }
        }
    }

    for pkg in iocs::MALICIOUS_PACKAGES
        .iter()
        .chain(iocs::SECONDARY_PACKAGES.iter())
    {
        if content.contains(pkg) {
            findings.push(Finding::critical(
                "pnpm-malicious-dep",
                &path_str,
                &format!("Package '{pkg}' referenced in pnpm-lock.yaml"),
            ));
        }
    }

    for shasum in iocs::COMPROMISED_SHASUMS {
        if content.contains(shasum) {
            findings.push(Finding::critical(
                "pnpm-compromised-integrity",
                &path_str,
                &format!("Compromised package shasum {shasum} found in pnpm-lock.yaml"),
            ));
        }
    }

    findings
}

/// Scan a yarn.lock for compromised versions via regex.
fn scan_yarn_lock(path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return findings,
    };
    let path_str = path.display().to_string();

    // Look for resolved axios versions
    let mut prev_was_axios = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("axios@") || trimmed.starts_with("\"axios@") {
            prev_was_axios = true;
            continue;
        }
        if prev_was_axios && trimmed.starts_with("version ") {
            let ver = trimmed
                .trim_start_matches("version ")
                .trim_matches('"');
            if is_compromised_version(ver) {
                findings.push(Finding::critical(
                    "yarn-compromised-axios",
                    &path_str,
                    &format!("yarn.lock resolves axios to compromised version {ver}"),
                ));
            }
            prev_was_axios = false;
        } else if !trimmed.is_empty() {
            prev_was_axios = false;
        }
    }

    for pkg in iocs::MALICIOUS_PACKAGES
        .iter()
        .chain(iocs::SECONDARY_PACKAGES.iter())
    {
        if content.contains(pkg) {
            findings.push(Finding::critical(
                "yarn-malicious-dep",
                &path_str,
                &format!("Package '{pkg}' referenced in yarn.lock"),
            ));
        }
    }

    findings
}

/// Inspect an installed node_modules directory for live compromise artifacts.
fn scan_node_modules(nm_path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let nm_str = nm_path.display().to_string();

    // plain-crypto-js should never exist
    for pkg in iocs::MALICIOUS_PACKAGES {
        let pkg_dir = nm_path.join(pkg);
        if pkg_dir.is_dir() {
            findings.push(Finding::critical(
                "installed-malicious-pkg",
                &pkg_dir.display().to_string(),
                &format!("Malicious package '{pkg}' installed on disk"),
            ));
            let setup = pkg_dir.join("setup.js");
            if setup.is_file() {
                let mut f = Finding::critical(
                    "active-dropper",
                    &setup.display().to_string(),
                    "Malicious setup.js dropper present (RAT installer)",
                );
                if let Some(hash) = sha256_file(&setup) {
                    let matched = hash == iocs::HASH_SETUP_JS;
                    let label = if matched { " (KNOWN MALICIOUS)" } else { "" };
                    f = f.with_hash(&format!("{hash}{label}"));
                }
                findings.push(f);
            }
            // Anti-forensics: dropper deletes setup.js and swaps package.md -> package.json
            let pkg_json = pkg_dir.join("package.json");
            if pkg_json.is_file() && !setup.is_file() {
                if let Some(data) = read_json_safe(&pkg_json) {
                    let has_hook = data.get("scripts")
                        .and_then(|s| s.as_object())
                        .map(|s| iocs::SUSPICIOUS_HOOKS.iter().any(|h| s.contains_key(*h)))
                        .unwrap_or(false);
                    if !has_hook {
                        findings.push(Finding::critical(
                            "cleaned-compromise",
                            &pkg_dir.display().to_string(),
                            &format!(
                                "Malicious '{pkg}' installed but setup.js deleted and \
                                 postinstall hook removed — dropper self-cleaned (anti-forensics)"
                            ),
                        ));
                    }
                }
            }

            // Check for orphan package.md (dropper backup before overwrite)
            let package_md = pkg_dir.join(iocs::ANTI_FORENSICS_PACKAGE_MD);
            if package_md.is_file() {
                findings.push(Finding::critical(
                    "anti-forensics-package-md",
                    &package_md.display().to_string(),
                    &format!(
                        "Orphan package.md in '{pkg}' — dropper artifact \
                         (original package.json was backed up before overwrite)"
                    ),
                ));
            }
        }
    }

    // Check installed axios for injected dependency
    let axios_pj = nm_path.join("axios").join("package.json");
    if axios_pj.is_file() {
        if let Ok(content) = fs::read_to_string(&axios_pj) {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&content) {
                let version = data.get("version").and_then(|v| v.as_str()).unwrap_or("");
                if is_compromised_version(version) {
                    findings.push(Finding::critical(
                        "installed-compromised-axios",
                        &axios_pj.display().to_string(),
                        &format!("Compromised axios@{version} installed"),
                    ));
                }
                if let Some(deps) = data.get("dependencies").and_then(|v| v.as_object()) {
                    for pkg in iocs::MALICIOUS_PACKAGES {
                        if deps.contains_key(*pkg) {
                            findings.push(Finding::critical(
                                "axios-injected-dep",
                                &axios_pj.display().to_string(),
                                &format!(
                                    "Installed axios has injected dependency '{pkg}'"
                                ),
                            ));
                        }
                    }
                }
            }
        }
    }

    // Secondary vectors
    for pkg in iocs::SECONDARY_PACKAGES {
        let pkg_dir = nm_path.join(pkg.replace('/', std::path::MAIN_SEPARATOR_STR));
        if pkg_dir.is_dir() {
            findings.push(Finding::critical(
                "installed-secondary-vector",
                &pkg_dir.display().to_string(),
                &format!("Secondary attack package '{pkg}' installed"),
            ));
        }
    }

    // Check for package.md in axios directory (anti-forensics artifact)
    let axios_md = nm_path.join("axios").join(iocs::ANTI_FORENSICS_PACKAGE_MD);
    if axios_md.is_file() {
        findings.push(Finding::warning(
            "anti-forensics-package-md",
            &axios_md.display().to_string(),
            "Orphan package.md in axios — possible dropper cleanup artifact",
        ));
    }

    let _ = nm_str;
    findings
}

/// An npm project discovered during the walk.
#[derive(Debug)]
pub struct NpmSource {
    pub path: PathBuf,
    pub has_lockfile: bool,
    pub lockfile_type: Option<String>,
    pub has_node_modules: bool,
    pub name: Option<String>,
}

/// Discovered targets for scanning.
pub struct ScanTargets {
    pub package_jsons: Vec<PathBuf>,
    pub lockfiles: Vec<PathBuf>,
    pub yarn_locks: Vec<PathBuf>,
    pub pnpm_locks: Vec<PathBuf>,
    pub node_modules_dirs: Vec<PathBuf>,
    pub npm_sources: Vec<NpmSource>,
}

/// Walk all roots and discover npm project locations + scannable files.
pub fn discover(roots: &[PathBuf]) -> ScanTargets {
    let mut package_jsons: Vec<PathBuf> = Vec::new();
    let mut lockfiles: Vec<PathBuf> = Vec::new();
    let mut yarn_locks: Vec<PathBuf> = Vec::new();
    let mut pnpm_locks: Vec<PathBuf> = Vec::new();
    let mut node_modules_dirs: Vec<PathBuf> = Vec::new();

    for root in roots {
        let walker = WalkDir::new(root).follow_links(false).into_iter();
        for entry in walker.filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            if e.file_type().is_dir() {
                if iocs::SKIP_DIRS.iter().any(|s| name.eq_ignore_ascii_case(s)) {
                    return false;
                }
                if name == "node_modules" {
                    return false;
                }
            }
            true
        }) {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            if entry.file_type().is_dir() {
                DIRS_SCANNED.fetch_add(1, Ordering::Relaxed);
                let path = entry.path();
                let nm = path.join("node_modules");
                if nm.is_dir() {
                    node_modules_dirs.push(nm);
                }
                continue;
            }

            let path = entry.into_path();
            let name = path.file_name().unwrap_or_default().to_string_lossy();

            match name.as_ref() {
                "package.json" => package_jsons.push(path),
                "package-lock.json" | "npm-shrinkwrap.json" => lockfiles.push(path),
                "yarn.lock" => yarn_locks.push(path),
                "pnpm-lock.yaml" => pnpm_locks.push(path),
                _ => {}
            }
        }
    }

    // Build npm source map: group by project root (parent of package.json)
    let mut npm_sources = Vec::new();
    for pj in &package_jsons {
        let project_dir = match pj.parent() {
            Some(p) => p,
            None => continue,
        };

        // Read project name from package.json
        let name = fs::read_to_string(pj)
            .ok()
            .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
            .and_then(|v| v.get("name")?.as_str().map(String::from));

        let has_lock = project_dir.join("package-lock.json").is_file()
            || project_dir.join("npm-shrinkwrap.json").is_file();
        let has_yarn = project_dir.join("yarn.lock").is_file();
        let has_pnpm = project_dir.join("pnpm-lock.yaml").is_file();
        let has_nm = project_dir.join("node_modules").is_dir();

        let lockfile_type = match (has_lock, has_yarn, has_pnpm) {
            (true, true, _) => Some("npm+yarn".into()),
            (true, _, true) => Some("npm+pnpm".into()),
            (true, _, _) => Some("npm".into()),
            (_, true, _) => Some("yarn".into()),
            (_, _, true) => Some("pnpm".into()),
            _ => None,
        };

        npm_sources.push(NpmSource {
            path: project_dir.to_path_buf(),
            has_lockfile: has_lock || has_yarn,
            lockfile_type,
            has_node_modules: has_nm,
            name,
        });
    }

    ScanTargets {
        package_jsons,
        lockfiles,
        yarn_locks,
        pnpm_locks,
        node_modules_dirs,
        npm_sources,
    }
}

/// Write the npm sources map to a YAML file.
pub fn write_sources_map(targets: &ScanTargets, output: &Path) {
    use std::io::Write;
    let mut f = match fs::File::create(output) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to write npm sources map: {e}");
            return;
        }
    };

    writeln!(f, "# npm sources map — generated by axios-rat-scan").ok();
    writeln!(f, "# {} project(s) discovered\n", targets.npm_sources.len()).ok();
    writeln!(f, "projects:").ok();

    for src in &targets.npm_sources {
        let name = src.name.as_deref().unwrap_or("(unnamed)");
        writeln!(f, "  - path: \"{}\"", src.path.display()).ok();
        writeln!(f, "    name: \"{}\"", name).ok();
        writeln!(f, "    has_lockfile: {}", src.has_lockfile).ok();
        if let Some(lt) = &src.lockfile_type {
            writeln!(f, "    lockfile_type: \"{lt}\"").ok();
        }
        writeln!(f, "    has_node_modules: {}", src.has_node_modules).ok();
    }
}

/// Scan the npm cache (~/.npm/_cacache) for references to malicious packages.
///
/// The npm cache stores content-addressable tarballs. After cleanup,
/// the cache may retain the malicious package data and reinstall it.
pub fn scan_npm_cache(findings: &mut Vec<Finding>) {
    let home = match home_dir() {
        Some(h) => h,
        None => return,
    };

    let cache_index = home.join(".npm").join("_cacache").join("index-v5");
    if !cache_index.is_dir() {
        return;
    }

    let search_terms: Vec<&str> = iocs::MALICIOUS_PACKAGES.iter()
        .chain(iocs::SECONDARY_PACKAGES.iter())
        .copied()
        .collect();

    for entry in WalkDir::new(&cache_index)
        .max_depth(4)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        // Index files are small (< 4KB typically). Skip anything large.
        if let Ok(meta) = entry.metadata() {
            if meta.len() > 64 * 1024 {
                continue;
            }
        }
        if let Ok(content) = std::fs::read_to_string(entry.path()) {
            let content_lower = content.to_lowercase();
            for term in &search_terms {
                if content_lower.contains(&term.to_lowercase()) {
                    findings.push(Finding::warning(
                        "npm-cache-malicious",
                        &entry.path().display().to_string(),
                        &format!(
                            "Malicious package '{term}' referenced in npm cache \
                             — cache may retain compromised artifacts after cleanup"
                        ),
                    ));
                    break;
                }
            }
            for shasum in iocs::COMPROMISED_SHASUMS {
                if content_lower.contains(shasum) {
                    findings.push(Finding::warning(
                        "npm-cache-compromised-integrity",
                        &entry.path().display().to_string(),
                        &format!(
                            "Compromised package shasum {shasum} found in npm cache index"
                        ),
                    ));
                    break;
                }
            }
        }
    }
}

/// Scan all discovered targets in parallel with progress reporting.
pub fn scan_targets_with_progress(
    targets: &ScanTargets,
    pb: &Option<indicatif::ProgressBar>,
) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();

    let bump = |p: &Path| {
        if let Some(pb) = pb {
            let name = p.file_name().unwrap_or_default().to_string_lossy();
            // Show parent dir for context
            let parent = p.parent()
                .and_then(|pp| pp.file_name())
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_default();
            pb.set_message(format!("{parent}/{name}"));
            pb.inc(1);
        }
    };

    let pj_findings: Vec<Finding> = targets
        .package_jsons
        .par_iter()
        .flat_map(|p| {
            let r = scan_package_json(p);
            bump(p);
            r
        })
        .collect();
    findings.extend(pj_findings);

    let lf_findings: Vec<Finding> = targets
        .lockfiles
        .par_iter()
        .flat_map(|p| {
            let r = scan_lockfile(p);
            bump(p);
            r
        })
        .collect();
    findings.extend(lf_findings);

    let yl_findings: Vec<Finding> = targets
        .yarn_locks
        .par_iter()
        .flat_map(|p| {
            let r = scan_yarn_lock(p);
            bump(p);
            r
        })
        .collect();
    findings.extend(yl_findings);

    let pnpm_findings: Vec<Finding> = targets
        .pnpm_locks
        .par_iter()
        .flat_map(|p| {
            let r = scan_pnpm_lock(p);
            bump(p);
            r
        })
        .collect();
    findings.extend(pnpm_findings);

    let nm_findings: Vec<Finding> = targets
        .node_modules_dirs
        .par_iter()
        .flat_map(|p| {
            let r = scan_node_modules(p);
            bump(p);
            r
        })
        .collect();
    findings.extend(nm_findings);

    findings
}

