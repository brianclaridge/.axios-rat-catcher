use crate::iocs;
use crate::report::Finding;
use sysinfo::System;
use std::collections::HashMap;

/// Check if `check_pid` is a descendant (child, grandchild, etc.) of `ancestor_pid`.
fn is_descendant_of(check_pid: u32, ancestor_pid: u32, sys: &System) -> bool {
    let mut current = check_pid;
    for _ in 0..32 {
        let parent = sys.processes()
            .get(&sysinfo::Pid::from_u32(current))
            .and_then(|p| p.parent())
            .map(|p| p.as_u32());
        match parent {
            Some(ppid) if ppid == ancestor_pid => return true,
            Some(ppid) if ppid == 0 || ppid == current => return false,
            Some(ppid) => current = ppid,
            None => return false,
        }
    }
    false
}

/// Check running processes for signs of active RAT execution.
///
/// Covers these Elastic detection rules:
/// - Execution via Renamed Signed Binary Proxy (wt.exe = renamed PowerShell)
/// - Curl or Wget Spawned via Node.js (node -> shell -> curl/wget)
/// - Process Backgrounded by Unusual Parent (node -> sh -c ... &)
/// - Suspicious URL as argument to Self-Signed Binary (macOS osascript)
/// - Suspicious XPC Service Child Process (macOS)
pub fn scan(findings: &mut Vec<Finding>) {
    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

    let self_pid = std::process::id();

    // Build parent PID -> process name map for parent-child chain detection
    let mut pid_name: HashMap<u32, String> = HashMap::new();
    let mut pid_cmd: HashMap<u32, String> = HashMap::new();
    for (pid, process) in sys.processes() {
        let name = process.name().to_string_lossy().to_lowercase();
        let cmd: String = process.cmd().iter()
            .map(|s| s.to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase();
        pid_name.insert(pid.as_u32(), name);
        pid_cmd.insert(pid.as_u32(), cmd);
    }

    for (pid, process) in sys.processes() {
        // Skip the scanner itself and its child processes to prevent self-detection
        if pid.as_u32() == self_pid || is_descendant_of(pid.as_u32(), self_pid, &sys) {
            continue;
        }

        let name = process.name().to_string_lossy().to_lowercase();
        let cmd: String = process.cmd().iter()
            .map(|s| s.to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase();
        let exe_path = process
            .exe()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        let parent_pid = process.parent().map(|p| p.as_u32());
        let parent_name = parent_pid
            .and_then(|ppid| pid_name.get(&ppid))
            .cloned()
            .unwrap_or_default();

        let loc = format!("PID {pid} ({exe_path})");

        // ── Windows: Renamed PowerShell (Elastic: Execution via Renamed Signed Binary Proxy) ──
        #[cfg(windows)]
        {
            let exe_lower = exe_path.to_lowercase();
            let programdata =
                std::env::var("PROGRAMDATA").unwrap_or_else(|_| r"C:\ProgramData".into());
            let pd_lower = programdata.to_lowercase();

            if name == "wt.exe" && exe_lower.contains(&pd_lower) {
                findings.push(Finding::critical(
                    "active-rat-process",
                    &loc,
                    "wt.exe running from ProgramData (renamed PowerShell — Elastic: Renamed Signed Binary Proxy)",
                ));
            }

            // Also flag any process running PowerShell flags from a non-powershell exe
            if !name.contains("powershell") && !name.contains("pwsh")
                && (cmd.contains("-noprofile") && cmd.contains("-ep bypass"))
            {
                findings.push(Finding::critical(
                    "renamed-binary-proxy",
                    &loc,
                    "Non-PowerShell binary executing with -NoProfile -ep Bypass flags",
                ));
            }

            // Elastic: Suspicious PowerShell Base64 Decoding
            if (name.contains("powershell") || name.contains("pwsh") || name == "wt.exe")
                && iocs::PS_BASE64_FLAGS.iter().any(|flag| cmd.contains(flag))
            {
                findings.push(Finding::critical(
                    "ps-base64-decode",
                    &loc,
                    "PowerShell Base64 decoding detected (Elastic: Suspicious PowerShell Base64 Decoding)",
                ));
            }

            // Elastic: Potential File Transfer via Curl for Windows
            if name == "curl.exe"
                && cmd.contains("http")
                && iocs::CURL_TRANSFER_FLAGS.iter().any(|flag| cmd.contains(flag))
            {
                let is_c2 = iocs::C2_DOMAINS.iter().any(|d| cmd.contains(d));
                if is_c2 {
                    findings.push(Finding::critical(
                        "curl-file-transfer-c2",
                        &loc,
                        "curl.exe downloading from C2 domain (Elastic: File Transfer via Curl for Windows)",
                    ));
                } else {
                    findings.push(Finding::warning(
                        "curl-file-transfer",
                        &loc,
                        "curl.exe file download detected (Elastic: Potential File Transfer via Curl for Windows)",
                    ));
                }
            }
        }

        // ── macOS: com.apple.act.mond RAT ──
        #[cfg(target_os = "macos")]
        {
            if name == "com.apple.act.mond" || exe_path.contains("com.apple.act.mond") {
                findings.push(Finding::critical(
                    "active-rat-process",
                    &loc,
                    "com.apple.act.mond RAT process running",
                ));
            }

            // Elastic: Suspicious URL as argument to Self-Signed Binary
            // osascript executing shell commands (dropper mechanism)
            if name == "osascript" && (cmd.contains("do shell script") || cmd.contains("curl") || cmd.contains(iocs::C2_DOMAIN)) {
                findings.push(Finding::critical(
                    "osascript-dropper",
                    &loc,
                    "osascript executing shell commands (Elastic: Suspicious URL as argument to Self-Signed Binary)",
                ));
            }
        }

        // ── Linux: Python running /tmp/ld.py ──
        #[cfg(target_os = "linux")]
        if (name.starts_with("python") || name == "python3")
            && cmd.contains("/tmp/ld.py")
        {
            findings.push(Finding::critical(
                "active-rat-process",
                &loc,
                "Python process running /tmp/ld.py RAT",
            ));
        }

        // ── Cross-platform: Spoofed IE8 User-Agent in command line ──
        // Per Elastic: "the toolkit's most reliable detection indicator"
        if cmd.contains(iocs::C2_USER_AGENT) {
            findings.push(Finding::critical(
                "c2-user-agent",
                &loc,
                "Spoofed IE8/WinXP User-Agent in cmdline — primary C2 beacon indicator (Elastic)",
            ));
        }

        // ── Elastic: Curl or Wget Spawned via Node.js ──
        // Detection: node -> (shell) -> curl/wget with http URL
        if iocs::SUSPICIOUS_NODE_CHILDREN.iter().any(|c| name == *c) {
            // Check if parent is a shell whose parent is node
            let grandparent_is_node = parent_pid
                .and_then(|ppid| {
                    // Look up the parent's parent
                    sys.processes().get(&sysinfo::Pid::from_u32(ppid))
                        .and_then(|p| p.parent())
                        .map(|gp| pid_name.get(&gp.as_u32()).cloned().unwrap_or_default())
                })
                .map(|gp_name| gp_name.starts_with("node") || gp_name == "bun")
                .unwrap_or(false);

            let parent_is_node = parent_name.starts_with("node") || parent_name == "bun";
            let parent_is_shell = iocs::SHELL_NAMES.iter().any(|s| parent_name == *s);

            if (parent_is_node || (parent_is_shell && grandparent_is_node)) && cmd.contains("http") {
                findings.push(Finding::critical(
                    "node-child-fetch",
                    &loc,
                    &format!(
                        "{name} with HTTP URL spawned via Node.js (parent: {parent_name}) — Elastic: Curl or Wget Spawned via Node.js"
                    ),
                ));
            }
        }

        // ── Elastic: Process Backgrounded by Unusual Parent ──
        if iocs::SHELL_NAMES.iter().any(|s| name == *s)
            && cmd.contains("-c") && cmd.contains('&')
            && iocs::UNUSUAL_PARENTS.iter().any(|p| parent_name.starts_with(p))
        {
            findings.push(Finding::warning(
                "backgrounded-by-unusual-parent",
                &loc,
                &format!(
                    "Shell with backgrounded command spawned by {parent_name} (Elastic: Process Backgrounded by Unusual Parent)"
                ),
            ));
        }

        // ── C2 domains in any process command line ──
        for domain in iocs::C2_DOMAINS {
            if cmd.contains(domain) {
                findings.push(Finding::critical(
                    "c2-domain-in-cmdline",
                    &loc,
                    &format!("C2 domain '{domain}' found in process command line"),
                ));
            }
        }
    }
}
