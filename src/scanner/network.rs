use crate::iocs;
use crate::report::Finding;
use std::process::Command;

/// Check for active C2 connections and DNS cache entries.
///
/// Covers:
/// - Active TCP connections to C2 IP 142.11.206.73:8000
/// - Connections to C2 domain sfrclak.com
/// - Connections to typosquat domain packages.npm.org
/// - DNS cache entries for C2 domains (Windows: ipconfig /displaydns)
pub fn scan(findings: &mut Vec<Finding>) {
    scan_connections(findings);
    scan_dns_cache(findings);
}

/// Parse netstat/ss output for connections to known C2 infrastructure.
fn scan_connections(findings: &mut Vec<Finding>) {
    let output = if cfg!(windows) {
        Command::new("netstat").args(["-n", "-o"]).output()
    } else {
        Command::new("netstat").args(["-tnp"]).output()
    };

    let output = match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => {
            if cfg!(target_os = "linux") {
                match Command::new("ss").args(["-tnp"]).output() {
                    Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
                    Err(_) => return,
                }
            } else {
                return;
            }
        }
    };

    // Deduplicate: track what we've already flagged
    let mut flagged_c2_ip = false;
    let mut flagged_c2_endpoint = false;

    for line in output.lines() {
        let lower = line.to_lowercase();

        // C2 endpoint: IP:port
        let c2_endpoint = format!("{}:{}", iocs::C2_IP, iocs::C2_PORT);
        if lower.contains(&c2_endpoint) && !flagged_c2_endpoint {
            findings.push(Finding::critical(
                "active-c2-connection",
                "network",
                &format!("Active connection to C2 endpoint {c2_endpoint}: {}", line.trim()),
            ));
            flagged_c2_endpoint = true;
        } else if lower.contains(iocs::C2_IP) && !flagged_c2_ip {
            findings.push(Finding::critical(
                "active-c2-connection",
                "network",
                &format!("Active connection to C2 IP {}: {}", iocs::C2_IP, line.trim()),
            ));
            flagged_c2_ip = true;
        }

        // All C2 domains (sfrclak.com + packages.npm.org)
        for domain in iocs::C2_DOMAINS {
            if lower.contains(domain) {
                findings.push(Finding::critical(
                    "active-c2-connection",
                    "network",
                    &format!("Active connection to C2 domain '{domain}': {}", line.trim()),
                ));
            }
        }
    }
}

/// Check OS DNS cache for C2 domain resolutions.
fn scan_dns_cache(findings: &mut Vec<Finding>) {
    // Windows: ipconfig /displaydns
    #[cfg(windows)]
    {
        if let Ok(output) = Command::new("ipconfig").args(["/displaydns"]).output() {
            let text = String::from_utf8_lossy(&output.stdout).to_lowercase();
            for domain in iocs::C2_DOMAINS {
                if text.contains(domain) {
                    findings.push(Finding::critical(
                        "dns-cache-c2",
                        "dns-cache",
                        &format!(
                            "C2 domain '{domain}' found in Windows DNS cache (ipconfig /displaydns) — \
                             indicates this host has resolved the C2 domain"
                        ),
                    ));
                }
            }
            // Also check for the C2 IP in DNS responses
            if text.contains(iocs::C2_IP) {
                findings.push(Finding::critical(
                    "dns-cache-c2-ip",
                    "dns-cache",
                    &format!(
                        "C2 IP {} found in Windows DNS cache — domain resolved to known C2 address",
                        iocs::C2_IP
                    ),
                ));
            }
        }
    }

    // macOS: dscacheutil -cachedump (may require root, best-effort)
    #[cfg(target_os = "macos")]
    {
        // Try log show for recent DNS queries (doesn't require root)
        if let Ok(output) = Command::new("log")
            .args(["show", "--predicate", "subsystem == 'com.apple.mdnsresponder'",
                   "--style", "compact", "--last", "1h"])
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout).to_lowercase();
            for domain in iocs::C2_DOMAINS {
                if text.contains(domain) {
                    findings.push(Finding::critical(
                        "dns-log-c2",
                        "dns-log",
                        &format!("C2 domain '{domain}' found in macOS DNS resolver log (last 1h)"),
                    ));
                }
            }
        }
    }

    // Linux: check /etc/hosts for hijacking and systemd-resolved cache
    #[cfg(target_os = "linux")]
    {
        // systemd-resolve --statistics / resolvectl statistics
        if let Ok(output) = Command::new("resolvectl")
            .args(["query", "--cache", "--legend=no", iocs::C2_DOMAIN])
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout).to_lowercase();
            if text.contains(iocs::C2_IP) || text.contains(iocs::C2_DOMAIN) {
                findings.push(Finding::critical(
                    "dns-cache-c2",
                    "dns-cache",
                    &format!("C2 domain '{}' found in systemd-resolved cache", iocs::C2_DOMAIN),
                ));
            }
        }
    }

    // Cross-platform: check /etc/hosts (or Windows hosts file) for C2 entries
    let hosts_path = if cfg!(windows) {
        r"C:\Windows\System32\drivers\etc\hosts".to_string()
    } else {
        "/etc/hosts".to_string()
    };
    if let Ok(hosts) = std::fs::read_to_string(&hosts_path) {
        let hosts_lower = hosts.to_lowercase();
        for domain in iocs::C2_DOMAINS {
            if hosts_lower.contains(domain) {
                findings.push(Finding::critical(
                    "hosts-file-c2",
                    &hosts_path,
                    &format!("C2 domain '{domain}' found in hosts file"),
                ));
            }
        }
    }
}
