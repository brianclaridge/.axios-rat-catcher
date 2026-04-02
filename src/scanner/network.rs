use crate::iocs;
use crate::report::Finding;
use std::path::Path;
use std::process::Command;

/// Hardened command paths to prevent PATH hijacking.
/// If the RAT modifies PATH, using bare "netstat" could execute attacker code.
#[cfg(windows)]
const NETSTAT: &str = r"C:\Windows\System32\netstat.exe";
#[cfg(windows)]
const IPCONFIG: &str = r"C:\Windows\System32\ipconfig.exe";

#[cfg(not(windows))]
const NETSTAT: &str = "/usr/bin/netstat";
#[cfg(target_os = "linux")]
const SS: &str = "/usr/sbin/ss";
#[cfg(target_os = "linux")]
const RESOLVECTL: &str = "/usr/bin/resolvectl";
#[cfg(target_os = "macos")]
const LOG_CMD: &str = "/usr/bin/log";

/// Check for active C2 connections and DNS cache entries.
pub fn scan(findings: &mut Vec<Finding>) {
    scan_connections(findings);
    scan_dns_cache(findings);
}

/// Parse netstat/ss output for connections to known C2 infrastructure.
fn scan_connections(findings: &mut Vec<Finding>) {
    let netstat_path = Path::new(NETSTAT);

    let output = if cfg!(windows) {
        if netstat_path.exists() {
            Command::new(NETSTAT).args(["-n", "-o"]).output()
        } else {
            Command::new("netstat").args(["-n", "-o"]).output()
        }
    } else if netstat_path.exists() {
        Command::new(NETSTAT).args(["-tnp"]).output()
    } else {
        Command::new("netstat").args(["-tnp"]).output()
    };

    let output = match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => {
            #[cfg(target_os = "linux")]
            {
                let ss_path = Path::new(SS);
                let cmd = if ss_path.exists() { SS } else { "ss" };
                match Command::new(cmd).args(["-tnp"]).output() {
                    Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
                    Err(_) => return,
                }
            }
            #[cfg(not(target_os = "linux"))]
            return;
        }
    };

    let mut flagged_c2_ip = false;
    let mut flagged_c2_endpoint = false;

    for line in output.lines() {
        let lower = line.to_lowercase();

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
    #[cfg(windows)]
    {
        let cmd = if Path::new(IPCONFIG).exists() { IPCONFIG } else { "ipconfig" };
        if let Ok(output) = Command::new(cmd).args(["/displaydns"]).output() {
            let text = String::from_utf8_lossy(&output.stdout).to_lowercase();
            for domain in iocs::C2_DOMAINS {
                if text.contains(domain) {
                    findings.push(Finding::critical(
                        "dns-cache-c2",
                        "dns-cache",
                        &format!(
                            "C2 domain '{domain}' in Windows DNS cache — host has resolved this C2 domain"
                        ),
                    ));
                }
            }
            if text.contains(iocs::C2_IP) {
                findings.push(Finding::critical(
                    "dns-cache-c2-ip",
                    "dns-cache",
                    &format!(
                        "C2 IP {} in Windows DNS cache — domain resolved to known C2 address",
                        iocs::C2_IP
                    ),
                ));
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let cmd = if Path::new(LOG_CMD).exists() { LOG_CMD } else { "log" };
        if let Ok(output) = Command::new(cmd)
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

    #[cfg(target_os = "linux")]
    {
        // Use resolvectl show-cache (systemd 256+) to dump the entire DNS cache
        // without putting IOC domain strings on the command line.
        let cmd = if Path::new(RESOLVECTL).exists() { RESOLVECTL } else { "resolvectl" };
        if let Ok(output) = Command::new(cmd).args(["show-cache"]).output() {
            let text = String::from_utf8_lossy(&output.stdout).to_lowercase();
            for domain in iocs::C2_DOMAINS {
                if text.contains(domain) {
                    findings.push(Finding::critical(
                        "dns-cache-c2",
                        "dns-cache",
                        &format!("C2 domain '{domain}' found in systemd-resolved cache"),
                    ));
                }
            }
            if text.contains(iocs::C2_IP) {
                findings.push(Finding::critical(
                    "dns-cache-c2-ip",
                    "dns-cache",
                    &format!(
                        "C2 IP {} found in systemd-resolved cache",
                        iocs::C2_IP
                    ),
                ));
            }
        }

        // Fallback: check journalctl for DNS resolution logs (older systemd)
        if let Ok(output) = Command::new("/usr/bin/journalctl")
            .args(["--unit=systemd-resolved", "--since=-1h", "--no-pager", "-q"])
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout).to_lowercase();
            for domain in iocs::C2_DOMAINS {
                if text.contains(domain) {
                    findings.push(Finding::critical(
                        "dns-log-c2",
                        "dns-log",
                        &format!("C2 domain '{domain}' found in systemd-resolved journal (last 1h)"),
                    ));
                }
            }
        }
    }

    // Cross-platform: hosts file tampering
    let hosts_path = if cfg!(windows) {
        r"C:\Windows\System32\drivers\etc\hosts"
    } else {
        "/etc/hosts"
    };
    if let Ok(hosts) = std::fs::read_to_string(hosts_path) {
        let hosts_lower = hosts.to_lowercase();
        for domain in iocs::C2_DOMAINS {
            if hosts_lower.contains(domain) {
                findings.push(Finding::critical(
                    "hosts-file-c2",
                    hosts_path,
                    &format!("C2 domain '{domain}' found in hosts file"),
                ));
            }
        }
    }
}
