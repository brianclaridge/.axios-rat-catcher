/// Known-compromised axios versions: (major, minor, patch)
pub const COMPROMISED_AXIOS: &[(&str, &str, &str)] = &[("1", "14", "1"), ("0", "30", "4")];

/// Malicious packages injected by the attack
pub const MALICIOUS_PACKAGES: &[&str] = &["plain-crypto-js"];

/// Secondary distribution vectors
pub const SECONDARY_PACKAGES: &[&str] = &["@shadanai/openclaw", "@qqbrowser/openclaw-qbot"];

/// C2 infrastructure
pub const C2_DOMAIN: &str = "sfrclak.com";
pub const C2_IP: &str = "142.11.206.73";
pub const C2_PORT: u16 = 8000;
pub const C2_ENDPOINT: &str = "/6202033";

/// Typosquat payload distribution domain (NOT the real npm registry)
pub const C2_PAYLOAD_DOMAIN: &str = "packages.npm.org";

/// All C2 domains to check in DNS caches and network connections
pub const C2_DOMAINS: &[&str] = &[C2_DOMAIN, C2_PAYLOAD_DOMAIN];

/// Spoofed User-Agent used by all RAT variants — IE8 on Windows XP
/// Per Elastic: "the toolkit's most reliable detection indicator"
pub const C2_USER_AGENT: &str =
    "mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)";

/// SHA-256 hashes of known malicious files
pub const HASH_SETUP_JS: &str =
    "e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09";
#[cfg(target_os = "macos")]
pub const HASHES_MACOS_RAT: &[&str] = &[
    "92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a",
];
#[cfg(windows)]
pub const HASHES_WINDOWS_PS1: &[&str] = &[
    "ed8560c1ac7ceb6983ba995124d5917dc1a00288912387a6389296637d5f815c",
    "617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101",
];
#[cfg(windows)]
pub const HASH_WINDOWS_BAT: &str =
    "e49c2732fb9861548208a78e72996b9c3c470b6b562576924bcc3a9fb75bf9ff";
#[cfg(target_os = "linux")]
pub const HASHES_LINUX_RAT: &[&str] = &[
    "6483c004e207137385f480909d6edecf1b699087378aa91745ecba7c3394f9d7",
    "fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf",
];

/// npm package shasum (SHA-1) for lockfile integrity field checking
pub const COMPROMISED_SHASUMS: &[&str] = &[
    "2553649f232204966871cea80a5d0d6adc700ca",  // axios@1.14.1
    "d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71", // axios@0.30.4
    "07d889e2dadce6f3910dcbc253317d28ca61c766", // plain-crypto-js@4.2.1
];

/// Suspicious install hook keywords
pub const SUSPICIOUS_HOOKS: &[&str] = &["postinstall", "preinstall", "install"];

/// Directories to skip during traversal
pub const SKIP_DIRS: &[&str] = &[
    ".git",
    ".hg",
    "System Volume Information",
    "$RECYCLE.BIN",
    "Windows",
];

/// Process names that should never be spawned by node as children
/// (Elastic: "Curl or Wget Spawned via Node.js" detection rule)
pub const SUSPICIOUS_NODE_CHILDREN: &[&str] = &[
    "curl", "wget", "curl.exe", "wget.exe",
];

/// Shell interpreters (for parent-child chain detection)
pub const SHELL_NAMES: &[&str] = &[
    "bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish",
    "cmd.exe", "bash.exe", "powershell.exe", "pwsh.exe",
];

/// Max file size (bytes) to parse as JSON. Prevents OOM on malicious files.
pub const MAX_JSON_SIZE: u64 = 10 * 1024 * 1024; // 10 MB

/// Compromised maintainer email (account takeover indicator)
pub const COMPROMISED_MAINTAINER_EMAIL: &str = "ifstap@proton.me";

/// Anti-forensics: the dropper renames package.md -> package.json after cleanup
pub const ANTI_FORENSICS_PACKAGE_MD: &str = "package.md";

/// PowerShell Base64 decode flags (Elastic: "Suspicious PowerShell Base64 Decoding")
#[cfg(windows)]
pub const PS_BASE64_FLAGS: &[&str] = &["-encodedcommand", "-enc ", "-ec ", "frombase64string"];

/// Curl flags for Windows file transfer (Elastic: "Potential File Transfer via Curl for Windows")
#[cfg(windows)]
pub const CURL_TRANSFER_FLAGS: &[&str] = &["-o ", "--output "];

/// Unusual parent processes for shell backgrounding detection
/// (Elastic: "Process Backgrounded by Unusual Parent")
pub const UNUSUAL_PARENTS: &[&str] = &[
    "node", "bun", "deno", "python", "python3", "ruby", "php", "java", "dotnet",
];
