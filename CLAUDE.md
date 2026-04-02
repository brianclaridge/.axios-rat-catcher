# Axios Supply Chain RAT Scanner — Research & Plan

## Incident Overview

On 2026-03-31, the npm account of axios maintainer "jasonsaayman" was hijacked (email changed to `ifstap@proton.me`). Two compromised versions were published that inject `plain-crypto-js@4.2.1` — a fake package whose postinstall hook (`setup.js`) deploys a cross-platform RAT. Elastic attributes overlap with **WAVESHAPER**, a C++ backdoor tracked by Mandiant and linked to **UNC1069 (DPRK)**. On 2026-04-01, Google Threat Intelligence Group formally attributed the attack to UNC1069, confirming the RAT as **WAVESHAPER.V2**.

## Sources

### Primary Analysis
- Elastic Security Labs: https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all
- Elastic detection rules: https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections
- Elastic detection-rules repo: https://github.com/elastic/detection-rules
- Elastic protections-artifacts repo: https://github.com/elastic/protections-artifacts
- Google/Mandiant UNC1069 attribution: https://cloud.google.com/blog/topics/threat-intelligence/north-korea-threat-actor-targets-axios-npm-package

### Industry Coverage (2026-03-31 — 2026-04-01)
- The Hacker News (attack): https://thehackernews.com/2026/03/axios-supply-chain-attack-pushes-cross.html
- The Hacker News (attribution): https://thehackernews.com/2026/04/google-attributes-axios-npm-supply.html
- Wiz: https://www.wiz.io/blog/axios-npm-compromised-in-supply-chain-attack
- Malwarebytes: https://www.malwarebytes.com/blog/news/2026/03/axios-supply-chain-attack-chops-away-at-npm-trust
- SOCRadar: https://socradar.io/blog/axios-npm-supply-chain-attack-2026-ciso-guide/
- Sophos: https://www.sophos.com/en-us/blog/axios-npm-package-compromised-to-deploy-malware
- SANS: https://www.sans.org/blog/axios-npm-supply-chain-compromise-malicious-packages-remote-access-trojan
- Trend Micro: https://www.trendmicro.com/en_us/research/26/c/axios-npm-package-compromised.html
- Aikido: https://www.aikido.dev/blog/axios-npm-compromised-maintainer-hijacked-rat
- CyberScoop: https://cyberscoop.com/axios-software-developer-tool-attack-compromise/
- Bloomberg: https://www.bloomberg.com/news/articles/2026-03-31/axios-software-tool-used-by-millions-compromised-in-hack
- Arctic Wolf: https://arcticwolf.com/resources/blog/supply-chain-attack-impacts-widely-used-axios-npm-package/
- StepSecurity: https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan
- Vercel: https://vercel.com/changelog/axios-package-compromise-and-remediation-steps
- OX Security: https://www.ox.security/blog/axios-compromised-with-a-malicious-dependency/

---

## Attack Timeline

| Timestamp (UTC) | Event |
|---|---|
| 2026-02-18 17:19 | `axios@0.30.3` published (legitimate) |
| 2026-03-27 19:01 | `axios@1.14.0` published via GitHub Actions OIDC (legitimate) |
| 2026-03-30 05:57 | `plain-crypto-js@4.2.0` published (clean decoy to establish package) |
| 2026-03-30 23:59 | `plain-crypto-js@4.2.1` published (malicious postinstall backdoor) |
| 2026-03-31 00:21 | `axios@1.14.1` published, tagged `latest` |
| 2026-03-31 01:00 | `axios@0.30.4` published, tagged `legacy` |
| 2026-03-31 01:50 | GitHub Security Advisory filed |
| 2026-03-31 ~03:15 | Compromised versions removed from npm |
| 2026-04-01 | Google/Mandiant attributes to UNC1069 (DPRK), WAVESHAPER.V2 |

## Attack Chain

1. Compromised axios version adds `plain-crypto-js@4.2.1` to dependencies
2. `npm install` triggers `postinstall: "node setup.js"`
3. `setup.js` is obfuscated: string reversal → Base64 decode → XOR cipher (key: `OrDeR_7077`, index: `7 * i² % 10`)
4. Dropper detects OS, fetches platform-specific stage-2 from C2
5. Stage-2 RAT installs, beacons every 60s
6. Dropper self-cleans: `fs.unlink(__filename)`, swaps `package.md` → `package.json`

## Account Compromise Details

The attacker used a **stolen long-lived npm access token** (not 2FA bypass) to publish directly to the npm registry. Legitimate axios releases always include OIDC provenance metadata and SLSA build attestations — the malicious versions had neither, which is a key detection signal. The compromised versions were live for approximately **3 hours** before npm removed them.

---

## Indicators of Compromise (IOCs)

### Compromised npm Packages

| Package | Version | shasum |
|---|---|---|
| axios | 1.14.1 | `2553649f232204966871cea80a5d0d6adc700ca` |
| axios | 0.30.4 | `d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71` |
| plain-crypto-js | 4.2.1 | `07d889e2dadce6f3910dcbc253317d28ca61c766` |

Secondary vectors:
- `@shadanai/openclaw` (versions 2026.3.28-2, 2026.3.28-3, 2026.3.31-1, 2026.3.31-2)
- `@qqbrowser/openclaw-qbot@0.0.130`

### Network IOCs

| Indicator | Value |
|---|---|
| C2 domain | `sfrclak[.]com` |
| C2 IP | `142.11.206[.]73` |
| C2 port | 8000 |
| C2 endpoint | `/6202033` |
| macOS payload URL | `packages[.]npm[.]org/product0` |
| Windows payload URL | `packages[.]npm[.]org/product1` |
| Linux payload URL | `packages[.]npm[.]org/product2` |
| User-Agent (all platforms) | `mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)` |
| C2 transport | HTTP POST, Base64-encoded JSON body |
| Beacon interval | 60 seconds |
| Session ID | 16-char random alphanumeric |

### File Hashes (SHA-256)

| File | SHA-256 |
|---|---|
| setup.js (dropper) | `e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09` |
| com.apple.act.mond (macOS RAT) | `92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a` |
| 6202033.ps1 (Windows RAT) | `ed8560c1ac7ceb6983ba995124d5917dc1a00288912387a6389296637d5f815c` |
| 6202033.ps1 (Windows, alt hash) | `617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101` |
| system.bat (Windows persistence) | `e49c2732fb9861548208a78e72996b9c3c470b6b562576924bcc3a9fb75bf9ff` |
| ld.py (Linux RAT) | `6483c004e207137385f480909d6edecf1b699087378aa91745ecba7c3394f9d7` |
| ld.py (Linux, alt hash) | `fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf` |

### File System Artifacts by Platform

**All platforms:**
- `$TMPDIR/6202033` (transient dropper artifact)
- `*/node_modules/plain-crypto-js/setup.js`

**macOS:**
- `/Library/Caches/com.apple.act.mond` (C++ RAT binary, executed via `/bin/zsh`)
- `/tmp/*.scpt` (AppleScript transient payload)

**Windows:**
- `%PROGRAMDATA%\wt.exe` (renamed copy of PowerShell)
- `%PROGRAMDATA%\system.bat` (persistence batch file)
- `%TEMP%\6202033.vbs` (VBScript launcher)
- `%TEMP%\6202033.ps1` (PowerShell RAT)
- Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdate` → points to `system.bat`

**Linux:**
- `/tmp/ld.py` (Python RAT, executed via `nohup` in background)
- No persistence mechanism

### RAT Capabilities

- **C2 message types (outbound):** FirstInfo, BaseInfo, CmdResult
- **C2 commands (inbound):** kill, peinject, runscript, rundir
- **Response types:** rsp_kill, rsp_peinject, rsp_runscript, rsp_rundir
- **Windows-specific:** In-memory DLL injection (`peinject`), arbitrary command execution, directory enumeration
- **macOS-specific:** C++ binary, system fingerprinting, 60s beacon
- **Linux-specific:** Python script, shell command execution

### Execution Mechanisms

- **Windows:** PowerShell with `-NoProfile -ep Bypass`
- **macOS:** AppleScript via `/usr/bin/osascript`
- **Linux:** `subprocess.run(shell=True)` or `python3 -c`

### Detection Signatures

**Most reliable cross-platform indicator:** The spoofed IE8/Windows XP User-Agent string (`mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)`) is an immediate anomaly on macOS and Linux hosts.

---

## Rust Scanner Plan

### Goal

A single cross-platform Rust binary (`axios-rat-scan`) that rapidly scans all mounted drives/volumes for evidence of this specific RAT infection and reports findings. Must compile for Windows, macOS, and Linux from one codebase.

### Architecture

```
axios-rat-scan/
├── Cargo.toml
└── src/
    ├── main.rs          # CLI entry, drive enumeration, report output
    ├── iocs.rs          # All IOC constants (hashes, paths, patterns, domains)
    ├── scanner/
    │   ├── mod.rs
    │   ├── filesystem.rs  # File existence + SHA-256 hash checks
    │   ├── npm.rs         # package.json / lockfile / node_modules scanning
    │   ├── registry.rs    # Windows registry checks (cfg(windows))
    │   ├── process.rs     # Running process inspection
    │   └── network.rs     # Active connection / DNS cache checks
    └── report.rs        # Finding collection, severity, text/JSON output
```

### Scan Modules

#### 1. `filesystem` — RAT artifact detection
- Check platform-specific dropped files (see artifacts above)
- For each file found: compute SHA-256 and compare against known hashes
- Scan `$TMPDIR` for `6202033` artifacts
- Scan for `*.scpt` in `/tmp` (macOS)
- Use `walkdir` crate for fast parallel directory traversal
- Skip irrelevant directories (`.git`, Windows system dirs like `Windows/WinSxS`)

#### 2. `npm` — Supply chain compromise in projects
- Walk all drives looking for `package.json`, `package-lock.json`, `yarn.lock`
- Parse JSON with `serde_json` — check for:
  - `axios` at versions `1.14.1` or `0.30.4`
  - `plain-crypto-js` in any dependency block
  - `@shadanai/openclaw`, `@qqbrowser/openclaw-qbot`
  - `postinstall`/`preinstall` hooks referencing `setup.js`
- Check `node_modules/plain-crypto-js/` existence
- Check `node_modules/axios/package.json` for injected `plain-crypto-js` dep
- Hash `node_modules/plain-crypto-js/setup.js` if present, compare to known SHA-256

#### 3. `registry` — Windows persistence (compile-gated `#[cfg(windows)]`)
- Read `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- Flag any value containing `system.bat`, `wt.exe`, or `MicrosoftUpdate`
- Use `winreg` crate

#### 4. `process` — Live infection detection
- Enumerate running processes via `sysinfo` crate
- Flag:
  - `wt.exe` running from `%PROGRAMDATA%` (Windows)
  - `com.apple.act.mond` process (macOS)
  - `python` with `/tmp/ld.py` in args (Linux)
  - Any process with the spoofed User-Agent in command line
- Check for `nohup` processes spawned by node

#### 5. `network` — Active C2 connections
- Parse active TCP connections (platform-native: netstat-equivalent)
- Flag connections to `142.11.206.73` or `sfrclak.com` on port 8000
- Use `sysinfo` or parse `/proc/net/tcp` (Linux), `netstat` output

### Drive/Volume Enumeration

- **Windows:** `GetLogicalDriveStringsW` API → iterate A:-Z:
- **macOS:** Scan `/Volumes/*` + `/Users`
- **Linux:** Parse `/proc/mounts` or `/etc/mtab`, skip pseudo-filesystems (proc, sysfs, tmpfs, devtmpfs)

### Performance Strategy

- Use `rayon` for parallel directory walking
- Use `ignore` crate (from ripgrep) for fast gitignore-aware traversal
- Skip known-irrelevant large directories: `.git`, `Windows/`, `System Volume Information`
- SHA-256 only computed on files that match expected paths/names (not blanket hashing)
- Early-exit option: `--fast` flag stops after first CRITICAL finding

### Dependencies (Cargo.toml)

```toml
[dependencies]
sha2 = "0.10"          # SHA-256 hashing
serde = { version = "1", features = ["derive"] }
serde_json = "1"       # package.json parsing
walkdir = "2"          # recursive directory traversal
rayon = "1"            # parallelism
clap = { version = "4", features = ["derive"] }  # CLI args
sysinfo = "0.33"       # process + system info
colored = "2"          # terminal colors
chrono = "0.4"         # timestamps for report

[target.'cfg(windows)'.dependencies]
winreg = "0.55"        # Windows registry
windows-sys = { version = "0.59", features = ["Win32_Storage_FileSystem"] }
```

### CLI Interface

```
axios-rat-scan [OPTIONS] [PATHS...]

Options:
  --all-drives     Scan all mounted drives/volumes (default if no paths given)
  --json           Output as JSON
  --fast           Stop after first CRITICAL finding
  --no-process     Skip process/network checks (filesystem only)
  --no-color       Disable colored output
  -v, --verbose    Show all directories being scanned
```

### Output Format

```
[CRITICAL] rat-artifact: RAT payload file exists — /Library/Caches/com.apple.act.mond
           SHA-256: 92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a (MATCH)

[CRITICAL] compromised-axios: axios@1.14.1 in lockfile
           -> /Users/dev/myapp/package-lock.json

[WARNING]  suspect-process: wt.exe running from C:\ProgramData\
           PID: 4812

============================================================
Scan complete in 3.2s — 2 critical, 1 warning, 0 info
Scanned: 3 drives, 847 package.json files, 12,403 directories

!! CRITICAL: Evidence of axios RAT compromise detected.
   1. Isolate this machine from the network immediately
   2. Preserve forensic artifacts before remediation
   3. Rotate ALL credentials accessed from this machine
   4. See: https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all
```

### Build & Distribution

```bash
# Native build
cargo build --release

# Cross-compile (via cross or cargo-zigbuild)
cargo zigbuild --release --target x86_64-pc-windows-msvc
cargo zigbuild --release --target x86_64-apple-darwin
cargo zigbuild --release --target aarch64-apple-darwin
cargo zigbuild --release --target x86_64-unknown-linux-musl
```

Single static binary per platform — no runtime dependencies.

### Implementation Order

1. `iocs.rs` — hardcode all constants from this document
2. `report.rs` — Finding struct, severity levels, text/JSON formatters
3. `scanner/filesystem.rs` — file existence + hash checks (immediate value)
4. `scanner/npm.rs` — package.json/lockfile/node_modules scanning
5. `scanner/registry.rs` — Windows registry (cfg-gated)
6. `scanner/process.rs` — running process checks
7. `scanner/network.rs` — active connection checks
8. `main.rs` — CLI, drive enumeration, orchestrate scanners, report
