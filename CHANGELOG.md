# Changelog

## v0.5.0

### New detection capabilities
- **npm cache scanning** (~/.npm/_cacache) for retained malicious packages
- **Anti-forensics detection**: cleaned compromise (deleted setup.js + removed postinstall)
- **Anti-forensics detection**: orphan package.md dropper artifact
- **Hidden /tmp executable scan** for Linux peinject payloads
- **Compromised maintainer email check** (ifstap@proton.me)
- **Suspicious PowerShell Base64 Decoding** (Windows, Elastic rule)
- **Potential File Transfer via Curl for Windows** (Elastic rule)

### Bug fixes
- Fix self-detection: process scanner now excludes own PID + descendant tree
- Fix Linux resolvectl leaking C2 domains in process args (show-cache + journalctl fallback)
- Replace hardcoded IOC strings with iocs.rs constants throughout
- cfg-gate platform-specific hash arrays to eliminate dead_code warnings

### Elastic rule refinements
- Curl/Wget via Node.js now requires HTTP URL in cmdline per Elastic spec
- Process Backgrounding broadened from node/bun to 9 unusual parent runtimes
- osascript check references C2_DOMAIN constant instead of hardcoded string

### Tests
- 26 assertions (up from 22), new test artifacts for all new capabilities

---

## v0.4.0

### Security hardening
- External commands (`netstat`, `ss`, `ipconfig`, `resolvectl`) now use absolute paths to prevent PATH hijacking by the RAT
- JSON parsing has 10MB size limit to prevent OOM on malicious `package.json` files
- Windows: registry checks now scan HKLM (machine-wide) in addition to HKCU, with graceful fallback if not elevated

### New detection vectors
- **pnpm-lock.yaml** scanning for compromised axios versions, malicious packages, and integrity hashes
- **Lockfile integrity checking** — `package-lock.json` `"integrity"` and `"resolved"` fields compared against known compromised shasums
- **npm package shasums** added to IOCs (axios@1.14.1, axios@0.30.4, plain-crypto-js@4.2.1)
- **Linux DNS bug fixed** — systemd-resolved cache now queries all C2 domains (was only checking primary)

### Output improvements
- JSON output now wrapped with scan metadata: `version`, `scan_duration_ms`, `dirs_scanned`, `packages_scanned`
- `--report <path>` flag for custom REPORT.txt location

### CLI
- `-j / --threads` flag to control rayon thread pool size
- `--demo-delay <secs>` flag for recording demos
- `--report <path>` flag

---

## v0.3.0

### Elastic detection intelligence
- Process parent-child chain analysis (Elastic: Curl/Wget Spawned via Node.js)
- Backgrounded process detection (Elastic: Process Backgrounded by Unusual Parent)
- Renamed binary proxy detection (Elastic: Execution via Renamed Signed Binary Proxy)
- macOS `osascript` dropper detection
- C2 domain grep in all process command lines
- `packages.npm.org` typosquat domain added to all IOC checks
- DNS cache inspection (Windows `ipconfig /displaydns`, macOS mdnsresponder, Linux systemd-resolved)
- Hosts file tampering detection
- Windows registry: exact `MicrosoftUpdate` key match, script-in-temp persistence

### Docker integration tests
- Multi-stage build compiles Linux binary + plants IOCs in container
- ~100 realistic npm projects across 5 orgs with 4 infected
- 22 test assertions, 33 critical findings, zero false positives
- VHS terminal GIF recording

---

## v0.2.0

- README with download links and usage
- Live progress UI with `indicatif` spinners and progress bars
- Discovery tree prints before scanning begins
- Split discover/scan flow for real-time feedback

---

## v0.1.0

- Initial release
- Cross-platform scanner (Windows, macOS, Linux)
- Host artifact detection with SHA-256 hash verification
- Process inspection for running RAT
- Network connection checks for C2
- npm package.json, lockfile, yarn.lock, node_modules scanning
- Auto-detect all mounted drives
- JSON and text output modes
- GitHub Actions release workflow for 4 targets
