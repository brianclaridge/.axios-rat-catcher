# axios-rat-scan

Cross-platform scanner for the [axios supply chain RAT](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all) (2026-03-31). Single static binary, no dependencies.

Compromised versions `axios@1.14.1` and `axios@0.30.4` inject `plain-crypto-js@4.2.1`, which drops a cross-platform RAT attributed to DPRK/UNC1069.

## Download

**[Latest release](https://github.com/brianclaridge/.axios-rat-helper/releases/latest)**

| Platform | Binary |
|---|---|
| Windows x64 | `axios-rat-scan-x86_64-pc-windows-msvc.zip` |
| macOS Intel | `axios-rat-scan-x86_64-apple-darwin.tar.gz` |
| macOS Apple Silicon | `axios-rat-scan-aarch64-apple-darwin.tar.gz` |
| Linux x64 (static) | `axios-rat-scan-x86_64-unknown-linux-musl.tar.gz` |

## Usage

```bash
# Scan all mounted drives (auto-detected)
axios-rat-scan

# Scan specific paths
axios-rat-scan /path/to/projects

# JSON output for pipelines
axios-rat-scan --json

# Stop at first critical finding
axios-rat-scan --fast

# Filesystem only (skip process/network checks)
axios-rat-scan --no-process

# Hide the project tree
axios-rat-scan --no-tree
```

## What it checks

| Phase | What |
|---|---|
| **Host artifacts** | RAT files (`wt.exe`, `system.bat`, `com.apple.act.mond`, `/tmp/ld.py`), temp dropper files, SHA-256 hash verification |
| **Registry** | `HKCU\...\Run\MicrosoftUpdate` persistence key (Windows) |
| **Processes** | Running RAT processes, spoofed IE8 User-Agent in command lines |
| **Network** | Active connections to C2 `142.11.206.73:8000` / `sfrclak.com` |
| **npm packages** | `package.json`, lockfiles, `yarn.lock` for compromised axios versions, `plain-crypto-js`, secondary vectors |
| **node_modules** | Installed malicious packages, injected deps in axios, `setup.js` dropper |

## Build from source

```bash
cargo build --release
```

## Exit codes

- `0` — clean
- `1` — critical findings detected

## References

- [Elastic: Axios, One RAT to Rule Them All](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)
- [Elastic: Detection Rules](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections)
- [REMEDIATION.md](REMEDIATION.md) — incident response playbook
- [ATTACK_FLOW.md](ATTACK_FLOW.md) — kill chain diagrams
- [DESIGN.md](DESIGN.md) — scanner architecture
