use crate::report::Finding;
use winreg::enums::HKEY_CURRENT_USER;
use winreg::RegKey;

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

/// Suspicious value substrings in registry Run key.
/// Elastic: "Suspicious String Value Written to Registry Run Key"
/// Elastic: "Startup Persistence via Windows Script Interpreter"
const SUSPECT_VALUES: &[&str] = &[
    "system.bat",
    "wt.exe",
    "microsoftupdate",
    "6202033",
    "programdata\\wt",
];

/// Check the Windows registry for persistence mechanisms planted by the RAT.
///
/// Covers Elastic detection rules:
/// - Suspicious String Value Written to Registry Run Key
/// - Startup Persistence via Windows Script Interpreter
pub fn scan(findings: &mut Vec<Finding>) {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let run_key = match hkcu.open_subkey_with_flags(RUN_KEY, winreg::enums::KEY_READ) {
        Ok(k) => k,
        Err(_) => return,
    };

    for value in run_key.enum_values().flatten() {
        let (name, data) = (value.0, format!("{:?}", value.1));
        let data_lower = data.to_lowercase();
        let name_lower = name.to_lowercase();

        // Check the exact key name used by this RAT
        if name_lower == "microsoftupdate" {
            findings.push(Finding::critical(
                "registry-persistence",
                &format!("HKCU\\{RUN_KEY}\\{name}"),
                &format!(
                    "Registry Run key 'MicrosoftUpdate' — exact persistence key used by axios RAT: {data}"
                ),
            ));
            continue;
        }

        // Check value data for suspicious substrings
        for suspect in SUSPECT_VALUES {
            if data_lower.contains(suspect) {
                findings.push(Finding::critical(
                    "registry-persistence",
                    &format!("HKCU\\{RUN_KEY}\\{name}"),
                    &format!("Registry Run key references '{suspect}': {data}"),
                ));
                break;
            }
        }

        // Elastic: "Startup Persistence via Windows Script Interpreter"
        // Flag .vbs, .bat, .ps1 scripts in Run key pointing to temp/programdata
        if data_lower.contains(".vbs") || data_lower.contains(".bat") || data_lower.contains(".ps1") {
            let suspicious_paths = ["\\temp\\", "\\tmp\\", "\\programdata\\", "\\appdata\\local\\temp\\"];
            if suspicious_paths.iter().any(|p| data_lower.contains(p)) {
                findings.push(Finding::warning(
                    "registry-suspect-script",
                    &format!("HKCU\\{RUN_KEY}\\{name}"),
                    &format!("Script interpreter persistence from suspicious path: {data}"),
                ));
            }
        }
    }
}
