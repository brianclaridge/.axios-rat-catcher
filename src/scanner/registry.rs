use crate::report::Finding;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
use winreg::RegKey;

/// Registry Run key paths to check.
const RUN_KEYS: &[(&str, &str)] = &[
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
];

/// Suspicious value substrings in registry Run key.
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
///
/// Checks both HKCU (user) and HKLM (machine-wide) Run/RunOnce keys.
pub fn scan(findings: &mut Vec<Finding>) {
    for (hive_name, subkey) in RUN_KEYS {
        let hive = match *hive_name {
            "HKCU" => RegKey::predef(HKEY_CURRENT_USER),
            "HKLM" => RegKey::predef(HKEY_LOCAL_MACHINE),
            _ => continue,
        };

        let run_key = match hive.open_subkey_with_flags(subkey, winreg::enums::KEY_READ) {
            Ok(k) => k,
            Err(_) => continue, // Graceful: HKLM may fail without admin
        };

        let key_path = format!("{hive_name}\\{subkey}");

        for value in run_key.enum_values().flatten() {
            let (name, data) = (value.0, format!("{:?}", value.1));
            let data_lower = data.to_lowercase();
            let name_lower = name.to_lowercase();

            // Check the exact key name used by this RAT
            if name_lower == "microsoftupdate" {
                findings.push(Finding::critical(
                    "registry-persistence",
                    &format!("{key_path}\\{name}"),
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
                        &format!("{key_path}\\{name}"),
                        &format!("Registry Run key references '{suspect}': {data}"),
                    ));
                    break;
                }
            }

            // Elastic: "Startup Persistence via Windows Script Interpreter"
            if data_lower.contains(".vbs") || data_lower.contains(".bat") || data_lower.contains(".ps1") {
                let suspicious_paths = ["\\temp\\", "\\tmp\\", "\\programdata\\", "\\appdata\\local\\temp\\"];
                if suspicious_paths.iter().any(|p| data_lower.contains(p)) {
                    findings.push(Finding::warning(
                        "registry-suspect-script",
                        &format!("{key_path}\\{name}"),
                        &format!("Script interpreter persistence from suspicious path: {data}"),
                    ));
                }
            }
        }
    }
}
