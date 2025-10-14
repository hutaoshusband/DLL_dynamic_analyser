use crate::config::LogLevel;
use crate::logging::LogEvent;
use crate::{log_event, SUSPICION_SCORE};
use pelite::pe64::{Pe, PeFile};
use std::collections::HashMap;
use std::sync::atomic::Ordering;

/// Calculates the Shannon entropy of a byte slice.
/// A value between 0 and 8, where 8 indicates high randomness (likely packed/encrypted).
fn shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = HashMap::new();
    for &byte in data {
        *counts.entry(byte).or_insert(0) += 1;
    }
    let len = data.len() as f32;
    counts
        .values()
        .map(|&count| {
            let p = count as f32 / len;
            -p * p.log2()
        })
        .sum()
}

/// Analyzes the sections of a PE file for suspicious characteristics.
fn analyze_sections(pe: PeFile) {
    for section in pe.section_headers() {
        let name = section.name().unwrap_or("<invalid>");
        let characteristics = section.Characteristics;
        let data = pe.get_section_bytes(section).unwrap_or(&[]);
        let entropy = shannon_entropy(data);

        // Check for suspicious section names
        let suspicious_names = [".vmp", ".upx", ".themida", ".aspack"];
        if suspicious_names.iter().any(|s| name.starts_with(s)) {
            SUSPICION_SCORE.fetch_add(1, Ordering::Relaxed);
            log_event(
                LogLevel::Warn,
                LogEvent::StaticAnalysis {
                    finding: "Suspicious Section Name".to_string(),
                    details: format!("Section '{}' has a name commonly used by packers.", name),
                },
            );
        }

        // Check for writable and executable sections
        let is_writable = (characteristics & pelite::image::IMAGE_SCN_MEM_WRITE) != 0;
        let is_executable = (characteristics & pelite::image::IMAGE_SCN_MEM_EXECUTE) != 0;
        if is_writable && is_executable {
            SUSPICION_SCORE.fetch_add(5, Ordering::Relaxed);
            log_event(
                LogLevel::Warn,
                LogEvent::StaticAnalysis {
                    finding: "Writable and Executable Section".to_string(),
                    details: format!(
                        "Section '{}' is both writable and executable, a common trait of packed or malicious code.",
                        name
                    ),
                },
            );
        }

        // Check for high entropy
        if entropy > 7.5 {
            SUSPICION_SCORE.fetch_add(5, Ordering::Relaxed);
            log_event(
                LogLevel::Warn,
                LogEvent::StaticAnalysis {
                    finding: "High Entropy Section".to_string(),
                    details: format!(
                        "Section '{}' has a high entropy ({:.2}), suggesting it may be compressed or encrypted.",
                        name, entropy
                    ),
                },
            );
        }
    }
}

/// Analyzes the Import Address Table (IAT) of a PE file.
fn analyze_iat(pe: PeFile) {
    if let Ok(imports) = pe.imports() {
        let mut import_count = 0;
        let mut has_loader_funcs = false;
        for import_desc in imports {
            let _dll_name = import_desc.dll_name().map(|s| s.to_str().unwrap_or("<unknown>")).unwrap_or("<unknown>");
            if let Ok(int) = import_desc.int() {
                for symbol in int {
                    import_count += 1;
                    if let Ok(import) = symbol {
                        if let pelite::pe64::imports::Import::ByName { name, .. } = import {
                            if let Ok(name_str) = name.to_str() {
                                if name_str == "LoadLibraryA" || name_str == "GetProcAddress" || name_str == "VirtualAlloc" {
                                    has_loader_funcs = true;
                                }
                            }
                        }
                    }
                }
            }
        }

        if import_count < 10 {
            SUSPICION_SCORE.fetch_add(2, Ordering::Relaxed);
            log_event(
                LogLevel::Warn,
                LogEvent::StaticAnalysis {
                    finding: "Small Import Table".to_string(),
                    details: format!(
                        "The module has a very small number of imports ({}). This can indicate dynamic API resolution.",
                        import_count
                    ),
                },
            );
        }

        if has_loader_funcs {
            log_event(
                LogLevel::Info,
                LogEvent::StaticAnalysis {
                    finding: "Loader Functions Found".to_string(),
                    details: "The module imports functions commonly used for manual API resolving (LoadLibrary, GetProcAddress, VirtualAlloc).".to_string(),
                },
            );
        }
    }
}

/// Analyzes the entry point of a PE file for common packer signatures.
fn analyze_entry_point(pe: PeFile) {
    let entry_point_rva = pe.optional_header().AddressOfEntryPoint;
    let entry_point_bytes = pe.derva_slice(entry_point_rva, 64).unwrap_or(&[]);
    if entry_point_bytes.is_empty() {
        return;
    }

    // Example: Look for `pushad` (0x60), a common packer stub instruction.
    if entry_point_bytes.starts_with(&[0x60]) {
        SUSPICION_SCORE.fetch_add(3, Ordering::Relaxed);
        log_event(
            LogLevel::Warn,
            LogEvent::StaticAnalysis {
                finding: "Packer Signature Found".to_string(),
                details: "The entry point starts with a PUSHAD instruction, which is a common packer signature.".to_string(),
            },
        );
    }
}

/// The main analysis function for a loaded module.
/// It takes a byte slice of the module and performs various static analyses.
pub fn analyze_module(module_data: &[u8]) {
    log_event(LogLevel::Info, LogEvent::StaticAnalysis {
        finding: "Static Analysis Started".to_string(),
        details: "Performing static analysis on a newly loaded module.".to_string(),
    });

    match PeFile::from_bytes(module_data) {
        Ok(pe) => {
            analyze_entry_point(pe);
            analyze_sections(pe);
            analyze_iat(pe);
        }
        Err(e) => {
            log_event(
                LogLevel::Error,
                LogEvent::Error {
                    source: "StaticAnalysis".to_string(),
                    message: format!("Failed to parse PE file: {}", e),
                },
            );
        }
    }
}