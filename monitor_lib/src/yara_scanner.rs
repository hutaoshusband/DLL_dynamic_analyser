use crate::config::LogLevel;
use crate::log_event;
use crate::logging::LogEvent;
use once_cell::sync::Lazy;
use serde_json::json;
use std::path::PathBuf;
use yara::{Compiler, Rules};

// Lazily compile the Yara rules. This ensures that the rules are compiled
// only once when they are first needed. The rules are embedded directly into
// the binary at compile time for portability.
static YARA_RULES: Lazy<Result<Rules, yara::Error>> = Lazy::new(|| {
    let rules_str = include_str!("../rules/vmp.yara");
    Compiler::new()?
        .add_rules_str(rules_str)
        .map_err(|e| {
            // Log the error during initialization. This is critical for debugging
            // if the Yara rules have a syntax error.
            log_event(
                LogLevel::Error,
                LogEvent::Error {
                    source: "YaraInitialization".to_string(),
                    message: format!("Failed to compile Yara rules: {}", e),
                },
            );
            e.into()
        })
});

/// Scans a given memory region with the pre-compiled Yara rules.
///
/// # Arguments
///
/// * `module_path` - The path of the module being scanned, for logging purposes.
/// * `memory_region` - A byte slice of the memory to be scanned.
///
pub fn scan_memory(module_path: &str, memory_region: &[u8]) {
    // Check if the rules were compiled successfully.
    let rules = match &*YARA_RULES {
        Ok(r) => r,
        Err(_) => {
            // The error was already logged during initialization, so we just exit.
            return;
        }
    };

    // Perform the scan.
    match rules.scan(memory_region, 10) {
        Ok(matches) => {
            if !matches.is_empty() {
                for m in matches {
                    // For each match, log a detailed event.
                    log_event(
                        LogLevel::Warn,
                        LogEvent::YaraMatch {
                            module_path: module_path.to_string(),
                            rule_name: m.identifier.to_string(),
                            scan_details: json!({
                                "tags": m.tags,
                                // You can add more details from the match if needed.
                            }),
                        },
                    );
                }
            }
        }
        Err(e) => {
            // Log any errors that occur during the scan itself.
            log_event(
                LogLevel::Error,
                LogEvent::Error {
                    source: "YaraScan".to_string(),
                    message: format!("Error scanning module {}: {}", module_path, e),
                },
            );
        }
    }
}