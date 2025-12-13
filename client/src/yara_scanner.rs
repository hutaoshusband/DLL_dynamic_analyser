// Copyright (c) 2024 HUTAOSHUSBAND - Wallbangbros.com/FireflyProtector.xyz

use crate::scanner::enumerate_modules;
use crate::{log_event, ReentrancyGuard};
use once_cell::sync::Lazy;
use serde_json::{json, Map, Value};
use shared::logging::{LogEvent, LogLevel};
use std::collections::HashSet;
#[cfg(feature = "use_yara")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "use_yara")]
use yara_x::{Compiler, Rules, Scanner};

#[cfg(feature = "use_yara")]
pub struct YaraScanner {
    rules: Option<Arc<Rules>>,
}

#[cfg(feature = "use_yara")]
const EMBEDDED_RULES: &str = include_str!(concat!(env!("OUT_DIR"), "/all_rules.yar"));
#[cfg(feature = "use_yara")]
const MAX_MODULE_SIZE: usize = 200 * 1024 * 1024;

#[cfg(feature = "use_yara")]
fn should_scan_module(normalized_path: &str) -> bool {
    if normalized_path.is_empty() {
        return false;
    }
    if normalized_path.contains("\\windows\\system32")
        || normalized_path.contains("\\windows\\syswow64")
        || normalized_path.contains("\\windows\\winsxs")
    {
        return false;
    }
    if normalized_path.contains("dll_dynamic_analyser") {
        return false;
    }
    true
}

#[cfg(feature = "use_yara")]
impl YaraScanner {
    pub fn new() -> Self {
        let mut instance = Self { rules: None };
        if let Err(e) = instance.compile_rules(EMBEDDED_RULES) {
            log_event(
                LogLevel::Error,
                LogEvent::Error {
                    source: "YaraScanner".to_string(),
                    message: format!("Failed to compile embedded YARA rules: {}", e),
                },
            );
        }
        instance
    }

    pub fn compile_rules(&mut self, rules_str: &str) -> Result<(), String> {
        let mut compiler = Compiler::new();
        if let Err(e) = compiler.add_source(rules_str) {
            return Err(e.to_string());
        }
        let rules = compiler.build();
        self.rules = Some(Arc::new(rules));

        log_event(
            LogLevel::Info,
            LogEvent::Message("YARA rules compiled successfully.".to_string()),
        );
        Ok(())
    }

    pub fn scan_memory(&self) {
        let rules = match &self.rules {
            Some(r) => r,
            None => return,
        };

        log_event(
            LogLevel::Info,
            LogEvent::Message("Starting YARA memory scan...".to_string()),
        );

        let mut scanner = Scanner::new(rules);
        let modules = unsafe { enumerate_modules() };
        let mut scanned_bases = HashSet::new();

        for (module_path, module_data) in modules {
            let normalized_path = module_path.to_ascii_lowercase();
            if !should_scan_module(&normalized_path) {
                continue;
            }

            let module_size = module_data.len();
            if module_size == 0 || module_size > MAX_MODULE_SIZE {
                continue;
            }

            let module_base = module_data.as_ptr() as usize;
            if !scanned_bases.insert(module_base) {
                continue;
            }

            if let Some(_guard) = ReentrancyGuard::new() {
                match scanner.scan(module_data) {
                    Ok(results) => {
                        for match_rule in results.matching_rules() {
                            let rule_name = match_rule.identifier();
                            let mut meta_map: Map<String, Value> = match_rule
                                .metadata()
                                .map(|(key, value)| {
                                    let val_str = match value {
                                        yara_x::MetaValue::Integer(i) => i.to_string(),
                                        yara_x::MetaValue::Float(f) => f.to_string(),
                                        yara_x::MetaValue::Bool(b) => b.to_string(),
                                        yara_x::MetaValue::String(s) => s.to_string(),
                                        yara_x::MetaValue::Bytes(b) => format!("{:?}", b),
                                    };
                                    (key.to_string(), json!(val_str))
                                })
                                .collect();
                            meta_map.insert("module_path".to_string(), json!(module_path.clone()));
                            meta_map.insert("module_base".to_string(), json!(module_base));
                            meta_map.insert("module_size".to_string(), json!(module_size));
                            let metadata_value = Value::Object(meta_map);

                            log_event(
                                LogLevel::Warn,
                                LogEvent::YaraMatch {
                                    rule_name: rule_name.to_string(),
                                    address: module_base,
                                    region_size: module_size,
                                    metadata: metadata_value.to_string(),
                                },
                            );
                        }
                    }
                    Err(e) => {
                        log_event(
                            LogLevel::Debug,
                            LogEvent::Error {
                                source: "YaraScanner".to_string(),
                                message: format!(
                                    "Scan failed for module {} (base {:#x}, size {:#x}): {}",
                                    module_path, module_base, module_size, e
                                ),
                            },
                        );
                    }
                }
            }
        }

        log_event(
            LogLevel::Info,
            LogEvent::Message("YARA memory scan completed.".to_string()),
        );
    }
}

#[cfg(feature = "use_yara")]
pub static SCANNER: Lazy<Mutex<YaraScanner>> = Lazy::new(|| Mutex::new(YaraScanner::new()));
