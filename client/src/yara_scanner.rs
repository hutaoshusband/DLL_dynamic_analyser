// Copyright (c) 2024 HUTAOSHUSBAND - Wallbangbros.com/CodeConfuser.dev
// All rights reserved.

#[cfg(feature = "use_yara")]
use yara_x::{Compiler, Rules, Scanner};
#[cfg(feature = "use_yara")]
use std::sync::{Arc, Mutex};
use once_cell::sync::Lazy;
use windows_sys::Win32::System::Memory::{
    VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_NOACCESS, PAGE_GUARD,
};
use std::ffi::c_void;
use crate::{log_event, ReentrancyGuard};
use shared::logging::{LogLevel, LogEvent};
use serde_json::json;

#[cfg(feature = "use_yara")]
pub struct YaraScanner {
    rules: Option<Arc<Rules>>,
}

#[cfg(feature = "use_yara")]
const EMBEDDED_RULES: &str = include_str!(concat!(env!("OUT_DIR"), "/all_rules.yar"));

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

        let mut address: usize = 0;
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let sys_info_max = 0x7FFFFFFF0000; // rough user-mode limit for x64

        // Create a Scanner
        let mut scanner = Scanner::new(rules);

        while address < sys_info_max {
            let result = unsafe {
                VirtualQuery(
                    address as *const c_void,
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };

            if result == 0 {
                break;
            }

            // Skip uncommitted, no-access, or guard pages
            let is_accessible = (mbi.State & MEM_COMMIT != 0)
                && (mbi.Protect & PAGE_NOACCESS == 0)
                && (mbi.Protect & PAGE_GUARD == 0);

            if is_accessible {
                let size = mbi.RegionSize;
                let ptr = mbi.BaseAddress as *const u8;
                
                // 100MB limit per region
                if size > 0 && size < 100 * 1024 * 1024 {
                    // Use ReentrancyGuard while scanning to prevent potential recursion if YARA scan triggers hooks
                    // (e.g. if it causes memory allocation or file access internally that is hooked)
                    if let Some(_guard) = ReentrancyGuard::new() {
                        // Safety: we checked that the memory is committed and accessible.
                        // However, memory state can change in a multi-threaded process.
                        // Accessing memory in a running process is inherently risky (race conditions).
                        // std::slice::from_raw_parts is unsafe, but we are doing our best with VirtualQuery.
                        let data = unsafe { std::slice::from_raw_parts(ptr, size) };
                        
                        // yara-x scan api
                        // We wrap the scan in a catch_unwind-like block if possible, but yara-x is pure Rust.
                        // If yara-x panics, it will bring down the thread (or process).
                        // We rely on yara-x robustness.
                        match scanner.scan(data) {
                            Ok(results) => {
                                for match_rule in results.matching_rules() {
                                    let rule_name = match_rule.identifier();
                                    let meta: serde_json::Value = match_rule.metadata().map(|(key, value)| {
                                        // yara-x metadata value handling
                                        let val_str = match value {
                                            yara_x::MetaValue::Integer(i) => i.to_string(),
                                            yara_x::MetaValue::Float(f) => f.to_string(),
                                            yara_x::MetaValue::Bool(b) => b.to_string(),
                                            yara_x::MetaValue::String(s) => s.to_string(),
                                            yara_x::MetaValue::Bytes(b) => format!("{:?}", b),
                                        };
                                        (key.to_string(), json!(val_str))
                                    }).collect();

                                    // Use the dedicated YaraMatch event for better UI display
                                    log_event(
                                        LogLevel::Warn,
                                        LogEvent::YaraMatch {
                                            rule_name: rule_name.to_string(),
                                            address,
                                            region_size: size,
                                            metadata: meta.to_string(),
                                        },
                                    );
                                }
                            },
                            Err(e) => {
                                // Log scan errors
                                log_event(
                                    LogLevel::Debug,
                                    LogEvent::Error {
                                        source: "YaraScanner".to_string(),
                                        message: format!("Scan failed for region {:#x} (size {:#x}): {}", address, size, e),
                                    },
                                );
                            }
                        }
                    }
                }
            }

            address += mbi.RegionSize;
        }
        
        log_event(
            LogLevel::Info,
            LogEvent::Message("YARA memory scan completed.".to_string()),
        );
    }
}

// Global instance
#[cfg(feature = "use_yara")]
pub static SCANNER: Lazy<Mutex<YaraScanner>> = Lazy::new(|| Mutex::new(YaraScanner::new()));
