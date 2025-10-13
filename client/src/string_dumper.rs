// This module is responsible for periodically scanning the process's memory
// for strings, which can reveal interesting information about a program's
// behavior, such as hidden commands, URLs, or configuration data.
// It will run in a background thread.
use shared::logging::{LogLevel, LogEvent};
use crate::{log_event, ReentrancyGuard};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use windows_sys::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

const MIN_STRING_LEN: usize = 8; // Minimum length for a sequence of bytes to be considered a string.

/// Scans a memory region for ASCII and UTF-16 strings.
fn scan_region_for_strings(
    region: &[u8],
    base_address: usize,
    found_strings: &mut HashSet<String>,
) {
    // ASCII scan
    for window in region.windows(MIN_STRING_LEN) {
        if window.iter().all(|&c| c.is_ascii_graphic() || c == b' ') {
            if let Ok(s) = std::str::from_utf8(window) {
                let owned_s = s.trim_end().to_string();
                if owned_s.len() >= MIN_STRING_LEN && found_strings.insert(owned_s.clone()) {
                    log_event(
                        LogLevel::Debug,
                        LogEvent::StringDump {
                            address: base_address,
                            value: owned_s,
                            encoding: "ASCII".to_string(),
                        },
                    );
                }
            }
        }
    }

    // UTF-16 scan
    if region.len() >= MIN_STRING_LEN * 2 {
        let u16_region: &[u16] = unsafe {
            core::slice::from_raw_parts(region.as_ptr() as *const u16, region.len() / 2)
        };
        for window in u16_region.windows(MIN_STRING_LEN) {
            if window.iter().all(|&c| {
                let ch = std::char::from_u32(c as u32).unwrap_or('\0');
                ch.is_ascii_graphic() || ch == ' '
            }) {
                if let Ok(s) = String::from_utf16(window) {
                    let owned_s = s.trim_end().to_string();
                    if owned_s.len() >= MIN_STRING_LEN && found_strings.insert(owned_s.clone()) {
                        log_event(
                            LogLevel::Debug,
                            LogEvent::StringDump {
                                address: base_address,
                                value: owned_s,
                                encoding: "UTF-16".to_string(),
                            },
                        );
                    }
                }
            }
        }
    }
}

/// The main loop for the string dumper thread.
/// Iterates through all committed memory regions and scans them.
fn string_dumper_main(found_strings: Arc<Mutex<HashSet<String>>>) {
    let process_handle = unsafe { GetCurrentProcess() };
    let mut current_address: usize = 0;

    loop {
        let mut mem_info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let result = unsafe {
            VirtualQueryEx(
                process_handle,
                current_address as *const _,
                &mut mem_info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if result == 0 {
            break; // End of memory regions
        }

        if mem_info.State == MEM_COMMIT {
            let region_data = unsafe {
                std::slice::from_raw_parts(
                    mem_info.BaseAddress as *const u8,
                    mem_info.RegionSize,
                )
            };
            if let Some(_guard) = ReentrancyGuard::new() {
                 if let Ok(mut found) = found_strings.lock() {
                    scan_region_for_strings(region_data, mem_info.BaseAddress as usize, &mut found);
                }
            }
        }

        current_address = mem_info.BaseAddress as usize + mem_info.RegionSize;
    }
}



/// Spawns the string dumper thread.
pub fn start_string_dumper() {
    log_event(LogLevel::Info, LogEvent::MemoryScan {
        status: "Starting background string dumper...".to_string(),
        result: "".to_string(),
    });

    let found_strings = Arc::new(Mutex::new(HashSet::new()));

    thread::spawn(move || {
        loop {
            let found_strings_clone = Arc::clone(&found_strings);
            string_dumper_main(found_strings_clone);
            // Adjust the sleep duration based on how frequently you want to scan.
            // A full memory scan can be intensive.
            thread::sleep(Duration::from_secs(300)); // e.g., every 5 minutes
        }
    });
}