// monitor_lib/src/vmp_dumper.rs

use crate::config::LogLevel;
use crate::logging::LogEvent;
use crate::log_event;
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use serde_json::json;
use std::collections::HashMap;
use std::ffi::c_void;
use std::fs::{self, File};
use std::io::Write;
use std::mem;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::slice;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, MAX_PATH};
use windows_sys::Win32::System::Diagnostics::Debug::{
    ReadProcessMemory, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentProcessId};
use windows_sys::Win32::UI::Shell::{SHGetFolderPathW, CSIDL_LOCAL_APPDATA};

// Data structures for tracking memory and VMP targets
#[derive(Debug, Clone)]
pub struct AllocatedRegion {
    pub address: usize,
    pub size: usize,
    pub protection: u32,
    pub timestamp: DateTime<Utc>,
    pub stack_trace: Vec<String>,
    pub content_hash: Option<String>,
}

#[derive(Debug, Clone)]
pub enum DumpReason {
    VmpSection,
    UnpackedPe,
    Manual,
}

#[derive(Debug, Clone)]
pub struct VmpTarget {
    pub base_address: usize,
    pub size: usize,
    pub module_name: String,
    pub dump_priority: u8,
    pub has_been_dumped: bool,
}

struct VmpState {
    allocations: HashMap<usize, AllocatedRegion>,
    targets: HashMap<usize, VmpTarget>,
}

impl VmpState {
    fn new() -> Self {
        Self {
            allocations: HashMap::new(),
            targets: HashMap::new(),
        }
    }
}

static VMP_STATE: Lazy<Mutex<VmpState>> = Lazy::new(|| Mutex::new(VmpState::new()));

// Public API for the dumper
pub fn track_memory_allocation(
    address: usize,
    size: usize,
    protection: u32,
    stack_trace: Vec<String>,
) {
    if let Ok(mut state) = VMP_STATE.lock() {
        let region = AllocatedRegion {
            address,
            size,
            protection,
            timestamp: Utc::now(),
            stack_trace,
            content_hash: None,
        };

        log_event(
            LogLevel::Debug,
            LogEvent::VmpTrace {
                message: format!("Tracking new allocation at {:#X}", address),
                details: json!({
                    "size": size,
                    "protection": protection,
                }),
            },
        );

        state.allocations.insert(address, region);
    }
}

pub fn start_vmp_monitoring() {
    thread::spawn(|| {
        log_event(
            LogLevel::Info,
            LogEvent::VmpTrace {
                message: "VMP monitoring thread started.".to_string(),
                details: json!(null),
            },
        );

        loop {
            thread::sleep(Duration::from_secs(30));
            scan_for_vmp_modules();
            analyze_and_dump_if_ready();
        }
    });
}

pub fn handle_command(command: &str) {
    match command {
        "scan_vmp" => {
            log_event(
                LogLevel::Info,
                LogEvent::VmpTrace {
                    message: "Manual VMP scan triggered.".to_string(),
                    details: json!(null),
                },
            );
            scan_for_vmp_modules();
        }
        "dump_all" => {
            log_event(
                LogLevel::Info,
                LogEvent::VmpTrace {
                    message: "Manual VMP dump triggered.".to_string(),
                    details: json!(null),
                },
            );
            dump_all_targets(DumpReason::Manual);
        }
        _ => {}
    }
}

// Internal implementation
fn scan_for_vmp_modules() {
    let modules = unsafe { crate::scanner::enumerate_modules() };
    let mut state = match VMP_STATE.lock() {
        Ok(s) => s,
        Err(_) => return,
    };

    for (path, memory) in modules {
        let base_addr = memory.as_ptr() as usize;
        if state.targets.contains_key(&base_addr) {
            continue; // Already tracking this module
        }

        if is_vmp_protected(base_addr) {
            log_event(
                LogLevel::Warn,
                LogEvent::VmpTrace {
                    message: format!("Detected VMP-protected module: {}", path),
                    details: json!({ "base_address": base_addr }),
                },
            );

            let target = VmpTarget {
                base_address: base_addr,
                size: memory.len(),
                module_name: path.clone(),
                dump_priority: 100,
                has_been_dumped: false,
            };
            state.targets.insert(base_addr, target);
        }
    }
}

/// Helper function to read a structure from the current process's memory.
unsafe fn read_memory<T: Copy>(address: usize) -> Result<T, ()> {
    let mut buffer: T = mem::zeroed();
    let process_handle = GetCurrentProcess();
    let mut bytes_read = 0;

    if ReadProcessMemory(
        process_handle,
        address as *const c_void,
        &mut buffer as *mut T as *mut c_void,
        mem::size_of::<T>(),
        &mut bytes_read,
    ) == 0
        || bytes_read != mem::size_of::<T>()
    {
        Err(())
    } else {
        Ok(buffer)
    }
}

/// Checks if a module is protected by VMProtect by scanning its PE section headers.
fn is_vmp_protected(base_address: usize) -> bool {
    unsafe {
        let Ok(dos_header) = read_memory::<IMAGE_DOS_HEADER>(base_address) else {
            return false;
        };
        if dos_header.e_magic != 0x5A4D {
            return false;
        }

        let nt_headers_addr = base_address + dos_header.e_lfanew as usize;
        let Ok(nt_headers) = read_memory::<IMAGE_NT_HEADERS64>(nt_headers_addr) else {
            return false;
        };
        if nt_headers.Signature != 0x00004550 {
            return false;
        }

        let section_header_addr =
            nt_headers_addr + mem::size_of::<IMAGE_NT_HEADERS64>();
        let number_of_sections = nt_headers.FileHeader.NumberOfSections;

        for i in 0..number_of_sections {
            let current_section_header_addr =
                section_header_addr + (i as usize * mem::size_of::<IMAGE_SECTION_HEADER>());
            let Ok(section_header) =
                read_memory::<IMAGE_SECTION_HEADER>(current_section_header_addr)
            else {
                continue;
            };

            let section_name = String::from_utf8_lossy(&section_header.Name);
            if section_name.trim_matches('\0').starts_with(".vmp") {
                log_event(
                    LogLevel::Debug,
                    LogEvent::VmpTrace {
                        message: format!("Found VMP section: {}", section_name.trim_matches('\0')),
                        details: json!({ "module_base": base_address }),
                    },
                );
                return true;
            }
        }
    }
    false
}

fn analyze_and_dump_if_ready() {
    // This logic can be expanded to automatically dump based on certain criteria,
    // e.g., after observing specific API calls that suggest unpacking is complete.
}

fn dump_all_targets(reason: DumpReason) {
    let targets_to_dump: Vec<VmpTarget> = {
        let state = VMP_STATE.lock().unwrap();
        state.targets.values().cloned().collect()
    };

    if targets_to_dump.is_empty() {
        log_event(
            LogLevel::Info,
            LogEvent::VmpTrace {
                message: "No VMP targets found to dump.".to_string(),
                details: json!(null),
            },
        );
        return;
    }

    for target in targets_to_dump {
        if !target.has_been_dumped {
            reconstruct_and_dump_pe(&target, &reason);
            if let Ok(mut state) = VMP_STATE.lock() {
                if let Some(t) = state.targets.get_mut(&target.base_address) {
                    t.has_been_dumped = true;
                }
            }
        }
    }
}

fn get_dump_path() -> Option<PathBuf> {
    unsafe {
        let mut path_buf = vec![0u16; MAX_PATH as usize];
        if SHGetFolderPathW(0, CSIDL_LOCAL_APPDATA as i32, 0, 0, path_buf.as_mut_ptr()) >= 0 {
            let len = path_buf.iter().position(|&c| c == 0).unwrap_or(path_buf.len());
            let appdata_path_os = std::ffi::OsString::from_wide(&path_buf[..len]);
            let mut dump_path = PathBuf::from(appdata_path_os);
            dump_path.push("cs2_monitor");
            dump_path.push("dumps");
            if fs::create_dir_all(&dump_path).is_ok() {
                return Some(dump_path);
            }
        }
    }
    None
}

/// Reconstructs a PE file from memory and dumps it to disk.
/// This is superior to a raw memory dump as it rebuilds the file according
/// to its PE headers, resulting in a cleaner, more analyzable file.
fn reconstruct_and_dump_pe(target: &VmpTarget, reason: &DumpReason) {
    let base_address = target.base_address;
    let process_handle = unsafe { GetCurrentProcess() };

    unsafe {
        // 1. Read headers from memory
        let Ok(dos_header) = read_memory::<IMAGE_DOS_HEADER>(base_address) else {
            log_event(LogLevel::Error, LogEvent::VmpTrace {
                message: "Failed to read DOS header for dumping.".to_string(),
                details: json!({ "base_address": base_address }),
            });
            return;
        };

        let nt_headers_addr = base_address + dos_header.e_lfanew as usize;
        let Ok(nt_headers) = read_memory::<IMAGE_NT_HEADERS64>(nt_headers_addr) else {
            log_event(LogLevel::Error, LogEvent::VmpTrace {
                message: "Failed to read NT headers for dumping.".to_string(),
                details: json!({ "nt_header_address": nt_headers_addr }),
            });
            return;
        };

        // 2. Allocate a buffer for the reconstructed PE file.
        // SizeOfImage is the size of the PE file in memory, which is what we want to reconstruct.
        let file_size = nt_headers.OptionalHeader.SizeOfImage as usize;
        let mut file_buffer = vec![0u8; file_size];

        // 3. Copy the PE headers into the buffer.
        let header_size = (dos_header.e_lfanew as usize) + mem::size_of::<IMAGE_NT_HEADERS64>();
        let mut headers_buffer = vec![0u8; header_size];
        if ReadProcessMemory(
            process_handle,
            base_address as *const c_void,
            headers_buffer.as_mut_ptr() as *mut c_void,
            header_size,
            std::ptr::null_mut(),
        ) == 0
        {
            log_event(LogLevel::Error, LogEvent::VmpTrace {
                message: "Failed to read PE headers into buffer.".to_string(),
                details: json!({ "base_address": base_address, "header_size": header_size }),
            });
            return;
        }
        file_buffer[..header_size].copy_from_slice(&headers_buffer);

        // 4. Iterate through sections, copy them from memory into the buffer at the correct file offset.
        let number_of_sections = nt_headers.FileHeader.NumberOfSections;
        let section_header_addr = nt_headers_addr + mem::size_of::<IMAGE_NT_HEADERS64>();

        for i in 0..number_of_sections {
            let current_section_header_addr =
                section_header_addr + (i as usize * mem::size_of::<IMAGE_SECTION_HEADER>());
            let Ok(section_header) =
                read_memory::<IMAGE_SECTION_HEADER>(current_section_header_addr)
            else {
                continue;
            };

            let section_data_addr = base_address + section_header.VirtualAddress as usize;
            let section_file_offset = section_header.PointerToRawData as usize;
            let section_size = section_header.SizeOfRawData as usize;

            if section_file_offset + section_size > file_buffer.len() {
                log_event(LogLevel::Warn, LogEvent::VmpTrace {
                    message: "Section data extends beyond file buffer. Truncating.".to_string(),
                    details: json!({ "section": i, "offset": section_file_offset, "size": section_size }),
                });
                continue;
            }

            let mut section_buffer = vec![0u8; section_size];
            if ReadProcessMemory(
                process_handle,
                section_data_addr as *const c_void,
                section_buffer.as_mut_ptr() as *mut c_void,
                section_size,
                std::ptr::null_mut(),
            ) != 0
            {
                file_buffer[section_file_offset..section_file_offset + section_size]
                    .copy_from_slice(&section_buffer);
            }
        }

        // 5. Write the reconstructed buffer to disk.
        let dump_path = match get_dump_path() {
            Some(p) => p,
            None => return,
        };

        let reason_str = match reason {
            DumpReason::Manual => "manual",
            DumpReason::UnpackedPe => "unpacked",
            DumpReason::VmpSection => "vmp_section",
        };
        let module_file_name = PathBuf::from(&target.module_name)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown_module")
            .to_string();

        let filename = format!("{}_{}_{:#X}.dmp", module_file_name, reason_str, base_address);
        let full_path = dump_path.join(filename);

        match File::create(&full_path) {
            Ok(mut f) => {
                if f.write_all(&file_buffer).is_ok() {
                    log_event(LogLevel::Success, LogEvent::FileOperation {
                        path: full_path.to_string_lossy().to_string(),
                        operation: "PE Reconstruction".to_string(),
                        details: format!(
                            "Successfully dumped {} bytes from {}",
                            file_size, target.module_name
                        ),
                    });
                } else {
                    log_event(LogLevel::Error, LogEvent::FileOperation {
                        path: full_path.to_string_lossy().to_string(),
                        operation: "PE Reconst. Write".to_string(),
                        details: "Failed to write dumped memory to file".to_string(),
                    });
                }
            }
            Err(e) => {
                log_event(LogLevel::Error, LogEvent::FileOperation {
                    path: full_path.to_string_lossy().to_string(),
                    operation: "PE Reconst. Create".to_string(),
                    details: e.to_string(),
                });
            }
        }
    }
}