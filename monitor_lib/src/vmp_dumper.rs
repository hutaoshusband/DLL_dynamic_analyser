// monitor_lib/src/vmp_dumper.rs

use crate::config::LogLevel;
use crate::logging::LogEvent;
use crate::log_event;
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use serde_json::json;
use std::collections::HashMap;
use std::ffi::c_void;
use std::os::windows::ffi::OsStringExt;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use windows_sys::Win32::Foundation::MAX_PATH;
use std::mem;
use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, ReadProcessMemory};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_SECTION_HEADER;
use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_HEADER};
use windows_sys::Win32::System::Threading::GetCurrentProcess;
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
        log_event(LogLevel::Info, LogEvent::VmpTrace {
            message: "VMP monitoring thread started.".to_string(),
            details: json!(null),
        });

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
            log_event(LogLevel::Info, LogEvent::VmpTrace {
                message: "Manual VMP scan triggered.".to_string(),
                details: json!(null),
            });
            scan_for_vmp_modules();
        },
        "dump_all" => {
            log_event(LogLevel::Info, LogEvent::VmpTrace {
                message: "Manual VMP dump triggered.".to_string(),
                details: json!(null),
            });
            dump_all_targets(DumpReason::Manual);
        },
        _ => {}
    }
}


// Internal implementation
fn scan_for_vmp_modules() {
    let process_handle = unsafe { GetCurrentProcess() };
    let snapshot_handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, 0) };

    if snapshot_handle as isize == -1 {
        return;
    }

    let mut module_entry: MODULEENTRY32W = unsafe { mem::zeroed() };
    module_entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

    if unsafe { Module32FirstW(snapshot_handle, &mut module_entry) } == 0 {
        return;
    }

    let mut modules = Vec::new();
    loop {
        modules.push(module_entry.clone());
        if unsafe { Module32NextW(snapshot_handle, &mut module_entry) } == 0 {
            break;
        }
    }

    let mut state = match VMP_STATE.lock() {
        Ok(s) => s,
        Err(_) => return,
    };

    for module in modules {
        let base_addr = module.modBaseAddr as usize;
        if state.targets.contains_key(&base_addr) {
            continue; // Already tracking this module
        }
        
        let module_name = String::from_utf16_lossy(&module.szModule).trim_end_matches('\0').to_string();

        if is_vmp_protected(base_addr, module.modBaseSize as usize) {
            log_event(LogLevel::Warn, LogEvent::VmpTrace {
                message: format!("Detected VMP-protected module: {}", module_name),
                details: json!({ "base_address": base_addr }),
            });

            let target = VmpTarget {
                base_address: base_addr,
                size: module.modBaseSize as usize,
                module_name: module_name.clone(),
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
fn is_vmp_protected(base_address: usize, _size: usize) -> bool {
    unsafe {
        // 1. Read the DOS header to find the NT headers.
        let Ok(dos_header) = read_memory::<IMAGE_DOS_HEADER>(base_address) else {
            return false;
        };

        if dos_header.e_magic != 0x5A4D { // "MZ"
            return false;
        }

        // 2. Read the NT headers.
        let nt_headers_addr = base_address + dos_header.e_lfanew as usize;
        let Ok(nt_headers) = read_memory::<IMAGE_NT_HEADERS64>(nt_headers_addr) else {
            return false;
        };

        if nt_headers.Signature != 0x00004550 { // "PE\0\0"
            return false;
        }

        // 3. Locate the first section header.
        let section_header_addr = nt_headers_addr + mem::size_of::<IMAGE_NT_HEADERS64>();
        let number_of_sections = nt_headers.FileHeader.NumberOfSections;

        // 4. Iterate through all sections and check their names.
        for i in 0..number_of_sections {
            let current_section_header_addr =
                section_header_addr + (i as usize * mem::size_of::<IMAGE_SECTION_HEADER>());
            
            let Ok(section_header) = read_memory::<IMAGE_SECTION_HEADER>(current_section_header_addr) else {
                continue; // Skip if a section header is unreadable.
            };

            // VMP uses section names like .vmp0, .vmp1, etc.
            let section_name = String::from_utf8_lossy(&section_header.Name);
            if section_name.trim_matches('\0').starts_with(".vmp") {
                log_event(LogLevel::Debug, LogEvent::VmpTrace {
                    message: format!("Found VMP section: {}", section_name.trim_matches('\0')),
                    details: json!({ "module_base": base_address }),
                });
                return true;
            }
        }
    }

    false
}

fn analyze_and_dump_if_ready() {
    // More complex logic would go here to decide *when* to dump.
    // For now, we don't do anything automatically after the initial scan.
}

fn dump_all_targets(reason: DumpReason) {
    let targets_to_dump: Vec<VmpTarget> = {
        let state = VMP_STATE.lock().unwrap();
        state.targets.values().cloned().collect()
    };

    if targets_to_dump.is_empty() {
        log_event(LogLevel::Info, LogEvent::VmpTrace {
            message: "No VMP targets found to dump.".to_string(),
            details: json!(null),
        });
        return;
    }

    for target in targets_to_dump {
        if !target.has_been_dumped {
            dump_pe(target.base_address, target.size, &target.module_name, &reason);
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

fn dump_pe(base_address: usize, size: usize, name: &str, reason: &DumpReason) {
    let dump_path = match get_dump_path() {
        Some(p) => p,
        None => {
            log_event(LogLevel::Error, LogEvent::VmpTrace {
                message: "Failed to get dump path.".to_string(),
                details: json!(null),
            });
            return;
        }
    };

    let reason_str = match reason {
        DumpReason::Manual => "manual",
        DumpReason::UnpackedPe => "unpacked",
        DumpReason::VmpSection => "vmp_section",
    };
    let filename = format!("{}_{}_{:#X}.bin", name, reason_str, base_address);
    let full_path = dump_path.join(filename);

    let mut buffer = vec![0u8; size];
    let process_handle = unsafe { GetCurrentProcess() };

    let res = unsafe {
        ReadProcessMemory(
            process_handle,
            base_address as *const c_void,
            buffer.as_mut_ptr() as *mut c_void,
            size,
            std::ptr::null_mut(),
        )
    };

    if res == 0 {
        log_event(LogLevel::Error, LogEvent::VmpTrace {
            message: format!("Failed to read process memory for dumping {}", name),
            details: json!({ "address": base_address, "size": size }),
        });
        return;
    }

    match File::create(&full_path) {
        Ok(mut f) => {
            if f.write_all(&buffer).is_ok() {
                log_event(LogLevel::Success, LogEvent::FileOperation {
                    path: full_path.to_string_lossy().to_string(),
                    operation: "VMP Dump".to_string(),
                    details: format!("Successfully dumped {} bytes from {}", size, name),
                });
            } else {
                 log_event(LogLevel::Error, LogEvent::FileOperation {
                    path: full_path.to_string_lossy().to_string(),
                    operation: "VMP Dump Write".to_string(),
                    details: "Failed to write dumped memory to file".to_string(),
                });
            }
        },
        Err(e) => {
            log_event(LogLevel::Error, LogEvent::FileOperation {
                path: full_path.to_string_lossy().to_string(),
                operation: "VMP Dump Create".to_string(),
                details: e.to_string(),
            });
        }
    }
}