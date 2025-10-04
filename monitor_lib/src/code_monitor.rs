use crate::config::LogLevel;
use crate::log_event;
use crate::logging::LogEvent;
use once_cell::sync::Lazy;
use serde_json::json;
use std::collections::HashSet;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::sync::Mutex;
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows_sys::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentProcessId};

static LOGGED_REGIONS: Lazy<Mutex<HashSet<usize>>> = Lazy::new(|| Mutex::new(HashSet::new()));

/// Finds the name of the module that contains the given memory address.
unsafe fn get_module_name_from_address(address: usize) -> String {
    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, 0);
    if snapshot == INVALID_HANDLE_VALUE {
        return "<unknown_module:snapshot_failed>".to_string();
    }

    let mut me32: MODULEENTRY32W = std::mem::zeroed();
    me32.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

    if Module32FirstW(snapshot, &mut me32) == 0 {
        CloseHandle(snapshot);
        return "<unknown_module:first_failed>".to_string();
    }

    loop {
        let mod_base = me32.modBaseAddr as usize;
        let mod_end = mod_base + me32.modBaseSize as usize;

        if address >= mod_base && address < mod_end {
            CloseHandle(snapshot);
            let mod_name_slice = &me32.szModule[..];
            let zero_pos =
                mod_name_slice.iter().position(|&c| c == 0).unwrap_or(mod_name_slice.len());
            let os_string = OsString::from_wide(&mod_name_slice[..zero_pos]);
            return os_string.to_string_lossy().into_owned();
        }

        if Module32NextW(snapshot, &mut me32) == 0 {
            break;
        }
    }

    CloseHandle(snapshot);
    "<no_enclosing_module>".to_string()
}

/// Periodically scans the process's memory for executable and writable regions.
/// Such regions are suspicious as they can be used for runtime code modification or injection.
pub fn monitor_code_modifications() {
    unsafe {
        let process = GetCurrentProcess();
        let mut address: usize = 0;
        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();

        loop {
            if VirtualQueryEx(
                process,
                address as *const _,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            ) == 0
            {
                break;
            }

            // Check for the suspicious combination of EXECUTE and WRITE permissions.
            if (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0 && mbi.State != 0x10000 /*MEM_FREE*/ {
                let base_address = mbi.BaseAddress as usize;
                let mut logged_regions = LOGGED_REGIONS.lock().unwrap();

                if !logged_regions.contains(&base_address) {
                    let mut buffer = vec![0u8; std::cmp::min(mbi.RegionSize, 4096)];
                    let mut bytes_read = 0;

                    if ReadProcessMemory(
                        process,
                        mbi.BaseAddress,
                        buffer.as_mut_ptr() as _,
                        buffer.len(),
                        &mut bytes_read,
                    ) != 0
                    {
                        logged_regions.insert(base_address);
                        let module_name = get_module_name_from_address(base_address);
                        log_event(LogLevel::Warn, LogEvent::MemoryScan {
                            status: "Suspicious Memory Region Found".to_string(),
                            result: format!(
                                "Address: {:#X}, Size: {}, Protection: {:#X}, Module: {}",
                                base_address, mbi.RegionSize, mbi.Protect, module_name
                            ),
                        });
                    }
                }
            }

            // Move to the next memory region.
            address = (mbi.BaseAddress as usize) + mbi.RegionSize;
        }
        CloseHandle(process);
    }
}