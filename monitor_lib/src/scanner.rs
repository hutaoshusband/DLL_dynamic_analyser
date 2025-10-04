use crate::config::LogLevel;
use crate::logging::LogEvent;
use crate::{log_event, ReentrancyGuard};
use patternscan::scan;
use std::ffi::OsString;
use std::io::Cursor;
use std::os::windows::ffi::OsStringExt;
use std::slice;
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, IMAGE_NT_HEADERS64};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
};
use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_TLS_DIRECTORY64};
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::Win32::System::Threading::GetCurrentProcessId;

/// Converts a fixed-size null-padded UTF-16 array to a Rust String.
fn u16_array_to_string(arr: &[u16]) -> String {
    let len = arr.iter().position(|&c| c == 0).unwrap_or(arr.len());
    OsString::from_wide(&arr[..len])
        .to_string_lossy()
        .into_owned()
}

/// Enumerates all loaded modules in the current process.
/// For each module, it returns its full path and a slice of its memory.
/// This is unsafe because it creates a slice from a raw pointer with a lifetime of 'static.
/// The caller must ensure this slice is only used while the module is loaded in memory.
pub unsafe fn enumerate_modules() -> Vec<(String, &'static [u8])> {
    let mut modules = Vec::new();
    let process_id = GetCurrentProcessId();
    // TH32CS_SNAPMODULE32 is needed even for 64-bit processes to get all modules.
    let snapshot_handle =
        CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id);

    if snapshot_handle == INVALID_HANDLE_VALUE {
        log_event(
            LogLevel::Error,
            LogEvent::Error {
                source: "ModuleEnumeration".to_string(),
                message: format!(
                    "CreateToolhelp32Snapshot failed. Last error: {}",
                    std::io::Error::last_os_error()
                ),
            },
        );
        return modules;
    }

    let mut module_entry: MODULEENTRY32W = std::mem::zeroed();
    module_entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

    if Module32FirstW(snapshot_handle, &mut module_entry) != 0 {
        loop {
            let mod_path = u16_array_to_string(&module_entry.szExePath);

            let module_slice =
                slice::from_raw_parts(module_entry.modBaseAddr, module_entry.modBaseSize as usize);

            modules.push((mod_path, module_slice));

            if Module32NextW(snapshot_handle, &mut module_entry) == 0 {
                break;
            }
        }
    }

    CloseHandle(snapshot_handle);
    modules
}

/// Gets a slice representing the memory of the main executable module.
/// This is unsafe because it involves reading directly from memory based on PE header information.
pub unsafe fn get_main_module_range() -> Option<&'static [u8]> {
    let base_addr = GetModuleHandleW(std::ptr::null_mut()) as *const u8;
    if base_addr.is_null() {
        return None;
    }
    let dos_header = &*(base_addr as *const IMAGE_DOS_HEADER);
    if dos_header.e_magic != 0x5A4D {
        // "MZ"
        return None;
    }
    let nt_headers_ptr =
        base_addr.add(dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    let nt_headers = &*nt_headers_ptr;
    if nt_headers.Signature != 0x4550 {
        // "PE\0\0"
        return None;
    }
    let size_of_image = nt_headers.OptionalHeader.SizeOfImage;
    Some(slice::from_raw_parts(
        base_addr,
        size_of_image as usize,
    ))
}

/// A simple wrapper around patternscan::scan to find a signature in the main module.
pub fn find_signature(signature: &str) -> Option<usize> {
    unsafe {
        if let Some(module_slice) = get_main_module_range() {
            let base_address = module_slice.as_ptr() as usize;
            let mut cursor = Cursor::new(module_slice);
            if let Ok(offsets) = scan(&mut cursor, signature) {
                offsets.first().map(|offset| base_address + offset)
            } else {
                None
            }
        } else {
            None
        }
    }
}

pub fn scan_for_manual_mapping() {
    unsafe {
        let process_handle = GetCurrentProcess();
        let mut current_address: usize = 0;
        loop {
            let mut mem_info: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            if VirtualQueryEx(
                process_handle,
                current_address as *const _,
                &mut mem_info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            ) == 0
            {
                break;
            }

            if let Some(_guard) = ReentrancyGuard::new() {
                let is_private_committed =
                    mem_info.State == MEM_COMMIT && mem_info.Type == MEM_PRIVATE;
                let is_executable = (mem_info.Protect & PAGE_EXECUTE_READ) != 0
                    || (mem_info.Protect & PAGE_EXECUTE_READWRITE) != 0
                    || (mem_info.Protect & PAGE_EXECUTE_WRITECOPY) != 0;

                if is_private_committed && is_executable {
                    let mut dos_header: IMAGE_DOS_HEADER = std::mem::zeroed();
                    if ReadProcessMemory(
                        process_handle,
                        mem_info.BaseAddress,
                        &mut dos_header as *mut _ as *mut _,
                        std::mem::size_of::<IMAGE_DOS_HEADER>(),
                        &mut 0,
                    ) != 0
                        && dos_header.e_magic == 0x5A4D
                    {
                        let nt_header_address =
                            (mem_info.BaseAddress as usize + dos_header.e_lfanew as usize)
                                as *const _;
                        let mut nt_headers: IMAGE_NT_HEADERS64 = std::mem::zeroed();
                        if ReadProcessMemory(
                            process_handle,
                            nt_header_address,
                            &mut nt_headers as *mut _ as *mut _,
                            std::mem::size_of::<IMAGE_NT_HEADERS64>(),
                            &mut 0,
                        ) != 0
                            && nt_headers.Signature == 0x4550
                        {
                            log_event(
                                LogLevel::Warn,
                                LogEvent::MemoryScan {
                                    status: "Potential manually mapped image found!".to_string(),
                                    result: format!(
                                        "Address: {:#X}",
                                        mem_info.BaseAddress as usize
                                    ),
                                },
                            );
                        }
                    }
                }
            }
            current_address = mem_info.BaseAddress as usize + mem_info.RegionSize;
        }
    }
}

/// Scans the PE header of a given module for TLS callbacks.
pub unsafe fn scan_tls_callbacks(module_base: usize) {
    let dos_header = &*(module_base as *const IMAGE_DOS_HEADER);
    if dos_header.e_magic != 0x5A4D {
        return;
    }

    let nt_headers_ptr = module_base + dos_header.e_lfanew as usize;
    let nt_headers = &*(nt_headers_ptr as *const IMAGE_NT_HEADERS64);

    let tls_dir_entry = &nt_headers.OptionalHeader.DataDirectory[9 as usize];
    if tls_dir_entry.VirtualAddress == 0 {
        return;
    }

    let tls_dir =
        (module_base + tls_dir_entry.VirtualAddress as usize) as *const IMAGE_TLS_DIRECTORY64;
    let mut callback_addr = (*tls_dir).AddressOfCallBacks as *const usize;

    // Callbacks are stored in a null-terminated array of pointers.
    if callback_addr.is_null() {
        return;
    }

    while *callback_addr != 0 {
        log_event(
            LogLevel::Warn,
            LogEvent::MemoryScan {
                status: "TLS Callback Found".to_string(),
                result: format!(
                    "Module: {:#X}, Callback Address: {:#X}",
                    module_base, *callback_addr
                ),
            },
        );
        callback_addr = callback_addr.add(1);
    }
}