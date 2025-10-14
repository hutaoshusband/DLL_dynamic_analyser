use crate::config::LogLevel;
use crate::log_event;
use crate::logging::LogEvent;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows_sys::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_IMPORT_DESCRIPTOR,
};
use windows_sys::Win32::System::Memory::{
    VirtualQuery, MEMORY_BASIC_INFORMATION
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::Win32::Foundation::CloseHandle;

/// Scans the IAT of a given module for potential hooks.
/// This is a simplified example and may need adjustments for different architectures.
unsafe fn scan_module_iat(module_base: usize) {
    let dos_header = &*(module_base as *const IMAGE_DOS_HEADER);
    if dos_header.e_magic != 0x5A4D { // "MZ"
        return;
    }

    let nt_headers_ptr = module_base + dos_header.e_lfanew as usize;
    let nt_headers = &*(nt_headers_ptr as *const windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64);

    let import_dir_entry = &nt_headers.OptionalHeader.DataDirectory
        [windows_sys::Win32::System::Diagnostics::Debug::IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
    if import_dir_entry.VirtualAddress == 0 {
        return;
    }

    let mut import_descriptor =
        (module_base + import_dir_entry.VirtualAddress as usize) as *const IMAGE_IMPORT_DESCRIPTOR;

    while (*import_descriptor).Name != 0 {
        let mut thunk = (module_base + (*import_descriptor).FirstThunk as usize) as *mut usize;
        while *thunk != 0 {
            let function_address = *thunk;

            // Check if the function address is outside the module's range it is being imported from.
            // This is a simple heuristic for detecting hooks.
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            if VirtualQuery(function_address as *const _, &mut mbi, std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) != 0 {
                 if mbi.AllocationBase != module_base as *mut _ {
                     // This address points outside of its supposed module, which is suspicious.
                     log_event(LogLevel::Warn, LogEvent::MemoryScan {
                         status: "Potential IAT Hook Detected".to_string(),
                         result: format!("Function at {:#X} points outside of its module.", function_address),
                     });
                 }
            }
            thunk = thunk.add(1);
        }
        import_descriptor = import_descriptor.add(1);
    }
}

/// Iterates through all loaded modules and triggers an IAT scan for each.
pub unsafe fn scan_iat_modifications() {
    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, 0);
    if snapshot as isize == -1 {
        return;
    }

    let mut module_entry: MODULEENTRY32W = std::mem::zeroed();
    module_entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

    if Module32FirstW(snapshot, &mut module_entry) != 0 {
        loop {
            scan_module_iat(module_entry.modBaseAddr as usize);
            if Module32NextW(snapshot, &mut module_entry) == 0 {
                break;
            }
        }
    }

    CloseHandle(snapshot);
}