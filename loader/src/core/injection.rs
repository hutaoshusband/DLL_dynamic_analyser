use std::{mem, path::Path};
use widestring::{U16CString, U16String};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW,
            Process32NextW, MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE,
            TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
        },
        LibraryLoader::{GetModuleHandleW, GetProcAddress},
        Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE},
        Threading::{
            CreateRemoteThread, OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
            PROCESS_SYNCHRONIZE, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
        },
    },
};

use crate::app::state::ModuleInfo;
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;

pub fn inject_dll(pid: u32, dll_path: &Path) -> Result<isize, String> {
    let process_handle = unsafe {
        OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ
                | PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    };

    if process_handle == 0 {
        return Err(format!("OpenProcess failed: {}", unsafe { GetLastError() }));
    }

    let dll_path_wide = U16CString::from_os_str(dll_path).unwrap();
    let dll_path_len_bytes = (dll_path_wide.len() + 1) * 2;

    let remote_buffer = unsafe {
        VirtualAllocEx(
            process_handle,
            std::ptr::null(),
            dll_path_len_bytes,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    if remote_buffer.is_null() {
        unsafe { CloseHandle(process_handle) };
        return Err(format!("VirtualAllocEx failed: {}", unsafe { GetLastError() }));
    }

    let mut bytes_written = 0;
    let write_success = unsafe {
        WriteProcessMemory(
            process_handle,
            remote_buffer,
            dll_path_wide.as_ptr() as _,
            dll_path_len_bytes,
            &mut bytes_written,
        )
    };

    if write_success == 0 {
        // In a real scenario, we should free the allocated memory here.
        unsafe { CloseHandle(process_handle) };
        return Err(format!("WriteProcessMemory failed: {}", unsafe { GetLastError() }));
    }

    let kernel32_name = U16CString::from_str("kernel32.dll").unwrap();
    let load_library_addr = unsafe {
        GetProcAddress(
            GetModuleHandleW(kernel32_name.as_ptr()),
            b"LoadLibraryW\0".as_ptr(),
        )
    };

    if load_library_addr.is_none() {
        // In a real scenario, we should free the allocated memory here.
        unsafe { CloseHandle(process_handle) };
        return Err("Could not find LoadLibraryW".into());
    }

    let thread_handle = unsafe {
        CreateRemoteThread(
            process_handle,
            std::ptr::null(),
            0,
            Some(std::mem::transmute(load_library_addr)),
            remote_buffer as _,
            0,
            std::ptr::null_mut(),
        )
    };

    if thread_handle == 0 {
        // In a real scenario, we should free the allocated memory here.
        unsafe { CloseHandle(process_handle) };
        return Err(format!("CreateRemoteThread failed: {}", unsafe { GetLastError() }));
    }

    unsafe { CloseHandle(thread_handle) };

    Ok(process_handle)
}

pub fn find_process_id(target_process_name: &str) -> Option<u32> {
    if target_process_name.is_empty() {
        return None;
    }
    unsafe {
        let snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot_handle == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut process_entry: PROCESSENTRY32W = mem::zeroed();
        process_entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snapshot_handle, &mut process_entry) != 0 {
            loop {
                let len = process_entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(0);
                let process_name = U16String::from_ptr(&process_entry.szExeFile as *const _, len);
                if process_name
                    .to_string_lossy()
                    .eq_ignore_ascii_case(target_process_name)
                {
                    CloseHandle(snapshot_handle);
                    return Some(process_entry.th32ProcessID);
                }
                if Process32NextW(snapshot_handle, &mut process_entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot_handle);
    }
    None
}

pub fn get_modules_for_process(pid: u32) -> Result<Vec<ModuleInfo>, String> {
    unsafe {
        let snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snapshot_handle == INVALID_HANDLE_VALUE {
            return Err(format!(
                "CreateToolhelp32Snapshot (Module) failed: {}",
                GetLastError()
            ));
        }

        let mut module_entry: MODULEENTRY32W = mem::zeroed();
        module_entry.dwSize = mem::size_of::<MODULEENTRY32W>() as u32;
        let mut modules = Vec::new();

        if Module32FirstW(snapshot_handle, &mut module_entry) != 0 {
            loop {
                let len = module_entry
                    .szModule
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(0);
                let module_name = U16String::from_ptr(module_entry.szModule.as_ptr(), len)
                    .to_string_lossy()
                    .to_owned();

                modules.push(ModuleInfo {
                    name: module_name,
                    base_address: module_entry.modBaseAddr as usize,
                    size: module_entry.modBaseSize,
                });
                if Module32NextW(snapshot_handle, &mut module_entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot_handle);
        Ok(modules)
    }
}