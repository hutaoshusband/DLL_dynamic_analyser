// Copyright (c) 2024 HUTAOSHUSBAND - Wallbangbros.com/CodeConfuser.dev
// All rights reserved.


use std::{mem, path::Path, fs, env};
use std::time::{SystemTime, UNIX_EPOCH};
use std::os::windows::process::CommandExt;
use widestring::{U16CString, U16String};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE, ERROR_NOT_ALL_ASSIGNED, LUID},
    Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW,
        SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    },
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW,
            Process32NextW, MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE,
            TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
        },
        LibraryLoader::{GetModuleHandleW, GetProcAddress},
        Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE},
        Threading::{
            CreateRemoteThread, GetCurrentProcess, OpenProcess, OpenProcessToken,
            PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_SYNCHRONIZE,
            PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, WaitForSingleObject,
            GetExitCodeThread, IsWow64Process,
        },
    },
};

use crate::app::state::ModuleInfo;
use windows_sys::Win32::System::Diagnostics::Debug::{WriteProcessMemory, ReadProcessMemory};
use pelite::pe64::{Pe, PeFile};
use pelite::pe64::imports::Import;
use windows_sys::Win32::System::Memory::{VirtualProtectEx, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY};
use windows_sys::Win32::System::SystemServices::{IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW, IMAGE_REL_BASED_ABSOLUTE};
use windows_sys::Win32::System::Threading::GetProcessId;

pub fn enable_debug_privilege() -> Result<(), String> {
    unsafe {
        let mut h_token: isize = 0;
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut h_token,
        ) == 0
        {
            return Err(format!("OpenProcessToken failed: {}", GetLastError()));
        }

        let mut luid: LUID = mem::zeroed();
        let name = U16CString::from_str("SeDebugPrivilege").unwrap();
        if LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) == 0 {
            CloseHandle(h_token);
            return Err(format!("LookupPrivilegeValueW failed: {}", GetLastError()));
        }

        let mut tp: TOKEN_PRIVILEGES = mem::zeroed();
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if AdjustTokenPrivileges(
            h_token,
            0,
            &tp,
            mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ) == 0
        {
            CloseHandle(h_token);
            return Err(format!("AdjustTokenPrivileges failed: {}", GetLastError()));
        }

        if GetLastError() == ERROR_NOT_ALL_ASSIGNED {
            CloseHandle(h_token);
            // It's possible we are not admin, so we can't get the privilege.
            // We return an error so the caller knows, but maybe we should allow proceeding?
            // For now, let's return error so it's explicit.
            return Err("AdjustTokenPrivileges: ERROR_NOT_ALL_ASSIGNED (Run as Admin?)".to_string());
        }

        CloseHandle(h_token);
        Ok(())
    }
}

pub fn inject_dll(pid: u32, dll_path: &Path) -> Result<isize, String> {
    if !dll_path.exists() {
        return Err(format!("DLL file not found at path: {}", dll_path.display()));
    }
    
    // Try to enable debug privilege to access elevated processes.
    // We log the error but proceed, in case the target is not elevated and we don't strictly need it.
    if let Err(e) = enable_debug_privilege() {
        eprintln!("Warning: Failed to enable debug privilege: {}", e);
    }
    
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

    // Architecture Check: Prevent 64-bit loader from injecting into 32-bit target.
    // A 64-bit DLL cannot be loaded into a 32-bit process, and LoadLibraryW failure often indicates this.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let mut is_wow64: i32 = 0;
        if IsWow64Process(process_handle, &mut is_wow64) != 0 && is_wow64 != 0 {
             CloseHandle(process_handle);
             return Err("Architecture Mismatch: Target process is 32-bit (WOW64), but this analyzer is 64-bit. Cannot inject 64-bit DLL into 32-bit process.".to_string());
        }
    }

    // Fix for "LoadLibraryW returns NULL" due to Permissions:
    // User's Temp dir (AppData) is often not readable by SYSTEM processes.
    // We use C:\Users\Public which is universally readable.
    // We use C:\Users\Public which is universally readable.
    // Randomize filename to avoid detection/locking.
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let random_name = format!("analyzer_{}.dll", timestamp);
    
    let public_dir = Path::new("C:\\Users\\Public");
    let temp_dll_path = if public_dir.exists() {
        public_dir.join(&random_name)
    } else {
        // Fallback to temp if Public missing (rare)
        env::temp_dir().join(&random_name)
    };
    
    // Attempt copy. If it fails (e.g. file in use), we try to overwrite or just proceed with original?
    // Let's try to copy and fall back to original if copy fails, or error out.
    let path_to_use = match fs::copy(dll_path, &temp_dll_path) {
        Ok(_) => {
            temp_dll_path.as_path()
        }
        Err(e) => {
            eprintln!("Warning: Failed to copy DLL to public directory: {}. Trying original path.", e);
            dll_path
        }
    };

    // Fix for "Access Denied" by specific Service Accounts or AppContainers:
    // Even in Public, specific low-privilege accounts might not have Read+Execute permissions inherited.
    // We explicitly grant "Everyone" (SID: S-1-1-0) Read & Execute rights using icacls.
    let _ = std::process::Command::new("icacls")
        .arg(path_to_use)
        .arg("/grant")
        .arg("*S-1-1-0:RX")
        .arg("/T")
        .arg("/C")
        .arg("/Q")
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output();

    let dll_path_wide = U16CString::from_os_str(path_to_use).unwrap();
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

    // Wait for the thread to finish executing LoadLibraryW.
    // This creates a slight delay but ensures we know if injection worked.
    // 5 seconds timeout should be plenty for LoadLibrary.
    let wait_result = unsafe { WaitForSingleObject(thread_handle, 5000) };
    if wait_result == 0x00000000 { // WAIT_OBJECT_0
        let mut exit_code = 0;
        unsafe { GetExitCodeThread(thread_handle, &mut exit_code) };
        if exit_code == 0 {
             unsafe { CloseHandle(thread_handle) };
             unsafe { CloseHandle(process_handle) };
             // Use \r\n to ensure it formats nicely if displayed in a message box or log
             return Err(format!("Injection failed: LoadLibraryW returned NULL in remote process.\nTarget PID: {}\nDLL Path: {}\n\nDIAGNOSTIC: Check if 'C:\\Users\\Public\\analyzer_beacon_{}.txt' exists. \nIf YES: DllMain ran but returned FALSE or crashed (panic caught).\nIf NO: LoadLibrary blocked by OS (AV/EDR/CFG/PPL).", pid, path_to_use.display(), pid));
        }
    } else {
        // Timeout or failed to wait
        // logging it but proceeding, though this usually implies something hung.
        eprintln!("Warning: WaitForSingleObject on injection thread timed out or failed (0x{:X})", wait_result);
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

pub fn manual_map_inject(pid: u32, dll_path: &Path) -> Result<isize, String> {
    if !dll_path.exists() {
        return Err(format!("DLL not found: {}", dll_path.display()));
    }

    let dll_bytes = fs::read(dll_path).map_err(|e| format!("Failed to read DLL: {}", e))?;
    let pe = PeFile::from_bytes(&dll_bytes).map_err(|e| format!("Failed to parse PE: {}", e))?;

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

    // Architecture Check
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let mut is_wow64: i32 = 0;
        if IsWow64Process(process_handle, &mut is_wow64) != 0 && is_wow64 != 0 {
             CloseHandle(process_handle);
             return Err("Architecture Mismatch: Target process is 32-bit (WOW64). Manual Map x64 -> x86 not supported.".to_string());
        }
    }

    // 1. Allocate Memory for the Image
    let optional_header = pe.optional_header();
    let image_size = optional_header.SizeOfImage as usize;
    let preferred_base = optional_header.ImageBase;

    let remote_base = unsafe {
        VirtualAllocEx(
            process_handle,
            std::ptr::null(), // Try to allocate anywhere first
            image_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    if remote_base.is_null() {
        unsafe { CloseHandle(process_handle) };
        return Err(format!("VirtualAllocEx failed to allocate image size: {}", unsafe { GetLastError() }));
    }

    let delta = (remote_base as u64).wrapping_sub(preferred_base);

    // 2. Copy Headers
    let headers_size = optional_header.SizeOfHeaders as usize;
    let mut bytes_written = 0;
    unsafe {
        WriteProcessMemory(
            process_handle,
            remote_base,
            dll_bytes.as_ptr() as _,
            headers_size,
            &mut bytes_written,
        );
    }

    // 3. Map Sections
    for section in pe.section_headers() {
        let section_va = remote_base as usize + section.VirtualAddress as usize;
        let size_of_raw_data = section.SizeOfRawData as usize;
        let pointer_to_raw_data = section.PointerToRawData as usize;
        
        if size_of_raw_data == 0 {
            continue;
        }

        let data = &dll_bytes[pointer_to_raw_data..pointer_to_raw_data + size_of_raw_data];
        
        unsafe {
            WriteProcessMemory(
                process_handle,
                section_va as _,
                data.as_ptr() as _,
                size_of_raw_data,
                &mut bytes_written,
            );
        }
    }

    // 4. Manual Relocations
    if delta != 0 {
        if let Ok(base_relocs) = pe.base_relocs() {
            for block in base_relocs.iter_blocks() {
                for reloc in block.words() {
                    let r_type = (reloc >> 12) as u8;
                    let r_offset = (reloc & 0xFFF) as u32;
                    let r_va = block.image().VirtualAddress as u32 + r_offset;
                    let target_va = remote_base as usize + r_va as usize;

                    let mut current_val: u64 = 0;
                    unsafe {
                         ReadProcessMemory(
                            process_handle,
                            target_va as _,
                            &mut current_val as *mut _ as _,
                            8,
                             &mut bytes_written,
                        );
                    }
                    
                    match r_type {
                        r if r == IMAGE_REL_BASED_DIR64 as u8 => {
                            current_val = current_val.wrapping_add(delta);
                        }
                         r if r == IMAGE_REL_BASED_HIGHLOW as u8 => {
                             let mut val32 = current_val as u32;
                             val32 = val32.wrapping_add(delta as u32);
                             unsafe {
                                WriteProcessMemory(
                                    process_handle,
                                    target_va as _,
                                    &val32 as *const _ as _,
                                    4,
                                    &mut bytes_written,
                                );
                             }
                             continue;
                        }
                        r if r == IMAGE_REL_BASED_ABSOLUTE as u8 => continue,
                        _ => continue,
                    }

                     unsafe {
                        WriteProcessMemory(
                            process_handle,
                            target_va as _,
                            &current_val as *const _ as _,
                            8,
                            &mut bytes_written,
                        );
                     }
                }
            }
        }
    }

    // 5. Build Import Table
    if let Ok(imports) = pe.imports() {
        for import_desc in imports {
            let module_name = match import_desc.dll_name() {
                Ok(n) => n.to_string(),
                Err(_) => continue,
            };
            
            let module_handle_in_target = load_library_remote(process_handle, &module_name)?;

            let int = match import_desc.int() { Ok(i) => i, Err(_) => continue };
            let iat_rva = import_desc.image().FirstThunk;

            for (i, import) in int.enumerate() {
                 let import = match import { Ok(i) => i, Err(_) => continue };
                 
                 let func_addr = match import {
                     Import::ByName { name, .. } => {
                         let local_module = unsafe {
                            let name_w = U16CString::from_str(&module_name).unwrap();
                            let h = windows_sys::Win32::System::LibraryLoader::LoadLibraryW(name_w.as_ptr());
                            h
                         };
                         
                         if local_module == 0 {
                             unsafe { CloseHandle(process_handle) };
                             return Err(format!("Could not load dependency locally: {}", module_name));
                         }

                         let proc_name_c = std::ffi::CString::new(name.as_ref()).unwrap();
                         let local_proc = unsafe { GetProcAddress(local_module, proc_name_c.as_ptr() as _) };
                         
                         if local_proc.is_none() {
                              unsafe { CloseHandle(process_handle) };
                              return Err(format!("Could not find procedure {} in {}", name, module_name));
                         }

                         let local_proc_addr = unsafe { std::mem::transmute::<Option<unsafe extern "system" fn() -> isize>, usize>(local_proc) };
                         let offset = local_proc_addr - local_module as usize;
                         module_handle_in_target as usize + offset
                     }
                     Import::ByOrdinal { ord: ordinal } => {
                          let local_module = unsafe {
                            let name_w = U16CString::from_str(&module_name).unwrap();
                            windows_sys::Win32::System::LibraryLoader::LoadLibraryW(name_w.as_ptr())
                         };
                         let local_proc = unsafe { GetProcAddress(local_module, (ordinal as u16) as *const u8) };
                          if local_proc.is_none() {
                              unsafe { CloseHandle(process_handle) };
                              return Err(format!("Could not find procedure ordinal {} in {}", ordinal, module_name));
                         }
                         let local_proc_addr = unsafe { std::mem::transmute::<Option<unsafe extern "system" fn() -> isize>, usize>(local_proc) };
                         let offset = local_proc_addr - local_module as usize;
                         module_handle_in_target as usize + offset
                     }
                 };
                 
                 let iat_va = remote_base as usize + (iat_rva as usize) + (i * 8);
                  unsafe {
                    WriteProcessMemory(
                        process_handle,
                        iat_va as _,
                        &func_addr as *const _ as _,
                        8,
                        &mut bytes_written,
                    );
                 }
            }
        }
    }

    // 6. Set Section Protections
    for section in pe.section_headers() {
        if section.SizeOfRawData == 0 { continue; }
        
        let section_va = remote_base as usize + section.VirtualAddress as usize;
        let characteristics = section.Characteristics;
        
        let protect = if characteristics & 0x20000000 != 0 { // MEM_EXECUTE
            if characteristics & 0x80000000 != 0 { // MEM_WRITE
                PAGE_EXECUTE_READWRITE
            } else {
                PAGE_EXECUTE_READ
            }
        } else if characteristics & 0x80000000 != 0 { // MEM_WRITE
             PAGE_READWRITE
        } else {
             PAGE_READONLY
        };
        
        let mut old_protect = 0;
        unsafe {
            VirtualProtectEx(
                process_handle,
                section_va as _,
                section.SizeOfRawData as usize,
                protect,
                &mut old_protect
            );
        }
    }

    // 7. Execute DllMain (and TLS callbacks)
    let entry_point = optional_header.AddressOfEntryPoint;
    let dll_main_addr = remote_base as usize + entry_point as usize;

    // TLS callbacks: AddressOfCallBacks in TLS directory is a VA (not RVA).
    // It points to a null-terminated array of callback function pointers.
    // We need to apply the relocation delta to both the pointer to the array AND
    // each callback address in the array (they were stored as absolute VAs at link time).
    let tls_callbacks_ptr = if let Ok(tls) = pe.tls() {
         let callback_array_va = tls.image().AddressOfCallBacks;
         if callback_array_va != 0 {
             // The AddressOfCallBacks is a VA that was based on preferred ImageBase.
             // After relocation, we need to apply delta to get the actual address in remote process.
             // callback_array_va - preferred_base + remote_base = new address
             let relocated_array_ptr = (callback_array_va as i64 + delta as i64) as u64;
             relocated_array_ptr
         } else {
             0
         }
    } else { 
        0 
    };

    #[repr(C)]
    struct ShellcodeData {
        dll_base: u64,
        dll_main: u64,
        tls_callbacks_ptr: u64,
    }
    
    let sc_data = ShellcodeData {
        dll_base: remote_base as u64,
        dll_main: dll_main_addr as u64,
        tls_callbacks_ptr,
    };
    
    let sc_data_size = std::mem::size_of::<ShellcodeData>();
    let sc_data_remote = unsafe {
        VirtualAllocEx(process_handle, std::ptr::null(), sc_data_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    };
    unsafe {
         WriteProcessMemory(
            process_handle,
            sc_data_remote,
            &sc_data as *const _ as _,
            sc_data_size,
            &mut bytes_written,
        );
    }
    
    // x64 Shellcode - Properly handles TLS callbacks + DllMain with correct x64 ABI
    // 
    // Function signature for DllMain/TLS callbacks:
    //   BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
    //   rcx = hinstDLL (dll_base)
    //   rdx = fdwReason (1 = DLL_PROCESS_ATTACH)
    //   r8  = lpvReserved (NULL for dynamic loads)
    //
    // ShellcodeData layout (passed in rcx by CreateRemoteThread):
    //   +0x00: dll_base
    //   +0x08: dll_main address
    //   +0x10: tls_callbacks_ptr (pointer to null-terminated array of callback VAs)
    //
    // Shellcode (x64, proper ABI with 0x28 shadow space for alignment):
    //   push rbx, rsi, rdi, r12, r13, r14, r15  ; save non-volatile registers
    //   sub rsp, 0x28                           ; shadow space (32) + alignment (8) = 0x28
    //   mov rbx, rcx                            ; rbx = pointer to ShellcodeData
    //   mov r12, [rbx]                          ; r12 = dll_base
    //   mov r13d, 1                             ; r13 = DLL_PROCESS_ATTACH
    //   xor r14, r14                            ; r14 = NULL (lpvReserved)
    //   
    //   ; Call TLS callbacks if any
    //   mov rsi, [rbx+0x10]                     ; rsi = tls_callbacks_ptr
    //   test rsi, rsi                           ; if NULL, skip TLS
    //   jz .call_dllmain
    // .tls_loop:
    //   mov rax, [rsi]                          ; rax = current callback
    //   test rax, rax                           ; if NULL, end of array
    //   jz .call_dllmain
    //   mov rcx, r12                            ; arg1 = dll_base
    //   mov rdx, r13                            ; arg2 = DLL_PROCESS_ATTACH  
    //   mov r8, r14                             ; arg3 = NULL
    //   call rax
    //   add rsi, 8                              ; next callback
    //   jmp .tls_loop
    //
    // .call_dllmain:
    //   mov rax, [rbx+0x08]                     ; rax = dll_main
    //   test rax, rax
    //   jz .done
    //   mov rcx, r12                            ; arg1 = dll_base
    //   mov rdx, r13                            ; arg2 = DLL_PROCESS_ATTACH
    //   mov r8, r14                             ; arg3 = NULL
    //   call rax
    // .done:
    //   add rsp, 0x28
    //   pop r15, r14, r13, r12, rdi, rsi, rbx
    //   ret
    let shellcode: [u8; _] = [
        // Prologue: save non-volatile registers and allocate shadow space
        0x53,                               // push rbx
        0x56,                               // push rsi
        0x57,                               // push rdi
        0x41, 0x54,                         // push r12
        0x41, 0x55,                         // push r13
        0x41, 0x56,                         // push r14
        0x41, 0x57,                         // push r15
        0x48, 0x83, 0xEC, 0x28,             // sub rsp, 0x28 (shadow space + alignment)
        
        // Load parameters from ShellcodeData
        0x48, 0x89, 0xCB,                   // mov rbx, rcx (rbx = &ShellcodeData)
        0x4C, 0x8B, 0x23,                   // mov r12, [rbx] (r12 = dll_base)
        0x41, 0xBD, 0x01, 0x00, 0x00, 0x00, // mov r13d, 1 (DLL_PROCESS_ATTACH)
        0x4D, 0x31, 0xF6,                   // xor r14, r14 (r14 = NULL for lpvReserved)
        
        // TLS callbacks loop
        0x48, 0x8B, 0x73, 0x10,             // mov rsi, [rbx+0x10] (rsi = tls_callbacks_ptr)
        0x48, 0x85, 0xF6,                   // test rsi, rsi
        0x74, 0x18,                         // jz .call_dllmain (offset to dllmain code)
        
        // .tls_loop:
        0x48, 0x8B, 0x06,                   // mov rax, [rsi]
        0x48, 0x85, 0xC0,                   // test rax, rax
        0x74, 0x10,                         // jz .call_dllmain
        0x4C, 0x89, 0xE1,                   // mov rcx, r12 (arg1 = dll_base)
        0x4C, 0x89, 0xEA,                   // mov rdx, r13 (arg2 = 1)
        0x4D, 0x89, 0xF0,                   // mov r8, r14 (arg3 = NULL)
        0xFF, 0xD0,                         // call rax
        0x48, 0x83, 0xC6, 0x08,             // add rsi, 8
        0xEB, 0xE8,                         // jmp .tls_loop
        
        // .call_dllmain:
        0x48, 0x8B, 0x43, 0x08,             // mov rax, [rbx+0x08] (rax = dll_main)
        0x48, 0x85, 0xC0,                   // test rax, rax
        0x74, 0x0B,                         // jz .done
        0x4C, 0x89, 0xE1,                   // mov rcx, r12 (arg1 = dll_base)
        0x4C, 0x89, 0xEA,                   // mov rdx, r13 (arg2 = 1)
        0x4D, 0x89, 0xF0,                   // mov r8, r14 (arg3 = NULL)
        0xFF, 0xD0,                         // call rax
        
        // .done: Epilogue
        0x48, 0x83, 0xC4, 0x28,             // add rsp, 0x28
        0x41, 0x5F,                         // pop r15
        0x41, 0x5E,                         // pop r14
        0x41, 0x5D,                         // pop r13
        0x41, 0x5C,                         // pop r12
        0x5F,                               // pop rdi
        0x5E,                               // pop rsi
        0x5B,                               // pop rbx
        0xC3,                               // ret
    ];

    let shellcode_size = shellcode.len();
    let shellcode_remote = unsafe {
        VirtualAllocEx(process_handle, std::ptr::null(), shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    };
     unsafe {
         WriteProcessMemory(
            process_handle,
            shellcode_remote,
            shellcode.as_ptr() as _,
            shellcode_size,
            &mut bytes_written,
        );
    }
    
    let thread_handle = unsafe {
        CreateRemoteThread(
            process_handle,
            std::ptr::null(),
            0,
            Some(std::mem::transmute(shellcode_remote)),
            sc_data_remote,
            0,
            std::ptr::null_mut(),
        )
    };

    if thread_handle == 0 {
         unsafe { CloseHandle(process_handle) };
         return Err(format!("CreateRemoteThread for shellcode failed: {}", unsafe { GetLastError() }));
    }

    unsafe { WaitForSingleObject(thread_handle, 5000) };
    unsafe { CloseHandle(thread_handle) };
    
    Ok(process_handle)
}

/// Resolves API Set DLL names to their actual implementation DLLs.
/// API Sets (api-ms-win-*) are virtual DLLs that forward to real implementations.
fn resolve_api_set(dll_name: &str) -> String {
    let lower_name = dll_name.to_lowercase();
    
    // Check if this is an API set DLL
    if lower_name.starts_with("api-ms-win-") || lower_name.starts_with("ext-ms-win-") {
        // Common API set mappings to their actual implementations
        // Most synchronization, memory, and core APIs are in kernelbase.dll or kernel32.dll
        if lower_name.contains("core-") || 
           lower_name.contains("synch-") || 
           lower_name.contains("processthreads-") ||
           lower_name.contains("memory-") ||
           lower_name.contains("handle-") ||
           lower_name.contains("libraryloader-") ||
           lower_name.contains("heap-") ||
           lower_name.contains("interlocked-") ||
           lower_name.contains("profile-") ||
           lower_name.contains("string-") ||
           lower_name.contains("sysinfo-") ||
           lower_name.contains("errorhandling-") ||
           lower_name.contains("fibers-") ||
           lower_name.contains("namedpipe-") ||
           lower_name.contains("file-") ||
           lower_name.contains("console-") ||
           lower_name.contains("timezone-") ||
           lower_name.contains("localization-") {
            return "kernelbase.dll".to_string();
        }
        
        // Security APIs
        if lower_name.contains("security-") {
            return "kernelbase.dll".to_string();
        }
        
        // Registry APIs
        if lower_name.contains("registry-") {
            return "kernelbase.dll".to_string();
        }
        
        // COM APIs
        if lower_name.contains("com-") {
            return "combase.dll".to_string();
        }
        
        // Default fallback for unknown API sets
        return "kernelbase.dll".to_string();
    }
    
    // Not an API set, return as-is
    dll_name.to_string()
}

fn load_library_remote(process: windows_sys::Win32::Foundation::HANDLE, dll_name: &str) -> Result<isize, String> {
    unsafe {
        use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
        
        // Resolve API set DLLs to their actual implementations
        let resolved_dll_name = resolve_api_set(dll_name);
        
        // Check if the resolved DLL is already loaded in the target process
        let modules = get_modules_for_process(GetProcessId(process))?;
        for m in &modules {
            if m.name.eq_ignore_ascii_case(&resolved_dll_name) {
                return Ok(m.base_address as isize);
            }
        }
        
        let kernel32 = U16CString::from_str("kernel32.dll").unwrap();
        let load_lib_str = std::ffi::CString::new("LoadLibraryW").unwrap();
        let load_library_addr = GetProcAddress(GetModuleHandleW(kernel32.as_ptr()), load_lib_str.as_ptr() as _);
        
        if load_library_addr.is_none() {
            return Err("Failed to find LoadLibraryW".to_string());
        }

        let dll_name_wide = U16CString::from_str(&resolved_dll_name).unwrap();
        let size = (dll_name_wide.len() + 1) * 2;
        let remote_str = VirtualAllocEx(process, std::ptr::null(), size, MEM_COMMIT, PAGE_READWRITE);
        if remote_str.is_null() {
            return Err(format!("Failed to allocate remote string for {}", resolved_dll_name));
        }
        
        WriteProcessMemory(process, remote_str, dll_name_wide.as_ptr() as _, size, std::ptr::null_mut());
        
        let thread = CreateRemoteThread(
            process,
            std::ptr::null(),
            0,
            Some(std::mem::transmute(load_library_addr)),
            remote_str,
            0,
            std::ptr::null_mut()
        );
        
        if thread == 0 {
            return Err(format!("Failed to create remote thread for loading {}", resolved_dll_name));
        }
        
        WaitForSingleObject(thread, 5000);
        
        let mut exit_code = 0;
        GetExitCodeThread(thread, &mut exit_code);
        CloseHandle(thread);
        
        if exit_code == 0 {
            return Err(format!("LoadLibraryW returned NULL for {} (resolved from {})", resolved_dll_name, dll_name));
        }
        
        // Re-scan modules to find the newly loaded DLL
        let modules = get_modules_for_process(GetProcessId(process))?;
        for m in modules {
            if m.name.eq_ignore_ascii_case(&resolved_dll_name) {
                return Ok(m.base_address as isize);
            }
        }
        
        Err(format!("Could not load dependency: {} (resolved to {})", dll_name, resolved_dll_name))
    }
}