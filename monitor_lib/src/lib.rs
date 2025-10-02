#![cfg(windows)]
// Include the new logging module
mod logging;

use std::cell::Cell;
use std::ffi::{c_void, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::thread::{self, JoinHandle};
use once_cell::sync::OnceCell;
use serde_json::json;

// Use the new logging structures
use logging::{LogEntry, LogEvent};
use windows_sys::Win32::Foundation::{BOOL, HANDLE, HINSTANCE, INVALID_HANDLE_VALUE, HWND};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::LibraryLoader::{LoadLibraryExW, LoadLibraryW, GetProcAddress, GetModuleHandleW};
use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, ReadProcessMemory};
use windows_sys::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
};
use windows_sys::Win32::System::SystemServices::{
    DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, IMAGE_DOS_HEADER,
};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, DeleteFileW, GetFinalPathNameByHandleW, OPEN_EXISTING, WriteFile};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, CreateRemoteThread, GetCurrentProcess, GetCurrentProcessId, Sleep,
    PROCESS_INFORMATION, STARTUPINFOW, THREAD_CREATION_FLAGS, LPTHREAD_START_ROUTINE,
};
use windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxW;
use windows_sys::Win32::System::IO::OVERLAPPED;
use windows_sys::Win32::Networking::WinSock::{
    inet_ntoa, AF_INET, IN_ADDR, SOCKET, SOCKADDR, SOCKADDR_IN, ADDRINFOW,
};
use windows_sys::Win32::System::Registry::{
    RegCreateKeyExW, RegDeleteKeyW, RegSetValueExW, HKEY,
};
use windows_sys::Win32::UI::Shell::{CSIDL_LOCAL_APPDATA, SHGetFolderPathW};

// Globals for logging and thread management.
static LOGGER: OnceCell<Mutex<MonitorLogger>> = OnceCell::new();
static SHUTDOWN_SIGNAL: AtomicBool = AtomicBool::new(false);
static SCANNER_THREAD_HANDLE: Mutex<Option<JoinHandle<()>>> = Mutex::new(None);

// Thread-local flag to prevent re-entrancy in hooks.
thread_local!(static IN_HOOK: Cell<bool> = Cell::new(false));

/// A guard to prevent re-entrant calls to hooked functions.
struct ReentrancyGuard;

impl ReentrancyGuard {
    /// Enters the guarded section. Returns `None` if already inside a hook.
    fn new() -> Option<ReentrancyGuard> {
        IN_HOOK.with(|in_hook| {
            if in_hook.get() {
                None
            } else {
                in_hook.set(true);
                Some(ReentrancyGuard)
            }
        })
    }
}

impl Drop for ReentrancyGuard {
    /// Exits the guarded section.
    fn drop(&mut self) {
        IN_HOOK.with(|in_hook| {
            in_hook.set(false);
        });
    }
}

/// Eine Struktur, die unsere Logging-Ziele verwaltet.
struct MonitorLogger {
    log_file: Option<File>,
    pipe: Option<HANDLE>,
}

/// Die zentrale Logging-Funktion. Serialisiert ein LogEvent und schreibt es als JSON.
fn log_event(event: LogEvent) {
    if let Some(logger_mutex) = LOGGER.get() {
        if let Ok(mut logger) = logger_mutex.lock() {
            let log_entry = LogEntry::new(event);

            if let Ok(json_string) = serde_json::to_string(&log_entry) {
                let formatted_message = format!("{}\n", json_string);
                let bytes = formatted_message.as_bytes();

                if let Some(file) = logger.log_file.as_mut() {
                    let _ = file.write_all(bytes);
                    let _ = file.flush();
                }

                if let Some(pipe_handle) = logger.pipe {
                    if pipe_handle != INVALID_HANDLE_VALUE {
                        let mut bytes_written = 0;
                        unsafe {
                            WriteFile(
                                pipe_handle,
                                bytes.as_ptr(),
                                bytes.len() as u32,
                                &mut bytes_written,
                                std::ptr::null_mut(),
                            );
                        }
                    }
                }
            }
        }
    }
}

// Definiert die Hooks für die API-Funktionen.
retour::static_detour! {
    static MessageBoxWHook: unsafe extern "system" fn(HWND, *const u16, *const u16, u32) -> i32;
    static CreateFileWHook: unsafe extern "system" fn(
        *const u16, u32, u32, *const SECURITY_ATTRIBUTES, u32, u32, HANDLE
    ) -> HANDLE;
    static WriteFileHook: unsafe extern "system" fn(
        HANDLE, *const u8, u32, *mut u32, *mut OVERLAPPED
    ) -> BOOL;
    static CreateProcessWHook: unsafe extern "system" fn(
        *const u16, *mut u16, *const SECURITY_ATTRIBUTES, *const SECURITY_ATTRIBUTES,
        BOOL, u32, *const c_void, *const u16, *const STARTUPINFOW, *mut PROCESS_INFORMATION
    ) -> BOOL;
    static LoadLibraryWHook: unsafe extern "system" fn(*const u16) -> HINSTANCE;
    static LoadLibraryExWHook: unsafe extern "system" fn(*const u16, HANDLE, u32) -> HINSTANCE;
    static ConnectHook: unsafe extern "system" fn(SOCKET, *const SOCKADDR, i32) -> i32;
    static RegCreateKeyExWHook: unsafe extern "system" fn(
        HKEY, *const u16, u32, *const u16, u32, u32, *const SECURITY_ATTRIBUTES, *mut HKEY, *mut u32
    ) -> u32;
    static RegSetValueExWHook: unsafe extern "system" fn(
        HKEY, *const u16, u32, u32, *const u8, u32
    ) -> u32;
    static RegDeleteKeyWHook: unsafe extern "system" fn(HKEY, *const u16) -> u32;
    static DeleteFileWHook: unsafe extern "system" fn(*const u16) -> BOOL;
    static CreateRemoteThreadHook: unsafe extern "system" fn(
        HANDLE, *const SECURITY_ATTRIBUTES, usize, LPTHREAD_START_ROUTINE, *const c_void, THREAD_CREATION_FLAGS, *mut u32
    ) -> HANDLE;
    static GetAddrInfoWHook: unsafe extern "system" fn(
        *const u16, *const u16, *const ADDRINFOW, *mut *mut ADDRINFOW
    ) -> i32;
}

// Safely converts a null-terminated wide string pointer to a String.
fn safe_u16_str(ptr: *const u16) -> String {
    if ptr.is_null() {
        "<NULL>".to_string()
    } else {
        unsafe { widestring::U16CStr::from_ptr_str(ptr).to_string_lossy() }
    }
}

// Hook für GetAddrInfoW, um DNS-Abfragen zu protokollieren.
fn hooked_get_addr_info_w(
    p_node_name: *const u16,
    p_service_name: *const u16,
    p_hints: *const ADDRINFOW,
    pp_result: *mut *mut ADDRINFOW,
) -> i32 {
    if let Some(_guard) = ReentrancyGuard::new() {
        let node_name = safe_u16_str(p_node_name);
        let service_name = safe_u16_str(p_service_name);
        log_event(LogEvent::ApiHook {
            function_name: "GetAddrInfoW".to_string(),
            parameters: json!({ "node_name": node_name, "service_name": service_name }),
        });
    }
    unsafe { GetAddrInfoWHook.call(p_node_name, p_service_name, p_hints, pp_result) }
}

// Unsere eigene Funktion, die anstelle von MessageBoxW aufgerufen wird.
fn hooked_message_box_w(h_wnd: HWND, text: *const u16, caption: *const u16, u_type: u32) -> i32 {
    if let Some(_guard) = ReentrancyGuard::new() {
        let text_str = safe_u16_str(text);
        let caption_str = safe_u16_str(caption);
        log_event(LogEvent::ApiHook {
            function_name: "MessageBoxW".to_string(),
            parameters: json!({ "title": caption_str, "text": text_str, "type": u_type }),
        });
    }
    unsafe { MessageBoxWHook.call(h_wnd, text, caption, u_type) }
}

// Unsere eigene Funktion, die anstelle von CreateFileW aufgerufen wird.
fn hooked_create_file_w(
    lp_file_name: *const u16,
    dw_desired_access: u32,
    dw_share_mode: u32,
    lp_security_attributes: *const SECURITY_ATTRIBUTES,
    dw_creation_disposition: u32,
    dw_flags_and_attributes: u32,
    h_template_file: HANDLE,
) -> HANDLE {
    if let Some(_guard) = ReentrancyGuard::new() {
        let file_name_str = safe_u16_str(lp_file_name);
        log_event(LogEvent::ApiHook {
            function_name: "CreateFileW".to_string(),
            parameters: json!({ "file_name": file_name_str, "access": dw_desired_access, "disposition": dw_creation_disposition }),
        });
    }
    unsafe {
        CreateFileWHook.call(
            lp_file_name, dw_desired_access, dw_share_mode, lp_security_attributes,
            dw_creation_disposition, dw_flags_and_attributes, h_template_file
        )
    }
}

// Hook für connect
fn hooked_connect(s: SOCKET, name: *const SOCKADDR, namelen: i32) -> i32 {
    if let Some(_guard) = ReentrancyGuard::new() {
        if !name.is_null() && namelen as u32 >= std::mem::size_of::<SOCKADDR_IN>() as u32 {
            let sockaddr_in = unsafe { *(name as *const SOCKADDR_IN) };
            if sockaddr_in.sin_family == AF_INET as u16 {
                let ip_addr_long = unsafe { sockaddr_in.sin_addr.S_un.S_addr };
                let port = u16::from_be(sockaddr_in.sin_port);
                
                let ip_str = unsafe {
                    let addr = IN_ADDR { S_un: std::mem::transmute([ip_addr_long]) };
                    let c_str = inet_ntoa(addr);
                    if c_str.is_null() {
                        "Invalid IP".to_string()
                    } else {
                        std::ffi::CStr::from_ptr(c_str as *const i8).to_string_lossy().into_owned()
                    }
                };
                
                log_event(LogEvent::ApiHook {
                    function_name: "connect".to_string(),
                    parameters: json!({ "target_ip": ip_str, "port": port }),
                });
            }
        }
    }
    unsafe { ConnectHook.call(s, name, namelen) }
}

// Hilfsfunktion zur Konvertierung von HKEY in einen lesbaren String.
fn hkey_to_string(hkey: HKEY) -> String {
    const HKEY_CLASSES_ROOT_VAL: isize = 0x80000000;
    const HKEY_CURRENT_USER_VAL: isize = 0x80000001;
    const HKEY_LOCAL_MACHINE_VAL: isize = 0x80000002;
    const HKEY_USERS_VAL: isize = 0x80000003;

    match hkey {
        HKEY_CLASSES_ROOT_VAL => "HKEY_CLASSES_ROOT".to_string(),
        HKEY_CURRENT_USER_VAL => "HKEY_CURRENT_USER".to_string(),
        HKEY_LOCAL_MACHINE_VAL => "HKEY_LOCAL_MACHINE".to_string(),
        HKEY_USERS_VAL => "HKEY_USERS".to_string(),
        _ => format!("Unknown HKEY ({:?})", hkey),
    }
}

// Hook für RegCreateKeyExW
fn hooked_reg_create_key_ex_w(
    hkey: HKEY,
    lp_sub_key: *const u16,
    _reserved: u32,
    lp_class: *const u16,
    dw_options: u32,
    sam_desired: u32,
    lp_security_attributes: *const SECURITY_ATTRIBUTES,
    phk_result: *mut HKEY,
    lpdw_disposition: *mut u32,
) -> u32 {
    if let Some(_guard) = ReentrancyGuard::new() {
        let sub_key = safe_u16_str(lp_sub_key);
        log_event(LogEvent::ApiHook {
            function_name: "RegCreateKeyExW".to_string(),
            parameters: json!({ "path": format!("{}\\{}", hkey_to_string(hkey), sub_key) }),
        });
    }
    unsafe {
        RegCreateKeyExWHook.call(
            hkey, lp_sub_key, _reserved, lp_class, dw_options, sam_desired,
            lp_security_attributes, phk_result, lpdw_disposition,
        )
    }
}

/// Sucht im Speicher des aktuellen Prozesses nach Anzeichen von "Manual Mapping".
/// This function performs a single scan. The looping is handled by the caller.
fn scan_for_manual_mapping() {
    if let Some(_guard) = ReentrancyGuard::new() {
        log_event(LogEvent::MemoryScan {
            status: "Starting periodic scan for manual mapping.".to_string(),
            result: "".to_string(),
        });
    }
    unsafe {
        let process_handle = GetCurrentProcess();
        let mut current_address: usize = 0;

        // This loop iterates over memory regions, not indefinitely.
        loop {
            if let Some(_guard) = ReentrancyGuard::new() {
                let mut mem_info: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
                let result = VirtualQueryEx(
                    process_handle,
                    current_address as *const _,
                    &mut mem_info,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );

                if result == 0 { break; }

                let is_private_committed = mem_info.State == MEM_COMMIT && mem_info.Type == MEM_PRIVATE;
                let is_executable = (mem_info.Protect & PAGE_EXECUTE_READ) != 0
                    || (mem_info.Protect & PAGE_EXECUTE_READWRITE) != 0
                    || (mem_info.Protect & PAGE_EXECUTE_WRITECOPY) != 0;

                if is_private_committed && is_executable {
                    let mut dos_header: IMAGE_DOS_HEADER = std::mem::zeroed();
                    let mut bytes_read = 0;

                    if ReadProcessMemory(
                        process_handle,
                        mem_info.BaseAddress,
                        &mut dos_header as *mut _ as *mut _,
                        std::mem::size_of::<IMAGE_DOS_HEADER>(),
                        &mut bytes_read,
                    ) != 0 && dos_header.e_magic == 0x5A4D { // Check for "MZ"
                        let nt_header_address = (mem_info.BaseAddress as usize + dos_header.e_lfanew as usize) as *const _;
                        let mut nt_headers: IMAGE_NT_HEADERS64 = std::mem::zeroed();

                        if ReadProcessMemory(
                            process_handle,
                            nt_header_address,
                            &mut nt_headers as *mut _ as *mut _,
                            std::mem::size_of::<IMAGE_NT_HEADERS64>(),
                            &mut bytes_read,
                        ) != 0 && nt_headers.Signature == 0x4550 { // Check for "PE"
                            log_event(LogEvent::MemoryScan {
                                status: "Potential manually mapped image found!".to_string(),
                                result: format!("Address: {:#X}", mem_info.BaseAddress as usize),
                            });
                        }
                    }
                }
                current_address = mem_info.BaseAddress as usize + mem_info.RegionSize;
            } else {
                // If we are in a hook, just advance to the next memory region without scanning.
                let mut mem_info: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
                let result = VirtualQueryEx(
                    process_handle,
                    current_address as *const _,
                    &mut mem_info,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );
                if result == 0 { break; }
                current_address = mem_info.BaseAddress as usize + mem_info.RegionSize;
            }
        }
    }
    if let Some(_guard) = ReentrancyGuard::new() {
        log_event(LogEvent::MemoryScan {
            status: "Memory scan finished.".to_string(),
            result: "".to_string(),
        });
    }
}

// Hook für RegSetValueExW
fn hooked_reg_set_value_ex_w(
    hkey: HKEY,
    lp_value_name: *const u16,
    _reserved: u32,
    dw_type: u32,
    lp_data: *const u8,
    cb_data: u32,
) -> u32 {
    if let Some(_guard) = ReentrancyGuard::new() {
        let value_name = safe_u16_str(lp_value_name);
        log_event(LogEvent::ApiHook {
            function_name: "RegSetValueExW".to_string(),
            parameters: json!({ "key": hkey_to_string(hkey), "value_name": value_name, "type": dw_type, "bytes": cb_data }),
        });
    }
    unsafe {
        RegSetValueExWHook.call(hkey, lp_value_name, _reserved, dw_type, lp_data, cb_data)
    }
}

// Hook für RegDeleteKeyW
fn hooked_reg_delete_key_w(hkey: HKEY, lp_sub_key: *const u16) -> u32 {
    if let Some(_guard) = ReentrancyGuard::new() {
        let sub_key = safe_u16_str(lp_sub_key);
        log_event(LogEvent::ApiHook {
            function_name: "RegDeleteKeyW".to_string(),
            parameters: json!({ "path": format!("{}\\{}", hkey_to_string(hkey), sub_key) }),
        });
    }
    unsafe { RegDeleteKeyWHook.call(hkey, lp_sub_key) }
}

// Hook für DeleteFileW
fn hooked_delete_file_w(lp_file_name: *const u16) -> BOOL {
    if let Some(_guard) = ReentrancyGuard::new() {
        let file_name = safe_u16_str(lp_file_name);
        log_event(LogEvent::ApiHook {
            function_name: "DeleteFileW".to_string(),
            parameters: json!({ "file_name": file_name }),
        });
    }
    unsafe { DeleteFileWHook.call(lp_file_name) }
}

// Hook für CreateRemoteThread
fn hooked_create_remote_thread(
    h_process: HANDLE,
    lp_thread_attributes: *const SECURITY_ATTRIBUTES,
    dw_stack_size: usize,
    lp_start_address: LPTHREAD_START_ROUTINE,
    lp_parameter: *const c_void,
    dw_creation_flags: THREAD_CREATION_FLAGS,
    lp_thread_id: *mut u32,
) -> HANDLE {
    if let Some(_guard) = ReentrancyGuard::new() {
        let start_address_val = lp_start_address.map_or(0, |f| f as usize);
        log_event(LogEvent::ApiHook {
            function_name: "CreateRemoteThread".to_string(),
            parameters: json!({ "target_process_handle": h_process, "start_address": start_address_val }),
        });
    }
    unsafe {
        CreateRemoteThreadHook.call(
            h_process, lp_thread_attributes, dw_stack_size, lp_start_address,
            lp_parameter, dw_creation_flags, lp_thread_id,
        )
    }
}

// Hook für LoadLibraryW
fn hooked_load_library_w(lp_lib_file_name: *const u16) -> HINSTANCE {
    if let Some(_guard) = ReentrancyGuard::new() {
        let lib_name = safe_u16_str(lp_lib_file_name);
        log_event(LogEvent::ApiHook {
            function_name: "LoadLibraryW".to_string(),
            parameters: json!({ "library_name": lib_name }),
        });
    }
    unsafe { LoadLibraryWHook.call(lp_lib_file_name) }
}

// Hook für LoadLibraryExW
fn hooked_load_library_ex_w(lp_lib_file_name: *const u16, h_file: HANDLE, dw_flags: u32) -> HINSTANCE {
    if let Some(_guard) = ReentrancyGuard::new() {
        let lib_name = safe_u16_str(lp_lib_file_name);
        log_event(LogEvent::ApiHook {
            function_name: "LoadLibraryExW".to_string(),
            parameters: json!({ "library_name": lib_name, "flags": dw_flags }),
        });
    }
    unsafe { LoadLibraryExWHook.call(lp_lib_file_name, h_file, dw_flags) }
}

// Hook für WriteFile
fn hooked_write_file(
    h_file: HANDLE,
    lp_buffer: *const u8,
    n_number_of_bytes_to_write: u32,
    lp_number_of_bytes_written: *mut u32,
    lp_overlapped: *mut OVERLAPPED,
) -> BOOL {
    if let Some(_guard) = ReentrancyGuard::new() {
        let mut file_path_buf = vec![0u16; 1024];
        let path_len = unsafe { GetFinalPathNameByHandleW(h_file, file_path_buf.as_mut_ptr(), file_path_buf.len() as u32, 0) };
        let file_name = if path_len > 0 {
            OsString::from_wide(&file_path_buf[..path_len as usize]).to_string_lossy().to_string()
        } else {
            "Unknown Handle".to_string()
        };

        log_event(LogEvent::ApiHook {
            function_name: "WriteFile".to_string(),
            parameters: json!({ "file_name": file_name, "bytes_to_write": n_number_of_bytes_to_write }),
        });
    }

    unsafe {
        WriteFileHook.call(h_file, lp_buffer, n_number_of_bytes_to_write, lp_number_of_bytes_written, lp_overlapped)
    }
}

// Hook für CreateProcessW
fn hooked_create_process_w(
    lp_application_name: *const u16,
    lp_command_line: *mut u16,
    lp_process_attributes: *const SECURITY_ATTRIBUTES,
    lp_thread_attributes: *const SECURITY_ATTRIBUTES,
    b_inherit_handles: BOOL,
    dw_creation_flags: u32,
    lp_environment: *const c_void,
    lp_current_directory: *const u16,
    lp_startup_info: *const STARTUPINFOW,
    lp_process_information: *mut PROCESS_INFORMATION,
) -> BOOL {
    if let Some(_guard) = ReentrancyGuard::new() {
        let app_name = safe_u16_str(lp_application_name);
        let cmd_line = safe_u16_str(lp_command_line);
        
        log_event(LogEvent::ApiHook {
            function_name: "CreateProcessW".to_string(),
            parameters: json!({ "application_name": app_name, "command_line": cmd_line }),
        });
    }
    
    unsafe {
        CreateProcessWHook.call(
            lp_application_name, lp_command_line, lp_process_attributes, lp_thread_attributes,
            b_inherit_handles, dw_creation_flags, lp_environment, lp_current_directory,
            lp_startup_info, lp_process_information
        )
    }
}

/// This function contains the core logic for DLL initialization.
/// It sets up logging, applies API hooks, and starts background threads.
/// It returns a `Result` to indicate success or failure, allowing `DllMain`
/// to prevent the DLL from loading if initialization fails.
fn dll_main_internal() -> Result<(), String> {
    let pid = unsafe { GetCurrentProcessId() };

    // Set up the named pipe for logging.
    let pipe_name = format!(r"\\.\pipe\cs2_monitor_{}", pid);
    let wide_pipe_name: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut pipe_handle = INVALID_HANDLE_VALUE;
    for _ in 0..5 {
        pipe_handle = unsafe {
            CreateFileW(
                wide_pipe_name.as_ptr(),
                0x40000000, // GENERIC_WRITE
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                0,
            )
        };
        if pipe_handle != INVALID_HANDLE_VALUE { break; }
        unsafe { Sleep(500) };
    }

    // Set up the log file in %LOCALAPPDATA%.
    let mut log_file: Option<File> = None;
    unsafe {
        let mut path_buf = vec![0u16; 260]; // MAX_PATH
        if SHGetFolderPathW(0, CSIDL_LOCAL_APPDATA as i32, 0, 0, path_buf.as_mut_ptr()) >= 0 {
            let len = path_buf.iter().position(|&c| c == 0).unwrap_or(path_buf.len());
            let appdata_path = OsString::from_wide(&path_buf[..len]);
            let mut log_dir = PathBuf::from(appdata_path);
            log_dir.push("cs2_monitor");
            log_dir.push("logs");

            if fs::create_dir_all(&log_dir).is_ok() {
                let mut i = 1;
                loop {
                    let log_path = log_dir.join(format!("log{}.txt", i));
                    if !log_path.exists() {
                        log_file = OpenOptions::new().create(true).append(true).open(log_path).ok();
                        break;
                    }
                    i += 1;
                    if i > 1000 { break; } // Failsafe to prevent infinite loop.
                }
            }
        }
    }

    let logger = MonitorLogger { log_file, pipe: Some(pipe_handle) };
    if LOGGER.set(Mutex::new(logger)).is_err() {
        return Err("Failed to initialize the global logger.".to_string());
    }
    
    log_event(LogEvent::Initialization { status: "Monitor DLL initializing...".to_string() });

    // Initialize and enable all API hooks.
    unsafe {
        macro_rules! hook {
            ($hook:ident, $func:expr, $hook_fn:ident) => {
                if $hook.initialize($func, $hook_fn).is_err() {
                    let msg = format!("Failed to hook {}", stringify!($func));
                    log_event(LogEvent::Error { source: "Initialization".to_string(), message: msg.clone() });
                    return Err(msg);
                }
                if $hook.enable().is_err() {
                    let msg = format!("Failed to enable hook for {}", stringify!($func));
                    log_event(LogEvent::Error { source: "Initialization".to_string(), message: msg.clone() });
                    return Err(msg);
                }
            };
        }
        
        hook!(MessageBoxWHook, MessageBoxW, hooked_message_box_w);
        hook!(CreateFileWHook, CreateFileW, hooked_create_file_w);
        hook!(WriteFileHook, WriteFile, hooked_write_file);
        hook!(CreateProcessWHook, CreateProcessW, hooked_create_process_w);
        hook!(LoadLibraryWHook, LoadLibraryW, hooked_load_library_w);
        hook!(LoadLibraryExWHook, LoadLibraryExW, hooked_load_library_ex_w);
        hook!(RegCreateKeyExWHook, RegCreateKeyExW, hooked_reg_create_key_ex_w);
        hook!(RegSetValueExWHook, RegSetValueExW, hooked_reg_set_value_ex_w);
        hook!(RegDeleteKeyWHook, RegDeleteKeyW, hooked_reg_delete_key_w);
        hook!(DeleteFileWHook, DeleteFileW, hooked_delete_file_w);
        hook!(CreateRemoteThreadHook, CreateRemoteThread, hooked_create_remote_thread);
        
        let ws2_32_name: Vec<u16> = "ws2_32.dll".encode_utf16().chain(std::iter::once(0)).collect();
        let ws2_32 = GetModuleHandleW(ws2_32_name.as_ptr());
        if ws2_32 != 0 {
            if let Some(addr) = GetProcAddress(ws2_32, b"connect\0".as_ptr()) {
                hook!(ConnectHook, std::mem::transmute(addr), hooked_connect);
            }
            if let Some(addr) = GetProcAddress(ws2_32, b"GetAddrInfoW\0".as_ptr()) {
                hook!(GetAddrInfoWHook, std::mem::transmute(addr), hooked_get_addr_info_w);
            }
        }
    }

    // Start the memory scanning thread.
    let scanner_handle = thread::spawn(|| {
        while !SHUTDOWN_SIGNAL.load(Ordering::SeqCst) {
            scan_for_manual_mapping();
            // Sleep for ~60 seconds, but check for shutdown signal frequently.
            for _ in 0..600 {
                if SHUTDOWN_SIGNAL.load(Ordering::SeqCst) {
                    break;
                }
                thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    });

    // Store the handle for graceful shutdown.
    *SCANNER_THREAD_HANDLE.lock().unwrap() = Some(scanner_handle);

    log_event(LogEvent::Initialization { status: "Monitor DLL initialized successfully.".to_string() });
    Ok(())
}


#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(
    _dll_module: HINSTANCE,
    call_reason: u32,
    _reserved: *mut c_void,
) -> BOOL {
    match call_reason {
        DLL_PROCESS_ATTACH => {
            if dll_main_internal().is_err() {
                return 0; // FALSE
            }
        }
        DLL_PROCESS_DETACH => {
            // Signal the memory scanner thread to shut down.
            SHUTDOWN_SIGNAL.store(true, Ordering::SeqCst);

            // Wait for the thread to finish.
            if let Some(handle) = SCANNER_THREAD_HANDLE.lock().unwrap().take() {
                let _ = handle.join();
            }
            
            log_event(LogEvent::Shutdown { status: "Unloading monitor DLL.".to_string() });
            
            if let Some(logger_mutex) = LOGGER.get() {
                 if let Ok(mut logger) = logger_mutex.lock() {
                     if let Some(pipe_handle) = logger.pipe.take() {
                         if pipe_handle != INVALID_HANDLE_VALUE {
                             unsafe { windows_sys::Win32::Foundation::CloseHandle(pipe_handle); }
                         }
                     }
                 }
            }
        }
        _ => {}
    }
    1 // TRUE
}