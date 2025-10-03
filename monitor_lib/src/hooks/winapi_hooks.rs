use crate::config::{LogLevel, CONFIG};
use crate::logging::{capture_stack_trace, LogEvent};
use crate::log_event;
use crate::ReentrancyGuard;
use retour::static_detour;
use serde_json::json;
use std::ffi::c_void;
use std::slice;
use std::thread;
use widestring::U16CStr;

use windows_sys::Win32::Foundation::{BOOL, HANDLE, HINSTANCE, HWND};
use windows_sys::Win32::Networking::WinSock::{
    inet_ntoa, ADDRINFOW, AF_INET, IN_ADDR, SOCKADDR, SOCKADDR_IN, SOCKET,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, DeleteFileW, WriteFile, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::IO::OVERLAPPED;
use windows_sys::Win32::System::LibraryLoader::{
    GetModuleHandleW, GetProcAddress, LoadLibraryExW, LoadLibraryW,
};
use windows_sys::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, PAGE_EXECUTE_READWRITE};
use windows_sys::Win32::System::Registry::{
    RegCreateKeyExW, RegDeleteKeyW, RegSetValueExW, HKEY,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, CreateRemoteThread, ExitProcess, OpenProcess, LPTHREAD_START_ROUTINE,
    PROCESS_INFORMATION, STARTUPINFOW, THREAD_CREATION_FLAGS, TerminateProcess,
};
use windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxW;

type HINTERNET = isize;

/// Safely converts a null-terminated UTF-16 string pointer to a Rust String.
/// Returns a placeholder if the pointer is null.
unsafe fn safe_u16_str(ptr: *const u16) -> String {
    if ptr.is_null() {
        "<null_string_ptr>".to_string()
    } else {
        U16CStr::from_ptr_str(ptr).to_string_lossy()
    }
}

/// Formats the access flags from a `CreateFileW` call into a human-readable string.
fn format_access_flags(flags: u32) -> String {
    let mut parts = Vec::new();
    if (flags & FILE_GENERIC_READ) != 0 {
        parts.push("GENERIC_READ");
    }
    if (flags & FILE_GENERIC_WRITE) != 0 {
        parts.push("GENERIC_WRITE");
    }
    if parts.is_empty() {
        format!("{:#X}", flags)
    } else {
        parts.join(" | ")
    }
}

/// Formats a preview of a byte buffer as a hexadecimal string for logging.
/// To avoid excessive memory reads, it only previews a small portion of the buffer.
unsafe fn format_buffer_preview(ptr: *const u8, len: u32) -> String {
    if ptr.is_null() {
        return "<null_buffer_ptr>".to_string();
    }
    let preview_len = std::cmp::min(32, len) as usize; // Log up to 32 bytes
    let byte_slice = slice::from_raw_parts(ptr, preview_len);
    let hex_string: Vec<String> = byte_slice.iter().map(|b| format!("{:02X}", b)).collect();
    let ellipsis = if (len as usize) > preview_len { "..." } else { "" };
    format!("[{}{}]", hex_string.join(" "), ellipsis)
}

static_detour! {
    pub static OpenProcessHook: unsafe extern "system" fn(u32, BOOL, u32) -> HANDLE;
    pub static WriteProcessMemoryHook: unsafe extern "system" fn(HANDLE, *const c_void, *const c_void, usize, *mut usize) -> BOOL;
    pub static VirtualAllocExHook: unsafe extern "system" fn(HANDLE, *const c_void, usize, u32, u32) -> *mut c_void;
    pub static CreateFileWHook: unsafe extern "system" fn(
        *const u16, u32, u32, *const SECURITY_ATTRIBUTES, u32, u32, HANDLE
    ) -> HANDLE;

    pub static WriteFileHook: unsafe extern "system" fn(
        HANDLE, *const u8, u32, *mut u32, *mut OVERLAPPED
    ) -> BOOL;

    pub static HttpSendRequestWHook: unsafe extern "system" fn(HINTERNET, *const u16, u32, *const c_void, u32) -> BOOL;
    pub static TerminateProcessHook: unsafe extern "system" fn(HANDLE, u32) -> BOOL;
    pub static NtTerminateProcessHook: unsafe extern "system" fn(HANDLE, u32) -> i32;
    pub static MessageBoxWHook: unsafe extern "system" fn(HWND, *const u16, *const u16, u32) -> i32;
    pub static CreateProcessWHook: unsafe extern "system" fn(
        *const u16, *mut u16, *const SECURITY_ATTRIBUTES, *const SECURITY_ATTRIBUTES,
        BOOL, u32, *const c_void, *const u16, *const STARTUPINFOW, *mut PROCESS_INFORMATION
    ) -> BOOL;
    pub static LoadLibraryWHook: unsafe extern "system" fn(*const u16) -> HINSTANCE;
    pub static LoadLibraryExWHook: unsafe extern "system" fn(*const u16, HANDLE, u32) -> HINSTANCE;
    pub static ConnectHook: unsafe extern "system" fn(SOCKET, *const SOCKADDR, i32) -> i32;
    pub static RegCreateKeyExWHook: unsafe extern "system" fn(
        HKEY, *const u16, u32, *const u16, u32, u32, *const SECURITY_ATTRIBUTES, *mut HKEY, *mut u32
    ) -> u32;
    pub static RegSetValueExWHook: unsafe extern "system" fn(
        HKEY, *const u16, u32, u32, *const u8, u32
    ) -> u32;
    pub static RegDeleteKeyWHook: unsafe extern "system" fn(HKEY, *const u16) -> u32;
    pub static DeleteFileWHook: unsafe extern "system" fn(*const u16) -> BOOL;
    pub static CreateRemoteThreadHook: unsafe extern "system" fn(
        HANDLE, *const SECURITY_ATTRIBUTES, usize, LPTHREAD_START_ROUTINE, *const c_void, THREAD_CREATION_FLAGS, *mut u32
    ) -> HANDLE;
    pub static GetAddrInfoWHook: unsafe extern "system" fn(
        *const u16, *const u16, *const ADDRINFOW, *mut *mut ADDRINFOW
    ) -> i32;
    pub static ExitProcessHook: unsafe extern "system" fn(u32) -> !;
}

/// Hook for `CreateFileW`. Logs the file path and desired access rights.
pub unsafe fn hooked_create_file_w(
    lp_file_name: *const u16,
    dw_desired_access: u32,
    dw_share_mode: u32,
    lp_security_attributes: *const SECURITY_ATTRIBUTES,
    dw_creation_disposition: u32,
    dw_flags_and_attributes: u32,
    h_template_file: HANDLE,
) -> HANDLE {
    if let Some(_guard) = ReentrancyGuard::new() {
        log_event(LogLevel::Info, LogEvent::ApiHook {
            function_name: "CreateFileW".to_string(),
            parameters: json!({
                "filePath": safe_u16_str(lp_file_name),
                "desiredAccess": format_access_flags(dw_desired_access),
            }),
            stack_trace: None,
        });
    }

    CreateFileWHook.call(
        lp_file_name,
        dw_desired_access,
        dw_share_mode,
        lp_security_attributes,
        dw_creation_disposition,
        dw_flags_and_attributes,
        h_template_file,
    )
}

/// Hook for `WriteFile`. Logs the number of bytes to write and a preview of the data.
pub unsafe fn hooked_write_file(
    h_file: HANDLE,
    lp_buffer: *const u8,
    n_number_of_bytes_to_write: u32,
    lp_number_of_bytes_written: *mut u32,
    lp_overlapped: *mut OVERLAPPED,
) -> BOOL {
    if let Some(_guard) = ReentrancyGuard::new() {
        log_event(LogLevel::Info, LogEvent::ApiHook {
            function_name: "WriteFile".to_string(),
            parameters: json!({
                "bytesToWrite": n_number_of_bytes_to_write,
                "dataPreview": format_buffer_preview(lp_buffer, n_number_of_bytes_to_write),
            }),
            stack_trace: None,
        });
    }

    WriteFileHook.call(
        h_file,
        lp_buffer,
        n_number_of_bytes_to_write,
        lp_number_of_bytes_written,
        lp_overlapped,
    )
}

pub fn hooked_exit_process(u_exit_code: u32) -> ! {
    let stack_trace = Some(capture_stack_trace(CONFIG.stack_trace_frame_limit));
    log_event(LogLevel::Fatal, LogEvent::ApiHook {
        function_name: "ExitProcess".to_string(),
        parameters: json!({
            "exit_code": u_exit_code,
            "action": "Termination blocked. The process will hang instead of exiting."
        }),
        stack_trace,
    });

    // This function must not return to properly emulate ExitProcess.
    // We loop indefinitely to prevent the process from exiting.
    loop {
        thread::sleep(std::time::Duration::from_secs(3600));
    }
}

pub fn hooked_terminate_process(h_process: HANDLE, u_exit_code: u32) -> BOOL {
    let stack_trace = Some(capture_stack_trace(CONFIG.stack_trace_frame_limit));
    log_event(LogLevel::Fatal, LogEvent::ApiHook {
        function_name: "TerminateProcess".to_string(),
        parameters: json!({
            "process_handle": format!("{:?}", h_process),
            "exit_code": u_exit_code,
            "action": "Termination blocked. Returning FALSE."
        }),
        stack_trace,
    });

    0 // Return FALSE to indicate that termination failed.
}

pub fn hooked_nt_terminate_process(h_process: HANDLE, exit_status: u32) -> i32 {
    let stack_trace = Some(capture_stack_trace(CONFIG.stack_trace_frame_limit));
    log_event(LogLevel::Fatal, LogEvent::ApiHook {
        function_name: "NtTerminateProcess".to_string(),
        parameters: json!({
            "process_handle": format!("{:?}", h_process),
            "exit_status": exit_status,
            "action": "Termination blocked. Returning STATUS_ACCESS_DENIED."
        }),
        stack_trace,
    });

    0xC0000022u32 as i32 // STATUS_ACCESS_DENIED
}

pub fn hooked_http_send_request_w(
    h_request: HINTERNET,
    lpsz_headers: *const u16,
    dw_headers_length: u32,
    lp_optional: *const c_void,
    dw_optional_length: u32,
) -> BOOL {
    let headers = unsafe { safe_u16_str(lpsz_headers) };
    log_event(LogLevel::Info, LogEvent::ApiHook {
        function_name: "HttpSendRequestW".to_string(),
        parameters: json!({
            "headers": headers,
            "headers_length": dw_headers_length,
            "optional_data_length": dw_optional_length,
        }),
        stack_trace: None,
    });

    unsafe {
        HttpSendRequestWHook.call(
            h_request,
            lpsz_headers,
            dw_headers_length,
            lp_optional,
            dw_optional_length,
        )
    }
}

pub fn hooked_get_addr_info_w(
    p_node_name: *const u16,
    p_service_name: *const u16,
    p_hints: *const ADDRINFOW,
    pp_result: *mut *mut ADDRINFOW,
) -> i32 {
    let node_name = unsafe { safe_u16_str(p_node_name) };
    let service_name = unsafe { safe_u16_str(p_service_name) };
    log_event(LogLevel::Debug, LogEvent::ApiHook {
        function_name: "GetAddrInfoW".to_string(),
        parameters: json!({ "node_name": node_name, "service_name": service_name }),
        stack_trace: None,
    });
    unsafe { GetAddrInfoWHook.call(p_node_name, p_service_name, p_hints, pp_result) }
}

pub fn hooked_message_box_w(h_wnd: HWND, text: *const u16, caption: *const u16, u_type: u32) -> i32 {
    let text_str = unsafe { safe_u16_str(text) };
    let caption_str = unsafe { safe_u16_str(caption) };
    log_event(LogLevel::Debug, LogEvent::ApiHook {
        function_name: "MessageBoxW".to_string(),
        parameters: json!({ "title": caption_str, "text": text_str, "type": u_type }),
        stack_trace: None,
    });
    unsafe { MessageBoxWHook.call(h_wnd, text, caption, u_type) }
}

pub fn hooked_connect(s: SOCKET, name: *const SOCKADDR, namelen: i32) -> i32 {
    if !name.is_null() && namelen as u32 >= std::mem::size_of::<SOCKADDR_IN>() as u32 {
        let sockaddr_in = unsafe { *(name as *const SOCKADDR_IN) };
        if sockaddr_in.sin_family == AF_INET as u16 {
            let ip_addr_long = unsafe { sockaddr_in.sin_addr.S_un.S_addr };
            let port = u16::from_be(sockaddr_in.sin_port);
            let ip_str = unsafe {
                let addr = IN_ADDR {
                    S_un: std::mem::transmute([ip_addr_long]),
                };
                let c_str = inet_ntoa(addr);
                if c_str.is_null() {
                    "Invalid IP".to_string()
                } else {
                    std::ffi::CStr::from_ptr(c_str as *const i8)
                        .to_string_lossy()
                        .into_owned()
                }
            };
            log_event(LogLevel::Debug, LogEvent::ApiHook {
                function_name: "connect".to_string(),
                parameters: json!({ "target_ip": ip_str, "port": port }),
                stack_trace: None,
            });
        }
    }
    unsafe { ConnectHook.call(s, name, namelen) }
}

fn hkey_to_string(hkey: HKEY) -> String {
    match hkey {
        0x80000000 => "HKEY_CLASSES_ROOT".to_string(),
        0x80000001 => "HKEY_CURRENT_USER".to_string(),
        0x80000002 => "HKEY_LOCAL_MACHINE".to_string(),
        0x80000003 => "HKEY_USERS".to_string(),
        _ => format!("Unknown HKEY ({:?})", hkey),
    }
}

pub fn hooked_reg_create_key_ex_w(
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
    let sub_key = unsafe { safe_u16_str(lp_sub_key) };
    log_event(LogLevel::Debug, LogEvent::ApiHook {
        function_name: "RegCreateKeyExW".to_string(),
        parameters: json!({ "path": format!("{}\\{}", hkey_to_string(hkey), sub_key) }),
        stack_trace: None,
    });
    unsafe {
        RegCreateKeyExWHook.call(
            hkey,
            lp_sub_key,
            _reserved,
            lp_class,
            dw_options,
            sam_desired,
            lp_security_attributes,
            phk_result,
            lpdw_disposition,
        )
    }
}

pub fn hooked_reg_set_value_ex_w(
    hkey: HKEY,
    lp_value_name: *const u16,
    _reserved: u32,
    dw_type: u32,
    lp_data: *const u8,
    cb_data: u32,
) -> u32 {
    let value_name = unsafe { safe_u16_str(lp_value_name) };
    log_event(LogLevel::Debug, LogEvent::ApiHook {
        function_name: "RegSetValueExW".to_string(),
        parameters: json!({ "key": hkey_to_string(hkey), "value_name": value_name, "type": dw_type, "bytes": cb_data }),
        stack_trace: None,
    });
    unsafe { RegSetValueExWHook.call(hkey, lp_value_name, _reserved, dw_type, lp_data, cb_data) }
}

pub fn hooked_reg_delete_key_w(hkey: HKEY, lp_sub_key: *const u16) -> u32 {
    let sub_key = unsafe { safe_u16_str(lp_sub_key) };
    log_event(LogLevel::Debug, LogEvent::ApiHook {
        function_name: "RegDeleteKeyW".to_string(),
        parameters: json!({ "path": format!("{}\\{}", hkey_to_string(hkey), sub_key) }),
        stack_trace: None,
    });
    unsafe { RegDeleteKeyWHook.call(hkey, lp_sub_key) }
}

pub fn hooked_delete_file_w(lp_file_name: *const u16) -> BOOL {
    let file_name = unsafe { safe_u16_str(lp_file_name) };
    log_event(LogLevel::Debug, LogEvent::ApiHook {
        function_name: "DeleteFileW".to_string(),
        parameters: json!({ "file_name": file_name }),
        stack_trace: None,
    });
    unsafe { DeleteFileWHook.call(lp_file_name) }
}

pub unsafe fn hooked_open_process(
    dw_desired_access: u32,
    b_inherit_handle: BOOL,
    dw_process_id: u32,
) -> HANDLE {
    log_event(LogLevel::Warn, LogEvent::ApiHook {
        function_name: "OpenProcess".to_string(),
        parameters: json!({
            "target_pid": dw_process_id,
            "desired_access": dw_desired_access,
        }),
        stack_trace: None,
    });
    OpenProcessHook.call(dw_desired_access, b_inherit_handle, dw_process_id)
}

pub unsafe fn hooked_write_process_memory(
    h_process: HANDLE,
    lp_base_address: *const c_void,
    lp_buffer: *const c_void,
    n_size: usize,
    lp_number_of_bytes_written: *mut usize,
) -> BOOL {
    log_event(LogLevel::Warn, LogEvent::ApiHook {
        function_name: "WriteProcessMemory".to_string(),
        parameters: json!({
            "target_process_handle": h_process as usize,
            "base_address": lp_base_address as usize,
            "size": n_size,
            "data_preview": format_buffer_preview(lp_buffer as *const u8, n_size as u32),
        }),
        stack_trace: None,
    });
    WriteProcessMemoryHook.call(
        h_process,
        lp_base_address,
        lp_buffer,
        n_size,
        lp_number_of_bytes_written,
    )
}

pub unsafe fn hooked_virtual_alloc_ex(
    h_process: HANDLE,
    lp_address: *const c_void,
    dw_size: usize,
    fl_allocation_type: u32,
    fl_protect: u32,
) -> *mut c_void {
    // Log only potentially suspicious allocations
    if (fl_allocation_type & MEM_COMMIT != 0) && (fl_protect & PAGE_EXECUTE_READWRITE != 0) {
        log_event(LogLevel::Warn, LogEvent::ApiHook {
            function_name: "VirtualAllocEx".to_string(),
            parameters: json!({
                "target_process_handle": h_process as usize,
                "size": dw_size,
                "protection": "PAGE_EXECUTE_READWRITE",
            }),
            stack_trace: None,
        });
    }
    VirtualAllocExHook.call(
        h_process,
        lp_address,
        dw_size,
        fl_allocation_type,
        fl_protect,
    )
}

pub fn hooked_create_remote_thread(
    h_process: HANDLE,
    lp_thread_attributes: *const SECURITY_ATTRIBUTES,
    dw_stack_size: usize,
    lp_start_address: LPTHREAD_START_ROUTINE,
    lp_parameter: *const c_void,
    dw_creation_flags: THREAD_CREATION_FLAGS,
    lp_thread_id: *mut u32,
) -> HANDLE {
    let start_address_val = lp_start_address.map_or(0, |f| f as usize);
    log_event(LogLevel::Warn, LogEvent::ApiHook {
        function_name: "CreateRemoteThread".to_string(),
        parameters: json!({ "target_process_handle": h_process as usize, "start_address": start_address_val }),
        stack_trace: None,
    });
    unsafe {
        CreateRemoteThreadHook.call(
            h_process,
            lp_thread_attributes,
            dw_stack_size,
            lp_start_address,
            lp_parameter,
            dw_creation_flags,
            lp_thread_id,
        )
    }
}

pub fn hooked_load_library_w(lp_lib_file_name: *const u16) -> HINSTANCE {
    let lib_name = unsafe { safe_u16_str(lp_lib_file_name) };
    log_event(LogLevel::Debug, LogEvent::ApiHook {
        function_name: "LoadLibraryW".to_string(),
        parameters: json!({ "library_name": lib_name }),
        stack_trace: None,
    });
    unsafe { LoadLibraryWHook.call(lp_lib_file_name) }
}

pub fn hooked_load_library_ex_w(
    lp_lib_file_name: *const u16,
    h_file: HANDLE,
    dw_flags: u32,
) -> HINSTANCE {
    let lib_name = unsafe { safe_u16_str(lp_lib_file_name) };
    log_event(LogLevel::Debug, LogEvent::ApiHook {
        function_name: "LoadLibraryExW".to_string(),
        parameters: json!({ "library_name": lib_name, "flags": dw_flags }),
        stack_trace: None,
    });
    unsafe { LoadLibraryExWHook.call(lp_lib_file_name, h_file, dw_flags) }
}

pub fn hooked_create_process_w(
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
    let app_name = unsafe { safe_u16_str(lp_application_name) };
    let cmd_line = unsafe { safe_u16_str(lp_command_line) };
    log_event(LogLevel::Warn, LogEvent::ApiHook {
        function_name: "CreateProcessW".to_string(),
        parameters: json!({ "application_name": app_name, "command_line": cmd_line }),
        stack_trace: None,
    });
    unsafe {
        CreateProcessWHook.call(
            lp_application_name,
            lp_command_line,
            lp_process_attributes,
            lp_thread_attributes,
            b_inherit_handles,
            dw_creation_flags,
            lp_environment,
            lp_current_directory,
            lp_startup_info,
            lp_process_information,
        )
    }
}

macro_rules! hook {
    ($hook:ident, $func:expr, $hook_fn:expr) => {
        let func_name = stringify!($func);
        $hook
            .initialize($func, $hook_fn)
            .and_then(|_| $hook.enable())
            .map_err(|e| {
                let msg = format!("Failed to hook {}: {}", func_name, e);
                log_event(
                    LogLevel::Error,
                    LogEvent::Error {
                        source: "Initialization".to_string(),
                        message: msg.clone(),
                    },
                );
                msg
            })?
    };
}

pub unsafe fn initialize_all_hooks() -> Result<(), String> {
    // Hook critical process termination functions.
    let exit_process_ptr: unsafe extern "system" fn(u32) -> ! =
        std::mem::transmute(ExitProcess as *const ());
    hook!(ExitProcessHook, exit_process_ptr, hooked_exit_process);

    let terminate_process_ptr: unsafe extern "system" fn(HANDLE, u32) -> BOOL =
        std::mem::transmute(TerminateProcess as *const ());
    hook!(
        TerminateProcessHook,
        terminate_process_ptr,
        hooked_terminate_process
    );

    hook!(CreateFileWHook, CreateFileW, |a, b, c, d, e, f, g| {
        hooked_create_file_w(a, b, c, d, e, f, g)
    });
    hook!(WriteFileHook, WriteFile, |a, b, c, d, e| {
        hooked_write_file(a, b, c, d, e)
    });
    hook!(CreateProcessWHook, CreateProcessW, hooked_create_process_w);
    hook!(MessageBoxWHook, MessageBoxW, hooked_message_box_w);

    // Hook process interaction functions
    hook!(OpenProcessHook, OpenProcess, |a, b, c| {
        hooked_open_process(a, b, c)
    });
    hook!(
        WriteProcessMemoryHook,
        WriteProcessMemory,
        |a, b, c, d, e| hooked_write_process_memory(a, b, c, d, e)
    );
    hook!(
        VirtualAllocExHook,
        VirtualAllocEx,
        |a, b, c, d, e| hooked_virtual_alloc_ex(a, b, c, d, e)
    );

    // Hook library loading functions.
    hook!(LoadLibraryWHook, LoadLibraryW, hooked_load_library_w);
    hook!(LoadLibraryExWHook, LoadLibraryExW, hooked_load_library_ex_w);

    // Hook registry functions.
    hook!(
        RegCreateKeyExWHook,
        RegCreateKeyExW,
        hooked_reg_create_key_ex_w
    );
    hook!(
        RegSetValueExWHook,
        RegSetValueExW,
        hooked_reg_set_value_ex_w
    );
    hook!(RegDeleteKeyWHook, RegDeleteKeyW, hooked_reg_delete_key_w);
    hook!(DeleteFileWHook, DeleteFileW, hooked_delete_file_w);

    // Hook thread creation.
    hook!(
        CreateRemoteThreadHook,
        CreateRemoteThread,
        hooked_create_remote_thread
    );

    initialize_dynamic_hooks()?;

    Ok(())
}

unsafe fn initialize_dynamic_hooks() -> Result<(), String> {
    macro_rules! hook {
        ($hook:ident, $func:expr, $hook_fn:expr) => {
            let func_name = stringify!($func);
            $hook
                .initialize($func, $hook_fn)
                .and_then(|_| $hook.enable())
                .map_err(|e| {
                    let msg = format!("Failed to hook {}: {}", func_name, e);
                    log_event(
                        LogLevel::Error,
                        LogEvent::Error {
                            source: "Initialization".to_string(),
                            message: msg.clone(),
                        },
                    );
                    msg
                })?
        };
    }

    let ws2_32_name: Vec<u16> = "ws2_32.dll".encode_utf16().chain(std::iter::once(0)).collect();
    let ws2_32 = GetModuleHandleW(ws2_32_name.as_ptr());
    if ws2_32 != 0 {
        if let Some(addr) = GetProcAddress(ws2_32, b"connect\0".as_ptr()) {
            hook!(ConnectHook, std::mem::transmute(addr), hooked_connect);
        }
        if let Some(addr) = GetProcAddress(ws2_32, b"GetAddrInfoW\0".as_ptr()) {
            hook!(
                GetAddrInfoWHook,
                std::mem::transmute(addr),
                hooked_get_addr_info_w
            );
        }
    }

    let ntdll_name: Vec<u16> = "ntdll.dll".encode_utf16().chain(std::iter::once(0)).collect();
    let ntdll = GetModuleHandleW(ntdll_name.as_ptr());
    if ntdll != 0 {
        if let Some(addr) = GetProcAddress(ntdll, b"NtTerminateProcess\0".as_ptr()) {
            hook!(
                NtTerminateProcessHook,
                std::mem::transmute(addr),
                hooked_nt_terminate_process
            );
        }
    }

    let wininet_name: Vec<u16> = "wininet.dll".encode_utf16().chain(std::iter::once(0)).collect();
    let wininet = GetModuleHandleW(wininet_name.as_ptr());
    if wininet != 0 {
        if let Some(addr) = GetProcAddress(wininet, b"HttpSendRequestW\0".as_ptr()) {
            hook!(
                HttpSendRequestWHook,
                std::mem::transmute(addr),
                hooked_http_send_request_w
            );
        }
    }
    Ok(())
}