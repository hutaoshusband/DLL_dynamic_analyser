// Copyright (c) 2024 HUTAOSHUSBAND - Wallbangbros.com/CodeConfuser.dev
// All rights reserved.


use shared::logging::{LogLevel, LogEvent};
use crate::config::CONFIG;
use crate::logging::capture_stack_trace;
use crate::{log_event, SUSPICION_SCORE};
use crate::ReentrancyGuard;
use once_cell::sync::Lazy;
use std::sync::atomic::Ordering;
use retour::static_detour;
use serde_json::json;
use std::ffi::c_void;
use std::slice;
use std::sync::Mutex;
use std::path::Path;
use std::time::{Duration, Instant};
use widestring::U16CStr;

// The AllocInfo struct and ALLOCATED_REGIONS static are now managed by the vmp_dumper module.

use windows_sys::Win32::Foundation::{BOOL, HANDLE, HINSTANCE, HWND};
use windows_sys::Win32::Networking::WinSock::{
    inet_ntoa, ADDRINFOW, AF_INET, IN_ADDR, SOCKADDR, SOCKADDR_IN, SOCKET, WSABUF,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, DeleteFileW, WriteFile, FILE_GENERIC_READ, FILE_GENERIC_WRITE, CopyFileW, MoveFileW, GetTempPathW, GetTempFileNameW, FindFirstFileW, FindNextFileW,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessA, QueueUserAPC, WinExec,
};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, CheckRemoteDebuggerPresent, IsDebuggerPresent,
    PVECTORED_EXCEPTION_HANDLER, OutputDebugStringA,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::IO::OVERLAPPED;
use windows_sys::Win32::System::LibraryLoader::{
    GetModuleHandleW, GetProcAddress, LoadLibraryExW, LoadLibraryW,
};
// use windows_sys::Win32::System::Memory::VirtualAllocEx;
use windows_sys::Win32::System::Registry::{
    RegCreateKeyExW, RegDeleteKeyW, RegSetValueExW, HKEY, RegOpenKeyExW, RegQueryValueExW, RegEnumKeyExW, RegEnumValueW
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, CreateRemoteThread, CreateThread, ExitProcess, OpenProcess,
    LPTHREAD_START_ROUTINE, PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW, STARTUPINFOW, THREAD_CREATION_FLAGS, TerminateProcess,
};
use windows_sys::Win32::System::SystemInformation::GetTickCount;
use windows_sys::Win32::System::Performance::QueryPerformanceCounter;
use windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxW;

type HINTERNET = isize;
type NTSTATUS = i32;
type PROCESSINFOCLASS = u32;
type HCRYPTKEY = usize;
type HCRYPTHASH = usize;

static LAST_IS_DEBUGGER_PRESENT_LOG: Lazy<Mutex<Option<Instant>>> =
    Lazy::new(|| Mutex::new(None));
static LAST_PROCESS_ENUM_LOG: Lazy<Mutex<Option<Instant>>> = Lazy::new(|| Mutex::new(None));
static LAST_WRITE_FILE_LOG: Lazy<Mutex<Option<Instant>>> = Lazy::new(|| Mutex::new(None));
static LAST_GET_TICK_COUNT_LOG: Lazy<Mutex<Option<Instant>>> = Lazy::new(|| Mutex::new(None));
static LAST_QUERY_PERF_COUNTER_LOG: Lazy<Mutex<Option<Instant>>> = Lazy::new(|| Mutex::new(None));


const GENERIC_LOG_COOLDOWN: Duration = Duration::from_secs(5);

/// Safely converts a null-terminated UTF-16 string pointer to a Rust String.
/// Returns a placeholder if the pointer is null.
unsafe fn safe_u16_str(ptr: *const u16) -> String {
    if ptr.is_null() {
        "<null_string_ptr>".to_string()
    } else {
        U16CStr::from_ptr_str(ptr).to_string_lossy()
    }
}

/// Safely converts a null-terminated UTF-8 string pointer to a Rust String.
/// Returns a placeholder if the pointer is null.
unsafe fn safe_u8_str(ptr: *const u8) -> String {
    if ptr.is_null() {
        "<null_string_ptr>".to_string()
    } else {
        // Treat the *const u8 as a C-style string.
        std::ffi::CStr::from_ptr(ptr as *const i8)
            .to_string_lossy()
            .into_owned()
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
    pub static RegOpenKeyExWHook: unsafe extern "system" fn(HKEY, *const u16, u32, u32, *mut HKEY) -> u32;
    pub static RegQueryValueExWHook: unsafe extern "system" fn(HKEY, *const u16, *const u32, *mut u32, *mut u8, *mut u32) -> u32;
    pub static RegEnumKeyExWHook: unsafe extern "system" fn(HKEY, u32, *mut u16, *mut u32, *const u32, *mut u16, *mut u32, *mut windows_sys::Win32::Foundation::FILETIME) -> u32;
    pub static RegEnumValueWHook: unsafe extern "system" fn(HKEY, u32, *mut u16, *mut u32, *const u32, *mut u32, *mut u8, *mut u32) -> u32;
    pub static DeleteFileWHook: unsafe extern "system" fn(*const u16) -> BOOL;
    pub static CreateRemoteThreadHook: unsafe extern "system" fn(
        HANDLE, *const SECURITY_ATTRIBUTES, usize, LPTHREAD_START_ROUTINE, *const c_void, THREAD_CREATION_FLAGS, *mut u32
    ) -> HANDLE;
    pub static GetAddrInfoWHook: unsafe extern "system" fn(
        *const u16, *const u16, *const ADDRINFOW, *mut *mut ADDRINFOW
    ) -> i32;
    pub static IsDebuggerPresentHook: unsafe extern "system" fn() -> BOOL;
    pub static CheckRemoteDebuggerPresentHook: unsafe extern "system" fn(HANDLE, *mut BOOL) -> BOOL;
    pub static NtQueryInformationProcessHook: unsafe extern "system" fn(HANDLE, PROCESSINFOCLASS, *mut c_void, u32, *mut u32) -> NTSTATUS;
    pub static CreateToolhelp32SnapshotHook: unsafe extern "system" fn(u32, u32) -> HANDLE;
    pub static Process32FirstWHook: unsafe extern "system" fn(HANDLE, *mut PROCESSENTRY32W) -> BOOL;
    pub static Process32NextWHook: unsafe extern "system" fn(HANDLE, *mut PROCESSENTRY32W) -> BOOL;
    pub static ExitProcessHook: unsafe extern "system" fn(u32) -> !;
    pub static GetTickCountHook: unsafe extern "system" fn() -> u32;
    pub static QueryPerformanceCounterHook: unsafe extern "system" fn(*mut i64) -> BOOL;
    pub static OutputDebugStringAHook: unsafe extern "system" fn(*const u8);


    // New hooks for VMP analysis
    pub static AddVectoredExceptionHandlerHook: unsafe extern "system" fn(u32, PVECTORED_EXCEPTION_HANDLER) -> *mut c_void;
    pub static CreateThreadHook: unsafe extern "system" fn(
        *const SECURITY_ATTRIBUTES, usize, LPTHREAD_START_ROUTINE,
        *const c_void, u32, *mut u32
    ) -> HANDLE;
    pub static FreeLibraryHook: unsafe extern "system" fn(HINSTANCE) -> BOOL;
    pub static CryptEncryptHook: unsafe extern "system" fn(
        HCRYPTKEY, HCRYPTHASH, BOOL, u32, *mut u8, *mut u32, u32
    ) -> BOOL;
    pub static CryptDecryptHook: unsafe extern "system" fn(
        HCRYPTKEY, HCRYPTHASH, BOOL, u32, *mut u8, *mut u32
    ) -> BOOL;

    // C2 Detection Hooks
    pub static WSASendHook: unsafe extern "system" fn(SOCKET, *const WSABUF, u32, *mut u32, u32, *mut OVERLAPPED, LpwsaOverlappedCompletionRoutine) -> i32;
    pub static WSARecvHook: unsafe extern "system" fn(SOCKET, *const WSABUF, u32, *mut u32, *mut u32, *mut OVERLAPPED, LpwsaOverlappedCompletionRoutine) -> i32;
    pub static SendHook: unsafe extern "system" fn(SOCKET, *const u8, i32, i32) -> i32;
    pub static RecvHook: unsafe extern "system" fn(SOCKET, *mut u8, i32, i32) -> i32;
    pub static InternetOpenWHook: unsafe extern "system" fn(*const u16, u32, *const u16, *const u16, u32) -> HINTERNET;
    pub static InternetConnectWHook: unsafe extern "system" fn(HINTERNET, *const u16, u16, *const u16, *const u16, u32, u32, usize) -> HINTERNET;
    pub static HttpOpenRequestWHook: unsafe extern "system" fn(HINTERNET, *const u16, *const u16, *const u16, *const u16, *const *const u16, u32, usize) -> HINTERNET;
    pub static InternetReadFileHook: unsafe extern "system" fn(HINTERNET, *mut c_void, u32, *mut u32) -> BOOL;
    pub static DnsQuery_AHook: unsafe extern "system" fn(*const u8, u16, u32, *const c_void, *mut *mut c_void, *mut *mut c_void) -> NTSTATUS;
    pub static DnsQuery_WHook: unsafe extern "system" fn(*const u16, u16, u32, *const c_void, *mut *mut c_void, *mut *mut c_void) -> NTSTATUS;
    pub static CertVerifyCertificateChainPolicyHook: unsafe extern "system" fn(i32, *const c_void, *const c_void, *mut c_void) -> BOOL;
    pub static CryptHashDataHook: unsafe extern "system" fn(HCRYPTHASH, *const u8, u32, u32) -> BOOL;

    // Broader Feature Hooks
    pub static CopyFileWHook: unsafe extern "system" fn(*const u16, *const u16, BOOL) -> BOOL;
    pub static MoveFileWHook: unsafe extern "system" fn(*const u16, *const u16) -> BOOL;
    pub static GetTempPathWHook: unsafe extern "system" fn(u32, *mut u16) -> u32;
    pub static GetTempFileNameWHook: unsafe extern "system" fn(*const u16, *const u16, u32, *mut u16) -> u32;
    pub static FindFirstFileWHook: unsafe extern "system" fn(*const u16, *mut windows_sys::Win32::Storage::FileSystem::WIN32_FIND_DATAW) -> HANDLE;
    pub static FindNextFileWHook: unsafe extern "system" fn(HANDLE, *mut windows_sys::Win32::Storage::FileSystem::WIN32_FIND_DATAW) -> BOOL;
    pub static NtCreateThreadExHook: unsafe extern "system" fn(*mut HANDLE, u32, *const c_void, HANDLE, *const c_void, *const c_void, BOOL, usize, usize, usize, *const c_void) -> NTSTATUS;
    pub static QueueUserAPCHook: unsafe extern "system" fn(Option<unsafe extern "system" fn(usize)>, HANDLE, usize) -> u32;
    pub static SetThreadContextHook: unsafe extern "system" fn(HANDLE, *const windows_sys::Win32::System::Diagnostics::Debug::CONTEXT) -> BOOL;
    pub static WinExecHook: unsafe extern "system" fn(*const u8, u32) -> u32;
    pub static SystemHook: unsafe extern "system" fn(*const i8) -> i32;
    pub static ShellExecuteWHook: unsafe extern "system" fn(HWND, *const u16, *const u16, *const u16, *const u16, i32) -> HINSTANCE;
    pub static ShellExecuteExWHook: unsafe extern "system" fn(*mut c_void) -> BOOL;
    pub static CreateProcessAHook: unsafe extern "system" fn(*const u8, *mut u8, *const SECURITY_ATTRIBUTES, *const SECURITY_ATTRIBUTES, BOOL, u32, *const c_void, *const u8, *const windows_sys::Win32::System::Threading::STARTUPINFOA, *mut PROCESS_INFORMATION) -> BOOL;
}

// Type definitions for function pointers and structs that might be missing or complex.
type LpwsaOverlappedCompletionRoutine = Option<unsafe extern "system" fn(u32, u32, *mut OVERLAPPED, u32)>;

pub fn hooked_is_debugger_present() -> BOOL {
    let should_log = {
        let mut last_log_time = LAST_IS_DEBUGGER_PRESENT_LOG.lock().unwrap();
        if let Some(last_time) = *last_log_time {
            if last_time.elapsed() < GENERIC_LOG_COOLDOWN {
                false
            } else {
                *last_log_time = Some(Instant::now());
                true
            }
        } else {
            *last_log_time = Some(Instant::now());
            true
        }
    };

    if should_log {
        if let Some(_guard) = ReentrancyGuard::new() {
            SUSPICION_SCORE.fetch_add(1, Ordering::Relaxed);
            log_event(
                LogLevel::Warn,
                LogEvent::AntiDebugCheck {
                    function_name: "IsDebuggerPresent".to_string(),
                    parameters: json!({
                        "note": "Anti-debugging check detected. Returning FALSE.",
                    }),
                    stack_trace: Some(capture_stack_trace(CONFIG.stack_trace_frame_limit)),
                },
            );
        }
    }

    // notice by HUTAOSHUSBAND on 2025-12-10
    // For safety/integrity, we now default to monitoring only.
    // Lying about debugger presence can break application logic or cause integrity checks to fail.
    let result = unsafe { IsDebuggerPresentHook.call() };
    
    // Optional: If you strictly want to hide the debugger, you could return 0.
    // But for analysis safety, we pass the real value.
    // return 0; 
    result
}

pub unsafe fn hooked_check_remote_debugger_present(
    h_process: HANDLE,
    pb_is_debugger_present: *mut BOOL,
) -> BOOL {
    if let Some(_guard) = ReentrancyGuard::new() {
        SUSPICION_SCORE.fetch_add(1, Ordering::Relaxed);
        log_event(
            LogLevel::Warn,
            LogEvent::AntiDebugCheck {
                function_name: "CheckRemoteDebuggerPresent".to_string(),
                parameters: json!({
                    "process_handle": h_process as usize,
                    "note": "Anti-debugging check detected. Returning FALSE.",
                }),
                stack_trace: Some(capture_stack_trace(CONFIG.stack_trace_frame_limit)),
            },
        );
    }

    // Safe Mode: Call original verify logic instead of lying.
    CheckRemoteDebuggerPresentHook.call(h_process, pb_is_debugger_present)
}

pub unsafe fn hooked_nt_query_information_process(
    process_handle: HANDLE,
    process_information_class: PROCESSINFOCLASS,
    process_information: *mut c_void,
    process_information_length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    const PROCESS_DEBUG_PORT: u32 = 7;
    if process_information_class == PROCESS_DEBUG_PORT {
        if let Some(_guard) = ReentrancyGuard::new() {
            SUSPICION_SCORE.fetch_add(2, Ordering::Relaxed);
            log_event(
                LogLevel::Warn,
                LogEvent::AntiDebugCheck {
                    function_name: "NtQueryInformationProcess".to_string(),
                    parameters: json!({
                        "process_handle": process_handle as usize,
                        "class": "ProcessDebugPort",
                        "note": "Anti-debugging check detected. Modifying return value.",
                    }),
                    stack_trace: Some(capture_stack_trace(CONFIG.stack_trace_frame_limit)),
                },
            );
        }
        // Safe Mode: We log the check but do not interfere with the return value.
        // Lying here often breaks the target's internal logic or injection chains.
    }

    NtQueryInformationProcessHook.call(
        process_handle,
        process_information_class,
        process_information,
        process_information_length,
        return_length,
    )
}

pub fn hooked_get_tick_count() -> u32 {
    let should_log = {
        let mut last_log_time = LAST_GET_TICK_COUNT_LOG.lock().unwrap();
        if let Some(last_time) = *last_log_time {
            if last_time.elapsed() < GENERIC_LOG_COOLDOWN {
                false
            } else {
                *last_log_time = Some(Instant::now());
                true
            }
        } else {
            *last_log_time = Some(Instant::now());
            true
        }
    };

    if should_log {
        if let Some(_guard) = ReentrancyGuard::new() {
            SUSPICION_SCORE.fetch_add(1, Ordering::Relaxed);
            SUSPICION_SCORE.fetch_add(1, Ordering::Relaxed);
            log_event(
                LogLevel::Info,
                LogEvent::AntiDebugCheck {
                    function_name: "GetTickCount".to_string(),
                    parameters: json!({
                        "note": "Frequent timing check, potential anti-debugging or performance measurement.",
                        "log_type": "(Rate-limited log)"
                    }),
                    stack_trace: Some(capture_stack_trace(CONFIG.stack_trace_frame_limit)),
                },
            );
        }
    }

    unsafe { GetTickCountHook.call() }
}

pub unsafe fn hooked_query_performance_counter(lp_performance_count: *mut i64) -> BOOL {
    let should_log = {
        let mut last_log_time = LAST_QUERY_PERF_COUNTER_LOG.lock().unwrap();
        if let Some(last_time) = *last_log_time {
            if last_time.elapsed() < GENERIC_LOG_COOLDOWN {
                false
            } else {
                *last_log_time = Some(Instant::now());
                true
            }
        } else {
            *last_log_time = Some(Instant::now());
            true
        }
    };

    if should_log {
        if let Some(_guard) = ReentrancyGuard::new() {
            log_event(
                LogLevel::Info,
                LogEvent::AntiDebugCheck {
                    function_name: "QueryPerformanceCounter".to_string(),
                    parameters: json!({
                        "note": "Frequent timing check, potential anti-debugging or performance measurement.",
                        "log_type": "(Rate-limited log)"
                    }),
                    stack_trace: Some(capture_stack_trace(CONFIG.stack_trace_frame_limit)),
                },
            );
        }
    }

    QueryPerformanceCounterHook.call(lp_performance_count)
}

pub unsafe fn hooked_output_debug_string_a(lp_output_string: *const u8) {
    if let Some(_guard) = ReentrancyGuard::new() {
        SUSPICION_SCORE.fetch_add(1, Ordering::Relaxed);
        log_event(
            LogLevel::Info,
            LogEvent::AntiDebugCheck {
                function_name: "OutputDebugStringA".to_string(),
                parameters: json!({
                    "output_string": safe_u8_str(lp_output_string),
                    "note": "Attempt to communicate with a debugger.",
                }),
                stack_trace: None,
            },
        );
    }

    // Call the original function to maintain normal behavior if a debugger is attached.
    OutputDebugStringAHook.call(lp_output_string);
}

pub unsafe fn hooked_create_toolhelp32_snapshot(dw_flags: u32, th32_process_id: u32) -> HANDLE {
    if dw_flags == TH32CS_SNAPPROCESS {
        log_event(
            LogLevel::Info,
            LogEvent::ProcessEnumeration {
                function_name: "CreateToolhelp32Snapshot".to_string(),
                parameters: json!({ "flags": "TH32CS_SNAPPROCESS" }),
            },
        );
    }
    CreateToolhelp32SnapshotHook.call(dw_flags, th32_process_id)
}

pub unsafe fn hooked_process32_first_w(h_snapshot: HANDLE, lppe: *mut PROCESSENTRY32W) -> BOOL {
    let should_log = {
        let mut last_log_time = LAST_PROCESS_ENUM_LOG.lock().unwrap();
        if let Some(last_time) = *last_log_time {
            if last_time.elapsed() < GENERIC_LOG_COOLDOWN {
                false
            } else {
                *last_log_time = Some(Instant::now());
                true
            }
        } else {
            *last_log_time = Some(Instant::now());
            true
        }
    };

    if should_log {
        log_event(
            LogLevel::Info,
            LogEvent::ProcessEnumeration {
                function_name: "Process32FirstW".to_string(),
                parameters: json!({ "note": "Process enumeration started (rate-limited log)." }),
            },
        );
    }
    Process32FirstWHook.call(h_snapshot, lppe)
}

pub unsafe fn hooked_process32_next_w(h_snapshot: HANDLE, lppe: *mut PROCESSENTRY32W) -> BOOL {
    // This hook is called repeatedly in a loop. We use the same rate limiter
    // as Process32FirstW to avoid spamming the log. A single message from
    // Process32FirstW is enough to indicate that enumeration is happening.
    Process32NextWHook.call(h_snapshot, lppe)
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
        log_event(
            LogLevel::Info,
            LogEvent::ApiHook {
                function_name: "CreateFileW".to_string(),
                parameters: json!({
                    "filePath": safe_u16_str(lp_file_name),
                    "desiredAccess": format_access_flags(dw_desired_access),
                }),
                stack_trace: None,
            },
        );
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
    // Rate limit logging for WriteFile to avoid spam, especially from logging itself.
    let should_log = {
        let mut last_log_time = LAST_WRITE_FILE_LOG.lock().unwrap();
        if let Some(last_time) = *last_log_time {
            if last_time.elapsed() < GENERIC_LOG_COOLDOWN {
                false
            } else {
                *last_log_time = Some(Instant::now());
                true
            }
        } else {
            *last_log_time = Some(Instant::now());
            true
        }
    };

    if should_log {
        if let Some(_guard) = ReentrancyGuard::new() {
            log_event(
                LogLevel::Info,
                LogEvent::ApiHook {
                    function_name: "WriteFile".to_string(),
                    parameters: json!({
                        "bytesToWrite": n_number_of_bytes_to_write,
                        "dataPreview": format_buffer_preview(lp_buffer, n_number_of_bytes_to_write),
                        "note": "(Rate-limited log)"
                    }),
                    stack_trace: None,
                },
            );
        }
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
    log_event(
        LogLevel::Info,
        LogEvent::ApiHook {
            function_name: "ExitProcess".to_string(),
            parameters: json!({
                "exit_code": u_exit_code,
                "action": "Process exiting."
            }),
            stack_trace: None,
        },
    );
    unsafe { ExitProcessHook.call(u_exit_code) };
}

pub fn hooked_terminate_process(h_process: HANDLE, u_exit_code: u32) -> BOOL {
    log_event(
        LogLevel::Info,
        LogEvent::ApiHook {
            function_name: "TerminateProcess".to_string(),
            parameters: json!({
                "process_handle": format!("{:?}", h_process),
                "exit_code": u_exit_code,
                "action": "Process termination requested."
            }),
            stack_trace: None,
        },
    );
    unsafe { TerminateProcessHook.call(h_process, u_exit_code) }
}

pub fn hooked_nt_terminate_process(h_process: HANDLE, exit_status: u32) -> i32 {
    log_event(
        LogLevel::Info,
        LogEvent::ApiHook {
            function_name: "NtTerminateProcess".to_string(),
            parameters: json!({
                "process_handle": format!("{:?}", h_process),
                "exit_status": exit_status,
                "action": "Process termination requested."
            }),
            stack_trace: None,
        },
    );
    unsafe { NtTerminateProcessHook.call(h_process, exit_status) }
}

pub fn hooked_http_send_request_w(
    h_request: HINTERNET,
    lpsz_headers: *const u16,
    dw_headers_length: u32,
    lp_optional: *const c_void,
    dw_optional_length: u32,
) -> BOOL {
    let headers = unsafe { safe_u16_str(lpsz_headers) };
    log_event(
        LogLevel::Info,
        LogEvent::ApiHook {
            function_name: "HttpSendRequestW".to_string(),
            parameters: json!({
                "headers": headers,
                "headers_length": dw_headers_length,
                "optional_data_length": dw_optional_length,
            }),
            stack_trace: None,
        },
    );

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
    log_event(
        LogLevel::Debug,
        LogEvent::ApiHook {
            function_name: "GetAddrInfoW".to_string(),
            parameters: json!({ "node_name": node_name, "service_name": service_name }),
            stack_trace: None,
        },
    );
    unsafe { GetAddrInfoWHook.call(p_node_name, p_service_name, p_hints, pp_result) }
}

pub fn hooked_message_box_w(h_wnd: HWND, text: *const u16, caption: *const u16, u_type: u32) -> i32 {
    let text_str = unsafe { safe_u16_str(text) };
    let caption_str = unsafe { safe_u16_str(caption) };
    log_event(
        LogLevel::Debug,
        LogEvent::ApiHook {
            function_name: "MessageBoxW".to_string(),
            parameters: json!({ "title": caption_str, "text": text_str, "type": u_type }),
            stack_trace: None,
        },
    );
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
            log_event(
                LogLevel::Debug,
                LogEvent::ApiHook {
                    function_name: "connect".to_string(),
                    parameters: json!({ "target_ip": ip_str, "port": port }),
                    stack_trace: None,
                },
            );
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

fn check_persistence_key(full_key_path: &str) {
    let persistence_keys = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"SYSTEM\CurrentControlSet\Services",
        r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
        r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
    ];

    for key in persistence_keys.iter() {
        if full_key_path.contains(key) {
            SUSPICION_SCORE.fetch_add(20, Ordering::Relaxed);
            log_event(
                LogLevel::Warn,
                LogEvent::ApiHook {
                    function_name: "RegistryPersistence".to_string(),
                    parameters: json!({
                        "key_path": full_key_path,
                        "note": "Suspicious registry key access related to persistence."
                    }),
                    stack_trace: Some(capture_stack_trace(CONFIG.stack_trace_frame_limit)),
                },
            );
            break;
        }
    }
}

pub unsafe fn hooked_reg_open_key_ex_w(
    hkey: HKEY,
    lp_sub_key: *const u16,
    ul_options: u32,
    sam_desired: u32,
    phk_result: *mut HKEY,
) -> u32 {
    let sub_key = safe_u16_str(lp_sub_key);
    let full_path = format!("{}\\{}", hkey_to_string(hkey), sub_key);
    check_persistence_key(&full_path);

    if let Some(_guard) = ReentrancyGuard::new() {
        log_event(
            LogLevel::Debug,
            LogEvent::ApiHook {
                function_name: "RegOpenKeyExW".to_string(),
                parameters: json!({ "path": full_path }),
                stack_trace: None,
            },
        );
    }
    RegOpenKeyExWHook.call(hkey, lp_sub_key, ul_options, sam_desired, phk_result)
}

pub unsafe fn hooked_reg_query_value_ex_w(
    hkey: HKEY,
    lp_value_name: *const u16,
    lp_reserved: *const u32,
    lp_type: *mut u32,
    lp_data: *mut u8,
    lpcb_data: *mut u32,
) -> u32 {
    let value_name = safe_u16_str(lp_value_name);
    // It's hard to get the full key path here without more complex tracking,
    // so we'll just log the value name.
    if let Some(_guard) = ReentrancyGuard::new() {
        log_event(
            LogLevel::Debug,
            LogEvent::ApiHook {
                function_name: "RegQueryValueExW".to_string(),
                parameters: json!({ "value_name": value_name }),
                stack_trace: None,
            },
        );
    }
    RegQueryValueExWHook.call(hkey, lp_value_name, lp_reserved, lp_type, lp_data, lpcb_data)
}

pub unsafe fn hooked_reg_enum_key_ex_w(
    hkey: HKEY,
    dw_index: u32,
    lp_name: *mut u16,
    lpcch_name: *mut u32,
    lp_reserved: *const u32,
    lp_class: *mut u16,
    lpcch_class: *mut u32,
    lpft_last_write_time: *mut windows_sys::Win32::Foundation::FILETIME,
) -> u32 {
    if let Some(_guard) = ReentrancyGuard::new() {
        log_event(
            LogLevel::Debug,
            LogEvent::ApiHook {
                function_name: "RegEnumKeyExW".to_string(),
                parameters: json!({
                    "hkey": hkey_to_string(hkey),
                    "index": dw_index,
                    "note": "Enumerating registry keys."
                }),
                stack_trace: None,
            },
        );
    }
    RegEnumKeyExWHook.call(hkey, dw_index, lp_name, lpcch_name, lp_reserved, lp_class, lpcch_class, lpft_last_write_time)
}

pub unsafe fn hooked_reg_enum_value_w(
    hkey: HKEY,
    dw_index: u32,
    lp_value_name: *mut u16,
    lpcch_value_name: *mut u32,
    lp_reserved: *const u32,
    lp_type: *mut u32,
    lp_data: *mut u8,
    lpcb_data: *mut u32,
) -> u32 {
    if let Some(_guard) = ReentrancyGuard::new() {
        log_event(
            LogLevel::Debug,
            LogEvent::ApiHook {
                function_name: "RegEnumValueW".to_string(),
                parameters: json!({
                    "hkey": hkey_to_string(hkey),
                    "index": dw_index,
                    "note": "Enumerating registry values."
                }),
                stack_trace: None,
            },
        );
    }
    RegEnumValueWHook.call(hkey, dw_index, lp_value_name, lpcch_value_name, lp_reserved, lp_type, lp_data, lpcb_data)
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
    log_event(
        LogLevel::Debug,
        LogEvent::ApiHook {
            function_name: "RegCreateKeyExW".to_string(),
            parameters: json!({ "path": format!("{}\\{}", hkey_to_string(hkey), sub_key) }),
            stack_trace: None,
        },
    );
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
    log_event(
        LogLevel::Debug,
        LogEvent::ApiHook {
            function_name: "RegSetValueExW".to_string(),
            parameters: json!({ "key": hkey_to_string(hkey), "value_name": value_name, "type": dw_type, "bytes": cb_data }),
            stack_trace: None,
        },
    );
    unsafe { RegSetValueExWHook.call(hkey, lp_value_name, _reserved, dw_type, lp_data, cb_data) }
}

pub fn hooked_reg_delete_key_w(hkey: HKEY, lp_sub_key: *const u16) -> u32 {
    let sub_key = unsafe { safe_u16_str(lp_sub_key) };
    log_event(
        LogLevel::Debug,
        LogEvent::ApiHook {
            function_name: "RegDeleteKeyW".to_string(),
            parameters: json!({ "path": format!("{}\\{}", hkey_to_string(hkey), sub_key) }),
            stack_trace: None,
        },
    );
    unsafe { RegDeleteKeyWHook.call(hkey, lp_sub_key) }
}

pub fn hooked_delete_file_w(lp_file_name: *const u16) -> BOOL {
    let file_name = unsafe { safe_u16_str(lp_file_name) };
    log_event(
        LogLevel::Debug,
        LogEvent::ApiHook {
            function_name: "DeleteFileW".to_string(),
            parameters: json!({ "file_name": file_name }),
            stack_trace: None,
        },
    );
    unsafe { DeleteFileWHook.call(lp_file_name) }
}

/// Gets the name of a process from its PID.
fn get_process_name_by_pid(pid: u32) -> String {
    if pid == 0 {
        return "<system_idle>".to_string();
    }
    // NOTE: The current process PID is `std::process::id()`. If we are opening our own process,
    // we can use a more direct way to get the name, but this is a general function.

    // Open the process with limited query rights.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };

    if handle == 0 {
        // This can happen if the process has already exited, or if we lack permissions.
        // For high-privilege processes, we might not be able to open them.
        return format!("<pid: {}>", pid);
    }

    let mut buffer: [u16; 1024] = [0; 1024];
    let mut size = buffer.len() as u32;

    let result = unsafe { QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size) };

    unsafe {
        windows_sys::Win32::Foundation::CloseHandle(handle);
    }

    if result == 0 {
        // Failed to get the process name.
        return format!("<pid: {}, error getting name>", pid);
    }

    let process_name_path = String::from_utf16_lossy(&buffer[..size as usize]);

    // Extract just the executable name from the full path for cleaner logs.
    Path::new(&process_name_path)
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.to_string())
        .unwrap_or(process_name_path) // Fallback to full path if parsing fails.
}

pub unsafe fn hooked_open_process(
    dw_desired_access: u32,
    b_inherit_handle: BOOL,
    dw_process_id: u32,
) -> HANDLE {
    let target_name = get_process_name_by_pid(dw_process_id);
    log_event(
        LogLevel::Warn,
        LogEvent::ApiHook {
            function_name: "OpenProcess".to_string(),
            parameters: json!({
                "target_pid": dw_process_id,
                "target_name": target_name,
                "desired_access": dw_desired_access,
            }),
            stack_trace: None,
        },
    );
    OpenProcessHook.call(dw_desired_access, b_inherit_handle, dw_process_id)
}

pub unsafe fn hooked_write_process_memory(
    h_process: HANDLE,
    lp_base_address: *const c_void,
    lp_buffer: *const c_void,
    n_size: usize,
    lp_number_of_bytes_written: *mut usize,
) -> BOOL {
    SUSPICION_SCORE.fetch_add(5, Ordering::Relaxed);
    log_event(
        LogLevel::Warn,
        LogEvent::ApiHook {
            function_name: "WriteProcessMemory".to_string(),
            parameters: json!({
                "target_process_handle": h_process as usize,
                "base_address": lp_base_address as usize,
                "size": n_size,
                "data_preview": format_buffer_preview(lp_buffer as *const u8, n_size as u32),
            }),
            stack_trace: None,
        },
    );
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
    let result = VirtualAllocExHook.call(
        h_process,
        lp_address,
        dw_size,
        fl_allocation_type,
        fl_protect,
    );

    if !result.is_null() {
        if let Some(_guard) = ReentrancyGuard::new() {
            let stack_trace = capture_stack_trace(CONFIG.stack_trace_frame_limit);

            // Forward allocation info to the VMP dumper module.
            crate::vmp_dumper::track_memory_allocation(
                result as usize,
                dw_size,
                fl_protect,
                stack_trace.clone(),
            );

            log_event(
                LogLevel::Info,
                LogEvent::ApiHook {
                    function_name: "VirtualAllocEx".to_string(),
                    parameters: json!({
                        "process_handle": h_process as usize,
                        "address": result as usize,
                        "size": dw_size,
                        "protection": format!("{:#X}", fl_protect),
                    }),
                    stack_trace: Some(stack_trace),
                },
            );
        }
    }

    result
}

// --- C2 Detection Hook Implementations ---

pub unsafe fn hooked_wsasend(
    s: SOCKET,
    lp_buffers: *const WSABUF,
    dw_buffer_count: u32,
    lp_number_of_bytes_sent: *mut u32,
    dw_flags: u32,
    lp_overlapped: *mut OVERLAPPED,
    lp_completion_routine: LpwsaOverlappedCompletionRoutine,
) -> i32 {
    if let Some(_guard) = ReentrancyGuard::new() {
        let mut total_len = 0;
        let mut data_preview = String::from("<disabled>");
        if !lp_buffers.is_null() && dw_buffer_count > 0 {
            let buffers = slice::from_raw_parts(lp_buffers, dw_buffer_count as usize);
            for buffer in buffers {
                total_len += buffer.len;
            }
            if CONFIG.features.read().unwrap().log_network_data {
                data_preview.clear();
                for buffer in buffers {
                    if data_preview.len() < 256 { // Limit preview size
                        data_preview.push_str(&format_buffer_preview(buffer.buf, buffer.len));
                    }
                }
            }
        }
        log_event(
            LogLevel::Info,
            LogEvent::ApiHook {
                function_name: "WSASend".to_string(),
                parameters: json!({
                    "socket": s,
                    "buffer_count": dw_buffer_count,
                    "total_size": total_len,
                    "data_hex": data_preview,
                    "direction": "send"
                }),
                stack_trace: Some(capture_stack_trace(CONFIG.stack_trace_frame_limit)),
            },
        );
    }
    WSASendHook.call(s, lp_buffers, dw_buffer_count, lp_number_of_bytes_sent, dw_flags, lp_overlapped, lp_completion_routine)
}

pub unsafe fn hooked_send(s: SOCKET, buf: *const u8, len: i32, flags: i32) -> i32 {
    if let Some(_guard) = ReentrancyGuard::new() {
        let data_preview = if CONFIG.features.read().unwrap().log_network_data {
            format_buffer_preview(buf, len as u32)
        } else {
            "<disabled>".to_string()
        };
        log_event(
            LogLevel::Info,
            LogEvent::ApiHook {
                function_name: "send".to_string(),
                parameters: json!({
                    "socket": s,
                    "size": len,
                    "data_hex": data_preview,
                    "direction": "send"
                }),
                stack_trace: Some(capture_stack_trace(CONFIG.stack_trace_frame_limit)),
            },
        );
    }
    SendHook.call(s, buf, len, flags)
}

pub unsafe fn hooked_internet_open_w(
    lpsz_agent: *const u16,
    dw_access_type: u32,
    lpsz_proxy: *const u16,
    lpsz_proxy_bypass: *const u16,
    dw_flags: u32,
) -> HINTERNET {
    if let Some(_guard) = ReentrancyGuard::new() {
        log_event(
            LogLevel::Info,
            LogEvent::ApiHook {
                function_name: "InternetOpenW".to_string(),
                parameters: json!({
                    "user_agent": safe_u16_str(lpsz_agent),
                    "proxy": safe_u16_str(lpsz_proxy),
                }),
                stack_trace: Some(capture_stack_trace(CONFIG.stack_trace_frame_limit)),
            },
        );
    }
    InternetOpenWHook.call(lpsz_agent, dw_access_type, lpsz_proxy, lpsz_proxy_bypass, dw_flags)
}

pub unsafe fn hooked_dns_query_w(
    psz_name: *const u16,
    w_type: u16,
    options: u32,
    p_extra: *const c_void,
    pp_query_results: *mut *mut c_void,
    p_reserved: *mut *mut c_void,
) -> NTSTATUS {
    if let Some(_guard) = ReentrancyGuard::new() {
        let hostname = safe_u16_str(psz_name);
        // Basic check against a list of known bad domains.
        if hostname.contains("bad-domain.com") {
             SUSPICION_SCORE.fetch_add(50, Ordering::Relaxed);
        }
        log_event(
            LogLevel::Info,
            LogEvent::ApiHook {
                function_name: "DnsQuery_W".to_string(),
                parameters: json!({ "hostname": hostname }),
                stack_trace: Some(capture_stack_trace(CONFIG.stack_trace_frame_limit)),
            },
        );
    }
    DnsQuery_WHook.call(psz_name, w_type, options, p_extra, pp_query_results, p_reserved)
}

pub unsafe fn hooked_cert_verify_certificate_chain_policy(
    psz_policy_oid: i32,
    p_chain_context: *const c_void,
    p_policy_para: *const c_void,
    p_policy_status: *mut c_void,
) -> BOOL {
    if let Some(_guard) = ReentrancyGuard::new() {
        log_event(
            LogLevel::Warn,
            LogEvent::ApiHook {
                function_name: "CertVerifyCertificateChainPolicy".to_string(),
                parameters: json!({
                    "policy_oid": psz_policy_oid,
                    "note": "SSL/TLS certificate chain validation occurred. Could be used for SSL pinning checks."
                }),
                stack_trace: Some(capture_stack_trace(CONFIG.stack_trace_frame_limit)),
            },
        );
    }
    CertVerifyCertificateChainPolicyHook.call(psz_policy_oid, p_chain_context, p_policy_para, p_policy_status)
}

pub unsafe fn hooked_internet_connect_w(
    h_internet: HINTERNET,
    lpsz_server_name: *const u16,
    n_server_port: u16,
    lpsz_user_name: *const u16,
    lpsz_password: *const u16,
    dw_service: u32,
    dw_flags: u32,
    dw_context: usize,
) -> HINTERNET {
    if let Some(_guard) = ReentrancyGuard::new() {
        log_event(
            LogLevel::Info,
            LogEvent::ApiHook {
                function_name: "InternetConnectW".to_string(),
                parameters: json!({
                    "target_host": safe_u16_str(lpsz_server_name),
                    "port": n_server_port,
                }),
                stack_trace: Some(capture_stack_trace(CONFIG.stack_trace_frame_limit)),
            },
        );
    }
    InternetConnectWHook.call(h_internet, lpsz_server_name, n_server_port, lpsz_user_name, lpsz_password, dw_service, dw_flags, dw_context)
}

pub unsafe fn hooked_http_open_request_w(
    h_connect: HINTERNET,
    lpsz_verb: *const u16,
    lpsz_object_name: *const u16,
    lpsz_version: *const u16,
    lpsz_referrer: *const u16,
    lplpsz_accept_types: *const *const u16,
    dw_flags: u32,
    dw_context: usize,
) -> HINTERNET {
    if let Some(_guard) = ReentrancyGuard::new() {
        log_event(
            LogLevel::Info,
            LogEvent::ApiHook {
                function_name: "HttpOpenRequestW".to_string(),
                parameters: json!({
                    "verb": safe_u16_str(lpsz_verb),
                    "path": safe_u16_str(lpsz_object_name),
                    "version": safe_u16_str(lpsz_version),
                }),
                stack_trace: Some(capture_stack_trace(CONFIG.stack_trace_frame_limit)),
            },
        );
    }
    HttpOpenRequestWHook.call(h_connect, lpsz_verb, lpsz_object_name, lpsz_version, lpsz_referrer, lplpsz_accept_types, dw_flags, dw_context)
}

pub unsafe fn hooked_internet_read_file(
    h_file: HINTERNET,
    lp_buffer: *mut c_void,
    dw_number_of_bytes_to_read: u32,
    lp_dw_number_of_bytes_read: *mut u32,
) -> BOOL {
    let result = InternetReadFileHook.call(h_file, lp_buffer, dw_number_of_bytes_to_read, lp_dw_number_of_bytes_read);
    if result != 0 && !lp_dw_number_of_bytes_read.is_null() && *lp_dw_number_of_bytes_read > 0 {
        if let Some(_guard) = ReentrancyGuard::new() {
            log_event(
                LogLevel::Info,
                LogEvent::ApiHook {
                    function_name: "InternetReadFile".to_string(),
                    parameters: json!({
                        "bytes_read": *lp_dw_number_of_bytes_read,
                        "data_preview": format_buffer_preview(lp_buffer as *const u8, *lp_dw_number_of_bytes_read),
                        "direction": "receive",
                    }),
                    stack_trace: Some(capture_stack_trace(CONFIG.stack_trace_frame_limit)),
                },
            );
        }
    }
    result
}

pub unsafe fn hooked_dns_query_a(
    psz_name: *const u8,
    w_type: u16,
    options: u32,
    p_extra: *const c_void,
    pp_query_results: *mut *mut c_void,
    p_reserved: *mut *mut c_void,
) -> NTSTATUS {
    if let Some(_guard) = ReentrancyGuard::new() {
        let hostname = safe_u8_str(psz_name);
        if hostname.contains("bad-domain.com") {
             SUSPICION_SCORE.fetch_add(50, Ordering::Relaxed);
        }
        log_event(
            LogLevel::Info,
            LogEvent::ApiHook {
                function_name: "DnsQuery_A".to_string(),
                parameters: json!({ "hostname": hostname }),
                stack_trace: Some(capture_stack_trace(CONFIG.stack_trace_frame_limit)),
            },
        );
    }
    DnsQuery_AHook.call(psz_name, w_type, options, p_extra, pp_query_results, p_reserved)
}

pub unsafe fn hooked_crypt_hash_data(
    h_hash: HCRYPTHASH,
    pb_data: *const u8,
    dw_data_len: u32,
    dw_flags: u32,
) -> BOOL {
    if let Some(_guard) = ReentrancyGuard::new() {
        log_event(
            LogLevel::Info,
            LogEvent::ApiHook {
                function_name: "CryptHashData".to_string(),
                parameters: json!({
                    "data_len": dw_data_len,
                    "data_preview": format_buffer_preview(pb_data, dw_data_len),
                }),
                stack_trace: Some(capture_stack_trace(CONFIG.stack_trace_frame_limit)),
            },
        );
    }
    CryptHashDataHook.call(h_hash, pb_data, dw_data_len, dw_flags)
}

// --- Broader Feature Hook Implementations ---

pub unsafe fn hooked_copy_file_w(lp_existing_file_name: *const u16, lp_new_file_name: *const u16, b_fail_if_exists: BOOL) -> BOOL {
    if let Some(_guard) = ReentrancyGuard::new() {
        log_event(
            LogLevel::Info,
            LogEvent::ApiHook {
                function_name: "CopyFileW".to_string(),
                parameters: json!({
                    "source": safe_u16_str(lp_existing_file_name),
                    "destination": safe_u16_str(lp_new_file_name),
                }),
                stack_trace: None,
            },
        );
    }
    CopyFileWHook.call(lp_existing_file_name, lp_new_file_name, b_fail_if_exists)
}

pub unsafe fn hooked_get_temp_path_w(n_buffer_length: u32, lp_buffer: *mut u16) -> u32 {
    if let Some(_guard) = ReentrancyGuard::new() {
        log_event(
            LogLevel::Info,
            LogEvent::ApiHook {
                function_name: "GetTempPathW".to_string(),
                parameters: json!({"note": "Code is attempting to find the temporary directory."}),
                stack_trace: None,
            },
        );
    }
    GetTempPathWHook.call(n_buffer_length, lp_buffer)
}

pub unsafe fn hooked_find_first_file_w(lp_file_name: *const u16, lp_find_file_data: *mut windows_sys::Win32::Storage::FileSystem::WIN32_FIND_DATAW) -> HANDLE {
    if let Some(_guard) = ReentrancyGuard::new() {
        log_event(
            LogLevel::Info,
            LogEvent::ApiHook {
                function_name: "FindFirstFileW".to_string(),
                parameters: json!({
                    "pattern": safe_u16_str(lp_file_name),
                    "note": "File/directory enumeration started."
                }),
                stack_trace: None,
            },
        );
    }
    FindFirstFileWHook.call(lp_file_name, lp_find_file_data)
}

pub unsafe fn hooked_queue_user_apc(pfn_apc: Option<unsafe extern "system" fn(usize)>, h_thread: HANDLE, dw_data: usize) -> u32 {
    SUSPICION_SCORE.fetch_add(15, Ordering::Relaxed);
    if let Some(_guard) = ReentrancyGuard::new() {
        log_event(
            LogLevel::Warn,
            LogEvent::ApiHook {
                function_name: "QueueUserAPC".to_string(),
                parameters: json!({
                    "apc_routine": pfn_apc.map_or(0, |f| f as usize),
                    "thread_handle": h_thread as usize,
                    "note": "APC injection attempt detected."
                }),
                stack_trace: Some(capture_stack_trace(CONFIG.stack_trace_frame_limit)),
            },
        );
    }
    QueueUserAPCHook.call(pfn_apc, h_thread, dw_data)
}

pub unsafe fn hooked_win_exec(lp_cmd_line: *const u8, u_cmd_show: u32) -> u32 {
    if let Some(_guard) = ReentrancyGuard::new() {
        log_event(
            LogLevel::Warn,
            LogEvent::ApiHook {
                function_name: "WinExec".to_string(),
                parameters: json!({ "command_line": safe_u8_str(lp_cmd_line) }),
                stack_trace: Some(capture_stack_trace(CONFIG.stack_trace_frame_limit)),
            },
        );
    }
    WinExecHook.call(lp_cmd_line, u_cmd_show)
}

pub unsafe fn hooked_create_process_a(
    lp_application_name: *const u8,
    lp_command_line: *mut u8,
    lp_process_attributes: *const SECURITY_ATTRIBUTES,
    lp_thread_attributes: *const SECURITY_ATTRIBUTES,
    b_inherit_handles: BOOL,
    dw_creation_flags: u32,
    lp_environment: *const c_void,
    lp_current_directory: *const u8,
    lp_startup_info: *const windows_sys::Win32::System::Threading::STARTUPINFOA, // Simplified for logging
    lp_process_information: *mut PROCESS_INFORMATION,
) -> BOOL {
    if let Some(_guard) = ReentrancyGuard::new() {
        let app_name = safe_u8_str(lp_application_name);
        let cmd_line = safe_u8_str(lp_command_line);
        if app_name.contains("cmd.exe") || app_name.contains("powershell.exe") ||
           cmd_line.contains("cmd.exe") || cmd_line.contains("powershell.exe") {
            SUSPICION_SCORE.fetch_add(25, Ordering::Relaxed);
        }
        log_event(
            LogLevel::Warn,
            LogEvent::ApiHook {
                function_name: "CreateProcessA".to_string(),
                parameters: json!({ "application_name": app_name, "command_line": cmd_line }),
                stack_trace: Some(capture_stack_trace(CONFIG.stack_trace_frame_limit)),
            },
        );
    }
    CreateProcessAHook.call(lp_application_name, lp_command_line, lp_process_attributes, lp_thread_attributes, b_inherit_handles, dw_creation_flags, lp_environment, lp_current_directory, lp_startup_info, lp_process_information)
}

pub unsafe fn hooked_move_file_w(lp_existing_file_name: *const u16, lp_new_file_name: *const u16) -> BOOL {
    if let Some(_guard) = ReentrancyGuard::new() {
        log_event(
            LogLevel::Info,
            LogEvent::ApiHook {
                function_name: "MoveFileW".to_string(),
                parameters: json!({
                    "from": safe_u16_str(lp_existing_file_name),
                    "to": safe_u16_str(lp_new_file_name),
                }),
                stack_trace: None,
            },
        );
    }
    MoveFileWHook.call(lp_existing_file_name, lp_new_file_name)
}

pub unsafe fn hooked_get_temp_file_name_w(lp_path_name: *const u16, lp_prefix_string: *const u16, u_unique: u32, lp_temp_file_name: *mut u16) -> u32 {
    let result = GetTempFileNameWHook.call(lp_path_name, lp_prefix_string, u_unique, lp_temp_file_name);
    if result != 0 {
        if let Some(_guard) = ReentrancyGuard::new() {
            log_event(
                LogLevel::Info,
                LogEvent::ApiHook {
                    function_name: "GetTempFileNameW".to_string(),
                    parameters: json!({ "path": safe_u16_str(lp_path_name), "prefix": safe_u16_str(lp_prefix_string) }),
                    stack_trace: None,
                },
            );
        }
    }
    result
}

pub unsafe fn hooked_find_next_file_w(h_find_file: HANDLE, lp_find_file_data: *mut windows_sys::Win32::Storage::FileSystem::WIN32_FIND_DATAW) -> BOOL {
    // This function is often called in a tight loop. To avoid log spam, we don't log it by default.
    // The initial FindFirstFileW call is usually sufficient to indicate enumeration.
    FindNextFileWHook.call(h_find_file, lp_find_file_data)
}

pub unsafe fn hooked_nt_create_thread_ex(
    ph_thread: *mut HANDLE,
    desired_access: u32,
    object_attributes: *const c_void,
    process_handle: HANDLE,
    start_routine: *const c_void,
    argument: *const c_void,
    create_suspended: BOOL,
    stack_zero_bits: usize,
    size_of_stack_commit: usize,
    size_of_stack_reserve: usize,
    bytes_buffer: *const c_void,
) -> NTSTATUS {
    SUSPICION_SCORE.fetch_add(10, Ordering::Relaxed);
    if let Some(_guard) = ReentrancyGuard::new() {
        log_event(
            LogLevel::Warn,
            LogEvent::ApiHook {
                function_name: "NtCreateThreadEx".to_string(),
                parameters: json!({
                    "process_handle": process_handle as usize,
                    "start_address": start_routine as usize,
                    "note": "Low-level thread creation detected."
                }),
                stack_trace: Some(capture_stack_trace(CONFIG.stack_trace_frame_limit)),
            },
        );
    }
    NtCreateThreadExHook.call(ph_thread, desired_access, object_attributes, process_handle, start_routine, argument, create_suspended, stack_zero_bits, size_of_stack_commit, size_of_stack_reserve, bytes_buffer)
}

pub unsafe fn hooked_set_thread_context(h_thread: HANDLE, lp_context: *const windows_sys::Win32::System::Diagnostics::Debug::CONTEXT) -> BOOL {
    SUSPICION_SCORE.fetch_add(15, Ordering::Relaxed);
    if let Some(_guard) = ReentrancyGuard::new() {
        log_event(
            LogLevel::Warn,
            LogEvent::ApiHook {
                function_name: "SetThreadContext".to_string(),
                parameters: json!({
                    "thread_handle": h_thread as usize,
                    "note": "Thread hijacking attempt detected."
                }),
                stack_trace: Some(capture_stack_trace(CONFIG.stack_trace_frame_limit)),
            },
        );
    }
    SetThreadContextHook.call(h_thread, lp_context)
}

pub unsafe fn hooked_system(command: *const i8) -> i32 {
    if let Some(_guard) = ReentrancyGuard::new() {
        log_event(
            LogLevel::Warn,
            LogEvent::ApiHook {
                function_name: "system".to_string(),
                parameters: json!({ "command": safe_u8_str(command as *const u8) }),
                stack_trace: Some(capture_stack_trace(CONFIG.stack_trace_frame_limit)),
            },
        );
    }
    SystemHook.call(command)
}

pub unsafe fn hooked_shell_execute_w(
    hwnd: HWND,
    lp_operation: *const u16,
    lp_file: *const u16,
    lp_parameters: *const u16,
    lp_directory: *const u16,
    n_show_cmd: i32,
) -> HINSTANCE {
    if let Some(_guard) = ReentrancyGuard::new() {
        log_event(
            LogLevel::Warn,
            LogEvent::ApiHook {
                function_name: "ShellExecuteW".to_string(),
                parameters: json!({
                    "operation": safe_u16_str(lp_operation),
                    "file": safe_u16_str(lp_file),
                    "parameters": safe_u16_str(lp_parameters),
                }),
                stack_trace: Some(capture_stack_trace(CONFIG.stack_trace_frame_limit)),
            },
        );
    }
    ShellExecuteWHook.call(hwnd, lp_operation, lp_file, lp_parameters, lp_directory, n_show_cmd)
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
    SUSPICION_SCORE.fetch_add(10, Ordering::Relaxed);
    let start_address_val = lp_start_address.map_or(0, |f| f as usize);
    log_event(
        LogLevel::Warn,
        LogEvent::ApiHook {
            function_name: "CreateRemoteThread".to_string(),
            parameters: json!({ "target_process_handle": h_process as usize, "start_address": start_address_val }),
            stack_trace: None,
        },
    );
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
    log_event(
        LogLevel::Info,
        LogEvent::ApiHook {
            function_name: "LoadLibraryW".to_string(),
            parameters: json!({ "library_name": lib_name.clone() }),
            stack_trace: None,
        },
    );

    let module_handle = unsafe { LoadLibraryWHook.call(lp_lib_file_name) };

    if module_handle != 0 {
        if let Some(_guard) = ReentrancyGuard::new() {
            // We have a valid handle, now let's read the module from memory for analysis.
            unsafe {
                let dos_header = &*(module_handle as *const windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER);
                if dos_header.e_magic == 0x5A4D { // "MZ"
                    let nt_headers_ptr = (module_handle as usize + dos_header.e_lfanew as usize)
                        as *const windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
                    let nt_headers = &*nt_headers_ptr;
                    if nt_headers.Signature == 0x4550 { // "PE\0\0"
                        let size_of_image = nt_headers.OptionalHeader.SizeOfImage;
                        let _module_data = slice::from_raw_parts(module_handle as *const u8, size_of_image as usize);
                        
                        // Run static analysis on the loaded module.
                        // crate::static_analyzer::analyze_module(module_data);
                    }
                }
            }
        }
    }

    module_handle
}

pub fn hooked_load_library_ex_w(
    lp_lib_file_name: *const u16,
    h_file: HANDLE,
    dw_flags: u32,
) -> HINSTANCE {
    let lib_name = unsafe { safe_u16_str(lp_lib_file_name) };
    log_event(
        LogLevel::Debug,
        LogEvent::ApiHook {
            function_name: "LoadLibraryExW".to_string(),
            parameters: json!({ "library_name": lib_name, "flags": dw_flags }),
            stack_trace: None,
        },
    );
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
    log_event(
        LogLevel::Warn,
        LogEvent::ApiHook {
            function_name: "CreateProcessW".to_string(),
            parameters: json!({ "application_name": app_name, "command_line": cmd_line }),
            stack_trace: None,
        },
    );
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

pub unsafe fn hooked_add_vectored_exception_handler(
    first: u32,
    handler: PVECTORED_EXCEPTION_HANDLER,
) -> *mut c_void {
    SUSPICION_SCORE.fetch_add(3, Ordering::Relaxed);
    log_event(
        LogLevel::Warn,
        LogEvent::ApiHook {
            function_name: "AddVectoredExceptionHandler".to_string(),
            parameters: json!({
                "handler_address": handler.map_or(0, |h| h as usize),
                "is_first": first != 0,
            }),
            stack_trace: Some(capture_stack_trace(CONFIG.stack_trace_frame_limit)),
        },
    );

    AddVectoredExceptionHandlerHook.call(first, handler)
}

pub unsafe fn hooked_create_thread(
    attrs: *const SECURITY_ATTRIBUTES,
    stack_size: usize,
    start_addr: LPTHREAD_START_ROUTINE,
    param: *const c_void,
    flags: u32,
    thread_id: *mut u32,
) -> HANDLE {
    log_event(
        LogLevel::Info,
        LogEvent::ApiHook {
            function_name: "CreateThread".to_string(),
            parameters: json!({
                "start_address": start_addr.map_or(0, |f| f as usize),
                "flags": flags,
            }),
            stack_trace: Some(capture_stack_trace(CONFIG.stack_trace_frame_limit)),
        },
    );

    CreateThreadHook.call(attrs, stack_size, start_addr, param, flags, thread_id)
}

pub unsafe fn hooked_free_library(module: HINSTANCE) -> BOOL {
    log_event(
        LogLevel::Info,
        LogEvent::ApiHook {
            function_name: "FreeLibrary".to_string(),
            parameters: json!({
                "module_handle": module as usize,
            }),
            stack_trace: Some(capture_stack_trace(CONFIG.stack_trace_frame_limit)),
        },
    );

    FreeLibraryHook.call(module)
}

pub unsafe fn hooked_crypt_encrypt(
    key: HCRYPTKEY,
    hash: HCRYPTHASH,
    final_op: BOOL,
    flags: u32,
    data: *mut u8,
    data_len: *mut u32,
    buffer_len: u32,
) -> BOOL {
    let len = if !data_len.is_null() { *data_len } else { 0 };

    if let Some(_guard) = ReentrancyGuard::new() {
        log_event(
            LogLevel::Info,
            LogEvent::ApiHook {
                function_name: "CryptEncrypt".to_string(),
                parameters: json!({
                    "data_length_before": len,
                    "data_preview": format_buffer_preview(data, len),
                }),
                stack_trace: Some(capture_stack_trace(CONFIG.stack_trace_frame_limit)),
            },
        );
    }

    let result = CryptEncryptHook.call(key, hash, final_op, flags, data, data_len, buffer_len);

    if result != 0 {
        if let Some(_guard) = ReentrancyGuard::new() {
            let len_after = if !data_len.is_null() { *data_len } else { 0 };
            log_event(
                LogLevel::Info,
                LogEvent::ApiHook {
                    function_name: "CryptEncrypt (Post-call)".to_string(),
                    parameters: json!({
                        "data_length_after": len_after,
                        "encrypted_data_preview": format_buffer_preview(data, len_after),
                    }),
                    stack_trace: None,
                },
            );
        }
    }

    result
}

pub unsafe fn hooked_crypt_decrypt(
    key: HCRYPTKEY,
    hash: HCRYPTHASH,
    final_op: BOOL,
    flags: u32,
    data: *mut u8,
    data_len: *mut u32,
) -> BOOL {
    let len = if !data_len.is_null() { *data_len } else { 0 };

    if let Some(_guard) = ReentrancyGuard::new() {
        log_event(
            LogLevel::Info,
            LogEvent::ApiHook {
                function_name: "CryptDecrypt".to_string(),
                parameters: json!({
                    "data_length_before": len,
                    "encrypted_data_preview": format_buffer_preview(data, len),
                }),
                stack_trace: Some(capture_stack_trace(CONFIG.stack_trace_frame_limit)),
            },
        );
    }

    let result = CryptDecryptHook.call(key, hash, final_op, flags, data, data_len);

    if result != 0 {
        if let Some(_guard) = ReentrancyGuard::new() {
            let len_after = if !data_len.is_null() { *data_len } else { 0 };
            log_event(
                LogLevel::Info,
                LogEvent::ApiHook {
                    function_name: "CryptDecrypt (Post-call)".to_string(),
                    parameters: json!({
                        "data_length_after": len_after,
                        "decrypted_data_preview": format_buffer_preview(data, len_after),
                    }),
                    stack_trace: None,
                },
            );
        }
    }

    result
}

macro_rules! hook {
    ($hook:ident, $func:expr, $hook_fn:expr) => {
        let func_name = stringify!($func);
        match $hook.initialize($func, $hook_fn).and_then(|_| $hook.enable()) {
            Ok(_) => {
                crate::crash_logger::log_hook(func_name, true, None, "Hook installed");
            }
            Err(e) => {
                crate::crash_logger::log_hook(func_name, false, None, &format!("Failed: {}", e));
                log_event(
                    LogLevel::Error,
                    LogEvent::Error {
                        source: "StaticHook".to_string(),
                        message: format!("Failed to hook {}: {}", func_name, e),
                    },
                );
            }
        }
    };
}

pub unsafe fn initialize_all_hooks() {
    crate::crash_logger::log_init_step("WinAPI hooks: Starting initialization");
    let config = CONFIG.features.read().unwrap();

    // Hook critical process termination functions.
    if config.hook_exit_process {
        let exit_process_ptr: unsafe extern "system" fn(u32) -> ! =
            std::mem::transmute(ExitProcess as *const ());
        hook!(ExitProcessHook, exit_process_ptr, hooked_exit_process);
    }
    if config.hook_terminate_process {
        let terminate_process_ptr: unsafe extern "system" fn(HANDLE, u32) -> BOOL =
            std::mem::transmute(TerminateProcess as *const ());
        hook!(
            TerminateProcessHook,
            terminate_process_ptr,
            hooked_terminate_process
        );
    }

    // Anti-debugging hooks
    if config.hook_is_debugger_present {
        hook!(
            IsDebuggerPresentHook,
            IsDebuggerPresent,
            hooked_is_debugger_present
        );
    }
    if config.hook_check_remote_debugger_present {
        hook!(
            CheckRemoteDebuggerPresentHook,
            CheckRemoteDebuggerPresent,
            |a, b| hooked_check_remote_debugger_present(a, b)
        );
    }
    if config.hook_get_tick_count {
        hook!(GetTickCountHook, GetTickCount, hooked_get_tick_count);
    }
    if config.hook_query_performance_counter {
        hook!(
            QueryPerformanceCounterHook,
            QueryPerformanceCounter,
            |a| hooked_query_performance_counter(a)
        );
    }
    if config.hook_output_debug_string_a {
        hook!(
            OutputDebugStringAHook,
            OutputDebugStringA,
            |a| hooked_output_debug_string_a(a)
        );
    }

    // Process enumeration hooks
    if config.hook_create_toolhelp32_snapshot {
        hook!(
            CreateToolhelp32SnapshotHook,
            CreateToolhelp32Snapshot,
            |a, b| hooked_create_toolhelp32_snapshot(a, b)
        );
    }
    if config.hook_process32_first_w {
        hook!(
            Process32FirstWHook,
            Process32FirstW,
            |a, b| hooked_process32_first_w(a, b)
        );
    }
    if config.hook_process32_next_w {
        hook!(
            Process32NextWHook,
            Process32NextW,
            |a, b| hooked_process32_next_w(a, b)
        );
    }

    if config.hook_create_file_w {
        hook!(CreateFileWHook, CreateFileW, |a, b, c, d, e, f, g| {
            hooked_create_file_w(a, b, c, d, e, f, g)
        });
    }
    if config.hook_write_file {
        hook!(WriteFileHook, WriteFile, |a, b, c, d, e| {
            hooked_write_file(a, b, c, d, e)
        });
    }
    if config.hook_create_process_w {
        hook!(CreateProcessWHook, CreateProcessW, hooked_create_process_w);
    }
    if config.hook_message_box_w {
        hook!(MessageBoxWHook, MessageBoxW, hooked_message_box_w);
    }

    // Hook process interaction functions - DISABLED FOR STABILITY
    /*
    if config.hook_open_process {
        hook!(OpenProcessHook, OpenProcess, |a, b, c| {
            hooked_open_process(a, b, c)
        });
    }
    if config.hook_write_process_memory {
        hook!(
            WriteProcessMemoryHook,
            WriteProcessMemory,
            |a, b, c, d, e| hooked_write_process_memory(a, b, c, d, e)
        );
    }
    if config.hook_virtual_alloc_ex {
        hook!(
            VirtualAllocExHook,
            VirtualAllocEx,
            |a, b, c, d, e| hooked_virtual_alloc_ex(a, b, c, d, e)
        );
    }
    */

    // Hook library loading functions.
    if config.hook_load_library_w {
        hook!(LoadLibraryWHook, LoadLibraryW, hooked_load_library_w);
    }
    if config.hook_load_library_ex_w {
        hook!(LoadLibraryExWHook, LoadLibraryExW, hooked_load_library_ex_w);
    }

    if config.registry_hooks_enabled {
        // Hook registry functions.
        if config.hook_reg_create_key_ex_w {
            hook!(
                RegCreateKeyExWHook,
                RegCreateKeyExW,
                |a, b, c, d, e, f, g, h, i| hooked_reg_create_key_ex_w(a, b, c, d, e, f, g, h, i)
            );
        }
        if config.hook_reg_set_value_ex_w {
            hook!(
                RegSetValueExWHook,
                RegSetValueExW,
                |a, b, c, d, e, f| hooked_reg_set_value_ex_w(a, b, c, d, e, f)
            );
        }
        if config.hook_reg_delete_key_w {
            hook!(RegDeleteKeyWHook, RegDeleteKeyW, |a, b| hooked_reg_delete_key_w(a, b));
        }
        if config.hook_reg_open_key_ex_w {
            hook!(RegOpenKeyExWHook, RegOpenKeyExW, |a, b, c, d, e| hooked_reg_open_key_ex_w(a, b, c, d, e));
        }
        if config.hook_reg_query_value_ex_w {
            hook!(RegQueryValueExWHook, RegQueryValueExW, |a, b, c, d, e, f| hooked_reg_query_value_ex_w(a, b, c, d, e, f));
        }
        if config.hook_reg_enum_key_ex_w {
            hook!(RegEnumKeyExWHook, RegEnumKeyExW, |a, b, c, d, e, f, g, h| hooked_reg_enum_key_ex_w(a, b, c, d, e, f, g, h));
        }
        if config.hook_reg_enum_value_w {
            hook!(RegEnumValueWHook, RegEnumValueW, |a, b, c, d, e, f, g, h| hooked_reg_enum_value_w(a, b, c, d, e, f, g, h));
        }
    }
    if config.hook_delete_file_w {
        hook!(DeleteFileWHook, DeleteFileW, |a| hooked_delete_file_w(a));
    }

    // Broader Feature Hooks
    if config.hook_copy_file_w {
        hook!(CopyFileWHook, CopyFileW, |a, b, c| hooked_copy_file_w(a, b, c));
    }
    if config.hook_move_file_w {
        hook!(MoveFileWHook, MoveFileW, |a, b| hooked_move_file_w(a, b));
    }
    if config.hook_get_temp_path_w {
        hook!(GetTempPathWHook, GetTempPathW, |a, b| hooked_get_temp_path_w(a, b));
    }
    if config.hook_get_temp_file_name_w {
        hook!(GetTempFileNameWHook, GetTempFileNameW, |a, b, c, d| hooked_get_temp_file_name_w(a, b, c, d));
    }
    if config.hook_find_first_file_w {
        hook!(FindFirstFileWHook, FindFirstFileW, |a, b| hooked_find_first_file_w(a, b));
    }
    if config.hook_find_next_file_w {
        hook!(FindNextFileWHook, FindNextFileW, |a, b| hooked_find_next_file_w(a, b));
    }
    if config.hook_queue_user_apc {
        hook!(QueueUserAPCHook, QueueUserAPC, |a, b, c| hooked_queue_user_apc(a, b, c));
    }
    /*
    if config.hook_set_thread_context {
        hook!(SetThreadContextHook, SetThreadContext, |a, b, c| hooked_set_thread_context(a, b, c));
    }
    */
    if config.hook_win_exec {
        hook!(WinExecHook, WinExec, |a, b| hooked_win_exec(a, b));
    }
    if config.hook_shell_execute_w {
        hook!(ShellExecuteWHook, ShellExecuteW, |a, b, c, d, e, f| hooked_shell_execute_w(a, b, c, d, e, f));
    }
    if config.hook_create_process_a {
        hook!(CreateProcessAHook, CreateProcessA, |a, b, c, d, e, f, g, h, i, j| hooked_create_process_a(a, b, c, d, e, f, g, h, i, j));
    }

    // Hook thread creation.
    if config.hook_create_remote_thread {
        hook!(
            CreateRemoteThreadHook,
            CreateRemoteThread,
            hooked_create_remote_thread
        );
    }
    if config.hook_create_thread {
        hook!(CreateThreadHook, CreateThread, |a, b, c, d, e, f| {
            hooked_create_thread(a, b, c, d, e, f)
        });
    }

    // Hook exception handling
    if config.hook_add_vectored_exception_handler {
        hook!(
            AddVectoredExceptionHandlerHook,
            AddVectoredExceptionHandler,
            |a, b| hooked_add_vectored_exception_handler(a, b)
        );
    }

    crate::crash_logger::log_init_step("WinAPI hooks: Static hooks complete, starting dynamic hooks");
    initialize_dynamic_hooks();
    crate::crash_logger::log_init_step("WinAPI hooks: All hooks initialized");
}

unsafe fn initialize_dynamic_hooks() {
    crate::crash_logger::log_init_step("WinAPI hooks: Dynamic hooks starting");
    let config = CONFIG.features.read().unwrap();

    macro_rules! dyn_hook {
        ($hook:ident, $lib:expr, $func:expr, $hook_fn:expr) => {
            let lib_name_str = $lib;
            let func_name_str = stringify!($func);
            let lib_name: Vec<u16> = lib_name_str.encode_utf16().chain(std::iter::once(0)).collect();
            let lib_handle = GetModuleHandleW(lib_name.as_ptr());

            if lib_handle != 0 {
                if let Some(addr) = GetProcAddress(lib_handle, $func.as_ptr() as *const u8) {
                    let typed_addr = std::mem::transmute(addr);
                    if let Err(e) = $hook.initialize(typed_addr, $hook_fn).and_then(|_| $hook.enable()) {
                        log_event(
                            LogLevel::Warn,
                            LogEvent::Error {
                                source: "DynamicHook".to_string(),
                                message: format!("Failed to hook {} in {}: {}", func_name_str, lib_name_str, e),
                            },
                        );
                    }
                } else {
                     log_event(
                        LogLevel::Debug,
                        LogEvent::Error {
                            source: "DynamicHook".to_string(),
                            message: format!("Function {} not found in {}", func_name_str, lib_name_str),
                        },
                    );
                }
            }
            // Silently ignore if the library is not loaded. This is common.
        };
    }

    if config.hook_connect {
        dyn_hook!(ConnectHook, "ws2_32.dll", b"connect\0", hooked_connect);
    }
    if config.hook_get_addr_info_w {
        dyn_hook!(GetAddrInfoWHook, "ws2_32.dll", b"GetAddrInfoW\0", hooked_get_addr_info_w);
    }

    if config.hook_nt_terminate_process {
        dyn_hook!(NtTerminateProcessHook, "ntdll.dll", b"NtTerminateProcess\0", hooked_nt_terminate_process);
    }
    if config.hook_nt_query_information_process {
        dyn_hook!(NtQueryInformationProcessHook, "ntdll.dll", b"NtQueryInformationProcess\0", |a, b, c, d, e| hooked_nt_query_information_process(a, b, c, d, e));
    }

    if config.hook_http_send_request_w {
        dyn_hook!(HttpSendRequestWHook, "wininet.dll", b"HttpSendRequestW\0", hooked_http_send_request_w);
    }

    if config.hook_free_library {
        dyn_hook!(FreeLibraryHook, "kernel32.dll", b"FreeLibrary\0", |a| hooked_free_library(a));
    }

    if config.crypto_hooks_enabled {
        if config.hook_crypt_encrypt {
            dyn_hook!(CryptEncryptHook, "advapi32.dll", b"CryptEncrypt\0", |a, b, c, d, e, f, g| hooked_crypt_encrypt(a, b, c, d, e, f, g));
        }
        if config.hook_crypt_decrypt {
            dyn_hook!(CryptDecryptHook, "advapi32.dll", b"CryptDecrypt\0", |a, b, c, d, e, f| hooked_crypt_decrypt(a, b, c, d, e, f));
        }
    }

    if config.network_hooks_enabled {
        // C2 Detection Hooks
        if config.hook_wsasend {
            dyn_hook!(WSASendHook, "ws2_32.dll", b"WSASend\0", |a, b, c, d, e, f, g| hooked_wsasend(a, b, c, d, e, f, g));
        }
        if config.hook_send {
            dyn_hook!(SendHook, "ws2_32.dll", b"send\0", |a, b, c, d| hooked_send(a, b, c, d));
        }
        // Note: WSARecv and recv are more complex to hook safely due to buffer management. Skipping for now.

        if config.hook_internet_open_w {
            dyn_hook!(InternetOpenWHook, "wininet.dll", b"InternetOpenW\0", |a, b, c, d, e| hooked_internet_open_w(a, b, c, d, e));
        }
        if config.hook_internet_connect_w {
            dyn_hook!(InternetConnectWHook, "wininet.dll", b"InternetConnectW\0", |a, b, c, d, e, f, g, h| hooked_internet_connect_w(a, b, c, d, e, f, g, h));
        }
        if config.hook_http_open_request_w {
            dyn_hook!(HttpOpenRequestWHook, "wininet.dll", b"HttpOpenRequestW\0", |a, b, c, d, e, f, g, h| hooked_http_open_request_w(a, b, c, d, e, f, g, h));
        }
        if config.hook_internet_read_file {
            dyn_hook!(InternetReadFileHook, "wininet.dll", b"InternetReadFile\0", |a, b, c, d| hooked_internet_read_file(a, b, c, d));
        }

        if config.hook_dns_query_w {
            dyn_hook!(DnsQuery_WHook, "dnsapi.dll", b"DnsQuery_W\0", |a, b, c, d, e, f| hooked_dns_query_w(a, b, c, d, e, f));
        }
        if config.hook_dns_query_a {
            dyn_hook!(DnsQuery_AHook, "dnsapi.dll", b"DnsQuery_A\0", |a, b, c, d, e, f| hooked_dns_query_a(a, b, c, d, e, f));
        }
    }

    if config.crypto_hooks_enabled {
        if config.hook_cert_verify_certificate_chain_policy {
            dyn_hook!(CertVerifyCertificateChainPolicyHook, "crypt32.dll", b"CertVerifyCertificateChainPolicy\0", |a, b, c, d| hooked_cert_verify_certificate_chain_policy(a, b, c, d));
        }
        if config.hook_crypt_hash_data {
            dyn_hook!(CryptHashDataHook, "advapi32.dll", b"CryptHashData\0", |a, b, c, d| hooked_crypt_hash_data(a, b, c, d));
        }
    }

    /*
    if config.hook_nt_create_thread_ex {
        dyn_hook!(NtCreateThreadExHook, "ntdll.dll", b"NtCreateThreadEx\0", |a, b, c, d, e, f, g, h, i, j, k| hooked_nt_create_thread_ex(a, b, c, d, e, f, g, h, i, j, k));
    }
    */
    if config.hook_system {
        dyn_hook!(SystemHook, "msvcrt.dll", b"system\0", |a| hooked_system(a));
    }
    if config.hook_shell_execute_ex_w {
        dyn_hook!(ShellExecuteExWHook, "shell32.dll", b"ShellExecuteExW\0", |a| hooked_shell_execute_ex_w(a));
    }
}

pub unsafe fn hooked_shell_execute_ex_w(p_shellexecuteinfo: *mut c_void) -> BOOL {
    // A more complex structure to parse here, for now we just log the call.
    if let Some(_guard) = ReentrancyGuard::new() {
        log_event(
            LogLevel::Warn,
            LogEvent::ApiHook {
                function_name: "ShellExecuteExW".to_string(),
                parameters: json!({ "note": "Extended shell execution attempt." }),
                stack_trace: Some(capture_stack_trace(CONFIG.stack_trace_frame_limit)),
            },
        );
    }
    ShellExecuteExWHook.call(p_shellexecuteinfo)
}