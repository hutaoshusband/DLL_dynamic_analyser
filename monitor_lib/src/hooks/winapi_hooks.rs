use crate::config::LogLevel;
use crate::log_event;
use crate::logging::LogEvent;
use retour::static_detour;
use serde_json::json;
use std::slice;
use widestring::U16CStr;
use windows_sys::Win32::Foundation::{BOOL, HANDLE};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_READ, FILE_GENERIC_WRITE};
use windows_sys::Win32::System::IO::OVERLAPPED;

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
    pub static CreateFileWHook: unsafe extern "system" fn(
        *const u16, u32, u32, *const SECURITY_ATTRIBUTES, u32, u32, HANDLE
    ) -> HANDLE;

    pub static WriteFileHook: unsafe extern "system" fn(
        HANDLE, *const u8, u32, *mut u32, *mut OVERLAPPED
    ) -> BOOL;
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
    log_event(LogLevel::Info, LogEvent::ApiHook {
        function_name: "CreateFileW".to_string(),
        parameters: json!({
            "filePath": safe_u16_str(lp_file_name),
            "desiredAccess": format_access_flags(dw_desired_access),
        }),
    });

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
    log_event(LogLevel::Info, LogEvent::ApiHook {
        function_name: "WriteFile".to_string(),
        parameters: json!({
            "bytesToWrite": n_number_of_bytes_to_write,
            "dataPreview": format_buffer_preview(lp_buffer, n_number_of_bytes_to_write),
        }),
    });

    WriteFileHook.call(
        h_file,
        lp_buffer,
        n_number_of_bytes_to_write,
        lp_number_of_bytes_written,
        lp_overlapped,
    )
}