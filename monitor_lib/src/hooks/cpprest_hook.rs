use crate::config::LogLevel;
use crate::log_event;
use crate::logging::LogEvent;
use lazy_static::lazy_static;
use patternscan::scan;
use retour::static_detour;
use serde_json::json;
use std::ffi::c_void;
use std::io::Cursor;
use std::mem::transmute;
use std::slice;
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;

// The signature of the target function:
// web::http::client::details::_http_client_communicator::async_send_request_impl
const CPPREST_SIGNATURE: &str = "48 89 5C 24 ? 48 89 74 24 ? 57 48 81 EC ? ? ? ? 48 8B F2 48 8B D9";

/// Gets a slice representing the memory of the main executable module.
/// This is unsafe because it involves reading directly from memory based on PE header information.
unsafe fn get_main_module_slice() -> Option<&'static [u8]> {
    let base_addr = GetModuleHandleW(std::ptr::null_mut()) as *const u8;
    if base_addr.is_null() {
        return None;
    }
    let dos_header = &*(base_addr as *const IMAGE_DOS_HEADER);
    if dos_header.e_magic != 0x5A4D { // "MZ"
        return None;
    }
    let nt_headers_ptr = base_addr.add(dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    let nt_headers = &*nt_headers_ptr;
    if nt_headers.Signature != 0x4550 { // "PE\0\0"
        return None;
    }
    let size_of_image = nt_headers.OptionalHeader.SizeOfImage;
    Some(slice::from_raw_parts(base_addr, size_of_image as usize))
}

lazy_static! {
    static ref CPPREST_SEND_REQUEST_FN_ADDR: Option<usize> = {
        unsafe {
            if let Some(module_slice) = get_main_module_slice() {
                let base_address = module_slice.as_ptr() as usize;
                // Use a cursor to read from the in-memory slice
                let mut cursor = Cursor::new(module_slice);
                // The scan function gives us offsets from the start of the slice
                if let Ok(offsets) = scan(&mut cursor, CPPREST_SIGNATURE) {
                    // We only need the first match
                    offsets.first().map(|offset| base_address + offset)
                } else {
                    None
                }
            } else {
                None
            }
        }
    };
}

static_detour! {
    static CppRestSendRequestHook: unsafe extern "system" fn(
        *const c_void, // this_ptr (_http_client_communicator)
        *const c_void  // request_ptr (http_request_impl)
    ) -> *const c_void;
}

/// Extracts a wide string (UTF-16) from a given memory address.
/// This is highly unsafe and depends on the specific structure of cpprest's internal objects.
unsafe fn extract_wide_string(base_ptr: *const c_void, offset: isize) -> String {
    if base_ptr.is_null() {
        return "<null_base_ptr>".to_string();
    }
    let wide_str_ptr = *(base_ptr.offset(offset) as *const *const u16);
    if wide_str_ptr.is_null() {
        return "<null_string_ptr>".to_string();
    }
    widestring::U16CStr::from_ptr_str(wide_str_ptr).to_string_lossy()
}

/// The hook handler for the cpprest send request function.
/// It intercepts the call, logs the request details, and then calls the original function.
unsafe fn hooked_cpprest_send_request(
    this_ptr: *const c_void,
    request_ptr: *const c_void,
) -> *const c_void {
    // These offsets are specific to the version of cpprestsdk being targeted
    // and may need adjustment for different versions.
    // Offsets for http_request_impl structure:
    let method = extract_wide_string(request_ptr, 8);
    let path = extract_wide_string(request_ptr, 32);
    let host = extract_wide_string(request_ptr, 48);
    let scheme = extract_wide_string(request_ptr, 16);

    log_event(LogLevel::Info, LogEvent::ApiHook {
        function_name: "cpprest_send_request".to_string(),
        parameters: json!({
            "scheme": scheme,
            "host": host,
            "path": path,
            "method": method,
        }),
    });

    // Call the original function to ensure the application continues to work correctly.
    CppRestSendRequestHook.call(this_ptr, request_ptr)
}

/// Initializes the cpprest hook.
/// This function finds the target function in memory using its signature and, if found,
/// applies the hook. This should be called once during DLL initialization.
pub fn initialize_and_enable_hook() {
    if let Some(addr) = *CPPREST_SEND_REQUEST_FN_ADDR {
        log_event(LogLevel::Info, LogEvent::Initialization {
            status: format!("Found cpprest!_http_client_communicator::async_send_request_impl at address: {:#X}", addr),
        });
        
        unsafe {
            let target_fn = transmute(addr);
            
            // The `initialize` function expects a closure, so we wrap our unsafe function call.
            let hook_result = CppRestSendRequestHook.initialize(
                target_fn, 
                |this, req| hooked_cpprest_send_request(this, req)
            );

            if hook_result.is_err() {
                log_event(LogLevel::Error, LogEvent::Error {
                    source: "cpprest_hook".to_string(),
                    message: "Failed to initialize cpprest hook".to_string(),
                });
                return;
            }
            
            if CppRestSendRequestHook.enable().is_err() {
                 log_event(LogLevel::Error, LogEvent::Error {
                    source: "cpprest_hook".to_string(),
                    message: "Failed to enable cpprest hook".to_string(),
                });
            } else {
                 log_event(LogLevel::Info, LogEvent::Initialization {
                    status: "Successfully enabled cpprest hook.".to_string(),
                });
            }
        }
    } else {
        log_event(LogLevel::Warn, LogEvent::Initialization {
            status: "cpprest function signature not found. Hook not applied.".to_string(),
        });
    }
}