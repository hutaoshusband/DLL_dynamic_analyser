use crate::config::LogLevel;
use crate::log_event;
use crate::logging::LogEvent;
use crate::scanner;
use lazy_static::lazy_static;
use retour::static_detour;
use serde_json::json;
use std::ffi::c_void;
use std::mem::transmute;

// The signature of the target function:
// web::http::client::details::_http_client_communicator::async_send_request_impl
const CPPREST_SIGNATURE: &str = "48 89 5C 24 ? 48 89 74 24 ? 57 48 81 EC ? ? ? ? 48 8B F2 48 8B D9";

lazy_static! {
    static ref CPPREST_SEND_REQUEST_FN_ADDR: Option<usize> = {
        scanner::find_signature(CPPREST_SIGNATURE)
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
    request_ptr: *const c_void, // This is a pointer to a std::shared_ptr<http_request_impl>
) -> *const c_void {
    // The request_ptr argument is a pointer to a shared_ptr. To get the actual
    // pointer to the http_request_impl object, we need to dereference it once.
    let actual_request_ptr = *(request_ptr as *const *const c_void);

    // These offsets are specific to the version of cpprestsdk being targeted
    // and may need adjustment for different versions.
    // Offsets for http_request_impl structure:
    let method = extract_wide_string(actual_request_ptr, 8);
    let path = extract_wide_string(actual_request_ptr, 32);
    let host = extract_wide_string(actual_request_ptr, 48);
    let scheme = extract_wide_string(actual_request_ptr, 16);

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