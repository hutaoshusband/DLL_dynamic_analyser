use crate::config::LogLevel;
use crate::log_event;
use crate::logging::LogEvent;
use serde_json::json;
use windows_sys::Win32::System::Diagnostics::Debug::{CONTEXT, GetThreadContext};
use windows_sys::Win32::System::Threading::GetCurrentThread;

// Define the CONTEXT_DEBUG_REGISTERS flag locally if it's not available in the current windows-sys version.
#[cfg(target_arch = "x86_64")]
const CONTEXT_DEBUG_REGISTERS: u32 = 0x00100010;
#[cfg(target_arch = "x86")]
const CONTEXT_DEBUG_REGISTERS: u32 = 0x00010010;

/// Checks the current thread's context for any active hardware breakpoints (DR0-DR3).
/// This is a common anti-debugging technique.
pub unsafe fn check_debug_registers() {
    let mut context: CONTEXT = std::mem::zeroed();
    // We must specify the flags for the context we want to retrieve.
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    let thread = GetCurrentThread();
    if GetThreadContext(thread, &mut context) != 0 {
        if context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0 {
            log_event(LogLevel::Warn, LogEvent::AntiDebugCheck {
                function_name: "HardwareBreakpointDetection".to_string(),
                parameters: json!({
                    "dr0": context.Dr0,
                    "dr1": context.Dr1,
                    "dr2": context.Dr2,
                    "dr3": context.Dr3,
                }),
                stack_trace: None,
            });
        }
    }
}