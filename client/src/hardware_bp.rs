// Copyright (c) 2024 HUTAOSHUSBAND - Wallbangbros.com/FireflyProtector.xyz

use crate::log_event;
use serde_json::json;
use shared::logging::{LogEvent, LogLevel};
use windows_sys::Win32::System::Diagnostics::Debug::{GetThreadContext, CONTEXT};
use windows_sys::Win32::System::Threading::GetCurrentThread;

#[cfg(target_arch = "x86_64")]
const CONTEXT_DEBUG_REGISTERS: u32 = 0x00100010;
#[cfg(target_arch = "x86")]
const CONTEXT_DEBUG_REGISTERS: u32 = 0x00010010;

pub unsafe fn check_debug_registers() {
    let mut context: CONTEXT = std::mem::zeroed();
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    let thread = GetCurrentThread();
    if GetThreadContext(thread, &mut context) != 0 {
        if context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0 {
            log_event(
                LogLevel::Warn,
                LogEvent::AntiDebugCheck {
                    function_name: "HardwareBreakpointDetection".to_string(),
                    parameters: json!({
                        "dr0": context.Dr0,
                        "dr1": context.Dr1,
                        "dr2": context.Dr2,
                        "dr3": context.Dr3,
                    }),
                    stack_trace: None,
                },
            );
        }
    }
}
