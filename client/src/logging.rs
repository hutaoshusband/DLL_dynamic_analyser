// Copyright (c) 2024 HUTAOSHUSBAND - Wallbangbros.com/CodeConfuser.dev
// All rights reserved.


#![allow(dead_code, unused_variables)]
use crate::config::CONFIG;
use crate::SUSPICION_SCORE;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use shared::logging::{LogEntry, LogEvent, LogLevel};
use std::ffi::c_void;
use windows_sys::Win32::System::Diagnostics::Debug::RtlCaptureStackBackTrace;
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, GetCurrentThreadId};
use windows_sys::Win32::System::Memory::{
    VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_PRIVATE, MEM_MAPPED
};

/// Internal helper to capture stack and check suspicion.
/// Returns (stack_trace_strings, is_suspicious).
fn capture_stack_trace_internal(max_frames: usize) -> (Vec<String>, bool) {
    let mut back_trace: Vec<*mut c_void> = vec![std::ptr::null_mut(); max_frames];
    // We skip the first frame, which is this function itself.
    // Actually we might want to skip more to hide our own logging overhead, 
    // but 1 is standard for "caller".
    let frames = unsafe {
        RtlCaptureStackBackTrace(
            1,
            max_frames as u32,
            back_trace.as_mut_ptr(),
            std::ptr::null_mut(),
        )
    };

    let mut stack_strings = Vec::new();
    let mut origin_suspicious = false;

    for i in 0..frames {
        let addr = back_trace[i as usize] as usize;
        stack_strings.push(format!("{:#x}", addr));

        if !origin_suspicious && is_address_suspicious(addr) {
            origin_suspicious = true;
        }
    }

    (stack_strings, origin_suspicious)
}

/// Captures the current call stack, returning a vector of function addresses.
/// This matches the original signature expected by winapi_hooks.rs.
pub fn capture_stack_trace(max_frames: usize) -> Vec<String> {
    capture_stack_trace_internal(max_frames).0
}

/// Helper to check if a specific address is from a suspicious memory region.
fn is_address_suspicious(addr: usize) -> bool {
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let result = unsafe {
        VirtualQuery(
            addr as *const c_void,
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };

    if result != 0 {
        if (mbi.State & MEM_COMMIT) != 0 {
             let is_private = (mbi.Type & MEM_PRIVATE) != 0;
             let is_mapped = (mbi.Type & MEM_MAPPED) != 0;
             let is_image = (mbi.Type & MEM_IMAGE) != 0;

             // Suspicious if PRIVATE or (MAPPED and NOT IMAGE)
             if is_private || (is_mapped && !is_image) {
                 return true;
             }
        }
    }
    false
}

/// Helper to check an existing string-based trace for suspicious addresses.
fn check_stack_suspicion(trace: &[String]) -> bool {
    for addr_str in trace {
        // Parse hex string back to usize
        let clean_str = addr_str.trim_start_matches("0x");
        if let Ok(addr) = usize::from_str_radix(clean_str, 16) {
            if is_address_suspicious(addr) {
                return true;
            }
        }
    }
    false
}

/// Creates a new LogEntry for a given event, automatically capturing
/// the timestamp, process ID, and thread ID. The stack trace is captured
/// conditionally based on the global configuration and the event's log level.
pub fn create_log_entry(level: LogLevel, mut event: LogEvent) -> LogEntry {
    // Check if the event itself comes with a stack trace.
    // We take it from the event, so it's not duplicated in the final JSON.
    let event_stack_trace = match &mut event {
        LogEvent::ApiHook { stack_trace, .. } => stack_trace.take(),
        LogEvent::AntiDebugCheck { stack_trace, .. } => stack_trace.take(),
        _ => None,
    };

    let mut origin_suspicious = false;

    let final_stack_trace = if let Some(trace) = event_stack_trace {
        // If the hook already provided a trace (as Vec<String>), 
        // we check it here for suspicious origins.
        if check_stack_suspicion(&trace) {
            origin_suspicious = true;
        }
        Some(trace)
    } else {
        // Fallback: Capture trace if configured
        let should_capture_stack = if CONFIG.stack_trace_on_error {
            level == LogLevel::Error || level == LogLevel::Fatal
        } else {
            true // Capture if the setting is disabled? Logic from original file.
                 // Original logic: "Capture if the setting is disabled" -> seems inverted or specific policy.
                 // Retaining original logic: 
                 // "if CONFIG.stack_trace_on_error { ... } else { true }"
        };

        if should_capture_stack {
            let (trace, suspicious) = capture_stack_trace_internal(CONFIG.stack_trace_frame_limit);
            if suspicious {
                origin_suspicious = true;
            }
            Some(trace)
        } else {
            None
        }
    };

    LogEntry {
        timestamp: Utc::now(),
        level,
        process_id: unsafe { GetCurrentProcessId() },
        thread_id: unsafe { GetCurrentThreadId() },
        suspicion_score: SUSPICION_SCORE.load(std::sync::atomic::Ordering::Relaxed),
        event,
        stack_trace: final_stack_trace,
        origin_suspicious,
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PeHeaderInfo {
    pub machine: String,
    pub timestamp: String,
    pub subsystem: String,
    pub characteristics: String,
    pub image_base: u64,
    pub entry_point: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SectionDetail {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_size: u64,
    pub characteristics: String,
    pub entropy: f32,
}
