#![allow(dead_code, unused_variables)]
use crate::config::CONFIG;
use crate::SUSPICION_SCORE;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use shared::logging::{LogEntry, LogEvent, LogLevel};
use std::ffi::c_void;
use windows_sys::Win32::System::Diagnostics::Debug::RtlCaptureStackBackTrace;
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, GetCurrentThreadId};

/// Captures the current call stack, returning a vector of function addresses.
pub fn capture_stack_trace(max_frames: usize) -> Vec<String> {
    let mut back_trace: Vec<*mut c_void> = vec![std::ptr::null_mut(); max_frames];
    // We skip the first frame, which is this function itself.
    let frames = unsafe {
        RtlCaptureStackBackTrace(
            1,
            max_frames as u32,
            back_trace.as_mut_ptr(),
            std::ptr::null_mut(),
        )
    };

    (0..frames)
        .map(|i| format!("{:#x}", back_trace[i as usize] as usize))
        .collect()
}

/// Creates a new LogEntry for a given event, automatically capturing
/// the timestamp, process ID, and thread ID. The stack trace is captured
/// conditionally based on the global configuration and the event's log level,
/// unless a stack trace is already provided with the event itself.
pub fn create_log_entry(level: LogLevel, mut event: LogEvent) -> LogEntry {
    // Check if the event itself comes with a stack trace.
    // We take it from the event, so it's not duplicated in the final JSON.
    let event_stack_trace = match &mut event {
        LogEvent::ApiHook { stack_trace, .. } => stack_trace.take(),
        LogEvent::AntiDebugCheck { stack_trace, .. } => stack_trace.take(),
        _ => None,
    };

    let final_stack_trace = if event_stack_trace.is_some() {
        event_stack_trace
    } else {
        // Fallback to the original logic if no trace is provided in the event.
        let should_capture_stack = if CONFIG.stack_trace_on_error {
            // For Fatal and Error, we always want a trace if possible.
            level == LogLevel::Error || level == LogLevel::Fatal
        } else {
            true // Capture if the setting is disabled
        };

        if should_capture_stack {
            Some(capture_stack_trace(CONFIG.stack_trace_frame_limit))
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