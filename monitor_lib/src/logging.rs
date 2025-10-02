use crate::config::{LogLevel, CONFIG};
use chrono::{DateTime, Utc};
use serde::Serialize;
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

/// Represents a single log entry in a structured, serializable format.
#[derive(Serialize, Debug)]
pub struct LogEntry {
    #[serde(with = "chrono::serde::ts_seconds")]
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    pub process_id: u32,
    pub thread_id: u32,
    #[serde(flatten)]
    pub event: LogEvent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack_trace: Option<Vec<String>>,
}

impl LogEntry {
    /// Creates a new LogEntry for a given event, automatically capturing
    /// the timestamp, process ID, and thread ID. The stack trace is captured
    /// conditionally based on the global configuration and the event's log level.
    pub fn new(level: LogLevel, event: LogEvent) -> Self {
        let should_capture_stack = if CONFIG.stack_trace_on_error_only {
            level == LogLevel::Error
        } else {
            true // Capture if the setting is disabled
        };

        let stack_trace = if should_capture_stack {
            Some(capture_stack_trace(CONFIG.stack_trace_frame_limit))
        } else {
            None
        };

        Self {
            timestamp: Utc::now(),
            level,
            process_id: unsafe { GetCurrentProcessId() },
            thread_id: unsafe { GetCurrentThreadId() },
            event,
            stack_trace,
        }
    }
}

/// Enumerates the different types of events that can be logged.
#[derive(Serialize, Debug)]
#[serde(tag = "event_type", content = "details")]
pub enum LogEvent {
    Initialization {
        status: String,
    },
    Shutdown {
        status: String,
    },
    ApiHook {
        function_name: String,
        parameters: serde_json::Value,
    },
    MemoryScan {
        status: String,
        result: String,
    },
    Error {
        source: String,
        message: String,
    },
}