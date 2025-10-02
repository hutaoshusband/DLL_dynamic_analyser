use chrono::{DateTime, Utc};
use serde::Serialize;
use std::ffi::c_void;
use windows_sys::Win32::System::Diagnostics::Debug::RtlCaptureStackBackTrace;
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, GetCurrentThreadId};

// The maximum number of stack frames to capture.
const MAX_STACK_FRAMES: usize = 64;

/// Captures the current call stack, returning a vector of function addresses.
pub fn capture_stack_trace() -> Vec<String> {
    let mut back_trace: [*mut c_void; MAX_STACK_FRAMES] = [std::ptr::null_mut(); MAX_STACK_FRAMES];
    // We skip the first frame, which is this function itself.
    let frames = unsafe { RtlCaptureStackBackTrace(1, MAX_STACK_FRAMES as u32, back_trace.as_mut_ptr(), std::ptr::null_mut()) };

    (0..frames)
        .map(|i| format!("{:#x}", back_trace[i as usize] as usize))
        .collect()
}

/// Represents a single log entry in a structured, serializable format.
#[derive(Serialize, Debug)]
pub struct LogEntry {
    #[serde(with = "chrono::serde::ts_seconds")]
    pub timestamp: DateTime<Utc>,
    pub process_id: u32,
    pub thread_id: u32,
    #[serde(flatten)]
    pub event: LogEvent,
    pub stack_trace: Vec<String>,
}

impl LogEntry {
    /// Creates a new LogEntry for a given event, automatically capturing
    /// the timestamp, process ID, thread ID, and stack trace.
    pub fn new(event: LogEvent) -> Self {
        Self {
            timestamp: Utc::now(),
            process_id: unsafe { GetCurrentProcessId() },
            thread_id: unsafe { GetCurrentThreadId() },
            event,
            stack_trace: capture_stack_trace(),
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