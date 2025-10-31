// Copyright (c) 2024 HUTAOSHUSBAND - Wallbangbros.com/CodeConfuser.dev
// All rights reserved.


use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// This enum is now the single source of truth for log levels.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Fatal = 0,
    Error = 1,
    Success = 2,
    Warn = 3,
    Info = 4,
    Debug = 5,
    Trace = 6,
}

// This struct is now the single source of truth for PE section info.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: usize,
    pub virtual_size: usize,
    pub characteristics: u32,
}

// This enum is now the single source of truth for all possible log events.
// It combines the variants from both the old loader and client definitions.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "event_type", content = "details")]
pub enum LogEvent {
    // Variants from both
    Initialization { status: String },
    Shutdown { status: String },
    Error { source: String, message: String },
    FileOperation { path: String, operation: String, details: String },
    VmpSectionFound { module_path: String, section_name: String },
    SectionList { sections: Vec<SectionInfo> },
    SectionDump { name: String, data: Vec<u8> },
    EntropyResult { name: String, entropy: Vec<f32> },
    ModuleDump { module_name: String, data: Vec<u8> },
    ApiHook {
        function_name: String,
        parameters: serde_json::Value,
        #[serde(skip_serializing_if = "Option::is_none")]
        stack_trace: Option<Vec<String>>,
    },
    AntiDebugCheck {
        function_name: String,
        parameters: serde_json::Value,
        #[serde(skip_serializing_if = "Option::is_none")]
        stack_trace: Option<Vec<String>>,
    },
    ProcessEnumeration { function_name: String, parameters: serde_json::Value },
    MemoryScan { status: String, result: String },
    // Client-specific variants
    VmpTrace { message: String, details: serde_json::Value },
    StaticAnalysis { finding: String, details: String },
    StringDump { address: usize, value: String, encoding: String },
    UnpackerActivity { source_address: usize, finding: String, details: String },
    // Loader-specific variant
    Message(String),
}

// Custom PartialEq to handle JSON value comparison
impl PartialEq for LogEvent {
    fn eq(&self, other: &Self) -> bool {
        serde_json::to_string(self).unwrap_or_default() == serde_json::to_string(other).unwrap_or_default()
    }
}

// This struct is now the single source of truth for a log entry.
#[derive(Serialize, Deserialize, Debug)]
pub struct LogEntry {
    #[serde(with = "chrono::serde::ts_seconds")]
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    pub process_id: u32,
    pub thread_id: u32,
    pub suspicion_score: usize,
    #[serde(flatten)]
    pub event: LogEvent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack_trace: Option<Vec<String>>,
}

// Custom PartialEq for deduplication logic in the loader
impl PartialEq for LogEntry {
    fn eq(&self, other: &Self) -> bool {
        self.level == other.level && self.event == other.event
    }
}

// Helper function for creating log entries in the loader
impl LogEntry {
    pub fn new_from_loader(level: LogLevel, event: LogEvent) -> Self {
        Self {
            timestamp: Utc::now(),
            level,
            process_id: 0, // Loader doesn't know this
            thread_id: 0, // Loader doesn't know this
            suspicion_score: 0,
            event,
            stack_trace: None,
        }
    }
}