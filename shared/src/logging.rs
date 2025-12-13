// Copyright (c) 2024 HUTAOSHUSBAND - Wallbangbros.com/FireflyProtector.xyz

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: usize,
    pub virtual_size: usize,
    pub characteristics: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "event_type", content = "details")]
pub enum LogEvent {
    Initialization {
        status: String,
    },
    Shutdown {
        status: String,
    },
    Error {
        source: String,
        message: String,
    },
    FileOperation {
        path: String,
        operation: String,
        details: String,
    },
    VmpSectionFound {
        module_path: String,
        section_name: String,
    },
    SectionList {
        sections: Vec<SectionInfo>,
    },
    SectionDump {
        name: String,
        data: Vec<u8>,
    },
    EntropyResult {
        name: String,
        entropy: Vec<f32>,
    },
    ModuleDump {
        module_name: String,
        data: Vec<u8>,
    },
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
    ProcessEnumeration {
        function_name: String,
        parameters: serde_json::Value,
    },
    MemoryScan {
        status: String,
        result: String,
    },
    VmpTrace {
        message: String,
        details: serde_json::Value,
    },
    StaticAnalysis {
        finding: String,
        details: String,
    },
    StringDump {
        address: usize,
        value: String,
        encoding: String,
    },
    UnpackerActivity {
        source_address: usize,
        finding: String,
        details: String,
    },
    FullEntropyResult {
        module_name: String,
        entropy: Vec<f32>,
    },
    YaraMatch {
        rule_name: String,
        address: usize,
        region_size: usize,
        metadata: String,
    },
    Message(String),
}

impl PartialEq for LogEvent {
    fn eq(&self, other: &Self) -> bool {
        serde_json::to_string(self).unwrap_or_default()
            == serde_json::to_string(other).unwrap_or_default()
    }
}

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
    pub origin_suspicious: bool,
}

impl PartialEq for LogEntry {
    fn eq(&self, other: &Self) -> bool {
        self.level == other.level && self.event == other.event
    }
}

impl LogEntry {
    pub fn new_from_loader(level: LogLevel, event: LogEvent) -> Self {
        Self {
            timestamp: Utc::now(),
            level,
            process_id: 0, // Loader doesn't know this
            thread_id: 0,  // Loader doesn't know this
            suspicion_score: 0,
            event,
            stack_trace: None,
            origin_suspicious: false,
        }
    }
}
