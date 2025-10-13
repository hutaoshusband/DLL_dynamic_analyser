#![allow(dead_code)]

use once_cell::sync::Lazy;
use shared::MonitorConfig;
use std::sync::{atomic::{AtomicBool, Ordering}, RwLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum LogLevel {
    Fatal = 0,
    Error = 1,
    Success = 2,
    Warn = 3,
    Info = 4,
    Debug = 5,
    Trace = 6,
}

impl LogLevel {
    pub fn from_env() -> Self {
        match std::env::var("MONITOR_LOG_LEVEL").as_deref() {
            Ok("FATAL") => LogLevel::Fatal,
            Ok("ERROR") => LogLevel::Error,
            Ok("SUCCESS") => LogLevel::Success,
            Ok("WARN") => LogLevel::Warn,
            Ok("INFO") => LogLevel::Info,
            Ok("DEBUG") => LogLevel::Debug,
            Ok("TRACE") => LogLevel::Trace,
            _ => LogLevel::Info, // Default
        }
    }
}

pub struct Features {
    pub features: RwLock<MonitorConfig>,
    pub termination_allowed: AtomicBool,
    pub log_level: LogLevel,
    pub stack_trace_on_error: bool,
    pub stack_trace_frame_limit: usize,
}

impl Features {
    pub fn is_termination_allowed(&self) -> bool {
        self.termination_allowed.load(Ordering::SeqCst)
    }
}

pub static CONFIG: Lazy<Features> = Lazy::new(|| Features {
    features: RwLock::new(MonitorConfig::default()),
    termination_allowed: AtomicBool::new(false),
    log_level: LogLevel::from_env(),
    stack_trace_on_error: std::env::var("MONITOR_STACK_TRACE_ON_ERROR")
        .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
        .unwrap_or(true),
    stack_trace_frame_limit: std::env::var("MONITOR_STACK_TRACE_FRAME_LIMIT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(16),
});