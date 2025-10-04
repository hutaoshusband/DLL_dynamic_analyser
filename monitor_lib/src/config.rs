use once_cell::sync::Lazy;
use serde::Serialize;
use std::str::FromStr;
use std::sync::atomic::AtomicBool;

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Fatal = 0,
    Error = 1,
    Warn = 2,
    Info = 3,
    Success = 4,
    Debug = 5,
    Trace = 6,
}

impl FromStr for LogLevel {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "fatal" => Ok(LogLevel::Fatal),
            "error" => Ok(LogLevel::Error),
            "warn" => Ok(LogLevel::Warn),
            "info" => Ok(LogLevel::Info),
            "success" => Ok(LogLevel::Success),
            "debug" => Ok(LogLevel::Debug),
            "trace" => Ok(LogLevel::Trace),
            _ => Ok(LogLevel::Info), // Default level
        }
    }
}

#[derive(Debug)]
pub struct Config {
    pub log_level: LogLevel,
    pub stack_trace_on_error_only: bool,
    pub stack_trace_frame_limit: usize,
    pub termination_allowed: AtomicBool,
}

impl Config {
    fn from_env() -> Self {
        let log_level = std::env::var("MONITOR_LOG_LEVEL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(LogLevel::Info);

        let stack_trace_on_error_only = std::env::var("MONITOR_STACK_TRACE_ON_ERROR")
            .ok()
            .and_then(|s| s.parse::<bool>().ok())
            .unwrap_or(true);
        
        let stack_trace_frame_limit = std::env::var("MONITOR_STACK_TRACE_FRAME_LIMIT")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(16); // Default to a reasonable limit

        Self {
            log_level,
            stack_trace_on_error_only,
            stack_trace_frame_limit,
            termination_allowed: AtomicBool::new(false),
        }
    }
}

pub static CONFIG: Lazy<Config> = Lazy::new(Config::from_env);