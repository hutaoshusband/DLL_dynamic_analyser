use once_cell::sync::Lazy;
use serde::Serialize;
use std::str::FromStr;

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
    Trace = 4,
}

impl FromStr for LogLevel {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "error" => Ok(LogLevel::Error),
            "warn" => Ok(LogLevel::Warn),
            "info" => Ok(LogLevel::Info),
            "debug" => Ok(LogLevel::Debug),
            "trace" => Ok(LogLevel::Trace),
            _ => Ok(LogLevel::Info), // Default level
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub log_level: LogLevel,
    pub stack_trace_on_error_only: bool,
    pub stack_trace_frame_limit: usize,
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
        }
    }
}

pub static CONFIG: Lazy<Config> = Lazy::new(Config::from_env);