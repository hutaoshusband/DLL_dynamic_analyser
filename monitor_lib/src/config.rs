use once_cell::sync::{Lazy, OnceCell};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::atomic::AtomicBool;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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
            _ => Ok(LogLevel::Info),
        }
    }
}

/// Configuration sent from the GUI to the DLL to control what features are enabled.
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct MonitorConfig {
    pub api_hooks_enabled: bool,
    pub iat_scan_enabled: bool,
    pub string_dump_enabled: bool,
    pub vmp_dump_enabled: bool,
    pub manual_map_scan_enabled: bool,
    pub network_hooks_enabled: bool,
    pub crypto_hooks_enabled: bool,
    pub registry_hooks_enabled: bool,
    pub log_network_data: bool,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            api_hooks_enabled: true,
            iat_scan_enabled: true,
            string_dump_enabled: false,
            vmp_dump_enabled: true,
            manual_map_scan_enabled: true,
            network_hooks_enabled: true,
            crypto_hooks_enabled: true,
            registry_hooks_enabled: true,
            log_network_data: false,
        }
    }
}

#[derive(Debug)]
pub struct Config {
    pub log_level: LogLevel,
    pub stack_trace_on_error_only: bool,
    pub stack_trace_frame_limit: usize,
    pub termination_allowed: AtomicBool,
    pub features: OnceCell<MonitorConfig>,
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
            .unwrap_or(16);

        Self {
            log_level,
            stack_trace_on_error_only,
            stack_trace_frame_limit,
            termination_allowed: AtomicBool::new(false),
            features: OnceCell::new(),
        }
    }
}

pub static CONFIG: Lazy<Config> = Lazy::new(Config::from_env);