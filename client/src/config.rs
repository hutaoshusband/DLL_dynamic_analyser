// Copyright (c) 2024 HUTAOSHUSBAND - Wallbangbros.com/FireflyProtector.xyz

#![allow(dead_code)]

use once_cell::sync::Lazy;
use shared::MonitorConfig;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    RwLock,
};

pub struct Features {
    pub features: RwLock<MonitorConfig>,
    pub termination_allowed: AtomicBool,
    pub stack_trace_on_error: bool,
    pub stack_trace_frame_limit: usize,
}

impl Features {
    pub fn is_termination_allowed(&self) -> bool {
        self.termination_allowed.load(Ordering::SeqCst)
    }
}

pub static CONFIG: Lazy<Features> = Lazy::new(|| {
    let mut config = MonitorConfig::default();
    let stack_trace_on_error = std::env::var("MONITOR_STACK_TRACE_ON_ERROR")
        .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
        .unwrap_or(true);
    let stack_trace_frame_limit = std::env::var("MONITOR_STACK_TRACE_FRAME_LIMIT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(16);

    config.stack_trace_on_error = stack_trace_on_error;
    config.stack_trace_frame_limit = stack_trace_frame_limit;

    Features {
        features: RwLock::new(config),
        termination_allowed: AtomicBool::new(false),
        stack_trace_on_error,
        stack_trace_frame_limit,
    }
});
