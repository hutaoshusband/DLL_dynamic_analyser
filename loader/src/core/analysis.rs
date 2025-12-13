// Copyright (c) 2024 HUTAOSHUSBAND - Wallbangbros.com/FireflyProtector.xyz

use crate::app::state::AppState;
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::Sender,
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
use windows_sys::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};

use shared::MonitorConfig;

use super::{communication, injection};

pub fn start_auto_inject_thread(state: &mut AppState) {
    let auto_inject_enabled = state.auto_inject_enabled.clone();
    let is_process_running = state.is_process_running.clone();
    let target_process_name = state.target_process_name.clone();
    let dll_path = state.dll_path.clone();
    let log_sender = state.log_sender.clone();
    let monitor_config = state.monitor_config.clone();
    let process_id = state.process_id.clone();
    let process_handle = state.process_handle.clone();
    let commands_pipe_handle = state.commands_pipe_handle.clone();
    let logs_pipe_handle = state.logs_pipe_handle.clone();
    let injection_status = state.injection_status.clone();

    let handle = thread::spawn(move || {
        while auto_inject_enabled.load(Ordering::SeqCst) {
            if !is_process_running.load(Ordering::SeqCst) {
                if let Some(dll_path) = dll_path.clone() {
                    run_analysis(
                        log_sender.clone(),
                        Some(target_process_name.as_str()),
                        None,
                        &dll_path,
                        monitor_config.clone(),
                        process_id.clone(),
                        process_handle.clone(),
                        commands_pipe_handle.clone(),
                        logs_pipe_handle.clone(),
                        is_process_running.clone(),
                        injection_status.clone(),
                        false, // Auto-inject doesn't support manual map yet or defaults to false
                    );
                }
            }
            thread::sleep(Duration::from_secs(2));
        }
    });

    *state.auto_inject_thread.lock().unwrap() = Some(handle);
}

pub fn start_analysis_thread(
    logger: Sender<String>,
    target_process_name: Option<String>,
    target_pid: Option<u32>,
    dll_path: &Path,
    config: MonitorConfig,
    pid_arc: Arc<Mutex<Option<u32>>>,
    handle_arc: Arc<Mutex<Option<isize>>>,
    commands_pipe_arc: Arc<Mutex<Option<isize>>>,
    logs_pipe_arc: Arc<Mutex<Option<isize>>>,
    running_arc: Arc<AtomicBool>,
    status_arc: Arc<Mutex<String>>,
    use_manual_map: bool,
) {
    let dll_path_owned = dll_path.to_owned();
    thread::spawn(move || {
        run_analysis(
            logger,
            target_process_name.as_deref(),
            target_pid,
            &dll_path_owned,
            config,
            pid_arc,
            handle_arc,
            commands_pipe_arc,
            logs_pipe_arc,
            running_arc,
            status_arc,
            use_manual_map,
        );
    });
}

fn run_analysis(
    logger: Sender<String>,
    target_process_name: Option<&str>,
    target_pid: Option<u32>,
    dll_path: &Path,
    config: MonitorConfig,
    pid_arc: Arc<Mutex<Option<u32>>>,
    handle_arc: Arc<Mutex<Option<isize>>>,
    commands_pipe_arc: Arc<Mutex<Option<isize>>>,
    logs_pipe_arc: Arc<Mutex<Option<isize>>>,
    running_arc: Arc<AtomicBool>,
    status_arc: Arc<Mutex<String>>,
    use_manual_map: bool,
) {
    running_arc.store(true, Ordering::SeqCst);

    let pid = match target_pid {
        Some(p) => Some(p),
        None => {
            let name = target_process_name.unwrap_or("");
            *status_arc.lock().unwrap() = format!("Searching for process: {}...", name);
            injection::find_process_id(name)
        }
    };

    let Some(pid) = pid else {
        *status_arc.lock().unwrap() = "Process not found.".to_string();
        running_arc.store(false, Ordering::SeqCst);
        return;
    };

    *pid_arc.lock().unwrap() = Some(pid);
    *status_arc.lock().unwrap() = format!("Injecting into PID {}...", pid);

    *status_arc.lock().unwrap() = format!("Injecting into PID {}...", pid);

    let injection_result = if use_manual_map {
        injection::manual_map_inject(pid, dll_path)
    } else {
        injection::inject_dll(pid, dll_path)
    };

    match injection_result {
        Ok(handle) => {
            *handle_arc.lock().unwrap() = Some(handle);
            thread::sleep(Duration::from_millis(500)); // Wait for DLL to initialize

            if communication::connect_and_send_config(
                pid,
                &config,
                commands_pipe_arc.clone(),
                logs_pipe_arc.clone(),
                status_arc.clone(),
                logger.clone(),
            ) {
                let running_clone = running_arc.clone();
                let status_clone = status_arc.clone();
                thread::spawn(move || {
                    unsafe { WaitForSingleObject(handle, u32::MAX) };
                    if running_clone.load(Ordering::SeqCst) {
                        *status_clone.lock().unwrap() = "Process terminated.".to_string();
                        running_clone.store(false, Ordering::SeqCst);
                    }
                });
            } else {
                running_arc.store(false, Ordering::SeqCst);
            }
        }
        Err(e) => {
            *status_arc.lock().unwrap() = format!("Injection failed: {}", e);
            running_arc.store(false, Ordering::SeqCst);
        }
    }
}

pub fn terminate_process(handle_arc: Arc<Mutex<Option<isize>>>) {
    if let Some(handle) = *handle_arc.lock().unwrap() {
        unsafe { TerminateProcess(handle, 1) };
    }
}
