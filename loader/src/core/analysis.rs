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

use crate::app::state::MonitorConfig;

use super::{communication, injection};

pub fn start_analysis_thread(
    logger: Sender<String>,
    target_process_name: Option<String>,
    target_pid: Option<u32>,
    dll_path: &Path,
    config: MonitorConfig,
    pid_arc: Arc<Mutex<Option<u32>>>,
    handle_arc: Arc<Mutex<Option<isize>>>,
    pipe_arc: Arc<Mutex<Option<isize>>>,
    running_arc: Arc<AtomicBool>,
    status_arc: Arc<Mutex<String>>,
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
            pipe_arc,
            running_arc,
            status_arc,
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
    pipe_arc: Arc<Mutex<Option<isize>>>,
    running_arc: Arc<AtomicBool>,
    status_arc: Arc<Mutex<String>>,
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

    match injection::inject_dll(pid, dll_path) {
        Ok(handle) => {
            *handle_arc.lock().unwrap() = Some(handle);
            thread::sleep(Duration::from_millis(500)); // Wait for DLL to initialize

            if communication::connect_and_send_config(
                pid,
                &config,
                pipe_arc.clone(),
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