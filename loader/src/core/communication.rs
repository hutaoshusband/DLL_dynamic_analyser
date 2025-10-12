use std::{
    sync::{mpsc::Sender, Arc, Mutex},
    thread,
};
use windows_sys::Win32::{
    Foundation::{GetLastError, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{CreateFileW, ReadFile, WriteFile, PIPE_ACCESS_DUPLEX},
};

use shared::MonitorConfig;
use widestring::U16CString;

pub fn start_pipe_log_listener(pipe_handle: isize, logger: Sender<String>) {
    thread::spawn(move || {
        let mut buffer = [0u8; 4096];
        loop {
            let mut bytes_read = 0;
            let success = unsafe {
                ReadFile(
                    pipe_handle,
                    buffer.as_mut_ptr() as _,
                    buffer.len() as u32,
                    &mut bytes_read,
                    std::ptr::null_mut(),
                )
            } != 0;
            if success && bytes_read > 0 {
                let message = String::from_utf8_lossy(&buffer[..bytes_read as usize]);
                for line in message.lines().filter(|l| !l.trim().is_empty()) {
                    let _ = logger.send(line.to_string());
                }
            } else {
                break;
            }
        }
    });
}

pub fn connect_and_send_config(
    pid: u32,
    config: &MonitorConfig,
    pipe_handle_arc: Arc<Mutex<Option<isize>>>,
    status_arc: Arc<Mutex<String>>,
    logger: Sender<String>,
) -> bool {
    let pipe_name = format!(r"\\.\pipe\cs2_monitor_{}", pid);
    let wide_pipe_name = U16CString::from_str(&pipe_name).unwrap();
    let pipe_handle = unsafe {
        CreateFileW(
            wide_pipe_name.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            0,
            std::ptr::null(),
            3,
            0,
            0,
        )
    };

    if pipe_handle != INVALID_HANDLE_VALUE {
        *pipe_handle_arc.lock().unwrap() = Some(pipe_handle);
        let config_json = serde_json::to_string(config).unwrap();
        unsafe {
            WriteFile(
                pipe_handle,
                config_json.as_ptr(),
                config_json.len() as u32,
                &mut 0,
                std::ptr::null_mut(),
            )
        };

        *status_arc.lock().unwrap() = "Configuration sent. Monitoring...".to_string();
        start_pipe_log_listener(pipe_handle, logger);
        true
    } else {
        *status_arc.lock().unwrap() =
            format!("Failed to connect to pipe: {}", unsafe { GetLastError() });
        false
    }
}