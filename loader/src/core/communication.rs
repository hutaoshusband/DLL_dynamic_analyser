use std::{
    sync::{mpsc::Sender, Arc, Mutex},
    thread,
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::{GetLastError, INVALID_HANDLE_VALUE, ERROR_PIPE_BUSY},
    Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile, OPEN_EXISTING, FILE_GENERIC_READ,
        FILE_GENERIC_WRITE,
    },
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
    const MAX_RETRIES: u32 = 10; // Total wait time up to 10 * 500ms = 5 seconds
    const RETRY_DELAY_MS: u64 = 500;

    let mut pipe_handle = INVALID_HANDLE_VALUE;

    for i in 0..MAX_RETRIES {
        pipe_handle = unsafe {
            CreateFileW(
                wide_pipe_name.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                0, // Not using FILE_FLAG_OVERLAPPED for the initial connection
                0,
            )
        };

        if pipe_handle != INVALID_HANDLE_VALUE {
            break; // Success
        }

        let err = unsafe { GetLastError() };
        if err != ERROR_PIPE_BUSY {
            *status_arc.lock().unwrap() = format!("Failed to connect to pipe. Error: {}", err);
            return false;
        }

        // Pipe is busy, wait and retry
        *status_arc.lock().unwrap() = format!("Pipe is busy, retrying... ({}/{})", i + 1, MAX_RETRIES);
        thread::sleep(Duration::from_millis(RETRY_DELAY_MS));
    }

    if pipe_handle != INVALID_HANDLE_VALUE {
        let mut pipe_handle_guard = pipe_handle_arc.lock().unwrap();
        *pipe_handle_guard = Some(pipe_handle);
        drop(pipe_handle_guard); // Release lock before potentially long operations

        let config_json = serde_json::to_string(config).unwrap();
        let config_bytes = config_json.as_bytes();
        let config_len = config_bytes.len() as u32;

        // Prepend the size of the JSON data to the message.
        let mut data_to_send = Vec::with_capacity(4 + config_bytes.len());
        data_to_send.extend_from_slice(&config_len.to_ne_bytes());
        data_to_send.extend_from_slice(config_bytes);

        let mut bytes_written = 0;
        let success = unsafe {
            WriteFile(
                pipe_handle,
                data_to_send.as_ptr() as *const _,
                data_to_send.len() as u32,
                &mut bytes_written,
                std::ptr::null_mut(),
            )
        };
        if success == 0 || bytes_written as usize != data_to_send.len() {
            let err = unsafe { GetLastError() };
            *status_arc.lock().unwrap() = format!("Failed to write config to pipe (wrote {}/{} bytes): {}", bytes_written, data_to_send.len(), err);
            return false;
        }

        *status_arc.lock().unwrap() = "Configuration sent. Monitoring...".to_string();
        start_pipe_log_listener(pipe_handle, logger);
        true
    } else {
        let err = unsafe { GetLastError() };
        *status_arc.lock().unwrap() = format!("Failed to connect to pipe: {}", err);
        false
    }
}