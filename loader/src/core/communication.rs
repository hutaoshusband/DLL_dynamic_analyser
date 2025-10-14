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

use shared::{Command, MonitorConfig};
use widestring::U16CString;

pub fn start_pipe_log_listener(pipe_handle: isize, logger: Sender<String>) {
    thread::spawn(move || {
        let mut buffer = [0u8; 4096];
        let mut message_buffer = String::new();
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
                let chunk = String::from_utf8_lossy(&buffer[..bytes_read as usize]);
                message_buffer.push_str(&chunk);

                // Process all complete messages (newline-delimited) in the buffer.
                while let Some(newline_pos) = message_buffer.find('\n') {
                    let message = message_buffer.drain(..=newline_pos).collect::<String>();
                    let trimmed_message = message.trim();
                    if !trimmed_message.is_empty() {
                        let _ = logger.send(trimmed_message.to_string());
                    }
                }
            } else {
                // Pipe was closed or an error occurred.
                break;
            }
        }
    });
}

pub fn connect_and_send_config(
    _pid: u32,
    config: &MonitorConfig,
    pipe_handle_arc: Arc<Mutex<Option<isize>>>,
    status_arc: Arc<Mutex<String>>,
    logger: Sender<String>,
) -> bool {
    // Connect to the fixed pipe name.
    let pipe_name = r"\\.\pipe\cs2_monitor_pipe";
    let wide_pipe_name = U16CString::from_str(pipe_name).unwrap();
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
                0,
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

        *status_arc.lock().unwrap() =
            format!("Pipe is busy, retrying... ({}/{})", i + 1, MAX_RETRIES);
        thread::sleep(Duration::from_millis(RETRY_DELAY_MS));
    }

    if pipe_handle != INVALID_HANDLE_VALUE {
        let mut pipe_handle_guard = pipe_handle_arc.lock().unwrap();
        *pipe_handle_guard = Some(pipe_handle);
        drop(pipe_handle_guard);

        // --- Standardized Communication ---
        // Wrap the config in an `UpdateConfig` command and send it as a newline-terminated JSON string.
        let command = Command::UpdateConfig(config.clone());
        let command_json = match serde_json::to_string(&command) {
            Ok(json) => json,
            Err(e) => {
                *status_arc.lock().unwrap() = format!("Failed to serialize config: {}", e);
                return false;
            }
        };
        let command_to_send = format!("{}\n", command_json);
        let bytes_to_send = command_to_send.as_bytes();
        *status_arc.lock().unwrap() = format!("Sending config ({} bytes)...", bytes_to_send.len());

        let mut bytes_written = 0;
        let success = unsafe {
            WriteFile(
                pipe_handle,
                bytes_to_send.as_ptr(),
                bytes_to_send.len() as u32,
                &mut bytes_written,
                std::ptr::null_mut(),
            )
        };

        if success == 0 || bytes_written as usize != bytes_to_send.len() {
            let err = unsafe { GetLastError() };
            *status_arc.lock().unwrap() = format!(
                "Failed to write config to pipe (wrote {}/{} bytes): {}",
                bytes_written,
                bytes_to_send.len(),
                err
            );
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