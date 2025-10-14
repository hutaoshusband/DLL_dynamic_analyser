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

use shared::{Command, MonitorConfig, COMMANDS_PIPE_NAME, LOGS_PIPE_NAME};
use widestring::U16CString;

pub fn start_pipe_log_listener(
    pipe_handle: isize,
    logger: Sender<String>,
    status_arc: Arc<Mutex<String>>,
) {
    thread::spawn(move || {
        *status_arc.lock().unwrap() = "Listener thread started.".to_string();
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
                *status_arc.lock().unwrap() =
                    format!("Listener: Read {} bytes.", message_buffer.len());

                // Process all complete messages (newline-delimited) in the buffer.
                while let Some(newline_pos) = message_buffer.find('\n') {
                    let message = message_buffer.drain(..=newline_pos).collect::<String>();
                    let trimmed_message = message.trim();
                    if !trimmed_message.is_empty() {
                        let _ = logger.send(trimmed_message.to_string());
                    }
                }
            } else {
                let err = unsafe { GetLastError() };
                *status_arc.lock().unwrap() = format!(
                    "Listener: ReadFile failed or got 0 bytes. success={}, bytes_read={}, err={}. Breaking.",
                    success,
                    bytes_read,
                    err
                );
                break;
            }
        }
    });
}

// A helper function to reduce code duplication for connecting to a named pipe.
fn connect_to_pipe(
    pipe_name: &str,
    access: u32,
    status_arc: &Arc<Mutex<String>>,
) -> Option<isize> {
    let wide_pipe_name = U16CString::from_str(pipe_name).unwrap();
    const MAX_RETRIES: u32 = 10;
    const RETRY_DELAY_MS: u64 = 500;

    for i in 0..MAX_RETRIES {
        let pipe_handle = unsafe {
            CreateFileW(
                wide_pipe_name.as_ptr(),
                access,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                0,
            )
        };

        if pipe_handle != INVALID_HANDLE_VALUE {
            *status_arc.lock().unwrap() = format!("Successfully connected to {}.", pipe_name);
            return Some(pipe_handle);
        }

        let err = unsafe { GetLastError() };
        if err != ERROR_PIPE_BUSY {
            *status_arc.lock().unwrap() =
                format!("Failed to connect to {}. Error: {}", pipe_name, err);
            return None;
        }

        *status_arc.lock().unwrap() = format!(
            "Pipe {} is busy, retrying... ({}/{})",
            pipe_name,
            i + 1,
            MAX_RETRIES
        );
        thread::sleep(Duration::from_millis(RETRY_DELAY_MS));
    }

    *status_arc.lock().unwrap() = format!("Failed to connect to {} after all retries.", pipe_name);
    None
}

pub fn connect_and_send_config(
    _pid: u32,
    config: &MonitorConfig,
    commands_pipe_handle_arc: Arc<Mutex<Option<isize>>>,
    logs_pipe_handle_arc: Arc<Mutex<Option<isize>>>,
    status_arc: Arc<Mutex<String>>,
    logger: Sender<String>,
) -> bool {
    // Connect to the two separate pipes.
    let commands_pipe_handle =
        match connect_to_pipe(COMMANDS_PIPE_NAME, FILE_GENERIC_WRITE, &status_arc) {
            Some(handle) => handle,
            None => return false,
        };

    let logs_pipe_handle = match connect_to_pipe(LOGS_PIPE_NAME, FILE_GENERIC_READ, &status_arc) {
        Some(handle) => handle,
        None => {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(commands_pipe_handle) };
            return false;
        }
    };

    // Store the handles in the AppState.
    *commands_pipe_handle_arc.lock().unwrap() = Some(commands_pipe_handle);
    *logs_pipe_handle_arc.lock().unwrap() = Some(logs_pipe_handle);

    // --- Send Initial Configuration via Commands Pipe ---
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
    *status_arc.lock().unwrap() =
        format!("Sending config ({} bytes)...", bytes_to_send.len());

    let mut bytes_written = 0;
    let success = unsafe {
        WriteFile(
            commands_pipe_handle,
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

    // Start the log listener on the dedicated logs pipe.
    start_pipe_log_listener(logs_pipe_handle, logger, status_arc.clone());
    true
}