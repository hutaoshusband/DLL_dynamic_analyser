// Copyright (c) 2024 HUTAOSHUSBAND - Wallbangbros.com/FireflyProtector.xyz

use std::{
    sync::{mpsc::Sender, Arc, Mutex},
    thread,
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::{GetLastError, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING,
    },
};

use shared::{get_commands_pipe_name, get_logs_pipe_name, Command, MonitorConfig};
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

fn connect_to_pipe(
    pipe_name: &str,
    access: u32,
    status_arc: &Arc<Mutex<String>>,
    _logger: &Sender<String>, // Kept for signature compatibility but not used here
) -> Option<isize> {
    let wide_pipe_name = U16CString::from_str(pipe_name).unwrap();
    const MAX_RETRIES: u32 = 60; // Increased to 30 seconds
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
            let msg = format!("Successfully connected to {}.", pipe_name);
            *status_arc.lock().unwrap() = msg;
            return Some(pipe_handle);
        }

        let err = unsafe { GetLastError() };
        if err != ERROR_PIPE_BUSY && err != ERROR_FILE_NOT_FOUND {
            let msg = format!("Failed to connect to {}. Error: {}", pipe_name, err);
            *status_arc.lock().unwrap() = msg;
            return None;
        }

        let msg = format!(
            "Pipe {} is busy or not ready, retrying... ({}/{})",
            pipe_name,
            i + 1,
            MAX_RETRIES
        );
        *status_arc.lock().unwrap() = msg;
        thread::sleep(Duration::from_millis(RETRY_DELAY_MS));
    }

    let msg = format!("Failed to connect to {} after all retries.", pipe_name);
    *status_arc.lock().unwrap() = msg;
    None
}

pub fn connect_and_send_config(
    pid: u32,
    config: &MonitorConfig,
    commands_pipe_handle_arc: Arc<Mutex<Option<isize>>>,
    logs_pipe_handle_arc: Arc<Mutex<Option<isize>>>,
    status_arc: Arc<Mutex<String>>,
    logger: Sender<String>,
) -> bool {
    let commands_pipe_handle = match connect_to_pipe(
        &get_commands_pipe_name(pid),
        FILE_GENERIC_WRITE,
        &status_arc,
        &logger,
    ) {
        Some(handle) => handle,
        None => return false,
    };

    let logs_pipe_handle = match connect_to_pipe(
        &get_logs_pipe_name(pid),
        FILE_GENERIC_READ,
        &status_arc,
        &logger,
    ) {
        Some(handle) => handle,
        None => {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(commands_pipe_handle) };
            return false;
        }
    };

    *commands_pipe_handle_arc.lock().unwrap() = Some(commands_pipe_handle);
    *logs_pipe_handle_arc.lock().unwrap() = Some(logs_pipe_handle);

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

    start_pipe_log_listener(logs_pipe_handle, logger, status_arc.clone());
    true
}
