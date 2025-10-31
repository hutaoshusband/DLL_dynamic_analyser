// Copyright (c) 2024 HUTAOSHUSBAND - Wallbangbros.com/CodeConfuser.dev
// All rights reserved.


#![recursion_limit = "1024"]
#![cfg(windows)]
#![allow(dead_code, unused_variables)]

mod code_monitor;
mod config;
mod hardware_bp;
mod hooks;
mod iat_monitor;
mod logging;
mod scanner;
mod security;
mod string_dumper;
mod vmp_dumper;
use crate::config::CONFIG;
use crate::hooks::{cpprest_hook, winapi_hooks};
use crate::logging::create_log_entry;
use crate::security::SecurityAttributes;
use crossbeam_channel::{bounded, Receiver, Sender};
use once_cell::sync::OnceCell;
use shared::logging::{LogEntry, LogEvent, LogLevel, SectionInfo};
use shared::{Command, COMMANDS_PIPE_NAME, LOGS_PIPE_NAME};
use std::cell::Cell;
use std::ffi::c_void;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use widestring::U16CString;
use windows_sys::Win32::Foundation::{
    CloseHandle, BOOL, GetLastError, HINSTANCE, INVALID_HANDLE_VALUE, ERROR_MORE_DATA,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_MESSAGE,
    PIPE_TYPE_MESSAGE, PIPE_WAIT,
};
use windows_sys::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};
use windows_sys::Win32::System::Threading::GetCurrentProcessId;
use windows_sys::Win32::Storage::FileSystem::{
    ReadFile, WriteFile, PIPE_ACCESS_INBOUND, PIPE_ACCESS_OUTBOUND,
};


// --- Globals ---
pub static SUSPICION_SCORE: AtomicUsize = AtomicUsize::new(0);
static LOG_SENDER: OnceCell<Sender<Option<LogEntry>>> = OnceCell::new();
static SHUTDOWN_SIGNAL: AtomicBool = AtomicBool::new(false);
static THREAD_HANDLES: Mutex<Vec<JoinHandle<()>>> = Mutex::new(Vec::new());
static DEBUG_LOG_MUTEX: Mutex<()> = Mutex::new(());

thread_local!(static IN_HOOK: Cell<bool> = Cell::new(false));

pub struct ReentrancyGuard;
impl ReentrancyGuard {
    pub fn new() -> Option<ReentrancyGuard> {
        IN_HOOK.with(|in_hook| {
            if in_hook.get() { None } else { in_hook.set(true); Some(ReentrancyGuard) }
        })
    }
}
impl Drop for ReentrancyGuard {
    fn drop(&mut self) { IN_HOOK.with(|in_hook| in_hook.set(false)); }
}

pub fn log_event(level: LogLevel, event: LogEvent) {
    if let Some(sender) = LOG_SENDER.get() {
        let entry = create_log_entry(level, event);
        let _ = sender.try_send(Some(entry));
    }
}

fn handle_dump_module(module_name: &str) {
    debug_log(&format!("Handling DumpModule command for module: {}", module_name));
    let wide_module_name = U16CString::from_str(module_name).unwrap();
    let module_handle = unsafe { GetModuleHandleW(wide_module_name.as_ptr()) };

    if module_handle == 0 {
        log_event(
            LogLevel::Error,
            LogEvent::Error {
                source: "handle_dump_module".to_string(),
                message: format!("Failed to get handle for module: {}", module_name),
            },
        );
        return;
    }

    unsafe {
        let dos_header = &*(module_handle as *const pelite::image::IMAGE_DOS_HEADER);
        if dos_header.e_magic != pelite::image::IMAGE_DOS_SIGNATURE {
            log_event(
                LogLevel::Error,
                LogEvent::Error {
                    source: "handle_dump_module".to_string(),
                    message: format!("Invalid DOS signature for module: {}", module_name),
                },
            );
            return;
        }

        let nt_headers = &*((module_handle as *const u8).add(dos_header.e_lfanew as usize)
            as *const pelite::image::IMAGE_NT_HEADERS64);
        if nt_headers.Signature != 0x00004550 { // "PE\0\0"
            log_event(
                LogLevel::Error,
                LogEvent::Error {
                    source: "handle_dump_module".to_string(),
                    message: format!("Invalid NT signature for module: {}", module_name),
                },
            );
            return;
        }

        let image_size = nt_headers.OptionalHeader.SizeOfImage as usize;
        let image_slice = std::slice::from_raw_parts(module_handle as *const u8, image_size);

        log_event(
            LogLevel::Info,
            LogEvent::ModuleDump {
                module_name: module_name.to_string(),
                data: image_slice.to_vec(),
            },
        );
    }
}

// A simple, panic-safe file logger for early-stage debugging.
fn debug_log(message: &str) {
    let _guard = DEBUG_LOG_MUTEX.lock().unwrap();
    let pid = unsafe { GetCurrentProcessId() };
    let log_path = std::env::temp_dir().join(format!("monitor_lib_debug_{}.log", pid));
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_path) {
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let _ = writeln!(file, "[{}] {}", timestamp, message);
    }
}

// Reads a single, newline-terminated message from the pipe, handling ERROR_MORE_DATA.
fn read_message_from_pipe(pipe_handle: isize, buffer: &mut String) -> Result<String, u32> {
    let mut read_buf = [0u8; 1024]; // A smaller, reasonable buffer for each read call.
    loop {
        if let Some(newline_pos) = buffer.find('\n') {
            let message = buffer.drain(..=newline_pos).collect();
            return Ok(message);
        }

        let mut bytes_read = 0;
        let success = unsafe {
            ReadFile(
                pipe_handle,
                read_buf.as_mut_ptr() as _,
                read_buf.len() as u32,
                &mut bytes_read,
                std::ptr::null_mut(),
            )
        };

        let error = unsafe { GetLastError() };

        if success != 0 || error == ERROR_MORE_DATA {
            if bytes_read > 0 {
                buffer.push_str(&String::from_utf8_lossy(&read_buf[..bytes_read as usize]));
            }
            if error != ERROR_MORE_DATA {
                 // If success was true but there's no more data, we might need to wait,
                 // but for message-based pipes, we should get the whole message or an error.
                 // If we have a newline, the loop start will catch it. If not, continue reading.
                 continue;
            }
        } else {
            // A real error occurred
            return Err(error);
        }
    }
}

/// The main initialization thread. Creates the pipe server, waits for config, and starts features.
fn main_initialization_thread() {
    debug_log("main_initialization_thread started.");

    // --- Create Pipes ---
    let mut sa = unsafe {
        match SecurityAttributes::new() {
            Some(sa) => sa,
            None => {
                debug_log(&format!(
                    "Failed to create security attributes. Error: {}",
                    GetLastError()
                ));
                return;
            }
        }
    };

    let commands_pipe_handle = unsafe {
        let wide_pipe_name = U16CString::from_str(COMMANDS_PIPE_NAME).unwrap();
        CreateNamedPipeW(
            wide_pipe_name.as_ptr(),
            PIPE_ACCESS_INBOUND, // Client reads commands from this pipe
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1, 8192, 8192, 0,
            &mut sa.attributes,
        )
    };

    if commands_pipe_handle == INVALID_HANDLE_VALUE {
        debug_log(&format!(
            "Failed to create commands pipe. Error: {}",
            unsafe { GetLastError() }
        ));
        return;
    }
    debug_log("Commands pipe created successfully.");

    let logs_pipe_handle = unsafe {
        let wide_pipe_name = U16CString::from_str(LOGS_PIPE_NAME).unwrap();
        CreateNamedPipeW(
            wide_pipe_name.as_ptr(),
            PIPE_ACCESS_OUTBOUND, // Client writes logs to this pipe
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1, 8192, 8192, 0,
            &mut sa.attributes,
        )
    };

    if logs_pipe_handle == INVALID_HANDLE_VALUE {
        debug_log(&format!("Failed to create logs pipe. Error: {}", unsafe {
            GetLastError()
        }));
        unsafe { CloseHandle(commands_pipe_handle) };
        return;
    }
    debug_log("Logs pipe created successfully.");

    // --- Connect Pipes ---
    debug_log("Waiting for loader to connect to both pipes...");
    let commands_connected = unsafe { ConnectNamedPipe(commands_pipe_handle, std::ptr::null_mut()) } != 0;
    let logs_connected = unsafe { ConnectNamedPipe(logs_pipe_handle, std::ptr::null_mut()) } != 0;

    if !commands_connected || !logs_connected {
        debug_log(&format!(
            "Failed to connect named pipes. Commands: {} (err {}), Logs: {} (err {}).",
            commands_connected,
            unsafe { GetLastError() },
            logs_connected,
            unsafe { GetLastError() }
        ));
        unsafe {
            CloseHandle(commands_pipe_handle);
            CloseHandle(logs_pipe_handle);
        }
        return;
    }
    debug_log("Both pipes connected.");

    // --- Unified Config/Command Handling ---
    let mut message_buffer = String::new();
    match read_message_from_pipe(commands_pipe_handle, &mut message_buffer) {
        Ok(config_message) => {
            match serde_json::from_str::<Command>(config_message.trim()) {
                Ok(Command::UpdateConfig(config)) => {
                    debug_log(&format!(
                        "Initial config parsed. Loader path: '{}'",
                        &config.loader_path
                    ));
                    let cloned_config = config.clone();
                    *CONFIG.features.write().unwrap() = config;

                    let (sender, receiver) = bounded(1024);
                    LOG_SENDER.set(sender).expect("Log sender already set");

                    // Spawn threads with their dedicated pipes
                    let command_thread = thread::spawn(move || {
                        command_listener_thread(commands_pipe_handle, message_buffer)
                    });
                    let log_thread =
                        thread::spawn(move || logging_thread_main(receiver, logs_pipe_handle));

                    let mut handles = THREAD_HANDLES.lock().unwrap();
                    handles.push(log_thread);
                    handles.push(command_thread);

                    debug_log("Starting feature initialization...");
                    initialize_features(cloned_config);
                    debug_log("Feature initialization returned.");
                }
                Ok(_) => {
                    debug_log("Received a valid command, but it was not the initial UpdateConfig.");
                    unsafe {
                        CloseHandle(commands_pipe_handle);
                        CloseHandle(logs_pipe_handle);
                    }
                }
                Err(e) => {
                    debug_log(&format!(
                        "Failed to parse initial config command: {}. Raw: '{}'",
                        e, config_message
                    ));
                    unsafe {
                        CloseHandle(commands_pipe_handle);
                        CloseHandle(logs_pipe_handle);
                    }
                }
            }
        }
        Err(error) => {
            debug_log(&format!(
                "Failed to read initial config message from pipe. Error: {}",
                error
            ));
            unsafe {
                CloseHandle(commands_pipe_handle);
                CloseHandle(logs_pipe_handle);
            }
        }
    }
    debug_log("main_initialization_thread finished.");
}


fn command_listener_thread(pipe_handle: isize, mut message_buffer: String) {
    debug_log("Command listener thread started.");
    loop {
        if SHUTDOWN_SIGNAL.load(Ordering::SeqCst) {
            break;
        }

        match read_message_from_pipe(pipe_handle, &mut message_buffer) {
            Ok(message) => {
                let command_str = message.trim();
                if command_str.is_empty() {
                    continue;
                }
                debug_log(&format!("Received command string: {}", command_str));

                match serde_json::from_str::<Command>(command_str) {
                    Ok(Command::ListSections { module_name }) => handle_list_sections(&module_name),
                    Ok(Command::DumpSection { module_name, name }) => handle_dump_section(&module_name, &name),
                    Ok(Command::CalculateEntropy { module_name, name }) => handle_calculate_entropy(&module_name, &name),
                    Ok(Command::UpdateConfig(new_config)) => {
                        debug_log(&format!("Updating config: {:?}", new_config));
                        let mut config_guard = CONFIG.features.write().unwrap();
                        *config_guard = new_config;
                    }
                    Ok(Command::DumpModule { module_name }) => {
                        handle_dump_module(&module_name);
                    }
                    Err(e) => debug_log(&format!("Failed to parse command: '{}', error: {}", command_str, e)),
                }
            }
            Err(_) => {
                let error = unsafe { GetLastError() };
                if error != windows_sys::Win32::Foundation::ERROR_BROKEN_PIPE {
                     debug_log(&format!("Pipe read failed in command listener with error: {}. Shutting down.", error));
                }
                break;
            }
        }
    }
    debug_log("Command listener thread finished.");
    // The pipe handle is now owned by the main initialization thread's scope
    // and will be closed when that thread finishes. We just disconnect here.
    if pipe_handle != INVALID_HANDLE_VALUE {
        unsafe {
            DisconnectNamedPipe(pipe_handle);
        }
    }
}

fn shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = std::collections::HashMap::new();
    for &byte in data {
        *counts.entry(byte).or_insert(0) += 1;
    }

    let len = data.len() as f32;
    counts.values().map(|&count| {
        let p = count as f32 / len;
        -p * p.log2()
    }).sum()
}

use pelite::pe64::{Pe, PeFile};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

// Helper function to safely access and parse a specific module's PE file.
fn with_pe_file<F, R>(source_name: &str, module_name: &str, closure: F) -> Option<R>
where
    F: FnOnce(PeFile, isize) -> R,
{
    unsafe {
        let wide_module_name = U16CString::from_str(module_name).unwrap();
        let base = GetModuleHandleW(wide_module_name.as_ptr());

        if base == 0 {
            log_event(LogLevel::Error, LogEvent::Error {
                source: source_name.to_string(),
                message: format!("Failed to get handle for module: {}", module_name),
            });
            return None;
        }

        let dos_header = &*(base as *const pelite::image::IMAGE_DOS_HEADER);
        if dos_header.e_magic != pelite::image::IMAGE_DOS_SIGNATURE {
            log_event(LogLevel::Error, LogEvent::Error {
                source: source_name.to_string(),
                message: format!("Invalid DOS signature for module: {}", module_name),
            });
            return None;
        }

        let nt_headers = &*((base as *const u8).add(dos_header.e_lfanew as usize)
            as *const pelite::image::IMAGE_NT_HEADERS64);
        if nt_headers.Signature != 0x00004550 { // "PE\0\0"
            log_event(LogLevel::Error, LogEvent::Error {
                source: source_name.to_string(),
                message: format!("Invalid NT signature for module: {}", module_name),
            });
            return None;
        }

        let image_size = nt_headers.OptionalHeader.SizeOfImage as usize;
        let image_slice = std::slice::from_raw_parts(base as *const u8, image_size);

        match PeFile::from_bytes(image_slice) {
            Ok(file) => Some(closure(file, base)),
            Err(e) => {
                log_event(LogLevel::Error, LogEvent::Error {
                    source: source_name.to_string(),
                    message: format!("Failed to parse PE file for {}: {}", module_name, e),
                });
                None
            }
        }
    }
}

fn handle_calculate_entropy(module_name: &str, section_name: &str) {
    debug_log(&format!("Handling CalculateEntropy for section: {} in module: {}", section_name, module_name));
    with_pe_file("handle_calculate_entropy", module_name, |file, _| {
        for section in file.section_headers() {
            if let Ok(name) = section.name() {
                if name == section_name {
                    let data = file.get_section_bytes(section).unwrap_or(&[]);
                    const CHUNK_SIZE: usize = 256;
                    let entropy = data.chunks(CHUNK_SIZE)
                        .map(|chunk| shannon_entropy(chunk))
                        .collect();
                    log_event(LogLevel::Info, LogEvent::EntropyResult {
                        name: section_name.to_string(),
                        entropy,
                    });
                    break;
                }
            }
        }
    });
}

fn handle_dump_section(module_name: &str, section_name: &str) {
    debug_log(&format!("Handling DumpSection for section: {} in module: {}", section_name, module_name));
    with_pe_file("handle_dump_section", module_name, |file, base| {
        for section in file.section_headers() {
            if let Ok(name) = section.name() {
                if name == section_name {
                    // The correct way to dump a section from memory is to use its virtual address
                    // relative to the module's base address, not the file-based `get_section_bytes`.
                    let section_start = (base as usize + section.VirtualAddress as usize) as *const u8;
                    let section_size = section.VirtualSize as usize;
                    let data = unsafe {
                        std::slice::from_raw_parts(section_start, section_size)
                    };

                    log_event(LogLevel::Info, LogEvent::SectionDump {
                        name: section_name.to_string(),
                        data: data.to_vec(),
                    });
                    break;
                }
            }
        }
    });
}

fn handle_list_sections(module_name: &str) {
    debug_log(&format!("Handling ListSections for module: {}", module_name));
    with_pe_file("handle_list_sections", module_name, |file, _| {
        let sections = file
            .section_headers()
            .iter()
            .map(|s| SectionInfo {
                name: s.name().unwrap_or("").to_string(),
                virtual_address: s.VirtualAddress as usize,
                virtual_size: s.VirtualSize as usize,
                characteristics: s.Characteristics,
            })
            .collect();
        log_event(LogLevel::Info, LogEvent::SectionList { sections });
    });
}

fn logging_thread_main(receiver: Receiver<Option<LogEntry>>, pipe_handle: isize) {
    // Use the loader_path from the global config to create log files.
    let config = CONFIG.features.read().unwrap();
    let base_path = PathBuf::from(&config.loader_path);

    let mut hook_log_file: Option<File> = None;
    let mut debug_log_file: Option<File> = None;

    let hook_log_path = base_path.join("logs").join("hook_logs");
    if fs::create_dir_all(&hook_log_path).is_ok() {
        let log_file_path = hook_log_path.join("hook_log.json");
        hook_log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file_path)
            .ok();
    }

    let debug_log_path = base_path.join("logs").join("debug");
    if fs::create_dir_all(&debug_log_path).is_ok() {
        let log_file_path = debug_log_path.join("debug_log.txt");
        debug_log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file_path)
            .ok();
    }
    // Drop the read lock so other threads can access the config.
    drop(config);

    while let Ok(Some(log_entry)) = receiver.recv() {
        // Always send to the pipe if it's valid
        if pipe_handle != INVALID_HANDLE_VALUE {
            if let Ok(json_string) = serde_json::to_string(&log_entry) {
                let formatted_message = format!("{}\n", json_string);
                let bytes = formatted_message.as_bytes();
                let mut bytes_written = 0;
                let success = unsafe {
                    WriteFile(
                        pipe_handle,
                        bytes.as_ptr(),
                        bytes.len() as u32,
                        &mut bytes_written,
                        std::ptr::null_mut(),
                    )
                };

                if success == 0 {
                    let error = unsafe { GetLastError() };
                    debug_log(&format!(
                        "Failed to write log to pipe. Wrote {}/{}. Error: {}",
                        bytes_written,
                        bytes.len(),
                        error
                    ));
                }
            }
        }

        // Write to the appropriate log file.
        // The ReentrancyGuard is intentionally omitted here. This thread is the designated
        // logger; it's the one place where I/O is expected. The hooks themselves are
        // guarded, so if this thread's file operations trigger a hook (e.g., WriteFile),
        // the hook will correctly ignore it, preventing a loop.
        match log_entry.level {
            LogLevel::Debug => {
                if let Some(file) = debug_log_file.as_mut() {
                    if let Ok(json_string) = serde_json::to_string(&log_entry) {
                        let _ = writeln!(file, "{}", json_string);
                    }
                }
            }
            _ => {
                // All other levels go to the hook log
                if let Some(file) = hook_log_file.as_mut() {
                    if let Ok(json_string) = serde_json::to_string(&log_entry) {
                        let _ = writeln!(file, "{}", json_string);
                    }
                }
            }
        }
    }
}

use shared::MonitorConfig;
fn initialize_features(config: MonitorConfig) {
    log_event(LogLevel::Info, LogEvent::Initialization { status: "HUTAOSHUSBAND's Advanced Analysis Framework enabled.".to_string() });
    log_event(LogLevel::Info, LogEvent::Initialization { status: format!("Configuration received: {:?}", config) });

    let addr = &CONFIG.termination_allowed as *const _ as usize;
    log_event(LogLevel::Debug, LogEvent::Initialization { status: format!("TERMINATION_FLAG_ADDR:{}", addr) });

    if config.api_hooks_enabled {
        unsafe {
            winapi_hooks::initialize_all_hooks();
        }
        thread::spawn(cpprest_hook::initialize_and_enable_hook);
    }

    let mut scanner_threads = Vec::new();
    if config.vmp_dump_enabled {
        scanner_threads.push(thread::spawn(vmp_dumper::start_vmp_monitoring));
    }
    if config.string_dump_enabled {
        scanner_threads.push(thread::spawn(string_dumper::start_string_dumper));
    }
    if config.iat_scan_enabled || config.manual_map_scan_enabled {
        let iat_enabled = config.iat_scan_enabled;
        let manual_map_enabled = config.manual_map_scan_enabled;
        let scanner_handle = thread::spawn(move || {
            while !SHUTDOWN_SIGNAL.load(Ordering::SeqCst) {
                if iat_enabled {
                    // This was disabled due to causing stability issues and log spam.
                    // unsafe { iat_monitor::scan_iat_modifications(); }
                }
                if manual_map_enabled {
                    unsafe {
                        scanner::scan_for_manual_mapping();
                        code_monitor::monitor_code_modifications();
                        hardware_bp::check_debug_registers();
                    }
                }
                thread::sleep(Duration::from_secs(5));
            }
        });
        scanner_threads.push(scanner_handle);
    }

    if !scanner_threads.is_empty() {
        THREAD_HANDLES.lock().unwrap().extend(scanner_threads);
    }
    log_event(LogLevel::Info, LogEvent::Initialization { status: "Feature initialization complete.".to_string() });
}


#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(_dll_module: HINSTANCE, call_reason: u32, _reserved: *mut c_void) -> BOOL {
    match call_reason {
        DLL_PROCESS_ATTACH => {
            debug_log("DllMain called with DLL_PROCESS_ATTACH.");
            // Using a separate thread for initialization is crucial to avoid deadlocks
            // inside DllMain, which is a highly restricted environment.
            let init_thread = thread::spawn(main_initialization_thread);
            THREAD_HANDLES.lock().unwrap().push(init_thread);
            debug_log("Initialization thread spawned from DllMain.");
        }
        DLL_PROCESS_DETACH => {
            debug_log("DllMain called with DLL_PROCESS_DETACH.");
            SHUTDOWN_SIGNAL.store(true, Ordering::SeqCst);

            // Signal the logging thread to shut down.
            if let Some(sender) = LOG_SENDER.get() {
                let _ = sender.send(None);
            }

            // Spawn a dedicated thread to handle the cleanup.
            // This avoids blocking DllMain while waiting for threads to join.
            thread::spawn(|| {
                debug_log("Shutdown thread started.");
                let mut handles = THREAD_HANDLES.lock().unwrap();
                // Drain the vector and join each handle. This will block the shutdown
                // thread (but not DllMain) until the background threads have exited.
                for handle in handles.drain(..) {
                    let _ = handle.join();
                }
                debug_log("All background threads have been joined.");
            });

            debug_log("Shutdown process initiated from DllMain.");
        }
        _ => {}
    }
    1 // Return TRUE to indicate success.
}