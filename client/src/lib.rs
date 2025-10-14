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
mod string_dumper;
mod vmp_dumper;
use crate::config::CONFIG;
use crate::hooks::{cpprest_hook, winapi_hooks};
use crate::logging::create_log_entry;
use crossbeam_channel::{bounded, Receiver, Sender};
use shared::logging::{LogEntry, LogEvent, LogLevel, SectionInfo};
use once_cell::sync::OnceCell;
use shared::Command;
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
    CloseHandle, BOOL, GetLastError, HINSTANCE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_MESSAGE,
    PIPE_TYPE_MESSAGE, PIPE_WAIT,
};
use windows_sys::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};
use windows_sys::Win32::System::Threading::GetCurrentProcessId;
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile, PIPE_ACCESS_DUPLEX};
use windows_sys::Win32::Security::{
    SECURITY_ATTRIBUTES,
    PSECURITY_DESCRIPTOR,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW
};
use windows_sys::Win32::UI::Shell::{CSIDL_LOCAL_APPDATA, SHGetFolderPathW};


// --- Globals ---
pub static SUSPICION_SCORE: AtomicUsize = AtomicUsize::new(0);
static LOG_SENDER: OnceCell<Sender<Option<LogEntry>>> = OnceCell::new();
static SHUTDOWN_SIGNAL: AtomicBool = AtomicBool::new(false);
static THREAD_HANDLES: Mutex<Vec<JoinHandle<()>>> = Mutex::new(Vec::new());

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
    let pid = unsafe { GetCurrentProcessId() };
    let log_path = std::env::temp_dir().join(format!("monitor_lib_debug_{}.log", pid));
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_path) {
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let _ = writeln!(file, "[{}] {}", timestamp, message);
    }
}

/// Reads a single, newline-terminated message from the pipe.
/// This function will block until a complete message is received or an error occurs.
fn read_message_from_pipe(pipe_handle: isize, buffer: &mut String) -> Result<String, ()> {
    let mut read_buf = [0u8; 1024];
    loop {
        // If a complete message is already in the buffer, return it.
        if let Some(newline_pos) = buffer.find('\n') {
            let message = buffer.drain(..=newline_pos).collect();
            return Ok(message);
        }

        // Otherwise, read more data from the pipe.
        let mut bytes_read = 0;
        let success = unsafe {
            ReadFile(
                pipe_handle,
                read_buf.as_mut_ptr() as _,
                read_buf.len() as u32,
                &mut bytes_read,
                std::ptr::null_mut(),
            )
        } != 0;

        if success && bytes_read > 0 {
            buffer.push_str(&String::from_utf8_lossy(&read_buf[..bytes_read as usize]));
        } else {
            // Error or pipe closed
            return Err(());
        }
    }
}

/// The main initialization thread. Creates the pipe server, waits for config, and starts features.
fn main_initialization_thread() {
    debug_log("main_initialization_thread started.");
    let pipe_handle = unsafe {
        let pid = GetCurrentProcessId();
        let pipe_name = format!(r"\\.\pipe\cs2_monitor_{}", pid);
        let wide_pipe_name = U16CString::from_str(&pipe_name).unwrap();

        let sddl = U16CString::from_str("D:(A;OICI;GRGW;;;SY)(A;OICI;GRGW;;;BA)").unwrap();
        let mut security_descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut security_descriptor,
            std::ptr::null_mut(),
        ) == 0 {
            debug_log(&format!("Failed to create security descriptor. Error: {}", GetLastError()));
            return;
        }

        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: security_descriptor,
            bInheritHandle: 0,
        };

        CreateNamedPipeW(
            wide_pipe_name.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1, 4096, 4096, 0, &mut sa,
        )
    };

    if pipe_handle == INVALID_HANDLE_VALUE {
        debug_log(&format!("Failed to create named pipe. Error: {}", unsafe { GetLastError() }));
        return;
    }
    debug_log("Named pipe created successfully.");

    if unsafe { ConnectNamedPipe(pipe_handle, std::ptr::null_mut()) } == 0 {
        debug_log(&format!("Failed to connect named pipe. Error: {}", unsafe { GetLastError() }));
        unsafe { CloseHandle(pipe_handle); }
        return;
    }
    debug_log("Pipe connected.");

    // --- Unified Config/Command Handling ---
    // The first message MUST be an UpdateConfig command.
    let mut message_buffer = String::new();
    if let Ok(config_message) = read_message_from_pipe(pipe_handle, &mut message_buffer) {
        match serde_json::from_str::<Command>(config_message.trim()) {
            Ok(Command::UpdateConfig(config)) => {
                debug_log("Initial config command parsed successfully.");
                *CONFIG.features.write().unwrap() = config;

                let (sender, receiver) = bounded(1024);
                LOG_SENDER.set(sender).expect("Log sender already set");

                // Pass the remaining buffer to the command listener.
                let command_thread = thread::spawn(move || command_listener_thread(pipe_handle, message_buffer));
                let log_thread = thread::spawn(move || logging_thread_main(receiver, pipe_handle));

                let mut handles = THREAD_HANDLES.lock().unwrap();
                handles.push(log_thread);
                handles.push(command_thread);

                debug_log("Starting feature initialization...");
                initialize_features();
                debug_log("Feature initialization returned.");
            },
            Ok(_) => {
                debug_log("Received a valid command, but it was not the initial UpdateConfig.");
                unsafe { CloseHandle(pipe_handle); }
            },
            Err(e) => {
                debug_log(&format!("Failed to parse initial config command: {}. Raw: '{}'", e, config_message));
                unsafe { CloseHandle(pipe_handle); }
            }
        }
    } else {
        debug_log("Failed to read initial config message from pipe.");
        unsafe { CloseHandle(pipe_handle); }
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
                    Ok(Command::ListSections) => handle_list_sections(),
                    Ok(Command::DumpSection { name }) => handle_dump_section(&name),
                    Ok(Command::CalculateEntropy { name }) => handle_calculate_entropy(&name),
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
    if pipe_handle != INVALID_HANDLE_VALUE {
        unsafe {
            DisconnectNamedPipe(pipe_handle);
            CloseHandle(pipe_handle);
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

// Helper function to safely access and parse the current module's PE file.
// This encapsulates the repetitive and unsafe logic of reading the PE headers
// and provides a safe way to operate on the parsed file via a closure.
fn with_pe_file<F, R>(source_name: &str, closure: F) -> Option<R>
where
    F: FnOnce(PeFile) -> R,
{
    unsafe {
        let base = GetModuleHandleW(std::ptr::null());
        if base == 0 {
            log_event(LogLevel::Error, LogEvent::Error {
                source: source_name.to_string(),
                message: "Failed to get main module handle.".to_string(),
            });
            return None;
        }

        // Manually parse headers to get the image size, as `from_module` is not available.
        let dos_header = &*(base as *const pelite::image::IMAGE_DOS_HEADER);
        if dos_header.e_magic != pelite::image::IMAGE_DOS_SIGNATURE {
            log_event(LogLevel::Error, LogEvent::Error {
                source: source_name.to_string(),
                message: "Invalid DOS signature for main module.".to_string(),
            });
            return None;
        }

        let nt_headers = &*((base as *const u8).add(dos_header.e_lfanew as usize)
            as *const pelite::image::IMAGE_NT_HEADERS64);
        if nt_headers.Signature != 0x00004550 { // "PE\0\0"
             log_event(LogLevel::Error, LogEvent::Error {
                source: source_name.to_string(),
                message: "Invalid NT signature for main module.".to_string(),
            });
            return None;
        }

        let image_size = nt_headers.OptionalHeader.SizeOfImage as usize;
        let image_slice = std::slice::from_raw_parts(base as *const u8, image_size);

        match PeFile::from_bytes(image_slice) {
            Ok(file) => Some(closure(file)),
            Err(e) => {
                log_event(LogLevel::Error, LogEvent::Error {
                    source: source_name.to_string(),
                    message: format!("Failed to parse PE file from bytes: {}", e),
                });
                None
            }
        }
    }
}

fn handle_calculate_entropy(section_name: &str) {
    debug_log(&format!("Handling CalculateEntropy for section: {}", section_name));
    with_pe_file("handle_calculate_entropy", |file| {
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

fn handle_dump_section(section_name: &str) {
    debug_log(&format!("Handling DumpSection for section: {}", section_name));
    with_pe_file("handle_dump_section", |file| {
        for section in file.section_headers() {
            if let Ok(name) = section.name() {
                if name == section_name {
                    let data = file.get_section_bytes(section).unwrap_or(&[]);
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

fn handle_list_sections() {
    debug_log("Handling ListSections command.");
    with_pe_file("handle_list_sections", |file| {
        let sections = file.section_headers().iter().map(|s| {
            SectionInfo {
                name: s.name().unwrap_or("").to_string(),
                virtual_address: s.VirtualAddress as usize,
                virtual_size: s.VirtualSize as usize,
                characteristics: s.Characteristics,
            }
        }).collect();
        log_event(LogLevel::Info, LogEvent::SectionList { sections });
    });
}

fn get_log_file_path() -> Option<PathBuf> {
    const MAX_PATH: usize = 260;
    let mut path_buf = [0u16; MAX_PATH];
    let result = unsafe {
        SHGetFolderPathW(
            0,
            CSIDL_LOCAL_APPDATA as i32,
            0,
            0,
            path_buf.as_mut_ptr(),
        )
    };

    if result == 0 { // S_OK
        let path_len = path_buf.iter().position(|&c| c == 0).unwrap_or(MAX_PATH);
        let log_dir = PathBuf::from(String::from_utf16_lossy(&path_buf[..path_len]));

        let mut dir = log_dir.join("cs2_creator");
        dir.push("logs");
        if fs::create_dir_all(&dir).is_err() {
            return None;
        }

        let pid = unsafe { GetCurrentProcessId() };
        Some(dir.join(format!("log_{}.txt", pid)))
    } else {
        None
    }
}


fn logging_thread_main(receiver: Receiver<Option<LogEntry>>, pipe_handle: isize) {
    let mut log_file: Option<File> = {
        let _guard = ReentrancyGuard::new();
        if let Some(log_path) = get_log_file_path() {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(log_path)
                .ok()
        } else {
            None
        }
    };

    while let Ok(Some(log_entry)) = receiver.recv() {
        if let Ok(json_string) = serde_json::to_string(&log_entry) {
            let formatted_message = format!("{}\n", json_string);
            let bytes = formatted_message.as_bytes();

            if let Some(_guard) = ReentrancyGuard::new() {
                if let Some(file) = log_file.as_mut() {
                    let _ = file.write_all(bytes);
                    let _ = file.flush();
                }
                if pipe_handle != INVALID_HANDLE_VALUE {
                    unsafe {
                        WriteFile(pipe_handle, bytes.as_ptr(), bytes.len() as u32, &mut 0, std::ptr::null_mut());
                    }
                }
            }
        }
    }

}

fn initialize_features() {
    let config = CONFIG.features.read().unwrap();
    log_event(LogLevel::Info, LogEvent::Initialization { status: format!("Configuration received: {:?}", *config) });

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
        let iat = config.iat_scan_enabled;
        let manual_map = config.manual_map_scan_enabled;
        let scanner_handle = thread::spawn(move || {
            while !SHUTDOWN_SIGNAL.load(Ordering::SeqCst) {
                let current_config = CONFIG.features.read().unwrap();
                unsafe {
                    if current_config.iat_scan_enabled {
                        iat_monitor::scan_iat_modifications();
                    }
                    if current_config.manual_map_scan_enabled {
                        scanner::scan_for_manual_mapping();
                        code_monitor::monitor_code_modifications();
                        hardware_bp::check_debug_registers();
                    }
                }
                drop(current_config); // Release the lock
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