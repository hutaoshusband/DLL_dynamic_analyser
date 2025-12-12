// Copyright (c) 2024 HUTAOSHUSBAND - Wallbangbros.com/FireflyProtector.xyz


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
#[cfg(feature = "use_yara")]
mod yara_scanner;
pub mod crash_logger;

use crate::config::CONFIG;
use crate::hooks::{cpprest_hook, winapi_hooks};
use crate::logging::create_log_entry;
use crate::security::SecurityAttributes;
use crossbeam_channel::{bounded, Receiver, Sender};
use once_cell::sync::OnceCell;
use shared::logging::{LogEntry, LogEvent, LogLevel, SectionInfo};
use shared::{Command, get_commands_pipe_name, get_logs_pipe_name};
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
use windows_sys::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, EXCEPTION_RECORD, CONTEXT,
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

fn debug_log(message: &str) {
    let _guard = DEBUG_LOG_MUTEX.lock().unwrap();
    let pid = unsafe { GetCurrentProcessId() };
    let log_path = std::env::temp_dir().join(format!("monitor_lib_debug_{}.log", pid));
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_path) {
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let _ = writeln!(file, "[{}] {}", timestamp, message);
    }
}

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
                 continue;
            }
        } else {
            return Err(error);
        }
    }
}

fn main_initialization_thread() {
    debug_log("main_initialization_thread started.");

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
        let wide_pipe_name = U16CString::from_str(&get_commands_pipe_name(unsafe { GetCurrentProcessId() })).unwrap();
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
        let wide_pipe_name = U16CString::from_str(&get_logs_pipe_name(unsafe { GetCurrentProcessId() })).unwrap();
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

    debug_log("Waiting for loader to connect to both pipes...");
    
    let ERROR_PIPE_CONNECTED = 535u32;

    let commands_res = unsafe { ConnectNamedPipe(commands_pipe_handle, std::ptr::null_mut()) };
    let commands_err = unsafe { GetLastError() };
    let commands_connected = commands_res != 0 || commands_err == ERROR_PIPE_CONNECTED;

    let logs_res = unsafe { ConnectNamedPipe(logs_pipe_handle, std::ptr::null_mut()) };
    let logs_err = unsafe { GetLastError() };
    let logs_connected = logs_res != 0 || logs_err == ERROR_PIPE_CONNECTED;

    if !commands_connected || !logs_connected {
        debug_log(&format!(
            "Failed to connect named pipes. Commands: {} (err {}), Logs: {} (err {}).",
            commands_connected,
            commands_err,
            logs_connected,
            logs_err
        ));
        unsafe {
            CloseHandle(commands_pipe_handle);
            CloseHandle(logs_pipe_handle);
        }
        return;
    }
    debug_log("Both pipes connected.");

    let mut message_buffer = String::new();
    match read_message_from_pipe(commands_pipe_handle, &mut message_buffer) {
        Ok(config_message) => {
            match serde_json::from_str::<Command>(config_message.trim()) {
                Ok(Command::UpdateConfig(config)) => {
                    debug_log(&format!(
                        "Initial config parsed. Loader path: '{}'",
                        &config.loader_path
                    ));
                    
                    crash_logger::init(&config.loader_path);
                    crash_logger::log_init_step("Config received, crash_logger initialized with loader path");
                    
                    let cloned_config = config.clone();
                    *CONFIG.features.write().unwrap() = config;

                    let (sender, receiver) = bounded(1024);
                    LOG_SENDER.set(sender).expect("Log sender already set");

                    crash_logger::log_init_step("Spawning command listener thread");
                    let command_thread = thread::spawn(move || {
                        command_listener_thread(commands_pipe_handle, message_buffer)
                    });
                    crash_logger::log_init_step("Spawning log thread");
                    let log_thread =
                        thread::spawn(move || logging_thread_main(receiver, logs_pipe_handle));

                    let mut handles = THREAD_HANDLES.lock().unwrap();
                    handles.push(log_thread);
                    handles.push(command_thread);

                    crash_logger::log_init_step("Starting feature initialization");
                    debug_log("Starting feature initialization...");
                    initialize_features(cloned_config);
                    crash_logger::log_init_step("Feature initialization returned");
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
                    Ok(Command::CalculateFullEntropy { module_name }) => handle_calculate_full_entropy(&module_name),
                    Ok(Command::UpdateConfig(new_config)) => {
                        debug_log(&format!("Updating config: {:?}", new_config));
                        let mut config_guard = CONFIG.features.write().unwrap();
                        *config_guard = new_config;
                    }
                    Ok(Command::DumpModule { module_name }) => {
                        handle_dump_module(&module_name);
                    }
                    Ok(Command::LoadYaraRules(rules_str)) => {
                        #[cfg(feature = "use_yara")]
                        {
                            debug_log("Compiling YARA rules...");
                            match crate::yara_scanner::SCANNER.lock().unwrap().compile_rules(&rules_str) {
                                Ok(_) => debug_log("YARA rules compiled."),
                                Err(e) => log_event(LogLevel::Error, LogEvent::Error { 
                                    source: "YaraScanner".to_string(), 
                                    message: format!("Failed to compile rules: {}", e) 
                                }),
                            }
                        }
                        #[cfg(not(feature = "use_yara"))]
                        log_event(LogLevel::Error, LogEvent::Error { 
                            source: "YaraScanner".to_string(), 
                            message: "YARA feature not enabled in build.".to_string() 
                        });
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

fn handle_calculate_full_entropy(module_name: &str) {
    debug_log(&format!("Handling CalculateFullEntropy for module: {}", module_name));
    with_pe_file("handle_calculate_full_entropy", module_name, |file, base| {
        let image_size = file.optional_header().SizeOfImage as usize;
        let data = unsafe {
            std::slice::from_raw_parts(base as *const u8, image_size)
        };
        
        const CHUNK_SIZE: usize = 256;
        let entropy: Vec<f32> = data.chunks(CHUNK_SIZE)
            .map(|chunk| shannon_entropy(chunk))
            .collect();
        
        log_event(LogLevel::Info, LogEvent::FullEntropyResult {
            module_name: module_name.to_string(),
            entropy,
        });
    });
}

fn handle_dump_section(module_name: &str, section_name: &str) {
    debug_log(&format!("Handling DumpSection for section: {} in module: {}", section_name, module_name));
    with_pe_file("handle_dump_section", module_name, |file, base| {
        for section in file.section_headers() {
            if let Ok(name) = section.name() {
                if name == section_name {
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
    drop(config);

    let _guard = ReentrancyGuard::new();

    while let Ok(Some(log_entry)) = receiver.recv() {
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

        match log_entry.level {
            LogLevel::Debug => {
                if let Some(file) = debug_log_file.as_mut() {
                    if let Ok(json_string) = serde_json::to_string(&log_entry) {
                        let _ = writeln!(file, "{}", json_string);
                    }
                }
            }
            _ => {
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
    crash_logger::log_init_step("initialize_features() starting");
    debug_log("initialize_features() called");
    log_event(LogLevel::Info, LogEvent::Initialization { status: "HUTAOSHUSBAND's Advanced Analysis Framework enabled.".to_string() });
    log_event(LogLevel::Info, LogEvent::Initialization { status: format!("Configuration received: {:?}", config) });

    let addr = &CONFIG.termination_allowed as *const _ as usize;
    log_event(LogLevel::Debug, LogEvent::Initialization { status: format!("TERMINATION_FLAG_ADDR:{}", addr) });

    if config.api_hooks_enabled {
        crash_logger::log_init_step("API hooks enabled - starting hook initialization");
        debug_log("API hooks enabled - initializing WinAPI hooks...");
        
        crash_logger::log_init_step("About to call winapi_hooks::initialize_all_hooks()");
        unsafe {
            winapi_hooks::initialize_all_hooks();
        }
                
                crash_logger::log_init_step("winapi_hooks::initialize_all_hooks() completed");
                debug_log("WinAPI hooks initialized successfully");
                
                /*
                crash_logger::log_init_step("Spawning CPP REST hook thread");
                debug_log("Spawning CPP REST hook thread...");
                thread::spawn(cpprest_hook::initialize_and_enable_hook);
                crash_logger::log_init_step("CPP REST hook thread spawned");
                debug_log("CPP REST hook thread spawned");
        
                crash_logger::log_init_step("About to initialize stealth hooks (Hardware Breakpoints)");
                debug_log("Initializing stealth hooks (Hardware Breakpoints)...");
                unsafe {
                    crate::hooks::stealth_hooks::initialize_stealth_hooks();
                }
                crash_logger::log_init_step("Stealth hooks initialization returned");
                debug_log("Stealth hooks initialized.");
                */
            } else {
        crash_logger::log_init_step("API hooks disabled in config");
        debug_log("API hooks disabled in config");
    }

    let mut scanner_threads = Vec::new();
    if config.vmp_dump_enabled {
        crash_logger::log_init_step("Starting VMP monitoring thread");
        debug_log("VMP dump enabled - starting VMP monitoring...");
        scanner_threads.push(thread::spawn(vmp_dumper::start_vmp_monitoring));
    }
    if config.string_dump_enabled {
        crash_logger::log_init_step("Starting string dumper thread");
        debug_log("String dump enabled - starting string dumper...");
        scanner_threads.push(thread::spawn(string_dumper::start_string_dumper));
    }

    #[cfg(feature = "use_yara")]
    {
         crash_logger::log_init_step("Starting YARA scanner thread");
         debug_log("YARA scanner enabled - starting YARA scan thread...");
         scanner_threads.push(thread::spawn(|| {
             debug_log("YARA scanner thread started");
             while !SHUTDOWN_SIGNAL.load(Ordering::SeqCst) {
                 {
                     let scanner = crate::yara_scanner::SCANNER.lock().unwrap();
                     scanner.scan_memory();
                 }
                 thread::sleep(Duration::from_secs(30));
             }
         }));
    }

    if config.iat_scan_enabled || config.manual_map_scan_enabled {
        crash_logger::log_init_step("Starting IAT/manual map scanner thread");
        debug_log("IAT or manual map scan enabled - starting scanner thread...");
        let iat_enabled = config.iat_scan_enabled;
        let manual_map_enabled = config.manual_map_scan_enabled;
        let scanner_handle = thread::spawn(move || {
            debug_log("Scanner thread started");
            while !SHUTDOWN_SIGNAL.load(Ordering::SeqCst) {
                if iat_enabled {
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
            debug_log("Scanner thread exiting");
        });
        scanner_threads.push(scanner_handle);
    }

    if !scanner_threads.is_empty() {
        debug_log(&format!("Registering {} scanner threads", scanner_threads.len()));
        THREAD_HANDLES.lock().unwrap().extend(scanner_threads);
    }
    
    crash_logger::log_init_step("Feature initialization complete");
    debug_log("Feature initialization complete");
    log_event(LogLevel::Info, LogEvent::Initialization { status: "Feature initialization complete.".to_string() });
}

const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

unsafe extern "system" fn exception_handler(exception_info: *mut c_void) -> i32 {
    use windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS;
    
    if exception_info.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let exception_ptrs = exception_info as *mut EXCEPTION_POINTERS;
    let exception_record_ptr = (*exception_ptrs).ExceptionRecord;
    
    if exception_record_ptr.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let exception_code = (*exception_record_ptr).ExceptionCode as u32;
    
    if exception_code == 0x80000003 || exception_code == 0x80000004 {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    
    crash_logger::log_crash(exception_ptrs);
    
    let exception_address = (*exception_record_ptr).ExceptionAddress;
    let exception_name = match exception_code {
        0xC0000005 => "ACCESS_VIOLATION",
        0xC000001D => "ILLEGAL_INSTRUCTION",
        0xC0000094 => "INTEGER_DIVIDE_BY_ZERO",
        0xC0000096 => "PRIVILEGED_INSTRUCTION",
        0xC00000FD => "STACK_OVERFLOW",
        _ => "UNKNOWN_EXCEPTION",
    };
    
    if let Some(sender) = LOG_SENDER.get() {
        let entry = create_log_entry(
            LogLevel::Error,
            LogEvent::Error {
                source: "VectoredExceptionHandler".to_string(),
                message: format!(
                    "CRASH DETECTED: {} (0x{:08X}) at address {:?}",
                    exception_name, exception_code, exception_address
                ),
            },
        );
        let _ = sender.try_send(Some(entry));
    }

    EXCEPTION_CONTINUE_SEARCH
}


#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(_dll_module: HINSTANCE, call_reason: u32, _reserved: *mut c_void) -> BOOL {
    unsafe {
        use windows_sys::Win32::Storage::FileSystem::{CreateFileA, WriteFile, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ};
        use windows_sys::Win32::Foundation::GENERIC_WRITE;
        
        let pid = GetCurrentProcessId();
        let name = format!("C:\\Users\\Public\\analyzer_beacon_{}.txt\0", pid);
        let handle = CreateFileA(
            name.as_ptr(), 
            GENERIC_WRITE, 
            FILE_SHARE_READ, 
            std::ptr::null(), 
            OPEN_ALWAYS, 
            FILE_ATTRIBUTE_NORMAL, 
            0
        );
        
        if handle != INVALID_HANDLE_VALUE {
            let msg = "DllMain Reached!\n";
            WriteFile(handle, msg.as_ptr(), msg.len() as u32, std::ptr::null_mut(), std::ptr::null_mut());
            CloseHandle(handle);
        }
    }

    let result = std::panic::catch_unwind(|| {
        match call_reason {
            DLL_PROCESS_ATTACH => {
                crash_logger::install_panic_hook();
                crash_logger::early_debug_log("DllMain ATTACH - panic hook installed");
                
                debug_log("DllMain called with DLL_PROCESS_ATTACH.");
                crash_logger::log_init_step("DllMain: DLL_PROCESS_ATTACH entered");
                
                unsafe {
                    crash_logger::log_init_step("DllMain: Installing VEH");
                    let handler = AddVectoredExceptionHandler(
                        1, 
                        Some(std::mem::transmute(exception_handler as *const ()))
                    );
                    if handler.is_null() {
                        debug_log("WARNING: Failed to install vectored exception handler!");
                        crash_logger::log_init_step("DllMain: VEH installation FAILED");
                    } else {
                        debug_log("Vectored exception handler installed successfully.");
                        crash_logger::log_init_step("DllMain: VEH installed successfully");
                    }
                }
                
                crash_logger::log_init_step("DllMain: Spawning initialization thread");
                let init_thread = thread::spawn(main_initialization_thread);
                THREAD_HANDLES.lock().unwrap().push(init_thread);
                debug_log("Initialization thread spawned from DllMain.");
                crash_logger::log_init_step("DllMain: Initialization thread spawned");
            }
            DLL_PROCESS_DETACH => {
                debug_log("DllMain called with DLL_PROCESS_DETACH.");
                SHUTDOWN_SIGNAL.store(true, Ordering::SeqCst);
    
                if let Some(sender) = LOG_SENDER.get() {
                    let _ = sender.send(None);
                }
    
                thread::spawn(|| {
                    debug_log("Shutdown thread started.");
                    let mut handles = THREAD_HANDLES.lock().unwrap();
                    for handle in handles.drain(..) {
                        let _ = handle.join();
                    }
                    debug_log("All background threads have been joined.");
                });
    
                debug_log("Shutdown process initiated from DllMain.");
            }
            _ => {}
        }
    });

    match result {
        Ok(_) => 1,
        Err(_) => {
            unsafe {
                 use windows_sys::Win32::System::Diagnostics::Debug::OutputDebugStringA;
                 let msg = "PANIC IN DLLMAIN!\0";
                 OutputDebugStringA(msg.as_ptr());
            }
            0
        }
    }
}