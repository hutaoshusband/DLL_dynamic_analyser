#![recursion_limit = "512"]
#![cfg(windows)]

mod code_monitor;
mod config;
mod hardware_bp;
mod hooks;
mod iat_monitor;
mod logging;
mod scanner;
mod static_analyzer;
mod string_dumper;
mod vmp_dumper;

use crate::config::{LogLevel, MonitorConfig, CONFIG};
use crate::hooks::{cpprest_hook, winapi_hooks};
use crate::logging::{LogEntry, LogEvent};
use crossbeam_channel::{unbounded, Receiver, Sender};
use once_cell::sync::OnceCell;
use std::cell::Cell;
use std::ffi::c_void;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use widestring::U16CString;
use windows_sys::Win32::Foundation::{CloseHandle, BOOL, HINSTANCE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_MESSAGE,
    PIPE_TYPE_MESSAGE, PIPE_WAIT,
};
use windows_sys::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};
use windows_sys::Win32::System::Threading::GetCurrentProcessId;
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile, PIPE_ACCESS_DUPLEX};
use windows_sys::Win32::Security::{
    InitializeSecurityDescriptor, SetSecurityDescriptorDacl, SECURITY_ATTRIBUTES,
    SECURITY_DESCRIPTOR,
};

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
    if level > CONFIG.log_level { return; }
    if let Some(sender) = LOG_SENDER.get() {
        let entry = LogEntry::new(level, event);
        let _ = sender.try_send(Some(entry));
    }
}

/// The main initialization thread. Creates the pipe server, waits for config, and starts features.
fn main_initialization_thread() {
    let pipe_handle = unsafe {
        let pid = GetCurrentProcessId();
        let pipe_name = format!(r"\\.\pipe\cs2_monitor_{}", pid);
        let wide_pipe_name = U16CString::from_str(&pipe_name).unwrap();

        let mut sa: SECURITY_ATTRIBUTES = std::mem::zeroed();
        let mut sd: SECURITY_DESCRIPTOR = std::mem::zeroed();
        InitializeSecurityDescriptor(&mut sd as *mut _ as *mut _, 1);
        SetSecurityDescriptorDacl(&mut sd as *mut _ as *mut _, 1, std::ptr::null_mut(), 0);
        sa.nLength = std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
        sa.lpSecurityDescriptor = &mut sd as *mut _ as *mut _;
        sa.bInheritHandle = 0;

        CreateNamedPipeW(
            wide_pipe_name.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1, 4096, 4096, 0, &sa,
        )
    };

    if pipe_handle == INVALID_HANDLE_VALUE { return; }

    let connected = unsafe { ConnectNamedPipe(pipe_handle, std::ptr::null_mut()) != 0 };
    if !connected {
        unsafe { CloseHandle(pipe_handle); }
        return;
    }

    let mut buffer = [0u8; 1024];
    let mut bytes_read = 0;
    let success = unsafe {
        ReadFile(pipe_handle, buffer.as_mut_ptr() as _, buffer.len() as u32, &mut bytes_read, std::ptr::null_mut())
    } != 0;

    if success && bytes_read > 0 {
        let config_str = String::from_utf8_lossy(&buffer[..bytes_read as usize]);
        if let Ok(config) = serde_json::from_str::<MonitorConfig>(&config_str) {
            if CONFIG.features.set(config).is_ok() {
                let (sender, receiver) = unbounded();
                LOG_SENDER.set(sender).expect("Log sender already set");
                let log_thread = thread::spawn(move || logging_thread_main(receiver, pipe_handle));
                THREAD_HANDLES.lock().unwrap().push(log_thread);
                initialize_features(config);
            }
        } else {
            unsafe { CloseHandle(pipe_handle); }
        }
    } else {
        unsafe { CloseHandle(pipe_handle); }
    }
}

fn logging_thread_main(receiver: Receiver<Option<LogEntry>>, pipe_handle: isize) {
    let mut log_file = {
        let _guard = ReentrancyGuard::new();
        let mut file: Option<File> = None;
        if let Ok(appdata) = std::env::var("LOCALAPPDATA") {
            let mut log_dir = PathBuf::from(appdata);
            log_dir.push("cs2_monitor");
            log_dir.push("logs");
            if fs::create_dir_all(&log_dir).is_ok() {
                let log_path = log_dir.join(format!("log_{}.txt", unsafe { GetCurrentProcessId() }));
                file = OpenOptions::new().create(true).append(true).open(log_path).ok();
            }
        }
        file
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

    if pipe_handle != INVALID_HANDLE_VALUE {
        unsafe {
            DisconnectNamedPipe(pipe_handle);
            CloseHandle(pipe_handle);
        }
    }
}

fn initialize_features(config: MonitorConfig) {
    log_event(LogLevel::Info, LogEvent::Initialization { status: format!("Configuration received: {:?}", config) });

    let addr = &CONFIG.termination_allowed as *const _ as usize;
    log_event(LogLevel::Debug, LogEvent::Initialization { status: format!("TERMINATION_FLAG_ADDR:{}", addr) });

    if config.api_hooks_enabled {
        unsafe {
            if let Err(e) = winapi_hooks::initialize_all_hooks() {
                log_event(LogLevel::Error, LogEvent::Error { source: "HookInit".into(), message: e });
            }
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
                unsafe {
                    if iat { iat_monitor::scan_iat_modifications(); }
                    if manual_map {
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
    if call_reason == DLL_PROCESS_ATTACH {
        let init_thread = thread::spawn(main_initialization_thread);
        THREAD_HANDLES.lock().unwrap().push(init_thread);
    } else if call_reason == DLL_PROCESS_DETACH {
        SHUTDOWN_SIGNAL.store(true, Ordering::SeqCst);
        if let Some(sender) = LOG_SENDER.get() {
            let _ = sender.send(None);
        }
    }
    1
}