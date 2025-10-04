#![recursion_limit = "512"]
#![cfg(windows)]

mod code_monitor;
mod config;
mod hardware_bp;
mod hooks;
mod iat_monitor;
mod logging;
mod scanner;
mod vmp_dumper;
mod yara_scanner;

use crate::config::{LogLevel, CONFIG};
use crate::hooks::cpprest_hook;
use crate::hooks::winapi_hooks::initialize_all_hooks;
use crate::logging::{LogEntry, LogEvent};
use crossbeam_channel::{unbounded, Receiver, Sender};
use once_cell::sync::OnceCell;
use std::cell::Cell;
use std::ffi::{c_void, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{CloseHandle, BOOL, HINSTANCE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, WriteFile, OPEN_EXISTING};
use windows_sys::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, Sleep};
use windows_sys::Win32::UI::Shell::{SHGetFolderPathW, CSIDL_LOCAL_APPDATA};

// Globals for logging and thread management.
static LOG_SENDER: OnceCell<Sender<Option<(LogLevel, LogEvent)>>> = OnceCell::new();
static SHUTDOWN_SIGNAL: AtomicBool = AtomicBool::new(false);
static SCANNER_THREAD_HANDLE: Mutex<Option<JoinHandle<()>>> = Mutex::new(None);
static LOGGING_THREAD_HANDLE: Mutex<Option<JoinHandle<()>>> = Mutex::new(None);

// Thread-local flag to prevent re-entrancy in hooks.
thread_local!(static IN_HOOK: Cell<bool> = Cell::new(false));

/// A guard to prevent re-entrant calls to hooked functions.
pub struct ReentrancyGuard;

impl ReentrancyGuard {
    pub fn new() -> Option<ReentrancyGuard> {
        IN_HOOK.with(|in_hook| {
            if in_hook.get() {
                None
            } else {
                in_hook.set(true);
                Some(ReentrancyGuard)
            }
        })
    }
}

impl Drop for ReentrancyGuard {
    fn drop(&mut self) {
        IN_HOOK.with(|in_hook| in_hook.set(false));
    }
}

/// The central logging function. It's lightweight, non-blocking, and filters
/// events based on the configured log level.
pub fn log_event(level: LogLevel, event: LogEvent) {
    if level > CONFIG.log_level {
        return; // Filter out messages below the configured level.
    }
    if let Some(sender) = LOG_SENDER.get() {
        let _ = sender.try_send(Some((level, event)));
    }
}

fn logging_thread_main(receiver: Receiver<Option<(LogLevel, LogEvent)>>) {
    let (mut pipe_handle, mut log_file) = {
        // The initialization of the pipe and log file involves calling Windows APIs
        // that we are hooking (e.g., CreateFileW). To prevent these initial calls
        // from generating log events that would then try to write to a not-yet-ready
        // log file, we wrap the entire setup in a ReentrancyGuard. This sets a
        // thread-local flag that our hooks will check, causing them to bypass
        // logging for any API calls made within this block.
        let _guard = ReentrancyGuard::new();

        let pid = unsafe { GetCurrentProcessId() };
        let pipe_name = format!(r"\\.\pipe\cs2_monitor_{}", pid);
        let wide_pipe_name: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut pipe_handle = INVALID_HANDLE_VALUE;

        // Attempt to connect to the named pipe for the GUI.
        for _ in 0..5 {
            pipe_handle = unsafe {
                CreateFileW(
                    wide_pipe_name.as_ptr(),
                    0x40000000, // GENERIC_WRITE
                    0,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    0,
                    0,
                )
            };
            if pipe_handle != INVALID_HANDLE_VALUE {
                break;
            }
            unsafe { Sleep(500) };
        }

        // Set up the log file in %LOCALAPPDATA%.
        let mut log_file: Option<File> = None;
        unsafe {
            let mut path_buf = vec![0u16; 260];
            if SHGetFolderPathW(0, CSIDL_LOCAL_APPDATA as i32, 0, 0, path_buf.as_mut_ptr()) >= 0 {
                let len = path_buf.iter().position(|&c| c == 0).unwrap_or(path_buf.len());
                let appdata_path = OsString::from_wide(&path_buf[..len]);
                let mut log_dir = PathBuf::from(appdata_path);
                log_dir.push("cs2_monitor");
                log_dir.push("logs");
                if fs::create_dir_all(&log_dir).is_ok() {
                    // Find an unused log file name.
                    let mut i = 1;
                    loop {
                        let log_path = log_dir.join(format!("log{}.txt", i));
                        if !log_path.exists() {
                            log_file =
                                OpenOptions::new().create(true).append(true).open(log_path).ok();
                            break;
                        }
                        i += 1;
                        if i > 1000 {
                            break;
                        } // Safety break.
                    }
                }
            }
        }
        (pipe_handle, log_file)
    }; // The _guard is dropped here, re-enabling logging for subsequent API calls.

    while let Ok(Some((level, event))) = receiver.recv() {
        // First, attempt to serialize the event to see if it's a special command.
        // We serialize it to a Value to inspect it without committing to a full log string yet.
        if let Ok(value) = serde_json::to_value(LogEntry::new(level, event.clone())) {
            let mut is_command = false;
            if let Some(event_obj) = value.get("event") {
                if let Some(details) = event_obj.get("details") {
                    if let Some(command) = details.get("command").and_then(|c| c.as_str()) {
                        vmp_dumper::handle_command(command);
                        is_command = true;
                    }
                } else if let Some(command) = event_obj.get("command").and_then(|c| c.as_str()) {
                    // Fallback for simpler command structures
                    vmp_dumper::handle_command(command);
                    is_command = true;
                }
            }

            // If it was a command, we skip logging it to avoid clutter.
            if is_command {
                continue;
            }
        }

        // If it wasn't a command, proceed with normal logging.
        let log_entry = LogEntry::new(level, event);
        if let Ok(json_string) = serde_json::to_string(&log_entry) {
            let formatted_message = format!("{}\n", json_string);
            let bytes = formatted_message.as_bytes();

            // Use the re-entrancy guard to prevent self-logging.
            if let Some(_guard) = ReentrancyGuard::new() {
                // Write to the log file.
                if let Some(file) = log_file.as_mut() {
                    let _ = file.write_all(bytes);
                    let _ = file.flush();
                }

                // Write to the named pipe if connected.
                if pipe_handle != INVALID_HANDLE_VALUE {
                    unsafe {
                        WriteFile(
                            pipe_handle,
                            bytes.as_ptr(),
                            bytes.len() as u32,
                            &mut 0,
                            std::ptr::null_mut(),
                        )
                    };
                }
            }
        }
    }

    if pipe_handle != INVALID_HANDLE_VALUE {
        unsafe { CloseHandle(pipe_handle) };
    }
}

fn dll_main_internal() -> Result<(), String> {
    let (sender, receiver) = unbounded::<Option<(LogLevel, LogEvent)>>();
    LOG_SENDER
        .set(sender)
        .map_err(|_| "Failed to set the global log sender.".to_string())?;

    let logging_handle = thread::spawn(move || logging_thread_main(receiver));
    *LOGGING_THREAD_HANDLE.lock().unwrap() = Some(logging_handle);

    log_event(
        LogLevel::Info,
        LogEvent::Initialization {
            status: "Monitor DLL initializing...".to_string(),
        },
    );

    // Send the address of the termination flag to the injector GUI.
    let addr = &CONFIG.termination_allowed as *const _ as usize;
    log_event(LogLevel::Debug, LogEvent::Initialization {
        status: format!("TERMINATION_FLAG_ADDR:{}", addr),
    });

    unsafe {
        initialize_all_hooks()?;
    }

    // Start the VMP dumper's background monitoring thread.
    vmp_dumper::start_vmp_monitoring();

    // Spawn a thread for the cpprest hook.
    thread::spawn(cpprest_hook::initialize_and_enable_hook);

    // Spawn the memory scanner thread.
    let scanner_handle = thread::spawn(|| {
        let mut last_yara_scan = Instant::now();
        let yara_scan_cooldown = Duration::from_secs(60); // Scan every minute

        while !SHUTDOWN_SIGNAL.load(Ordering::SeqCst) {
            unsafe {
                // These scans are lightweight and can run more frequently.
                scanner::scan_for_manual_mapping();
                code_monitor::monitor_code_modifications();
                hardware_bp::check_debug_registers();
                iat_monitor::scan_iat_modifications();

                // Perform the more intensive Yara scan on a cooldown.
                if last_yara_scan.elapsed() >= yara_scan_cooldown {
                    log_event(
                        LogLevel::Info,
                        LogEvent::MemoryScan {
                            status: "Starting Yara scan on all loaded modules.".to_string(),
                            result: "".to_string(),
                        },
                    );
                    let modules = scanner::enumerate_modules();
                    for (path, mem_slice) in modules {
                        yara_scanner::scan_memory(&path, mem_slice);
                    }
                    last_yara_scan = Instant::now();
                }
            }
            // Sleep for a bit to avoid excessive CPU usage.
            for _ in 0..50 {
                // Sleep for 5 seconds total
                if SHUTDOWN_SIGNAL.load(Ordering::SeqCst) {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
    });
    *SCANNER_THREAD_HANDLE.lock().unwrap() = Some(scanner_handle);

    log_event(
        LogLevel::Info,
        LogEvent::Initialization {
            status: "Monitor DLL initialized successfully.".to_string(),
        },
    );
    Ok(())
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(
    _dll_module: HINSTANCE,
    call_reason: u32,
    _reserved: *mut c_void,
) -> BOOL {
    match call_reason {
        DLL_PROCESS_ATTACH => {
            if dll_main_internal().is_err() {
                return 0; // FALSE
            }
        }
        DLL_PROCESS_DETACH => {
            // Set the shutdown signal for all background threads.
            SHUTDOWN_SIGNAL.store(true, Ordering::SeqCst);

            log_event(
                LogLevel::Info,
                LogEvent::Shutdown {
                    status: "Unloading monitor DLL.".to_string(),
                },
            );

            // Signal the logging thread to shut down. We do not wait (`join`) for
            // the threads here, as that can cause deadlocks inside DllMain.
            // The OS will clean up the threads when the process terminates.
            if let Some(sender) = LOG_SENDER.get() {
                // This signals the logging thread to break its loop.
                let _ = sender.send(None);
            }
        }
        _ => {}
    }
    1 // TRUE
}