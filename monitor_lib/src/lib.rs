#![cfg(windows)]
use std::ffi::{c_void, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::sync::Mutex;
use std::thread;
use once_cell::sync::OnceCell;

use windows_sys::Win32::Foundation::{BOOL, HANDLE, HINSTANCE, INVALID_HANDLE_VALUE, HWND};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows_sys::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, GetFinalPathNameByHandleW, OPEN_EXISTING, WriteFile};
use windows_sys::Win32::System::Threading::{CreateProcessW, GetCurrentProcessId, Sleep, PROCESS_INFORMATION, STARTUPINFOW};
use windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxW;
use windows_sys::Win32::System::IO::OVERLAPPED;

// Globale, thread-sichere Logger-Instanz.
static LOGGER: OnceCell<Mutex<MonitorLogger>> = OnceCell::new();

/// Eine Struktur, die unsere Logging-Ziele verwaltet.
struct MonitorLogger {
    log_file: Option<File>,
    pipe: Option<HANDLE>,
}

/// Die zentrale Logging-Funktion. Schreibt eine Nachricht in die Log-Datei und an die Pipe.
fn log_message(message: &str) {
    if let Some(logger_mutex) = LOGGER.get() {
        let mut logger = logger_mutex.lock().unwrap();
        let formatted_message = format!("{}\n", message);
        let bytes = formatted_message.as_bytes();

        // In die Datei schreiben.
        if let Some(file) = logger.log_file.as_mut() {
            let _ = file.write_all(bytes);
            let _ = file.flush();
        }

        // An die Pipe senden.
        if let Some(pipe_handle) = logger.pipe {
            if pipe_handle != INVALID_HANDLE_VALUE {
                let mut bytes_written = 0;
                unsafe {
                    WriteFile(
                        pipe_handle,
                        bytes.as_ptr(),
                        bytes.len() as u32,
                        &mut bytes_written,
                        std::ptr::null_mut(),
                    );
                }
            }
        }
    }
}

// Definiert die Hooks für die API-Funktionen.
retour::static_detour! {
    static MessageBoxWHook: unsafe extern "system" fn(HWND, *const u16, *const u16, u32) -> i32;
    static CreateFileWHook: unsafe extern "system" fn(
        *const u16, u32, u32, *const SECURITY_ATTRIBUTES, u32, u32, HANDLE
    ) -> HANDLE;
    static WriteFileHook: unsafe extern "system" fn(
        HANDLE, *const u8, u32, *mut u32, *mut OVERLAPPED
    ) -> BOOL;
    static CreateProcessWHook: unsafe extern "system" fn(
        *const u16, *mut u16, *const SECURITY_ATTRIBUTES, *const SECURITY_ATTRIBUTES,
        BOOL, u32, *const c_void, *const u16, *const STARTUPINFOW, *mut PROCESS_INFORMATION
    ) -> BOOL;
}

// Unsere eigene Funktion, die anstelle von MessageBoxW aufgerufen wird.
fn hooked_message_box_w(h_wnd: HWND, text: *const u16, caption: *const u16, u_type: u32) -> i32 {
    let text_str = unsafe { widestring::U16CStr::from_ptr_str(text).to_string_lossy() };
    let caption_str = unsafe { widestring::U16CStr::from_ptr_str(caption).to_string_lossy() };
    log_message(&format!("[HOOK] MessageBoxW -> Titel: '{}', Text: '{}'", caption_str, text_str));
    unsafe { MessageBoxWHook.call(h_wnd, text, caption, u_type) }
}

// Unsere eigene Funktion, die anstelle von CreateFileW aufgerufen wird.
fn hooked_create_file_w(
    lp_file_name: *const u16,
    dw_desired_access: u32,
    dw_share_mode: u32,
    lp_security_attributes: *const SECURITY_ATTRIBUTES,
    dw_creation_disposition: u32,
    dw_flags_and_attributes: u32,
    h_template_file: HANDLE,
) -> HANDLE {
    let file_name_str = unsafe { widestring::U16CStr::from_ptr_str(lp_file_name).to_string_lossy() };
    log_message(&format!("[HOOK] CreateFileW -> Datei: '{}'", file_name_str));
    unsafe {
        CreateFileWHook.call(
            lp_file_name, dw_desired_access, dw_share_mode, lp_security_attributes,
            dw_creation_disposition, dw_flags_and_attributes, h_template_file
        )
    }
}

// Hook für WriteFile
fn hooked_write_file(
    h_file: HANDLE,
    lp_buffer: *const u8,
    n_number_of_bytes_to_write: u32,
    lp_number_of_bytes_written: *mut u32,
    lp_overlapped: *mut OVERLAPPED,
) -> BOOL {
    let mut file_path_buf = vec![0u16; 1024];
    let path_len = unsafe {
        GetFinalPathNameByHandleW(h_file, file_path_buf.as_mut_ptr(), file_path_buf.len() as u32, 0)
    };
    let file_name = if path_len > 0 {
        OsString::from_wide(&file_path_buf[..path_len as usize]).to_string_lossy().to_string()
    } else {
        "Unbekannter Handle".to_string()
    };

    log_message(&format!(
        "[HOOK] WriteFile -> Datei: '{}', Bytes: {}",
        file_name, n_number_of_bytes_to_write
    ));

    unsafe {
        WriteFileHook.call(h_file, lp_buffer, n_number_of_bytes_to_write, lp_number_of_bytes_written, lp_overlapped)
    }
}

// Hook für CreateProcessW
fn hooked_create_process_w(
    lp_application_name: *const u16,
    lp_command_line: *mut u16,
    lp_process_attributes: *const SECURITY_ATTRIBUTES,
    lp_thread_attributes: *const SECURITY_ATTRIBUTES,
    b_inherit_handles: BOOL,
    dw_creation_flags: u32,
    lp_environment: *const c_void,
    lp_current_directory: *const u16,
    lp_startup_info: *const STARTUPINFOW,
    lp_process_information: *mut PROCESS_INFORMATION,
) -> BOOL {
    let app_name = if lp_application_name.is_null() { "N/A".to_string() } else { unsafe { widestring::U16CStr::from_ptr_str(lp_application_name).to_string_lossy().to_string() } };
    let cmd_line = if lp_command_line.is_null() { "N/A".to_string() } else { unsafe { widestring::U16CStr::from_ptr_str(lp_command_line).to_string_lossy().to_string() } };
    
    log_message(&format!("[HOOK] CreateProcessW -> App: '{}', Kommandozeile: '{}'", app_name, cmd_line));
    
    unsafe {
        CreateProcessWHook.call(
            lp_application_name, lp_command_line, lp_process_attributes, lp_thread_attributes,
            b_inherit_handles, dw_creation_flags, lp_environment, lp_current_directory,
            lp_startup_info, lp_process_information
        )
    }
}

/// Initialisiert den Logger in einem separaten Thread, um `DllMain`-Einschränkungen zu umgehen.
fn initialize() {
    let pid = unsafe { GetCurrentProcessId() };

    let pipe_name = format!(r"\\.\pipe\cs2_monitor_{}", pid);
    let wide_pipe_name: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut pipe_handle = INVALID_HANDLE_VALUE;
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

    let mut log_file: Option<File> = None;
    let mut exe_path_buf = vec![0u16; 1024];
    let len = unsafe { GetModuleFileNameW(0, exe_path_buf.as_mut_ptr(), exe_path_buf.len() as u32) };
    if len > 0 {
        let exe_path_os = OsString::from_wide(&exe_path_buf[..len as usize]);
        let mut exe_path = PathBuf::from(exe_path_os);
        if exe_path.pop() {
            let log_dir = exe_path.join("logs");
            if fs::create_dir_all(&log_dir).is_ok() {
                let mut i = 1;
                loop {
                    let log_path = log_dir.join(format!("log{}.txt", i));
                    if !log_path.exists() {
                         log_file = OpenOptions::new().create(true).append(true).open(log_path).ok();
                         break;
                    }
                    i += 1;
                    if i > 1000 { break; }
                }
            }
        }
    }

    let logger = MonitorLogger { log_file, pipe: Some(pipe_handle) };
    if LOGGER.set(Mutex::new(logger)).is_ok() {
        log_message("[INIT] Monitor-DLL erfolgreich initialisiert.");

        unsafe {
            if MessageBoxWHook.initialize(MessageBoxW, hooked_message_box_w).is_ok() {
                let _ = MessageBoxWHook.enable();
            }
            if CreateFileWHook.initialize(CreateFileW, hooked_create_file_w).is_ok() {
                let _ = CreateFileWHook.enable();
            }
            if WriteFileHook.initialize(WriteFile, hooked_write_file).is_ok() {
                let _ = WriteFileHook.enable();
            }
            if CreateProcessWHook.initialize(CreateProcessW, hooked_create_process_w).is_ok() {
                let _ = CreateProcessWHook.enable();
            }
        }
    }
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
            thread::spawn(initialize);
        }
        DLL_PROCESS_DETACH => {
            log_message("[EXIT] Monitor-DLL wird entladen.");
            if let Some(logger_mutex) = LOGGER.get() {
                 let mut logger = logger_mutex.lock().unwrap();
                 if let Some(pipe_handle) = logger.pipe.take() {
                     if pipe_handle != INVALID_HANDLE_VALUE {
                         unsafe { windows_sys::Win32::Foundation::CloseHandle(pipe_handle); }
                     }
                 }
            }
        }
        _ => {}
    }
    1
}