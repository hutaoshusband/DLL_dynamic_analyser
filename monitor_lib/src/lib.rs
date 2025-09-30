use std::ffi::c_void;
use std::fs::File;
use windows_sys::Win32::Foundation::{BOOL, HWND, HINSTANCE, HANDLE};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};
use windows_sys::Win32::Storage::FileSystem::CreateFileW;
use windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxW;
use log::{info, LevelFilter};
use simple_logger::SimpleLogger;

// Definiert den Hook für die MessageBoxW Funktion.
retour::static_detour! {
    static MessageBoxWHook: unsafe extern "system" fn(HWND, *const u16, *const u16, u32) -> i32;
    static CreateFileWHook: unsafe extern "system" fn(
        *const u16, u32, u32, *const SECURITY_ATTRIBUTES, u32, u32, HANDLE
    ) -> HANDLE;
}

// Unsere eigene Funktion, die anstelle von MessageBoxW aufgerufen wird.
fn hooked_message_box_w(h_wnd: HWND, text: *const u16, caption: *const u16, u_type: u32) -> i32 {
    let text_str = unsafe { widestring::U16CStr::from_ptr_str(text).to_string_lossy() };
    let caption_str = unsafe { widestring::U16CStr::from_ptr_str(caption).to_string_lossy() };

    info!("[HOOK] MessageBoxW aufgerufen! Titel: '{}', Text: '{}'", caption_str, text_str);

    // Rufe die originale MessageBoxW Funktion auf, damit das Programm normal weiterläuft.
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
    info!("[HOOK] CreateFileW aufgerufen! Datei: '{}'", file_name_str);

    // Rufe die originale CreateFileW Funktion auf.
    unsafe {
        CreateFileWHook.call(
            lp_file_name, dw_desired_access, dw_share_mode, lp_security_attributes,
            dw_creation_disposition, dw_flags_and_attributes, h_template_file
        )
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
            // Log-Datei für den Zielprozess initialisieren
            // VERBESSERUNG: Nur initialisieren, wenn die Datei erstellt werden kann.
            if File::create("C:\\temp\\monitor_log.txt").is_ok() {
                // Wir ignorieren Fehler, falls der Logger bereits initialisiert wurde.
                let _ = SimpleLogger::new()
                    .with_level(LevelFilter::Info)
                    .with_module_level("simple_logger", LevelFilter::Error)
                    .init();
            }
            
            info!("Monitor-DLL erfolgreich injiziert und geladen.");

            unsafe {
                if let Ok(_) = MessageBoxWHook.initialize(MessageBoxW, hooked_message_box_w) {
                    if let Ok(_) = MessageBoxWHook.enable() {
                        info!("[HOOK] MessageBoxW wurde erfolgreich gehookt.");
                    }
                }
                if let Ok(_) = CreateFileWHook.initialize(CreateFileW, hooked_create_file_w) {
                    if let Ok(_) = CreateFileWHook.enable() {
                        info!("[HOOK] CreateFileW wurde erfolgreich gehookt.");
                    }
                }
            }
        }
        DLL_PROCESS_DETACH => {}
        _ => {}
    }
    1
}
