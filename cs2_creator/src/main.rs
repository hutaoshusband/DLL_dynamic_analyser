#![cfg(windows)]
// Verhindert das Konsolenfenster beim Start
// #![windows_subsystem = "windows"]

// Nötige Importe
use tray_icon::{
    menu::{Menu, MenuItem, MenuEvent},
    TrayIconBuilder,
};
// Nötige Importe für die Windows-API
use std::ffi::OsString;
use std::fs::File;
use std::os::windows::ffi::OsStringExt;
use std::thread;
use log::{info, warn};
use simple_logger::SimpleLogger;
use winit::event_loop::{ControlFlow, EventLoopBuilder};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE},
    Security::{
        InitializeSecurityDescriptor, SetSecurityDescriptorDacl, SECURITY_ATTRIBUTES,
        SECURITY_DESCRIPTOR,
    },
    Storage::FileSystem::{ReadFile, PIPE_ACCESS_INBOUND},
    System::{
        Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory, IMAGE_NT_HEADERS64},
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW,
            Process32NextW, MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPPROCESS,
        },
        LibraryLoader::{GetModuleHandleW, GetProcAddress},
        Memory::{
            VirtualAllocEx, VirtualFreeEx, VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT,
            MEM_PRIVATE, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
            PAGE_EXECUTE_WRITECOPY, PAGE_READWRITE,
        },
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_WAIT,
        },
        SystemServices::IMAGE_DOS_HEADER,
        Threading::{
            CreateRemoteThread, OpenProcess, WaitForSingleObject, PROCESS_CREATE_THREAD,
            PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
            PROCESS_SYNCHRONIZE,
        },
    },
};
use rfd::FileDialog;

/// Ein RAII-Wrapper für Windows-Handles, der `CloseHandle` automatisch aufruft.
struct Handle(isize);

impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

fn get_all_processes() -> Vec<(u32, String)> {
    let mut processes = Vec::new();
    unsafe {
        let snapshot_handle = Handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if snapshot_handle.0 == INVALID_HANDLE_VALUE {
            warn!("Konnte keine Prozessliste erstellen: {}", GetLastError());
            return processes;
        }

        let mut process_entry: PROCESSENTRY32W = std::mem::zeroed();
        process_entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot_handle.0, &mut process_entry) != 0 {
            loop {
                let process_name = OsString::from_wide(
                    &process_entry.szExeFile
                        [..process_entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0)],
                )
                .to_string_lossy()
                .into_owned();

                if !process_name.is_empty() {
                    processes.push((process_entry.th32ProcessID, process_name));
                }

                if Process32NextW(snapshot_handle.0, &mut process_entry) == 0 {
                    break;
                }
            }
        }
    }
    processes
}

/// Listet alle geladenen Module für eine gegebene Prozess-ID (PID) auf.
fn find_loaded_modules_by_pid(pid: u32) -> Vec<String> {
    let mut loaded_modules = Vec::new();
    unsafe {
        let snapshot_handle = Handle(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid));
        if snapshot_handle.0 == INVALID_HANDLE_VALUE {
            warn!(
                "CreateToolhelp32Snapshot (Module) für PID {} fehlgeschlagen: {}",
                pid,
                GetLastError()
            );
            return loaded_modules;
        }

        let mut module_entry: MODULEENTRY32W = std::mem::zeroed();
        module_entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

        if Module32FirstW(snapshot_handle.0, &mut module_entry) != 0 {
            loop {
                let module_name = OsString::from_wide(
                    &module_entry.szModule
                        [..module_entry.szModule.iter().position(|&c| c == 0).unwrap_or(0)],
                );
                loaded_modules.push(module_name.to_string_lossy().into_owned());

                if Module32NextW(snapshot_handle.0, &mut module_entry) == 0 {
                    break;
                }
            }
        }
    }
    loaded_modules
}

/// Sucht die Prozess-ID (PID) für einen gegebenen Prozessnamen.
fn find_process_id(target_process_name: &str) -> Option<u32> {
    unsafe {
        let snapshot_handle = Handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if snapshot_handle.0 == INVALID_HANDLE_VALUE {
            warn!(
                "CreateToolhelp32Snapshot (Process) failed: {}",
                GetLastError()
            );
            return None;
        }

        let mut process_entry: PROCESSENTRY32W = std::mem::zeroed();
        process_entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot_handle.0, &mut process_entry) != 0 {
            loop {
                let process_name = OsString::from_wide(
                    &process_entry.szExeFile
                        [..process_entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0)],
                );

                if process_name
                    .to_string_lossy()
                    .eq_ignore_ascii_case(target_process_name)
                {
                    return Some(process_entry.th32ProcessID);
                }

                if Process32NextW(snapshot_handle.0, &mut process_entry) == 0 {
                    break;
                }
            }
        }
    }
    None
}

/// Hier würde die Logik zur Überwachung von Prozessen und zur Erkennung von DLL-Injections leben.
/// Das ist eine sehr komplexe Aufgabe, die Windows-APIs erfordert.
/// Diese Funktion listet alle offiziell geladenen Module (DLLs) für einen Zielprozess auf.
fn find_loaded_modules(target_process_name: &str) -> (Option<u32>, Vec<String>) {
    let Some(pid) = find_process_id(target_process_name) else {
        info!("Zielprozess '{}' nicht gefunden.", target_process_name);
        return (None, vec![]);
    };

    info!(
        "Zielprozess '{}' gefunden mit PID: {}",
        target_process_name, pid
    );
    let mut loaded_modules = Vec::new();

    unsafe {
        let snapshot_handle = Handle(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid));
        if snapshot_handle.0 == INVALID_HANDLE_VALUE {
            warn!(
                "CreateToolhelp32Snapshot (Module) für PID {} fehlgeschlagen: {}",
                pid,
                GetLastError()
            );
            return (Some(pid), loaded_modules);
        }

        let mut module_entry: MODULEENTRY32W = std::mem::zeroed();
        module_entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

        if Module32FirstW(snapshot_handle.0, &mut module_entry) != 0 {
            loop {
                let module_name = OsString::from_wide(
                    &module_entry.szModule
                        [..module_entry.szModule.iter().position(|&c| c == 0).unwrap_or(0)],
                );
                loaded_modules.push(module_name.to_string_lossy().into_owned());

                if Module32NextW(snapshot_handle.0, &mut module_entry) == 0 {
                    break;
                }
            }
        }
    }

    (Some(pid), loaded_modules)
}

/// Sucht nach Anzeichen von "Manual Mapping" durch Scannen des Prozess-Speichers.
fn detect_manual_mapping(pid: u32) -> Vec<String> {
    let mut findings = Vec::new();

    unsafe {
        let process_handle = Handle(OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            0,
            pid,
        ));

        if process_handle.0 == 0 {
            warn!(
                "OpenProcess für PID {} fehlgeschlagen: {}",
                pid,
                GetLastError()
            );
            return findings;
        }

        let mut current_address: usize = 0;
        loop {
            let mut mem_info: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let result = VirtualQueryEx(
                process_handle.0,
                current_address as *const _,
                &mut mem_info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            if result == 0 {
                break;
            }

            let is_private_committed =
                mem_info.State == MEM_COMMIT && mem_info.Type == MEM_PRIVATE;
            let is_executable = (mem_info.Protect & PAGE_EXECUTE_READ) != 0
                || (mem_info.Protect & PAGE_EXECUTE_READWRITE) != 0
                || (mem_info.Protect & PAGE_EXECUTE_WRITECOPY) != 0;

            if is_private_committed && is_executable {
                let mut dos_header: IMAGE_DOS_HEADER = std::mem::zeroed();
                let mut bytes_read = 0;

                if ReadProcessMemory(
                    process_handle.0,
                    mem_info.BaseAddress,
                    &mut dos_header as *mut _ as *mut _,
                    std::mem::size_of::<IMAGE_DOS_HEADER>(),
                    &mut bytes_read,
                ) != 0
                    && bytes_read > 0
                    && dos_header.e_magic == 0x5A4D
                {
                    let nt_header_address =
                        (mem_info.BaseAddress as usize + dos_header.e_lfanew as usize) as *const _;
                    let mut nt_headers: IMAGE_NT_HEADERS64 = std::mem::zeroed();

                    if ReadProcessMemory(
                        process_handle.0,
                        nt_header_address,
                        &mut nt_headers as *mut _ as *mut _,
                        std::mem::size_of::<IMAGE_NT_HEADERS64>(),
                        &mut bytes_read,
                    ) != 0
                        && bytes_read > 0
                        && nt_headers.Signature == 0x4550
                    {
                        let finding = format!(
                            "Potenziell manuell gemapptes Image gefunden an Adresse: {:#X}",
                            mem_info.BaseAddress as usize
                        );
                        info!("{}", &finding);
                        findings.push(finding);
                    }
                }
            }
            current_address = mem_info.BaseAddress as usize + mem_info.RegionSize;
        }
    }

    if findings.is_empty() {
        info!("Keine Anzeichen für Manual Mapping gefunden.");
    }

    findings
}

/// Injiziert eine DLL in einen Prozess mittels CreateRemoteThread und LoadLibrary.
fn inject_dll(pid: u32, dll_path: &str) -> Result<(), String> {
    unsafe {
        let process_handle = Handle(OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ,
            0,
            pid,
        ));
        if process_handle.0 == 0 {
            return Err(format!(
                "OpenProcess für PID {} fehlgeschlagen: {}",
                pid,
                GetLastError()
            ));
        }

        let dll_path_bytes = (dll_path.to_owned() + "\0")
            .encode_utf16()
            .collect::<Vec<u16>>();
        let remote_buffer = VirtualAllocEx(
            process_handle.0,
            std::ptr::null(),
            dll_path_bytes.len() * 2,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if remote_buffer.is_null() {
            return Err(format!("VirtualAllocEx fehlgeschlagen: {}", GetLastError()));
        }

        let mut bytes_written = 0;
        if WriteProcessMemory(
            process_handle.0,
            remote_buffer,
            dll_path_bytes.as_ptr() as _,
            dll_path_bytes.len() * 2,
            &mut bytes_written,
        ) == 0
        {
            VirtualFreeEx(process_handle.0, remote_buffer, 0, MEM_RELEASE);
            return Err(format!(
                "WriteProcessMemory fehlgeschlagen: {}",
                GetLastError()
            ));
        }

        let kernel32_handle =
            GetModuleHandleW("kernel32.dll\0".encode_utf16().collect::<Vec<u16>>().as_ptr());
        let load_library_addr = GetProcAddress(kernel32_handle, "LoadLibraryW\0".as_ptr() as _);

        if load_library_addr.is_none() {
            VirtualFreeEx(process_handle.0, remote_buffer, 0, MEM_RELEASE);
            return Err("Konnte Adresse von LoadLibraryW nicht finden".to_string());
        }

        let thread_handle = Handle(CreateRemoteThread(
            process_handle.0,
            std::ptr::null(),
            0,
            Some(std::mem::transmute(load_library_addr)),
            remote_buffer as *const std::ffi::c_void,
            0,
            std::ptr::null_mut(),
        ));
        if thread_handle.0 == 0 {
            VirtualFreeEx(process_handle.0, remote_buffer, 0, MEM_RELEASE);
            return Err(format!(
                "CreateRemoteThread fehlgeschlagen: {}",
                GetLastError()
            ));
        }
    }
    Ok(())
}

/// Führt alle Analyse-Schritte durch und loggt die Ergebnisse.
fn run_analysis() {
    thread::spawn(|| {
        _run_analysis_internal();
    });
}

fn _run_analysis_internal() {
    info!("--- Starte interaktive Analyse ---");

    let processes = get_all_processes();
    info!("Laufende Prozesse:");
    for (pid, name) in &processes {
        info!("  PID: {:<6} | Name: {}", pid, name);
    }

    let target_input = match tinyfiledialogs::input_box(
        "Prozess auswählen",
        "Bitte gib den Namen oder die PID des Zielprozesses ein.\n(Eine Liste ist in der cs2_runner.log) Ich werde das noch umbenennen keine Sorge.",
        "",
    ) {
        Some(input) if !input.is_empty() => input,
        _ => {
            info!("Keine Eingabe. Analyse abgebrochen.");
            return;
        }
    };

    let target_pid = if let Ok(pid) = target_input.parse::<u32>() {
        processes.iter().find(|(p, _)| *p == pid).map(|(p, _)| *p)
    } else {
        find_process_id(&target_input)
    };

    let Some(pid) = target_pid else {
        warn!(
            "Prozess '{}' konnte nicht gefunden werden. Analyse abgebrochen.",
            target_input
        );
        return;
    };

    info!("Zielprozess mit PID {} ausgewählt.", pid);

    let dll_path = match FileDialog::new()
        .add_filter("Dynamic Link Library", &["dll"])
        .set_title("Wähle die zu injizierende Monitor-DLL")
        .pick_file()
    {
        Some(path) => path,
        None => {
            info!("Keine DLL ausgewählt. Analyse abgebrochen.");
            return;
        }
    };

    info!("--- Starte Scan für PID {} ---", pid);

    let modules = find_loaded_modules_by_pid(pid);
    info!("Gefundene Module in PID {}:", pid);
    modules.iter().for_each(|m| info!("- {}", m));

    let manual_map_findings = detect_manual_mapping(pid);
    info!("Ergebnisse der Manual-Mapping-Analyse:");
    if manual_map_findings.is_empty() {
        info!("Keine Auffälligkeiten gefunden.");
    } else {
        manual_map_findings
            .iter()
            .for_each(|f| info!("- {}", f));
    }

    // Starte den Pipe-Server, um auf Logs von der DLL zu lauschen.
    start_pipe_server(pid);

    info!("Warte kurz, damit der Pipe-Server bereit ist...");
thread::sleep(std::time::Duration::from_millis(500)); 

    match inject_dll(pid, dll_path.to_str().unwrap()) {
        Ok(_) => {
            info!(
                "Monitor-DLL '{}' erfolgreich injiziert. Überwachung aktiv.",
                dll_path.display()
            );
            info!("Warte darauf, dass der Zielprozess beendet wird...");

            // Öffne ein Handle zum Prozess, um auf sein Ende warten zu können.
            let process_handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
            if process_handle != 0 {
                unsafe {
                    // Warte unendlich lange, bis der Prozess terminiert.
                    WaitForSingleObject(process_handle, u32::MAX);
                    CloseHandle(process_handle);
                }
                info!("Zielprozess wurde beendet.");
            } else {
                warn!(
                    "Konnte kein Handle zum Warten auf den Prozess erstellen. Fehler: {}",
                    unsafe { GetLastError() }
                );
            }
        }
        Err(e) => warn!("Fehler beim Injizieren der Monitor-DLL: {}", e),
    }

    info!("--- Analyse abgeschlossen ---");
}

/// Startet einen Named-Pipe-Server in einem neuen Thread, um auf Log-Nachrichten von der injizierten DLL zu lauschen.
fn start_pipe_server(pid: u32) {
    thread::spawn(move || unsafe {
        // Erstelle einen eindeutigen Pipe-Namen mit der PID.
        let pipe_name = format!(r"\\.\pipe\cs2_monitor_{}", pid);
        let wide_pipe_name: Vec<u16> =
            pipe_name.encode_utf16().chain(std::iter::once(0)).collect();

        // Erstelle einen Security Descriptor, der jedem den Zugriff erlaubt.
        // Das ist nötig, weil der Creator als Admin läuft, der Zielprozess aber nicht.
        let mut sa: SECURITY_ATTRIBUTES = std::mem::zeroed();
        let mut sd: SECURITY_DESCRIPTOR = std::mem::zeroed();
        InitializeSecurityDescriptor(&mut sd as *mut _ as *mut _, 1);
        // Ein NULL DACL erlaubt allen Zugriff.
        SetSecurityDescriptorDacl(&mut sd as *mut _ as *mut _, 1, std::ptr::null_mut(), 0);
        sa.nLength = std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
        sa.lpSecurityDescriptor = &mut sd as *mut _ as *mut _;
        sa.bInheritHandle = 0;

        loop {
            // Erstelle die Named Pipe.
            let pipe_handle = CreateNamedPipeW(
                wide_pipe_name.as_ptr(),
                PIPE_ACCESS_INBOUND,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                1,    // Nur eine Instanz erlaubt
                512,  // output buffer size
                4096, // input buffer size
                0,    // default time-out
                &sa,
            );

            if pipe_handle == INVALID_HANDLE_VALUE {
                warn!(
                    "[Pipe Server] CreateNamedPipeW fehlgeschlagen: {}. Thread wird beendet.",
                    GetLastError()
                );
                return;
            }
            info!(
                "[Pipe Server] Pipe '{}' erstellt. Warte auf Client...",
                pipe_name
            );

            // Warte, bis sich die DLL (der Client) verbindet.
            if ConnectNamedPipe(pipe_handle, std::ptr::null_mut()) == 0 {
                let error = GetLastError();
                // ERROR_PIPE_CONNECTED (535) ist kein Fehler, sondern bedeutet, dass der Client sich bereits verbunden hat.
                if error != 535 {
                    // ERROR_PIPE_CONNECTED
                    warn!("[Pipe Server] ConnectNamedPipe fehlgeschlagen: {}", error);
                    CloseHandle(pipe_handle);
                    continue; // Versuche, eine neue Pipe zu erstellen.
                }
            }
            info!("[Pipe Server] Client verbunden. Lese Nachrichten...");

            // Lese Nachrichten von der Pipe in einer Schleife.
            let mut buffer = [0u8; 4096];
            loop {
                let mut bytes_read = 0;
                if ReadFile(
                    pipe_handle as _,
                    buffer.as_mut_ptr() as _,
                    buffer.len() as u32,
                    &mut bytes_read,
                    std::ptr::null_mut(),
                ) != 0
                {
                    if bytes_read > 0 {
                        let message = String::from_utf8_lossy(&buffer[..bytes_read as usize]);
                        info!("[DLL] {}", message.trim_end());
                    } else {
                        info!("[Pipe Server] Client hat die Verbindung (sauber) getrennt.");
                        break;
                    }
                } else {
                    let error = GetLastError();
                    if error == 109 {
                        // ERROR_BROKEN_PIPE
                        info!("[Pipe Server] Client hat die Verbindung (unerwartet) getrennt.");
                    } else {
                        warn!("[Pipe Server] ReadFile fehlgeschlagen: {}", error);
                    }
                    break;
                }
            }
            CloseHandle(pipe_handle);
        }
    });
}

fn main() {

    // Initialisiere den Logger, der in die Konsole schreibt.
    match SimpleLogger::new().with_level(log::LevelFilter::Info).init() {
        Ok(_) => (), // Logger ist bereit
        Err(e) => {
            eprintln!("Fehler: Logger konnte nicht initialisiert werden: {}", e);
            return;
        }
    }

    // Diese Nachricht wird jetzt in der Konsole erscheinen.
    log::info!("DLL Dynamic Analyzer by HUTAOSHUSBAND gestartet. Logging zur Konsole ist aktiv.");

    // Ein "Event Loop" wird benötigt, damit das Programm auf Klicks reagieren kann
    let event_loop = EventLoopBuilder::new().build().unwrap();

    // --- Tray-Menü erstellen (korrigiert) ---
    let tray_menu = Menu::new();
    let title_item = MenuItem::new("DLL Analyzer by HUTAOSHUSBAND", false, None);
    let scan_item = MenuItem::new("Analyse starten", true, None);
    let exit_item = MenuItem::new("Exit", true, None);
    
    // Die .unwrap()-Aufrufe wurden entfernt, da sie die Fehler verursacht haben.
    let _ = tray_menu.append(&title_item);
    let _ = tray_menu.append(&scan_item);
    let _ = tray_menu.append(&exit_item);

    // Erstellen des eigentlichen Tray-Icons
    let _tray_icon = TrayIconBuilder::new()
        .with_tooltip("DLL Analyzer by HUTAOSHUSBAND")
        .with_menu(Box::new(tray_menu))
        .build()
        .unwrap();

    // Überwachen von Klick-Events auf das Menü
    let menu_channel = MenuEvent::receiver();

    // Startet die Hauptschleife des Programms
    event_loop
        .run(move |_event, event_loop| {
            event_loop.set_control_flow(ControlFlow::Wait);

            if let Ok(event) = menu_channel.try_recv() {
                if event.id == scan_item.id() {
                    log::info!("'Analyse starten' geklickt. Analyse wird im Hintergrund ausgeführt.");
                    run_analysis();
                } else if event.id == exit_item.id() {
                    log::info!("Exit-Button geklickt. Programm wird beendet.");
                    event_loop.exit();
                }
            }
        })
        .unwrap();
}