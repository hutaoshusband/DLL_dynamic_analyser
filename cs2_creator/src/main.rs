// Verhindert das Konsolenfenster beim Start
// #![windows_subsystem = "windows"]

// Nötige Importe
use tray_icon::{
    menu::{Menu, MenuItem, MenuEvent},
    TrayIconBuilder,
};
// Nötige Importe für die Windows-API
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::fs::File;
use std::thread;
use log::{info, warn};
use simple_logger::SimpleLogger;
use winit::event_loop::{ControlFlow, EventLoopBuilder};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory, IMAGE_NT_HEADERS64},
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW,
            Process32NextW, MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPPROCESS,
        },
        Threading::{CreateRemoteThread, OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE},
        Memory::{
            VirtualAllocEx, VirtualFreeEx, VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT,
            MEM_PRIVATE, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
            PAGE_EXECUTE_WRITECOPY, PAGE_READWRITE,
        },
        LibraryLoader::{GetModuleHandleW, GetProcAddress},
        SystemServices::IMAGE_DOS_HEADER,
    },
};
use rfd::FileDialog;

/// Ein RAII-Wrapper für Windows-Handles, der `CloseHandle` automatisch aufruft.
struct Handle(isize);

impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 && self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0); }
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
                    &process_entry.szExeFile[..process_entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0)]
                ).to_string_lossy().into_owned();
                
                // Leere oder System-Prozesse ignorieren wir hier nicht, um die Liste vollständig zu halten.
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
            warn!("CreateToolhelp32Snapshot (Module) für PID {} fehlgeschlagen: {}", pid, GetLastError());
            return loaded_modules;
        }

        let mut module_entry: MODULEENTRY32W = std::mem::zeroed();
        module_entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

        if Module32FirstW(snapshot_handle.0, &mut module_entry) != 0 {
            loop {
                let module_name = OsString::from_wide(
                    &module_entry.szModule[..module_entry.szModule.iter().position(|&c| c == 0).unwrap_or(0)]
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
            warn!("CreateToolhelp32Snapshot (Process) failed: {}", GetLastError());
            return None;
        }

        let mut process_entry: PROCESSENTRY32W = std::mem::zeroed();
        process_entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot_handle.0, &mut process_entry) != 0 {
            loop {
                let process_name = OsString::from_wide(
                    &process_entry.szExeFile[..process_entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0)]
                );

                if process_name.to_string_lossy().eq_ignore_ascii_case(target_process_name) {
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

    info!("Zielprozess '{}' gefunden mit PID: {}", target_process_name, pid);
    let mut loaded_modules = Vec::new();

    unsafe {
        let snapshot_handle = Handle(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid));
        if snapshot_handle.0 == INVALID_HANDLE_VALUE {
            warn!("CreateToolhelp32Snapshot (Module) für PID {} fehlgeschlagen: {}", pid, GetLastError());
            return (Some(pid), loaded_modules);
        }

        let mut module_entry: MODULEENTRY32W = std::mem::zeroed();
        module_entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

        if Module32FirstW(snapshot_handle.0, &mut module_entry) != 0 {
            loop {
                let module_name = OsString::from_wide(
                    &module_entry.szModule[..module_entry.szModule.iter().position(|&c| c == 0).unwrap_or(0)]
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
        // 1. Prozess mit den nötigen Rechten öffnen.
        let process_handle = Handle(OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            0,
            pid,
        ));

        if process_handle.0 == 0 {
            warn!("OpenProcess für PID {} fehlgeschlagen: {}", pid, GetLastError());
            return findings;
        }

        // 2. Den Speicher des Prozesses in einer Schleife durchgehen.
        let mut current_address: usize = 0;
        loop {
            let mut mem_info: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let result = VirtualQueryEx(
                process_handle.0,
                current_address as *const _,
                &mut mem_info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            // Wenn wir am Ende des Speichers angekommen sind, beenden wir die Schleife.
            if result == 0 {
                break;
            }

            // 3. Prüfen, ob der Speicherbereich "interessant" ist.
            let is_private_committed = mem_info.State == MEM_COMMIT && mem_info.Type == MEM_PRIVATE;
            let is_executable = (mem_info.Protect & PAGE_EXECUTE_READ) != 0 ||
                                (mem_info.Protect & PAGE_EXECUTE_READWRITE) != 0 ||
                                (mem_info.Protect & PAGE_EXECUTE_WRITECOPY) != 0;

            if is_private_committed && is_executable {
                // 4. & 5. Die ersten Bytes lesen und auf einen PE-Header ('MZ') prüfen.
                let mut dos_header: IMAGE_DOS_HEADER = std::mem::zeroed();
                let mut bytes_read = 0;

                if ReadProcessMemory(
                    process_handle.0,
                    mem_info.BaseAddress,
                    &mut dos_header as *mut _ as *mut _,
                    std::mem::size_of::<IMAGE_DOS_HEADER>(),
                    &mut bytes_read,
                ) != 0 && bytes_read > 0 && dos_header.e_magic == 0x5A4D { // 0x5A4D ist 'MZ' in little-endian
                    
                    // Zusätzliche, robustere Prüfung: Dem 'e_lfanew' Pointer folgen und den NT-Header ('PE') verifizieren.
                    let nt_header_address = (mem_info.BaseAddress as usize + dos_header.e_lfanew as usize) as *const _;
                    let mut nt_headers: IMAGE_NT_HEADERS64 = std::mem::zeroed();

                    if ReadProcessMemory(
                        process_handle.0,
                        nt_header_address,
                        &mut nt_headers as *mut _ as *mut _,
                        std::mem::size_of::<IMAGE_NT_HEADERS64>(),
                        &mut bytes_read,
                    ) != 0 && bytes_read > 0 && nt_headers.Signature == 0x4550 { // 0x4550 ist 'PE'
                        // 6. Ein starker Hinweis wurde gefunden.
                        let finding = format!(
                            "Potenziell manuell gemapptes Image gefunden an Adresse: {:#X}",
                            mem_info.BaseAddress as usize
                        );
                        info!("{}", &finding);
                        findings.push(finding);
                    }
                }
            }

            // 7. Zum nächsten Speicherbereich springen.
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
        // 1. Prozess mit allen nötigen Rechten öffnen (RAII-Wrapper wird verwendet).
        let process_handle = Handle(OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            0,
            pid,
        ));
        if process_handle.0 == 0 {
            return Err(format!("OpenProcess für PID {} fehlgeschlagen: {}", pid, GetLastError()));
        }

        // 2. Speicher im Zielprozess für den DLL-Pfad allozieren.
        let dll_path_bytes = (dll_path.to_owned() + "\0").encode_utf16().collect::<Vec<u16>>();
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

        // 3. Den DLL-Pfad in den alloziierten Speicher schreiben.
        let mut bytes_written = 0;
        // KORREKTUR: WriteProcessMemory statt ReadProcessMemory verwenden.
        if WriteProcessMemory(process_handle.0, remote_buffer, dll_path_bytes.as_ptr() as _, dll_path_bytes.len() * 2, &mut bytes_written) == 0 {
            VirtualFreeEx(process_handle.0, remote_buffer, 0, MEM_RELEASE);
            return Err(format!("WriteProcessMemory fehlgeschlagen: {}", GetLastError()));
        }

        // 4. Die Adresse von LoadLibraryW finden.
        let kernel32_handle = GetModuleHandleW("kernel32.dll\0".encode_utf16().collect::<Vec<u16>>().as_ptr());
        let load_library_addr = GetProcAddress(kernel32_handle, "LoadLibraryW\0".as_ptr() as _);
        
        if load_library_addr.is_none() {
            VirtualFreeEx(process_handle.0, remote_buffer, 0, MEM_RELEASE);
            return Err("Konnte Adresse von LoadLibraryW nicht finden".to_string());
        }

        // 5. Einen neuen Thread im Zielprozess starten, der LoadLibraryW mit unserem DLL-Pfad aufruft.
        let thread_handle = Handle(CreateRemoteThread(process_handle.0, std::ptr::null(), 0, Some(std::mem::transmute(load_library_addr)), remote_buffer as *const std::ffi::c_void, 0, std::ptr::null_mut()));
        if thread_handle.0 == 0 {
            VirtualFreeEx(process_handle.0, remote_buffer, 0, MEM_RELEASE);
            return Err(format!("CreateRemoteThread fehlgeschlagen: {}", GetLastError()));
        }

        // Handles werden durch den RAII-Wrapper (Drop-Implementierung) automatisch geschlossen.
    }
    Ok(())
}

/// Führt alle Analyse-Schritte durch und loggt die Ergebnisse.
fn run_analysis() {
    // VERBESSERUNG: Analyse in einem neuen Thread ausführen, um die GUI nicht zu blockieren.
    thread::spawn(|| {
        _run_analysis_internal();
    });
}

fn _run_analysis_internal() {
    info!("--- Starte interaktive Analyse ---");

    // 1. Alle laufenden Prozesse auflisten und in die Log-Datei schreiben.
    let processes = get_all_processes();
    info!("Laufende Prozesse:");
    for (pid, name) in &processes {
        info!("  PID: {:<6} | Name: {}", pid, name);
    }

    // 2. Benutzer zur Eingabe des Prozessnamens oder der PID auffordern.
    let target_input = match tinyfiledialogs::input_box( // <-- Korrigierter Funktionsname
        "Prozess auswählen",
        "Bitte geben Sie den Namen oder die PID des Zielprozesses ein.\n(Eine Liste finden Sie in der cs2_runner.log)",
        "", // Standardwert
    ) {
        Some(input) if !input.is_empty() => input,
        _ => {
            info!("Keine Eingabe. Analyse abgebrochen.");
            return;
        }
    };

    // 3. PID aus der Benutzereingabe ermitteln.
    let target_pid = if let Ok(pid) = target_input.parse::<u32>() {
        // Eingabe ist eine PID. Prüfen, ob der Prozess existiert.
        processes.iter().find(|(p, _)| *p == pid).map(|(p, _)| *p)
    } else {
        // Eingabe ist ein Prozessname.
        find_process_id(&target_input)
    };

    let Some(pid) = target_pid else {
        warn!("Prozess '{}' konnte nicht gefunden werden. Analyse abgebrochen.", target_input);
        return;
    };

    info!("Zielprozess mit PID {} ausgewählt.", pid);

    // 4. Benutzer auffordern, die Monitor-DLL auszuwählen (wie zuvor).
    let dll_path = match FileDialog::new()
        .add_filter("Dynamic Link Library", &["dll"])
        .set_title("Wähle die zu injizierende Monitor-DLL")
        .pick_file() {
            Some(path) => path,
            None => {
                info!("Keine DLL ausgewählt. Analyse abgebrochen.");
                return;
            }
        };

    // 5. Analyse und Injektion durchführen.
    info!("--- Starte Scan für PID {} ---", pid);
    
    let modules = find_loaded_modules_by_pid(pid);
    info!("Gefundene Module in PID {}:", pid);
    modules.iter().for_each(|m| info!("- {}", m));

    let manual_map_findings = detect_manual_mapping(pid);
    info!("Ergebnisse der Manual-Mapping-Analyse:");
    if manual_map_findings.is_empty() {
        info!("Keine Auffälligkeiten gefunden.");
    } else {
        manual_map_findings.iter().for_each(|f| info!("- {}", f));
    }
    
    match inject_dll(pid, dll_path.to_str().unwrap()) {
        Ok(_) => info!("Monitor-DLL '{}' erfolgreich injiziert.", dll_path.display()),
        Err(e) => warn!("Fehler beim Injizieren der Monitor-DLL: {}", e),
    }

    info!("--- Analyse beendet ---");
}

fn main() {
    // Ein "Event Loop" wird benötigt, damit das Programm auf Klicks reagieren kann
    let event_loop = EventLoopBuilder::new().build().unwrap();

    // --- Tray-Menü erstellen ---
    let tray_menu = Menu::new();
    let title_item = MenuItem::new("CS2 Runner by HUTAOSHUSBAND", false, None);
    let scan_item = MenuItem::new("Analyse starten", true, None);
    let exit_item = MenuItem::new("Exit", true, None);
    tray_menu.append(&title_item).unwrap();
    tray_menu.append(&scan_item).unwrap();
    tray_menu.append(&exit_item).unwrap();

    // Erstellen des eigentlichen Tray-Icons
    let _tray_icon = TrayIconBuilder::new()
        .with_tooltip("CS2 Runner by HUTAOSHUSBAND")
        .with_menu(Box::new(tray_menu))
        .build()
        .unwrap();

    // Initialisiere das Logging in eine Datei
    // Fehler werden ignoriert, falls die Datei nicht erstellt werden kann.
    if File::create("cs2_runner.log").is_ok() {
        let _ = SimpleLogger::new().with_level(log::LevelFilter::Info).init();
        info!("CS2 Runner by HUTAOSHUSBAND gestartet. Logging ist aktiv.");
    } else {
        // Optional: Eine Fehlermeldung anzeigen, wenn das Log nicht erstellt werden kann.
        // In einem Tray-Icon-Programm ist das aber schwierig ohne GUI.
    }

    // Überwachen von Klick-Events auf das Menü
    let menu_channel = MenuEvent::receiver();

    // Startet die Hauptschleife des Programms
    event_loop.run(move |_event, event_loop| {
        // Stellt sicher, dass das Programm nicht 100% CPU verbraucht
        event_loop.set_control_flow(ControlFlow::Wait);

        // Prüft, ob ein Menü-Item geklickt wurde
        if let Ok(event) = menu_channel.try_recv() {
            if event.id == scan_item.id() {
                info!("'Analyse starten' geklickt. Analyse wird im Hintergrund ausgeführt.");
                run_analysis();
            } else if event.id == exit_item.id() {
                info!("Exit-Button geklickt. Starte Analyse vor dem Beenden...");
                // Hinweis: Die Analyse beim Beenden wird möglicherweise nicht abgeschlossen,
                // da das Hauptprogramm sofort beendet wird.
                event_loop.exit();
            }
        }
    }).unwrap();
}
