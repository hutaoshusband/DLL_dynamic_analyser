#![windows_subsystem = "windows"] // hide console window in all builds

use std::{
    ffi::{OsStr, OsString},
    mem,
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
        Arc, Mutex,
    },
    thread,
};

use eframe::egui;
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::Debug::WriteProcessMemory,
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        },
        LibraryLoader::{GetModuleHandleW, GetProcAddress},
        Memory::{
            VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
        },
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_MESSAGE,
            PIPE_TYPE_MESSAGE, PIPE_WAIT,
        },
        Threading::{
            CreateRemoteThread, OpenProcess, TerminateProcess, WaitForSingleObject,
            PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_SYNCHRONIZE,
            PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
        },
    },
    Security::{
        InitializeSecurityDescriptor, SetSecurityDescriptorDacl, SECURITY_ATTRIBUTES,
        SECURITY_DESCRIPTOR,
    },
    Storage::FileSystem::{ReadFile, PIPE_ACCESS_INBOUND},
};

const DLL_NAME: &str = "client.dll";

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
/// State für die GUI-Anwendung.
struct MyApp {
    target_process_name: String,
    dll_path: Option<PathBuf>,
    log_receiver: Receiver<String>,
    log_sender: Sender<String>,
    logs: Vec<String>,
    process_id: Arc<Mutex<Option<u32>>>,
    process_handle: Arc<Mutex<Option<isize>>>,
    is_process_running: Arc<AtomicBool>,
    injection_status: Arc<Mutex<String>>,
}

impl MyApp {
    /// Erstellt eine neue Instanz der Anwendung.
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let (log_sender, log_receiver) = mpsc::channel();

        // Finde den Pfad zur client.dll relativ zur .exe
        let dll_path = match std::env::current_exe() {
            Ok(exe_path) => {
                let exe_dir = exe_path.parent().unwrap();
                let dll_path = exe_dir.join(DLL_NAME);
                if dll_path.exists() {
                    log_sender
                        .send(format!("{} gefunden in: {}", DLL_NAME, dll_path.display()))
                        .unwrap();
                    Some(dll_path)
                } else {
                    log_sender
                        .send(format!(
                            "FEHLER: {} nicht im Verzeichnis {} gefunden.",
                            DLL_NAME,
                            exe_dir.display()
                        ))
                        .unwrap();
                    None
                }
            }
            Err(e) => {
                log_sender
                    .send(format!(
                        "FEHLER: Aktueller Pfad der Anwendung konnte nicht ermittelt werden: {}",
                        e
                    ))
                    .unwrap();
                None
            }
        };

        Self {
            target_process_name: "cs2.exe".to_owned(),
            dll_path,
            log_receiver,
            log_sender,
            logs: Vec::new(),
            process_id: Arc::new(Mutex::new(None)),
            process_handle: Arc::new(Mutex::new(None)),
            is_process_running: Arc::new(AtomicBool::new(false)),
            injection_status: Arc::new(Mutex::new("Nicht injiziert".to_string())),
        }
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Log-Nachrichten aus dem Channel abrufen und speichern
        while let Ok(log_message) = self.log_receiver.try_recv() {
            self.logs.push(log_message);
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("DLL Dynamic Analyzer");
            ui.separator();

            // --- Obere Sektion: Prozess und DLL ---
            ui.horizontal(|ui| {
                ui.label("Zielprozess:");
                ui.text_edit_singleline(&mut self.target_process_name);
            });

            if let Some(path) = &self.dll_path {
                ui.horizontal(|ui| {
                    ui.label("DLL Pfad:");
                    ui.monospace(path.to_str().unwrap_or("Ungültiger Pfad"));
                });
            } else {
                ui.colored_label(egui::Color32::RED, "Keine client.dll gefunden!");
                ui.label("Stellen Sie sicher, dass sich die client.dll im selben Verzeichnis wie die .exe befindet.");
            }

            ui.separator();

            // --- Mittlere Sektion: Steuerung ---
            ui.horizontal(|ui| {
                let is_running = self.is_process_running.load(Ordering::SeqCst);

                // Button "Analyse starten"
                if ui.add_enabled(!is_running && self.dll_path.is_some(), egui::Button::new("Analyse starten")).clicked() {
                    let logger = self.log_sender.clone();
                    let target = self.target_process_name.clone();
                    let dll_path = self.dll_path.as_ref().unwrap().clone();
                    let pid_arc = self.process_id.clone();
                    let handle_arc = self.process_handle.clone();
                    let running_arc = self.is_process_running.clone();
                    let status_arc = self.injection_status.clone();

                    thread::spawn(move || {
                        run_analysis(
                            logger,
                            &target,
                            &dll_path,
                            pid_arc,
                            handle_arc,
                            running_arc,
                            status_arc,
                        );
                    });
                }

                // Button "Analyse manuell stoppen"
                if ui.add_enabled(is_running, egui::Button::new("Analyse manuell stoppen und kill client.dll")).clicked() {
                    if let Some(handle) = *self.process_handle.lock().unwrap() {
                        self.log_sender.send("Versuche, Prozess manuell zu beenden...".to_string()).unwrap();
                        unsafe {
                            if TerminateProcess(handle, 1) != 0 {
                                self.log_sender.send("Prozess erfolgreich beendet.".to_string()).unwrap();
                                CloseHandle(handle);
                            } else {
                                self.log_sender.send(format!("Prozess konnte nicht beendet werden: Fehler {}", GetLastError())).unwrap();
                            }
                        }
                    } else {
                        self.log_sender.send("Kein gültiges Prozess-Handle zum Beenden vorhanden.".to_string()).unwrap();
                    }
                    // Reset state regardless of success
                    *self.process_id.lock().unwrap() = None;
                    *self.process_handle.lock().unwrap() = None;
                    self.is_process_running.store(false, Ordering::SeqCst);
                    *self.injection_status.lock().unwrap() = "Prozess manuell beendet".to_string();
                }
            });

            ui.separator();

            // --- Untere Sektion: Status und Logs ---
            ui.label(format!("Status: {}", *self.injection_status.lock().unwrap()));

            ui.add_space(10.0);
            ui.label("Logs:");
            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for log in &self.logs {
                        ui.monospace(log);
                    }
                });
        });

        // UI kontinuierlich aktualisieren, um auf neue Logs zu reagieren
        ctx.request_repaint();
    }
}

/// Sucht die Prozess-ID (PID) für einen gegebenen Prozessnamen.
fn find_process_id(target_process_name: &str, logger: &Sender<String>) -> Option<u32> {
    unsafe {
        let snapshot_handle = Handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if snapshot_handle.0 == INVALID_HANDLE_VALUE {
            logger.send(format!("CreateToolhelp32Snapshot (Process) failed: {}", GetLastError())).unwrap();
            return None;
        }

        let mut process_entry: PROCESSENTRY32W = mem::zeroed();
        process_entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot_handle.0, &mut process_entry) != 0 {
            loop {
                let process_name = OsString::from_wide(
                    &process_entry.szExeFile[..process_entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0)],
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

/// Injiziert eine DLL in einen Prozess.
fn inject_dll(pid: u32, dll_path: &Path) -> Result<isize, String> {
    let process_handle = unsafe {
        OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ
                | PROCESS_SYNCHRONIZE, // Wichtig für WaitForSingleObject
            0,
            pid,
        )
    };
    if process_handle == 0 {
        return Err(format!("OpenProcess für PID {} fehlgeschlagen: {}", pid, unsafe { GetLastError() }));
    }

    let dll_path_str = dll_path.as_os_str();
    let dll_path_bytes: Vec<u16> = OsStr::new(dll_path_str).encode_wide().chain(Some(0)).collect();

    let remote_buffer = unsafe {
        VirtualAllocEx(
            process_handle,
            std::ptr::null(),
            dll_path_bytes.len() * 2,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if remote_buffer.is_null() {
        unsafe { CloseHandle(process_handle) };
        return Err(format!("VirtualAllocEx fehlgeschlagen: {}", unsafe { GetLastError() }));
    }

    let mut bytes_written = 0;
    if unsafe {
        WriteProcessMemory(
            process_handle,
            remote_buffer,
            dll_path_bytes.as_ptr() as _,
            dll_path_bytes.len() * 2,
            &mut bytes_written,
        )
    } == 0
    {
        unsafe {
            VirtualFreeEx(process_handle, remote_buffer, 0, MEM_RELEASE);
            CloseHandle(process_handle);
        }
        return Err(format!("WriteProcessMemory fehlgeschlagen: {}", unsafe { GetLastError() }));
    }

    let kernel32_handle = unsafe { GetModuleHandleW("kernel32.dll\0".encode_utf16().collect::<Vec<u16>>().as_ptr()) };
    let load_library_addr = unsafe { GetProcAddress(kernel32_handle, "LoadLibraryW\0".as_ptr() as _) };

    if load_library_addr.is_none() {
        unsafe {
            VirtualFreeEx(process_handle, remote_buffer, 0, MEM_RELEASE);
            CloseHandle(process_handle);
        }
        return Err("Konnte Adresse von LoadLibraryW nicht finden".to_string());
    }

    let thread_handle = unsafe {
        CreateRemoteThread(
            process_handle,
            std::ptr::null(),
            0,
            Some(std::mem::transmute(load_library_addr)),
            remote_buffer as *const _,
            0,
            std::ptr::null_mut(),
        )
    };
    if thread_handle == 0 {
        unsafe {
            VirtualFreeEx(process_handle, remote_buffer, 0, MEM_RELEASE);
            CloseHandle(process_handle);
        }
        return Err(format!("CreateRemoteThread fehlgeschlagen: {}", unsafe { GetLastError() }));
    }

    // Remote-Buffer muss nicht mehr aufgeräumt werden, da LoadLibraryW den Pfad kopiert.
    // VirtualFreeEx(process_handle, remote_buffer, 0, MEM_RELEASE); // Optional
    unsafe { CloseHandle(thread_handle) };

    Ok(process_handle)
}

/// Hauptanalyse-Routine.
fn run_analysis(
    logger: Sender<String>,
    target_process_name: &str,
    dll_path: &Path,
    pid_arc: Arc<Mutex<Option<u32>>>,
    handle_arc: Arc<Mutex<Option<isize>>>,
    running_arc: Arc<AtomicBool>,
    status_arc: Arc<Mutex<String>>,
) {
    logger.send("--- Starte Analyse ---".to_string()).unwrap();
    running_arc.store(true, Ordering::SeqCst);
    *status_arc.lock().unwrap() = format!("Suche Prozess: {}...", target_process_name);

    let Some(pid) = find_process_id(target_process_name, &logger) else {
        logger.send(format!("Prozess '{}' nicht gefunden.", target_process_name)).unwrap();
        *status_arc.lock().unwrap() = format!("Prozess '{}' nicht gefunden.", target_process_name);
        running_arc.store(false, Ordering::SeqCst);
        return;
    };

    logger.send(format!("Prozess '{}' gefunden mit PID: {}", target_process_name, pid)).unwrap();
    *pid_arc.lock().unwrap() = Some(pid);
    *status_arc.lock().unwrap() = format!("Injiziere in PID {}...", pid);

    // Starte Pipe Server
    start_pipe_server(pid, logger.clone());
    logger.send("Warte kurz, damit der Pipe-Server bereit ist...".to_string()).unwrap();
    thread::sleep(std::time::Duration::from_millis(500));

    match inject_dll(pid, dll_path) {
        Ok(handle) => {
            logger.send(format!("DLL '{}' erfolgreich injiziert. Überwachung aktiv.", dll_path.display())).unwrap();
            *status_arc.lock().unwrap() = "Erfolgreich injiziert. Überwache Prozess.".to_string();
            *handle_arc.lock().unwrap() = Some(handle);

            // Thread, der auf das Ende des Prozesses wartet
            let logger_clone = logger.clone();
            let running_arc_clone = running_arc.clone();
            let status_arc_clone = status_arc.clone();
            let pid_arc_clone = pid_arc.clone();
            let handle_arc_clone = handle_arc.clone();
            thread::spawn(move || {
                unsafe {
                    WaitForSingleObject(handle, u32::MAX);
                }
                // Nur den Status ändern, wenn der Prozess nicht manuell gestoppt wurde
                if running_arc_clone.load(Ordering::SeqCst) {
                     logger_clone.send("Zielprozess wurde beendet.".to_string()).unwrap();
                    *status_arc_clone.lock().unwrap() = "Prozess beendet".to_string();
                    running_arc_clone.store(false, Ordering::SeqCst);
                    *pid_arc_clone.lock().unwrap() = None;
                    *handle_arc_clone.lock().unwrap() = None;
                }
                unsafe { CloseHandle(handle) };
            });
        }
        Err(e) => {
            logger.send(format!("Fehler beim Injizieren der DLL: {}", e)).unwrap();
            *status_arc.lock().unwrap() = format!("Fehler: {}", e);
            running_arc.store(false, Ordering::SeqCst);
        }
    }
}

/// Startet einen Named-Pipe-Server, um auf Logs von der DLL zu lauschen.
fn start_pipe_server(pid: u32, logger: Sender<String>) {
    thread::spawn(move || unsafe {
        let pipe_name = format!(r"\\.\pipe\cs2_monitor_{}", pid);
        let wide_pipe_name: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();

        let mut sa: SECURITY_ATTRIBUTES = mem::zeroed();
        let mut sd: SECURITY_DESCRIPTOR = mem::zeroed();
        InitializeSecurityDescriptor(&mut sd as *mut _ as *mut _, 1);
        SetSecurityDescriptorDacl(&mut sd as *mut _ as *mut _, 1, std::ptr::null_mut(), 0);
        sa.nLength = mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
        sa.lpSecurityDescriptor = &mut sd as *mut _ as *mut _;
        sa.bInheritHandle = 0;

        // Nur eine Verbindung erlauben, dann beenden.
        let pipe_handle = CreateNamedPipeW(
            wide_pipe_name.as_ptr(),
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1, 512, 4096, 0, &sa,
        );

        if pipe_handle == INVALID_HANDLE_VALUE {
            logger.send(format!("[Pipe Server] CreateNamedPipeW fehlgeschlagen: {}. Thread wird beendet.", GetLastError())).unwrap();
            return;
        }
        logger.send(format!("[Pipe Server] Pipe '{}' erstellt. Warte auf Client...", pipe_name)).unwrap();

        if ConnectNamedPipe(pipe_handle, std::ptr::null_mut()) == 0 {
            let error = GetLastError();
            if error != 535 { // ERROR_PIPE_CONNECTED
                logger.send(format!("[Pipe Server] ConnectNamedPipe fehlgeschlagen: {}", error)).unwrap();
                CloseHandle(pipe_handle);
                return;
            }
        }
        logger.send("[Pipe Server] Client verbunden. Lese Nachrichten...".to_string()).unwrap();

        let mut buffer = [0u8; 4096];
        loop {
            let mut bytes_read = 0;
            if ReadFile(
                pipe_handle as _,
                buffer.as_mut_ptr() as _,
                buffer.len() as u32,
                &mut bytes_read,
                std::ptr::null_mut(),
            ) != 0 {
                if bytes_read > 0 {
                    let message = String::from_utf8_lossy(&buffer[..bytes_read as usize]);
                    logger.send(format!("[DLL] {}", message.trim_end())).unwrap();
                } else {
                    logger.send("[Pipe Server] Client hat die Verbindung (sauber) getrennt.".to_string()).unwrap();
                    break;
                }
            } else {
                let error = GetLastError();
                if error == 109 { // ERROR_BROKEN_PIPE
                    logger.send("[Pipe Server] Client hat die Verbindung (unerwartet) getrennt.".to_string()).unwrap();
                } else {
                    logger.send(format!("[Pipe Server] ReadFile fehlgeschlagen: {}", error)).unwrap();
                }
                break;
            }
        }
        CloseHandle(pipe_handle);
    });
}

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([600.0, 400.0])
            .with_title("DLL Dynamic Analyzer"),
        ..Default::default()
    };
    eframe::run_native(
        "DLL Dynamic Analyzer",
        options,
        Box::new(|cc| Box::new(MyApp::new(cc))),
    )
}