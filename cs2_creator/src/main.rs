#![windows_subsystem = "windows"] // hide console window in all builds

use chrono::{DateTime, Utc};
use eframe::egui;
use serde::Deserialize;
use std::{
    mem,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
        Arc, Mutex,
    },
    thread,
};
use widestring::{U16CString, U16String};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::Debug::{
            ReadProcessMemory, WriteProcessMemory, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
        },
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW,
            Process32NextW, MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE,
            TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
        },
        LibraryLoader::{GetModuleHandleW, GetProcAddress},
        Memory::{
            VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
        },
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_WAIT,
        },
        SystemServices::IMAGE_DOS_HEADER,
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

const DLL_NAME: &str = "monitor_lib.dll";

// --- Data Structures for Deserializing Logs ---

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Fatal = 0,
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
    Trace = 5,
}

#[derive(Deserialize, Debug)]
#[serde(tag = "event_type", content = "details")]
pub enum LogEvent {
    Initialization {
        status: String,
    },
    Shutdown {
        status: String,
    },
    ApiHook {
        function_name: String,
        parameters: serde_json::Value,
        #[serde(skip_serializing_if = "Option::is_none")]
        stack_trace: Option<Vec<String>>,
    },
    AntiDebugCheck {
        function_name: String,
        parameters: serde_json::Value,
        #[serde(skip_serializing_if = "Option::is_none")]
        stack_trace: Option<Vec<String>>,
    },
    ProcessEnumeration {
        function_name: String,
        parameters: serde_json::Value,
    },
    MemoryScan {
        status: String,
        result: String,
    },
    Error {
        source: String,
        message: String,
    },
}

// Implement PartialEq manually for LogEvent because serde_json::Value doesn't derive it.
impl PartialEq for LogEvent {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                LogEvent::Initialization { status: s1 },
                LogEvent::Initialization { status: s2 },
            ) => s1 == s2,
            (LogEvent::Shutdown { status: s1 }, LogEvent::Shutdown { status: s2 }) => s1 == s2,
            (
                LogEvent::ApiHook {
                    function_name: f1,
                    parameters: p1,
                    ..
                },
                LogEvent::ApiHook {
                    function_name: f2,
                    parameters: p2,
                    ..
                },
            ) => f1 == f2 && p1.to_string() == p2.to_string(), // Compare parameters as strings
            (
                LogEvent::AntiDebugCheck {
                    function_name: f1,
                    parameters: p1,
                    ..
                },
                LogEvent::AntiDebugCheck {
                    function_name: f2,
                    parameters: p2,
                    ..
                },
            ) => f1 == f2 && p1.to_string() == p2.to_string(),
            (
                LogEvent::ProcessEnumeration {
                    function_name: f1,
                    parameters: p1,
                },
                LogEvent::ProcessEnumeration {
                    function_name: f2,
                    parameters: p2,
                },
            ) => f1 == f2 && p1.to_string() == p2.to_string(),
            (
                LogEvent::MemoryScan {
                    status: s1,
                    result: r1,
                },
                LogEvent::MemoryScan {
                    status: s2,
                    result: r2,
                },
            ) => s1 == s2 && r1 == r2,
            (
                LogEvent::Error {
                    source: s1,
                    message: m1,
                },
                LogEvent::Error {
                    source: s2,
                    message: m2,
                },
            ) => s1 == s2 && m1 == m2,
            _ => false,
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct LogEntry {
    #[serde(with = "chrono::serde::ts_seconds")]
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    pub process_id: u32,
    pub thread_id: u32,
    #[serde(flatten)]
    pub event: LogEvent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack_trace: Option<Vec<String>>,
}

impl PartialEq for LogEntry {
    fn eq(&self, other: &Self) -> bool {
        self.level == other.level && self.event == other.event
    }
}

// --- End of Log Data Structures ---

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

#[derive(Clone, Debug)]
struct ModuleInfo {
    name: String,
    base_address: usize,
    size: u32,
}

struct FilterOptions {
    show_api_hooks: bool,
    show_anti_debug: bool,
    show_memory_allocs: bool,
    show_memory_scans: bool,
    min_log_level: LogLevel,
}

struct MyApp {
    target_process_name: String,
    dll_path: Option<PathBuf>,
    second_dll_path: Option<PathBuf>,
    log_receiver: Receiver<String>,
    log_sender: Sender<String>,
    logs: Vec<(LogEntry, usize)>, // Store LogEntry and a count for deduplication
    process_id: Arc<Mutex<Option<u32>>>,
    process_handle: Arc<Mutex<Option<isize>>>,
    is_process_running: Arc<AtomicBool>,
    injection_status: Arc<Mutex<String>>,
    modules: Arc<Mutex<Vec<ModuleInfo>>>,
    selected_module_index: Option<usize>,
    filters: FilterOptions,
}

impl MyApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let (log_sender, log_receiver) = mpsc::channel();

        let dll_path = match std::env::current_exe() {
            Ok(exe_path) => {
                let exe_dir = exe_path.parent().unwrap();
                let dll_path = exe_dir.join(DLL_NAME);
                if dll_path.exists() {
                    log_sender
                        .send(format!(
                            r#"{{"timestamp":{},"level":"Info","event_type":"Initialization","details":{{"status":"DLL gefunden in: {}"}}}}"#,
                            Utc::now().timestamp(),
                            dll_path.display().to_string().replace('\\', "/")
                        ))
                        .unwrap();
                    Some(dll_path)
                } else {
                    log_sender
                        .send(format!(
                            r#"{{"timestamp":{},"level":"Error","event_type":"Error","details":{{"source":"GUI","message":"FEHLER: {} nicht im Verzeichnis {} gefunden."}}}}"#,
                            Utc::now().timestamp(), DLL_NAME, exe_dir.display()
                        ))
                        .unwrap();
                    None
                }
            }
            Err(e) => {
                log_sender
                    .send(format!(
                        r#"{{"timestamp":{},"level":"Error","event_type":"Error","details":{{"source":"GUI","message":"FEHLER: Aktueller Pfad der Anwendung konnte nicht ermittelt werden: {}"}}}}"#,
                        Utc::now().timestamp(), e
                    ))
                    .unwrap();
                None
            }
        };

        Self {
            target_process_name: "cs2.exe".to_owned(),
            dll_path,
            second_dll_path: None,
            log_receiver,
            log_sender,
            logs: Vec::new(),
            process_id: Arc::new(Mutex::new(None)),
            process_handle: Arc::new(Mutex::new(None)),
            is_process_running: Arc::new(AtomicBool::new(false)),
            injection_status: Arc::new(Mutex::new("Nicht injiziert".to_string())),
            modules: Arc::new(Mutex::new(Vec::new())),
            selected_module_index: None,
            filters: FilterOptions {
                show_api_hooks: true,
                show_anti_debug: true,
                show_memory_allocs: true, // This now includes VirtualAllocEx
                show_memory_scans: true,
                min_log_level: LogLevel::Trace, // Show all levels by default
            },
        }
    }

    fn filtered_logs(&self) -> Vec<&(LogEntry, usize)> {
        self.logs
            .iter()
            .filter(|(log, _)| {
                // Filter by log level first
                if log.level > self.filters.min_log_level {
                    return false;
                }

                // Then filter by event type
                match &log.event {
                    LogEvent::ApiHook { function_name, .. } => {
                        if function_name.contains("VirtualAlloc") {
                            self.filters.show_memory_allocs
                        } else {
                            self.filters.show_api_hooks
                        }
                    }
                    LogEvent::AntiDebugCheck { .. } => self.filters.show_anti_debug,
                    LogEvent::MemoryScan { .. } => self.filters.show_memory_scans,
                    // Always show these important events regardless of filters
                    LogEvent::Initialization { .. }
                    | LogEvent::Shutdown { .. }
                    | LogEvent::Error { .. }
                    | LogEvent::ProcessEnumeration { .. } => true,
                }
            })
            .collect()
    }
}

fn dump_module_from_process(
    process_handle: isize,
    module: &ModuleInfo,
    logger: &Sender<String>,
) {
    fn read_memory<T: Copy>(process_handle: isize, address: usize) -> Result<T, String> {
        let mut buffer: T = unsafe { mem::zeroed() };
        let mut bytes_read = 0;
        if unsafe {
            ReadProcessMemory(
                process_handle,
                address as _,
                &mut buffer as *mut _ as _,
                mem::size_of::<T>(),
                &mut bytes_read,
            )
        } == 0
            || bytes_read != mem::size_of::<T>()
        {
            Err(format!(
                "ReadProcessMemory<T> bei 0x{:X} fehlgeschlagen. Fehler: {}",
                address,
                unsafe { GetLastError() }
            ))
        } else {
            Ok(buffer)
        }
    }

    fn read_memory_slice(
        process_handle: isize,
        address: usize,
        size: usize,
    ) -> Result<Vec<u8>, String> {
        if size == 0 {
            return Ok(Vec::new());
        }
        let mut buffer = vec![0u8; size];
        let mut bytes_read = 0;
        if unsafe {
            ReadProcessMemory(
                process_handle,
                address as _,
                buffer.as_mut_ptr() as _,
                size,
                &mut bytes_read,
            )
        } == 0
            || bytes_read != size
        {
            Err(format!(
                "ReadProcessMemory für Slice bei 0x{:X} ({} Bytes) fehlgeschlagen. Gelesen: {}/{}. Fehler: {}",
                address,
                size,
                bytes_read,
                size,
                unsafe { GetLastError() }
            ))
        } else {
            Ok(buffer)
        }
    }

    let file_path = rfd::FileDialog::new()
        .set_file_name(&module.name)
        .add_filter("DLL", &["dll"])
        .add_filter("All Files", &["*"])
        .save_file();

    let Some(target_path) = file_path else {
        // No need to log here, user cancelled.
        return;
    };

    let log_info = |msg: String| {
        logger
            .send(format!(
                r#"{{"timestamp":{},"level":"Info","event_type":"Initialization","details":{{"status":"{}"}}}}"#,
                Utc::now().timestamp(), msg
            ))
            .unwrap();
    };
    let log_error = |msg: String| {
        logger
            .send(format!(
                r#"{{"timestamp":{},"level":"Error","event_type":"Error","details":{{"source":"Dumper","message":"{}"}}}}"#,
                Utc::now().timestamp(), msg
            ))
            .unwrap();
    };

    log_info(format!(
        "Starte PE-basierten Dump für Modul '{}'...",
        module.name
    ));
    log_info("Hinweis: Stark geschützte (VMP, Themida) oder gepackte Module können möglicherweise nicht korrekt gedumpt werden.".to_string());

    let dump_result = (|| -> Result<PathBuf, String> {
        let dos_header: IMAGE_DOS_HEADER = read_memory(process_handle, module.base_address)?;
        if dos_header.e_magic != 0x5A4D {
            return Err("Ungültiger DOS-Header (MZ-Signatur nicht gefunden).".to_string());
        }

        let nt_header_addr = module.base_address + dos_header.e_lfanew as usize;
        let nt_headers: IMAGE_NT_HEADERS64 = read_memory(process_handle, nt_header_addr)?;
        if nt_headers.Signature != 0x00004550 {
            return Err("Ungültiger PE-Header (PE-Signatur nicht gefunden).".to_string());
        }

        let headers_size = nt_headers.OptionalHeader.SizeOfHeaders as usize;
        let mut file_buffer =
            read_memory_slice(process_handle, module.base_address, headers_size)?;

        let number_of_sections = nt_headers.FileHeader.NumberOfSections as usize;
        let section_header_addr = nt_header_addr + mem::size_of::<IMAGE_NT_HEADERS64>();

        for i in 0..number_of_sections {
            let current_section_header_addr =
                section_header_addr + i * mem::size_of::<IMAGE_SECTION_HEADER>();
            let section_header: IMAGE_SECTION_HEADER =
                read_memory(process_handle, current_section_header_addr)?;

            let raw_data_ptr = section_header.PointerToRawData as usize;
            let raw_data_size = section_header.SizeOfRawData as usize;

            if raw_data_size == 0 {
                continue;
            }

            let section_data_addr_in_mem =
                module.base_address + section_header.VirtualAddress as usize;

            match read_memory_slice(process_handle, section_data_addr_in_mem, raw_data_size) {
                Ok(section_data) => {
                    let required_size = raw_data_ptr + raw_data_size;
                    if file_buffer.len() < required_size {
                        file_buffer.resize(required_size, 0);
                    }
                    file_buffer[raw_data_ptr..required_size].copy_from_slice(&section_data);
                }
                Err(e) => {
                    log_error(format!(
                        "Warnung: Konnte Sektion '{}' nicht lesen: {}. Die Sektion wird im Dump fehlen.",
                        String::from_utf8_lossy(&section_header.Name).trim_end_matches('\0'),
                        e
                    ));
                }
            }
        }

        std::fs::write(&target_path, &file_buffer)
            .map_err(|e| format!("Fehler beim Schreiben der Dump-Datei: {}", e))?;

        Ok(target_path)
    })();

    match dump_result {
        Ok(path) => {
            log_info(format!(
                "Modul erfolgreich nach '{}' gedumpt.",
                path.display()
            ));
        }
        Err(e) => {
            log_error(format!("Fehler beim Dumpen des Moduls: {}", e));
        }
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(log_json) = self.log_receiver.try_recv() {
            match serde_json::from_str::<LogEntry>(&log_json) {
                Ok(new_log) => {
                    if let Some((last_log, count)) = self.logs.last_mut() {
                        if *last_log == new_log {
                            *count += 1;
                        } else {
                            self.logs.push((new_log, 1));
                        }
                    } else {
                        self.logs.push((new_log, 1));
                    }
                }
                Err(_) => {
                    // Fallback for non-JSON messages or parse errors
                    let fallback_log = LogEntry {
                        timestamp: Utc::now(),
                        level: LogLevel::Info,
                        process_id: 0,
                        thread_id: 0,
                        event: LogEvent::Initialization { status: log_json },
                        stack_trace: None,
                    };
                    self.logs.push((fallback_log, 1));
                }
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("DLL Dynamic Analyzer");
            ui.separator();

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
                ui.colored_label(egui::Color32::RED, "Keine monitor_lib.dll gefunden!");
                ui.label(
                    "Stellen Sie sicher, dass sich die DLL im selben Verzeichnis wie die .exe befindet.",
                );
            }

            ui.horizontal(|ui| {
                if ui.button("Zweite DLL auswählen").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("DLL", &["dll"])
                        .pick_file()
                    {
                        self.second_dll_path = Some(path);
                    }
                }
                if let Some(path) = &self.second_dll_path {
                    ui.label("Zweite DLL:");
                    ui.monospace(path.to_str().unwrap_or("Ungültiger Pfad"));
                }
            });

            ui.separator();

            ui.horizontal(|ui| {
                let is_running = self.is_process_running.load(Ordering::SeqCst);
                if ui
                    .add_enabled(
                        !is_running && self.dll_path.is_some(),
                        egui::Button::new("Analyse starten"),
                    )
                    .clicked()
                {
                    let logger = self.log_sender.clone();
                    let target = self.target_process_name.clone();
                    let dll_path = self.dll_path.as_ref().unwrap().clone();
                    let second_dll_path = self.second_dll_path.clone();
                    let pid_arc = self.process_id.clone();
                    let handle_arc = self.process_handle.clone();
                    let running_arc = self.is_process_running.clone();
                    let status_arc = self.injection_status.clone();
                    thread::spawn(move || {
                        run_analysis(
                            logger,
                            &target,
                            &dll_path,
                            second_dll_path,
                            pid_arc,
                            handle_arc,
                            running_arc,
                            status_arc,
                        );
                    });
                }
                if ui
                    .add_enabled(is_running, egui::Button::new("Analyse stoppen & Prozess killen"))
                    .clicked()
                {
                    if let Some(handle) = *self.process_handle.lock().unwrap() {
                        unsafe {
                            TerminateProcess(handle, 1);
                            CloseHandle(handle);
                        }
                    }
                    *self.process_id.lock().unwrap() = None;
                    *self.process_handle.lock().unwrap() = None;
                    self.is_process_running.store(false, Ordering::SeqCst);
                    *self.injection_status.lock().unwrap() = "Prozess manuell beendet".to_string();
                    self.modules.lock().unwrap().clear();
                    self.selected_module_index = None;
                }
            });

            ui.separator();

            ui.heading("DLLs im Zielprozess");
            ui.horizontal(|ui| {
                let is_running = self.is_process_running.load(Ordering::SeqCst);
                if ui
                    .add_enabled(is_running, egui::Button::new("Geladene DLLs aktualisieren"))
                    .clicked()
                {
                    if let Some(pid) = *self.process_id.lock().unwrap() {
                        match get_modules_for_process(pid) {
                            Ok(modules) => {
                                *self.modules.lock().unwrap() = modules;
                                self.selected_module_index = None;
                            }
                            Err(_) => {
                                // Error already logged by get_modules_for_process
                            }
                        }
                    }
                }
                if ui
                    .add_enabled(
                        self.selected_module_index.is_some(),
                        egui::Button::new("Ausgewählte DLL dumpen"),
                    )
                    .clicked()
                {
                    if let (Some(handle), Some(index)) =
                        (*self.process_handle.lock().unwrap(), self.selected_module_index)
                    {
                        let modules = self.modules.lock().unwrap();
                        if let Some(module_info) = modules.get(index) {
                            dump_module_from_process(handle, module_info, &self.log_sender);
                        }
                    }
                }
            });

            let modules_guard = self.modules.lock().unwrap();
            let module_names: Vec<String> = modules_guard.iter().map(|m| m.name.clone()).collect();
            let selected_module_name = self
                .selected_module_index
                .map(|i| module_names[i].clone())
                .unwrap_or_else(|| "Kein Modul ausgewählt".to_string());
            egui::ComboBox::from_label("Wähle eine DLL zum Dumpen aus")
                .selected_text(selected_module_name)
                .show_ui(ui, |ui| {
                    for (i, name) in module_names.iter().enumerate() {
                        if ui
                            .selectable_label(self.selected_module_index == Some(i), name)
                            .clicked()
                        {
                            self.selected_module_index = Some(i);
                        }
                    }
                });

            ui.separator();

            ui.heading("Log-Filter");
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.filters.show_api_hooks, "API-Hooks");
                ui.checkbox(&mut self.filters.show_anti_debug, "Anti-Debug");
                ui.checkbox(&mut self.filters.show_memory_allocs, "Memory-Allocs");
                ui.checkbox(&mut self.filters.show_memory_scans, "Memory-Scans");
            });

            ui.separator();

            ui.label(format!("Status: {}", *self.injection_status.lock().unwrap()));
            ui.add_space(10.0);
            ui.label("Logs:");
            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for (log, count) in self.filtered_logs() {
                        let color = match log.level {
                            LogLevel::Fatal | LogLevel::Error => egui::Color32::RED,
                            LogLevel::Warn => egui::Color32::from_rgb(255, 165, 0), // Orange
                            LogLevel::Info => egui::Color32::YELLOW,
                            LogLevel::Debug | LogLevel::Trace => egui::Color32::GREEN,
                        };

                        let mut log_text = format_log_entry(log);
                        if *count > 1 {
                            log_text = format!("({}x) {}", count, log_text);
                        }

                        ui.colored_label(color, log_text);
                    }
                });
        });

        ctx.request_repaint();
    }
}

fn format_log_entry(log: &LogEntry) -> String {
    let event_str = match &log.event {
        LogEvent::Initialization { status } => status.clone(),
        LogEvent::Shutdown { status } => status.clone(),
        LogEvent::ApiHook {
            function_name,
            parameters,
            ..
        } => format!("API Hook: {} | Params: {}", function_name, parameters),
        LogEvent::AntiDebugCheck {
            function_name,
            parameters,
            ..
        } => format!("Anti-Debug: {} | Params: {}", function_name, parameters),
        LogEvent::ProcessEnumeration {
            function_name,
            parameters,
        } => format!("Process Enum: {} | Params: {}", function_name, parameters),
        LogEvent::MemoryScan { status, result } => format!("Scan: {} -> {}", status, result),
        LogEvent::Error { source, message } => format!("ERROR [{}]: {}", source, message),
    };
    format!("[{}] {}", log.timestamp.format("%H:%M:%S"), event_str)
}

fn find_process_id(target_process_name: &str, _logger: &Sender<String>) -> Option<u32> {
    unsafe {
        let snapshot_handle = Handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if snapshot_handle.0 == INVALID_HANDLE_VALUE {
            return None;
        }

        let mut process_entry: PROCESSENTRY32W = mem::zeroed();
        process_entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot_handle.0, &mut process_entry) != 0 {
            loop {
                let len = process_entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(0);
                let process_name =
                    U16String::from_ptr(process_entry.szExeFile.as_ptr(), len).to_os_string();

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

fn get_modules_for_process(pid: u32) -> Result<Vec<ModuleInfo>, String> {
    unsafe {
        let snapshot_handle = Handle(CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
            pid,
        ));
        if snapshot_handle.0 == INVALID_HANDLE_VALUE {
            return Err(format!(
                "CreateToolhelp32Snapshot (Module) failed: {}",
                GetLastError()
            ));
        }

        let mut module_entry: MODULEENTRY32W = mem::zeroed();
        module_entry.dwSize = mem::size_of::<MODULEENTRY32W>() as u32;
        let mut modules = Vec::new();

        if Module32FirstW(snapshot_handle.0, &mut module_entry) != 0 {
            loop {
                let len = module_entry
                    .szModule
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(0);
                let module_name = U16String::from_ptr(module_entry.szModule.as_ptr(), len)
                    .to_string_lossy()
                    .to_owned();

                modules.push(ModuleInfo {
                    name: module_name,
                    base_address: module_entry.modBaseAddr as usize,
                    size: module_entry.modBaseSize,
                });
                if Module32NextW(snapshot_handle.0, &mut module_entry) == 0 {
                    break;
                }
            }
        }
        Ok(modules)
    }
}

fn inject_dll(pid: u32, dll_path: &Path) -> Result<isize, String> {
    let process_handle = unsafe {
        OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ
                | PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    };
    if process_handle == 0 {
        return Err(format!("OpenProcess für PID {} fehlgeschlagen: {}", pid, unsafe {
            GetLastError()
        }));
    }

    let dll_path_wide = U16CString::from_os_str(dll_path)
        .map_err(|e| format!("Pfad zur DLL ist ungültig: {}", e))?;
    // The length in bytes includes the null terminator, so we take len() + 1 u16 chars and multiply by 2.
    let dll_path_len_bytes = (dll_path_wide.len() + 1) * 2;

    let remote_buffer = unsafe {
        VirtualAllocEx(
            process_handle,
            std::ptr::null(),
            dll_path_len_bytes,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if remote_buffer.is_null() {
        unsafe { CloseHandle(process_handle) };
        return Err(format!("VirtualAllocEx fehlgeschlagen: {}", unsafe {
            GetLastError()
        }));
    }

    let mut bytes_written = 0;
    if unsafe {
        WriteProcessMemory(
            process_handle,
            remote_buffer,
            dll_path_wide.as_ptr() as _,
            dll_path_len_bytes,
            &mut bytes_written,
        )
    } == 0
    {
        unsafe {
            VirtualFreeEx(process_handle, remote_buffer, 0, MEM_RELEASE);
            CloseHandle(process_handle);
        }
        return Err(format!("WriteProcessMemory fehlgeschlagen: {}", unsafe {
            GetLastError()
        }));
    }

    let kernel32_handle = unsafe {
        GetModuleHandleW(U16CString::from_str("kernel32.dll").unwrap().as_ptr())
    };
    let load_library_addr =
        unsafe { GetProcAddress(kernel32_handle, b"LoadLibraryW\0".as_ptr()) };

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
        return Err(format!("CreateRemoteThread fehlgeschlagen: {}", unsafe {
            GetLastError()
        }));
    }
    unsafe { CloseHandle(thread_handle) };
    Ok(process_handle)
}

fn run_analysis(
    logger: Sender<String>,
    target_process_name: &str,
    dll_path: &Path,
    second_dll_path: Option<PathBuf>,
    pid_arc: Arc<Mutex<Option<u32>>>,
    handle_arc: Arc<Mutex<Option<isize>>>,
    running_arc: Arc<AtomicBool>,
    status_arc: Arc<Mutex<String>>,
) {
    running_arc.store(true, Ordering::SeqCst);
    *status_arc.lock().unwrap() = format!("Suche Prozess: {}...", target_process_name);

    let Some(pid) = find_process_id(target_process_name, &logger) else {
        *status_arc.lock().unwrap() = format!("Prozess '{}' nicht gefunden.", target_process_name);
        running_arc.store(false, Ordering::SeqCst);
        return;
    };

    *pid_arc.lock().unwrap() = Some(pid);
    *status_arc.lock().unwrap() = format!("Injiziere in PID {}...", pid);

    start_pipe_server(pid, logger.clone());
    thread::sleep(std::time::Duration::from_millis(500));

    match inject_dll(pid, dll_path) {
        Ok(handle) => {
            *status_arc.lock().unwrap() = "Erfolgreich injiziert. Überwache Prozess.".to_string();
            *handle_arc.lock().unwrap() = Some(handle);

            if let Some(path) = second_dll_path {
                if inject_dll(pid, &path).is_err() {
                    let _ = logger.send(format!(
                            r#"{{"timestamp":{},"level":"Error","event_type":"Error","details":{{"source":"Injector","message":"Fehler beim Injizieren der zweiten DLL."}}}}"#,
                            Utc::now().timestamp()
                        ));
                }
            }

            let running_arc_clone = running_arc.clone();
            let status_arc_clone = status_arc.clone();
            let pid_arc_clone = pid_arc.clone();
            let handle_arc_clone = handle_arc.clone();
            thread::spawn(move || {
                unsafe {
                    WaitForSingleObject(handle, u32::MAX);
                }
                if running_arc_clone.load(Ordering::SeqCst) {
                    *status_arc_clone.lock().unwrap() = "Prozess beendet".to_string();
                    running_arc_clone.store(false, Ordering::SeqCst);
                    *pid_arc_clone.lock().unwrap() = None;
                    *handle_arc_clone.lock().unwrap() = None;
                }
                unsafe { CloseHandle(handle) };
            });
        }
        Err(e) => {
            *status_arc.lock().unwrap() = format!("Fehler: {}", e);
            running_arc.store(false, Ordering::SeqCst);
        }
    }
}

fn start_pipe_server(pid: u32, logger: Sender<String>) {
    thread::spawn(move || unsafe {
        let pipe_name = format!(r"\\.\pipe\cs2_monitor_{}", pid);
        let wide_pipe_name = U16CString::from_str(pipe_name).unwrap();

        let mut sa: SECURITY_ATTRIBUTES = mem::zeroed();
        let mut sd: SECURITY_DESCRIPTOR = mem::zeroed();
        InitializeSecurityDescriptor(&mut sd as *mut _ as *mut _, 1);
        SetSecurityDescriptorDacl(&mut sd as *mut _ as *mut _, 1, std::ptr::null_mut(), 0);
        sa.nLength = mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
        sa.lpSecurityDescriptor = &mut sd as *mut _ as *mut _;
        sa.bInheritHandle = 0;

        let pipe_handle = CreateNamedPipeW(
            wide_pipe_name.as_ptr(),
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1,
            512,
            4096,
            0,
            &sa,
        );

        if pipe_handle == INVALID_HANDLE_VALUE {
            return;
        }

        if ConnectNamedPipe(pipe_handle, std::ptr::null_mut()) == 0 {
            let error = GetLastError();
            if error != 535 {
                CloseHandle(pipe_handle);
                return;
            }
        }

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
                    // Forward the raw JSON string
                    for line in message.lines() {
                        if !line.trim().is_empty() {
                            let _ = logger.send(line.to_string());
                        }
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        CloseHandle(pipe_handle);
    });
}

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([700.0, 500.0])
            .with_title("DLL Dynamic Analyzer"),
        ..Default::default()
    };
    eframe::run_native(
        "DLL Dynamic Analyzer",
        options,
        Box::new(|cc| Box::new(MyApp::new(cc))),
    )
}
