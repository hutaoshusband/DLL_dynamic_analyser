
use chrono::{DateTime, Utc};
use eframe::egui;
use serde::{Deserialize, Serialize};
use std::{
    mem,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
use widestring::{U16CString, U16String};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW,
            Process32NextW, MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE,
            TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
        },
        LibraryLoader::{GetModuleHandleW, GetProcAddress},
        Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE},
        Threading::{
            CreateRemoteThread, OpenProcess, TerminateProcess, WaitForSingleObject,
            PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_SYNCHRONIZE,
            PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
        },
    },
    Storage::FileSystem::{CreateFileW, ReadFile, WriteFile, PIPE_ACCESS_DUPLEX},
};

const DLL_NAME: &str = "monitor_lib.dll";

// --- Data Structures ---

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct MonitorConfig {
    pub api_hooks_enabled: bool,
    pub iat_scan_enabled: bool,
    pub string_dump_enabled: bool,
    pub vmp_dump_enabled: bool,
    pub manual_map_scan_enabled: bool,
    pub network_hooks_enabled: bool,
    pub registry_hooks_enabled: bool,
    pub crypto_hooks_enabled: bool,
    pub log_network_data: bool,
    pub suspicion_threshold: u32,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            api_hooks_enabled: true,
            iat_scan_enabled: true,
            string_dump_enabled: false,
            vmp_dump_enabled: true,
            manual_map_scan_enabled: true,
            network_hooks_enabled: true,
            registry_hooks_enabled: true,
            crypto_hooks_enabled: true,
            log_network_data: false,
            suspicion_threshold: 10,
        }
    }
}

#[derive(serde::Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Fatal = 0, Error = 1, Success = 2, Warn = 3, Info = 4, Debug = 5, Trace = 6,
}

#[derive(serde::Serialize, Deserialize, Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: usize,
    pub virtual_size: usize,
    pub characteristics: u32,
}

#[derive(serde::Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "event_type", content = "details")]
pub enum LogEvent {
    Initialization { status: String },
    Shutdown { status: String },
    ApiHook { function_name: String, parameters: serde_json::Value, #[serde(skip_serializing_if = "Option::is_none")] stack_trace: Option<Vec<String>>, },
    AntiDebugCheck { function_name: String, parameters: serde_json::Value, #[serde(skip_serializing_if = "Option::is_none")] stack_trace: Option<Vec<String>>, },
    ProcessEnumeration { function_name: String, parameters: serde_json::Value },
    MemoryScan { status: String, result: String },
    Error { source: String, message: String },
    FileOperation { path: String, operation: String, details: String },
    VmpSectionFound { module_path: String, section_name: String },
    SectionList { sections: Vec<SectionInfo> },
    SectionDump { name: String, data: Vec<u8> },
    EntropyResult { name: String, entropy: Vec<f32> },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "command", content = "payload")]
pub enum Command {
    ListSections,
    DumpSection { name: String },
    CalculateEntropy { name: String },
}

impl PartialEq for LogEvent {
    fn eq(&self, other: &Self) -> bool {
        serde_json::to_string(self).unwrap_or_default() == serde_json::to_string(other).unwrap_or_default()
    }
}

#[derive(serde::Serialize, Deserialize, Debug)]
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

// --- App State and GUI ---

struct Handle(isize);
impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 && self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0) };
        }
    }
}

#[derive(Clone, Debug)]
struct ModuleInfo {
    name: String,
    base_address: usize,
    size: u32,
}

struct MyApp {
    target_process_name: String,
    manual_injection_pid: String,
    dll_path: Option<PathBuf>,
    log_receiver: Receiver<String>,
    log_sender: Sender<String>,
    logs: Vec<(LogEntry, usize)>,
    process_id: Arc<Mutex<Option<u32>>>,
    process_handle: Arc<Mutex<Option<isize>>>,
    pipe_handle: Arc<Mutex<Option<isize>>>,
    is_process_running: Arc<AtomicBool>,
    injection_status: Arc<Mutex<String>>,
    modules: Arc<Mutex<Vec<ModuleInfo>>>,
    selected_module_index: Option<usize>,
    sections: Arc<Mutex<Vec<SectionInfo>>>,
    selected_section_name: Option<String>,
    entropy_results: Arc<Mutex<std::collections::HashMap<String, Vec<f32>>>>,
    monitor_config: MonitorConfig,
}

impl MyApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let (log_sender, log_receiver) = mpsc::channel();
        let dll_path = std::env::current_exe().ok().and_then(|p| p.parent().map(|p| p.join(DLL_NAME))).filter(|p| p.exists());

        Self {
            target_process_name: "cs2.exe".to_owned(),
            manual_injection_pid: String::new(),
            dll_path,
            log_receiver,
            log_sender,
            logs: Vec::new(),
            process_id: Arc::new(Mutex::new(None)),
            process_handle: Arc::new(Mutex::new(None)),
            pipe_handle: Arc::new(Mutex::new(None)),
            is_process_running: Arc::new(AtomicBool::new(false)),
            injection_status: Arc::new(Mutex::new("Not Injected".to_string())),
            modules: Arc::new(Mutex::new(Vec::new())),
            selected_module_index: None,
            sections: Arc::new(Mutex::new(Vec::new())),
            selected_section_name: None,
            entropy_results: Arc::new(Mutex::new(std::collections::HashMap::new())),
            monitor_config: MonitorConfig::default(),
        }
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(log_json) = self.log_receiver.try_recv() {
            if let Ok(new_log) = serde_json::from_str::<LogEntry>(&log_json) {
                match &new_log.event {
                    LogEvent::SectionList { sections } => {
                        *self.sections.lock().unwrap() = sections.clone();
                    }
                    LogEvent::SectionDump { name, data } => {
                        if let Some(path) = rfd::FileDialog::new().set_file_name(name).save_file() {
                            if let Err(e) = std::fs::write(&path, data) {
                                // Log error to GUI
                            }
                        }
                    }
                    LogEvent::EntropyResult { name, entropy } => {
                        self.entropy_results.lock().unwrap().insert(name.clone(), entropy.clone());
                    }
                    _ => {}
                }

                if let Some((last_log, count)) = self.logs.last_mut() {
                    if *last_log == new_log { *count += 1; } else { self.logs.push((new_log, 1)); }
                } else {
                    self.logs.push((new_log, 1));
                }
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("DLL Dynamic Analyzer");
            ui.separator();

            ui.horizontal(|ui| {
                ui.label("Target Process Name:");
                ui.text_edit_singleline(&mut self.target_process_name);
            });
            ui.horizontal(|ui| {
                ui.label("Target Process ID:");
                ui.text_edit_singleline(&mut self.manual_injection_pid);
                if ui.button("Inject by PID").clicked() {
                    if let Ok(pid) = self.manual_injection_pid.parse::<u32>() {
                        start_analysis_thread(self, None, Some(pid));
                    }
                }
            });

            ui.separator();
            ui.heading("Analysis Options");
            egui::Grid::new("analysis_options_grid").num_columns(2).show(ui, |ui| {
                ui.checkbox(&mut self.monitor_config.api_hooks_enabled, "API Hooks");
                ui.checkbox(&mut self.monitor_config.iat_scan_enabled, "IAT Scans");
                ui.end_row();
                ui.checkbox(&mut self.monitor_config.string_dump_enabled, "String Dumper");
                ui.checkbox(&mut self.monitor_config.vmp_dump_enabled, "VMP Dumper");
                ui.end_row();
                ui.checkbox(&mut self.monitor_config.manual_map_scan_enabled, "Manual Map Scans");
                ui.checkbox(&mut self.monitor_config.network_hooks_enabled, "Network Hooks");
                ui.end_row();
                ui.checkbox(&mut self.monitor_config.registry_hooks_enabled, "Registry Hooks");
                ui.checkbox(&mut self.monitor_config.crypto_hooks_enabled, "Crypto Hooks");
                ui.end_row();
                ui.checkbox(&mut self.monitor_config.log_network_data, "Log Network Data Payloads");
            });
            ui.separator();

            ui.horizontal(|ui| {
                if ui.add_enabled(!self.is_process_running.load(Ordering::SeqCst) && self.dll_path.is_some(), egui::Button::new("Find Process & Inject")).clicked() {
                    start_analysis_thread(self, Some(self.target_process_name.clone()), None);
                }
                if ui.add_enabled(self.is_process_running.load(Ordering::SeqCst), egui::Button::new("Terminate Process")).clicked() {
                    if let Some(handle) = *self.process_handle.lock().unwrap() {
                        unsafe { TerminateProcess(handle, 1) };
                    }
                }
            });

            ui.separator();
            ui.heading("DLLs in Target Process");
            ui.horizontal(|ui| {
                if ui.add_enabled(self.is_process_running.load(Ordering::SeqCst), egui::Button::new("Refresh Modules")).clicked() {
                    if let Some(pid) = *self.process_id.lock().unwrap() {
                        match get_modules_for_process(pid) {
                            Ok(modules) => *self.modules.lock().unwrap() = modules,
                            Err(e) => {
                                let _ = self.log_sender.send(format!("Error getting modules: {}", e));
                            }
                        }
                    }
                }
                if ui.add_enabled(self.selected_module_index.is_some(), egui::Button::new("Dump Selected DLL")).clicked() {
                     if let (Some(handle), Some(index)) = (*self.process_handle.lock().unwrap(), self.selected_module_index) {
                        let modules = self.modules.lock().unwrap();
                        if let Some(module_info) = modules.get(index) {
                            let logger = self.log_sender.clone();
                            let module_clone = module_info.clone();
                            thread::spawn(move || {
                                dump_module_from_process(handle, &module_clone, &logger);
                            });
                        }
                    }
                }
            });

            let modules_guard = self.modules.lock().unwrap();
            let module_names: Vec<String> = modules_guard.iter().map(|m| m.name.clone()).collect();
            let selected_module_name = self.selected_module_index.and_then(|i| module_names.get(i).cloned()).unwrap_or_else(|| "No Module Selected".to_string());
            egui::ComboBox::from_label("").selected_text(selected_module_name).show_ui(ui, |ui| {
                for (i, name) in module_names.iter().enumerate() {
                    if ui.selectable_label(self.selected_module_index == Some(i), name).clicked() {
                        self.selected_module_index = Some(i);
                    }
                }
            });

            ui.separator();

            ui.collapsing("Memory Sections", |ui| {
                if ui.button("Refresh Sections").clicked() {
                    if let Some(pipe_handle) = *self.pipe_handle.lock().unwrap() {
                        let command = Command::ListSections;
                        if let Ok(command_json) = serde_json::to_string(&command) {
                            unsafe {
                                WriteFile(pipe_handle, command_json.as_ptr(), command_json.len() as u32, &mut 0, std::ptr::null_mut());
                            }
                        }
                    }
                }

                egui::ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
                    let sections = self.sections.lock().unwrap().clone();
                    for section in sections.iter() {
                        ui.horizontal(|ui| {
                            if ui.selectable_label(self.selected_section_name == Some(section.name.clone()), &section.name).clicked() {
                                self.selected_section_name = Some(section.name.clone());
                            }
                            ui.label(format!(
                                "Address: {:#X}, Size: {} bytes",
                                section.virtual_address, section.virtual_size
                            ));
                            if ui.button("Dump").clicked() {
                                if let Some(pipe_handle) = *self.pipe_handle.lock().unwrap() {
                                    let command = Command::DumpSection { name: section.name.clone() };
                                    if let Ok(command_json) = serde_json::to_string(&command) {
                                        unsafe {
                                            WriteFile(pipe_handle, command_json.as_ptr(), command_json.len() as u32, &mut 0, std::ptr::null_mut());
                                        }
                                    }
                                }
                            }
                            if ui.button("Entropy Scan").clicked() {
                                if let Some(pipe_handle) = *self.pipe_handle.lock().unwrap() {
                                    let command = Command::CalculateEntropy { name: section.name.clone() };
                                    if let Ok(command_json) = serde_json::to_string(&command) {
                                        unsafe {
                                            WriteFile(pipe_handle, command_json.as_ptr(), command_json.len() as u32, &mut 0, std::ptr::null_mut());
                                        }
                                    }
                                }
                            }
                        });
                    }
                });
            });

            ui.separator();

            ui.collapsing("Entropy Viewer", |ui| {
                if let Some(selected_section_name) = &self.selected_section_name {
                    let entropy_results = self.entropy_results.lock().unwrap();
                    if let Some(entropy) = entropy_results.get(selected_section_name) {
                        let points: egui_plot::PlotPoints = entropy.iter().enumerate().map(|(i, &y)| [i as f64, y as f64]).collect();
                        let line = egui_plot::Line::new(points);
                        egui_plot::Plot::new("entropy_plot")
                            .view_aspect(2.0)
                            .show(ui, |plot_ui| plot_ui.line(line));
                    } else {
                        ui.label("No entropy data for the selected section. Perform an entropy scan first.");
                    }
                } else {
                    ui.label("Select a section to view its entropy.");
                }
            });

            ui.separator();
            ui.label(format!("Status: {}", *self.injection_status.lock().unwrap()));
            egui::ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
                for (log, count) in &self.logs {
                    let color = match log.level {
                        LogLevel::Fatal | LogLevel::Error => egui::Color32::RED,
                        LogLevel::Success => egui::Color32::GREEN,
                        LogLevel::Warn => egui::Color32::from_rgb(255, 165, 0),
                        LogLevel::Info => egui::Color32::YELLOW,
                        _ => egui::Color32::LIGHT_BLUE,
                    };
                    let mut log_text = format!("[{}] {}", log.timestamp.format("%H:%M:%S"), format_log_event(&log.event));
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

fn format_log_event(event: &LogEvent) -> String {
    match event {
        LogEvent::Initialization { status } => status.clone(),
        LogEvent::Shutdown { status } => status.clone(),
        LogEvent::ApiHook { function_name, parameters, .. } => format!("API Hook: {} | Params: {}", function_name, parameters),
        LogEvent::AntiDebugCheck { function_name, parameters, .. } => format!("Anti-Debug: {} | Params: {}", function_name, parameters),
        LogEvent::ProcessEnumeration { function_name, parameters } => format!("Process Enum: {} | Params: {}", function_name, parameters),
        LogEvent::MemoryScan { status, result } => format!("Scan: {} -> {}", status, result),
        LogEvent::Error { source, message } => format!("ERROR [{}]: {}", source, message),
        LogEvent::FileOperation { path, operation, details } => format!("File Op: {} on {} | Details: {}", operation, path, details),
        LogEvent::VmpSectionFound { module_path, section_name } => format!("VMP Section: {} in {}", section_name, module_path),
        LogEvent::SectionList { sections } => format!("Received section list with {} entries.", sections.len()),
        LogEvent::SectionDump { name, data } => format!("Dumped section '{}' ({} bytes).", name, data.len()),
        LogEvent::EntropyResult { name, .. } => format!("Calculated entropy for section '{}'.", name),
    }
}

fn start_analysis_thread(app: &mut MyApp, name: Option<String>, pid: Option<u32>) {
    let logger = app.log_sender.clone();
    let dll_path = app.dll_path.as_ref().unwrap().clone();
    let config = app.monitor_config;
    let pid_arc = app.process_id.clone();
    let handle_arc = app.process_handle.clone();
    let pipe_arc = app.pipe_handle.clone();
    let running_arc = app.is_process_running.clone();
    let status_arc = app.injection_status.clone();

    thread::spawn(move || {
        run_analysis(logger, name.as_deref(), pid, &dll_path, config, pid_arc, handle_arc, pipe_arc, running_arc, status_arc);
    });
}

// --- Backend Logic ---

fn run_analysis(
    logger: Sender<String>,
    target_process_name: Option<&str>,
    target_pid: Option<u32>,
    dll_path: &Path,
    config: MonitorConfig,
    pid_arc: Arc<Mutex<Option<u32>>>,
    handle_arc: Arc<Mutex<Option<isize>>>,
    pipe_arc: Arc<Mutex<Option<isize>>>,
    running_arc: Arc<AtomicBool>,
    status_arc: Arc<Mutex<String>>,
) {
    running_arc.store(true, Ordering::SeqCst);

    let pid = match target_pid {
        Some(p) => Some(p),
        None => {
            let name = target_process_name.unwrap_or("");
            *status_arc.lock().unwrap() = format!("Searching for process: {}...", name);
            find_process_id(name)
        }
    };

    let Some(pid) = pid else {
        *status_arc.lock().unwrap() = "Process not found.".to_string();
        running_arc.store(false, Ordering::SeqCst);
        return;
    };

    *pid_arc.lock().unwrap() = Some(pid);
    *status_arc.lock().unwrap() = format!("Injecting into PID {}...", pid);

    match inject_dll(pid, dll_path) {
        Ok(handle) => {
            *handle_arc.lock().unwrap() = Some(handle);
            thread::sleep(Duration::from_millis(500));

            let pipe_name = format!(r"\\.\pipe\cs2_monitor_{}", pid);
            let wide_pipe_name = U16CString::from_str(&pipe_name).unwrap();
            let pipe_handle = unsafe {
                CreateFileW(wide_pipe_name.as_ptr(), PIPE_ACCESS_DUPLEX, 0, std::ptr::null(), 3, 0, 0)
            };

            if pipe_handle != INVALID_HANDLE_VALUE {
                *pipe_arc.lock().unwrap() = Some(pipe_handle);
                let config_json = serde_json::to_string(&config).unwrap();
                unsafe { WriteFile(pipe_handle, config_json.as_ptr(), config_json.len() as u32, &mut 0, std::ptr::null_mut()) };

                *status_arc.lock().unwrap() = "Configuration sent. Monitoring...".to_string();
                pipe_log_listener(pipe_handle, logger);
            } else {
                *status_arc.lock().unwrap() = format!("Failed to connect to pipe: {}", unsafe { GetLastError() });
                running_arc.store(false, Ordering::SeqCst);
                return;
            }

            let running_clone = running_arc.clone();
            let status_clone = status_arc.clone();
            thread::spawn(move || {
                unsafe { WaitForSingleObject(handle, u32::MAX) };
                if running_clone.load(Ordering::SeqCst) {
                    *status_clone.lock().unwrap() = "Process terminated.".to_string();
                    running_clone.store(false, Ordering::SeqCst);
                }
            });
        }
        Err(e) => {
            *status_arc.lock().unwrap() = format!("Injection failed: {}", e);
            running_arc.store(false, Ordering::SeqCst);
        }
    }
}

fn pipe_log_listener(pipe_handle: isize, logger: Sender<String>) {
    thread::spawn(move || {
        let mut buffer = [0u8; 4096];
        loop {
            let mut bytes_read = 0;
            let success = unsafe { ReadFile(pipe_handle, buffer.as_mut_ptr() as _, buffer.len() as u32, &mut bytes_read, std::ptr::null_mut()) } != 0;
            if success && bytes_read > 0 {
                let message = String::from_utf8_lossy(&buffer[..bytes_read as usize]);
                for line in message.lines().filter(|l| !l.trim().is_empty()) {
                    let _ = logger.send(line.to_string());
                }
            } else { break; }
        }
    });
}

fn find_process_id(target_process_name: &str) -> Option<u32> {
    if target_process_name.is_empty() { return None; }
    unsafe {
        let snapshot_handle = Handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if snapshot_handle.0 == INVALID_HANDLE_VALUE { return None; }
        let mut process_entry: PROCESSENTRY32W = mem::zeroed();
        process_entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snapshot_handle.0, &mut process_entry) != 0 {
            loop {
                let len = process_entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0);
                let process_name = U16String::from_ptr(&process_entry.szExeFile as *const _, len);
                if process_name.to_string_lossy().eq_ignore_ascii_case(target_process_name) {
                    return Some(process_entry.th32ProcessID);
                }
                if Process32NextW(snapshot_handle.0, &mut process_entry) == 0 { break; }
            }
        }
    }
    None
}

fn inject_dll(pid: u32, dll_path: &Path) -> Result<isize, String> {
    eprintln!("[DEBUG] Starting injection into PID: {}", pid);

    let process_handle = unsafe {
        eprintln!("[DEBUG] Before OpenProcess");
        let handle = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_SYNCHRONIZE,
            0,
            pid,
        );
        eprintln!("[DEBUG] After OpenProcess: handle={:?}", handle);
        handle
    };

    if process_handle == 0 {
        let err = unsafe { GetLastError() };
        eprintln!("[FATAL] OpenProcess failed with error: {}", err);
        return Err(format!("OpenProcess failed: {}", err));
    }

    let dll_path_wide = U16CString::from_os_str(dll_path).unwrap();
    let dll_path_len_bytes = (dll_path_wide.len() + 1) * 2;

    let remote_buffer = unsafe {
        eprintln!("[DEBUG] Before VirtualAllocEx");
        let buffer = VirtualAllocEx(
            process_handle,
            std::ptr::null(),
            dll_path_len_bytes,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        eprintln!("[DEBUG] After VirtualAllocEx: buffer={:?}", buffer);
        buffer
    };

    if remote_buffer.is_null() {
        let err = unsafe { GetLastError() };
        eprintln!("[FATAL] VirtualAllocEx failed with error: {}", err);
        unsafe { CloseHandle(process_handle) };
        return Err(format!("VirtualAllocEx failed: {}", err));
    }

    let mut bytes_written = 0;
    let write_success = unsafe {
        eprintln!("[DEBUG] Before WriteProcessMemory");
        let success = WriteProcessMemory(
            process_handle,
            remote_buffer,
            dll_path_wide.as_ptr() as _,
            dll_path_len_bytes,
            &mut bytes_written,
        );
        eprintln!("[DEBUG] After WriteProcessMemory: success={}, bytes_written={}", success, bytes_written);
        success
    };

    if write_success == 0 {
        let err = unsafe { GetLastError() };
        eprintln!("[FATAL] WriteProcessMemory failed with error: {}", err);
        // TODO: Free remote_buffer
        unsafe { CloseHandle(process_handle) };
        return Err(format!("WriteProcessMemory failed: {}", err));
    }

    let kernel32_name = U16CString::from_str("kernel32.dll").unwrap();
    let load_library_addr = unsafe {
        eprintln!("[DEBUG] Before GetProcAddress for LoadLibraryW");
        let addr = GetProcAddress(GetModuleHandleW(kernel32_name.as_ptr()), b"LoadLibraryW\0".as_ptr());
        eprintln!("[DEBUG] After GetProcAddress: addr={:?}", addr);
        addr
    };

    if load_library_addr.is_none() {
        let err = unsafe { GetLastError() };
        eprintln!("[FATAL] GetProcAddress for LoadLibraryW failed with error: {}", err);
        // TODO: Free remote_buffer
        unsafe { CloseHandle(process_handle) };
        return Err("Could not find LoadLibraryW".into());
    }

    let thread_handle = unsafe {
        eprintln!("[DEBUG] Before CreateRemoteThread");
        let handle = CreateRemoteThread(
            process_handle,
            std::ptr::null(),
            0,
            Some(std::mem::transmute(load_library_addr)),
            remote_buffer as _,
            0,
            std::ptr::null_mut(),
        );
        eprintln!("[DEBUG] After CreateRemoteThread: handle={:?}", handle);
        handle
    };

    if thread_handle == 0 {
        let err = unsafe { GetLastError() };
        eprintln!("[FATAL] CreateRemoteThread failed with error: {}", err);
        // TODO: Free remote_buffer
        unsafe { CloseHandle(process_handle) };
        return Err(format!("CreateRemoteThread failed: {}", err));
    }

    eprintln!("[DEBUG] Injection thread created successfully. Closing remote thread handle.");
    unsafe { CloseHandle(thread_handle) };
    eprintln!("[DEBUG] Injection seems successful. Returning process handle.");
    Ok(process_handle)
}

fn get_modules_for_process(pid: u32) -> Result<Vec<ModuleInfo>, String> {
    unsafe {
        let snapshot_handle = Handle(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid));
        if snapshot_handle.0 == INVALID_HANDLE_VALUE {
            return Err(format!("CreateToolhelp32Snapshot (Module) failed: {}", GetLastError()));
        }

        let mut module_entry: MODULEENTRY32W = mem::zeroed();
        module_entry.dwSize = mem::size_of::<MODULEENTRY32W>() as u32;
        let mut modules = Vec::new();

        if Module32FirstW(snapshot_handle.0, &mut module_entry) != 0 {
            loop {
                let len = module_entry.szModule.iter().position(|&c| c == 0).unwrap_or(0);
                let module_name = U16String::from_ptr(module_entry.szModule.as_ptr(), len).to_string_lossy().to_owned();

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

fn dump_module_from_process(process_handle: isize, module: &ModuleInfo, logger: &Sender<String>) {
    let file_path = rfd::FileDialog::new().set_file_name(&module.name).add_filter("DLL", &["dll"]).save_file();
    if let Some(target_path) = file_path {
        let mut buffer = vec![0u8; module.size as usize];
        if unsafe { ReadProcessMemory(process_handle, module.base_address as _, buffer.as_mut_ptr() as _, buffer.len(), &mut 0) } != 0 {
            if let Err(e) = std::fs::write(&target_path, &buffer) {
                let _ = logger.send(format!("Error writing dump file: {}", e));
            } else {
                let _ = logger.send(format!("Successfully dumped {} to {}", module.name, target_path.display()));
            }
        } else {
            let _ = logger.send(format!("Failed to read module {} from memory. Error: {}", module.name, unsafe { GetLastError() }));
        }
    }
}

fn cli_run(pid: u32) -> Result<(), String> {
    println!("CLI mode: Attempting to inject into PID {}", pid);

    let dll_path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.join(DLL_NAME)))
        .filter(|p| p.exists());

    let Some(dll_path) = dll_path else {
        return Err("monitor_lib.dll not found in the same directory as the executable.".to_string());
    };

    println!("Found DLL at: {}", dll_path.display());

    match inject_dll(pid, &dll_path) {
        Ok(handle) => {
            println!("Injection successful. Process handle: {:?}", handle);
            // In CLI mode, we might just exit, or wait for the process to terminate.
            // For now, we'll just exit.
            unsafe { CloseHandle(handle) };
            Ok(())
        }
        Err(e) => {
            Err(format!("Injection failed: {}", e))
        }
    }
}

fn main() -> Result<(), eframe::Error> {
    let args: Vec<String> = std::env::args().collect();
    if let Some(pid_index) = args.iter().position(|arg| arg == "--pid") {
        if let Some(pid_str) = args.get(pid_index + 1) {
            if let Ok(pid) = pid_str.parse::<u32>() {
                // Allocate a console for debug output in CLI mode
                unsafe { windows_sys::Win32::System::Console::AllocConsole() };
                match cli_run(pid) {
                    Ok(_) => println!("CLI operation completed successfully."),
                    Err(e) => eprintln!("CLI operation failed: {}", e),
                }
                // Give time for user to see output
                thread::sleep(Duration::from_secs(5));
                return Ok(());
            }
        }
    }

    // Default to GUI mode if no valid CLI args are provided
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([700.0, 900.0]),
        ..Default::default()
    };
    eframe::run_native("DLL Dynamic Analyzer", options, Box::new(|cc| {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        Box::new(MyApp::new(cc))
    }))
}