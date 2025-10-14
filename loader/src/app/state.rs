use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{atomic::AtomicBool, mpsc::Sender, Arc, Mutex},
    thread::JoinHandle,
};
use shared::{
    logging::{LogEntry, LogEvent, LogLevel, SectionInfo},
    MonitorConfig, Preset,
};
pub const DLL_NAME: &str = "client.dll";

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct ModuleInfo {
    pub name: String,
    pub base_address: usize,
    pub size: u32,
}

// Represents the currently active main tab in the GUI.
#[derive(PartialEq, Clone, Copy)]
pub enum ActiveTab {
    Launcher,
    Logs,
    MemoryAnalysis,
    Hooking,
    Network,
}

pub struct AppState {
    pub target_process_name: String,
    pub manual_injection_pid: String,
    pub dll_path: Option<PathBuf>,
    pub log_sender: Sender<String>,
    pub logs: Vec<(LogEntry, usize)>,
    pub process_id: Arc<Mutex<Option<u32>>>,
    pub process_handle: Arc<Mutex<Option<isize>>>,
    pub cmd_pipe_handle: Arc<Mutex<Option<isize>>>,
    pub log_pipe_handle: Arc<Mutex<Option<isize>>>,
    pub is_process_running: Arc<AtomicBool>,
    pub injection_status: Arc<Mutex<String>>,
    pub modules: Arc<Mutex<Vec<ModuleInfo>>>,
    pub selected_module_index: Option<usize>,
    pub sections: Arc<Mutex<Vec<SectionInfo>>>,
    pub selected_section_name: Option<String>,
    pub entropy_results: Arc<Mutex<HashMap<String, Vec<f32>>>>,
    pub selected_preset: Preset,
    pub monitor_config: MonitorConfig,
    pub active_tab: ActiveTab,
    pub auto_inject_enabled: Arc<AtomicBool>,
    pub auto_inject_thread: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl AppState {
    pub fn new(log_sender: Sender<String>) -> Self {
        let dll_path = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.join(DLL_NAME)))
            .filter(|p| p.exists());

        let default_preset = Preset::default();

        Self {
            target_process_name: "cs2.exe".to_owned(),
            manual_injection_pid: String::new(),
            dll_path,
            log_sender,
            logs: Vec::new(),
            process_id: Arc::new(Mutex::new(None)),
            process_handle: Arc::new(Mutex::new(None)),
            cmd_pipe_handle: Arc::new(Mutex::new(None)),
            log_pipe_handle: Arc::new(Mutex::new(None)),
            is_process_running: Arc::new(AtomicBool::new(false)),
            injection_status: Arc::new(Mutex::new("Not Injected".to_string())),
            modules: Arc::new(Mutex::new(Vec::new())),
            selected_module_index: None,
            sections: Arc::new(Mutex::new(Vec::new())),
            selected_section_name: None,
            entropy_results: Arc::new(Mutex::new(HashMap::new())),
            selected_preset: default_preset,
            monitor_config: MonitorConfig::from_preset(default_preset),
            active_tab: ActiveTab::Launcher,
            auto_inject_enabled: Arc::new(AtomicBool::new(false)),
            auto_inject_thread: Arc::new(Mutex::new(None)),
        }
    }

    pub fn handle_log(&mut self, log_json: &str) {
        match serde_json::from_str::<LogEntry>(log_json) {
            Ok(new_log) => {
                match &new_log.event {
                    LogEvent::SectionList { sections } => {
                        *self.sections.lock().unwrap() = sections.clone();
                    }
                    LogEvent::SectionDump { name, data } => {
                        if let Some(path) = rfd::FileDialog::new().set_file_name(name).save_file() {
                            if let Err(e) = std::fs::write(&path, data) {
                                self.add_log_entry(LogEntry::new_from_loader(
                                    LogLevel::Error,
                                    LogEvent::Error {
                                        source: "GUI".to_string(),
                                        message: format!("Failed to save dump: {}", e),
                                    },
                                ));
                            }
                        }
                    }
                    LogEvent::EntropyResult { name, entropy } => {
                        self.entropy_results
                            .lock()
                            .unwrap()
                            .insert(name.clone(), entropy.clone());
                    }
                    _ => {}
                }

                self.add_log_entry(new_log);
            }
            Err(e) => {
                let error_log = LogEntry::new_from_loader(
                    LogLevel::Error,
                    LogEvent::Error {
                        source: "Log Deserialization".to_string(),
                        message: format!("Failed to parse log: {}. Original: '{}'", e, log_json),
                    },
                );
                self.add_log_entry(error_log);
            }
        }
    }

    // Helper function to add a log entry and handle deduplication
    fn add_log_entry(&mut self, new_log: LogEntry) {
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
}