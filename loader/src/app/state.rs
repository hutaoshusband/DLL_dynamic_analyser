use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        atomic::AtomicBool,
        mpsc::Sender,
        Arc, Mutex,
    },
};

pub const DLL_NAME: &str = "monitor_lib.dll";

// --- Data Structures ---

use shared::MonitorConfig;

#[derive(serde::Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Fatal = 0,
    Error = 1,
    Success = 2,
    Warn = 3,
    Info = 4,
    Debug = 5,
    Trace = 6,
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
    FileOperation {
        path: String,
        operation: String,
        details: String,
    },
    VmpSectionFound {
        module_path: String,
        section_name: String,
    },
    SectionList {
        sections: Vec<SectionInfo>,
    },
    SectionDump {
        name: String,
        data: Vec<u8>,
    },
    EntropyResult {
        name: String,
        entropy: Vec<f32>,
    },
}

impl PartialEq for LogEvent {
    fn eq(&self, other: &Self) -> bool {
        serde_json::to_string(self).unwrap_or_default()
            == serde_json::to_string(other).unwrap_or_default()
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

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct ModuleInfo {
    pub name: String,
    pub base_address: usize,
    pub size: u32,
}

pub struct AppState {
    pub target_process_name: String,
    pub manual_injection_pid: String,
    pub dll_path: Option<PathBuf>,
    pub log_sender: Sender<String>,
    pub logs: Vec<(LogEntry, usize)>,
    pub process_id: Arc<Mutex<Option<u32>>>,
    pub process_handle: Arc<Mutex<Option<isize>>>,
    pub pipe_handle: Arc<Mutex<Option<isize>>>,
    pub is_process_running: Arc<AtomicBool>,
    pub injection_status: Arc<Mutex<String>>,
    pub modules: Arc<Mutex<Vec<ModuleInfo>>>,
    pub selected_module_index: Option<usize>,
    pub sections: Arc<Mutex<Vec<SectionInfo>>>,
    pub selected_section_name: Option<String>,
    pub entropy_results: Arc<Mutex<HashMap<String, Vec<f32>>>>,
    pub monitor_config: MonitorConfig,
    pub windows: AppWindows,
}

pub struct AppWindows {
    pub log_window_open: bool,
    pub memory_analysis_window_open: bool,
    pub entropy_viewer_window_open: bool,
    pub hooking_control_window_open: bool,
    pub network_activity_window_open: bool,
    pub launcher_window_open: bool,
}

impl Default for AppWindows {
    fn default() -> Self {
        Self {
            log_window_open: true,
            memory_analysis_window_open: true,
            entropy_viewer_window_open: false,
            hooking_control_window_open: true,
            network_activity_window_open: false,
            launcher_window_open: true,
        }
    }
}

impl AppState {
    pub fn new(log_sender: Sender<String>) -> Self {
        let dll_path = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.join(DLL_NAME)))
            .filter(|p| p.exists());

        Self {
            target_process_name: "cs2.exe".to_owned(),
            manual_injection_pid: String::new(),
            dll_path,
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
            entropy_results: Arc::new(Mutex::new(HashMap::new())),
            monitor_config: MonitorConfig::default(),
            windows: AppWindows::default(),
        }
    }

    pub fn handle_log(&mut self, log_json: &str) {
        if let Ok(new_log) = serde_json::from_str::<LogEntry>(log_json) {
            match &new_log.event {
                LogEvent::SectionList { sections } => {
                    *self.sections.lock().unwrap() = sections.clone();
                }
                LogEvent::SectionDump { name, data } => {
                    if let Some(path) = rfd::FileDialog::new().set_file_name(name).save_file() {
                        if let Err(_e) = std::fs::write(&path, data) {
                            // Log error to GUI
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
}