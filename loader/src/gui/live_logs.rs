use eframe::egui;

use crate::app::state::{AppState, LogLevel};

pub fn render_log_window(ctx: &egui::Context, state: &mut AppState) {
    if !state.windows.log_window_open {
        return;
    }

    egui::Window::new("Live Logs")
        .open(&mut state.windows.log_window_open)
        .show(ctx, |ui| {
            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for (log, count) in &state.logs {
                        let color = match log.level {
                            LogLevel::Fatal | LogLevel::Error => egui::Color32::RED,
                            LogLevel::Success => egui::Color32::GREEN,
                            LogLevel::Warn => egui::Color32::from_rgb(255, 165, 0),
                            LogLevel::Info => egui::Color32::YELLOW,
                            _ => egui::Color32::LIGHT_BLUE,
                        };
                        let mut log_text = format!(
                            "[{}] {}",
                            log.timestamp.format("%H:%M:%S"),
                            format_log_event(&log.event)
                        );
                        if *count > 1 {
                            log_text = format!("({}x) {}", count, log_text);
                        }
                        ui.colored_label(color, log_text);
                    }
                });
        });
}

fn format_log_event(event: &crate::app::state::LogEvent) -> String {
    match event {
        crate::app::state::LogEvent::Message(msg) => msg.clone(),
        crate::app::state::LogEvent::Initialization { status } => status.clone(),
        crate::app::state::LogEvent::Shutdown { status } => status.clone(),
        crate::app::state::LogEvent::ApiHook {
            function_name,
            parameters,
            ..
        } => format!("API Hook: {} | Params: {}", function_name, parameters),
        crate::app::state::LogEvent::AntiDebugCheck {
            function_name,
            parameters,
            ..
        } => format!("Anti-Debug: {} | Params: {}", function_name, parameters),
        crate::app::state::LogEvent::ProcessEnumeration {
            function_name,
            parameters,
        } => format!("Process Enum: {} | Params: {}", function_name, parameters),
        crate::app::state::LogEvent::MemoryScan { status, result } => {
            format!("Scan: {} -> {}", status, result)
        }
        crate::app::state::LogEvent::Error { source, message } => {
            format!("ERROR [{}]: {}", source, message)
        }
        crate::app::state::LogEvent::FileOperation {
            path,
            operation,
            details,
        } => format!("File Op: {} on {} | Details: {}", operation, path, details),
        crate::app::state::LogEvent::VmpSectionFound {
            module_path,
            section_name,
        } => format!("VMP Section: {} in {}", section_name, module_path),
        crate::app::state::LogEvent::SectionList { sections } => {
            format!("Received section list with {} entries.", sections.len())
        }
        crate::app::state::LogEvent::SectionDump { name, data } => {
            format!("Dumped section '{}' ({} bytes).", name, data.len())
        }
        crate::app::state::LogEvent::EntropyResult { name, .. } => {
            format!("Calculated entropy for section '{}'.", name)
        }
    }
}