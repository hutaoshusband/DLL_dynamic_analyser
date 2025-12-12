// Copyright (c) 2024 HUTAOSHUSBAND - Wallbangbros.com/FireflyProtector.xyz

use eframe::egui::{self, Ui};

use crate::app::state::AppState;
use shared::logging::{LogEvent, LogLevel};

use egui::{Align, Color32, Frame, Layout};

pub fn render_log_tab(ui: &mut Ui, state: &mut AppState) {
    ui.with_layout(Layout::top_down(Align::Center), |ui| {
        let terminal_frame = Frame::central_panel(&ui.style())
            .fill(Color32::from_rgb(10, 10, 15)) // Darker, terminal-like background
            .inner_margin(egui::Margin::same(10.0));

        terminal_frame.show(ui, |ui| {
            ui.set_max_width(ui.available_width() * 0.9); // Use 90% of available width
            ui.set_max_height(ui.available_height() * 0.95); // Use 95% of available height

            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for (log, count) in &state.logs {
                        let color = match log.level {
                            LogLevel::Fatal | LogLevel::Error => Color32::from_rgb(243, 139, 168), // Red
                            LogLevel::Success => Color32::from_rgb(166, 227, 161), // Green
                            LogLevel::Warn => Color32::from_rgb(250, 179, 135),    // Orange
                            LogLevel::Info => Color32::from_rgb(137, 180, 250),     // Blue
                            LogLevel::Debug => Color32::from_rgb(198, 160, 246),    // Mauve
                            LogLevel::Trace => Color32::from_rgb(127, 132, 156),    // Faint
                        };
                        let mut log_text = format!(
                            "[{}] {}",
                            log.timestamp.format("%H:%M:%S"),
                            format_log_event(&log.event)
                        );
                        if *count > 1 {
                            log_text = format!("({}x) {}", count, log_text);
                        }
                        
                        ui.horizontal(|ui| {
                            if log.origin_suspicious {
                                ui.colored_label(Color32::from_rgb(255, 0, 0), "💀");
                            }
                            ui.colored_label(color, log_text);
                        });
                    }
                });
        });
    });
}

fn format_log_event(event: &LogEvent) -> String {
    match event {
        LogEvent::Message(msg) => msg.clone(),
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
        LogEvent::MemoryScan { status, result } => {
            format!("Scan: {} -> {}", status, result)
        }
        LogEvent::Error { source, message } => {
            format!("ERROR [{}]: {}", source, message)
        }
        LogEvent::FileOperation {
            path,
            operation,
            details,
        } => format!("File Op: {} on {} | Details: {}", operation, path, details),
        LogEvent::VmpSectionFound {
            module_path,
            section_name,
        } => format!("VMP Section: {} in {}", section_name, module_path),
        LogEvent::SectionList { sections } => {
            format!("Received section list with {} entries.", sections.len())
        }
        LogEvent::SectionDump { name, data } => {
            format!("Dumped section '{}' ({} bytes).", name, data.len())
        }
        LogEvent::EntropyResult { name, .. } => {
            format!("Calculated entropy for section '{}'.", name)
        }
        LogEvent::ModuleDump { module_name, data } => {
            format!("Dumped module '{}' ({} bytes).", module_name, data.len())
        }
        LogEvent::VmpTrace { message, details } => {
            format!("VMP Trace: {} | Details: {}", message, details)
        }
        LogEvent::StaticAnalysis { finding, details } => {
            format!("Static Analysis: {} | Details: {}", finding, details)
        }
        LogEvent::StringDump { address, value, .. } => {
            format!("String at {:#x}: {}", address, value)
        }
        LogEvent::UnpackerActivity { source_address, finding, details } => {
            format!("Unpacker activity at {:#x}: {} | Details: {}", source_address, finding, details)
        }
        LogEvent::FullEntropyResult { module_name, entropy } => {
            let avg = if !entropy.is_empty() {
                entropy.iter().sum::<f32>() / entropy.len() as f32
            } else { 0.0 };
            format!("Full entropy for '{}': avg {:.2} ({} chunks)", module_name, avg, entropy.len())
        }
        LogEvent::YaraMatch { rule_name, address, region_size, .. } => {
            format!("🔍 YARA Match: {} @ {:#x} (size: {:#x})", rule_name, address, region_size)
        }
    }
}
