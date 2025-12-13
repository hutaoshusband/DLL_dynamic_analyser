// Copyright (c) 2024 HUTAOSHUSBAND - Wallbangbros.com/FireflyProtector.xyz

use eframe::egui::{self, Color32, Ui};
use shared::logging::{LogEntry, LogEvent, LogLevel};

use crate::app::state::AppState;

use egui::{Align, Frame, Layout};

pub fn render_network_activity_tab(ui: &mut Ui, state: &mut AppState) {
    ui.with_layout(Layout::top_down(Align::Center), |ui| {
        let terminal_frame = Frame::central_panel(&ui.style())
            .fill(Color32::from_rgb(10, 10, 15)) // Darker, terminal-like background
            .inner_margin(egui::Margin::same(10.0));

        terminal_frame.show(ui, |ui| {
            ui.set_max_width(ui.available_width() * 0.9);
            ui.set_max_height(ui.available_height() * 0.95);

            let network_events = [
                "connect",
                "HttpSendRequestW",
                "GetAddrInfoW",
                "WSASend",
                "send",
                "InternetOpenW",
                "InternetConnectW",
                "HttpOpenRequestW",
                "InternetReadFile",
                "DnsQuery_A",
                "DnsQuery_W",
            ];

            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for (log_entry, count) in &state.logs {
                        if let LogEvent::ApiHook { function_name, .. } = &log_entry.event {
                            if network_events.contains(&function_name.as_str()) {
                                render_log_entry(ui, log_entry, *count);
                            }
                        }
                    }
                });
        });
    });
}

fn render_log_entry(ui: &mut Ui, log_entry: &LogEntry, count: usize) {
    let (color, level_str) = get_level_display(log_entry.level);
    let timestamp = log_entry.timestamp.format("%H:%M:%S%.3f").to_string();

    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new(format!("[{}]", timestamp))
                .monospace()
                .color(Color32::GRAY),
        );
        ui.label(egui::RichText::new(level_str).monospace().color(color));

        if let LogEvent::ApiHook {
            function_name,
            parameters,
            ..
        } = &log_entry.event
        {
            ui.label(egui::RichText::new(function_name).monospace().strong());

            if let Some(params_obj) = parameters.as_object() {
                let mut param_strings = Vec::new();
                for (key, value) in params_obj {
                    param_strings.push(format!(
                        "{}: {}",
                        key,
                        value.to_string().trim_matches('\"')
                    ));
                }
                ui.label(egui::RichText::new(param_strings.join(", ")).monospace());
            }
        }

        if count > 1 {
            ui.label(egui::RichText::new(format!("(x{})", count)).color(Color32::GOLD));
        }
    });
}

fn get_level_display(level: LogLevel) -> (Color32, &'static str) {
    match level {
        LogLevel::Fatal => (Color32::from_rgb(255, 0, 0), "FATAL"),
        LogLevel::Error => (Color32::from_rgb(255, 80, 80), "ERROR"),
        LogLevel::Success => (Color32::from_rgb(0, 255, 0), "SUCCESS"),
        LogLevel::Warn => (Color32::from_rgb(255, 255, 0), "WARN "),
        LogLevel::Info => (Color32::from_rgb(173, 216, 230), "INFO "),
        LogLevel::Debug => (Color32::from_rgb(128, 128, 128), "DEBUG"),
        LogLevel::Trace => (Color32::from_rgb(211, 211, 211), "TRACE"),
    }
}
