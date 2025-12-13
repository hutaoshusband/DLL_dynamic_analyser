// Copyright (c) 2024 HUTAOSHUSBAND - Wallbangbros.com/FireflyProtector.xyz

use std::sync::atomic::Ordering;

use eframe::egui;
use shared::{MonitorConfig, Preset};

use crate::app::state::AppState;
use crate::core::{analysis, injection};

use crate::app::state::ActiveTab;
use eframe::egui::Ui;

pub fn render_launcher_tab(_ctx: &egui::Context, ui: &mut Ui, state: &mut AppState) {
    let mut auto_inject_clicked = false;
    let mut auto_inject_enabled = state.auto_inject_enabled.load(Ordering::SeqCst);
    const BOX_SPACING: f32 = 12.0;
    let available = ui.available_width();
    let column_width = ((available - BOX_SPACING) * 0.5).max(240.0);
    let top_height = 220.0;
    let bottom_height = 160.0;

    fn render_panel<F>(ui: &mut Ui, title: &str, size: egui::Vec2, body: F)
    where
        F: FnOnce(&mut Ui),
    {
        let frame = egui::Frame {
            fill: ui.visuals().panel_fill,
            stroke: egui::Stroke::new(1.2, ui.visuals().widgets.noninteractive.bg_stroke.color),
            inner_margin: egui::Margin::same(14.0),
            rounding: ui.visuals().widgets.noninteractive.rounding,
            ..Default::default()
        };

        ui.allocate_ui_with_layout(size, egui::Layout::top_down(egui::Align::Center), |ui| {
            frame.show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.heading(title);
                });
                ui.add_space(8.0);
                body(ui);
            });
        });
    }

    ui.horizontal(|ui| {
        render_panel(ui, "Analysis Launcher", egui::vec2(column_width, top_height), |ui| {
            ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                ui.horizontal(|ui| {
                    ui.label("Target Process Name:");
                    ui.text_edit_singleline(&mut state.target_process_name);
                });
                ui.horizontal(|ui| {
                    ui.label("Target Process ID:");
                    ui.text_edit_singleline(&mut state.manual_injection_pid);
                });
                ui.separator();

                ui.horizontal(|ui| {
                    ui.label("Monitoring Preset:");
                    let mut preset_changed = false;
                    let selected_preset_text = format!("{:?}", state.selected_preset);
                    egui::ComboBox::from_id_source("preset_selector")
                        .selected_text(selected_preset_text)
                        .show_ui(ui, |ui| {
                            preset_changed |= ui
                                .selectable_value(&mut state.selected_preset, Preset::Stealth, "Stealth")
                                .changed();
                            preset_changed |= ui
                                .selectable_value(&mut state.selected_preset, Preset::Balanced, "Balanced")
                                .changed();
                            preset_changed |= ui
                                .selectable_value(&mut state.selected_preset, Preset::Aggressive, "Aggressive")
                                .changed();
                        });

                    if preset_changed {
                        state.monitor_config = MonitorConfig::from_preset(state.selected_preset);
                    }
                });

                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.checkbox(&mut state.use_manual_map, "Use Manual Map (Broken)").clicked() {}
                    if ui.checkbox(&mut auto_inject_enabled, "Auto-Inject").clicked() {
                        auto_inject_clicked = true;
                    }
                });

                ui.add_space(6.0);
                ui.vertical_centered(|ui| {
                    ui.label(format!("Status: {}", *state.injection_status.lock().unwrap()));
                });
            });
        });

        ui.add_space(BOX_SPACING);

        render_panel(ui, "Inject", egui::vec2(column_width, top_height), |ui| {
            ui.vertical_centered(|ui| {
                if let Some(path) = &state.dll_path {
                    ui.label(format!(
                        "Main DLL: {}",
                        path.file_name().and_then(|n| n.to_str()).unwrap_or("client.dll")
                    ));
                    ui.small(format!("Path: {}", path.to_string_lossy()));
                } else {
                    ui.colored_label(egui::Color32::LIGHT_RED, "client.dll not found");
                }
            });

            ui.add_space(12.0);
            ui.vertical_centered(|ui| {
                let is_running = state.is_process_running.load(Ordering::SeqCst);
                let can_inject = !is_running && state.dll_path.is_some();

                if ui
                    .add_enabled(
                        can_inject,
                        egui::Button::new("Inject main DLL").min_size(egui::vec2(140.0, 48.0)),
                    )
                    .clicked()
                {
                    let pid_to_use = state.manual_injection_pid.parse::<u32>().ok();
                    let name_to_use = if pid_to_use.is_none() {
                        Some(state.target_process_name.clone())
                    } else {
                        None
                    };

                    if let Some(dll_path) = state.dll_path.clone() {
                        analysis::start_analysis_thread(
                            state.log_sender.clone(),
                            name_to_use,
                            pid_to_use,
                            &dll_path,
                            state.monitor_config.clone(),
                            state.process_id.clone(),
                            state.process_handle.clone(),
                            state.commands_pipe_handle.clone(),
                            state.logs_pipe_handle.clone(),
                            state.is_process_running.clone(),
                            state.injection_status.clone(),
                            state.use_manual_map,
                        );
                        state.active_tab = ActiveTab::Logs;
                    }
                }

                ui.add_space(6.0);
                if ui
                    .add_enabled(is_running, egui::Button::new("Terminate").min_size(egui::vec2(140.0, 40.0)))
                    .clicked()
                {
                    analysis::terminate_process(state.process_handle.clone());
                }
            });
        });
    });

    ui.add_space(BOX_SPACING);

    ui.horizontal(|ui| {
        render_panel(ui, "Actions", egui::vec2(column_width, bottom_height), |ui| {
            ui.vertical_centered(|ui| {
                ui.horizontal(|ui| {
                    if ui.button("Open Logs").clicked() {
                        state.previous_tab = Some(state.active_tab);
                        state.active_tab = ActiveTab::Logs;
                    }
                    if ui.button("Clear Logs").clicked() {
                        state.logs.clear();
                    }
                });
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Reveal main DLL").clicked() {
                        if let Some(path) = &state.dll_path {
                            let _ = open::that(
                                path.parent()
                                    .unwrap_or_else(|| std::path::Path::new("."))
                                    .to_string_lossy()
                                    .to_string(),
                            );
                        }
                    }
                    if ui.button("Show Process PID").clicked() {
                        let pid = *state.process_id.lock().unwrap();
                        if let Some(pid) = pid {
                            *state.injection_status.lock().unwrap() = format!("Process PID: {}", pid);
                        } else {
                            *state.injection_status.lock().unwrap() = "No process".to_string();
                        }
                    }
                });
            });
        });

        ui.add_space(BOX_SPACING);

        render_panel(ui, "Inject a second DLL", egui::vec2(column_width, bottom_height), |ui| {
            ui.vertical_centered(|ui| {
                if let Some(path) = &state.second_dll_path {
                    ui.label(format!(
                        "Selected: {}",
                        path.file_name().and_then(|n| n.to_str()).unwrap_or(""),
                    ));
                } else {
                    ui.label("No DLL selected");
                }
            });

            ui.add_space(6.0);
            ui.vertical_centered(|ui| {
                ui.horizontal(|ui| {
                    if ui.button("Select DLL...").clicked() {
                        if let Some(p) = rfd::FileDialog::new().add_filter("DLL", &["dll"]).pick_file() {
                            state.second_dll_path = Some(p);
                        }
                    }
                    let is_running = state.is_process_running.load(Ordering::SeqCst);
                    if ui
                        .add_enabled(is_running && state.second_dll_path.is_some(), egui::Button::new("Inject Second DLL"))
                        .clicked()
                    {
                        if let Some(pid) = *state.process_id.lock().unwrap() {
                            if let Some(dll_path) = state.second_dll_path.clone() {
                                let res = if state.use_manual_map {
                                    injection::manual_map_inject(pid, &dll_path)
                                } else {
                                    injection::inject_dll(pid, &dll_path)
                                };

                                match res {
                                    Ok(_) => {
                                        *state.injection_status.lock().unwrap() = "Second DLL injected".to_string();
                                    }
                                    Err(e) => {
                                        *state.injection_status.lock().unwrap() = format!(
                                            "Inject failed: {}",
                                            e,
                                        );
                                    }
                                }
                            }
                        } else {
                            *state.injection_status.lock().unwrap() = "No running process to inject into".to_string();
                        }
                    }
                });
            });
        });
    });

    if auto_inject_clicked {
        state
            .auto_inject_enabled
            .store(auto_inject_enabled, Ordering::SeqCst);
        if auto_inject_enabled {
            analysis::start_auto_inject_thread(state);
        }
    }
}
