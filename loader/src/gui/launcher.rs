// Copyright (c) 2024 HUTAOSHUSBAND - Wallbangbros.com/FireflyProtector.xyz

use std::sync::atomic::Ordering;

use eframe::egui;
use shared::{MonitorConfig, Preset};

use crate::app::state::AppState;
use crate::core::analysis;

use crate::app::state::ActiveTab;
use eframe::egui::Ui;

pub fn render_launcher_tab(_ctx: &egui::Context, ui: &mut Ui, state: &mut AppState) {
    let mut auto_inject_clicked = false;
    let mut auto_inject_enabled = state.auto_inject_enabled.load(Ordering::SeqCst);
    ui.heading("Analysis Launcher");
    ui.add_space(6.0);

    // Two-column layout: left for target & controls, right for DLL & actions
    let avail = ui.available_width();
    let left_w = (avail * 0.62).max(300.0);
    let right_w = avail - left_w - 8.0;

    ui.horizontal(|ui| {
        ui.allocate_ui_with_layout(
            egui::vec2(left_w, ui.available_height()),
            egui::Layout::top_down(egui::Align::LEFT),
            |ui| {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.heading("Target Selection");
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label("Target Process Name:");
                        ui.text_edit_singleline(&mut state.target_process_name);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Target Process ID:");
                        ui.text_edit_singleline(&mut state.manual_injection_pid);
                    });

                    ui.separator();

                    ui.heading("Injection Controls");
                    ui.add_space(4.0);

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
                        ui.checkbox(&mut state.use_manual_map, "Use Manual Map (Broken for now 11/12/2025)");
                        ui.separator();
                        if ui.checkbox(&mut auto_inject_enabled, "Auto-Inject").clicked() {
                            auto_inject_clicked = true;
                        }
                    });

                    ui.add_space(6.0);

                    ui.label(format!("Status: {}", *state.injection_status.lock().unwrap()));
                });
            },
        );

        ui.add_space(8.0);

        ui.allocate_ui_with_layout(
            egui::vec2(right_w, ui.available_height()),
            egui::Layout::top_down(egui::Align::RIGHT),
            |ui| {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.with_layout(egui::Layout::top_down(egui::Align::Center), |ui| {
                        ui.heading("DLL & Launch");
                        ui.add_space(6.0);

                        // DLL selector
                        if let Some(path) = &state.dll_path {
                            ui.label(path.to_string_lossy());
                        } else {
                            ui.colored_label(egui::Color32::LIGHT_RED, "client.dll not found");
                        }

                        ui.add_space(6.0);

                        ui.horizontal(|ui| {
                            if ui.button("Select DLL...").clicked() {
                                if let Some(p) = rfd::FileDialog::new().add_filter("DLL", &["dll"]).pick_file() {
                                    state.dll_path = Some(p);
                                }
                            }
                            // Show path copy or reveal in explorer
                            if ui.button("Open Containing Folder").clicked() {
                                if let Some(path) = &state.dll_path {
                                    let _ = open::that(path.parent().unwrap_or_else(|| std::path::Path::new(".")).to_string_lossy().to_string());
                                }
                            }
                        });

                        ui.add_space(10.0);

                        // Large action buttons stacked vertically to use vertical space
                        ui.vertical_centered(|ui| {
                            let is_running = state.is_process_running.load(Ordering::SeqCst);
                            let can_inject = !is_running && state.dll_path.is_some();

                            if ui.add_enabled(can_inject, egui::Button::new("Inject").min_size(egui::vec2(140.0, 48.0))).clicked() {
                                let pid_to_use = state.manual_injection_pid.parse::<u32>().ok();
                                let name_to_use = if pid_to_use.is_none() { Some(state.target_process_name.clone()) } else { None };

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

                            if ui.add_enabled(is_running, egui::Button::new("Terminate").min_size(egui::vec2(140.0, 40.0))).clicked() {
                                analysis::terminate_process(state.process_handle.clone());
                            }
                        });

                        ui.add_space(8.0);

                        // Quick summary of selected preset
                        ui.separator();
                        ui.add_space(6.0);
                        ui.label(format!("Preset: {:?}", state.selected_preset));
                        ui.label(format!("Monitor Path: {}", state.monitor_config.loader_path));
                    });
                });
            },
        );
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
