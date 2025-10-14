use std::sync::atomic::Ordering;

use eframe::egui;
use shared::{MonitorConfig, Preset};

use crate::app::state::AppState;
use crate::core::analysis;

use crate::app::state::ActiveTab;
use eframe::egui::{Ui};

pub fn render_launcher_tab(_ctx: &egui::Context, ui: &mut Ui, state: &mut AppState) {
    let mut auto_inject_clicked = false;
    let mut auto_inject_enabled = state.auto_inject_enabled.load(Ordering::SeqCst);

    ui.heading("Analysis Launcher");
    ui.separator();

            // --- Target Selection ---
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.heading("Target Selection");
                ui.horizontal(|ui| {
                    ui.label("Target Process Name:");
                    ui.text_edit_singleline(&mut state.target_process_name);
                });
                ui.horizontal(|ui| {
                    ui.label("Target Process ID:");
                    ui.text_edit_singleline(&mut state.manual_injection_pid);
                });
            });

            // --- Injection Controls ---
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.heading("Injection Controls");

                // Preset selection
                ui.horizontal(|ui| {
                    ui.label("Monitoring Preset:");
                    let mut preset_changed = false;
                    let selected_preset_text = format!("{:?}", state.selected_preset);
                    egui::ComboBox::from_id_source("preset_selector")
                        .selected_text(selected_preset_text)
                        .show_ui(ui, |ui| {
                            preset_changed |= ui.selectable_value(&mut state.selected_preset, Preset::Stealth, "Stealth").changed();
                            preset_changed |= ui.selectable_value(&mut state.selected_preset, Preset::Balanced, "Balanced").changed();
                            preset_changed |= ui.selectable_value(&mut state.selected_preset, Preset::Aggressive, "Aggressive").changed();
                        });

                    if preset_changed {
                        state.monitor_config = MonitorConfig::from_preset(state.selected_preset);
                    }
                });

                ui.separator();

                // Action buttons
                ui.horizontal(|ui| {
                    let is_running = state.is_process_running.load(Ordering::SeqCst);
                    let can_inject = !is_running && state.dll_path.is_some();

                    if ui.add_enabled(can_inject, egui::Button::new("Inject")).clicked() {
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
                                state.pipe_handle.clone(),
                                state.is_process_running.clone(),
                                state.injection_status.clone(),
                            );
                            state.active_tab = ActiveTab::Logs;
                        }
                    }

                    if ui.add_enabled(is_running, egui::Button::new("Terminate")).clicked() {
                        analysis::terminate_process(state.process_handle.clone());
                    }

                    if ui.checkbox(&mut auto_inject_enabled, "Auto-Inject").clicked() {
                        auto_inject_clicked = true;
                    }
                });
            });


            ui.separator();
            ui.label(format!("Status: {}", *state.injection_status.lock().unwrap()));
             if state.dll_path.is_none() {
                ui.colored_label(egui::Color32::RED, "client.dll not found in the application directory.");
            }

    if auto_inject_clicked {
        state.auto_inject_enabled.store(auto_inject_enabled, Ordering::SeqCst);
        if auto_inject_enabled {
            analysis::start_auto_inject_thread(state);
        }
    }
}