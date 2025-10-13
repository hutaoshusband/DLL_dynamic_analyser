use std::sync::atomic::Ordering;

use eframe::egui;

use crate::app::state::AppState;
use crate::core::analysis;

pub fn render_launcher_window(ctx: &egui::Context, state: &mut AppState) {
    let mut auto_inject_clicked = false;
    let mut auto_inject_enabled = state.auto_inject_enabled.load(Ordering::SeqCst);

    egui::Window::new("Launcher & Controls")
        .open(&mut state.windows.launcher_window_open)
        .vscroll(true)
        .show(ctx, |ui| {
            ui.heading("Analysis Launcher");
            ui.separator();

            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.heading("Target Selection");
                ui.horizontal(|ui| {
                    ui.label("Target Process Name:");
                    ui.text_edit_singleline(&mut state.target_process_name);
                });
                ui.horizontal(|ui| {
                    ui.label("Target Process ID:");
                    ui.text_edit_singleline(&mut state.manual_injection_pid);
                    if ui.button("Inject by PID").clicked() {
                        if let Ok(pid) = state.manual_injection_pid.parse::<u32>() {
                            if let Some(dll_path) = state.dll_path.clone() {
                                analysis::start_analysis_thread(
                                    state.log_sender.clone(),
                                    None,
                                    Some(pid),
                                    &dll_path,
                                    state.monitor_config,
                                    state.process_id.clone(),
                                    state.process_handle.clone(),
                                    state.pipe_handle.clone(),
                                    state.is_process_running.clone(),
                                    state.injection_status.clone(),
                                );
                            }
                        }
                    }
                });
            });

            ui.separator();

            ui.horizontal(|ui| {
                if ui.add_enabled(!state.is_process_running.load(Ordering::SeqCst) && state.dll_path.is_some(), egui::Button::new("Find Process & Inject")).clicked() {
                    if let Some(dll_path) = state.dll_path.clone() {
                        analysis::start_analysis_thread(
                            state.log_sender.clone(),
                            Some(state.target_process_name.clone()),
                            None,
                            &dll_path,
                            state.monitor_config,
                            state.process_id.clone(),
                            state.process_handle.clone(),
                            state.pipe_handle.clone(),
                            state.is_process_running.clone(),
                            state.injection_status.clone(),
                        );
                    }
                }
                if ui.add_enabled(state.is_process_running.load(Ordering::SeqCst), egui::Button::new("Terminate Process")).clicked() {
                    analysis::terminate_process(state.process_handle.clone());
                }

                if ui.checkbox(&mut auto_inject_enabled, "Auto-Inject").clicked() {
                    auto_inject_clicked = true;
                }
            });

            ui.separator();
            ui.label(format!("Status: {}", *state.injection_status.lock().unwrap()));
        });

    if auto_inject_clicked {
        state.auto_inject_enabled.store(auto_inject_enabled, Ordering::SeqCst);
        if auto_inject_enabled {
            analysis::start_auto_inject_thread(state);
        }
    }
}