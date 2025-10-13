use eframe::egui;
use shared::{Command, MonitorConfig, Preset};
use std::sync::atomic::Ordering;

use crate::app::state::AppState;

pub fn render_hooking_controls_window(ctx: &egui::Context, state: &mut AppState) {
    if !state.windows.hooking_control_window_open {
        return;
    }

    egui::Window::new("Hooking Controls")
        .open(&mut state.windows.hooking_control_window_open)
        .vscroll(true)
        .show(ctx, |ui| {
            ui.heading("Dynamic Hook Configuration");
            ui.separator();

            let is_running = state.is_process_running.load(Ordering::SeqCst);

            ui.add_enabled_ui(is_running, |ui| {
                ui.label("Select a preset to apply during runtime.");

                // Preset selection
                ui.horizontal(|ui| {
                    ui.label("Monitoring Preset:");
                    let selected_preset_text = format!("{:?}", state.selected_preset);
                    let combo_box = egui::ComboBox::from_id_source("runtime_preset_selector")
                        .selected_text(selected_preset_text)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut state.selected_preset, Preset::Stealth, "Stealth");
                            ui.selectable_value(&mut state.selected_preset, Preset::Balanced, "Balanced");
                            ui.selectable_value(&mut state.selected_preset, Preset::Aggressive, "Aggressive");
                        });

                    if combo_box.response.changed() {
                        // The config is updated here, but not sent until the button is clicked.
                        state.monitor_config = MonitorConfig::from_preset(state.selected_preset);
                    }
                });

                if ui.button("Apply Configuration").clicked() {
                     if let Some(pipe_handle) = *state.pipe_handle.lock().unwrap() {
                        let command = Command::UpdateConfig(state.monitor_config);
                        if let Ok(command_json) = serde_json::to_string(&command) {
                            let command_to_send = format!("{}\n", command_json);
                            unsafe {
                                windows_sys::Win32::Storage::FileSystem::WriteFile(
                                    pipe_handle,
                                    command_to_send.as_ptr(),
                                    command_to_send.len() as u32,
                                    &mut 0,
                                    std::ptr::null_mut(),
                                );
                            }
                        }
                    }
                }
            });

            if !is_running {
                ui.separator();
                ui.label("Inject into a process to enable runtime configuration.");
            }
        });
}