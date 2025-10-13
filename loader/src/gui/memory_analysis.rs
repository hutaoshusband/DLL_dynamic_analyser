use eframe::egui;

use crate::app::state::AppState;
use crate::core::injection;
use shared::Command;

pub fn render_memory_analysis_window(ctx: &egui::Context, state: &mut AppState) {
    if !state.windows.memory_analysis_window_open {
        return;
    }

    egui::Window::new("Module & Memory Analysis")
        .open(&mut state.windows.memory_analysis_window_open)
        .vscroll(true)
        .show(ctx, |ui| {
            ui.collapsing("DLLs in Target Process", |ui| {
                ui.horizontal(|ui| {
                    if ui.button("Refresh Modules").clicked() {
                        if let Some(pid) = *state.process_id.lock().unwrap() {
                            match injection::get_modules_for_process(pid) {
                                Ok(modules) => *state.modules.lock().unwrap() = modules,
                                Err(e) => {
                                    let _ = state.log_sender.send(format!("Error getting modules: {}", e));
                                }
                            }
                        }
                    }
                });

                let modules_guard = state.modules.lock().unwrap();
                let module_names: Vec<String> = modules_guard.iter().map(|m| m.name.clone()).collect();
                let selected_module_name = state.selected_module_index.and_then(|i| module_names.get(i).cloned()).unwrap_or_else(|| "No Module Selected".to_string());

                egui::ComboBox::from_label("Target Module")
                    .selected_text(selected_module_name)
                    .show_ui(ui, |ui| {
                        for (i, name) in module_names.iter().enumerate() {
                            if ui.selectable_label(state.selected_module_index == Some(i), name).clicked() {
                                state.selected_module_index = Some(i);
                            }
                        }
                    });
            });

            ui.collapsing("Memory Sections", |ui| {
                if ui.button("Refresh Sections").clicked() {
                    if let Some(pipe_handle) = *state.pipe_handle.lock().unwrap() {
                        let command = Command::ListSections;
                        if let Ok(command_json) = serde_json::to_string(&command) {
                            unsafe {
                                windows_sys::Win32::Storage::FileSystem::WriteFile(
                                    pipe_handle,
                                    command_json.as_ptr(),
                                    command_json.len() as u32,
                                    &mut 0,
                                    std::ptr::null_mut(),
                                );
                            }
                        }
                    }
                }

                egui::ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
                    let sections = state.sections.lock().unwrap().clone();
                    for section in sections.iter() {
                        ui.horizontal(|ui| {
                            if ui.selectable_label(state.selected_section_name == Some(section.name.clone()), &section.name).clicked() {
                                state.selected_section_name = Some(section.name.clone());
                            }
                            ui.label(format!(
                                "Address: {:#X}, Size: {} bytes",
                                section.virtual_address, section.virtual_size
                            ));
                            if ui.button("Dump").clicked() {
                                if let Some(pipe_handle) = *state.pipe_handle.lock().unwrap() {
                                    let command = Command::DumpSection { name: section.name.clone() };
                                    if let Ok(command_json) = serde_json::to_string(&command) {
                                        unsafe {
                                            windows_sys::Win32::Storage::FileSystem::WriteFile(
                                                pipe_handle,
                                                command_json.as_ptr(),
                                                command_json.len() as u32,
                                                &mut 0,
                                                std::ptr::null_mut(),
                                            );
                                        }
                                    }
                                }
                            }
                            if ui.button("Entropy Scan").clicked() {
                                if let Some(pipe_handle) = *state.pipe_handle.lock().unwrap() {
                                    let command = Command::CalculateEntropy { name: section.name.clone() };
                                    if let Ok(command_json) = serde_json::to_string(&command) {
                                        unsafe {
                                            windows_sys::Win32::Storage::FileSystem::WriteFile(
                                                pipe_handle,
                                                command_json.as_ptr(),
                                                command_json.len() as u32,
                                                &mut 0,
                                                std::ptr::null_mut(),
                                            );
                                        }
                                    }
                                }
                            }
                        });
                    }
                });
            });
        });
}