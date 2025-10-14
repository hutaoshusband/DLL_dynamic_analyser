use eframe::egui::{self, Ui};

use crate::app::state::AppState;
use crate::core::injection;
use shared::Command;

pub fn render_memory_analysis_tab(_ctx: &egui::Context, ui: &mut Ui, state: &mut AppState) {
    ui.collapsing("DLLs in Target Process", |ui| {
        ui.horizontal(|ui| {
            if ui.button("Refresh Modules").clicked() {
                if let Some(pid) = *state.process_id.lock().unwrap() {
                    match injection::get_modules_for_process(pid) {
                        Ok(modules) => *state.modules.lock().unwrap() = modules,
                        Err(e) => {
                            let _ = state
                                .log_sender
                                .send(format!("Error getting modules: {}", e));
                        }
                    }
                }
            }
        });

        let modules_guard = state.modules.lock().unwrap();
        let module_names: Vec<String> = modules_guard.iter().map(|m| m.name.clone()).collect();
        let selected_module_name = state
            .selected_module_index
            .and_then(|i| module_names.get(i).cloned())
            .unwrap_or_else(|| "No Module Selected".to_string());

        egui::ComboBox::from_label("Target Module")
            .selected_text(selected_module_name)
            .show_ui(ui, |ui| {
                for (i, name) in module_names.iter().enumerate() {
                    if ui
                        .selectable_label(state.selected_module_index == Some(i), name)
                        .clicked()
                    {
                        state.selected_module_index = Some(i);
                    }
                }
            });
    });

    ui.collapsing("Memory Sections", |ui| {
        if ui.button("Refresh Sections").clicked() {
            if let Some(pipe_handle) = *state.commands_pipe_handle.lock().unwrap() {
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

        egui::ScrollArea::vertical()
            .max_height(200.0)
            .show(ui, |ui| {
                let sections = state.sections.lock().unwrap().clone();
                for section in sections.iter() {
                    ui.horizontal(|ui| {
                        if ui
                            .selectable_label(
                                state.selected_section_name == Some(section.name.clone()),
                                &section.name,
                            )
                            .clicked()
                        {
                            state.selected_section_name = Some(section.name.clone());
                        }
                        ui.label(format!(
                            "Address: {:#X}, Size: {} bytes",
                            section.virtual_address, section.virtual_size
                        ));
                        if ui.button("Dump").clicked() {
                            if let Some(pipe_handle) = *state.commands_pipe_handle.lock().unwrap() {
                                let command = Command::DumpSection {
                                    name: section.name.clone(),
                                };
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
                            if let Some(pipe_handle) = *state.commands_pipe_handle.lock().unwrap() {
                                let command = Command::CalculateEntropy {
                                    name: section.name.clone(),
                                };
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

    ui.collapsing("Entropy Viewer", |ui| {
        use egui_plot::{Line, Plot, PlotPoints};

        ui.horizontal(|ui| {
            ui.label("This view shows the entropy of each memory section of the target process.");
            if ui.button("Clear Results").clicked() {
                state.entropy_results.lock().unwrap().clear();
            }
        });
        ui.separator();

        let sections = state.sections.lock().unwrap().clone();
        let entropy_results = state.entropy_results.lock().unwrap();

        if sections.is_empty() {
            ui.label("No sections loaded. Refresh sections first.");
            return;
        }

        egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
            for section in sections.iter() {
                ui.collapsing(section.name.clone(), |ui| {
                    let mut annotations = Vec::new();
                    if section.name.starts_with(".vmp") {
                        annotations.push("VMProtect section detected!".to_string());
                    }

                    if let Some(entropy) = entropy_results.get(&section.name) {
                        if entropy.is_empty() {
                            ui.label("Entropy data is empty for this section.");
                            return;
                        }
                        let high_entropy_threshold = 7.5;
                        let average_entropy = entropy.iter().sum::<f32>() / entropy.len() as f32;
                        if average_entropy > high_entropy_threshold {
                            annotations.push(format!("High entropy ({:.2}) suggests packed/encrypted data.", average_entropy));
                        }

                        let points: PlotPoints = entropy
                            .iter()
                            .enumerate()
                            .map(|(i, &y)| [i as f64, y as f64])
                            .collect();
                        let line = Line::new(points);
                        Plot::new(&section.name)
                            .view_aspect(2.0)
                            .show(ui, |plot_ui| plot_ui.line(line));
                    } else {
                        ui.label("No entropy data available. Perform an 'Entropy Scan' for this section.");
                    }

                    if !annotations.is_empty() {
                        ui.separator();
                        ui.label("Annotations:");
                        for annotation in annotations {
                            ui.label(annotation);
                        }
                    }
                });
            }
        });
    });
}