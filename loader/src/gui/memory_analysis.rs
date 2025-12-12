use eframe::egui::{self, Ui};

use crate::app::state::AppState;
use crate::core::injection;
use shared::Command;

pub fn render_memory_analysis_tab(_ctx: &egui::Context, ui: &mut Ui, state: &mut AppState) {
    ui.with_layout(egui::Layout::top_down(egui::Align::Center), |ui| {
        // YARA Matches Panel - at the top for visibility
        ui.collapsing("🔍 YARA Matches", |ui| {
            ui.horizontal(|ui| {
                ui.label("Detected YARA rule matches from memory scans.");
                if ui.button("Clear Matches").clicked() {
                    state.yara_matches.lock().unwrap().clear();
                }
            });
            ui.separator();
            
            let yara_matches = state.yara_matches.lock().unwrap();
            if yara_matches.is_empty() {
                ui.label("No YARA matches yet. Wait for automatic scans or load YARA rules.");
            } else {
                egui::ScrollArea::vertical().max_height(150.0).show(ui, |ui| {
                    egui::Grid::new("yara_matches_grid")
                        .num_columns(3)
                        .striped(true)
                        .show(ui, |ui| {
                            ui.strong("Rule Name");
                            ui.strong("Address");
                            ui.strong("Region Size");
                            ui.end_row();
                            
                            for m in yara_matches.iter() {
                                // Highlight protector-related rules
                                let is_protector = m.rule_name.to_lowercase().contains("vmprotect")
                                    || m.rule_name.to_lowercase().contains("enigma")
                                    || m.rule_name.to_lowercase().contains("themida");
                                
                                if is_protector {
                                    ui.colored_label(egui::Color32::from_rgb(243, 139, 168), &m.rule_name);
                                } else {
                                    ui.label(&m.rule_name);
                                }
                                ui.label(format!("{:#x}", m.address));
                                ui.label(format!("{:#x}", m.region_size));
                                ui.end_row();
                            }
                        });
                });
            }
        });

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
                    if let Some(module_index) = state.selected_module_index {
                        let modules = state.modules.lock().unwrap();
                        if let Some(module) = modules.get(module_index) {
                            let command = Command::ListSections {
                                module_name: module.name.clone(),
                            };
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
                            let module_name = state.selected_module_index.and_then(|i| {
                                let modules = state.modules.lock().unwrap();
                                modules.get(i).map(|m| m.name.clone())
                            }).unwrap_or_default();

                            if ui.button("Dump").clicked() {
                                if let Some(pipe_handle) = *state.commands_pipe_handle.lock().unwrap() {
                                    let command = Command::DumpSection {
                                        module_name: module_name.clone(),
                                        name: section.name.clone(),
                                    };
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
                            if ui.button("Entropy Scan").clicked() {
                                if let Some(pipe_handle) = *state.commands_pipe_handle.lock().unwrap() {
                                    let command = Command::CalculateEntropy {
                                        module_name: module_name.clone(),
                                        name: section.name.clone(),
                                    };
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
                    }
                });
        });

        ui.collapsing("Full Entropy Graph", |ui| {
            use egui_plot::{Line, Plot, PlotPoints, HLine};

            ui.horizontal(|ui| {
                ui.label("Entropy visualization of the entire module image.");
                if ui.button("Calculate Full Entropy").clicked() {
                    if let Some(pipe_handle) = *state.commands_pipe_handle.lock().unwrap() {
                        if let Some(module_index) = state.selected_module_index {
                            let modules = state.modules.lock().unwrap();
                            if let Some(module) = modules.get(module_index) {
                                let command = Command::CalculateFullEntropy {
                                    module_name: module.name.clone(),
                                };
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
                    }
                }
                if ui.button("Clear").clicked() {
                    *state.full_entropy_results.lock().unwrap() = None;
                }
            });
            ui.separator();

            let full_entropy = state.full_entropy_results.lock().unwrap();
            if let Some((module_name, entropy)) = full_entropy.as_ref() {
                if !entropy.is_empty() {
                    let avg = entropy.iter().sum::<f32>() / entropy.len() as f32;
                    let max = entropy.iter().cloned().fold(0.0_f32, f32::max);
                    ui.label(format!("Module: {} | Avg: {:.2} | Max: {:.2} | Chunks: {}", 
                        module_name, avg, max, entropy.len()));
                    
                    if avg > 7.5 {
                        ui.colored_label(egui::Color32::from_rgb(243, 139, 168), 
                            "⚠️ High entropy suggests packed/encrypted data");
                    }
                    
                    let points: PlotPoints = entropy
                        .iter()
                        .enumerate()
                        .map(|(i, &y)| [i as f64, y as f64])
                        .collect();
                    let line = Line::new(points).name("Entropy");
                    let threshold_line = HLine::new(7.5)
                        .color(egui::Color32::from_rgb(243, 139, 168))
                        .name("High entropy threshold (7.5)");
                    let warning_line = HLine::new(7.0)
                        .color(egui::Color32::from_rgb(250, 179, 135))
                        .name("Warning threshold (7.0)");

                    Plot::new("full_entropy_plot")
                        .view_aspect(3.0)
                        .height(200.0)
                        .include_y(0.0)
                        .include_y(8.0)
                        .show(ui, |plot_ui| {
                            plot_ui.line(line);
                            plot_ui.hline(threshold_line);
                            plot_ui.hline(warning_line);
                        });
                } else {
                    ui.label("Entropy data is empty.");
                }
            } else {
                ui.label("No full entropy data. Select a module and click 'Calculate Full Entropy'.");
            }
        });

        ui.collapsing("Entropy Viewer (Per-Section)", |ui| {
            use egui_plot::{Line, Plot, PlotPoints, HLine};

            ui.horizontal(|ui| {
                ui.label("Per-section entropy analysis.");
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
                        if section.name.starts_with(".enigma") {
                            annotations.push("Enigma section detected!".to_string());
                        }
                        if section.name.starts_with(".themida") || section.name.starts_with(".winlice") {
                            annotations.push("Themida/Winlicense section detected!".to_string());
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
                            let threshold = HLine::new(7.5).color(egui::Color32::from_rgb(243, 139, 168));
                            
                            Plot::new(&section.name)
                                .view_aspect(2.0)
                                .height(120.0)
                                .include_y(0.0)
                                .include_y(8.0)
                                .show(ui, |plot_ui| {
                                    plot_ui.line(line);
                                    plot_ui.hline(threshold);
                                });
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
    });
}