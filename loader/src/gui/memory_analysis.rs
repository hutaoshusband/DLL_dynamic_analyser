// Copyright (c) 2024 HUTAOSHUSBAND - Wallbangbros.com/FireflyProtector.xyz

use eframe::egui::{self, Color32, RichText, Ui};

use crate::app::state::AppState;
use crate::core::injection;
use shared::Command;

#[derive(Default, Clone, Copy, PartialEq)]
pub enum MemoryViewMode {
    #[default]
    FullEntropy,
    PerSectionEntropy,
    YaraMatches,
}

pub fn render_memory_analysis_tab(_ctx: &egui::Context, ui: &mut Ui, state: &mut AppState) {
    use egui_plot::{HLine, Line, Plot, PlotPoints};

    let available_height = ui.available_height();

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            
            ui.horizontal(|ui| {
                ui.group(|ui| {
                    ui.set_min_width(280.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("📦 Module").strong().color(Color32::from_rgb(137, 180, 250)));
                        if ui.button("⟳").on_hover_text("Refresh Modules").clicked() {
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
                    let selected_module_name = state
                        .selected_module_index
                        .and_then(|i| module_names.get(i).cloned())
                        .unwrap_or_else(|| "Select a module...".to_string());
                    drop(modules_guard);

                    egui::ComboBox::from_id_source("module_selector")
                        .selected_text(&selected_module_name)
                        .width(200.0)
                        .show_ui(ui, |ui: &mut Ui| {
                            for (i, name) in module_names.iter().enumerate() {
                                if ui.selectable_label(state.selected_module_index == Some(i), name).clicked() {
                                    state.selected_module_index = Some(i);
                                }
                            }
                        });
                });

                ui.add_space(16.0);

                ui.group(|ui| {
                    ui.set_min_width(280.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("📑 Section").strong().color(Color32::from_rgb(166, 227, 161)));
                        if ui.button("⟳").on_hover_text("Refresh Sections").clicked() {
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
                    });

                    let sections = state.sections.lock().unwrap();
                    let section_names: Vec<String> = sections.iter().map(|s| s.name.clone()).collect();
                    let selected_section = state.selected_section_name.clone().unwrap_or_else(|| "Select a section...".to_string());
                    drop(sections);

                    egui::ComboBox::from_id_source("section_selector")
                        .selected_text(&selected_section)
                        .width(200.0)
                        .show_ui(ui, |ui: &mut Ui| {
                            let sections = state.sections.lock().unwrap();
                            for section in sections.iter() {
                                let is_protector = section.name.starts_with(".vmp")
                                    || section.name.starts_with(".enigma")
                                    || section.name.starts_with(".themida");
                                
                                let label = if is_protector {
                                    RichText::new(&section.name).color(Color32::from_rgb(243, 139, 168))
                                } else {
                                    RichText::new(&section.name)
                                };
                                
                                if ui.selectable_label(state.selected_section_name == Some(section.name.clone()), label).clicked() {
                                    state.selected_section_name = Some(section.name.clone());
                                }
                            }
                        });
                });

                if state.selected_section_name.is_some() {
                    ui.add_space(8.0);
                    let module_name = state.selected_module_index.and_then(|i| {
                        let modules = state.modules.lock().unwrap();
                        modules.get(i).map(|m| m.name.clone())
                    }).unwrap_or_default();
                    
                    let section_name = state.selected_section_name.clone().unwrap_or_default();
                    
                    if ui.button("📥 Dump Section").clicked() {
                        if let Some(pipe_handle) = *state.commands_pipe_handle.lock().unwrap() {
                            let command = Command::DumpSection {
                                module_name: module_name.clone(),
                                name: section_name.clone(),
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
                    
                    if ui.button("📊 Section Entropy").clicked() {
                        if let Some(pipe_handle) = *state.commands_pipe_handle.lock().unwrap() {
                            let command = Command::CalculateEntropy {
                                module_name: module_name.clone(),
                                name: section_name.clone(),
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
            });

            ui.add_space(12.0);
            ui.separator();
            ui.add_space(8.0);

            ui.horizontal(|ui| {
                let current_mode = state.memory_view_mode;
                
                let tab_color = |active: bool| {
                    if active { Color32::from_rgb(137, 180, 250) } else { Color32::from_rgb(127, 132, 156) }
                };
                
                if ui.selectable_label(current_mode == MemoryViewMode::FullEntropy, 
                    RichText::new("📊 Full Module Entropy").size(14.0).color(tab_color(current_mode == MemoryViewMode::FullEntropy))
                ).clicked() {
                    state.memory_view_mode = MemoryViewMode::FullEntropy;
                }
                
                ui.add_space(16.0);
                
                if ui.selectable_label(current_mode == MemoryViewMode::PerSectionEntropy,
                    RichText::new("📈 Per-Section Entropy").size(14.0).color(tab_color(current_mode == MemoryViewMode::PerSectionEntropy))
                ).clicked() {
                    state.memory_view_mode = MemoryViewMode::PerSectionEntropy;
                }
                
                ui.add_space(16.0);
                
                let yara_matches = state.yara_matches.lock().unwrap();
                let yara_count = yara_matches.len();
                drop(yara_matches);
                
                let yara_label = if yara_count > 0 {
                    format!("🔍 YARA Matches ({})", yara_count)
                } else {
                    "🔍 YARA Matches".to_string()
                };
                
                if ui.selectable_label(current_mode == MemoryViewMode::YaraMatches,
                    RichText::new(yara_label).size(14.0).color(tab_color(current_mode == MemoryViewMode::YaraMatches))
                ).clicked() {
                    state.memory_view_mode = MemoryViewMode::YaraMatches;
                }
            });

            ui.add_space(8.0);
            ui.separator();
            ui.add_space(12.0);

            match state.memory_view_mode {
                MemoryViewMode::FullEntropy => {
                    ui.horizontal(|ui| {
                        if ui.button("⚡ Calculate Full Module Entropy").clicked() {
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
                        
                        if ui.button("🗑 Clear").clicked() {
                            *state.full_entropy_results.lock().unwrap() = None;
                        }
                        
                        ui.label(RichText::new("│").color(Color32::from_rgb(60, 64, 82)));
                        ui.label(RichText::new("Entropy visualization of the entire module image").size(12.0).color(Color32::from_rgb(127, 132, 156)));
                    });
                    
                    ui.add_space(12.0);

                    let full_entropy = state.full_entropy_results.lock().unwrap();
                    if let Some((module_name, entropy)) = full_entropy.as_ref() {
                        if !entropy.is_empty() {
                            let avg = entropy.iter().sum::<f32>() / entropy.len() as f32;
                            let max = entropy.iter().cloned().fold(0.0_f32, f32::max);
                            let min = entropy.iter().cloned().fold(8.0_f32, f32::min);
                            
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("Module:").color(Color32::from_rgb(127, 132, 156)));
                                ui.label(RichText::new(module_name).strong());
                                ui.add_space(16.0);
                                
                                ui.label(RichText::new("Avg:").color(Color32::from_rgb(127, 132, 156)));
                                let avg_color = if avg > 7.5 { Color32::from_rgb(243, 139, 168) } 
                                    else if avg > 7.0 { Color32::from_rgb(250, 179, 135) }
                                    else { Color32::from_rgb(166, 227, 161) };
                                ui.label(RichText::new(format!("{:.2}", avg)).strong().color(avg_color));
                                ui.add_space(12.0);
                                
                                ui.label(RichText::new("Max:").color(Color32::from_rgb(127, 132, 156)));
                                ui.label(RichText::new(format!("{:.2}", max)));
                                ui.add_space(12.0);
                                
                                ui.label(RichText::new("Min:").color(Color32::from_rgb(127, 132, 156)));
                                ui.label(RichText::new(format!("{:.2}", min)));
                                ui.add_space(12.0);
                                
                                ui.label(RichText::new("Chunks:").color(Color32::from_rgb(127, 132, 156)));
                                ui.label(format!("{}", entropy.len()));
                            });
                            
                            if avg > 7.5 {
                                ui.add_space(4.0);
                                ui.colored_label(Color32::from_rgb(243, 139, 168), 
                                    "⚠️ High entropy detected - likely packed, encrypted, or compressed data");
                            }
                            
                            ui.add_space(12.0);

                            let graph_height = (available_height - 200.0).max(300.0);
                            
                            let points: PlotPoints = entropy
                                .iter()
                                .enumerate()
                                .map(|(i, &y)| [i as f64, y as f64])
                                .collect();
                            let line = Line::new(points)
                                .name("Entropy")
                                .color(Color32::from_rgb(137, 180, 250))
                                .width(2.0);
                            let threshold_line = HLine::new(7.5)
                                .color(Color32::from_rgb(243, 139, 168))
                                .name("High entropy (7.5)");
                            let warning_line = HLine::new(7.0)
                                .color(Color32::from_rgb(250, 179, 135))
                                .name("Warning (7.0)");

                            Plot::new("full_entropy_plot_main")
                                .height(graph_height)
                                .include_y(0.0)
                                .include_y(8.5)
                                .legend(egui_plot::Legend::default())
                                .show_axes(true)
                                .show_grid(true)
                                .allow_zoom(true)
                                .allow_drag(true)
                                .allow_scroll(true)
                                .show(ui, |plot_ui| {
                                    plot_ui.line(line);
                                    plot_ui.hline(threshold_line);
                                    plot_ui.hline(warning_line);
                                });
                        } else {
                            ui.label(RichText::new("Entropy data is empty.").italics().color(Color32::from_rgb(127, 132, 156)));
                        }
                    } else {
                        ui.vertical_centered(|ui| {
                            ui.add_space(60.0);
                            ui.label(RichText::new("📊").size(48.0).color(Color32::from_rgb(60, 64, 82)));
                            ui.add_space(12.0);
                            ui.label(RichText::new("Select a module and click 'Calculate Full Module Entropy'").size(14.0).color(Color32::from_rgb(127, 132, 156)));
                        });
                    }
                }

                MemoryViewMode::PerSectionEntropy => {
                    ui.horizontal(|ui| {
                        if ui.button("🗑 Clear All Results").clicked() {
                            state.entropy_results.lock().unwrap().clear();
                        }
                        ui.label(RichText::new("│").color(Color32::from_rgb(60, 64, 82)));
                        ui.label(RichText::new("Individual section entropy analysis").size(12.0).color(Color32::from_rgb(127, 132, 156)));
                    });
                    
                    ui.add_space(12.0);

                    let sections = state.sections.lock().unwrap().clone();
                    let entropy_results = state.entropy_results.lock().unwrap().clone();

                    if sections.is_empty() {
                        ui.vertical_centered(|ui| {
                            ui.add_space(60.0);
                            ui.label(RichText::new("📈").size(48.0).color(Color32::from_rgb(60, 64, 82)));
                            ui.add_space(12.0);
                            ui.label(RichText::new("Load sections from a module first").size(14.0).color(Color32::from_rgb(127, 132, 156)));
                        });
                    } else {
                        for section in sections.iter() {
                            let is_protector = section.name.starts_with(".vmp")
                                || section.name.starts_with(".enigma")
                                || section.name.starts_with(".themida")
                                || section.name.starts_with(".winlice");
                                
                            let header_color = if is_protector {
                                Color32::from_rgb(243, 139, 168)
                            } else {
                                Color32::from_rgb(166, 227, 161)
                            };
                            
                            ui.group(|ui| {
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new(&section.name).strong().size(14.0).color(header_color));
                                    if is_protector {
                                        ui.label(RichText::new("⚠ Protector").size(11.0).color(Color32::from_rgb(243, 139, 168)));
                                    }
                                    ui.label(RichText::new(format!("{:#X} • {} bytes", section.virtual_address, section.virtual_size))
                                        .size(11.0).color(Color32::from_rgb(127, 132, 156)));
                                        
                                    let module_name = state.selected_module_index.and_then(|i| {
                                        let modules = state.modules.lock().unwrap();
                                        modules.get(i).map(|m| m.name.clone())
                                    }).unwrap_or_default();
                                    
                                    if ui.small_button("Scan").clicked() {
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
                                
                                if let Some(entropy) = entropy_results.get(&section.name) {
                                    if !entropy.is_empty() {
                                        let avg = entropy.iter().sum::<f32>() / entropy.len() as f32;
                                        let avg_color = if avg > 7.5 { Color32::from_rgb(243, 139, 168) } 
                                            else if avg > 7.0 { Color32::from_rgb(250, 179, 135) }
                                            else { Color32::from_rgb(166, 227, 161) };
                                        
                                        ui.horizontal(|ui| {
                                            ui.label(RichText::new("Average:").size(11.0).color(Color32::from_rgb(127, 132, 156)));
                                            ui.label(RichText::new(format!("{:.2}", avg)).size(11.0).strong().color(avg_color));
                                        });

                                        let points: PlotPoints = entropy
                                            .iter()
                                            .enumerate()
                                            .map(|(i, &y)| [i as f64, y as f64])
                                            .collect();
                                        let line = Line::new(points)
                                            .color(Color32::from_rgb(137, 180, 250))
                                            .width(1.5);
                                        let threshold = HLine::new(7.5)
                                            .color(Color32::from_rgb(243, 139, 168));

                                        Plot::new(format!("section_entropy_{}", &section.name))
                                            .height(150.0)
                                            .include_y(0.0)
                                            .include_y(8.5)
                                            .show_axes(true)
                                            .show_grid(true)
                                            .allow_zoom(true)
                                            .allow_drag(true)
                                            .show(ui, |plot_ui| {
                                                plot_ui.line(line);
                                                plot_ui.hline(threshold);
                                            });
                                    } else {
                                        ui.label(RichText::new("Entropy data is empty").italics().size(11.0).color(Color32::from_rgb(127, 132, 156)));
                                    }
                                } else {
                                    ui.label(RichText::new("Click 'Scan' to analyze entropy").italics().size(11.0).color(Color32::from_rgb(127, 132, 156)));
                                }
                            });
                            
                            ui.add_space(8.0);
                        }
                    }
                }

                MemoryViewMode::YaraMatches => {
                    ui.horizontal(|ui| {
                        if ui.button("🔍 Scan Now").clicked() {
                            if let Some(pipe_handle) = *state.commands_pipe_handle.lock().unwrap() {
                                let command = Command::ScanYara;
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
                        if ui.button("🗑 Clear Matches").clicked() {
                            state.yara_matches.lock().unwrap().clear();
                        }
                        ui.label(RichText::new("│").color(Color32::from_rgb(60, 64, 82)));
                        ui.label(RichText::new("Detected YARA rule matches from memory scans").size(12.0).color(Color32::from_rgb(127, 132, 156)));
                    });
                    
                    ui.add_space(12.0);

                    let yara_matches = state.yara_matches.lock().unwrap();
                    
                    if yara_matches.is_empty() {
                        drop(yara_matches);
                        ui.vertical_centered(|ui| {
                            ui.add_space(60.0);
                            ui.label(RichText::new("🔍").size(48.0).color(Color32::from_rgb(60, 64, 82)));
                            ui.add_space(12.0);
                            ui.label(RichText::new("No YARA matches yet. Wait for automatic scans, click 'Scan Now', or load YARA rules.").size(14.0).color(Color32::from_rgb(127, 132, 156)));
                        });
                    } else {
                        let matches_clone: Vec<_> = yara_matches.iter().cloned().collect();
                        drop(yara_matches);
                        
                        egui::Grid::new("yara_header")
                            .num_columns(4)
                            .spacing([40.0, 4.0])
                            .show(ui, |ui| {
                                ui.label(RichText::new("Rule Name").strong());
                                ui.label(RichText::new("Address").strong());
                                ui.label(RichText::new("Region Size").strong());
                                ui.label(RichText::new("Metadata").strong());
                                ui.end_row();
                            });
                        
                        ui.separator();
                        
                        egui::Grid::new("yara_matches_grid")
                            .num_columns(4)
                            .spacing([40.0, 6.0])
                            .striped(true)
                            .show(ui, |ui| {
                                for m in matches_clone.iter() {
                                    let is_protector = m.rule_name.to_lowercase().contains("vmprotect")
                                        || m.rule_name.to_lowercase().contains("enigma")
                                        || m.rule_name.to_lowercase().contains("themida");
                                    
                                    let rule_color = if is_protector {
                                        Color32::from_rgb(243, 139, 168)
                                    } else {
                                        Color32::from_rgb(205, 214, 244)
                                    };
                                    
                                    ui.label(RichText::new(&m.rule_name).color(rule_color));
                                    ui.label(RichText::new(format!("{:#x}", m.address)).color(Color32::from_rgb(137, 180, 250)));
                                    ui.label(RichText::new(format!("{:#x}", m.region_size)).color(Color32::from_rgb(127, 132, 156)));
                                    
                                    // Parse and format metadata if it looks like JSON
                                    let metadata_display = if m.metadata.starts_with('{') {
                                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&m.metadata) {
                                            if let Some(obj) = json.as_object() {
                                                obj.iter()
                                                   .map(|(k, v)| format!("{}: {}", k, v))
                                                   .collect::<Vec<_>>()
                                                   .join(", ")
                                            } else {
                                                m.metadata.clone()
                                            }
                                        } else {
                                            m.metadata.clone()
                                        }
                                    } else {
                                        m.metadata.clone()
                                    };

                                    ui.label(RichText::new(metadata_display).color(Color32::from_rgb(166, 227, 161)));
                                    ui.end_row();
                                }
                            });
                    }
                }
            }
        });
}
