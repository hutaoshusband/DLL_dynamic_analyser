use eframe::egui;
use egui_plot::{Line, Plot, PlotPoints};

use crate::app::state::AppState;

pub fn render_entropy_viewer_window(ctx: &egui::Context, state: &mut AppState) {
    if !state.windows.entropy_viewer_window_open {
        return;
    }

    egui::Window::new("Entropy Viewer")
        .open(&mut state.windows.entropy_viewer_window_open)
        .vscroll(true)
        .show(ctx, |ui| {
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
                ui.label("No sections loaded. Refresh sections in the 'Memory Analysis' tab.");
                return;
            }

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
                        ui.label("No entropy data available. Perform an 'Entropy Scan' in the 'Memory Analysis' tab for this section.");
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
}