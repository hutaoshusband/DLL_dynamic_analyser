use eframe::egui;

use crate::app::state::AppState;

mod entropy_viewer;
mod launcher;
mod live_logs;
mod memory_analysis;

pub fn render(ctx: &egui::Context, state: &mut AppState) {
    launcher::render_launcher_window(ctx, state);
    live_logs::render_log_window(ctx, state);
    memory_analysis::render_memory_analysis_window(ctx, state);
    entropy_viewer::render_entropy_viewer_window(ctx, state);
}