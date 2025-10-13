use eframe::egui;

use crate::app::state::AppState;

mod entropy_viewer;
mod hooking_controls;
mod launcher;
mod live_logs;
mod memory_analysis;
mod network_activity;

pub fn render(ctx: &egui::Context, state: &mut AppState) {
    launcher::render_launcher_window(ctx, state);
    live_logs::render_log_window(ctx, state);
    memory_analysis::render_memory_analysis_window(ctx, state);
    entropy_viewer::render_entropy_viewer_window(ctx, state);
    hooking_controls::render_hooking_controls_window(ctx, state);
    network_activity::render_network_activity_window(ctx, state);
}