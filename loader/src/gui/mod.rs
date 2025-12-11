use eframe::egui::{self, Ui};

use crate::app::state::{ActiveTab, AppState};

mod hooking_controls;
mod launcher;
mod live_logs;
mod memory_analysis;
mod network_activity;

pub fn render_tab(ctx: &egui::Context, ui: &mut Ui, state: &mut AppState, tab: ActiveTab) {
    match tab {
        ActiveTab::Launcher => launcher::render_launcher_tab(ctx, ui, state),
        ActiveTab::Logs => live_logs::render_log_tab(ui, state),
        ActiveTab::MemoryAnalysis => memory_analysis::render_memory_analysis_tab(ctx, ui, state),
        ActiveTab::Hooking => hooking_controls::render_hooking_controls_tab(ui, state),
        ActiveTab::Network => network_activity::render_network_activity_tab(ui, state),
    }
}