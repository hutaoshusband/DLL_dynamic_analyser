use eframe::egui;

use crate::app::state::AppState;

pub fn render_network_activity_window(ctx: &egui::Context, state: &mut AppState) {
    if !state.windows.network_activity_window_open {
        return;
    }

    egui::Window::new("Network Activity")
        .open(&mut state.windows.network_activity_window_open)
        .vscroll(true)
        .show(ctx, |ui| {
            ui.label("Network activity will be displayed here.");
        });
}