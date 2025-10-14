use eframe::egui::{Ui};

use crate::app::state::AppState;

pub fn render_network_activity_tab(ui: &mut Ui, _state: &mut AppState) {
    ui.label("Network activity will be displayed here.");
}