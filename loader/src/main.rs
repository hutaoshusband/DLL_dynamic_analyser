#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release

mod app;
mod core;
mod gui;

use app::App;
use eframe::egui;

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([300.0, 200.0]) // Compact initial window
            .with_resizable(true),
        ..Default::default()
    };

    eframe::run_native(
        "Modular Dynamic Analyzer",
        options,
        Box::new(|cc| {
            // Set the dark mode theme
            let mut style = (*cc.egui_ctx.style()).clone();
            style.visuals = egui::Visuals::dark();
            cc.egui_ctx.set_style(style);
            Box::new(App::new(cc))
        }),
    )
}