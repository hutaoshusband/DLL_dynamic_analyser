#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release

mod app;
mod core;
mod gui;

use app::App;
use eframe::egui::{self, style::Widgets, Rounding, Stroke, Style, Visuals};
use egui::Color32;

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 700.0])
            .with_resizable(true)
            .with_transparent(true)
            .with_decorations(false),
        ..Default::default()
    };

    eframe::run_native(
        "Modular Dynamic Analyzer",
        options,
        Box::new(|cc| {
            cc.egui_ctx.set_style(create_custom_style());
            Box::new(App::new(cc))
        }),
    )
}

fn create_custom_style() -> Style {
    let background = Color32::from_rgba_unmultiplied(30, 30, 46, 180); // Lower alpha for more transparency
    let panel_fill = Color32::from_rgba_unmultiplied(24, 24, 37, 190); // Lower alpha
    let accent_blue = Color32::from_rgb(137, 180, 250);
    let text_color = Color32::from_rgb(205, 214, 244);
    let faint_text = Color32::from_rgb(127, 132, 156);

    let mut style = Style::default();
    style.visuals = Visuals {
        dark_mode: true,
        override_text_color: Some(text_color),
        window_rounding: Rounding::same(12.0),
        window_shadow: egui::epaint::Shadow::NONE,
        window_fill: Color32::TRANSPARENT, // Make window background fully transparent
        window_stroke: Stroke::new(1.0, Color32::from_gray(60)),
        panel_fill,
        extreme_bg_color: Color32::from_gray(10),
        hyperlink_color: accent_blue,
        selection: egui::style::Selection {
            bg_fill: accent_blue.linear_multiply(0.2),
            stroke: Stroke::new(1.0, accent_blue),
        },
        widgets: Widgets {
            noninteractive: egui::style::WidgetVisuals {
                bg_fill: Color32::from_gray(30),
                weak_bg_fill: Color32::from_gray(30),
                bg_stroke: Stroke::NONE,
                rounding: Rounding::same(8.0),
                fg_stroke: Stroke::new(1.0, faint_text),
                expansion: 0.0,
            },
            inactive: egui::style::WidgetVisuals {
                bg_fill: Color32::from_gray(40),
                weak_bg_fill: Color32::from_gray(30),
                bg_stroke: Stroke::new(1.0, Color32::from_gray(60)),
                rounding: Rounding::same(8.0),
                fg_stroke: Stroke::new(1.0, faint_text),
                expansion: 0.0,
            },
            hovered: egui::style::WidgetVisuals {
                bg_fill: Color32::from_gray(60),
                weak_bg_fill: Color32::from_gray(50),
                bg_stroke: Stroke::new(1.5, accent_blue),
                rounding: Rounding::same(10.0),
                fg_stroke: Stroke::new(1.5, text_color),
                expansion: 1.0,
            },
            active: egui::style::WidgetVisuals {
                bg_fill: accent_blue,
                weak_bg_fill: accent_blue,
                bg_stroke: Stroke::new(1.5, Color32::WHITE),
                rounding: Rounding::same(10.0),
                fg_stroke: Stroke::new(1.5, Color32::BLACK),
                expansion: 1.0,
            },
            open: egui::style::WidgetVisuals {
                bg_fill: panel_fill,
                weak_bg_fill: panel_fill,
                bg_stroke: Stroke::new(1.0, accent_blue),
                rounding: Rounding::same(8.0),
                fg_stroke: Stroke::new(1.0, text_color),
                expansion: 0.0,
            },
        },
        ..Visuals::dark()
    };
    style
}