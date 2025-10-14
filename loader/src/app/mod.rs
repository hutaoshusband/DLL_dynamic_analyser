pub mod state;

use std::sync::{atomic::Ordering, mpsc, Arc, Mutex};

use eframe::egui;

use self::state::{ActiveTab, AppState};

pub struct App {
    state: Arc<Mutex<AppState>>,
    log_receiver: mpsc::Receiver<String>,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let (log_sender, log_receiver) = mpsc::channel();

        // --- Customizing EGUI Style ---
        let mut style = (*cc.egui_ctx.style()).clone();

        // General visual settings
        style.visuals.window_rounding = egui::Rounding::same(10.0);
        style.visuals.widgets.noninteractive.rounding = egui::Rounding::same(8.0);
        style.visuals.widgets.inactive.rounding = egui::Rounding::same(8.0);
        style.visuals.widgets.hovered.rounding = egui::Rounding::same(8.0);
        style.visuals.widgets.active.rounding = egui::Rounding::same(8.0);
        style.visuals.widgets.open.rounding = egui::Rounding::same(8.0);
        style.spacing.item_spacing = egui::vec2(8.0, 8.0);
        style.spacing.button_padding = egui::vec2(10.0, 6.0);

        // Custom colors for a cleaner look
        let visuals = &mut style.visuals;
        visuals.widgets.inactive.bg_fill = egui::Color32::from_gray(40); // Darker inactive widgets
        visuals.widgets.hovered.bg_fill = egui::Color32::from_gray(60);
        visuals.widgets.active.bg_fill = egui::Color32::from_gray(80);
        visuals.selection.bg_fill = egui::Color32::from_rgb(0, 116, 217); // Blue selection
        visuals.hyperlink_color = egui::Color32::from_rgb(0, 150, 255);

        cc.egui_ctx.set_style(style);


        Self {
            state: Arc::new(Mutex::new(AppState::new(log_sender))),
            log_receiver,
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let mut state = self.state.lock().unwrap();

        // Process any incoming logs
        while let Ok(log_json) = self.log_receiver.try_recv() {
            state.handle_log(&log_json);
        }

        // Render the main menu bar
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Exit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                let tabs = [
                    (ActiveTab::Launcher, "🚀 Launcher"),
                    (ActiveTab::Logs, "📜 Logs"),
                    (ActiveTab::MemoryAnalysis, "🧠 Memory Analysis"),
                    (ActiveTab::Hooking, "🎣 Hooking"),
                    (ActiveTab::Network, "🌐 Network"),
                ];

                for (tab, title) in tabs.iter() {
                    let is_active = state.active_tab == *tab;
                    let button = egui::Button::new(*title).frame(is_active); // Frame only if active
                    if ui.add(button).clicked() {
                        state.active_tab = *tab;
                    }
                }
            });

            ui.separator();

            // Render the content for the active tab
            crate::gui::render_active_tab(ctx, ui, &mut state);
        });


        // Request a repaint if the process is running to keep the UI updated
        if state.is_process_running.load(Ordering::SeqCst) {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
}