pub mod state;

use std::sync::{atomic::Ordering, mpsc, Arc, Mutex};

use eframe::egui;

use self::state::{ActiveTab, AppState};

pub struct App {
    state: Arc<Mutex<AppState>>,
    log_receiver: mpsc::Receiver<String>,
}

impl App {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let (log_sender, log_receiver) = mpsc::channel();
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

        // Custom window frame for the "frosted glass" look
        let panel_frame = egui::Frame {
            fill: ctx.style().visuals.window_fill(),
            ..egui::Frame::central_panel(&ctx.style())
        };

        egui::CentralPanel::default()
            .frame(panel_frame)
            .show(ctx, |ui| {
                // Title bar
                ui.with_layout(egui::Layout::top_down(egui::Align::LEFT), |ui| {
                    // Centered Tab bar
                    ui.with_layout(egui::Layout::top_down(egui::Align::Center), |ui| {
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
                                let mut button = egui::Button::new(*title);
                                if is_active {
                                    button = button.fill(ui.style().visuals.selection.bg_fill);
                                } else {
                                    button = button.frame(false);
                                }
                                if ui.add(button).clicked() {
                                    state.active_tab = *tab;
                                }
                            }
                        });
                    });
                    ui.add(egui::Separator::default().spacing(10.0));
                });


                // Render the content for the active tab
                crate::gui::render_active_tab(ctx, ui, &mut state);
            });


        // Request a repaint if the process is running to keep the UI updated
        if state.is_process_running.load(Ordering::SeqCst) {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
}