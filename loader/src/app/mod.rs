pub mod state;

use std::sync::{atomic::Ordering, mpsc, Arc, Mutex};

use eframe::egui;

use self::state::AppState;

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

        // Render the main menu bar
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Exit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                ui.menu_button("View", |ui| {
                    ui.checkbox(&mut state.windows.log_window_open, "Logs");
                    ui.checkbox(
                        &mut state.windows.memory_analysis_window_open,
                        "Memory Analysis",
                    );
                    ui.checkbox(
                        &mut state.windows.hooking_control_window_open,
                        "Hooking Controls",
                    );
                    ui.checkbox(
                        &mut state.windows.entropy_viewer_window_open,
                        "Entropy Viewer",
                    );
                    ui.checkbox(
                        &mut state.windows.network_activity_window_open,
                        "Network Activity",
                    );
                });
            });
        });

        // Render the UI
        crate::gui::render(ctx, &mut state);

        // Request a repaint if the process is running to keep the UI updated
        if state.is_process_running.load(Ordering::SeqCst) {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
}