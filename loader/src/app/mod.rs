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
            fill: egui::Color32::TRANSPARENT, // Make the central panel transparent
            ..egui::Frame::central_panel(&ctx.style())
        };

        // Custom title bar and centered tabs
        egui::TopBottomPanel::top("title_bar")
            .frame(egui::Frame::none().fill(egui::Color32::TRANSPARENT))
            .exact_height(40.0) // Set a fixed height
            .show(ctx, |ui| {
                // Allow dragging the window by the title bar
                let response = ui.interact(ui.max_rect(), ui.id(), egui::Sense::drag());
                if response.dragged() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
                }

                // Center the content vertically
                ui.with_layout(egui::Layout::from_main_dir_and_cross_align(egui::Direction::LeftToRight, egui::Align::Center), |ui| {
                    let tabs = [
                        (ActiveTab::Launcher, "🚀 Launcher"),
                        (ActiveTab::Logs, "📜 Logs"),
                        (ActiveTab::MemoryAnalysis, "💾 Memory Analysis"),
                        (ActiveTab::Hooking, "🎣 Hooking"),
                        (ActiveTab::Network, "🌐 Network"),
                    ];

                    // Calculate tabs width
                    let mut tabs_width = 0.0;
                    let style = ui.style();
                    let font_id = egui::TextStyle::Button.resolve(style);
                    let button_padding = style.spacing.button_padding;
                    let item_spacing = style.spacing.item_spacing.x;
                    let min_button_size = egui::vec2(100.0, 40.0);

                    for (_, title) in tabs.iter() {
                        let text_size = ui.painter().layout_no_wrap(title.to_string(), font_id.clone(), style.visuals.text_color()).size();
                        let button_width = (text_size.x + button_padding.x * 2.0).max(min_button_size.x);
                        tabs_width += button_width;
                    }
                    tabs_width += (tabs.len() - 1) as f32 * item_spacing;

                    let available_width = ui.available_width();
                    let close_button_width = 40.0;
                    let spacer_width = (available_width - tabs_width - close_button_width).max(0.0) / 2.0;

                    ui.add_space(spacer_width);

                    // Render tabs
                    for (tab, title) in tabs.iter() {
                        let is_active = state.active_tab == *tab;
                        let button = egui::Button::new(*title)
                            .frame(false)
                            .min_size(min_button_size);
                        let response = ui.add(button);

                        if is_active {
                            let rect = response.rect;
                            ui.painter().line_segment(
                                [rect.left_bottom() + egui::vec2(0.0, -5.0), rect.right_bottom() + egui::vec2(0.0, -5.0)],
                                egui::Stroke::new(2.0, egui::Color32::from_rgb(0x33, 0xCC, 0xFF))
                            );
                        }

                        if response.clicked() {
                            state.active_tab = *tab;
                        }
                    }

                    // Close button on the right
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.add_sized([40.0, 40.0], egui::Button::new("❌")).clicked() {
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                    });
                });
            });

        egui::CentralPanel::default()
            .frame(panel_frame)
            .show(ctx, |ui| {
                // Add a separator and space for visual clarity
                ui.add(egui::Separator::default().spacing(10.0));

                // Render the content for the active tab
                crate::gui::render_active_tab(ctx, ui, &mut state);
            });


        // Request a repaint if the process is running to keep the UI updated
        if state.is_process_running.load(Ordering::SeqCst) {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
}