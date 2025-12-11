// Copyright (c) 2024 HUTAOSHUSBAND - Wallbangbros.com/CodeConfuser.dev
// All rights reserved.

pub mod state;

use std::sync::{atomic::Ordering, mpsc, Arc, Mutex};

use eframe::egui;
use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetWindowLongPtrW, SetWindowLongPtrW, GWL_EXSTYLE, WS_EX_LAYERED,
};

use self::state::{ActiveTab, AppState, RippleAnimation};


fn get_tab_index(tab: ActiveTab) -> usize {
    match tab {
        ActiveTab::Launcher => 0,
        ActiveTab::Logs => 1,
        ActiveTab::MemoryAnalysis => 2,
        ActiveTab::Hooking => 3,
        ActiveTab::Network => 4,
    }
}

pub struct App {
    state: Arc<Mutex<AppState>>,
    log_receiver: mpsc::Receiver<String>,
    is_maximized: bool,
    last_window_rect: Option<egui::Rect>,
}

impl App {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let (log_sender, log_receiver) = mpsc::channel();
        Self {
            state: Arc::new(Mutex::new(AppState::new(log_sender))),
            log_receiver,
            is_maximized: false,
            last_window_rect: None,
        }
    }
}

// Helper function to enforce WS_EX_LAYERED style for transparency
fn enforce_transparency(hwnd: isize) {
    unsafe {
        let ex_style = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
        if (ex_style & WS_EX_LAYERED as isize) == 0 {
            SetWindowLongPtrW(hwnd, GWL_EXSTYLE, ex_style | WS_EX_LAYERED as isize);
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        let mut state = self.state.lock().unwrap();

        // Process any incoming logs
        while let Ok(log_json) = self.log_receiver.try_recv() {
            state.handle_log(&log_json);
        }

        // --- Transparency Enforcement ---
        // Access the raw window handle to force the WS_EX_LAYERED style.
        // This is necessary because some Windows operations (like snapping/maximizing)
        // can strip this style, breaking the transparency.
        if let Ok(handle) = frame.window_handle() {
            if let RawWindowHandle::Win32(win32_handle) = handle.as_raw() {
                enforce_transparency(win32_handle.hwnd.get());
            }
        }

        ctx.send_viewport_cmd(egui::ViewportCommand::Transparent(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Decorations(false));

        // --- Window Management Logic ---

        // 1. Detect OS Maximize attempt (e.g. Win+Up) and switch to custom maximize
        if ctx.input(|i| i.viewport().maximized.unwrap_or(false)) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(false));
            self.is_maximized = true;
            
            // Re-assert transparency properties immediately
            ctx.send_viewport_cmd(egui::ViewportCommand::Transparent(true));
            ctx.send_viewport_cmd(egui::ViewportCommand::Decorations(false));

            let monitor_rect = ctx.input(|i| i.screen_rect());
            // Reduce height by 1.0 to avoid Windows "Fullscreen Optimization" which kills transparency
            // This 1px difference is invisible but critical.
            let safe_rect = egui::Rect::from_min_size(monitor_rect.min, monitor_rect.size() - egui::vec2(0.0, 1.0));
            ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(safe_rect.min));
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(safe_rect.size()));
        }

        // 2. Track window size when not maximized (for restore)
        if !self.is_maximized {
            if let Some(rect) = ctx.input(|i| i.viewport().outer_rect) {
                self.last_window_rect = Some(rect);
            }
        }

        // Helper for toggling maximize state
        let toggle_maximize = |is_maximized: &mut bool, last_rect: Option<egui::Rect>| {
            if *is_maximized {
                // Restore
                *is_maximized = false;
                ctx.send_viewport_cmd(egui::ViewportCommand::Transparent(true));
                if let Some(rect) = last_rect {
                    ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(rect.min));
                    ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(rect.size()));
                } else {
                    // Default fallback if no history
                     ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize([1000.0, 700.0].into()));
                }
            } else {
                // Maximize
                *is_maximized = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Transparent(true));
                let monitor_rect = ctx.input(|i| i.screen_rect());
                // Reduce height by 1.0 to avoid Windows "Fullscreen Optimization" which kills transparency
                let safe_rect = egui::Rect::from_min_size(monitor_rect.min, monitor_rect.size() - egui::vec2(0.0, 1.0));
                ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(safe_rect.min));
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(safe_rect.size()));
            }
        };

        // Custom window frame for the "frosted glass" look
        let panel_frame = egui::Frame {
            fill: egui::Color32::TRANSPARENT, // Keep transparent as per original requirement
            ..egui::Frame::central_panel(&ctx.style())
        };

        // Custom title bar and centered tabs
        egui::TopBottomPanel::top("title_bar")
            .frame(egui::Frame::none().fill(egui::Color32::TRANSPARENT))
            .exact_height(40.0) // Set a fixed height
            .show(ctx, |ui| {
                // Allow dragging the window by the title bar
                let response = ui.interact(ui.max_rect(), ui.id(), egui::Sense::click_and_drag());
                if response.dragged() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
                }
                if response.double_clicked() {
                     toggle_maximize(&mut self.is_maximized, self.last_window_rect);
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
                    let close_button_width = 40.0 * 3.0; // Space for 3 buttons
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
                            if state.active_tab != *tab {
                                state.previous_tab = Some(state.active_tab);
                                state.tab_transition_start = Some(ctx.input(|i| i.time));
                                state.active_tab = *tab;
                            }
                            
                            // Add Ripple Effect
                            if let Some(pos) = response.interact_pointer_pos() {
                                state.active_ripples.push(RippleAnimation {
                                    start_time: ctx.input(|i| i.time),
                                    center: pos,
                                    color: egui::Color32::from_rgb(0x33, 0xCC, 0xFF),
                                });
                            }
                        }
                    }

                    // --- Render Ripples ---
                    let current_time = ctx.input(|i| i.time);
                    state.active_ripples.retain(|ripple| {
                        let elapsed = current_time - ripple.start_time;
                        let duration = 0.6; // 600ms animation
                        if elapsed >= duration {
                            false
                        } else {
                            let t = elapsed as f32 / duration as f32;
                            let radius = t * 150.0; // Max radius 150
                            let opacity = (1.0 - t).powi(2); // Quadratic ease-out or just squared falloff for faster fade
                            
                            // Use a separate painter to draw on top of everything in this layer
                             ui.ctx().layer_painter(ui.layer_id()).circle_filled(
                                ripple.center,
                                radius,
                                ripple.color.linear_multiply(opacity),
                            );
                            true
                        }
                    });

                    if !state.active_ripples.is_empty() {
                        ctx.request_repaint();
                    }

                    // Window Controls (Min, Max, Close)
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let button_size = [24.0, 24.0];
                        
                        // Close
                        if ui.add_sized(button_size, egui::Button::new("❌")).clicked() {
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        }

                        // Maximize / Restore
                        let max_icon = if self.is_maximized { "❐" } else { "🗖" };
                        if ui.add_sized(button_size, egui::Button::new(max_icon)).clicked() {
                             toggle_maximize(&mut self.is_maximized, self.last_window_rect);
                        }

                        // Minimize
                        if ui.add_sized(button_size, egui::Button::new("🗕")).clicked() {
                            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                        }
                    });
                });
            });

        egui::CentralPanel::default()
            .frame(panel_frame)
            .show(ctx, |ui| {
                // Add a separator and space for visual clarity
                ui.add(egui::Separator::default().spacing(10.0));

                // --- Tab Content Transition ---
                let mut transition_active = false;
                if let (Some(prev_tab), Some(start_time)) = (state.previous_tab, state.tab_transition_start) {
                    let now = ctx.input(|i| i.time);
                    let duration = 0.3; // 300ms transition
                    let t = (now - start_time) / duration;

                    if t < 1.0 {
                        transition_active = true;
                        let t = t as f32;
                        // Cubic ease out: 1 - (1-t)^3
                        let t_ease = 1.0 - (1.0 - t).powi(3);
                        
                        let prev_idx = get_tab_index(prev_tab);
                        let curr_idx = get_tab_index(state.active_tab);
                        let dir = if curr_idx > prev_idx { 1.0 } else { -1.0 };
                        
                        let rect = ui.available_rect_before_wrap();
                        let width = rect.width();

                        // Clip to viewport
                        ui.set_clip_rect(rect);

                        // Render Previous Tab (Sliding Out)
                        {
                            let offset_x = -dir * width * t_ease;
                            let mut prev_rect = rect;
                            prev_rect = prev_rect.translate(egui::vec2(offset_x, 0.0));
                            
                            ui.allocate_ui_at_rect(prev_rect, |ui| {
                                ui.push_id("prev_tab_view", |ui| {
                                     crate::gui::render_tab(ctx, ui, &mut state, prev_tab);
                                });
                            });
                        }

                        // Render Current Tab (Sliding In)
                        {
                            let offset_x = dir * width * (1.0 - t_ease);
                            let mut curr_rect = rect;
                            curr_rect = curr_rect.translate(egui::vec2(offset_x, 0.0));

                            ui.allocate_ui_at_rect(curr_rect, |ui| {
                                ui.push_id("curr_tab_view", |ui| {
                                     let current_tab = state.active_tab;
                                     crate::gui::render_tab(ctx, ui, &mut state, current_tab);
                                });
                            });
                        }
                        
                        ctx.request_repaint();
                    } else {
                        // Transition finished
                        state.previous_tab = None;
                        state.tab_transition_start = None;
                    }
                }

                if !transition_active {
                    let current_tab = state.active_tab;
                    crate::gui::render_tab(ctx, ui, &mut state, current_tab);
                }
            });


        // Request a repaint if the process is running to keep the UI updated
        if state.is_process_running.load(Ordering::SeqCst) {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
}