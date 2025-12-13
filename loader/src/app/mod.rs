// Copyright (c) 2024 HUTAOSHUSBAND - Wallbangbros.com/FireflyProtector.xyz

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

    startup_time: Option<f64>,
    animation_finished: bool,
    frame_count: usize,
    startup_target_rect: Option<egui::Rect>,
}

impl App {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let (log_sender, log_receiver) = mpsc::channel();
        Self {
            state: Arc::new(Mutex::new(AppState::new(log_sender))),
            log_receiver,
            is_maximized: false,
            last_window_rect: None,
            startup_time: None,
            animation_finished: false,
            frame_count: 0,
            startup_target_rect: None,
        }
    }
}

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

        while let Ok(log_json) = self.log_receiver.try_recv() {
            state.handle_log(&log_json);
        }

        if let Ok(handle) = frame.window_handle() {
            if let RawWindowHandle::Win32(win32_handle) = handle.as_raw() {
                enforce_transparency(win32_handle.hwnd.get());
            }
        }

        ctx.send_viewport_cmd(egui::ViewportCommand::Transparent(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Decorations(false));

        if self.startup_target_rect.is_none() {
            let mut screen_rect = ctx.input(|i| i.screen_rect());

            if screen_rect.width() < 800.0 || screen_rect.height() < 600.0 {
                if let Some(vp_rect) = ctx.input(|i| i.viewport().outer_rect) {
                    if vp_rect.width() > 800.0 {
                        screen_rect = vp_rect;
                    } else {
                        screen_rect =
                            egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1920.0, 1080.0));
                    }
                } else {
                    screen_rect =
                        egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1920.0, 1080.0));
                }
            }

            let target_w = 1200.0f32.min(screen_rect.width() * 0.9);
            let target_h = 800.0f32.min(screen_rect.height() * 0.9);
            let target_size = egui::vec2(target_w, target_h);

            let center = screen_rect.center();
            let target_pos = center - target_size / 2.0;

            let candidate = egui::Rect::from_min_size(target_pos, target_size);

            self.startup_target_rect = Some(candidate);
        }

        let target_final_rect = self.startup_target_rect.unwrap();

        self.frame_count += 1;
        if self.frame_count < 10 {
            let start_w = 10.0;
            let start_h = 10.0;
            let center = target_final_rect.center();
            let start_pos = center - egui::vec2(start_w, start_h) / 2.0;

            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize([start_w, start_h].into()));
            ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(start_pos));

            ctx.request_repaint();
        } else if !self.animation_finished {
            let now = ctx.input(|i| i.time);

            if self.startup_time.is_none() {
                self.startup_time = Some(now);
            }

            let start = self.startup_time.unwrap();
            let duration = 0.6; // 600ms
            let t_raw = ((now - start) / duration).clamp(0.0, 1.0) as f32;

            let t = 1.0 - (1.0 - t_raw).powi(3);

            if t_raw >= 1.0 {
                self.animation_finished = true;

                self.is_maximized = false;

                ctx.send_viewport_cmd(egui::ViewportCommand::Transparent(true));
                ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(target_final_rect.min));
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(target_final_rect.size()));
            } else {
                let center = target_final_rect.center();
                let target_size = target_final_rect.size();

                let start_size = egui::vec2(10.0, 10.0);

                let current_size = start_size + (target_size - start_size) * t;
                let current_pos = center - current_size / 2.0;

                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(current_size));
                ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(current_pos));

                ctx.request_repaint();
            }
        }

        if ctx.input(|i| i.viewport().maximized.unwrap_or(false)) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(false));
            self.is_maximized = true;

            ctx.send_viewport_cmd(egui::ViewportCommand::Transparent(true));
            ctx.send_viewport_cmd(egui::ViewportCommand::Decorations(false));

            let monitor_rect = ctx.input(|i| i.screen_rect());
            let safe_rect = egui::Rect::from_min_size(
                monitor_rect.min,
                monitor_rect.size() - egui::vec2(0.0, 1.0),
            );
            ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(safe_rect.min));
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(safe_rect.size()));
        }

        if !self.is_maximized && self.animation_finished {
            if let Some(rect) = ctx.input(|i| i.viewport().outer_rect) {
                self.last_window_rect = Some(rect);
            }
        }

        let toggle_maximize = |is_maximized: &mut bool, last_rect: Option<egui::Rect>| {
            if *is_maximized {
                *is_maximized = false;
                ctx.send_viewport_cmd(egui::ViewportCommand::Transparent(true));
                if let Some(rect) = last_rect {
                    ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(rect.min));
                    ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(rect.size()));
                } else {
                    ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize([1000.0, 700.0].into()));
                }
            } else {
                *is_maximized = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Transparent(true));
                let monitor_rect = ctx.input(|i| i.screen_rect());
                let safe_rect = egui::Rect::from_min_size(
                    monitor_rect.min,
                    monitor_rect.size() - egui::vec2(0.0, 1.0),
                );
                ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(safe_rect.min));
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(safe_rect.size()));
            }
        };

        let (primary_clicked, pointer_pos) = ctx.input(|i| {
            (
                i.pointer.button_pressed(egui::PointerButton::Primary),
                i.pointer.interact_pos().or(i.pointer.hover_pos()),
            )
        });

        if primary_clicked {
            if let Some(pos) = pointer_pos {
                state.active_ripples.push(RippleAnimation {
                    start_time: ctx.input(|i| i.time),
                    center: pos,
                    color: egui::Color32::from_rgb(0x33, 0xCC, 0xFF),
                });
            }
        }

        let panel_frame = egui::Frame {
            fill: egui::Color32::TRANSPARENT, // Keep transparent as per original requirement
            ..egui::Frame::central_panel(&ctx.style())
        };

        egui::TopBottomPanel::top("title_bar")
            .frame(egui::Frame::none().fill(egui::Color32::TRANSPARENT))
            .exact_height(40.0) // Set a fixed height
            .show(ctx, |ui| {
                let response = ui.interact(ui.max_rect(), ui.id(), egui::Sense::click_and_drag());
                if response.dragged() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
                }
                if response.double_clicked() {
                    toggle_maximize(&mut self.is_maximized, self.last_window_rect);
                }

                ui.with_layout(
                    egui::Layout::from_main_dir_and_cross_align(
                        egui::Direction::LeftToRight,
                        egui::Align::Center,
                    ),
                    |ui| {
                        let tabs = [
                            (ActiveTab::Launcher, "🚀 Launcher"),
                            (ActiveTab::Logs, "📜 Logs"),
                            (ActiveTab::MemoryAnalysis, "💾 Memory Analysis"),
                            (ActiveTab::Hooking, "🎣 Hooking"),
                            (ActiveTab::Network, "🌐 Network"),
                        ];

                        let mut tabs_width = 0.0;
                        let style = ui.style();
                        let font_id = egui::TextStyle::Button.resolve(style);
                        let button_padding = style.spacing.button_padding;
                        let item_spacing = style.spacing.item_spacing.x;
                        let min_button_size = egui::vec2(100.0, 40.0);

                        for (_, title) in tabs.iter() {
                            let text_size = ui
                                .painter()
                                .layout_no_wrap(
                                    title.to_string(),
                                    font_id.clone(),
                                    style.visuals.text_color(),
                                )
                                .size();
                            let button_width =
                                (text_size.x + button_padding.x * 2.0).max(min_button_size.x);
                            tabs_width += button_width;
                        }
                        tabs_width += (tabs.len() - 1) as f32 * item_spacing;

                        let available_width = ui.available_width();
                        let close_button_width = 40.0 * 3.0; // Space for 3 buttons
                        let spacer_width =
                            (available_width - tabs_width - close_button_width).max(0.0) / 2.0;

                        ui.add_space(spacer_width);

                        for (tab, title) in tabs.iter() {
                            let is_active = state.active_tab == *tab;
                            let button = egui::Button::new(*title)
                                .frame(false)
                                .min_size(min_button_size);
                            let response = ui.add(button);

                            if is_active {
                                let rect = response.rect;
                                ui.painter().line_segment(
                                    [
                                        rect.left_bottom() + egui::vec2(0.0, -5.0),
                                        rect.right_bottom() + egui::vec2(0.0, -5.0),
                                    ],
                                    egui::Stroke::new(
                                        2.0,
                                        egui::Color32::from_rgb(0x33, 0xCC, 0xFF),
                                    ),
                                );
                            }

                            if response.clicked() {
                                if state.active_tab != *tab {
                                    state.previous_tab = Some(state.active_tab);
                                    state.tab_transition_start = Some(ctx.input(|i| i.time));
                                    state.active_tab = *tab;
                                }
                            }
                        }

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let button_size = [24.0, 24.0];

                            if ui.add_sized(button_size, egui::Button::new("❌")).clicked() {
                                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                            }

                            let max_icon = if self.is_maximized { "❐" } else { "🗖" };
                            if ui
                                .add_sized(button_size, egui::Button::new(max_icon))
                                .clicked()
                            {
                                toggle_maximize(&mut self.is_maximized, self.last_window_rect);
                            }

                            if ui.add_sized(button_size, egui::Button::new("🗕")).clicked() {
                                ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                            }
                        });
                    },
                );
            });

        egui::CentralPanel::default()
            .frame(panel_frame)
            .show(ctx, |ui| {
                if !self.animation_finished {
                    ui.centered_and_justified(|ui| {
                        ui.spinner(); // Optional: Show a small spinner or nothing
                    });
                    return;
                }

                ui.add(egui::Separator::default().spacing(10.0));

                let mut transition_active = false;
                if let (Some(prev_tab), Some(start_time)) =
                    (state.previous_tab, state.tab_transition_start)
                {
                    let now = ctx.input(|i| i.time);
                    let duration = 0.3; // 300ms transition
                    let t = (now - start_time) / duration;

                    if t < 1.0 {
                        transition_active = true;
                        let t = t as f32;
                        let t_ease = 1.0 - (1.0 - t).powi(3);

                        let prev_idx = get_tab_index(prev_tab);
                        let curr_idx = get_tab_index(state.active_tab);
                        let dir = if curr_idx > prev_idx { 1.0 } else { -1.0 };

                        let rect = ui.available_rect_before_wrap();
                        let width = rect.width();

                        ui.set_clip_rect(rect);

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
                        state.previous_tab = None;
                        state.tab_transition_start = None;
                    }
                }

                if !transition_active {
                    let current_tab = state.active_tab;
                    crate::gui::render_tab(ctx, ui, &mut state, current_tab);
                }
            });

        if state.is_process_running.load(Ordering::SeqCst) {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }

        // Render Global Ripples
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

                ctx.layer_painter(egui::LayerId::new(
                    egui::Order::Foreground,
                    egui::Id::new("global_ripples"),
                ))
                .circle_filled(
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
    }
}
