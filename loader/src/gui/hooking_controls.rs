use eframe::egui::{self, Ui};
use shared::Command;
use std::sync::atomic::Ordering;

use crate::app::state::AppState;

// Custom switch widget
fn switch(ui: &mut egui::Ui, on: &mut bool) -> egui::Response {
    let desired_size = ui.spacing().interact_size.y * egui::vec2(1.8, 1.0);
    let (rect, mut response) = ui.allocate_exact_size(desired_size, egui::Sense::click());
    if response.clicked() {
        *on = !*on;
        response.mark_changed();
    }
    response.widget_info(|| egui::WidgetInfo::selected(egui::WidgetType::Checkbox, *on, ""));

    if ui.is_rect_visible(rect) {
        let how_on = ui.ctx().animate_bool(response.id, *on);
        let visuals = ui.style().interact(&response);
        let rect = rect.expand(visuals.expansion);
        let radius = rect.height() / 2.0;

        let bg_fill = if *on {
            egui::Color32::from_rgb(0x33, 0xCC, 0xFF)
        } else {
            ui.style().visuals.widgets.inactive.bg_fill
        };

        ui.painter().rect(rect, radius, bg_fill, visuals.bg_stroke);

        let circle_x = egui::lerp((rect.left() + radius)..=(rect.right() - radius), how_on);
        let center = egui::pos2(circle_x, rect.center().y);

        ui.painter().circle_filled(center, 0.85 * radius, visuals.fg_stroke.color);
    }

    response
}

fn switch_with_label(ui: &mut egui::Ui, on: &mut bool, label: &str) {
    ui.horizontal(|ui| {
        switch(ui, on);
        ui.label(label);
    });
}

pub fn render_hooking_controls_tab(ui: &mut Ui, state: &mut AppState) {
    let is_running = state.is_process_running.load(Ordering::SeqCst);

    ui.with_layout(egui::Layout::top_down(egui::Align::Center), |ui| {
        // Card for General Settings
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.with_layout(egui::Layout::top_down(egui::Align::LEFT), |ui| {
                ui.heading("General Settings");
                ui.add_space(12.0);

                egui::Grid::new("general_settings_grid").num_columns(2).spacing([40.0, 8.0]).show(ui, |ui| {
                    switch_with_label(ui, &mut state.monitor_config.api_hooks_enabled, "API Hooks Enabled");
                    switch_with_label(ui, &mut state.monitor_config.iat_scan_enabled, "IAT Scan Enabled");
                    ui.end_row();
                    switch_with_label(ui, &mut state.monitor_config.string_dump_enabled, "String Dump Enabled");
                    switch_with_label(ui, &mut state.monitor_config.vmp_dump_enabled, "VMP Dump Enabled");
                    ui.end_row();
                    switch_with_label(ui, &mut state.monitor_config.manual_map_scan_enabled, "Manual Map Scan Enabled");
                    switch_with_label(ui, &mut state.monitor_config.network_hooks_enabled, "Network Hooks Enabled");
                    ui.end_row();
                    switch_with_label(ui, &mut state.monitor_config.registry_hooks_enabled, "Registry Hooks Enabled");
                    switch_with_label(ui, &mut state.monitor_config.crypto_hooks_enabled, "Crypto Hooks Enabled");
                    ui.end_row();
                    switch_with_label(ui, &mut state.monitor_config.log_network_data, "Log Network Data");
                    switch_with_label(ui, &mut state.monitor_config.stack_trace_on_error, "Stack Trace on Error");
                    ui.end_row();

                    ui.add_space(8.0);
                    ui.end_row();

                    ui.label("Suspicion Threshold:");
                    ui.add(egui::Slider::new(&mut state.monitor_config.suspicion_threshold, 0..=100));
                    ui.end_row();

                    ui.label("Stack Trace Frame Limit:");
                    ui.add(egui::Slider::new(&mut state.monitor_config.stack_trace_frame_limit, 1..=64));
                    ui.end_row();
                });
            });
        });

        ui.add_space(10.0);

        // Card for Individual Hooks
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.with_layout(egui::Layout::top_down(egui::Align::LEFT), |ui| {
                ui.heading("Individual Hooks");
                ui.add_space(12.0);

                egui::ScrollArea::vertical().show(ui, |ui| {
                    egui::Grid::new("hooks_grid").num_columns(4).spacing([20.0, 8.0]).show(ui, |ui| {
                        switch_with_label(ui, &mut state.monitor_config.hook_open_process, "OpenProcess");
                        switch_with_label(ui, &mut state.monitor_config.hook_write_process_memory, "WriteProcessMemory");
                        switch_with_label(ui, &mut state.monitor_config.hook_virtual_alloc_ex, "VirtualAllocEx");
                        switch_with_label(ui, &mut state.monitor_config.hook_create_file_w, "CreateFileW");
                        ui.end_row();

                        switch_with_label(ui, &mut state.monitor_config.hook_write_file, "WriteFile");
                        switch_with_label(ui, &mut state.monitor_config.hook_http_send_request_w, "HttpSendRequestW");
                        switch_with_label(ui, &mut state.monitor_config.hook_terminate_process, "TerminateProcess");
                        switch_with_label(ui, &mut state.monitor_config.hook_nt_terminate_process, "NtTerminateProcess");
                        ui.end_row();

                        switch_with_label(ui, &mut state.monitor_config.hook_message_box_w, "MessageBoxW");
                        switch_with_label(ui, &mut state.monitor_config.hook_create_process_w, "CreateProcessW");
                        switch_with_label(ui, &mut state.monitor_config.hook_load_library_w, "LoadLibraryW");
                        switch_with_label(ui, &mut state.monitor_config.hook_load_library_ex_w, "LoadLibraryExW");
                        ui.end_row();

                        switch_with_label(ui, &mut state.monitor_config.hook_connect, "connect");
                        switch_with_label(ui, &mut state.monitor_config.hook_reg_create_key_ex_w, "RegCreateKeyExW");
                        switch_with_label(ui, &mut state.monitor_config.hook_reg_set_value_ex_w, "RegSetValueExW");
                        switch_with_label(ui, &mut state.monitor_config.hook_reg_delete_key_w, "RegDeleteKeyW");
                        ui.end_row();

                        switch_with_label(ui, &mut state.monitor_config.hook_reg_open_key_ex_w, "RegOpenKeyExW");
                        switch_with_label(ui, &mut state.monitor_config.hook_reg_query_value_ex_w, "RegQueryValueExW");
                        switch_with_label(ui, &mut state.monitor_config.hook_reg_enum_key_ex_w, "RegEnumKeyExW");
                        switch_with_label(ui, &mut state.monitor_config.hook_reg_enum_value_w, "RegEnumValueW");
                        ui.end_row();

                        switch_with_label(ui, &mut state.monitor_config.hook_delete_file_w, "DeleteFileW");
                        switch_with_label(ui, &mut state.monitor_config.hook_create_remote_thread, "CreateRemoteThread");
                        switch_with_label(ui, &mut state.monitor_config.hook_get_addr_info_w, "GetAddrInfoW");
                        switch_with_label(ui, &mut state.monitor_config.hook_is_debugger_present, "IsDebuggerPresent");
                        ui.end_row();

                        switch_with_label(ui, &mut state.monitor_config.hook_check_remote_debugger_present, "CheckRemoteDebuggerPresent");
                        switch_with_label(ui, &mut state.monitor_config.hook_nt_query_information_process, "NtQueryInformationProcess");
                        switch_with_label(ui, &mut state.monitor_config.hook_create_toolhelp32_snapshot, "CreateToolhelp32Snapshot");
                        switch_with_label(ui, &mut state.monitor_config.hook_process32_first_w, "Process32FirstW");
                        ui.end_row();

                        switch_with_label(ui, &mut state.monitor_config.hook_process32_next_w, "Process32NextW");
                        switch_with_label(ui, &mut state.monitor_config.hook_exit_process, "ExitProcess");
                        switch_with_label(ui, &mut state.monitor_config.hook_get_tick_count, "GetTickCount");
                        switch_with_label(ui, &mut state.monitor_config.hook_query_performance_counter, "QueryPerformanceCounter");
                        ui.end_row();

                        switch_with_label(ui, &mut state.monitor_config.hook_output_debug_string_a, "OutputDebugStringA");
                        switch_with_label(ui, &mut state.monitor_config.hook_add_vectored_exception_handler, "AddVectoredExceptionHandler");
                        switch_with_label(ui, &mut state.monitor_config.hook_create_thread, "CreateThread");
                        switch_with_label(ui, &mut state.monitor_config.hook_free_library, "FreeLibrary");
                        ui.end_row();

                        switch_with_label(ui, &mut state.monitor_config.hook_crypt_encrypt, "CryptEncrypt");
                        switch_with_label(ui, &mut state.monitor_config.hook_crypt_decrypt, "CryptDecrypt");
                        switch_with_label(ui, &mut state.monitor_config.hook_wsasend, "WSASend");
                        switch_with_label(ui, &mut state.monitor_config.hook_wsarecv, "WSARecv");
                        ui.end_row();

                        switch_with_label(ui, &mut state.monitor_config.hook_send, "send");
                        switch_with_label(ui, &mut state.monitor_config.hook_recv, "recv");
                        switch_with_label(ui, &mut state.monitor_config.hook_internet_open_w, "InternetOpenW");
                        switch_with_label(ui, &mut state.monitor_config.hook_internet_connect_w, "InternetConnectW");
                        ui.end_row();

                        switch_with_label(ui, &mut state.monitor_config.hook_http_open_request_w, "HttpOpenRequestW");
                        switch_with_label(ui, &mut state.monitor_config.hook_internet_read_file, "InternetReadFile");
                        switch_with_label(ui, &mut state.monitor_config.hook_dns_query_a, "DnsQuery_A");
                        switch_with_label(ui, &mut state.monitor_config.hook_dns_query_w, "DnsQuery_W");
                        ui.end_row();

                        switch_with_label(ui, &mut state.monitor_config.hook_cert_verify_certificate_chain_policy, "CertVerifyCertificateChainPolicy");
                        switch_with_label(ui, &mut state.monitor_config.hook_crypt_hash_data, "CryptHashData");
                        switch_with_label(ui, &mut state.monitor_config.hook_copy_file_w, "CopyFileW");
                        switch_with_label(ui, &mut state.monitor_config.hook_move_file_w, "MoveFileW");
                        ui.end_row();

                        switch_with_label(ui, &mut state.monitor_config.hook_get_temp_path_w, "GetTempPathW");
                        switch_with_label(ui, &mut state.monitor_config.hook_get_temp_file_name_w, "GetTempFileNameW");
                        switch_with_label(ui, &mut state.monitor_config.hook_find_first_file_w, "FindFirstFileW");
                        switch_with_label(ui, &mut state.monitor_config.hook_find_next_file_w, "FindNextFileW");
                        ui.end_row();

                        switch_with_label(ui, &mut state.monitor_config.hook_nt_create_thread_ex, "NtCreateThreadEx");
                        switch_with_label(ui, &mut state.monitor_config.hook_queue_user_apc, "QueueUserAPC");
                        switch_with_label(ui, &mut state.monitor_config.hook_set_thread_context, "SetThreadContext");
                        switch_with_label(ui, &mut state.monitor_config.hook_win_exec, "WinExec");
                        ui.end_row();

                        switch_with_label(ui, &mut state.monitor_config.hook_system, "system");
                        switch_with_label(ui, &mut state.monitor_config.hook_shell_execute_w, "ShellExecuteW");
                        switch_with_label(ui, &mut state.monitor_config.hook_shell_execute_ex_w, "ShellExecuteExW");
                        switch_with_label(ui, &mut state.monitor_config.hook_create_process_a, "CreateProcessA");
                        ui.end_row();
                    });
                });
            });
        });

        ui.separator();

        ui.scope(|ui| {
            let mut style = ui.style_mut().clone();
            style.visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(0x33, 0xCC, 0xFF);
            style.visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(0x55, 0xE6, 0xF8);
            style.visuals.widgets.inactive.rounding = egui::Rounding::same(12.0);
            style.visuals.widgets.hovered.rounding = egui::Rounding::same(12.0);
            style.visuals.widgets.active.rounding = egui::Rounding::same(12.0);
            style.visuals.widgets.inactive.bg_stroke = egui::Stroke::NONE;
            style.visuals.widgets.hovered.bg_stroke = egui::Stroke::NONE;
            style.visuals.widgets.active.bg_stroke = egui::Stroke::NONE;
            ui.set_style(style);

            if ui.add_enabled(is_running, egui::Button::new("Apply Configuration")).clicked() {
                if let Some(pipe_handle) = *state.commands_pipe_handle.lock().unwrap() {
                    let command = Command::UpdateConfig(state.monitor_config.clone());
                    if let Ok(command_json) = serde_json::to_string(&command) {
                        let command_to_send = format!("{}\n", command_json);
                        unsafe {
                            windows_sys::Win32::Storage::FileSystem::WriteFile(
                                pipe_handle,
                                command_to_send.as_ptr(),
                                command_to_send.len() as u32,
                                &mut 0,
                                std::ptr::null_mut(),
                            );
                        }
                    }
                }
            }
        });


        if !is_running {
            ui.label("Inject into a process to enable runtime configuration.");
        }
    });
}