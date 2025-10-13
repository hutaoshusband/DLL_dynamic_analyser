use eframe::egui::{self, Ui};
use shared::{Command, MonitorConfig, Preset};
use std::sync::atomic::Ordering;

use crate::app::state::AppState;

pub fn render_hooking_controls_tab(ui: &mut Ui, state: &mut AppState) {
    let is_running = state.is_process_running.load(Ordering::SeqCst);

    ui.heading("Configuration Presets");
    ui.horizontal(|ui| {
        ui.label("Monitoring Preset:");
        let selected_preset_text = format!("{:?}", state.selected_preset);
        let combo_box = egui::ComboBox::from_id_source("preset_selector")
            .selected_text(selected_preset_text)
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut state.selected_preset, Preset::Stealth, "Stealth");
                ui.selectable_value(&mut state.selected_preset, Preset::Balanced, "Balanced");
                ui.selectable_value(&mut state.selected_preset, Preset::Aggressive, "Aggressive");
            });

        if combo_box.response.changed() {
            state.monitor_config = MonitorConfig::from_preset(state.selected_preset);
        }
    });

    ui.separator();

    ui.heading("General Settings");
    egui::Grid::new("general_settings_grid").num_columns(2).show(ui, |ui| {
        ui.checkbox(&mut state.monitor_config.api_hooks_enabled, "API Hooks Enabled");
        ui.checkbox(&mut state.monitor_config.iat_scan_enabled, "IAT Scan Enabled");
        ui.checkbox(&mut state.monitor_config.string_dump_enabled, "String Dump Enabled");
        ui.checkbox(&mut state.monitor_config.vmp_dump_enabled, "VMP Dump Enabled");
        ui.checkbox(&mut state.monitor_config.manual_map_scan_enabled, "Manual Map Scan Enabled");
        ui.checkbox(&mut state.monitor_config.network_hooks_enabled, "Network Hooks Enabled");
        ui.checkbox(&mut state.monitor_config.registry_hooks_enabled, "Registry Hooks Enabled");
        ui.checkbox(&mut state.monitor_config.crypto_hooks_enabled, "Crypto Hooks Enabled");
        ui.checkbox(&mut state.monitor_config.log_network_data, "Log Network Data");
        ui.checkbox(&mut state.monitor_config.stack_trace_on_error, "Stack Trace on Error");
        ui.end_row();

        ui.label("Suspicion Threshold:");
        ui.add(egui::Slider::new(&mut state.monitor_config.suspicion_threshold, 0..=100));
        ui.end_row();

        ui.label("Stack Trace Frame Limit:");
        ui.add(egui::Slider::new(&mut state.monitor_config.stack_trace_frame_limit, 1..=64));
        ui.end_row();
    });


    ui.separator();

    ui.heading("Individual Hooks");
    egui::ScrollArea::vertical().show(ui, |ui| {
        egui::Grid::new("hooks_grid").num_columns(3).show(ui, |ui| {
            // This part can be generated with a macro in a real scenario to avoid repetition
            ui.checkbox(&mut state.monitor_config.hook_open_process, "OpenProcess");
            ui.checkbox(&mut state.monitor_config.hook_write_process_memory, "WriteProcessMemory");
            ui.checkbox(&mut state.monitor_config.hook_virtual_alloc_ex, "VirtualAllocEx");
            ui.end_row();
            ui.checkbox(&mut state.monitor_config.hook_create_file_w, "CreateFileW");
            ui.checkbox(&mut state.monitor_config.hook_write_file, "WriteFile");
            ui.checkbox(&mut state.monitor_config.hook_http_send_request_w, "HttpSendRequestW");
            ui.end_row();
            ui.checkbox(&mut state.monitor_config.hook_terminate_process, "TerminateProcess");
            ui.checkbox(&mut state.monitor_config.hook_nt_terminate_process, "NtTerminateProcess");
            ui.checkbox(&mut state.monitor_config.hook_message_box_w, "MessageBoxW");
            ui.end_row();
            ui.checkbox(&mut state.monitor_config.hook_create_process_w, "CreateProcessW");
            ui.checkbox(&mut state.monitor_config.hook_load_library_w, "LoadLibraryW");
            ui.checkbox(&mut state.monitor_config.hook_load_library_ex_w, "LoadLibraryExW");
            ui.end_row();
            ui.checkbox(&mut state.monitor_config.hook_connect, "connect");
            ui.checkbox(&mut state.monitor_config.hook_reg_create_key_ex_w, "RegCreateKeyExW");
            ui.checkbox(&mut state.monitor_config.hook_reg_set_value_ex_w, "RegSetValueExW");
            ui.end_row();
            ui.checkbox(&mut state.monitor_config.hook_reg_delete_key_w, "RegDeleteKeyW");
            ui.checkbox(&mut state.monitor_config.hook_reg_open_key_ex_w, "RegOpenKeyExW");
            ui.checkbox(&mut state.monitor_config.hook_reg_query_value_ex_w, "RegQueryValueExW");
            ui.end_row();
            ui.checkbox(&mut state.monitor_config.hook_reg_enum_key_ex_w, "RegEnumKeyExW");
            ui.checkbox(&mut state.monitor_config.hook_reg_enum_value_w, "RegEnumValueW");
            ui.checkbox(&mut state.monitor_config.hook_delete_file_w, "DeleteFileW");
            ui.end_row();
            ui.checkbox(&mut state.monitor_config.hook_create_remote_thread, "CreateRemoteThread");
            ui.checkbox(&mut state.monitor_config.hook_get_addr_info_w, "GetAddrInfoW");
            ui.checkbox(&mut state.monitor_config.hook_is_debugger_present, "IsDebuggerPresent");
            ui.end_row();
            ui.checkbox(&mut state.monitor_config.hook_check_remote_debugger_present, "CheckRemoteDebuggerPresent");
            ui.checkbox(&mut state.monitor_config.hook_nt_query_information_process, "NtQueryInformationProcess");
            ui.checkbox(&mut state.monitor_config.hook_create_toolhelp32_snapshot, "CreateToolhelp32Snapshot");
            ui.end_row();
            ui.checkbox(&mut state.monitor_config.hook_process32_first_w, "Process32FirstW");
            ui.checkbox(&mut state.monitor_config.hook_process32_next_w, "Process32NextW");
            ui.checkbox(&mut state.monitor_config.hook_exit_process, "ExitProcess");
            ui.end_row();
            ui.checkbox(&mut state.monitor_config.hook_get_tick_count, "GetTickCount");
            ui.checkbox(&mut state.monitor_config.hook_query_performance_counter, "QueryPerformanceCounter");
            ui.checkbox(&mut state.monitor_config.hook_output_debug_string_a, "OutputDebugStringA");
            ui.end_row();
            ui.checkbox(&mut state.monitor_config.hook_add_vectored_exception_handler, "AddVectoredExceptionHandler");
            ui.checkbox(&mut state.monitor_config.hook_create_thread, "CreateThread");
            ui.checkbox(&mut state.monitor_config.hook_free_library, "FreeLibrary");
            ui.end_row();
            ui.checkbox(&mut state.monitor_config.hook_crypt_encrypt, "CryptEncrypt");
            ui.checkbox(&mut state.monitor_config.hook_crypt_decrypt, "CryptDecrypt");
            ui.checkbox(&mut state.monitor_config.hook_wsasend, "WSASend");
            ui.end_row();
            ui.checkbox(&mut state.monitor_config.hook_wsarecv, "WSARecv");
            ui.checkbox(&mut state.monitor_config.hook_send, "send");
            ui.checkbox(&mut state.monitor_config.hook_recv, "recv");
            ui.end_row();
            ui.checkbox(&mut state.monitor_config.hook_internet_open_w, "InternetOpenW");
            ui.checkbox(&mut state.monitor_config.hook_internet_connect_w, "InternetConnectW");
            ui.checkbox(&mut state.monitor_config.hook_http_open_request_w, "HttpOpenRequestW");
            ui.end_row();
            ui.checkbox(&mut state.monitor_config.hook_internet_read_file, "InternetReadFile");
            ui.checkbox(&mut state.monitor_config.hook_dns_query_a, "DnsQuery_A");
            ui.checkbox(&mut state.monitor_config.hook_dns_query_w, "DnsQuery_W");
            ui.end_row();
            ui.checkbox(&mut state.monitor_config.hook_cert_verify_certificate_chain_policy, "CertVerifyCertificateChainPolicy");
            ui.checkbox(&mut state.monitor_config.hook_crypt_hash_data, "CryptHashData");
            ui.checkbox(&mut state.monitor_config.hook_copy_file_w, "CopyFileW");
            ui.end_row();
            ui.checkbox(&mut state.monitor_config.hook_move_file_w, "MoveFileW");
            ui.checkbox(&mut state.monitor_config.hook_get_temp_path_w, "GetTempPathW");
            ui.checkbox(&mut state.monitor_config.hook_get_temp_file_name_w, "GetTempFileNameW");
            ui.end_row();
            ui.checkbox(&mut state.monitor_config.hook_find_first_file_w, "FindFirstFileW");
            ui.checkbox(&mut state.monitor_config.hook_find_next_file_w, "FindNextFileW");
            ui.checkbox(&mut state.monitor_config.hook_nt_create_thread_ex, "NtCreateThreadEx");
            ui.end_row();
            ui.checkbox(&mut state.monitor_config.hook_queue_user_apc, "QueueUserAPC");
            ui.checkbox(&mut state.monitor_config.hook_set_thread_context, "SetThreadContext");
            ui.checkbox(&mut state.monitor_config.hook_win_exec, "WinExec");
            ui.end_row();
            ui.checkbox(&mut state.monitor_config.hook_system, "system");
            ui.checkbox(&mut state.monitor_config.hook_shell_execute_w, "ShellExecuteW");
            ui.checkbox(&mut state.monitor_config.hook_shell_execute_ex_w, "ShellExecuteExW");
            ui.end_row();
            ui.checkbox(&mut state.monitor_config.hook_create_process_a, "CreateProcessA");
        });
    });

    ui.separator();

    if ui.add_enabled(is_running, egui::Button::new("Apply Configuration")).clicked() {
         if let Some(pipe_handle) = *state.pipe_handle.lock().unwrap() {
            let command = Command::UpdateConfig(state.monitor_config);
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

    if !is_running {
        ui.label("Inject into a process to enable runtime configuration.");
    }
}