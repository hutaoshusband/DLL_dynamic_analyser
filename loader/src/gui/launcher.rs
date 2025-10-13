use std::sync::atomic::Ordering;

use eframe::egui;

use crate::app::state::AppState;
use crate::core::analysis;

pub fn render_launcher_window(ctx: &egui::Context, state: &mut AppState) {
    egui::Window::new("Launcher & Controls")
        .open(&mut state.windows.launcher_window_open)
        .vscroll(true)
        .show(ctx, |ui| {
            ui.heading("Analysis Launcher");
            ui.separator();

            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.heading("Target Selection");
                ui.horizontal(|ui| {
                    ui.label("Target Process Name:");
                    ui.text_edit_singleline(&mut state.target_process_name);
                });
                ui.horizontal(|ui| {
                    ui.label("Target Process ID:");
                    ui.text_edit_singleline(&mut state.manual_injection_pid);
                    if ui.button("Inject by PID").clicked() {
                        if let Ok(pid) = state.manual_injection_pid.parse::<u32>() {
                            if let Some(dll_path) = state.dll_path.clone() {
                                analysis::start_analysis_thread(
                                    state.log_sender.clone(),
                                    None,
                                    Some(pid),
                                    &dll_path,
                                    state.monitor_config,
                                    state.process_id.clone(),
                                    state.process_handle.clone(),
                                    state.pipe_handle.clone(),
                                    state.is_process_running.clone(),
                                    state.injection_status.clone(),
                                );
                            }
                        }
                    }
                });
            });

            ui.separator();

            ui.horizontal(|ui| {
                if ui.add_enabled(!state.is_process_running.load(Ordering::SeqCst) && state.dll_path.is_some(), egui::Button::new("Find Process & Inject")).clicked() {
                    if let Some(dll_path) = state.dll_path.clone() {
                        analysis::start_analysis_thread(
                            state.log_sender.clone(),
                            Some(state.target_process_name.clone()),
                            None,
                            &dll_path,
                            state.monitor_config,
                            state.process_id.clone(),
                            state.process_handle.clone(),
                            state.pipe_handle.clone(),
                            state.is_process_running.clone(),
                            state.injection_status.clone(),
                        );
                    }
                }
                if ui.add_enabled(state.is_process_running.load(Ordering::SeqCst), egui::Button::new("Terminate Process")).clicked() {
                    analysis::terminate_process(state.process_handle.clone());
                }
            });

            ui.separator();
            ui.label(format!("Status: {}", *state.injection_status.lock().unwrap()));
            ui.separator();

            ui.heading("Hooking Controls");
            ui.collapsing("General Settings", |ui| {
                ui.checkbox(&mut state.monitor_config.api_hooks_enabled, "Enable General API Hooks");
                ui.checkbox(&mut state.monitor_config.iat_scan_enabled, "IAT Hook Scanning");
                ui.checkbox(&mut state.monitor_config.string_dump_enabled, "Live String Dumping");
                ui.checkbox(&mut state.monitor_config.vmp_dump_enabled, "VMP Section Scanning");
                ui.checkbox(&mut state.monitor_config.manual_map_scan_enabled, "Manual Map Detection");
                ui.checkbox(&mut state.monitor_config.network_hooks_enabled, "Network Function Hooks (WinINet, WS2_32)");
                ui.checkbox(&mut state.monitor_config.crypto_hooks_enabled, "Cryptography Hooks (CryptoAPI)");
                ui.checkbox(&mut state.monitor_config.registry_hooks_enabled, "Registry Hooks");
                ui.checkbox(&mut state.monitor_config.log_network_data, "Log Full Network Data Payloads");
            });
            ui.collapsing("Individual Hook Controls", |ui| {
                ui.checkbox(&mut state.monitor_config.hook_open_process, "OpenProcess");
                ui.checkbox(&mut state.monitor_config.hook_write_process_memory, "WriteProcessMemory");
                ui.checkbox(&mut state.monitor_config.hook_virtual_alloc_ex, "VirtualAllocEx");
                ui.checkbox(&mut state.monitor_config.hook_create_file_w, "CreateFileW");
                ui.checkbox(&mut state.monitor_config.hook_write_file, "WriteFile");
                ui.checkbox(&mut state.monitor_config.hook_http_send_request_w, "HttpSendRequestW");
                ui.checkbox(&mut state.monitor_config.hook_terminate_process, "TerminateProcess");
                ui.checkbox(&mut state.monitor_config.hook_nt_terminate_process, "NtTerminateProcess");
                ui.checkbox(&mut state.monitor_config.hook_message_box_w, "MessageBoxW");
                ui.checkbox(&mut state.monitor_config.hook_create_process_w, "CreateProcessW");
                ui.checkbox(&mut state.monitor_config.hook_load_library_w, "LoadLibraryW");
                ui.checkbox(&mut state.monitor_config.hook_load_library_ex_w, "LoadLibraryExW");
                ui.checkbox(&mut state.monitor_config.hook_connect, "connect");
                ui.checkbox(&mut state.monitor_config.hook_reg_create_key_ex_w, "RegCreateKeyExW");
                ui.checkbox(&mut state.monitor_config.hook_reg_set_value_ex_w, "RegSetValueExW");
                ui.checkbox(&mut state.monitor_config.hook_reg_delete_key_w, "RegDeleteKeyW");
                ui.checkbox(&mut state.monitor_config.hook_reg_open_key_ex_w, "RegOpenKeyExW");
                ui.checkbox(&mut state.monitor_config.hook_reg_query_value_ex_w, "RegQueryValueExW");
                ui.checkbox(&mut state.monitor_config.hook_reg_enum_key_ex_w, "RegEnumKeyExW");
                ui.checkbox(&mut state.monitor_config.hook_reg_enum_value_w, "RegEnumValueW");
                ui.checkbox(&mut state.monitor_config.hook_delete_file_w, "DeleteFileW");
                ui.checkbox(&mut state.monitor_config.hook_create_remote_thread, "CreateRemoteThread");
                ui.checkbox(&mut state.monitor_config.hook_get_addr_info_w, "GetAddrInfoW");
                ui.checkbox(&mut state.monitor_config.hook_is_debugger_present, "IsDebuggerPresent");
                ui.checkbox(&mut state.monitor_config.hook_check_remote_debugger_present, "CheckRemoteDebuggerPresent");
                ui.checkbox(&mut state.monitor_config.hook_nt_query_information_process, "NtQueryInformationProcess");
                ui.checkbox(&mut state.monitor_config.hook_create_toolhelp32_snapshot, "CreateToolhelp32Snapshot");
                ui.checkbox(&mut state.monitor_config.hook_process32_first_w, "Process32FirstW");
                ui.checkbox(&mut state.monitor_config.hook_process32_next_w, "Process32NextW");
                ui.checkbox(&mut state.monitor_config.hook_exit_process, "ExitProcess");
                ui.checkbox(&mut state.monitor_config.hook_get_tick_count, "GetTickCount");
                ui.checkbox(&mut state.monitor_config.hook_query_performance_counter, "QueryPerformanceCounter");
                ui.checkbox(&mut state.monitor_config.hook_output_debug_string_a, "OutputDebugStringA");
                ui.checkbox(&mut state.monitor_config.hook_add_vectored_exception_handler, "AddVectoredExceptionHandler");
                ui.checkbox(&mut state.monitor_config.hook_create_thread, "CreateThread");
                ui.checkbox(&mut state.monitor_config.hook_free_library, "FreeLibrary");
                ui.checkbox(&mut state.monitor_config.hook_crypt_encrypt, "CryptEncrypt");
                ui.checkbox(&mut state.monitor_config.hook_crypt_decrypt, "CryptDecrypt");
                ui.checkbox(&mut state.monitor_config.hook_wsasend, "WSASend");
                ui.checkbox(&mut state.monitor_config.hook_wsarecv, "WSARecv");
                ui.checkbox(&mut state.monitor_config.hook_send, "send");
                ui.checkbox(&mut state.monitor_config.hook_recv, "recv");
                ui.checkbox(&mut state.monitor_config.hook_internet_open_w, "InternetOpenW");
                ui.checkbox(&mut state.monitor_config.hook_internet_connect_w, "InternetConnectW");
                ui.checkbox(&mut state.monitor_config.hook_http_open_request_w, "HttpOpenRequestW");
                ui.checkbox(&mut state.monitor_config.hook_internet_read_file, "InternetReadFile");
                ui.checkbox(&mut state.monitor_config.hook_dns_query_a, "DnsQuery_A");
                ui.checkbox(&mut state.monitor_config.hook_dns_query_w, "DnsQuery_W");
                ui.checkbox(&mut state.monitor_config.hook_cert_verify_certificate_chain_policy, "CertVerifyCertificateChainPolicy");
                ui.checkbox(&mut state.monitor_config.hook_crypt_hash_data, "CryptHashData");
                ui.checkbox(&mut state.monitor_config.hook_copy_file_w, "CopyFileW");
                ui.checkbox(&mut state.monitor_config.hook_move_file_w, "MoveFileW");
                ui.checkbox(&mut state.monitor_config.hook_get_temp_path_w, "GetTempPathW");
                ui.checkbox(&mut state.monitor_config.hook_get_temp_file_name_w, "GetTempFileNameW");
                ui.checkbox(&mut state.monitor_config.hook_find_first_file_w, "FindFirstFileW");
                ui.checkbox(&mut state.monitor_config.hook_find_next_file_w, "FindNextFileW");
                ui.checkbox(&mut state.monitor_config.hook_nt_create_thread_ex, "NtCreateThreadEx");
                ui.checkbox(&mut state.monitor_config.hook_queue_user_apc, "QueueUserAPC");
                ui.checkbox(&mut state.monitor_config.hook_set_thread_context, "SetThreadContext");
                ui.checkbox(&mut state.monitor_config.hook_win_exec, "WinExec");
                ui.checkbox(&mut state.monitor_config.hook_system, "system");
                ui.checkbox(&mut state.monitor_config.hook_shell_execute_w, "ShellExecuteW");
                ui.checkbox(&mut state.monitor_config.hook_shell_execute_ex_w, "ShellExecuteExW");
                ui.checkbox(&mut state.monitor_config.hook_create_process_a, "CreateProcessA");
            });
        });
}