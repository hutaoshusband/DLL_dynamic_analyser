use eframe::egui;
use shared::Command;

use crate::app::state::AppState;

pub fn render_hooking_controls_window(ctx: &egui::Context, state: &mut AppState) {
    if !state.windows.hooking_control_window_open {
        return;
    }

    let mut changed = false;

    egui::Window::new("Hooking Controls")
        .open(&mut state.windows.hooking_control_window_open)
        .vscroll(true)
        .show(ctx, |ui| {
            ui.collapsing("Global Toggles", |ui| {
                changed |= ui.checkbox(&mut state.monitor_config.api_hooks_enabled, "API Hooks").changed();
                changed |= ui.checkbox(&mut state.monitor_config.network_hooks_enabled, "Network Hooks").changed();
                changed |= ui.checkbox(&mut state.monitor_config.registry_hooks_enabled, "Registry Hooks").changed();
                changed |= ui.checkbox(&mut state.monitor_config.crypto_hooks_enabled, "Crypto Hooks").changed();
                changed |= ui.checkbox(&mut state.monitor_config.log_network_data, "Log Network Data").changed();
            });

            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.collapsing("Process & Memory", |ui| {
                    changed |= ui.checkbox(&mut state.monitor_config.hook_open_process, "OpenProcess").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_write_process_memory, "WriteProcessMemory").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_virtual_alloc_ex, "VirtualAllocEx").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_terminate_process, "TerminateProcess").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_nt_terminate_process, "NtTerminateProcess").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_create_process_w, "CreateProcessW").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_create_process_a, "CreateProcessA").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_load_library_w, "LoadLibraryW").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_load_library_ex_w, "LoadLibraryExW").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_free_library, "FreeLibrary").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_create_remote_thread, "CreateRemoteThread").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_nt_create_thread_ex, "NtCreateThreadEx").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_create_thread, "CreateThread").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_queue_user_apc, "QueueUserAPC").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_set_thread_context, "SetThreadContext").changed();
                });

                ui.collapsing("File System", |ui| {
                    changed |= ui.checkbox(&mut state.monitor_config.hook_create_file_w, "CreateFileW").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_write_file, "WriteFile").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_delete_file_w, "DeleteFileW").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_copy_file_w, "CopyFileW").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_move_file_w, "MoveFileW").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_get_temp_path_w, "GetTempPathW").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_get_temp_file_name_w, "GetTempFileNameW").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_find_first_file_w, "FindFirstFileW").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_find_next_file_w, "FindNextFileW").changed();
                });

                ui.collapsing("Network", |ui| {
                    changed |= ui.checkbox(&mut state.monitor_config.hook_connect, "connect").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_wsasend, "WSASend").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_wsarecv, "WSARecv").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_send, "send").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_recv, "recv").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_get_addr_info_w, "GetAddrInfoW").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_dns_query_a, "DnsQuery_A").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_dns_query_w, "DnsQuery_W").changed();
                });

                ui.collapsing("WinINet", |ui| {
                    changed |= ui.checkbox(&mut state.monitor_config.hook_internet_open_w, "InternetOpenW").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_internet_connect_w, "InternetConnectW").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_http_open_request_w, "HttpOpenRequestW").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_http_send_request_w, "HttpSendRequestW").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_internet_read_file, "InternetReadFile").changed();
                });

                ui.collapsing("Registry", |ui| {
                    changed |= ui.checkbox(&mut state.monitor_config.hook_reg_create_key_ex_w, "RegCreateKeyExW").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_reg_set_value_ex_w, "RegSetValueExW").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_reg_delete_key_w, "RegDeleteKeyW").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_reg_open_key_ex_w, "RegOpenKeyExW").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_reg_query_value_ex_w, "RegQueryValueExW").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_reg_enum_key_ex_w, "RegEnumKeyExW").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_reg_enum_value_w, "RegEnumValueW").changed();
                });

                ui.collapsing("Anti-Debug & Anti-Analysis", |ui| {
                    changed |= ui.checkbox(&mut state.monitor_config.hook_is_debugger_present, "IsDebuggerPresent").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_check_remote_debugger_present, "CheckRemoteDebuggerPresent").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_nt_query_information_process, "NtQueryInformationProcess").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_create_toolhelp32_snapshot, "CreateToolhelp32Snapshot").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_process32_first_w, "Process32FirstW").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_process32_next_w, "Process32NextW").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_exit_process, "ExitProcess").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_get_tick_count, "GetTickCount").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_query_performance_counter, "QueryPerformanceCounter").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_output_debug_string_a, "OutputDebugStringA").changed();
                });

                ui.collapsing("Crypto & Security", |ui| {
                    changed |= ui.checkbox(&mut state.monitor_config.hook_crypt_encrypt, "CryptEncrypt").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_crypt_decrypt, "CryptDecrypt").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_crypt_hash_data, "CryptHashData").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_cert_verify_certificate_chain_policy, "CertVerifyCertificateChainPolicy").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_add_vectored_exception_handler, "AddVectoredExceptionHandler").changed();
                });

                ui.collapsing("Miscellaneous", |ui| {
                    changed |= ui.checkbox(&mut state.monitor_config.hook_message_box_w, "MessageBoxW").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_win_exec, "WinExec").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_system, "system").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_shell_execute_w, "ShellExecuteW").changed();
                    changed |= ui.checkbox(&mut state.monitor_config.hook_shell_execute_ex_w, "ShellExecuteExW").changed();
                });
            });
        });

    if changed {
        if let Some(pipe_handle) = *state.pipe_handle.lock().unwrap() {
            let command = Command::UpdateConfig(state.monitor_config);
            if let Ok(command_json) = serde_json::to_string(&command) {
                // To allow the client to potentially receive multiple commands in one buffer,
                // we append a newline. The client should split the buffer by newlines.
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
}