// Copyright (c) 2024 HUTAOSHUSBAND - Wallbangbros.com/FireflyProtector.xyz


pub mod logging;

use serde::{Deserialize, Serialize};

pub fn get_commands_pipe_name(pid: u32) -> String {
    format!(r"\\.\pipe\hutaoshusband_monitor_commands_pipe_{}", pid)
}

pub fn get_logs_pipe_name(pid: u32) -> String {
    format!(r"\\.\pipe\hutaoshusband_monitor_logs_pipe_{}", pid)
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    Stealth,
    Balanced,
    Aggressive,
}

impl Default for Preset {
    fn default() -> Self {
        Preset::Balanced
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Command {
    ListSections { module_name: String },
    DumpSection { module_name: String, name: String },
    CalculateEntropy { module_name: String, name: String },
    CalculateFullEntropy { module_name: String },
    UpdateConfig(MonitorConfig),
    DumpModule { module_name: String },
    LoadYaraRules(String),
    ScanYara,
}

macro_rules! define_monitor_config {
    (
        general {
            $($g_field:ident: $g_type:ty = $g_default:expr),*
        },
        hooks {
            $($h_field:ident),*
        }
    ) => {
        #[derive(Serialize, Deserialize, Debug, Clone)]
        pub struct MonitorConfig {
            $(pub $g_field: $g_type),*,
            $(pub $h_field: bool),*
        }

        impl Default for MonitorConfig {
            fn default() -> Self {
                Self {
                    $($g_field: $g_default),*,
                    $($h_field: true),*
                }
            }
        }

        impl MonitorConfig {
            pub fn from_preset(preset: Preset) -> Self {
                let mut config = Self::default();
                match preset {
                    Preset::Stealth => {
                        config.api_hooks_enabled = true;
                        config.iat_scan_enabled = false;
                        config.string_dump_enabled = false;
                        config.vmp_dump_enabled = false;
                        config.manual_map_scan_enabled = true; // Keep for security
                        config.network_hooks_enabled = false;
                        config.registry_hooks_enabled = false;
                        config.crypto_hooks_enabled = false;
                        config.log_network_data = false;

                        $(config.$h_field = false;)*

                        config.hook_virtual_alloc_ex = true;
                        config.hook_create_remote_thread = true;
                        config.hook_load_library_w = true;
                        config.hook_is_debugger_present = true;
                        config.hook_check_remote_debugger_present = true;
                        config.hook_nt_query_information_process = true;
                    }
                    Preset::Balanced => {
                        config.string_dump_enabled = false;
                        config.log_network_data = false;
                        config.stack_trace_on_error = true;

                        config.hook_get_tick_count = false;
                        config.hook_query_performance_counter = false;
                        config.hook_output_debug_string_a = false;
                        config.hook_find_first_file_w = false;
                        config.hook_find_next_file_w = false;
                    }
                    Preset::Aggressive => {
                    }
                }
                config
            }
        }
    };
}

define_monitor_config! {
    general {
        loader_path: String = "".to_string(),
        api_hooks_enabled: bool = true,
        iat_scan_enabled: bool = true,
        string_dump_enabled: bool = false,
        vmp_dump_enabled: bool = true,
        manual_map_scan_enabled: bool = true,
        network_hooks_enabled: bool = true,
        registry_hooks_enabled: bool = true,
        crypto_hooks_enabled: bool = true,
        log_network_data: bool = false,
        suspicion_threshold: u32 = 10,
        stack_trace_on_error: bool = true,
        stack_trace_frame_limit: usize = 16
    },
    hooks {
        hook_open_process,
        hook_write_process_memory,
        hook_virtual_alloc_ex,
        hook_create_file_w,
        hook_write_file,
        hook_http_send_request_w,
        hook_terminate_process,
        hook_nt_terminate_process,
        hook_message_box_w,
        hook_create_process_w,
        hook_load_library_w,
        hook_load_library_ex_w,
        hook_connect,
        hook_reg_create_key_ex_w,
        hook_reg_set_value_ex_w,
        hook_reg_delete_key_w,
        hook_reg_open_key_ex_w,
        hook_reg_query_value_ex_w,
        hook_reg_enum_key_ex_w,
        hook_reg_enum_value_w,
        hook_delete_file_w,
        hook_create_remote_thread,
        hook_get_addr_info_w,
        hook_is_debugger_present,
        hook_check_remote_debugger_present,
        hook_nt_query_information_process,
        hook_create_toolhelp32_snapshot,
        hook_process32_first_w,
        hook_process32_next_w,
        hook_exit_process,
        hook_get_tick_count,
        hook_query_performance_counter,
        hook_output_debug_string_a,
        hook_add_vectored_exception_handler,
        hook_create_thread,
        hook_free_library,
        hook_crypt_encrypt,
        hook_crypt_decrypt,
        hook_wsasend,
        hook_wsarecv,
        hook_send,
        hook_recv,
        hook_internet_open_w,
        hook_internet_connect_w,
        hook_http_open_request_w,
        hook_internet_read_file,
        hook_dns_query_a,
        hook_dns_query_w,
        hook_cert_verify_certificate_chain_policy,
        hook_crypt_hash_data,
        hook_copy_file_w,
        hook_move_file_w,
        hook_get_temp_path_w,
        hook_get_temp_file_name_w,
        hook_find_first_file_w,
        hook_find_next_file_w,
        hook_nt_create_thread_ex,
        hook_queue_user_apc,
        hook_set_thread_context,
        hook_win_exec,
        hook_system,
        hook_shell_execute_w,
        hook_shell_execute_ex_w,
        hook_create_process_a
    }
}