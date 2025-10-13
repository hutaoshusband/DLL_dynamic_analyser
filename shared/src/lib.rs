pub mod logging;

use serde::{Deserialize, Serialize};

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
    ListSections,
    DumpSection { name: String },
    CalculateEntropy { name: String },
    UpdateConfig(MonitorConfig),
    DumpModule { module_name: String },
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct MonitorConfig {
    pub api_hooks_enabled: bool,
    pub iat_scan_enabled: bool,
    pub string_dump_enabled: bool,
    pub vmp_dump_enabled: bool,
    pub manual_map_scan_enabled: bool,
    pub network_hooks_enabled: bool,
    pub registry_hooks_enabled: bool,
    pub crypto_hooks_enabled: bool,
    pub log_network_data: bool,
    pub suspicion_threshold: u32,
    pub stack_trace_on_error: bool,
    pub stack_trace_frame_limit: usize,
    // Add a boolean for each hook
    pub hook_open_process: bool,
    pub hook_write_process_memory: bool,
    pub hook_virtual_alloc_ex: bool,
    pub hook_create_file_w: bool,
    pub hook_write_file: bool,
    pub hook_http_send_request_w: bool,
    pub hook_terminate_process: bool,
    pub hook_nt_terminate_process: bool,
    pub hook_message_box_w: bool,
    pub hook_create_process_w: bool,
    pub hook_load_library_w: bool,
    pub hook_load_library_ex_w: bool,
    pub hook_connect: bool,
    pub hook_reg_create_key_ex_w: bool,
    pub hook_reg_set_value_ex_w: bool,
    pub hook_reg_delete_key_w: bool,
    pub hook_reg_open_key_ex_w: bool,
    pub hook_reg_query_value_ex_w: bool,
    pub hook_reg_enum_key_ex_w: bool,
    pub hook_reg_enum_value_w: bool,
    pub hook_delete_file_w: bool,
    pub hook_create_remote_thread: bool,
    pub hook_get_addr_info_w: bool,
    pub hook_is_debugger_present: bool,
    pub hook_check_remote_debugger_present: bool,
    pub hook_nt_query_information_process: bool,
    pub hook_create_toolhelp32_snapshot: bool,
    pub hook_process32_first_w: bool,
    pub hook_process32_next_w: bool,
    pub hook_exit_process: bool,
    pub hook_get_tick_count: bool,
    pub hook_query_performance_counter: bool,
    pub hook_output_debug_string_a: bool,
    pub hook_add_vectored_exception_handler: bool,
    pub hook_create_thread: bool,
    pub hook_free_library: bool,
    pub hook_crypt_encrypt: bool,
    pub hook_crypt_decrypt: bool,
    pub hook_wsasend: bool,
    pub hook_wsarecv: bool,
    pub hook_send: bool,
    pub hook_recv: bool,
    pub hook_internet_open_w: bool,
    pub hook_internet_connect_w: bool,
    pub hook_http_open_request_w: bool,
    pub hook_internet_read_file: bool,
    pub hook_dns_query_a: bool,
    pub hook_dns_query_w: bool,
    pub hook_cert_verify_certificate_chain_policy: bool,
    pub hook_crypt_hash_data: bool,
    pub hook_copy_file_w: bool,
    pub hook_move_file_w: bool,
    pub hook_get_temp_path_w: bool,
    pub hook_get_temp_file_name_w: bool,
    pub hook_find_first_file_w: bool,
    pub hook_find_next_file_w: bool,
    pub hook_nt_create_thread_ex: bool,
    pub hook_queue_user_apc: bool,
    pub hook_set_thread_context: bool,
    pub hook_win_exec: bool,
    pub hook_system: bool,
    pub hook_shell_execute_w: bool,
    pub hook_shell_execute_ex_w: bool,
    pub hook_create_process_a: bool,
}

impl MonitorConfig {
    pub fn from_preset(preset: Preset) -> Self {
        let mut config = Self::default(); // Start with defaults (all true)
        match preset {
            Preset::Stealth => {
                // Disable most hooks, keep only essential ones for detection
                config.api_hooks_enabled = true;
                config.iat_scan_enabled = false;
                config.string_dump_enabled = false;
                config.vmp_dump_enabled = false;
                config.manual_map_scan_enabled = true; // Keep this for security
                config.network_hooks_enabled = false;
                config.registry_hooks_enabled = false;
                config.crypto_hooks_enabled = false;
                config.log_network_data = false;

                // Disable all individual hooks by default for stealth
                let mut all_hooks_false = config.clone();
                for field in get_mut_field_names() {
                    if let Some(field_mut) = get_field_mut(&mut all_hooks_false, &field) {
                         if field.starts_with("hook_") {
                            *field_mut = false;
                        }
                    }
                }
                config = all_hooks_false;


                // Enable only a few, high-value hooks
                config.hook_virtual_alloc_ex = true;
                config.hook_create_remote_thread = true;
                config.hook_load_library_w = true;
                config.hook_is_debugger_present = true;
                config.hook_check_remote_debugger_present = true;
                config.hook_nt_query_information_process = true;
            }
            Preset::Balanced => {
                // Keep most things enabled, but turn off noisy or performance-heavy features
                config.string_dump_enabled = false;
                config.log_network_data = false;
                config.stack_trace_on_error = true;

                // Disable some less common or potentially noisy hooks
                config.hook_get_tick_count = false;
                config.hook_query_performance_counter = false;
                config.hook_output_debug_string_a = false;
                config.hook_find_first_file_w = false;
                config.hook_find_next_file_w = false;
            }
            Preset::Aggressive => {
                // Default is already aggressive, so just return that.
                // All boolean fields are true.
            }
        }
        config
    }
}

// Helper functions to dynamically access struct fields.
// This is a bit of a workaround for Rust's lack of field iteration.
fn get_field_mut<'a>(config: &'a mut MonitorConfig, field_name: &str) -> Option<&'a mut bool> {
    match field_name {
        "api_hooks_enabled" => Some(&mut config.api_hooks_enabled),
        "iat_scan_enabled" => Some(&mut config.iat_scan_enabled),
        "string_dump_enabled" => Some(&mut config.string_dump_enabled),
        "vmp_dump_enabled" => Some(&mut config.vmp_dump_enabled),
        "manual_map_scan_enabled" => Some(&mut config.manual_map_scan_enabled),
        "network_hooks_enabled" => Some(&mut config.network_hooks_enabled),
        "registry_hooks_enabled" => Some(&mut config.registry_hooks_enabled),
        "crypto_hooks_enabled" => Some(&mut config.crypto_hooks_enabled),
        "log_network_data" => Some(&mut config.log_network_data),
        "stack_trace_on_error" => Some(&mut config.stack_trace_on_error),
        "hook_open_process" => Some(&mut config.hook_open_process),
        "hook_write_process_memory" => Some(&mut config.hook_write_process_memory),
        "hook_virtual_alloc_ex" => Some(&mut config.hook_virtual_alloc_ex),
        "hook_create_file_w" => Some(&mut config.hook_create_file_w),
        "hook_write_file" => Some(&mut config.hook_write_file),
        "hook_http_send_request_w" => Some(&mut config.hook_http_send_request_w),
        "hook_terminate_process" => Some(&mut config.hook_terminate_process),
        "hook_nt_terminate_process" => Some(&mut config.hook_nt_terminate_process),
        "hook_message_box_w" => Some(&mut config.hook_message_box_w),
        "hook_create_process_w" => Some(&mut config.hook_create_process_w),
        "hook_load_library_w" => Some(&mut config.hook_load_library_w),
        "hook_load_library_ex_w" => Some(&mut config.hook_load_library_ex_w),
        "hook_connect" => Some(&mut config.hook_connect),
        "hook_reg_create_key_ex_w" => Some(&mut config.hook_reg_create_key_ex_w),
        "hook_reg_set_value_ex_w" => Some(&mut config.hook_reg_set_value_ex_w),
        "hook_reg_delete_key_w" => Some(&mut config.hook_reg_delete_key_w),
        "hook_reg_open_key_ex_w" => Some(&mut config.hook_reg_open_key_ex_w),
        "hook_reg_query_value_ex_w" => Some(&mut config.hook_reg_query_value_ex_w),
        "hook_reg_enum_key_ex_w" => Some(&mut config.hook_reg_enum_key_ex_w),
        "hook_reg_enum_value_w" => Some(&mut config.hook_reg_enum_value_w),
        "hook_delete_file_w" => Some(&mut config.hook_delete_file_w),
        "hook_create_remote_thread" => Some(&mut config.hook_create_remote_thread),
        "hook_get_addr_info_w" => Some(&mut config.hook_get_addr_info_w),
        "hook_is_debugger_present" => Some(&mut config.hook_is_debugger_present),
        "hook_check_remote_debugger_present" => Some(&mut config.hook_check_remote_debugger_present),
        "hook_nt_query_information_process" => Some(&mut config.hook_nt_query_information_process),
        "hook_create_toolhelp32_snapshot" => Some(&mut config.hook_create_toolhelp32_snapshot),
        "hook_process32_first_w" => Some(&mut config.hook_process32_first_w),
        "hook_process32_next_w" => Some(&mut config.hook_process32_next_w),
        "hook_exit_process" => Some(&mut config.hook_exit_process),
        "hook_get_tick_count" => Some(&mut config.hook_get_tick_count),
        "hook_query_performance_counter" => Some(&mut config.hook_query_performance_counter),
        "hook_output_debug_string_a" => Some(&mut config.hook_output_debug_string_a),
        "hook_add_vectored_exception_handler" => Some(&mut config.hook_add_vectored_exception_handler),
        "hook_create_thread" => Some(&mut config.hook_create_thread),
        "hook_free_library" => Some(&mut config.hook_free_library),
        "hook_crypt_encrypt" => Some(&mut config.hook_crypt_encrypt),
        "hook_crypt_decrypt" => Some(&mut config.hook_crypt_decrypt),
        "hook_wsasend" => Some(&mut config.hook_wsasend),
        "hook_wsarecv" => Some(&mut config.hook_wsarecv),
        "hook_send" => Some(&mut config.hook_send),
        "hook_recv" => Some(&mut config.hook_recv),
        "hook_internet_open_w" => Some(&mut config.hook_internet_open_w),
        "hook_internet_connect_w" => Some(&mut config.hook_internet_connect_w),
        "hook_http_open_request_w" => Some(&mut config.hook_http_open_request_w),
        "hook_internet_read_file" => Some(&mut config.hook_internet_read_file),
        "hook_dns_query_a" => Some(&mut config.hook_dns_query_a),
        "hook_dns_query_w" => Some(&mut config.hook_dns_query_w),
        "hook_cert_verify_certificate_chain_policy" => Some(&mut config.hook_cert_verify_certificate_chain_policy),
        "hook_crypt_hash_data" => Some(&mut config.hook_crypt_hash_data),
        "hook_copy_file_w" => Some(&mut config.hook_copy_file_w),
        "hook_move_file_w" => Some(&mut config.hook_move_file_w),
        "hook_get_temp_path_w" => Some(&mut config.hook_get_temp_path_w),
        "hook_get_temp_file_name_w" => Some(&mut config.hook_get_temp_file_name_w),
        "hook_find_first_file_w" => Some(&mut config.hook_find_first_file_w),
        "hook_find_next_file_w" => Some(&mut config.hook_find_next_file_w),
        "hook_nt_create_thread_ex" => Some(&mut config.hook_nt_create_thread_ex),
        "hook_queue_user_apc" => Some(&mut config.hook_queue_user_apc),
        "hook_set_thread_context" => Some(&mut config.hook_set_thread_context),
        "hook_win_exec" => Some(&mut config.hook_win_exec),
        "hook_system" => Some(&mut config.hook_system),
        "hook_shell_execute_w" => Some(&mut config.hook_shell_execute_w),
        "hook_shell_execute_ex_w" => Some(&mut config.hook_shell_execute_ex_w),
        "hook_create_process_a" => Some(&mut config.hook_create_process_a),
        _ => None,
    }
}

fn get_mut_field_names() -> Vec<String> {
    // This is not ideal, but it's a way to iterate over fields without a macro
    vec![
        "api_hooks_enabled", "iat_scan_enabled", "string_dump_enabled", "vmp_dump_enabled",
        "manual_map_scan_enabled", "network_hooks_enabled", "registry_hooks_enabled",
        "crypto_hooks_enabled", "log_network_data", "stack_trace_on_error",
        "hook_open_process", "hook_write_process_memory", "hook_virtual_alloc_ex",
        "hook_create_file_w", "hook_write_file", "hook_http_send_request_w",
        "hook_terminate_process", "hook_nt_terminate_process", "hook_message_box_w",
        "hook_create_process_w", "hook_load_library_w", "hook_load_library_ex_w",
        "hook_connect", "hook_reg_create_key_ex_w", "hook_reg_set_value_ex_w",
        "hook_reg_delete_key_w", "hook_reg_open_key_ex_w", "hook_reg_query_value_ex_w",
        "hook_reg_enum_key_ex_w", "hook_reg_enum_value_w", "hook_delete_file_w",
        "hook_create_remote_thread", "hook_get_addr_info_w", "hook_is_debugger_present",
        "hook_check_remote_debugger_present", "hook_nt_query_information_process",
        "hook_create_toolhelp32_snapshot", "hook_process32_first_w", "hook_process32_next_w",
        "hook_exit_process", "hook_get_tick_count", "hook_query_performance_counter",
        "hook_output_debug_string_a", "hook_add_vectored_exception_handler",
        "hook_create_thread", "hook_free_library", "hook_crypt_encrypt", "hook_crypt_decrypt",
        "hook_wsasend", "hook_wsarecv", "hook_send", "hook_recv", "hook_internet_open_w",
        "hook_internet_connect_w", "hook_http_open_request_w", "hook_internet_read_file",
        "hook_dns_query_a", "hook_dns_query_w", "hook_cert_verify_certificate_chain_policy",
        "hook_crypt_hash_data", "hook_copy_file_w", "hook_move_file_w",
        "hook_get_temp_path_w", "hook_get_temp_file_name_w", "hook_find_first_file_w",
        "hook_find_next_file_w", "hook_nt_create_thread_ex", "hook_queue_user_apc",
        "hook_set_thread_context", "hook_win_exec", "hook_system", "hook_shell_execute_w",
        "hook_shell_execute_ex_w", "hook_create_process_a",
    ].iter().map(|s| s.to_string()).collect()
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            api_hooks_enabled: true,
            iat_scan_enabled: true,
            string_dump_enabled: false,
            vmp_dump_enabled: true,
            manual_map_scan_enabled: true,
            network_hooks_enabled: true,
            registry_hooks_enabled: true,
            crypto_hooks_enabled: true,
            log_network_data: false,
            suspicion_threshold: 10,
            stack_trace_on_error: true,
            stack_trace_frame_limit: 16,
            // Set all hooks to true by default
            hook_open_process: true,
            hook_write_process_memory: true,
            hook_virtual_alloc_ex: true,
            hook_create_file_w: true,
            hook_write_file: true,
            hook_http_send_request_w: true,
            hook_terminate_process: true,
            hook_nt_terminate_process: true,
            hook_message_box_w: true,
            hook_create_process_w: true,
            hook_load_library_w: true,
            hook_load_library_ex_w: true,
            hook_connect: true,
            hook_reg_create_key_ex_w: true,
            hook_reg_set_value_ex_w: true,
            hook_reg_delete_key_w: true,
            hook_reg_open_key_ex_w: true,
            hook_reg_query_value_ex_w: true,
            hook_reg_enum_key_ex_w: true,
            hook_reg_enum_value_w: true,
            hook_delete_file_w: true,
            hook_create_remote_thread: true,
            hook_get_addr_info_w: true,
            hook_is_debugger_present: true,
            hook_check_remote_debugger_present: true,
            hook_nt_query_information_process: true,
            hook_create_toolhelp32_snapshot: true,
            hook_process32_first_w: true,
            hook_process32_next_w: true,
            hook_exit_process: true,
            hook_get_tick_count: true,
            hook_query_performance_counter: true,
            hook_output_debug_string_a: true,
            hook_add_vectored_exception_handler: true,
            hook_create_thread: true,
            hook_free_library: true,
            hook_crypt_encrypt: true,
            hook_crypt_decrypt: true,
            hook_wsasend: true,
            hook_wsarecv: true,
            hook_send: true,
            hook_recv: true,
            hook_internet_open_w: true,
            hook_internet_connect_w: true,
            hook_http_open_request_w: true,
            hook_internet_read_file: true,
            hook_dns_query_a: true,
            hook_dns_query_w: true,
            hook_cert_verify_certificate_chain_policy: true,
            hook_crypt_hash_data: true,
            hook_copy_file_w: true,
            hook_move_file_w: true,
            hook_get_temp_path_w: true,
            hook_get_temp_file_name_w: true,
            hook_find_first_file_w: true,
            hook_find_next_file_w: true,
            hook_nt_create_thread_ex: true,
            hook_queue_user_apc: true,
            hook_set_thread_context: true,
            hook_win_exec: true,
            hook_system: true,
            hook_shell_execute_w: true,
            hook_shell_execute_ex_w: true,
            hook_create_process_a: true,
        }
    }
}