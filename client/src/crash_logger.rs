// Copyright (c) 2024 HUTAOSHUSBAND - Wallbangbros.com/CodeConfuser.dev
// All rights reserved.

//! Comprehensive crash logging module.
//! 
//! This module provides detailed crash logging with:
//! - Panic hooks for Rust panics
//! - MessageBox display on crash
//! - Detailed log files in logs/ folder
//! - Register dumps, stack traces, module info

#![allow(dead_code)]

use std::ffi::c_void;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use chrono::Local;
use once_cell::sync::OnceCell;
use widestring::U16CString;
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT, EXCEPTION_POINTERS, EXCEPTION_RECORD,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, GetCurrentThreadId};
use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_OK, MB_ICONERROR};

// ============================================================================
// Global State
// ============================================================================

/// Path to the logs directory (set from loader_path config)
static LOG_DIR: OnceCell<PathBuf> = OnceCell::new();

/// Recent initialization steps (circular buffer for context)
static INIT_STEPS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Flag to prevent recursive logging during crash handling
static IN_CRASH_HANDLER: AtomicBool = AtomicBool::new(false);

/// Maximum number of init steps to keep
const MAX_INIT_STEPS: usize = 50;

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the crash logger with the base path for logs.
/// Call this early in DllMain before any other initialization.
pub fn init(loader_path: &str) {
    let base_path = PathBuf::from(loader_path);
    let logs_dir = base_path.join("logs");
    
    // Create logs directory
    let _ = fs::create_dir_all(&logs_dir);
    
    let _ = LOG_DIR.set(logs_dir);
    
    log_init_step("Crash logger initialized");
}

/// Get the logs directory path, with fallback to temp if not initialized
fn get_log_dir() -> PathBuf {
    LOG_DIR.get()
        .cloned()
        .unwrap_or_else(|| std::env::temp_dir())
}

/// Install the Rust panic hook to catch panics
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|panic_info| {
        let pid = unsafe { GetCurrentProcessId() };
        let tid = unsafe { GetCurrentThreadId() };
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        
        let location = panic_info.location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown location".to_string());
        
        let payload = if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "Unknown panic payload".to_string()
        };
        
        let message = format!(
            "========== RUST PANIC ==========\n\
            Timestamp: {}\n\
            PID: {} | TID: {}\n\
            Location: {}\n\
            Message: {}\n\
            ================================",
            timestamp, pid, tid, location, payload
        );
        
        // Log to file
        log_to_file("panic", &message);
        
        // Show MessageBox
        show_crash_message_box("RUST PANIC", &format!(
            "A panic occurred in the DLL!\n\n\
            Location: {}\n\
            Message: {}\n\n\
            Check logs folder for details.",
            location, payload
        ));
    }));
    
    log_init_step("Panic hook installed");
}

// ============================================================================
// Step Logging
// ============================================================================

/// Log an initialization step. These are kept in memory for crash context.
pub fn log_init_step(step: &str) {
    let timestamp = Local::now().format("%H:%M:%S%.3f");
    let pid = unsafe { GetCurrentProcessId() };
    let tid = unsafe { GetCurrentThreadId() };
    
    let entry = format!("[{}] [PID:{} TID:{}] {}", timestamp, pid, tid, step);
    
    // Add to in-memory buffer
    if let Ok(mut steps) = INIT_STEPS.lock() {
        steps.push(entry.clone());
        // Keep only the last N steps
        if steps.len() > MAX_INIT_STEPS {
            steps.remove(0);
        }
    }
    
    // Also write to init log file
    log_to_file("init", &entry);
}

/// Log a hook installation with success/failure status
pub fn log_hook(hook_name: &str, success: bool, address: Option<usize>, details: &str) {
    let status = if success { "SUCCESS" } else { "FAILED" };
    let addr_str = address.map(|a| format!(" at {:#x}", a)).unwrap_or_default();
    
    let message = format!(
        "[HOOK] {} - {}{} | {}",
        hook_name, status, addr_str, details
    );
    
    log_init_step(&message);
}

// ============================================================================
// Crash Logging
// ============================================================================

/// Main crash logging function called from VEH
/// This logs detailed crash info and shows a MessageBox
pub unsafe fn log_crash(exception_info: *mut EXCEPTION_POINTERS) {
    // Prevent recursive crashes during logging
    if IN_CRASH_HANDLER.swap(true, Ordering::SeqCst) {
        return;
    }
    
    let pid = GetCurrentProcessId();
    let tid = GetCurrentThreadId();
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
    
    let mut crash_info = String::new();
    crash_info.push_str("\n============================================================\n");
    crash_info.push_str("         CRASH DETECTED - DLL ANALYZER\n");
    crash_info.push_str("============================================================\n\n");
    crash_info.push_str(&format!("Timestamp: {}\n", timestamp));
    crash_info.push_str(&format!("Process ID: {}\n", pid));
    crash_info.push_str(&format!("Thread ID: {}\n\n", tid));
    
    if !exception_info.is_null() {
        let exception_record = (*exception_info).ExceptionRecord;
        let context_record = (*exception_info).ContextRecord;
        
        if !exception_record.is_null() {
            let record = &*exception_record;
            let exception_code = record.ExceptionCode as u32;
            let exception_address = record.ExceptionAddress;
            let exception_flags = record.ExceptionFlags;
            
            let exception_name = get_exception_name(exception_code);
            
            crash_info.push_str("--- EXCEPTION INFO ---\n");
            crash_info.push_str(&format!("Code: 0x{:08X} ({})\n", exception_code, exception_name));
            crash_info.push_str(&format!("Address: {:?}\n", exception_address));
            crash_info.push_str(&format!("Flags: 0x{:08X}\n", exception_flags));
            
            // Access violation details
            if exception_code == 0xC0000005 && record.NumberParameters >= 2 {
                let access_type = record.ExceptionInformation[0];
                let access_address = record.ExceptionInformation[1];
                let access_str = match access_type {
                    0 => "READ",
                    1 => "WRITE",
                    8 => "DEP_VIOLATION (Execute on NX memory)",
                    _ => "UNKNOWN",
                };
                crash_info.push_str(&format!(
                    "Access Type: {} at {:#018x}\n",
                    access_str, access_address
                ));
            }
            
            // Find which module crashed
            if let Some((name, base, offset)) = get_module_for_address(exception_address as usize) {
                crash_info.push_str(&format!(
                    "Module: {} (base: {:#x}, offset: +{:#x})\n",
                    name, base, offset
                ));
            } else {
                crash_info.push_str("Module: UNKNOWN (possibly shellcode or unmapped memory)\n");
            }
            crash_info.push_str("\n");
        }
        
        // Register dump
        if !context_record.is_null() {
            #[cfg(target_arch = "x86_64")]
            {
                let ctx = &*context_record;
                crash_info.push_str("--- REGISTERS (x64) ---\n");
                crash_info.push_str(&format!("RAX: {:#018x}  RBX: {:#018x}\n", ctx.Rax, ctx.Rbx));
                crash_info.push_str(&format!("RCX: {:#018x}  RDX: {:#018x}\n", ctx.Rcx, ctx.Rdx));
                crash_info.push_str(&format!("RSI: {:#018x}  RDI: {:#018x}\n", ctx.Rsi, ctx.Rdi));
                crash_info.push_str(&format!("RBP: {:#018x}  RSP: {:#018x}\n", ctx.Rbp, ctx.Rsp));
                crash_info.push_str(&format!("R8:  {:#018x}  R9:  {:#018x}\n", ctx.R8, ctx.R9));
                crash_info.push_str(&format!("R10: {:#018x}  R11: {:#018x}\n", ctx.R10, ctx.R11));
                crash_info.push_str(&format!("R12: {:#018x}  R13: {:#018x}\n", ctx.R12, ctx.R13));
                crash_info.push_str(&format!("R14: {:#018x}  R15: {:#018x}\n", ctx.R14, ctx.R15));
                crash_info.push_str(&format!("RIP: {:#018x}  EFLAGS: {:#010x}\n", ctx.Rip, ctx.EFlags));
                crash_info.push_str(&format!("CS: {:04x}  SS: {:04x}  DS: {:04x}\n", ctx.SegCs, ctx.SegSs, ctx.SegDs));
                crash_info.push_str(&format!("ES: {:04x}  FS: {:04x}  GS: {:04x}\n", ctx.SegEs, ctx.SegFs, ctx.SegGs));
                crash_info.push_str("\n");
                
                // Debug registers (relevant for hardware BP issues)
                crash_info.push_str("--- DEBUG REGISTERS ---\n");
                crash_info.push_str(&format!("DR0: {:#018x}  DR1: {:#018x}\n", ctx.Dr0, ctx.Dr1));
                crash_info.push_str(&format!("DR2: {:#018x}  DR3: {:#018x}\n", ctx.Dr2, ctx.Dr3));
                crash_info.push_str(&format!("DR6: {:#018x}  DR7: {:#018x}\n", ctx.Dr6, ctx.Dr7));
                crash_info.push_str("\n");
            }
        }
    }
    
    // Recent initialization steps
    crash_info.push_str("--- RECENT INIT STEPS ---\n");
    if let Ok(steps) = INIT_STEPS.lock() {
        let start = if steps.len() > 15 { steps.len() - 15 } else { 0 };
        for step in &steps[start..] {
            crash_info.push_str(&format!("  {}\n", step));
        }
    }
    crash_info.push_str("\n");
    
    crash_info.push_str("============================================================\n");
    
    // Write to file
    log_to_file("crash", &crash_info);
    
    // Build MessageBox content (shorter version)
    let exception_name = if !exception_info.is_null() && !(*exception_info).ExceptionRecord.is_null() {
        let code = (*(*exception_info).ExceptionRecord).ExceptionCode as u32;
        get_exception_name(code)
    } else {
        "UNKNOWN"
    };
    
    let exception_addr = if !exception_info.is_null() && !(*exception_info).ExceptionRecord.is_null() {
        format!("{:?}", (*(*exception_info).ExceptionRecord).ExceptionAddress)
    } else {
        "UNKNOWN".to_string()
    };
    
    let last_steps: String = INIT_STEPS.lock()
        .map(|steps| {
            let start = if steps.len() > 5 { steps.len() - 5 } else { 0 };
            steps[start..].iter()
                .map(|s| format!("• {}", s.split("] ").last().unwrap_or(s)))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_else(|_| "Unable to get steps".to_string());
    
    let msgbox_content = format!(
        "Exception: {} at {}\n\n\
        Last Steps:\n{}\n\n\
        Full details saved to logs/ folder.",
        exception_name, exception_addr, last_steps
    );
    
    show_crash_message_box("DLL ANALYZER CRASH", &msgbox_content);
    
    IN_CRASH_HANDLER.store(false, Ordering::SeqCst);
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get human-readable exception name
fn get_exception_name(code: u32) -> &'static str {
    match code {
        0xC0000005 => "ACCESS_VIOLATION",
        0xC000001D => "ILLEGAL_INSTRUCTION",
        0xC0000094 => "INTEGER_DIVIDE_BY_ZERO",
        0xC0000095 => "INTEGER_OVERFLOW",
        0xC0000096 => "PRIVILEGED_INSTRUCTION",
        0xC00000FD => "STACK_OVERFLOW",
        0xC000008C => "ARRAY_BOUNDS_EXCEEDED",
        0xC000008D => "FLOAT_DENORMAL_OPERAND",
        0xC000008E => "FLOAT_DIVIDE_BY_ZERO",
        0xC000008F => "FLOAT_INEXACT_RESULT",
        0xC0000090 => "FLOAT_INVALID_OPERATION",
        0xC0000091 => "FLOAT_OVERFLOW",
        0xC0000092 => "FLOAT_STACK_CHECK",
        0xC0000093 => "FLOAT_UNDERFLOW",
        0x80000003 => "BREAKPOINT",
        0x80000004 => "SINGLE_STEP",
        0xC0000026 => "INVALID_DISPOSITION",
        0xC000008E => "FLT_DIVIDE_BY_ZERO",
        0xC0000194 => "POSSIBLE_DEADLOCK",
        0xE06D7363 => "CPP_EXCEPTION (Microsoft C++ Exception)",
        _ => "UNKNOWN_EXCEPTION",
    }
}

/// Find which module contains a given address
fn get_module_for_address(addr: usize) -> Option<(String, usize, usize)> {
    unsafe {
        let pid = GetCurrentProcessId();
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }
        
        let mut module_entry: MODULEENTRY32W = std::mem::zeroed();
        module_entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
        
        let mut result = None;
        
        if Module32FirstW(snapshot, &mut module_entry) != 0 {
            loop {
                let base = module_entry.modBaseAddr as usize;
                let size = module_entry.modBaseSize as usize;
                
                if addr >= base && addr < base + size {
                    let name_len = module_entry.szModule.iter()
                        .position(|&c| c == 0)
                        .unwrap_or(module_entry.szModule.len());
                    let name = String::from_utf16_lossy(&module_entry.szModule[..name_len]);
                    let offset = addr - base;
                    result = Some((name, base, offset));
                    break;
                }
                
                if Module32NextW(snapshot, &mut module_entry) == 0 {
                    break;
                }
            }
        }
        
        CloseHandle(snapshot);
        result
    }
}

/// Write a message to a log file
fn log_to_file(log_type: &str, message: &str) {
    let log_dir = get_log_dir();
    let pid = unsafe { GetCurrentProcessId() };
    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    
    let filename = format!("{}_{}.log", log_type, pid);
    let log_path = log_dir.join(&filename);
    
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        let _ = writeln!(file, "{}", message);
        let _ = file.flush();
    }
}

/// Show a MessageBox with crash information
fn show_crash_message_box(title: &str, message: &str) {
    let title_wide = match U16CString::from_str(title) {
        Ok(s) => s,
        Err(_) => return,
    };
    
    let message_wide = match U16CString::from_str(message) {
        Ok(s) => s,
        Err(_) => return,
    };
    
    unsafe {
        MessageBoxW(
            0,
            message_wide.as_ptr(),
            title_wide.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}

// ============================================================================
// Quick Debug Log (for use before crash_logger is initialized)
// ============================================================================

/// Early debug log to temp directory (for use before crash_logger is fully initialized)
pub fn early_debug_log(message: &str) {
    let pid = unsafe { GetCurrentProcessId() };
    let log_path = std::env::temp_dir().join(format!("analyzer_early_debug_{}.log", pid));
    
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let _ = writeln!(file, "[{}] {}", timestamp, message);
    }
}
