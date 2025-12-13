// Copyright (c) 2024 HUTAOSHUSBAND - Wallbangbros.com/FireflyProtector.xyz


#![allow(dead_code)]

use std::ffi::c_void;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use chrono::Local;
use once_cell::sync::OnceCell;
use widestring::U16CString;
use crate::config::CONFIG;
use crate::ReentrancyGuard;
use iced_x86::{Decoder, Formatter, FormatterOutput, FormatterTextKind, NasmFormatter};
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE, MAX_PATH};
use windows_sys::Win32::System::Diagnostics::Debug::{
    EXCEPTION_POINTERS, ReadProcessMemory, RtlCaptureStackBackTrace,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_OK, MB_ICONERROR};


static LOG_DIR: OnceCell<PathBuf> = OnceCell::new();

static INIT_STEPS: Mutex<Vec<String>> = Mutex::new(Vec::new());

static IN_CRASH_HANDLER: AtomicBool = AtomicBool::new(false);

const MAX_INIT_STEPS: usize = 50;


pub fn init(loader_path: &str) {
    let base_path = PathBuf::from(loader_path);
    let logs_dir = base_path.join("logs");
    
    let _ = fs::create_dir_all(&logs_dir);
    
    let _ = LOG_DIR.set(logs_dir);
    
    log_init_step("Crash logger initialized");
}

fn get_log_dir() -> PathBuf {
    LOG_DIR.get()
        .cloned()
        .unwrap_or_else(|| std::env::temp_dir())
}

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
        
        log_to_file("panic", &message);
        
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


pub fn log_init_step(step: &str) {
    let timestamp = Local::now().format("%H:%M:%S%.3f");
    let pid = unsafe { GetCurrentProcessId() };
    let tid = unsafe { GetCurrentThreadId() };
    
    let entry = format!("[{}] [PID:{} TID:{}] {}", timestamp, pid, tid, step);
    
    if let Ok(mut steps) = INIT_STEPS.lock() {
        steps.push(entry.clone());
        if steps.len() > MAX_INIT_STEPS {
            steps.remove(0);
        }
    }
    
    log_to_file("init", &entry);
}

pub fn log_hook(hook_name: &str, success: bool, address: Option<usize>, details: &str) {
    let status = if success { "SUCCESS" } else { "FAILED" };
    let addr_str = address.map(|a| format!(" at {:#x}", a)).unwrap_or_default();
    
    let message = format!(
        "[HOOK] {} - {}{} | {}",
        hook_name, status, addr_str, details
    );
    
    log_init_step(&message);
}


pub unsafe fn log_crash(exception_info: *mut EXCEPTION_POINTERS) {
    if IN_CRASH_HANDLER.swap(true, Ordering::SeqCst) {
        return;
    }
    
    let pid = GetCurrentProcessId();
    let tid = GetCurrentThreadId();
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
    
    let mut exception_code = 0u32;
    let mut exception_address_ptr: *mut c_void = std::ptr::null_mut();
    
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
            exception_code = record.ExceptionCode as u32;
            let exception_address = record.ExceptionAddress;
            exception_address_ptr = exception_address;
            let exception_name = get_exception_name(exception_code);
            let exception_flags = record.ExceptionFlags;
            
            crash_info.push_str("--- EXCEPTION INFO ---\n");
            crash_info.push_str(&format!("Code: 0x{:08X} ({})\n", exception_code, exception_name));
            crash_info.push_str(&format!("Address: {:?}\n", exception_address));
            crash_info.push_str(&format!("Flags: 0x{:08X}\n", exception_flags));
            
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
                
                crash_info.push_str("--- DEBUG REGISTERS ---\n");
                crash_info.push_str(&format!("DR0: {:#018x}  DR1: {:#018x}\n", ctx.Dr0, ctx.Dr1));
                crash_info.push_str(&format!("DR2: {:#018x}  DR3: {:#018x}\n", ctx.Dr2, ctx.Dr3));
                crash_info.push_str(&format!("DR6: {:#018x}  DR7: {:#018x}\n", ctx.Dr6, ctx.Dr7));
                crash_info.push_str("\n");
            }
        }
    }
    
    crash_info.push_str("--- RECENT INIT STEPS ---\n");
    if let Ok(steps) = INIT_STEPS.lock() {
        let start = if steps.len() > 15 { steps.len() - 15 } else { 0 };
        for step in &steps[start..] {
            crash_info.push_str(&format!("  {}\n", step));
        }
    }
    crash_info.push_str("\n");

    let stack_addresses = capture_stack_addresses(CONFIG.stack_trace_frame_limit);
    let stack_lines: Vec<String> = stack_addresses
        .iter()
        .enumerate()
        .map(|(idx, addr)| {
            let module_desc = if let Some((name, base, offset)) = get_module_for_address(*addr) {
                format!("{} + {:#x}", name, offset)
            } else {
                "UNKNOWN".to_string()
            };
            format!("{:02}: {:#018x} ({})", idx, addr, module_desc)
        })
        .collect();

    crash_info.push_str("--- STACK TRACE ---\n");
    if stack_lines.is_empty() {
        crash_info.push_str("Unable to capture stack trace.\n\n");
    } else {
        for line in &stack_lines {
            crash_info.push_str(line);
            crash_info.push('\n');
        }
        crash_info.push('\n');
    }

    let disasm_lines = if exception_address_ptr.is_null() {
        Vec::new()
    } else {
        disassemble_near(exception_address_ptr as usize, 64, 192)
    };

    crash_info.push_str("--- ASSEMBLY NEAR CRASH ---\n");
    if disasm_lines.is_empty() {
        crash_info.push_str("Disassembly unavailable.\n");
    } else {
        for line in &disasm_lines {
            crash_info.push_str(line);
            crash_info.push('\n');
        }
    }
    crash_info.push_str("\n");
    crash_info.push_str("============================================================\n");
    
    log_to_file("crash", &crash_info);
    
    let exception_name = if exception_code != 0 {
        get_exception_name(exception_code)
    } else {
        "UNKNOWN"
    };
    let exception_addr_display = if exception_address_ptr.is_null() {
        "UNKNOWN".to_string()
    } else {
        format!("{:#018x}", exception_address_ptr as usize)
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
    
    let process_path = get_process_path();
    let process_name = Path::new(&process_path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown_process");
    let stack_section = if stack_lines.is_empty() {
        "Stack trace unavailable".to_string()
    } else {
        stack_lines.join("\n")
    };
    let disasm_section = if disasm_lines.is_empty() {
        "Disassembly unavailable".to_string()
    } else {
        disasm_lines.join("\n")
    };

    let msgbox_content = format!(
        "DLL CRASHED INSIDE OF ({})\n\n\
        Exception: {} at {}\n\n\
        Stack Trace:\n{}\n\n\
        Assembly Around Crash Address:\n{}\n\n\
        Last Steps:\n{}\n\n\
        Full details saved to logs/ folder.",
        process_name,
        exception_name,
        exception_addr_display,
        stack_section,
        disasm_section,
        last_steps
    );

    show_crash_message_box("DLL ANALYZER CRASH", &msgbox_content);

    IN_CRASH_HANDLER.store(false, Ordering::SeqCst);
}


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
        0xC0000194 => "POSSIBLE_DEADLOCK",
        0xE06D7363 => "CPP_EXCEPTION (Microsoft C++ Exception)",
        _ => "UNKNOWN_EXCEPTION",
    }
}

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

fn log_to_file(log_type: &str, message: &str) {
    let _guard = ReentrancyGuard::new();

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

struct DisasmOutput(String);

impl DisasmOutput {
    fn new() -> Self {
        Self(String::new())
    }

    fn clear(&mut self) {
        self.0.clear();
    }

    fn take(&mut self) -> String {
        std::mem::take(&mut self.0)
    }
}

impl FormatterOutput for DisasmOutput {
    fn write(&mut self, text: &str, _kind: FormatterTextKind) {
        self.0.push_str(text);
    }
}

fn get_process_path() -> String {
    let mut buffer = [0u16; MAX_PATH as usize];
    let len = unsafe { GetModuleFileNameW(0, buffer.as_mut_ptr(), buffer.len() as u32) };
    if len == 0 {
        return "unknown".to_string();
    }
    String::from_utf16_lossy(&buffer[..len as usize])
}

fn capture_stack_addresses(max_frames: usize) -> Vec<usize> {
    if max_frames == 0 {
        return Vec::new();
    }
    let mut frames: Vec<*mut c_void> = vec![std::ptr::null_mut(); max_frames];
    let captured = unsafe {
        RtlCaptureStackBackTrace(
            1,
            max_frames as u32,
            frames.as_mut_ptr(),
            std::ptr::null_mut(),
        )
    } as usize;
    frames.into_iter().take(captured).map(|addr| addr as usize).collect()
}

fn read_memory(address: usize, length: usize) -> Option<Vec<u8>> {
    if length == 0 {
        return None;
    }
    let process = unsafe { GetCurrentProcess() };
    let mut buffer = vec![0u8; length];
    let mut bytes_read = 0;
    let success = unsafe {
        ReadProcessMemory(
            process,
            address as *const c_void,
            buffer.as_mut_ptr() as *mut c_void,
            length,
            &mut bytes_read,
        )
    };
    if success != 0 && bytes_read > 0 {
        buffer.truncate(bytes_read as usize);
        Some(buffer)
    } else {
        None
    }
}

fn disassemble_near(address: usize, before: usize, after: usize) -> Vec<String> {
    if after == 0 && before == 0 {
        return Vec::new();
    }
    let start = address.saturating_sub(before);
    let total = before.saturating_add(after);
    if total == 0 {
        return Vec::new();
    }
    let bytes = match read_memory(start, total) {
        Some(data) => data,
        None => return Vec::new(),
    };
    let mut decoder = Decoder::new(64, &bytes, 0);
    decoder.set_ip(start as u64);
    let mut formatter = NasmFormatter::new();
    let mut output = DisasmOutput::new();
    let mut instructions = Vec::new();
    let end_ip = address.saturating_add(after) as u64;
    
    while decoder.can_decode() && instructions.len() < 64 {
        let instruction = decoder.decode();
        output.clear();
        formatter.format(&instruction, &mut output);
        let disasm_text = output.take();
        let marker = if instruction.ip() == address as u64 { "->" } else { "  " };
        instructions.push(format!("{} {:#018x}: {}", marker, instruction.ip(), disasm_text));
        if instruction.ip() >= end_ip {
            break;
        }
    }
    instructions
}


pub fn early_debug_log(message: &str) {
    let _guard = ReentrancyGuard::new();
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
