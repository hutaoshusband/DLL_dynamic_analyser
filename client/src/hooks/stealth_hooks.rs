// Copyright (c) 2024 HUTAOSHUSBAND - Wallbangbros.com/CodeConfuser.dev
// All rights reserved.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::ffi::c_void;
use windows_sys::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, GetThreadContext, SetThreadContext, CONTEXT, EXCEPTION_POINTERS,
};
use windows_sys::Win32::System::Threading::{GetCurrentThread, GetCurrentProcessId};
use crate::log_event;
use shared::logging::{LogLevel, LogEvent};
use serde_json::json;

// Define EXCEPTION_SINGLE_STEP manually if not found (it's usually 0x80000004)
const EXCEPTION_SINGLE_STEP: u32 = 0x80000004;
const CONTEXT_DEBUG_REGISTERS: u32 = 0x00100010; // amd64

// Global array to track which addresses we have hooked with which DR register.
// 0 = unused.
static DR0_HOOK: AtomicUsize = AtomicUsize::new(0);
static DR1_HOOK: AtomicUsize = AtomicUsize::new(0);
static DR2_HOOK: AtomicUsize = AtomicUsize::new(0);
static DR3_HOOK: AtomicUsize = AtomicUsize::new(0);

pub fn install_hw_bp(address: usize, dr_index: u8) -> bool {
    unsafe {
        let thread = GetCurrentThread();
        match dr_index {
            0 => DR0_HOOK.store(address, Ordering::SeqCst),
            1 => DR1_HOOK.store(address, Ordering::SeqCst),
            2 => DR2_HOOK.store(address, Ordering::SeqCst),
            3 => DR3_HOOK.store(address, Ordering::SeqCst),
            _ => return false,
        }

        apply_hw_bp_to_thread(thread, address, dr_index)
    }
}

unsafe fn apply_hw_bp_to_thread(thread: windows_sys::Win32::Foundation::HANDLE, address: usize, dr_index: u8) -> bool {
    let mut ctx: CONTEXT = std::mem::zeroed();
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    if GetThreadContext(thread, &mut ctx) == 0 {
        return false;
    }

    match dr_index {
        0 => ctx.Dr0 = address as u64,
        1 => ctx.Dr1 = address as u64,
        2 => ctx.Dr2 = address as u64,
        3 => ctx.Dr3 = address as u64,
        _ => return false,
    }

    // Enable local breakpoint (Lx)
    ctx.Dr7 |= 1 << (dr_index * 2);
    // Clear R/W bits to 00 (Execute) for this register
    ctx.Dr7 &= !(0b11 << (16 + dr_index * 4));
    // Clear Len bits to 00 (1 byte) for this register
    ctx.Dr7 &= !(0b11 << (18 + dr_index * 4));

    if SetThreadContext(thread, &ctx) == 0 {
        return false;
    }
    
    true
}

// The VEH Handler
pub unsafe extern "system" fn stealth_veh_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    if exception_info.is_null() {
        return 0; // EXCEPTION_CONTINUE_SEARCH
    }

    let record = &*(*exception_info).ExceptionRecord;
    let context = &mut *(*exception_info).ContextRecord;

    if record.ExceptionCode as u32 == EXCEPTION_SINGLE_STEP {
        let exception_addr = record.ExceptionAddress as usize;

        // Check if this matches one of our hooks
        let mut hit_index = None;
        if exception_addr == DR0_HOOK.load(Ordering::SeqCst) { hit_index = Some(0); }
        else if exception_addr == DR1_HOOK.load(Ordering::SeqCst) { hit_index = Some(1); }
        else if exception_addr == DR2_HOOK.load(Ordering::SeqCst) { hit_index = Some(2); }
        else if exception_addr == DR3_HOOK.load(Ordering::SeqCst) { hit_index = Some(3); }

        if let Some(index) = hit_index {
            // It's our hook!
            log_event(
                LogLevel::Warn,
                LogEvent::ApiHook {
                    function_name: format!("StealthHook[Dr{}]", index),
                    parameters: json!({
                        "address": format!("{:#x}", exception_addr),
                        "note": "Hardware Breakpoint Hit - Stealth Hook",
                        "rcx": format!("{:#x}", context.Rcx),
                        "rdx": format!("{:#x}", context.Rdx),
                    }),
                    stack_trace: None,
                },
            );

            // Important: Set Resume Flag (RF) in EFLAGS (bit 16)
            context.EFlags |= 0x10000;

            return -1; // EXCEPTION_CONTINUE_EXECUTION
        }
    }

    0 // EXCEPTION_CONTINUE_SEARCH
}

pub unsafe fn initialize_stealth_hooks() {
    // Register VEH
    let handle = AddVectoredExceptionHandler(1, Some(stealth_veh_handler));
    if handle.is_null() {
        log_event(LogLevel::Error, LogEvent::Error { 
            source: "StealthHooks".to_string(), 
            message: "Failed to register VEH".to_string() 
        });
        return;
    }

    // Apply proof-of-concept hook on NtQuerySystemInformation
    let ntdll = windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(
        widestring::U16CString::from_str("ntdll.dll").unwrap().as_ptr()
    );
    
    if ntdll != 0 {
        let func_name = b"NtQuerySystemInformation\0";
        if let Some(addr) = windows_sys::Win32::System::LibraryLoader::GetProcAddress(ntdll, func_name.as_ptr()) {
            apply_to_all_threads(addr as usize, 0);
        }
    }
}

unsafe fn apply_to_all_threads(address: usize, dr_index: u8) {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32
    };
    use windows_sys::Win32::System::Threading::{OpenThread, THREAD_ALL_ACCESS};

    let pid = GetCurrentProcessId();
    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if snapshot == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return;
    }

    let mut te: THREADENTRY32 = std::mem::zeroed();
    te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

    if Thread32First(snapshot, &mut te) != 0 {
        loop {
            if te.th32OwnerProcessID == pid {
                 let h_thread = OpenThread(THREAD_ALL_ACCESS, 0, te.th32ThreadID);
                 if h_thread != 0 {
                     apply_hw_bp_to_thread(h_thread, address, dr_index);
                     windows_sys::Win32::Foundation::CloseHandle(h_thread);
                 }
            }
            if Thread32Next(snapshot, &mut te) == 0 {
                break;
            }
        }
    }
    windows_sys::Win32::Foundation::CloseHandle(snapshot);
}
