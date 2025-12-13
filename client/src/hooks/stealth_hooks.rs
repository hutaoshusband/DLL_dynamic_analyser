// Copyright (c) 2024 HUTAOSHUSBAND - Wallbangbros.com/FireflyProtector.xyz

use crate::{log_event, ReentrancyGuard};
use serde_json::json;
use shared::logging::{LogEvent, LogLevel};
use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use windows_sys::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, GetThreadContext, SetThreadContext, CONTEXT, EXCEPTION_POINTERS,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, GetCurrentThread};

const EXCEPTION_SINGLE_STEP: u32 = 0x80000004;
const CONTEXT_DEBUG_REGISTERS: u32 = 0x00100010; // amd64

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

unsafe fn apply_hw_bp_to_thread(
    thread: windows_sys::Win32::Foundation::HANDLE,
    address: usize,
    dr_index: u8,
) -> bool {
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

    ctx.Dr7 |= 1 << (dr_index * 2);
    ctx.Dr7 &= !(0b11 << (16 + dr_index * 4));
    ctx.Dr7 &= !(0b11 << (18 + dr_index * 4));

    if SetThreadContext(thread, &ctx) == 0 {
        return false;
    }

    true
}

pub unsafe extern "system" fn stealth_veh_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    if exception_info.is_null() {
        return 0; // EXCEPTION_CONTINUE_SEARCH
    }

    let record = &*(*exception_info).ExceptionRecord;
    let context = &mut *(*exception_info).ContextRecord;

    if record.ExceptionCode as u32 == EXCEPTION_SINGLE_STEP {
        let exception_addr = record.ExceptionAddress as usize;

        let mut hit_index = None;
        if exception_addr == DR0_HOOK.load(Ordering::SeqCst) {
            hit_index = Some(0);
        } else if exception_addr == DR1_HOOK.load(Ordering::SeqCst) {
            hit_index = Some(1);
        } else if exception_addr == DR2_HOOK.load(Ordering::SeqCst) {
            hit_index = Some(2);
        } else if exception_addr == DR3_HOOK.load(Ordering::SeqCst) {
            hit_index = Some(3);
        }

        if let Some(index) = hit_index {
            if let Some(_guard) = ReentrancyGuard::new() {
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
            }

            context.EFlags |= 0x10000;

            return -1; // EXCEPTION_CONTINUE_EXECUTION
        }
    }

    0 // EXCEPTION_CONTINUE_SEARCH
}

pub unsafe fn initialize_stealth_hooks() {
    crate::crash_logger::log_init_step("Stealth hooks: Starting initialization");
    crate::crash_logger::log_hook("stealth_veh_handler", true, None, "Registering VEH handler");

    let handle = AddVectoredExceptionHandler(1, Some(stealth_veh_handler));
    if handle.is_null() {
        crate::crash_logger::log_hook(
            "stealth_veh_handler",
            false,
            None,
            "VEH registration failed",
        );
        log_event(
            LogLevel::Error,
            LogEvent::Error {
                source: "StealthHooks".to_string(),
                message: "Failed to register VEH".to_string(),
            },
        );
        return;
    }
    crate::crash_logger::log_hook(
        "stealth_veh_handler",
        true,
        None,
        "VEH registered successfully",
    );

    crate::crash_logger::log_init_step("Stealth hooks: Getting ntdll.dll handle");
    let ntdll = windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(
        widestring::U16CString::from_str("ntdll.dll")
            .unwrap()
            .as_ptr(),
    );

    if ntdll != 0 {
        crate::crash_logger::log_init_step(&format!("Stealth hooks: ntdll.dll at {:#x}", ntdll));

        crate::crash_logger::log_init_step("Stealth hooks: Resolving NtQuerySystemInformation");
        let func_name = b"NtQuerySystemInformation\0";
        if let Some(addr) =
            windows_sys::Win32::System::LibraryLoader::GetProcAddress(ntdll, func_name.as_ptr())
        {
            crate::crash_logger::log_hook(
                "NtQuerySystemInformation",
                true,
                Some(addr as usize),
                "Function resolved, applying HW BP to all threads",
            );
            apply_to_all_threads(addr as usize, 0);
            crate::crash_logger::log_hook(
                "NtQuerySystemInformation",
                true,
                Some(addr as usize),
                "HW BP applied to all threads",
            );
        } else {
            crate::crash_logger::log_hook(
                "NtQuerySystemInformation",
                false,
                None,
                "Failed to resolve function address",
            );
        }
    } else {
        crate::crash_logger::log_init_step("Stealth hooks: FAILED to get ntdll.dll handle!");
    }

    crate::crash_logger::log_init_step("Stealth hooks: Initialization complete");
}

unsafe fn apply_to_all_threads(address: usize, dr_index: u8) {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows_sys::Win32::System::Threading::{OpenThread, THREAD_ALL_ACCESS};

    crate::crash_logger::log_init_step(&format!(
        "Stealth hooks: apply_to_all_threads(addr={:#x}, dr={})",
        address, dr_index
    ));

    let pid = GetCurrentProcessId();
    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if snapshot == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        crate::crash_logger::log_init_step("Stealth hooks: CreateToolhelp32Snapshot FAILED");
        return;
    }

    let mut te: THREADENTRY32 = std::mem::zeroed();
    te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

    let mut thread_count = 0;
    let mut success_count = 0;

    if Thread32First(snapshot, &mut te) != 0 {
        loop {
            if te.th32OwnerProcessID == pid {
                thread_count += 1;
                let h_thread = OpenThread(THREAD_ALL_ACCESS, 0, te.th32ThreadID);
                if h_thread != 0 {
                    if apply_hw_bp_to_thread(h_thread, address, dr_index) {
                        success_count += 1;
                    }
                    windows_sys::Win32::Foundation::CloseHandle(h_thread);
                }
            }
            if Thread32Next(snapshot, &mut te) == 0 {
                break;
            }
        }
    }
    windows_sys::Win32::Foundation::CloseHandle(snapshot);

    crate::crash_logger::log_init_step(&format!(
        "Stealth hooks: Applied HW BP to {}/{} threads",
        success_count, thread_count
    ));
}
