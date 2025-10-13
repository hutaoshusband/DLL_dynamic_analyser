use shared::logging::{LogLevel, LogEvent};
use crate::log_event;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

/// Periodically scans the process's memory for executable and writable regions.
/// Such regions are suspicious as they can be used for runtime code modification or injection.
pub fn monitor_code_modifications() {
    unsafe {
        let process = GetCurrentProcess();
        let mut address: usize = 0;
        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();

        loop {
            if VirtualQueryEx(
                process,
                address as *const _,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            ) == 0
            {
                break;
            }

            // Check for the suspicious combination of EXECUTE and WRITE permissions.
            if (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0 && mbi.State != 0x10000 /*MEM_FREE*/ {
                let mut buffer = vec![0u8; std::cmp::min(mbi.RegionSize, 4096)];
                let mut bytes_read = 0;

                if ReadProcessMemory(
                    process,
                    mbi.BaseAddress,
                    buffer.as_mut_ptr() as _,
                    buffer.len(),
                    &mut bytes_read,
                ) != 0
                {
                    // For now, we just log the existence of such a region.
                    // A more advanced implementation could hash the region and track changes.
                    log_event(LogLevel::Warn, LogEvent::MemoryScan {
                        status: "Suspicious Memory Region Found".to_string(),
                        result: format!(
                            "Address: {:#X}, Size: {}, Protection: {:#X}",
                            mbi.BaseAddress as usize, mbi.RegionSize, mbi.Protect
                        ),
                    });
                }
            }

            // Move to the next memory region.
            address = (mbi.BaseAddress as usize) + mbi.RegionSize;
        }
        CloseHandle(process);
    }
}