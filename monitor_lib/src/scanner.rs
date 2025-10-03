use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
};
use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows_sys::Win32::System::Threading::GetCurrentProcess;

/// Parses a signature string (e.g., "48 89 5C 24 ? 48") into a byte vector and a mask vector.
/// '?' or '??' are treated as wildcards.
fn parse_signature(signature: &str) -> (Vec<u8>, Vec<bool>) {
    let mut sig = Vec::new();
    let mut mask = Vec::new();
    for byte_str in signature.split_whitespace() {
        if byte_str == "?" || byte_str == "??" {
            sig.push(0);
            mask.push(false);
        } else if let Ok(byte) = u8::from_str_radix(byte_str, 16) {
            sig.push(byte);
            mask.push(true);
        }
    }
    (sig, mask)
}

/// Searches a given memory region for a byte signature.
fn signature_scan(
    buffer: &[u8],
    signature: &[u8],
    mask: &[bool],
) -> Option<usize> {
    let sig_len = signature.len();
    if buffer.len() < sig_len {
        return None;
    }

    for i in 0..=(buffer.len() - sig_len) {
        let mut found = true;
        for j in 0..sig_len {
            if mask[j] && buffer[i + j] != signature[j] {
                found = false;
                break;
            }
        }
        if found {
            return Some(i);
        }
    }
    None
}

/// Finds a function address in the current process's memory by its byte signature.
pub fn find_signature(signature_str: &str) -> Option<*const u8> {
    let (signature, mask) = parse_signature(signature_str);
    let process_handle = unsafe { GetCurrentProcess() };
    let mut base_address: usize = 0;

    loop {
        let mut mem_info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let result = unsafe {
            VirtualQueryEx(
                process_handle,
                base_address as *const _,
                &mut mem_info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if result == 0 {
            break; // Reached the end of the process's memory space.
        }

        let is_executable_and_committed = mem_info.State == MEM_COMMIT
            && (mem_info.Protect & PAGE_EXECUTE_READ != 0
                || mem_info.Protect & PAGE_EXECUTE_READWRITE != 0
                || mem_info.Protect & PAGE_EXECUTE_WRITECOPY != 0);

        if is_executable_and_committed {
            let region_size = mem_info.RegionSize;
            let mut buffer = vec![0u8; region_size];
            let mut bytes_read: usize = 0;

            let read_success = unsafe {
                ReadProcessMemory(
                    process_handle,
                    mem_info.BaseAddress,
                    buffer.as_mut_ptr() as *mut _,
                    region_size,
                    &mut bytes_read,
                )
            } != 0;

            if read_success && bytes_read > 0 {
                if let Some(offset) = signature_scan(&buffer[..bytes_read], &signature, &mask) {
                    return Some((mem_info.BaseAddress as usize + offset) as *const u8);
                }
            }
        }

        base_address = mem_info.BaseAddress as usize + mem_info.RegionSize;
    }

    None
}

/// Gets the start and end address of the main module.
pub fn get_main_module_range() -> Option<(usize, usize)> {
    let process_handle = unsafe { GetCurrentProcess() };
    let base_address: usize = 0;
    let mut mem_info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };

    // The first memory region of a process is typically its main module.
    if unsafe {
        VirtualQueryEx(
            process_handle,
            base_address as *const _,
            &mut mem_info,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    } != 0
    {
        // Check for the DOS header magic number to be more certain.
        let mut dos_header: IMAGE_DOS_HEADER = unsafe { std::mem::zeroed() };
        if unsafe {
            ReadProcessMemory(
                process_handle,
                mem_info.BaseAddress,
                &mut dos_header as *mut _ as *mut _,
                std::mem::size_of::<IMAGE_DOS_HEADER>(),
                &mut 0,
            )
        } != 0 && dos_header.e_magic == 0x5A4D
        {
            // This is likely the main module. We need to find its total size.
            // This is a simplification; a full-fledged solution would parse the PE header.
            // For now, we'll scan the first few committed regions.
            // A more robust approach might be needed if the .exe is large or has many sections.
            let start = mem_info.BaseAddress as usize;
            // Let's find the end of the module by finding the end of the contiguous executable memory.
            let mut current_addr = start;
            loop {
                let mut next_mem_info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
                 if unsafe {
                    VirtualQueryEx(
                        process_handle,
                        current_addr as *const _,
                        &mut next_mem_info,
                        std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                    )
                } == 0 { break; }

                if next_mem_info.AllocationBase != mem_info.AllocationBase {
                    // We've hit a new allocation region, so the module has ended.
                    break;
                }
                 current_addr = next_mem_info.BaseAddress as usize + next_mem_info.RegionSize;
            }

            return Some((start, current_addr));
        }
    }

    None
}

/// Placeholder function for manual mapping detection.
/// This should be implemented based on your specific detection logic.
pub fn scan_for_manual_mapping() {
    // TODO: Implement manual mapping detection logic
    // This could involve:
    // - Scanning for suspicious memory regions
    // - Checking for modules not in the PEB
    // - Detecting anomalies in the module list
}