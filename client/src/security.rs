// Copyright (c) 2024 HUTAOSHUSBAND - Wallbangbros.com/FireflyProtector.xyz


#![allow(dead_code, unused_variables)]
use std::mem::zeroed;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;
use widestring::U16CString;

pub struct SecurityAttributes {
    pub attributes: SECURITY_ATTRIBUTES,
    security_descriptor: PSECURITY_DESCRIPTOR,
}

impl SecurityAttributes {
    pub unsafe fn new() -> Option<Self> {
        let sddl = U16CString::from_str("D:(A;OICI;GA;;;WD)").ok()?; // Grant all access to everyone
        let mut security_descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();

        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SECURITY_DESCRIPTOR_REVISION as u32,
            &mut security_descriptor,
            std::ptr::null_mut(),
        ) == 0
        {
            return None;
        }

        let mut sa: SECURITY_ATTRIBUTES = zeroed();
        sa.nLength = std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
        sa.lpSecurityDescriptor = security_descriptor;
        sa.bInheritHandle = 0; // FALSE

        Some(Self {
            attributes: sa,
            security_descriptor,
        })
    }
}

impl Drop for SecurityAttributes {
    fn drop(&mut self) {
        if !self.security_descriptor.is_null() {
            unsafe { LocalFree(self.security_descriptor as *mut _) };
        }
    }
}