//! The current process token: elevation and privileges.

use std::io;

use anyhow::{Result, bail};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_NOT_ALL_ASSIGNED, GetLastError, HANDLE, LUID};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY, TokenElevation,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::wide;

struct Token(HANDLE);

impl Token {
    fn open(access: u32) -> io::Result<Self> {
        let mut h: HANDLE = std::ptr::null_mut();
        // SAFETY: GetCurrentProcess returns a pseudo-handle; `h` is a valid out pointer.
        if unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut h) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Token(h))
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: we own the handle and close it exactly once.
        unsafe { CloseHandle(self.0) };
    }
}

/// Whether the process runs with a full (elevated) administrator token.
pub fn is_elevated() -> bool {
    let Ok(token) = Token::open(TOKEN_QUERY) else { return false };
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut len = 0u32;
    // SAFETY: the buffer is a TOKEN_ELEVATION of the size we pass.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    };
    ok != 0 && elevation.TokenIsElevated != 0
}

/// Enables a privilege (e.g. `SeRestorePrivilege`) on the process token. Privileges an
/// administrator holds but has disabled by default must be enabled before APIs like
/// `RegLoadKey` accept the call.
pub fn enable_privilege(name: &str) -> Result<()> {
    let token = Token::open(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY)?;
    let mut luid = LUID { LowPart: 0, HighPart: 0 };
    let name_w = wide(name);
    // SAFETY: `name_w` is NUL-terminated; `luid` is a valid out pointer.
    if unsafe { LookupPrivilegeValueW(std::ptr::null(), name_w.as_ptr(), &mut luid) } == 0 {
        bail!("unknown privilege {name}: {}", io::Error::last_os_error());
    }
    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
    };
    // SAFETY: `tp` is a fully initialized TOKEN_PRIVILEGES with one entry.
    let ok = unsafe { AdjustTokenPrivileges(token.0, 0, &tp, 0, std::ptr::null_mut(), std::ptr::null_mut()) };
    // AdjustTokenPrivileges "succeeds" even when the privilege is not held; check explicitly.
    // SAFETY: trivially safe.
    if ok == 0 || unsafe { GetLastError() } == ERROR_NOT_ALL_ASSIGNED {
        bail!("cannot enable {name} (is the agent running as administrator?)");
    }
    Ok(())
}
