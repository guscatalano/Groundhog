//! Encrypting small secrets at rest with DPAPI, scoped to the current user: only this account
//! on this machine can decrypt them.

use std::io;

use anyhow::{Result, bail};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};

fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 }
}

/// Copies out and frees a blob DPAPI allocated.
fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
    // SAFETY: DPAPI filled `out` with a buffer of `cbData` bytes that we now own.
    let v = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
    // SAFETY: allocated by DPAPI with LocalAlloc.
    unsafe { LocalFree(out.pbData.cast()) };
    v
}

pub fn protect(data: &[u8]) -> Result<Vec<u8>> {
    let input = blob(data);
    let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    // SAFETY: `input` borrows `data` for the call; no prompt, no entropy.
    let ok = unsafe {
        CryptProtectData(
            &input,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    };
    if ok == 0 {
        bail!("encrypting secrets: {}", io::Error::last_os_error());
    }
    Ok(take(out))
}

pub fn unprotect(data: &[u8]) -> Result<Vec<u8>> {
    let input = blob(data);
    let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    // SAFETY: as in `protect`.
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    };
    if ok == 0 {
        bail!("decrypting secrets (were they saved by another account?): {}", io::Error::last_os_error());
    }
    Ok(take(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_is_not_plain_text() {
        let secret = b"hunter2-groundhog";
        let sealed = protect(secret).unwrap();
        assert!(!sealed.windows(secret.len()).any(|w| w == secret));
        assert_eq!(unprotect(&sealed).unwrap(), secret);
        assert!(unprotect(b"not a dpapi blob").is_err());
    }
}
