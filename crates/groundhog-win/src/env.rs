//! User environment variables and PATH, persisted in `HKCU\Environment`.

use std::io;

use anyhow::{Result, bail};
use windows_sys::Win32::System::Environment::ExpandEnvironmentStringsW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    HWND_BROADCAST, SMTO_ABORTIFHUNG, SendMessageTimeoutW, WM_SETTINGCHANGE,
};
use winreg::RegKey;
use winreg::enums::HKEY_CURRENT_USER;

use crate::registry::{self, Data};
use crate::wide;

const ENV_KEY: &str = "Environment";

/// Expands `%VARS%` using the current process environment.
pub fn expand(s: &str) -> Result<String> {
    let src = wide(s);
    // SAFETY: a null buffer with size 0 asks for the required length.
    let needed = unsafe { ExpandEnvironmentStringsW(src.as_ptr(), std::ptr::null_mut(), 0) };
    if needed == 0 {
        bail!("expanding '{s}': {}", io::Error::last_os_error());
    }
    let mut buf = vec![0u16; needed as usize];
    // SAFETY: `buf` holds `needed` u16s as requested.
    let n = unsafe { ExpandEnvironmentStringsW(src.as_ptr(), buf.as_mut_ptr(), needed) };
    if n == 0 || n > needed {
        bail!("expanding '{s}': {}", io::Error::last_os_error());
    }
    Ok(String::from_utf16_lossy(&buf[..n as usize - 1]))
}

/// Expands a leading `~` to the user profile and then `%VARS%`.
pub fn expand_path(s: &str) -> Result<String> {
    let s = match s.strip_prefix('~') {
        Some(rest) if rest.is_empty() || rest.starts_with(['/', '\\']) => format!("%USERPROFILE%{rest}"),
        _ => s.to_owned(),
    };
    expand(&s)
}

/// Sets a persistent user environment variable and mirrors it into this process, so later
/// steps see it. Returns whether it changed.
pub fn set_user_var(name: &str, value: &str) -> Result<bool> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let data = if value.contains('%') { Data::ExpandString(value) } else { Data::String(value) };
    let changed = registry::set_value(&hkcu, ENV_KEY, Some(name), &data)?;
    set_process_var(name, &expand(value)?);
    Ok(changed)
}

/// Appends a directory to the user PATH if it is not already there. Returns whether it changed.
pub fn add_user_path(dir: &str) -> Result<bool> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let current = registry::get_string(&hkcu, ENV_KEY, "Path").unwrap_or_default();
    let norm = |p: &str| p.trim().trim_end_matches('\\').to_ascii_lowercase();
    let present = current.split(';').any(|p| norm(p) == norm(dir));

    let changed = if present {
        false
    } else {
        let updated = match current.trim_end_matches(';') {
            "" => dir.to_owned(),
            cur => format!("{cur};{dir}"),
        };
        registry::set_value(&hkcu, ENV_KEY, Some("Path"), &Data::ExpandString(&updated))?
    };

    let process_path = std::env::var("PATH").unwrap_or_default();
    if !process_path.split(';').any(|p| norm(p) == norm(dir)) {
        set_process_var("PATH", &format!("{process_path};{}", expand(dir)?));
    }
    Ok(changed)
}

fn set_process_var(name: &str, value: &str) {
    // SAFETY: the agent changes its environment only from the main thread, between steps,
    // while no other thread reads it.
    unsafe { std::env::set_var(name, value) };
}

/// Tells running programs (Explorer in particular) that the environment changed, so new
/// processes they start pick it up without a log off.
pub fn broadcast_change() {
    let param = wide(ENV_KEY);
    let mut result = 0usize;
    // SAFETY: `param` outlives the call; the timeout bounds how long hung windows can block us.
    unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            param.as_ptr() as isize,
            SMTO_ABORTIFHUNG,
            2000,
            &mut result,
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_home_and_vars() {
        let profile = std::env::var("USERPROFILE").unwrap();
        assert_eq!(expand_path(r"~\.gitconfig").unwrap(), format!(r"{profile}\.gitconfig"));
        assert_eq!(expand_path("~other").unwrap(), "~other");
        assert_eq!(expand("%USERPROFILE%").unwrap(), profile);
    }
}
