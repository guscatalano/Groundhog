//! Environment variables and PATH, persisted for the user (`HKCU\Environment`) or the whole
//! machine (the system environment every account and service starts with).

use std::io;

use anyhow::{Result, bail};
use windows_sys::Win32::System::Environment::ExpandEnvironmentStringsW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    HWND_BROADCAST, SMTO_ABORTIFHUNG, SendMessageTimeoutW, WM_SETTINGCHANGE,
};
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

use crate::registry::{self, Data};
use crate::wide;

const ENV_KEY: &str = "Environment";
const MACHINE_ENV_KEY: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";

/// Where a variable is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    User,
    Machine,
}

impl Scope {
    fn key(self) -> (RegKey, &'static str) {
        match self {
            Scope::User => (RegKey::predef(HKEY_CURRENT_USER), ENV_KEY),
            Scope::Machine => (RegKey::predef(HKEY_LOCAL_MACHINE), MACHINE_ENV_KEY),
        }
    }
}

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

/// Sets a persistent environment variable and mirrors it into this process, so later steps
/// see it. Returns whether it changed. Machine scope needs the agent elevated.
pub fn set_var(scope: Scope, name: &str, value: &str) -> Result<bool> {
    let (root, key) = scope.key();
    let data = if value.contains('%') { Data::ExpandString(value) } else { Data::String(value) };
    let changed = registry::set_value(&root, key, Some(name), &data)?;
    set_process_var(name, &expand(value)?);
    Ok(changed)
}

/// Appends a directory to the user or machine PATH if it is not already there. Returns whether
/// it changed. Machine scope needs the agent elevated.
pub fn add_path(scope: Scope, dir: &str) -> Result<bool> {
    let (root, key) = scope.key();
    let current = match (registry::get_string(&root, key, "Path"), scope) {
        (Some(p), _) => p,
        (None, Scope::User) => String::new(),
        // Every Windows has a system PATH. Failing to read it must never become "it's empty",
        // which would write back a PATH holding only `dir`.
        (None, Scope::Machine) => bail!("can't read the machine PATH ({MACHINE_ENV_KEY}); not changing it"),
    };
    let norm = |p: &str| p.trim().trim_end_matches('\\').to_ascii_lowercase();
    let present = current.split(';').any(|p| norm(p) == norm(dir));

    let changed = if present {
        false
    } else {
        let updated = match current.trim_end_matches(';') {
            "" => dir.to_owned(),
            cur => format!("{cur};{dir}"),
        };
        registry::set_value(&root, key, Some("Path"), &Data::ExpandString(&updated))?
    };

    let process_path = std::env::var("PATH").unwrap_or_default();
    if !process_path.split(';').any(|p| norm(p) == norm(dir)) {
        set_process_var("PATH", &format!("{process_path};{}", expand(dir)?));
    }
    Ok(changed)
}

/// Whether the variable is already set to exactly this value.
pub fn var_matches(scope: Scope, name: &str, value: &str) -> bool {
    let (root, key) = scope.key();
    let data = if value.contains('%') { Data::ExpandString(value) } else { Data::String(value) };
    registry::value_matches(&root, key, Some(name), &data)
}

pub fn var_exists(scope: Scope, name: &str) -> bool {
    let (root, key) = scope.key();
    registry::value_exists(&root, key, Some(name))
}

/// Removes a persistent variable (and from this process). Returns whether it was set.
pub fn remove_var(scope: Scope, name: &str) -> Result<bool> {
    if name.eq_ignore_ascii_case("path") {
        bail!("refusing to remove PATH as a whole; remove entries with `path:` and state: absent");
    }
    let (root, key) = scope.key();
    let removed = registry::delete_value(&root, key, Some(name))?;
    // SAFETY: as in set_process_var.
    unsafe { std::env::remove_var(name) };
    Ok(removed)
}

fn path_entries(scope: Scope) -> Result<Option<String>> {
    let (root, key) = scope.key();
    Ok(match (registry::get_string(&root, key, "Path"), scope) {
        (Some(p), _) => Some(p),
        (None, Scope::User) => None,
        (None, Scope::Machine) => bail!("can't read the machine PATH ({MACHINE_ENV_KEY}); not changing it"),
    })
}

fn same_dir(a: &str, b: &str) -> bool {
    let norm = |p: &str| p.trim().trim_end_matches('\\').to_ascii_lowercase();
    norm(a) == norm(b)
}

/// Whether the PATH (user or machine) has this folder.
pub fn path_contains(scope: Scope, dir: &str) -> Result<bool> {
    Ok(path_entries(scope)?.is_some_and(|p| p.split(';').any(|e| same_dir(e, dir))))
}

/// Takes a folder out of the user or machine PATH, keeping every other entry as it was.
/// Returns whether it was there.
pub fn remove_path(scope: Scope, dir: &str) -> Result<bool> {
    let Some(current) = path_entries(scope)? else { return Ok(false) };
    if !current.split(';').any(|e| same_dir(e, dir)) {
        return Ok(false);
    }
    let kept: Vec<&str> = current.split(';').filter(|e| !same_dir(e, dir)).collect();
    let (root, key) = scope.key();
    registry::set_value(&root, key, Some("Path"), &Data::ExpandString(&kept.join(";")))?;
    let process: Vec<String> = std::env::var("PATH")
        .unwrap_or_default()
        .split(';')
        .filter(|e| !same_dir(e, dir) && !expand(dir).is_ok_and(|x| same_dir(e, &x)))
        .map(str::to_owned)
        .collect();
    set_process_var("PATH", &process.join(";"));
    Ok(true)
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
