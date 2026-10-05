//! Registry writes, including values for the Default User profile.

use std::io;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use windows_sys::Win32::System::Registry::{HKEY_USERS, RegLoadKeyW, RegUnLoadKeyW};
use winreg::enums::{
    HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ,
    REG_QWORD, REG_SZ,
};
use winreg::{RegKey, RegValue};

use crate::{token, wide};

/// A value to write, already typed.
#[derive(Debug, Clone, PartialEq)]
pub enum Data<'a> {
    String(&'a str),
    ExpandString(&'a str),
    MultiString(&'a [String]),
    Dword(u32),
    Qword(u64),
}

impl Data<'_> {
    /// The registry type number and the bytes as stored.
    pub fn raw(&self) -> (u32, Vec<u8>) {
        let v = self.to_reg_value();
        (v.vtype as u32, v.bytes.into_owned())
    }

    fn to_reg_value(&self) -> RegValue<'static> {
        let utf16 = |s: &str| s.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect::<Vec<u8>>();
        let (bytes, vtype) = match self {
            Data::String(s) => (utf16(s), REG_SZ),
            Data::ExpandString(s) => (utf16(s), REG_EXPAND_SZ),
            Data::MultiString(v) => {
                let mut b: Vec<u8> = v.iter().flat_map(|s| utf16(s)).collect();
                b.extend([0, 0]);
                (b, REG_MULTI_SZ)
            }
            Data::Dword(n) => (n.to_le_bytes().to_vec(), REG_DWORD),
            Data::Qword(n) => (n.to_le_bytes().to_vec(), REG_QWORD),
        };
        RegValue { bytes: bytes.into(), vtype }
    }
}

/// Splits `HKCU\Software\X` into its predefined root and the subkey path.
pub fn split_key(path: &str) -> Result<(RegKey, String)> {
    let (root, sub) = path.split_once('\\').unwrap_or((path, ""));
    let hkey = match root.to_ascii_uppercase().as_str() {
        "HKCU" | "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
        "HKLM" | "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
        "HKCR" | "HKEY_CLASSES_ROOT" => HKEY_CLASSES_ROOT,
        "HKU" | "HKEY_USERS" => winreg::enums::HKEY_USERS,
        other => bail!("unsupported registry root '{other}'"),
    };
    Ok((RegKey::predef(hkey), sub.to_owned()))
}

/// Writes a value under `root\subkey`, creating the key if needed.
/// Returns whether anything changed.
pub fn set_value(root: &RegKey, subkey: &str, name: Option<&str>, data: &Data) -> Result<bool> {
    let name = name.unwrap_or("");
    let wanted = data.to_reg_value();
    if let Ok(key) = root.open_subkey_with_flags(subkey, KEY_READ)
        && let Ok(current) = key.get_raw_value(name)
        && current.vtype == wanted.vtype
        && current.bytes == wanted.bytes
    {
        return Ok(false);
    }
    let (key, _) = root.create_subkey(subkey).with_context(|| format!("creating key {subkey}"))?;
    key.set_raw_value(name, &wanted).with_context(|| format!("writing {subkey}\\{name}"))?;
    Ok(true)
}

/// `HKEY_CURRENT_USER`: the account this process runs as.
pub fn hkcu() -> RegKey {
    RegKey::predef(HKEY_CURRENT_USER)
}

/// Reads a string value, if present.
pub fn get_string(root: &RegKey, subkey: &str, name: &str) -> Option<String> {
    root.open_subkey_with_flags(subkey, KEY_READ).ok()?.get_value(name).ok()
}

/// Whether `root\subkey` already holds exactly this value (type and data).
pub fn value_matches(root: &RegKey, subkey: &str, name: Option<&str>, data: &Data) -> bool {
    let wanted = data.to_reg_value();
    root.open_subkey_with_flags(subkey, KEY_READ)
        .and_then(|k| k.get_raw_value(name.unwrap_or("")))
        .is_ok_and(|current| current.vtype == wanted.vtype && current.bytes == wanted.bytes)
}

pub fn value_exists(root: &RegKey, subkey: &str, name: Option<&str>) -> bool {
    root.open_subkey_with_flags(subkey, KEY_READ).and_then(|k| k.get_raw_value(name.unwrap_or(""))).is_ok()
}

pub fn key_exists(root: &RegKey, subkey: &str) -> bool {
    root.open_subkey_with_flags(subkey, KEY_READ).is_ok()
}

/// Deletes one value. Returns whether it was there.
pub fn delete_value(root: &RegKey, subkey: &str, name: Option<&str>) -> Result<bool> {
    if !value_exists(root, subkey, name) {
        return Ok(false);
    }
    let name = name.unwrap_or("");
    let key = root
        .open_subkey_with_flags(subkey, winreg::enums::KEY_SET_VALUE)
        .with_context(|| format!("opening {subkey}"))?;
    key.delete_value(name).with_context(|| format!("deleting {subkey}\\{name}"))?;
    Ok(true)
}

/// Deletes a key and everything under it. Returns whether it was there.
pub fn delete_key(root: &RegKey, subkey: &str) -> Result<bool> {
    if subkey.trim_matches('\\').is_empty() {
        bail!("refusing to delete the root of a hive");
    }
    if !key_exists(root, subkey) {
        return Ok(false);
    }
    root.delete_subkey_all(subkey).with_context(|| format!("deleting key {subkey}"))?;
    Ok(true)
}

const DEFAULT_USER_MOUNT: &str = "groundhog-default-user";

/// The Default User hive (`C:\Users\Default\NTUSER.DAT`), loaded under `HKEY_USERS` for as
/// long as this guard lives. Profiles created later start as a copy of it, so values written
/// here reach users who have not logged on yet.
pub struct DefaultUserHive {
    root: RegKey,
}

impl DefaultUserHive {
    pub fn load() -> Result<Self> {
        token::enable_privilege("SeRestorePrivilege")?;
        token::enable_privilege("SeBackupPrivilege")?;
        let file = default_user_hive_path()?;
        let mount = wide(DEFAULT_USER_MOUNT);
        let file_w = wide(&file.to_string_lossy());

        // A previous run that crashed may have left it mounted.
        // SAFETY: both strings are NUL-terminated.
        unsafe { RegUnLoadKeyW(HKEY_USERS, mount.as_ptr()) };
        // SAFETY: both strings are NUL-terminated; HKEY_USERS is a predefined key.
        let rc = unsafe { RegLoadKeyW(HKEY_USERS, mount.as_ptr(), file_w.as_ptr()) };
        if rc != 0 {
            bail!("loading {}: {}", file.display(), io::Error::from_raw_os_error(rc as i32));
        }
        let root = RegKey::predef(winreg::enums::HKEY_USERS)
            .open_subkey(DEFAULT_USER_MOUNT)
            .context("opening loaded Default User hive")?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &RegKey {
        &self.root
    }
}

impl Drop for DefaultUserHive {
    fn drop(&mut self) {
        // The hive only unloads once every handle into it is closed, including ours.
        let root = std::mem::replace(&mut self.root, RegKey::predef(winreg::enums::HKEY_USERS));
        drop(root);
        let mount = wide(DEFAULT_USER_MOUNT);
        // SAFETY: NUL-terminated string; unloading a key we loaded.
        unsafe { RegUnLoadKeyW(HKEY_USERS, mount.as_ptr()) };
    }
}

fn default_user_hive_path() -> Result<PathBuf> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let dir = get_string(&hklm, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList", "Default")
        .unwrap_or_else(|| r"%SystemDrive%\Users\Default".to_owned());
    Ok(PathBuf::from(crate::env::expand(&dir)?).join("NTUSER.DAT"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_are_idempotent() {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let sub = format!(r"Software\groundhog-test-{}", std::process::id());
        let list = vec!["a".to_owned(), "b".to_owned()];
        for data in [Data::Dword(7), Data::String("x"), Data::MultiString(&list), Data::Qword(1 << 40)] {
            assert!(set_value(&hkcu, &sub, Some("v"), &data).unwrap());
            assert!(!set_value(&hkcu, &sub, Some("v"), &data).unwrap());
        }
        hkcu.delete_subkey_all(&sub).unwrap();
    }

    #[test]
    fn splits_keys() {
        assert_eq!(split_key(r"HKCU\Software\X").unwrap().1, r"Software\X");
        assert!(split_key(r"HKXX\Software").is_err());
    }
}
