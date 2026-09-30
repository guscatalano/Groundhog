//! Local user accounts and group membership (netapi32), and generating passwords.

use std::io;

use anyhow::{Result, bail};
use windows_sys::Win32::Foundation::{ERROR_MEMBER_IN_ALIAS, LocalFree};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    LOCALGROUP_MEMBERS_INFO_3, NERR_Success as NERR_SUCCESS, NERR_UserNotFound as NERR_USER_NOT_FOUND,
    NetApiBufferFree, NetLocalGroupAddMembers, NetUserAdd, NetUserDel, NetUserGetInfo, NetUserSetInfo,
    UF_DONT_EXPIRE_PASSWD, UF_SCRIPT, USER_INFO_1, USER_INFO_1003, USER_INFO_1008, USER_INFO_1011, USER_PRIV_USER,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom};
use windows_sys::Win32::Security::{LookupAccountSidW, PSID, SID_NAME_USE};

use crate::wide;

/// Built-in groups by their English names. Windows localizes group names ("Administratoren"
/// on German Windows), but their SIDs never change, so these resolve on any language.
const WELL_KNOWN_GROUPS: &[(&str, &str)] = &[
    ("administrators", "S-1-5-32-544"),
    ("users", "S-1-5-32-545"),
    ("guests", "S-1-5-32-546"),
    ("power users", "S-1-5-32-547"),
    ("backup operators", "S-1-5-32-551"),
    ("remote desktop users", "S-1-5-32-555"),
    ("network configuration operators", "S-1-5-32-556"),
    ("performance monitor users", "S-1-5-32-558"),
    ("performance log users", "S-1-5-32-559"),
    ("distributed com users", "S-1-5-32-562"),
    ("event log readers", "S-1-5-32-573"),
    ("hyper-v administrators", "S-1-5-32-578"),
    ("remote management users", "S-1-5-32-580"),
];

fn net_error(what: &str, code: u32) -> anyhow::Error {
    anyhow::anyhow!("{what}: {}", io::Error::from_raw_os_error(code as i32))
}

/// Whether a local account with this name exists.
pub fn user_exists(name: &str) -> Result<bool> {
    let name_w = wide(name);
    let mut buf: *mut u8 = std::ptr::null_mut();
    // SAFETY: `name_w` is NUL-terminated; the buffer the API allocates is freed below.
    let rc = unsafe { NetUserGetInfo(std::ptr::null(), name_w.as_ptr(), 1, &mut buf) };
    if !buf.is_null() {
        // SAFETY: allocated by NetUserGetInfo.
        unsafe { NetApiBufferFree(buf.cast()) };
    }
    match rc {
        NERR_SUCCESS => Ok(true),
        NERR_USER_NOT_FOUND => Ok(false),
        other => Err(net_error(&format!("looking up user {name}"), other)),
    }
}

/// Creates a standard local user. `never_expires` stops Windows from forcing a password change
/// later (42 days by default), which would break unattended logons.
pub fn create_user(name: &str, password: &str, never_expires: bool) -> Result<()> {
    let (mut name_w, mut password_w) = (wide(name), wide(password));
    let mut flags = UF_SCRIPT;
    if never_expires {
        flags |= UF_DONT_EXPIRE_PASSWD;
    }
    let info = USER_INFO_1 {
        usri1_name: name_w.as_mut_ptr(),
        usri1_password: password_w.as_mut_ptr(),
        usri1_password_age: 0,
        usri1_priv: USER_PRIV_USER,
        usri1_home_dir: std::ptr::null_mut(),
        usri1_comment: std::ptr::null_mut(),
        usri1_flags: flags,
        usri1_script_path: std::ptr::null_mut(),
    };
    let mut parm_err = 0u32;
    // SAFETY: `info` points at NUL-terminated strings that outlive the call.
    let rc = unsafe { NetUserAdd(std::ptr::null(), 1, (&info as *const USER_INFO_1).cast(), &mut parm_err) };
    password_w.fill(0);
    if rc != NERR_SUCCESS {
        return Err(net_error(&format!("creating user {name}"), rc));
    }
    Ok(())
}

pub fn set_password(name: &str, password: &str) -> Result<()> {
    let name_w = wide(name);
    let mut password_w = wide(password);
    let info = USER_INFO_1003 { usri1003_password: password_w.as_mut_ptr() };
    let mut parm_err = 0u32;
    // SAFETY: as in `create_user`.
    let rc = unsafe {
        NetUserSetInfo(std::ptr::null(), name_w.as_ptr(), 1003, (&info as *const USER_INFO_1003).cast(), &mut parm_err)
    };
    password_w.fill(0);
    if rc != NERR_SUCCESS {
        return Err(net_error(&format!("setting the password of {name}"), rc));
    }
    Ok(())
}

pub fn set_full_name(name: &str, full_name: &str) -> Result<()> {
    let name_w = wide(name);
    let mut full_w = wide(full_name);
    let info = USER_INFO_1011 { usri1011_full_name: full_w.as_mut_ptr() };
    let mut parm_err = 0u32;
    // SAFETY: as in `create_user`.
    let rc = unsafe {
        NetUserSetInfo(std::ptr::null(), name_w.as_ptr(), 1011, (&info as *const USER_INFO_1011).cast(), &mut parm_err)
    };
    if rc != NERR_SUCCESS {
        return Err(net_error(&format!("setting the full name of {name}"), rc));
    }
    Ok(())
}

/// Turns "password never expires" on or off. Returns whether it changed.
pub fn set_password_never_expires(name: &str, never_expires: bool) -> Result<bool> {
    let name_w = wide(name);
    let mut buf: *mut u8 = std::ptr::null_mut();
    // SAFETY: level 1 returns a USER_INFO_1, freed below.
    let rc = unsafe { NetUserGetInfo(std::ptr::null(), name_w.as_ptr(), 1, &mut buf) };
    if rc != NERR_SUCCESS {
        return Err(net_error(&format!("reading user {name}"), rc));
    }
    // SAFETY: NetUserGetInfo succeeded, so `buf` holds a USER_INFO_1.
    let flags = unsafe { (*(buf as *const USER_INFO_1)).usri1_flags };
    // SAFETY: allocated by NetUserGetInfo.
    unsafe { NetApiBufferFree(buf.cast()) };

    let wanted = if never_expires { flags | UF_DONT_EXPIRE_PASSWD } else { flags & !UF_DONT_EXPIRE_PASSWD };
    if wanted == flags {
        return Ok(false);
    }
    let info = USER_INFO_1008 { usri1008_flags: wanted };
    let mut parm_err = 0u32;
    // SAFETY: a plain USER_INFO_1008.
    let rc = unsafe {
        NetUserSetInfo(std::ptr::null(), name_w.as_ptr(), 1008, (&info as *const USER_INFO_1008).cast(), &mut parm_err)
    };
    if rc != NERR_SUCCESS {
        return Err(net_error(&format!("updating user {name}"), rc));
    }
    Ok(true)
}

/// Adds a user to a local group. Returns whether it changed (false if already a member).
pub fn add_to_group(user: &str, group: &str) -> Result<bool> {
    let local = resolve_group(group)?;
    let group_w = wide(&local);
    let mut user_w = wide(user);
    let member = LOCALGROUP_MEMBERS_INFO_3 { lgrmi3_domainandname: user_w.as_mut_ptr() };
    // SAFETY: one LOCALGROUP_MEMBERS_INFO_3 pointing at a NUL-terminated name.
    let rc = unsafe {
        NetLocalGroupAddMembers(
            std::ptr::null(),
            group_w.as_ptr(),
            3,
            (&member as *const LOCALGROUP_MEMBERS_INFO_3).cast(),
            1,
        )
    };
    match rc {
        NERR_SUCCESS => Ok(true),
        ERROR_MEMBER_IN_ALIAS => Ok(false),
        other => Err(net_error(&format!("adding {user} to {local}"), other)),
    }
}

/// The name this machine uses for a group: a built-in group's localized name when given its
/// English name, otherwise the name as given.
pub fn resolve_group(name: &str) -> Result<String> {
    let Some((_, sid)) = WELL_KNOWN_GROUPS.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)) else {
        return Ok(name.to_owned());
    };
    let sid_w = wide(sid);
    let mut psid: PSID = std::ptr::null_mut();
    // SAFETY: `sid_w` is NUL-terminated; the SID the API allocates is freed below.
    if unsafe { ConvertStringSidToSidW(sid_w.as_ptr(), &mut psid) } == 0 {
        bail!("bad SID {sid}: {}", io::Error::last_os_error());
    }
    let mut name_buf = [0u16; 256];
    let mut domain_buf = [0u16; 256];
    let (mut name_len, mut domain_len) = (name_buf.len() as u32, domain_buf.len() as u32);
    let mut use_: SID_NAME_USE = 0;
    // SAFETY: buffers and their lengths are passed together; `psid` is valid.
    let ok = unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            psid,
            name_buf.as_mut_ptr(),
            &mut name_len,
            domain_buf.as_mut_ptr(),
            &mut domain_len,
            &mut use_,
        )
    };
    // SAFETY: allocated by ConvertStringSidToSidW.
    unsafe { LocalFree(psid) };
    if ok == 0 {
        bail!("looking up group {name}: {}", io::Error::last_os_error());
    }
    Ok(String::from_utf16_lossy(&name_buf[..name_len as usize]))
}

/// Removes a local user (used by tests and for cleanup).
pub fn delete_user(name: &str) -> Result<()> {
    let name_w = wide(name);
    // SAFETY: NUL-terminated name.
    let rc = unsafe { NetUserDel(std::ptr::null(), name_w.as_ptr()) };
    match rc {
        NERR_SUCCESS | NERR_USER_NOT_FOUND => Ok(()),
        other => Err(net_error(&format!("deleting user {name}"), other)),
    }
}

/// A random password from the system's secure generator. It always has upper and lower case
/// letters, digits and symbols, so it passes Windows' complexity policy.
pub fn generate_password(len: usize) -> Result<String> {
    const SETS: [&[u8]; 4] = [b"ABCDEFGHJKLMNPQRSTUVWXYZ", b"abcdefghijkmnopqrstuvwxyz", b"23456789", b"!#%+-=?@^_"];
    let len = len.max(SETS.len());
    let mut rnd = vec![0u8; len * 2];
    // SAFETY: the buffer and its length are passed together.
    let status = unsafe {
        BCryptGenRandom(std::ptr::null_mut(), rnd.as_mut_ptr(), rnd.len() as u32, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
    };
    if status != 0 {
        bail!("the system random generator failed ({status:#x})");
    }
    // One character from each set, the rest from all of them, then a shuffle so the guaranteed
    // ones aren't always first.
    let all: Vec<u8> = SETS.concat();
    let mut chars: Vec<u8> = SETS.iter().zip(&rnd).map(|(set, r)| set[*r as usize % set.len()]).collect();
    chars.extend((SETS.len()..len).map(|i| all[rnd[i] as usize % all.len()]));
    for i in (1..len).rev() {
        chars.swap(i, rnd[len + i] as usize % (i + 1));
    }
    Ok(String::from_utf8(chars).expect("ascii"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_groups_resolve_by_sid_and_others_pass_through() {
        // Whatever the display language, SID S-1-5-32-544 is the administrators group.
        let admins = resolve_group("Administrators").unwrap();
        assert!(!admins.is_empty());
        assert_eq!(resolve_group("REMOTE DESKTOP USERS").unwrap(), resolve_group("remote desktop users").unwrap());
        assert_eq!(resolve_group("My Custom Group").unwrap(), "My Custom Group");
    }

    #[test]
    fn generated_passwords_are_random_and_complex() {
        let a = generate_password(24).unwrap();
        let b = generate_password(24).unwrap();
        assert_eq!(a.len(), 24);
        assert_ne!(a, b);
        assert!(a.chars().any(|c| c.is_ascii_uppercase()) && a.chars().any(|c| c.is_ascii_lowercase()));
        assert!(a.chars().any(|c| c.is_ascii_digit()) && a.chars().any(|c| !c.is_ascii_alphanumeric()));
    }

    #[test]
    fn a_missing_user_does_not_exist() {
        assert!(!user_exists("groundhog-no-such-user").unwrap());
    }

    /// Creates a real account, so it needs an elevated process: CI runners are, a normal
    /// developer shell usually isn't (and then this test does nothing).
    #[test]
    fn creates_users_and_manages_groups_when_elevated() {
        if !crate::token::is_elevated() {
            eprintln!("skipped: needs an elevated process");
            return;
        }
        let name = format!("gh-test-{}", std::process::id() % 100_000);
        let _ = delete_user(&name);
        create_user(&name, &generate_password(20).unwrap(), true).unwrap();
        assert!(user_exists(&name).unwrap());
        assert!(add_to_group(&name, "Remote Desktop Users").unwrap());
        assert!(!add_to_group(&name, "Remote Desktop Users").unwrap(), "already a member");
        assert!(!set_password_never_expires(&name, true).unwrap(), "set at creation");
        assert!(set_password_never_expires(&name, false).unwrap());
        set_password(&name, &generate_password(20).unwrap()).unwrap();
        set_full_name(&name, "Groundhog Test").unwrap();
        delete_user(&name).unwrap();
        assert!(!user_exists(&name).unwrap());
    }
}
