//! Desktop appearance: wallpaper, solid background color, and the light or dark theme.
//!
//! Each setting is a few registry values in a user hive, so the same functions write the
//! current user's (`HKCU`) or the Default User profile's. For the current user the change is
//! also applied to the running session, the way Settings does it.

use std::io;

use anyhow::{Result, bail};
use windows_sys::Win32::Graphics::Gdi::{COLOR_DESKTOP, SetSysColors};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    HWND_BROADCAST, SMTO_ABORTIFHUNG, SPI_SETDESKWALLPAPER, SPI_SETSCREENSAVEACTIVE, SPI_SETSCREENSAVESECURE,
    SPI_SETSCREENSAVETIMEOUT, SPIF_SENDWININICHANGE, SPIF_UPDATEINIFILE, SendMessageTimeoutW, SystemParametersInfoW,
    WM_SETTINGCHANGE,
};
use winreg::RegKey;

use crate::registry::{self, Data};
use crate::wide;

const DESKTOP: &str = r"Control Panel\Desktop";
const COLORS: &str = r"Control Panel\Colors";
const PERSONALIZE: &str = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";

/// How a picture fills the screen, as Settings names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    Fill,
    Fit,
    Stretch,
    Tile,
    Center,
    Span,
}

impl Style {
    /// `WallpaperStyle` and `TileWallpaper`, the two values Windows reads.
    fn values(self) -> (&'static str, &'static str) {
        match self {
            Style::Fill => ("10", "0"),
            Style::Fit => ("6", "0"),
            Style::Stretch => ("2", "0"),
            Style::Tile => ("0", "1"),
            Style::Center => ("0", "0"),
            Style::Span => ("22", "0"),
        }
    }
}

/// The wallpaper for one user hive: `picture` (a full path, or "" for none) and its style.
/// `root` is `HKCU` or a loaded profile hive. Returns whether anything changed.
pub fn set_wallpaper(root: &RegKey, picture: &str, style: Style, check: bool) -> Result<bool> {
    let (wallpaper_style, tile) = style.values();
    let wanted = [("Wallpaper", picture), ("WallpaperStyle", wallpaper_style), ("TileWallpaper", tile)];
    let mut changed = false;
    for (name, value) in wanted {
        let data = Data::String(value);
        if check {
            changed |= !registry::value_matches(root, DESKTOP, Some(name), &data);
        } else {
            changed |= registry::set_value(root, DESKTOP, Some(name), &data)?;
        }
    }
    Ok(changed)
}

/// The solid desktop color (behind a picture that doesn't cover the screen, or instead of one).
pub fn set_background(root: &RegKey, rgb: (u8, u8, u8), check: bool) -> Result<bool> {
    let value = format!("{} {} {}", rgb.0, rgb.1, rgb.2);
    let data = Data::String(&value);
    if check {
        return Ok(!registry::value_matches(root, COLORS, Some("Background"), &data));
    }
    registry::set_value(root, COLORS, Some("Background"), &data)
}

/// Light or dark, for apps and for Windows itself (taskbar, Start); `None` leaves one alone.
pub fn set_theme(root: &RegKey, apps_light: Option<bool>, windows_light: Option<bool>, check: bool) -> Result<bool> {
    let mut changed = false;
    for (name, light) in [("AppsUseLightTheme", apps_light), ("SystemUsesLightTheme", windows_light)] {
        let Some(light) = light else { continue };
        let data = Data::Dword(u32::from(light));
        if check {
            changed |= !registry::value_matches(root, PERSONALIZE, Some(name), &data);
        } else {
            changed |= registry::set_value(root, PERSONALIZE, Some(name), &data)?;
        }
    }
    Ok(changed)
}

/// Shows the current user's wallpaper and background color now, rather than at next logon.
pub fn apply_now(picture: &str, background: Option<(u8, u8, u8)>) -> Result<()> {
    if let Some((r, g, b)) = background {
        let color = u32::from(r) | (u32::from(g) << 8) | (u32::from(b) << 16);
        let element = COLOR_DESKTOP;
        // SAFETY: one element and one color, as the counts say.
        if unsafe { SetSysColors(1, &element, &color) } == 0 {
            bail!("setting the desktop color: {}", io::Error::last_os_error());
        }
    }
    let path = wide(picture);
    // SAFETY: `path` is a NUL-terminated wide string that outlives the call.
    let ok = unsafe {
        SystemParametersInfoW(
            SPI_SETDESKWALLPAPER,
            0,
            path.as_ptr() as *mut _,
            SPIF_UPDATEINIFILE | SPIF_SENDWININICHANGE,
        )
    };
    if ok == 0 {
        bail!("setting the wallpaper: {}", io::Error::last_os_error());
    }
    Ok(())
}

/// The screen saver for one user hive: on or off, the idle time before it starts, whether
/// resuming needs a sign-in, and which `.scr` runs.
pub struct ScreenSaver<'a> {
    pub enabled: bool,
    pub timeout_secs: Option<u64>,
    pub secure: Option<bool>,
    pub program: Option<&'a str>,
}

pub fn set_screen_saver(root: &RegKey, s: &ScreenSaver, check: bool) -> Result<bool> {
    let flag = |b: bool| if b { "1" } else { "0" };
    let timeout = s.timeout_secs.map(|t| t.to_string());
    let mut wanted: Vec<(&str, &str)> = vec![("ScreenSaveActive", flag(s.enabled))];
    if s.enabled {
        if let Some(t) = &timeout {
            wanted.push(("ScreenSaveTimeOut", t));
        }
        if let Some(secure) = s.secure {
            wanted.push(("ScreenSaverIsSecure", flag(secure)));
        }
        if let Some(program) = s.program {
            wanted.push(("SCRNSAVE.EXE", program));
        }
    }
    let mut changed = false;
    for (name, value) in wanted {
        let data = Data::String(value);
        if check {
            changed |= !registry::value_matches(root, DESKTOP, Some(name), &data);
        } else {
            changed |= registry::set_value(root, DESKTOP, Some(name), &data)?;
        }
    }
    Ok(changed)
}

/// Applies the current user's screen saver settings to the running session.
pub fn apply_screen_saver_now(s: &ScreenSaver) -> Result<()> {
    let spi = |action: u32, value: u32| {
        // SAFETY: these actions take their value in `uiParam` and no buffer.
        if unsafe {
            SystemParametersInfoW(action, value, std::ptr::null_mut(), SPIF_UPDATEINIFILE | SPIF_SENDWININICHANGE)
        } == 0
        {
            bail!("applying the screen saver setting: {}", io::Error::last_os_error());
        }
        Ok(())
    };
    spi(SPI_SETSCREENSAVEACTIVE, u32::from(s.enabled))?;
    if s.enabled {
        if let Some(t) = s.timeout_secs {
            spi(SPI_SETSCREENSAVETIMEOUT, u32::try_from(t).unwrap_or(u32::MAX))?;
        }
        if let Some(secure) = s.secure {
            spi(SPI_SETSCREENSAVESECURE, u32::from(secure))?;
        }
    }
    Ok(())
}

const PERSONALIZATION_CSP: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP";
const SYSTEM_POLICIES: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";

/// The lock screen picture for the whole machine (the values the Personalization CSP and
/// Intune write), so every account sees it at sign-in.
pub fn set_lock_screen_image(picture: &str, check: bool) -> Result<bool> {
    let hklm = RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE);
    let wanted = [
        ("LockScreenImagePath", Data::String(picture)),
        ("LockScreenImageUrl", Data::String(picture)),
        ("LockScreenImageStatus", Data::Dword(1)),
    ];
    let mut changed = false;
    for (name, data) in &wanted {
        if check {
            changed |= !registry::value_matches(&hklm, PERSONALIZATION_CSP, Some(name), data);
        } else {
            changed |= registry::set_value(&hklm, PERSONALIZATION_CSP, Some(name), data)?;
        }
    }
    Ok(changed)
}

/// Lock the machine after this much idle time (the "Interactive logon: Machine inactivity
/// limit" security setting), for every account.
pub fn set_lock_after(secs: u64, check: bool) -> Result<bool> {
    let hklm = RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE);
    let data = Data::Dword(u32::try_from(secs).unwrap_or(u32::MAX));
    if check {
        return Ok(!registry::value_matches(&hklm, SYSTEM_POLICIES, Some("InactivityTimeoutSecs"), &data));
    }
    registry::set_value(&hklm, SYSTEM_POLICIES, Some("InactivityTimeoutSecs"), &data)
}

/// Tells Explorer and apps that the light/dark setting changed, so they switch now.
pub fn broadcast_theme_change() {
    let param = wide("ImmersiveColorSet");
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

/// What [`set_tray_icon`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayIcon {
    /// The program has no entry yet: Windows makes one the first time it shows an icon.
    NotSeenYet,
    /// Every entry for the program was already as wanted.
    AsWanted,
    /// This many entries were (or, when checking, would be) changed.
    Changed(usize),
}

const NOTIFY_ICON_SETTINGS: &str = r"Control Panel\NotifyIconSettings";

/// Puts a program's notification-area icon on the taskbar (`shown`) or in the overflow, for
/// the current user. `program` is a file name (`OneDrive.exe`) or the end of a path
/// (`Microsoft OneDrive\OneDrive.exe`); every entry whose program matches is set.
pub fn set_tray_icon(program: &str, shown: bool, check: bool) -> Result<TrayIcon> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE};

    let settings = match RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(NOTIFY_ICON_SETTINGS, KEY_READ) {
        Ok(k) => k,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(TrayIcon::NotSeenYet),
        Err(e) => return Err(e.into()),
    };
    let wanted = u32::from(shown);
    let (mut found, mut changed) = (0, 0);
    for name in settings.enum_keys().collect::<io::Result<Vec<_>>>()? {
        let entry = settings.open_subkey_with_flags(&name, KEY_READ | KEY_SET_VALUE)?;
        let Ok(path) = entry.get_value::<String, _>("ExecutablePath") else { continue };
        if !program_matches(&path, program) {
            continue;
        }
        found += 1;
        if entry.get_value::<u32, _>("IsPromoted").ok() != Some(wanted) {
            if !check {
                entry.set_value("IsPromoted", &wanted)?;
            }
            changed += 1;
        }
    }
    Ok(match (found, changed) {
        (0, _) => TrayIcon::NotSeenYet,
        (_, 0) => TrayIcon::AsWanted,
        (_, n) => TrayIcon::Changed(n),
    })
}

/// Whether a tray entry's program (often written with a known-folder id in place of the
/// folder, `{6D809377-…}\App\app.exe`) is `program`.
fn program_matches(path: &str, program: &str) -> bool {
    let path = path.to_ascii_lowercase().replace('/', "\\");
    let program = program.to_ascii_lowercase().replace('/', "\\");
    path == program || path.ends_with(&format!(r"\{}", program.trim_start_matches('\\')))
}

#[cfg(test)]
mod tray_tests {
    use super::program_matches;

    #[test]
    fn tray_programs_match_by_file_name_or_path_tail() {
        let p = r"{6D809377-6AF0-444B-8957-A3773F02200E}\Microsoft OneDrive\OneDrive.exe";
        assert!(program_matches(p, "OneDrive.exe"));
        assert!(program_matches(p, "onedrive.EXE"));
        assert!(program_matches(p, r"Microsoft OneDrive\OneDrive.exe"));
        assert!(!program_matches(p, "Drive.exe"), "a file name matches whole, not as a suffix");
        assert!(!program_matches(p, "Teams.exe"));
        assert!(program_matches(r"C:\Tools\x.exe", r"C:\Tools\x.exe"));
    }
}

const QUIET_HOURS_KEY: &str = concat!(
    r"Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\DefaultAccount\Current\",
    r"default$windows.data.donotdisturb.quiethourssettings\windows.data.donotdisturb.quiethourssettings"
);
/// Where Start keeps its pinned apps, under a profile's folder.
const START_LAYOUT: &str =
    r"AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\start2.bin";

/// Whose Start: this user's (now) or new accounts' (from the Default profile).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Current,
    Default,
}

/// The Start layout file of this user or of the Default profile.
pub fn start_layout_path(profile: Profile) -> Result<std::path::PathBuf> {
    let dir = match profile {
        Profile::Current => std::path::PathBuf::from(crate::env::expand("%USERPROFILE%")?),
        Profile::Default => registry::default_profile_dir()?,
    };
    Ok(dir.join(START_LAYOUT))
}

/// Puts a Start layout (`start2.bin`) in place. Windows has no setting for Start's pins on
/// editions without device management; it keeps them in this file, in a format of its own
/// that isn't tied to a machine or user, so one taken from a machine pinned by hand works
/// anywhere. For this user, Start's host is ended first: it holds the file and would write
/// its own copy back. It starts again by itself and shows the new pins.
pub fn set_start_pins(layout: &[u8], profile: Profile) -> Result<bool> {
    let path = start_layout_path(profile)?;
    if std::fs::read(&path).is_ok_and(|now| now == layout) {
        return Ok(false);
    }
    std::fs::create_dir_all(path.parent().expect("has a folder"))?;
    let mut last = None;
    for _ in 0..10 {
        if profile == Profile::Current {
            let _ = crate::process::Proc::new("taskkill.exe")
                .args(["/f", "/im", "StartMenuExperienceHost.exe"])
                .run(&mut |_| {});
        }
        match std::fs::write(&path, layout) {
            Ok(()) => return Ok(true),
            Err(e) => last = Some(e),
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    bail!("writing {}: {}", path.display(), last.map(|e| e.to_string()).unwrap_or_default())
}

const PROFILE_ON: &str = "Microsoft.QuietHoursProfile.PriorityOnly";
const PROFILE_OFF: &str = "Microsoft.QuietHoursProfile.Unrestricted";

/// Do Not Disturb for the current user, as Settings saves it. Windows reads it at sign-in:
/// writing it doesn't change a session that's already running (the running state lives in
/// the shell, which offers programs no way to change it).
pub fn set_do_not_disturb(on: bool, check: bool) -> Result<bool> {
    use winreg::enums::{HKEY_CURRENT_USER, REG_BINARY};

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let current = hkcu.open_subkey(QUIET_HOURS_KEY).and_then(|k| k.get_raw_value("Data")).ok();
    let wanted = utf16(if on { PROFILE_ON } else { PROFILE_OFF });
    let is_wanted = current.as_ref().is_some_and(|v| contains(&v.bytes, &wanted));
    // Without a saved record Windows' default is off.
    let is_off_by_default = current.is_none() && !on;
    if is_wanted || is_off_by_default {
        return Ok(false);
    }
    if check {
        return Ok(true);
    }
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let blob = quiet_hours_blob(if on { PROFILE_ON } else { PROFILE_OFF }, now);
    let (key, _) = hkcu.create_subkey(QUIET_HOURS_KEY)?;
    key.set_raw_value("Data", &winreg::RegValue { bytes: blob.into(), vtype: REG_BINARY })?;
    Ok(true)
}

/// The quiet hours record in CloudStore's encoding, as Settings writes it: a header, the time
/// it was saved, and a nested record naming the active profile.
fn quiet_hours_blob(profile: &str, unix_time: u64) -> Vec<u8> {
    let name = utf16(profile);
    let mut inner = vec![0x43, 0x42, 0x01, 0x00, 0xc2, 0x0a, 0x01, 0xd2, 0x14];
    inner.extend(leb128(name.len() as u64 / 2));
    inner.extend(&name);
    inner.extend([0xca, 0x28, 0x00, 0x00]);
    let mut out = vec![0x43, 0x42, 0x01, 0x00, 0x0a, 0x02, 0x01, 0x00, 0x2a, 0x06];
    out.extend(leb128(unix_time));
    out.extend([0x2a, 0x2b, 0x0e]);
    out.extend(leb128(inner.len() as u64));
    out.extend(inner);
    out.extend([0x00, 0x00, 0x00]);
    out
}

fn leb128(mut n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod quiet_hours_tests {
    use super::*;

    /// What Settings wrote on Windows 11 25H2 (build 26200) when Do Not Disturb was turned on.
    const SETTINGS_ON: &str = "43 42 01 00 0a 02 01 00 2a 06 c6 c8 95 d6 06 2a 2b 0e 5e 43 42 01 00 c2 0a 01 d2 14 28 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 51 00 75 00 69 00 65 00 74 00 48 00 6f 00 75 00 72 00 73 00 50 00 72 00 6f 00 66 00 69 00 6c 00 65 00 2e 00 50 00 72 00 69 00 6f 00 72 00 69 00 74 00 79 00 4f 00 6e 00 6c 00 79 00 ca 28 00 00 00 00 00";

    #[test]
    fn the_blob_matches_what_settings_writes() {
        let expected: Vec<u8> = SETTINGS_ON.split(' ').map(|b| u8::from_str_radix(b, 16).unwrap()).collect();
        assert_eq!(quiet_hours_blob(PROFILE_ON, 1_791_321_158), expected);
        let off = quiet_hours_blob(PROFILE_OFF, 1_791_321_158);
        assert_eq!(off.len(), expected.len());
        assert!(contains(&off, &utf16(PROFILE_OFF)) && !contains(&off, &utf16(PROFILE_ON)));
    }
}
