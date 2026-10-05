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
