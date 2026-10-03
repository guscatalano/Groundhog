//! Finding `winget.exe`, which is not always on PATH (fresh profiles, SYSTEM, Sandbox).

use std::path::PathBuf;

/// winget return codes the agent treats specially.
/// See `doc/windows/package-manager/winget/returnCodes.md` in microsoft/winget-cli.
pub mod codes {
    pub const NO_APPLICATIONS_FOUND: i32 = 0x8A150014_u32 as i32;
    pub const UPDATE_NOT_APPLICABLE: i32 = 0x8A15002B_u32 as i32;
    pub const PACKAGE_ALREADY_INSTALLED: i32 = 0x8A150061_u32 as i32;
    pub const INSTALL_REBOOT_REQUIRED_TO_FINISH: i32 = 0x8A150109_u32 as i32;
    pub const INSTALL_REBOOT_REQUIRED_FOR_INSTALL: i32 = 0x8A15010A_u32 as i32;
    pub const INSTALL_REBOOT_INITIATED: i32 = 0x8A15010B_u32 as i32;
    pub const INSTALL_ALREADY_INSTALLED: i32 = 0x8A15010D_u32 as i32;
    /// "The package installed for user scope cannot be uninstalled when running with
    /// administrator privileges" (portable packages installed per user).
    pub const USER_SCOPE_NEEDS_UNELEVATED: i32 = 0x8A15007D_u32 as i32;
}

pub fn locate() -> Option<PathBuf> {
    // App execution aliases are reparse points that `metadata` cannot follow; only check
    // that the entry exists.
    let exists = |p: &PathBuf| std::fs::symlink_metadata(p).is_ok();

    let on_path = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).map(|d| d.join("winget.exe")).collect::<Vec<_>>())
        .unwrap_or_default();
    let alias = std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join(r"Microsoft\WindowsApps\winget.exe"));

    if let Some(found) = on_path.into_iter().chain(alias).find(exists) {
        return Some(found);
    }
    // No alias when running as SYSTEM: use the newest installed App Installer package directly.
    let apps = PathBuf::from(std::env::var_os("ProgramFiles")?).join("WindowsApps");
    let mut candidates: Vec<PathBuf> = std::fs::read_dir(apps)
        .ok()?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            name.starts_with("Microsoft.DesktopAppInstaller_") && name.contains("_x64__")
        })
        .map(|p| p.join("winget.exe"))
        .filter(|p| p.is_file())
        .collect();
    candidates.sort();
    candidates.pop()
}
