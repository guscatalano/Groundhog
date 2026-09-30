//! Windows optional features and capabilities (Features on Demand) through the DISM API
//! (`dismapi.dll`), for the running system.
//!
//! The DISM API gives typed state, exact error codes, progress and clean cancellation, where
//! `dism.exe` gives localized text. Its header ships with the ADK rather than the SDK, so the
//! functions are loaded at run time, and this module deliberately reads only the `State` field
//! of DISM's info structures. That field follows a single pointer, so its offset is the same
//! whichever packing the header uses; nothing here walks DISM arrays or packed fields.

use std::ffi::c_void;
use std::io;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows_sys::Win32::System::Threading::{CreateEventW, SetEvent};
use windows_sys::core::{BOOL, HRESULT, PCWSTR};

use crate::wide;

/// DISM's name for "the Windows that is running", as opposed to a mounted image.
const DISM_ONLINE_IMAGE: &str = "DISM_{53BFAE52-B167-4E2F-A258-0A37B57FF845}";
const LOG_ERRORS_WARNINGS_INFO: u32 = 2;
const PACKAGE_NONE: u32 = 0;

/// `DismPackageFeatureState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    NotPresent,
    UninstallPending,
    Staged,
    Removed,
    Installed,
    InstallPending,
    Superseded,
    PartiallyInstalled,
    Unknown(u32),
}

impl State {
    fn from_raw(v: u32) -> Self {
        match v {
            0 => State::NotPresent,
            1 => State::UninstallPending,
            2 => State::Staged,
            3 => State::Removed,
            4 => State::Installed,
            5 => State::InstallPending,
            6 => State::Superseded,
            7 => State::PartiallyInstalled,
            other => State::Unknown(other),
        }
    }

    pub fn is_on(self) -> bool {
        matches!(self, State::Installed | State::InstallPending)
    }

    pub fn is_pending(self) -> bool {
        matches!(self, State::InstallPending | State::UninstallPending)
    }
}

/// HRESULTs worth recognizing.
pub mod codes {
    pub const REBOOT_REQUIRED: i32 = 3010;
    pub const REBOOT_REQUIRED_HRESULT: i32 = 0x80070BC2_u32 as i32;
    pub const CANCELLED: i32 = 0x800704C7_u32 as i32;
    pub const ELEVATION_REQUIRED: i32 = 0x800702E4_u32 as i32;
    pub const SOURCE_MISSING: i32 = 0x800F081F_u32 as i32;
    pub const PENDING: i32 = 0x800F082F_u32 as i32;
    pub const UNKNOWN_UPDATE: i32 = 0x800F080C_u32 as i32;
    pub const WSUS_BLOCKED: i32 = 0x800F0954_u32 as i32;
    pub const DOWNLOAD_FAILED: i32 = 0x800F0906_u32 as i32;
    pub const NETWORK_BLOCKED: i32 = 0x800F0907_u32 as i32;
}

/// A DISM failure with its HRESULT, so callers can react to specific codes.
#[derive(Debug)]
pub struct DismError {
    pub hresult: i32,
    pub message: String,
}

impl std::fmt::Display for DismError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({:#010X})", self.message, self.hresult as u32)
    }
}

impl std::error::Error for DismError {}

type Progress = unsafe extern "system" fn(current: u32, total: u32, user: *mut c_void);

#[allow(non_snake_case)]
struct Api {
    DismInitialize: unsafe extern "system" fn(u32, PCWSTR, PCWSTR) -> HRESULT,
    DismOpenSession: unsafe extern "system" fn(PCWSTR, PCWSTR, PCWSTR, *mut u32) -> HRESULT,
    DismCloseSession: unsafe extern "system" fn(u32) -> HRESULT,
    DismDelete: unsafe extern "system" fn(*const c_void) -> HRESULT,
    DismGetLastErrorMessage: unsafe extern "system" fn(*mut *mut PCWSTR) -> HRESULT,
    DismGetFeatureInfo: unsafe extern "system" fn(u32, PCWSTR, PCWSTR, u32, *mut *mut c_void) -> HRESULT,
    DismEnableFeature: unsafe extern "system" fn(
        u32,
        PCWSTR,
        PCWSTR,
        u32,
        BOOL,
        *const PCWSTR,
        u32,
        BOOL,
        HANDLE,
        Option<Progress>,
        *mut c_void,
    ) -> HRESULT,
    DismDisableFeature:
        unsafe extern "system" fn(u32, PCWSTR, PCWSTR, BOOL, HANDLE, Option<Progress>, *mut c_void) -> HRESULT,
    DismGetCapabilityInfo: unsafe extern "system" fn(u32, PCWSTR, *mut *mut c_void) -> HRESULT,
    DismAddCapability: unsafe extern "system" fn(
        u32,
        PCWSTR,
        BOOL,
        *const PCWSTR,
        u32,
        HANDLE,
        Option<Progress>,
        *mut c_void,
    ) -> HRESULT,
    DismRemoveCapability: unsafe extern "system" fn(u32, PCWSTR, HANDLE, Option<Progress>, *mut c_void) -> HRESULT,
}

/// Loads dismapi.dll and initializes DISM once per process (DismInitialize may not be called
/// twice), logging to `log_file`.
fn api(log_file: &Path) -> Result<&'static Api> {
    static API: OnceLock<std::result::Result<Api, String>> = OnceLock::new();
    API.get_or_init(|| load(log_file).map_err(|e| format!("{e:#}"))).as_ref().map_err(|e| anyhow!("{e}"))
}

// Each transmute's target type is the `Api` field it's assigned to, which spells out the
// dismapi.h signature; repeating it at every call would only add places to get it wrong.
#[allow(clippy::missing_transmute_annotations)]
fn load(log_file: &Path) -> Result<Api> {
    let dll = wide("dismapi.dll");
    // SAFETY: NUL-terminated name; the module stays loaded for the life of the process.
    let module = unsafe { LoadLibraryW(dll.as_ptr()) };
    if module.is_null() {
        bail!("loading dismapi.dll: {}", io::Error::last_os_error());
    }
    macro_rules! get {
        ($name:ident) => {{
            let proc_name = concat!(stringify!($name), "\0");
            // SAFETY: NUL-terminated ASCII name.
            let proc = unsafe { GetProcAddress(module, proc_name.as_ptr()) }
                .ok_or_else(|| anyhow!("dismapi.dll has no {} (Windows too old?)", stringify!($name)))?;
            // SAFETY: the declared signature matches dismapi.h for this export.
            unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, _>(proc) }
        }};
    }
    let api = Api {
        DismInitialize: get!(DismInitialize),
        DismOpenSession: get!(DismOpenSession),
        DismCloseSession: get!(DismCloseSession),
        DismDelete: get!(DismDelete),
        DismGetLastErrorMessage: get!(DismGetLastErrorMessage),
        DismGetFeatureInfo: get!(DismGetFeatureInfo),
        DismEnableFeature: get!(DismEnableFeature),
        DismDisableFeature: get!(DismDisableFeature),
        DismGetCapabilityInfo: get!(DismGetCapabilityInfo),
        DismAddCapability: get!(DismAddCapability),
        DismRemoveCapability: get!(DismRemoveCapability),
    };
    if let Some(dir) = log_file.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let log = wide(&log_file.to_string_lossy());
    // SAFETY: valid NUL-terminated log path; no scratch directory.
    let hr = unsafe { (api.DismInitialize)(LOG_ERRORS_WARNINGS_INFO, log.as_ptr(), std::ptr::null()) };
    if hr < 0 {
        if hr == codes::ELEVATION_REQUIRED {
            bail!("DISM needs the agent to run elevated");
        }
        bail!("DismInitialize failed ({:#010X})", hr as u32);
    }
    Ok(api)
}

/// A DISM session on the running Windows.
pub struct Session {
    api: &'static Api,
    handle: u32,
}

impl Session {
    pub fn open(log_file: &Path) -> Result<Self> {
        let api = api(log_file)?;
        let image = wide(DISM_ONLINE_IMAGE);
        let mut handle = 0u32;
        // SAFETY: valid NUL-terminated image path; `handle` is an out parameter.
        let hr = unsafe { (api.DismOpenSession)(image.as_ptr(), std::ptr::null(), std::ptr::null(), &mut handle) };
        if hr < 0 {
            return Err(error(api, hr, "opening a DISM session").into());
        }
        Ok(Self { api, handle })
    }

    pub fn feature_state(&self, name: &str) -> Result<State> {
        let name_w = wide(name);
        let mut info: *mut c_void = std::ptr::null_mut();
        // SAFETY: valid session and name; DISM allocates `info`, freed below.
        let hr = unsafe {
            (self.api.DismGetFeatureInfo)(self.handle, name_w.as_ptr(), std::ptr::null(), PACKAGE_NONE, &mut info)
        };
        if hr < 0 {
            return Err(error(self.api, hr, &format!("looking up feature {name}")).into());
        }
        Ok(State::from_raw(self.read_state(info)))
    }

    pub fn capability_state(&self, name: &str) -> Result<State> {
        let name_w = wide(name);
        let mut info: *mut c_void = std::ptr::null_mut();
        // SAFETY: as above.
        let hr = unsafe { (self.api.DismGetCapabilityInfo)(self.handle, name_w.as_ptr(), &mut info) };
        if hr < 0 {
            return Err(error(self.api, hr, &format!("looking up capability {name}")).into());
        }
        Ok(State::from_raw(self.read_state(info)))
    }

    /// Reads `State` from a DismFeatureInfo/DismCapabilityInfo and frees the structure. Both
    /// start with a string pointer followed by the state, so it's at offset 8 (or 4 on 32-bit)
    /// under either packing.
    fn read_state(&self, info: *mut c_void) -> u32 {
        // SAFETY: `info` was returned by DISM and starts with { PCWSTR; UINT state; ... }.
        let state = unsafe { (info as *const u8).add(size_of::<PCWSTR>()).cast::<u32>().read_unaligned() };
        // SAFETY: DISM allocated it; DismDelete frees it.
        unsafe { (self.api.DismDelete)(info) };
        state
    }

    /// Enables a feature (and, with `all`, the features it depends on).
    pub fn enable_feature(
        &self,
        name: &str,
        all: bool,
        sources: &[String],
        limit_access: bool,
        timeout: Option<Duration>,
        progress: &mut dyn FnMut(u32),
    ) -> Result<()> {
        let name_w = wide(name);
        let (_owned, source_ptrs) = wide_list(sources);
        self.call(timeout, progress, &format!("enabling feature {name}"), |cancel, cb, user| {
            // SAFETY: every pointer is valid for the duration of the call.
            unsafe {
                (self.api.DismEnableFeature)(
                    self.handle,
                    name_w.as_ptr(),
                    std::ptr::null(),
                    PACKAGE_NONE,
                    limit_access as BOOL,
                    if source_ptrs.is_empty() { std::ptr::null() } else { source_ptrs.as_ptr() },
                    source_ptrs.len() as u32,
                    all as BOOL,
                    cancel,
                    cb,
                    user,
                )
            }
        })
    }

    pub fn disable_feature(
        &self,
        name: &str,
        remove_payload: bool,
        timeout: Option<Duration>,
        progress: &mut dyn FnMut(u32),
    ) -> Result<()> {
        let name_w = wide(name);
        self.call(timeout, progress, &format!("disabling feature {name}"), |cancel, cb, user| {
            // SAFETY: as above.
            unsafe {
                (self.api.DismDisableFeature)(
                    self.handle,
                    name_w.as_ptr(),
                    std::ptr::null(),
                    remove_payload as BOOL,
                    cancel,
                    cb,
                    user,
                )
            }
        })
    }

    pub fn add_capability(
        &self,
        name: &str,
        sources: &[String],
        limit_access: bool,
        timeout: Option<Duration>,
        progress: &mut dyn FnMut(u32),
    ) -> Result<()> {
        let name_w = wide(name);
        let (_owned, source_ptrs) = wide_list(sources);
        self.call(timeout, progress, &format!("adding capability {name}"), |cancel, cb, user| {
            // SAFETY: as above.
            unsafe {
                (self.api.DismAddCapability)(
                    self.handle,
                    name_w.as_ptr(),
                    limit_access as BOOL,
                    if source_ptrs.is_empty() { std::ptr::null() } else { source_ptrs.as_ptr() },
                    source_ptrs.len() as u32,
                    cancel,
                    cb,
                    user,
                )
            }
        })
    }

    pub fn remove_capability(
        &self,
        name: &str,
        timeout: Option<Duration>,
        progress: &mut dyn FnMut(u32),
    ) -> Result<()> {
        let name_w = wide(name);
        self.call(timeout, progress, &format!("removing capability {name}"), |cancel, cb, user| {
            // SAFETY: as above.
            unsafe { (self.api.DismRemoveCapability)(self.handle, name_w.as_ptr(), cancel, cb, user) }
        })
    }

    /// Runs one DISM operation with progress reporting and an optional timeout, which signals
    /// DISM's cancel event (DISM then rolls back cleanly, which can itself take a while).
    fn call(
        &self,
        timeout: Option<Duration>,
        progress: &mut dyn FnMut(u32),
        what: &str,
        op: impl FnOnce(HANDLE, Option<Progress>, *mut c_void) -> HRESULT,
    ) -> Result<()> {
        // SAFETY: an unnamed manual-reset event, closed below.
        let cancel = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if cancel.is_null() {
            bail!("creating a cancel event: {}", io::Error::last_os_error());
        }
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let cancel_addr = cancel as usize;
        let timer = timeout.map(|t| {
            std::thread::spawn(move || {
                if done_rx.recv_timeout(t).is_err() {
                    // SAFETY: the event outlives this thread (joined below before closing it).
                    unsafe { SetEvent(cancel_addr as HANDLE) };
                }
            })
        });

        let mut sink = ProgressSink { report: progress, last: u32::MAX };
        let hr = op(cancel, Some(on_progress), (&mut sink as *mut ProgressSink).cast());

        drop(done_tx);
        if let Some(t) = timer {
            let _ = t.join();
        }
        // SAFETY: we own the event.
        unsafe { CloseHandle(cancel) };

        if hr == codes::CANCELLED
            && let Some(t) = timeout
        {
            bail!("{what} timed out after {}s and was cancelled", t.as_secs());
        }
        // 3010 and "reload the session" are successes; callers re-read state to learn about
        // pending restarts rather than relying on how a restart is reported here.
        if hr < 0 && hr != codes::REBOOT_REQUIRED_HRESULT {
            return Err(error(self.api, hr, what).into());
        }
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: closing the session we opened.
        unsafe { (self.api.DismCloseSession)(self.handle) };
    }
}

struct ProgressSink<'a> {
    report: &'a mut dyn FnMut(u32),
    last: u32,
}

/// Reports progress in 10% steps.
unsafe extern "system" fn on_progress(current: u32, total: u32, user: *mut c_void) {
    if user.is_null() || total == 0 {
        return;
    }
    // SAFETY: `user` is the ProgressSink passed to the operation, alive for the whole call, and
    // DISM calls back only while that call is in progress.
    let sink = unsafe { &mut *(user as *mut ProgressSink) };
    let pct = ((current as u64 * 100) / total as u64).min(100) as u32;
    let step = pct / 10 * 10;
    if sink.last == u32::MAX || step > sink.last {
        sink.last = step;
        (sink.report)(step);
    }
}

fn wide_list(items: &[String]) -> (Vec<Vec<u16>>, Vec<PCWSTR>) {
    let owned: Vec<Vec<u16>> = items.iter().map(|s| wide(s)).collect();
    let ptrs = owned.iter().map(|w| w.as_ptr()).collect();
    (owned, ptrs)
}

fn error(api: &Api, hresult: i32, what: &str) -> DismError {
    let mut msg: *mut PCWSTR = std::ptr::null_mut();
    // SAFETY: DISM allocates a DismString { PCWSTR Value }, freed below.
    let detail = if unsafe { (api.DismGetLastErrorMessage)(&mut msg) } >= 0 && !msg.is_null() {
        // SAFETY: `msg` points at a DismString whose first field is the message.
        let text = unsafe {
            let p = *msg;
            let len = (0..).take_while(|&i| *p.add(i) != 0).count();
            String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
        };
        // SAFETY: allocated by DISM.
        unsafe { (api.DismDelete)(msg.cast()) };
        text.trim().to_owned()
    } else {
        String::new()
    };
    let message = if detail.is_empty() { what.to_owned() } else { format!("{what}: {detail}") };
    DismError { hresult, message }
}

/// Whether Windows servicing is waiting for a restart; new operations fail until it happens.
pub fn servicing_reboot_pending() -> bool {
    let hklm = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE);
    hklm.open_subkey(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending").is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_map_from_dism_values() {
        assert_eq!(State::from_raw(4), State::Installed);
        assert!(State::from_raw(5).is_on() && State::from_raw(5).is_pending());
        assert!(!State::from_raw(2).is_on());
        assert_eq!(State::from_raw(99), State::Unknown(99));
    }

    /// Without elevation, this still proves dismapi.dll loads, every function is found, and
    /// DismInitialize can be called: it must answer "elevation required", not crash.
    #[test]
    fn loads_the_api_and_reports_missing_elevation() {
        if crate::token::is_elevated() {
            return; // covered by the elevated tests below
        }
        let log = std::env::temp_dir().join("groundhog-test-dism.log");
        let err = Session::open(&log).err().expect("an unelevated session must fail");
        assert!(format!("{err:#}").contains("elevated"), "{err:#}");
    }

    /// Needs an elevated process (CI runners are); does nothing otherwise.
    #[test]
    fn reads_feature_and_capability_state_when_elevated() {
        if !crate::token::is_elevated() {
            eprintln!("skipped: needs an elevated process");
            return;
        }
        let log = std::env::temp_dir().join("groundhog-test-dism.log");
        let dism = Session::open(&log).unwrap();
        // Present on every client and server edition since Windows 8 / Server 2012.
        let state = dism.feature_state("TelnetClient").unwrap();
        assert!(!matches!(state, State::Unknown(_)), "{state:?}");
        let err = dism.feature_state("Groundhog-No-Such-Feature").unwrap_err();
        assert!(err.downcast_ref::<DismError>().is_some(), "{err:#}");
        let cap = dism.capability_state("OpenSSH.Client~~~~0.0.1.0");
        assert!(cap.is_ok(), "{cap:?}");
    }

    /// Enables and disables a small feature; elevated only. TelnetClient needs no restart and
    /// no download.
    #[test]
    fn enables_and_disables_a_feature_when_elevated() {
        if !crate::token::is_elevated() {
            eprintln!("skipped: needs an elevated process");
            return;
        }
        let log = std::env::temp_dir().join("groundhog-test-dism.log");
        let dism = Session::open(&log).unwrap();
        let before = dism.feature_state("TelnetClient").unwrap();
        let mut seen = Vec::new();
        dism.enable_feature("TelnetClient", true, &[], true, Some(Duration::from_secs(600)), &mut |p| seen.push(p))
            .unwrap();
        assert!(dism.feature_state("TelnetClient").unwrap().is_on());
        if !before.is_on() {
            dism.disable_feature("TelnetClient", false, Some(Duration::from_secs(600)), &mut |_| {}).unwrap();
            assert!(!dism.feature_state("TelnetClient").unwrap().is_on());
        }
    }
}
