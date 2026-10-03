//! Read-only questions about the running system, for health checks: which processes are
//! running, what state a service is in, and what an event log says.

use std::io;
use std::time::SystemTime;

use anyhow::{Result, bail};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_SERVICE_DOES_NOT_EXIST, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_HANDLE, SC_MANAGER_CONNECT,
    SERVICE_QUERY_STATUS, SERVICE_STATUS,
};

use crate::process::Proc;
use crate::wide;

/// PIDs of running processes whose image name matches `name` (case-insensitive; the `.exe`
/// suffix is optional), in snapshot order.
/// The Windows build number and whether this is a Server edition, from the registry (which,
/// unlike `GetVersionEx`, doesn't lie to programs without a compatibility manifest). A build
/// of 0 means it couldn't be read.
pub fn windows_version() -> (u32, bool) {
    let key = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
    let Ok(key) = key else { return (0, false) };
    let build = key.get_value::<String, _>("CurrentBuildNumber").ok().and_then(|b| b.parse().ok()).unwrap_or(0);
    let server = key.get_value::<String, _>("InstallationType").is_ok_and(|t| t.eq_ignore_ascii_case("Server"));
    (build, server)
}

pub fn find_processes(name: &str) -> Result<Vec<u32>> {
    let want = name.to_ascii_lowercase();
    let want = want.strip_suffix(".exe").unwrap_or(&want).to_owned();

    // SAFETY: a process snapshot takes no pointers; the handle is closed below.
    let snap: HANDLE = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE {
        bail!("process snapshot failed: {}", io::Error::last_os_error());
    }
    let mut pids = Vec::new();
    // SAFETY: PROCESSENTRY32W is plain data; dwSize is set as the API requires.
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
    // SAFETY: `snap` is a valid snapshot and `entry` a correctly sized out buffer.
    let mut ok = unsafe { Process32FirstW(snap, &mut entry) };
    while ok != 0 {
        let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
        let exe = String::from_utf16_lossy(&entry.szExeFile[..len]).to_ascii_lowercase();
        if exe.strip_suffix(".exe").unwrap_or(&exe) == want {
            pids.push(entry.th32ProcessID);
        }
        // SAFETY: as above.
        ok = unsafe { Process32NextW(snap, &mut entry) };
    }
    // SAFETY: we own the snapshot handle.
    unsafe { CloseHandle(snap) };
    Ok(pids)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStatus {
    Stopped,
    StartPending,
    StopPending,
    Running,
    ContinuePending,
    PausePending,
    Paused,
}

struct ScHandle(SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        // SAFETY: we own the handle and close it once.
        unsafe { CloseServiceHandle(self.0) };
    }
}

/// The current state of a service, or `None` if no service has that name.
pub fn service_status(name: &str) -> Result<Option<ServiceStatus>> {
    // SAFETY: null machine and database mean the local, active database.
    let scm = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if scm.is_null() {
        bail!("opening the service manager: {}", io::Error::last_os_error());
    }
    let scm = ScHandle(scm);
    let name_w = wide(name);
    // SAFETY: `name_w` is NUL-terminated and `scm` is open.
    let svc = unsafe { OpenServiceW(scm.0, name_w.as_ptr(), SERVICE_QUERY_STATUS) };
    if svc.is_null() {
        // SAFETY: trivially safe.
        if unsafe { GetLastError() } == ERROR_SERVICE_DOES_NOT_EXIST {
            return Ok(None);
        }
        bail!("opening service {name}: {}", io::Error::last_os_error());
    }
    let svc = ScHandle(svc);
    // SAFETY: SERVICE_STATUS is plain data used as an out buffer.
    let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
    // SAFETY: `svc` was opened with SERVICE_QUERY_STATUS.
    if unsafe { QueryServiceStatus(svc.0, &mut status) } == 0 {
        bail!("querying service {name}: {}", io::Error::last_os_error());
    }
    Ok(Some(match status.dwCurrentState {
        1 => ServiceStatus::Stopped,
        2 => ServiceStatus::StartPending,
        3 => ServiceStatus::StopPending,
        4 => ServiceStatus::Running,
        5 => ServiceStatus::ContinuePending,
        6 => ServiceStatus::PausePending,
        _ => ServiceStatus::Paused,
    }))
}

/// The events `provider` wrote to `log` (newest first, up to `max`), each as its rendered
/// event XML with entities decoded. That includes the formatted message when the provider
/// registered one, and the raw event data either way. Matching against it therefore works
/// for providers without a message file, and on every Windows display language.
pub fn provider_events(log: &str, provider: &str, since: Option<SystemTime>, max: u32) -> Result<Vec<String>> {
    if provider.contains(['\'', '"', '<', '>', '&']) || log.contains(['"', '\'']) {
        bail!("unsupported characters in event log or provider name");
    }
    let mut filter = format!("Provider[@Name='{provider}']");
    if let Some(t) = since {
        filter += &format!(" and TimeCreated[@SystemTime>='{}']", humantime::format_rfc3339_millis(t));
    }
    let query = format!("/q:*[System[{filter}]]");
    let mut errors = Vec::new();
    let out = Proc {
        capture_stdout: true,
        ..Proc::new("wevtutil.exe")
            .args(["qe", log, query.as_str(), "/f:RenderedXml", "/rd:true"])
            .args([format!("/c:{max}")])
    }
    .run(&mut |l| errors.push(l.to_owned()))?;
    if out.code != 0 {
        bail!("reading event log '{log}' failed ({}): {}", out.code, errors.join(" "));
    }
    Ok(out.stdout.split("<Event ").skip(1).map(|e| xml_unescape(&format!("<Event {e}"))).collect())
}

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_this_process_by_name() {
        let exe = std::env::current_exe().unwrap();
        let name = exe.file_name().unwrap().to_str().unwrap();
        assert!(find_processes(name).unwrap().contains(&std::process::id()));
        assert!(find_processes(&name.to_uppercase().replace(".EXE", "")).unwrap().contains(&std::process::id()));
        assert!(find_processes("groundhog-no-such-process").unwrap().is_empty());
    }

    #[test]
    fn reads_service_status() {
        // The event log service runs on every Windows machine.
        assert_eq!(service_status("EventLog").unwrap(), Some(ServiceStatus::Running));
        assert_eq!(service_status("groundhog-no-such-service").unwrap(), None);
    }

    #[test]
    fn queries_event_logs_without_errors_for_empty_results() {
        assert!(provider_events("Application", "groundhog-no-such-provider", None, 5).unwrap().is_empty());
        // An existing provider filtered to the future also yields nothing, not an error.
        let future = SystemTime::now() + std::time::Duration::from_secs(3600);
        assert!(provider_events("System", "EventLog", Some(future), 5).unwrap().is_empty());
        assert!(provider_events("groundhog-no-such-log", "x", None, 5).is_err());
    }
}
