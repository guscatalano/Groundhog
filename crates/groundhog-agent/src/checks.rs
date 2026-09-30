//! Running `verify:` checks. Each one polls until it passes or its `within` deadline runs out,
//! so a Groundhogfile never needs a hand-tuned `Start-Sleep` before a check.

use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Result, bail};
use groundhog_core::model::{Check, EventsSince, ServiceState, Shell};
use groundhog_win::env;
use groundhog_win::process::Proc;
use groundhog_win::system::{self, ServiceStatus};

use crate::exec::powershell;

const POLL: Duration = Duration::from_millis(500);
/// Enough to see through a crash loop without reading the whole log.
const MAX_EVENTS: u32 = 200;

/// Passes or fails one check. `started` is when this apply began, for `since: apply`.
pub fn run(check: &Check, started: SystemTime, log: &mut dyn FnMut(&str)) -> Result<()> {
    match check {
        Check::Process { name, stable_for_ms, within_ms } => process(name, *stable_for_ms, *within_ms, log),
        Check::Service { name, status, within_ms } => wait(*within_ms, log, || {
            Ok(match system::service_status(name)? {
                None => Err(format!("service {name} does not exist")),
                Some(s) if matches(s, *status) => Ok(format!("service {name} is {s:?}")),
                Some(s) => Err(format!("service {name} is {s:?}, expected {status:?}")),
            })
        }),
        Check::Port { host, port, within_ms } => wait(*within_ms, log, || {
            let addrs: Vec<_> = match (host.as_str(), *port).to_socket_addrs() {
                Ok(a) => a.collect(),
                Err(e) => return Ok(Err(format!("cannot resolve {host}: {e}"))),
            };
            for addr in &addrs {
                if TcpStream::connect_timeout(addr, Duration::from_secs(2)).is_ok() {
                    return Ok(Ok(format!("{addr} accepted a connection")));
                }
            }
            Ok(Err(format!("nothing accepts connections on {host}:{port}")))
        }),
        Check::File { path, within_ms } => {
            let expanded = env::expand_path(path)?;
            wait(*within_ms, log, || {
                Ok(if Path::new(&expanded).exists() {
                    Ok(format!("{expanded} exists"))
                } else {
                    Err(format!("{expanded} does not exist"))
                })
            })
        }
        Check::Command { command, shell, within_ms } => wait(*within_ms, log, || {
            let mut output = Vec::new();
            let proc = match shell {
                Shell::Cmd => Proc::new("cmd.exe").args(["/d", "/s", "/c"]).raw(Some(&format!("\"{command}\""))),
                _ => powershell(*shell, command),
            };
            let code = proc.run(&mut |l| output.push(l.to_owned()))?.code;
            Ok(if code == 0 {
                Ok("command succeeded".to_owned())
            } else {
                let tail = output.iter().rev().take(5).rev().cloned().collect::<Vec<_>>().join(" / ");
                Err(if tail.is_empty() {
                    format!("command exited with {code}")
                } else {
                    format!("command exited with {code}: {tail}")
                })
            })
        }),
        Check::EventLog { log: event_log, provider, must_contain, must_not_contain, since, within_ms } => {
            let since = (*since == EventsSince::Apply).then_some(started);
            let deadline = Instant::now() + Duration::from_millis(*within_ms);
            // Wanted events may still be on their way (a service logs "started" a moment after
            // its process appears), so keep looking until `within`. An unwanted one fails at once.
            loop {
                let events = system::provider_events(event_log, provider, since, MAX_EVENTS)?;
                let lowered: Vec<String> = events.iter().map(|e| e.to_lowercase()).collect();
                for pattern in must_not_contain {
                    let p = pattern.to_lowercase();
                    if let Some(i) = lowered.iter().position(|e| e.contains(&p)) {
                        bail!("a {provider} event contains '{pattern}': {}", summarize(&events[i]));
                    }
                }
                let missing = must_contain.iter().find(|p| !lowered.iter().any(|e| e.contains(&p.to_lowercase())));
                match missing {
                    None => {
                        log(&format!("{} {provider} events checked", events.len()));
                        return Ok(());
                    }
                    Some(p) if Instant::now() >= deadline => bail!(
                        "no {provider} event in {event_log} contains '{p}' ({} events checked, waited {})",
                        events.len(),
                        seconds(*within_ms)
                    ),
                    Some(_) => std::thread::sleep(POLL),
                }
            }
        }
    }
}

fn matches(actual: ServiceStatus, wanted: ServiceState) -> bool {
    match wanted {
        ServiceState::Running => actual == ServiceStatus::Running,
        ServiceState::Stopped => actual == ServiceStatus::Stopped,
    }
}

/// Retries `probe` until it passes or `within_ms` runs out. A probe returns `Ok(Ok(detail))` on
/// success, `Ok(Err(reason))` for "not yet", and `Err` for errors that retrying won't fix.
fn wait(
    within_ms: u64,
    log: &mut dyn FnMut(&str),
    mut probe: impl FnMut() -> Result<std::result::Result<String, String>>,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_millis(within_ms);
    loop {
        match probe()? {
            Ok(detail) => {
                log(&detail);
                return Ok(());
            }
            Err(reason) if Instant::now() >= deadline => bail!("{reason} (waited {})", seconds(within_ms)),
            Err(_) => std::thread::sleep(POLL),
        }
    }
}

/// Waits for the process to appear, then requires one PID to stay alive for `stable_for_ms`.
/// A PID that dies early (a crash loop) doesn't pass; the check keeps watching for a stable
/// one until `within_ms` runs out.
fn process(name: &str, stable_for_ms: u64, within_ms: u64, log: &mut dyn FnMut(&str)) -> Result<()> {
    let deadline = Instant::now() + Duration::from_millis(within_ms);
    let stable = Duration::from_millis(stable_for_ms);
    let mut last_problem = format!("no {name} process");
    loop {
        if let Some(&pid) = system::find_processes(name)?.first() {
            let seen = Instant::now();
            let mut alive = true;
            while seen.elapsed() < stable {
                std::thread::sleep(POLL.min(stable));
                if !system::find_processes(name)?.contains(&pid) {
                    alive = false;
                    break;
                }
            }
            if alive {
                let how_long =
                    if stable.is_zero() { String::new() } else { format!(", stable for {}", seconds(stable_for_ms)) };
                log(&format!("{name} running as pid {pid}{how_long}"));
                return Ok(());
            }
            last_problem = format!("{name} pid {pid} exited after {:.1}s", seen.elapsed().as_secs_f32());
            log(&last_problem);
        }
        if Instant::now() >= deadline {
            bail!("{last_problem} (waited {})", seconds(within_ms));
        }
        std::thread::sleep(POLL);
    }
}

fn seconds(ms: u64) -> String {
    if ms.is_multiple_of(1000) { format!("{}s", ms / 1000) } else { format!("{:.1}s", ms as f64 / 1000.0) }
}

/// A short, readable version of an event: its message if it has one, otherwise its data.
fn summarize(event_xml: &str) -> String {
    let message = event_xml.split("<Message>").nth(1).and_then(|s| s.split("</Message>").next()).map(str::trim);
    let text = match message {
        Some(m) if !m.is_empty() => m.to_owned(),
        // No registered message: show the event's data values instead.
        _ => event_xml
            .split("<Data")
            .skip(1)
            .filter_map(|s| s.split_once('>'))
            .filter(|(attrs, _)| !attrs.ends_with('/'))
            .filter_map(|(_, rest)| rest.split("</Data>").next())
            .map(str::trim)
            .filter(|d| !d.is_empty())
            .collect::<Vec<_>>()
            .join(" | "),
    };
    let one_line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    one_line.chars().take(200).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(c: &Check) -> Result<Vec<String>> {
        let mut lines = Vec::new();
        run(c, SystemTime::now(), &mut |l| lines.push(l.to_owned())).map(|_| lines)
    }

    #[test]
    fn process_checks_find_this_test_and_fail_fast_for_missing_ones() {
        let me = std::env::current_exe().unwrap().file_name().unwrap().to_str().unwrap().to_owned();
        let lines = check(&Check::Process { name: me, stable_for_ms: 600, within_ms: 0 }).unwrap();
        assert!(lines[0].contains("stable for 0.6s"), "{lines:?}");

        let started = Instant::now();
        let err =
            check(&Check::Process { name: "groundhog-nope".into(), stable_for_ms: 0, within_ms: 1000 }).unwrap_err();
        assert!(err.to_string().contains("no groundhog-nope process (waited 1s)"), "{err}");
        assert!(started.elapsed() >= Duration::from_secs(1));
    }

    #[test]
    fn process_checks_reject_a_crash_loop() {
        // A uniquely named process that lives ~1s never satisfies "stable for 3s". (A real name
        // like ping.exe won't do: other copies may be running on the machine.)
        let dir = tempfile::tempdir().unwrap();
        let name = format!("groundhog-short-{}", std::process::id());
        let exe = dir.path().join(format!("{name}.exe"));
        std::fs::copy(r"C:\Windows\System32\cmd.exe", &exe).unwrap();
        let mut child = std::process::Command::new(&exe).args(["/c", "ping -n 2 127.0.0.1 >nul"]).spawn().unwrap();
        let err = check(&Check::Process { name, stable_for_ms: 3000, within_ms: 0 }).unwrap_err();
        let _ = child.wait();
        assert!(err.to_string().contains("exited after"), "{err}");
    }

    #[test]
    fn service_port_file_and_command_checks() {
        assert!(
            check(&Check::Service { name: "EventLog".into(), status: ServiceState::Running, within_ms: 0 }).is_ok()
        );
        let err = check(&Check::Service { name: "groundhog-nope".into(), status: ServiceState::Running, within_ms: 0 });
        assert!(err.unwrap_err().to_string().contains("does not exist"));

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(check(&Check::Port { host: "127.0.0.1".into(), port, within_ms: 0 }).is_ok());
        drop(listener);
        assert!(check(&Check::Port { host: "127.0.0.1".into(), port, within_ms: 0 }).is_err());

        assert!(check(&Check::File { path: r"%SystemRoot%\System32\cmd.exe".into(), within_ms: 0 }).is_ok());
        assert!(check(&Check::File { path: r"C:\groundhog-nope".into(), within_ms: 0 }).is_err());

        assert!(check(&Check::Command { command: "exit 0".into(), shell: Shell::Cmd, within_ms: 0 }).is_ok());
        let err = check(&Check::Command {
            command: "Write-Output 'not ready'; exit 3".into(),
            shell: Shell::Powershell,
            within_ms: 0,
        });
        assert!(err.unwrap_err().to_string().contains("exited with 3: not ready"));
    }

    #[test]
    fn eventlog_checks_pass_when_a_provider_has_no_events() {
        // The exact trap from a hand-written Get-WinEvent check: nothing logged is a pass.
        let eventlog = |must_contain: &[&str], must_not_contain: &[&str]| Check::EventLog {
            log: "Application".into(),
            provider: "groundhog-no-such-provider".into(),
            must_contain: must_contain.iter().map(|s| s.to_string()).collect(),
            must_not_contain: must_not_contain.iter().map(|s| s.to_string()).collect(),
            since: EventsSince::Apply,
            within_ms: 1000,
        };
        let started = Instant::now();
        assert!(check(&eventlog(&[], &["0xC0000142"])).is_ok());
        assert!(started.elapsed() < Duration::from_secs(1), "nothing to wait for, so no waiting");

        let err = check(&eventlog(&["started"], &[])).unwrap_err();
        assert!(err.to_string().contains("no groundhog-no-such-provider event"), "{err}");
        assert!(err.to_string().contains("waited 1s"), "must-contain waits for its event: {err}");
    }

    #[test]
    fn eventlog_checks_find_real_events() {
        // The event log service writes to the System log whenever Windows starts.
        let c = Check::EventLog {
            log: "System".into(),
            provider: "EventLog".into(),
            must_contain: vec!["eventlog".into()],
            must_not_contain: vec!["groundhog-never-logged".into()],
            since: EventsSince::Any,
            within_ms: 0,
        };
        let lines = check(&c).unwrap();
        assert!(lines[0].ends_with("EventLog events checked"), "{lines:?}");
    }

    #[test]
    fn summarizes_events_by_message_or_data() {
        let with_msg = "<Event><EventData><Data>x</Data></EventData><RenderingInfo><Message>Faulting app\r\n  rdpeek.exe</Message></RenderingInfo></Event>";
        assert_eq!(summarize(with_msg), "Faulting app rdpeek.exe");
        let data_only = "<Event><EventData><Data Name='a'>first</Data><Data>second</Data></EventData></Event>";
        assert_eq!(summarize(data_only), "first | second");
    }
}
