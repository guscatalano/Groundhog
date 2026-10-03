//! The logon scheduled task that runs the agent in templated VMs.

use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};

use crate::process::Proc;

pub const TASK_NAME: &str = r"Groundhog\RunPending";

/// Registers (or replaces) a task that runs `"<exe>" <args>` elevated whenever the current
/// user logs on. `/IT` means it runs only in that user's interactive session, which is what
/// per-user configuration needs and avoids storing a password.
pub fn install_logon_task(exe: &Path, args: &str, on_line: &mut dyn FnMut(&str)) -> Result<()> {
    let user = current_user()?;
    let action = format!(r#""{}" {args}"#, exe.display());
    if action.len() > 261 {
        bail!("task command line is longer than schtasks allows: {action}");
    }
    let out = Proc::new("schtasks.exe")
        .args(["/Create", "/F", "/TN", TASK_NAME, "/SC", "ONLOGON", "/RL", "HIGHEST", "/IT", "/DELAY", "0000:15"])
        .args(["/RU", user.as_str(), "/TR", action.as_str()])
        .run(on_line)?;
    if out.code != 0 {
        bail!("schtasks exited with {}", out.code);
    }
    Ok(())
}

fn current_user() -> Result<String> {
    Ok(match (std::env::var("USERDOMAIN"), std::env::var("USERNAME")) {
        (Ok(d), Ok(u)) => format!(r"{d}\{u}"),
        (_, Ok(u)) => u,
        _ => bail!("cannot determine the current user"),
    })
}

/// Runs a program as the current user *without* elevation and waits for it, through a
/// one-off scheduled task with the limited run level in the user's session. Some tools refuse
/// to act from an elevated process (winget won't uninstall a per-user package), and the agent
/// is usually elevated. Returns the exit code and the program's output lines.
pub fn run_unelevated(program: &Path, args: &[&str], timeout: Duration) -> Result<(i32, Vec<String>)> {
    let dir = std::env::temp_dir().join("groundhog-unelevated");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let id = format!("{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis());
    let (script, out, done) =
        (dir.join(format!("{id}.cmd")), dir.join(format!("{id}.log")), dir.join(format!("{id}.code")));
    if args.iter().any(|a| a.contains(['"', '%', '&', '|', '<', '>', '^'])) {
        bail!("refusing to pass characters cmd would interpret to an unelevated command: {args:?}");
    }
    let body = format!(
        // Redirection first: `echo 2> file` would redirect stderr instead of writing "2".
        "@echo off\r\n\"{}\" {} > \"{}\" 2>&1\r\n> \"{}\" echo %errorlevel%\r\n",
        program.display(),
        args.join(" "),
        out.display(),
        done.display()
    );
    std::fs::write(&script, body).with_context(|| format!("writing {}", script.display()))?;
    let task = format!(r"Groundhog\Unelevated-{id}");
    let action = format!("\"{}\"", script.display());
    let user = current_user()?;
    let quiet = &mut |_: &str| {};
    let created = Proc::new("schtasks.exe")
        .args(["/Create", "/F", "/TN", task.as_str(), "/SC", "ONCE", "/ST", "00:00", "/RL", "LIMITED", "/IT"])
        .args(["/RU", user.as_str(), "/TR", action.as_str()])
        .run(quiet)?;
    if created.code != 0 {
        bail!("couldn't create a task to run {} unelevated (schtasks exited with {})", program.display(), created.code);
    }
    let result = (|| {
        let ran = Proc::new("schtasks.exe").args(["/Run", "/TN", task.as_str()]).run(quiet)?;
        if ran.code != 0 {
            bail!("couldn't start the unelevated task (schtasks exited with {})", ran.code);
        }
        let deadline = Instant::now() + timeout;
        loop {
            if let Ok(code) = std::fs::read_to_string(&done)
                && let Ok(code) = code.trim().parse::<i32>()
            {
                let lines = std::fs::read_to_string(&out).unwrap_or_default().lines().map(str::to_owned).collect();
                return Ok((code, lines));
            }
            if Instant::now() > deadline {
                bail!("{} didn't finish within {}s when run unelevated", program.display(), timeout.as_secs());
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    })();
    let _ = Proc::new("schtasks.exe").args(["/Delete", "/F", "/TN", task.as_str()]).run(quiet);
    for f in [&script, &out, &done] {
        let _ = std::fs::remove_file(f);
    }
    result
}
