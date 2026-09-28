//! The logon scheduled task that runs the agent in templated VMs.

use std::path::Path;

use anyhow::{Result, bail};

use crate::process::Proc;

pub const TASK_NAME: &str = r"Groundhog\RunPending";

/// Registers (or replaces) a task that runs `"<exe>" <args>` elevated whenever the current
/// user logs on. `/IT` means it runs only in that user's interactive session, which is what
/// per-user configuration needs and avoids storing a password.
pub fn install_logon_task(exe: &Path, args: &str, on_line: &mut dyn FnMut(&str)) -> Result<()> {
    let user = match (std::env::var("USERDOMAIN"), std::env::var("USERNAME")) {
        (Ok(d), Ok(u)) => format!(r"{d}\{u}"),
        (_, Ok(u)) => u,
        _ => bail!("cannot determine the current user"),
    };
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
