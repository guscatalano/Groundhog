//! Self-update: before applying anything, replace this exe with a newer agent from the update
//! source and hand over to it.
//!
//! A running exe can't be overwritten on Windows, but it can be renamed. So the new agent is
//! written next to this one, this one is renamed aside, the new one takes its name, and it's
//! started with the same arguments. The renamed copy is deleted on a later run.
//!
//! Updating must never be what breaks a machine: any failure (no network, a bad hash, a
//! read-only folder) is logged and the current agent carries on.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result};
use groundhog_core::content::ContentStore;
use groundhog_core::report::Reporter;
use groundhog_core::update::{self, Candidate, Policy, Version};

/// Set for the agent we hand over to, so it doesn't try to update again (and loop).
const HANDED_OVER_FROM: &str = "GROUNDHOG_UPDATED_FROM";

pub struct Settings {
    pub policy: Policy,
    pub from: Option<String>,
}

pub enum Outcome {
    /// Nothing to do, or updating failed and this agent carries on.
    Continue,
    /// A newer agent ran in our place; exit with its code.
    HandedOver(i32),
}

/// Checks the source and, if there's an agent to switch to, installs it and runs it in our
/// place with the same arguments.
pub fn run(settings: &Settings, home: &Path, content: &ContentStore, reporter: &dyn Reporter) -> Outcome {
    if let Ok(from) = std::env::var(HANDED_OVER_FROM) {
        reporter.log(&format!("updated from groundhog-agent {from}"));
        return Outcome::Continue;
    }
    remove_old_copies();
    if settings.policy == Policy::Off {
        return Outcome::Continue;
    }
    match try_update(settings, home, content, reporter) {
        Ok(Some(code)) => Outcome::HandedOver(code),
        Ok(None) => Outcome::Continue,
        Err(e) => {
            reporter.note(&format!("warning: agent update skipped: {e:#}"));
            Outcome::Continue
        }
    }
}

fn try_update(
    settings: &Settings,
    home: &Path,
    content: &ContentStore,
    reporter: &dyn Reporter,
) -> Result<Option<i32>> {
    let current = Version::current();
    let Some(exe) = update_now(settings, home, content, reporter)? else {
        return Ok(None);
    };
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let status = std::process::Command::new(&exe)
        .args(&args)
        .env(HANDED_OVER_FROM, current.to_string())
        .status()
        .with_context(|| format!("starting {}", exe.display()))?;
    Ok(Some(status.code().unwrap_or(1)))
}

/// Installs the agent the source offers, if the policy wants it. Returns where it went.
pub fn update_now(
    settings: &Settings,
    home: &Path,
    content: &ContentStore,
    reporter: &dyn Reporter,
) -> Result<Option<PathBuf>> {
    let current = Version::current();
    let manifest = update::manifest_url(settings.from.as_deref(), &settings.policy, &std::env::current_dir()?)?;
    let Some(candidate) = update::find_update(content, &manifest, &settings.policy, &current)? else {
        return Ok(None);
    };
    reporter.note(&format!("updating groundhog-agent {current} -> {} from {}", candidate.version, candidate.url));
    install(&candidate, home, content, reporter).map(Some)
}

/// Puts the new agent in place of this one when possible, or in `<home>\versions\<v>` when
/// this exe's folder isn't writable (a read-only mapped folder, say). Returns its path.
fn install(candidate: &Candidate, home: &Path, content: &ContentStore, reporter: &dyn Reporter) -> Result<PathBuf> {
    let bytes = content.get(&candidate.url, Some(&candidate.sha256))?.bytes;
    let current = std::env::current_exe()?;
    match replace_exe(&current, &bytes) {
        Ok(()) => Ok(current),
        Err(e) => {
            let dir = home.join("versions").join(candidate.version.to_string());
            std::fs::create_dir_all(&dir)?;
            let path = dir.join("groundhog-agent.exe");
            std::fs::write(&path, &bytes).with_context(|| format!("writing {}", path.display()))?;
            reporter.log(&format!(
                "could not replace {} ({e:#}); running {} instead",
                current.display(),
                path.display()
            ));
            Ok(path)
        }
    }
}

fn replace_exe(current: &Path, bytes: &[u8]) -> Result<()> {
    let new = with_suffix(current, ".new");
    std::fs::write(&new, bytes).with_context(|| format!("writing {}", new.display()))?;
    let stamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_millis());
    let old = with_suffix(current, &format!(".old-{stamp}"));
    if let Err(e) = std::fs::rename(current, &old) {
        let _ = std::fs::remove_file(&new);
        return Err(e).with_context(|| format!("moving {} aside", current.display()));
    }
    if let Err(e) = std::fs::rename(&new, current) {
        let _ = std::fs::rename(&old, current);
        return Err(e).with_context(|| format!("putting the new agent at {}", current.display()));
    }
    Ok(())
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    path.with_file_name(name)
}

/// Best effort: copies set aside by earlier updates, once nothing runs them anymore.
fn remove_old_copies() {
    let Ok(current) = std::env::current_exe() else { return };
    let (Some(dir), Some(name)) = (current.parent(), current.file_name()) else { return };
    let prefix = format!("{}.old-", name.to_string_lossy());
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.filter_map(Result::ok) {
        if entry.file_name().to_string_lossy().starts_with(&prefix) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Explains a Groundhogfile's `agent:` requirement that this agent doesn't meet, in terms of
/// what would fix it under the current update settings.
pub fn explain_requirement(required: &Version, settings: &Settings) -> String {
    let current = Version::current();
    let hint = match &settings.policy {
        Policy::Off => {
            "Agent updates are off: pass --update (or set agentUpdate in pending.json), or update the agent".to_owned()
        }
        Policy::Pinned(v) => format!("The agent is pinned to {v}; pin a newer version or use 'latest'"),
        Policy::Latest => {
            let source = settings.from.as_deref().unwrap_or(update::GITHUB_RELEASES);
            format!("The update source ({source}) doesn't offer a new enough agent yet")
        }
    };
    format!("this Groundhogfile needs groundhog-agent {required} or newer, and this is {current}. {hint}.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_a_running_exe_by_renaming_it_aside() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("agent.exe");
        std::fs::copy(r"C:\Windows\System32\cmd.exe", &exe).unwrap();
        let mut running = std::process::Command::new(&exe).args(["/c", "ping -n 3 127.0.0.1 >nul"]).spawn().unwrap();

        replace_exe(&exe, b"new agent").unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"new agent");
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().any(|n| n.starts_with("agent.exe.old-")), "{names:?}");
        running.wait().unwrap();
    }

    #[test]
    fn explains_unmet_requirements_by_policy() {
        let req = Version::parse("99.0.0").unwrap();
        let off = explain_requirement(&req, &Settings { policy: Policy::Off, from: None });
        assert!(off.contains("needs groundhog-agent 99.0.0") && off.contains("--update"), "{off}");
        let latest = explain_requirement(&req, &Settings { policy: Policy::Latest, from: Some(r"\\nas\gh".into()) });
        assert!(latest.contains(r"\\nas\gh"), "{latest}");
    }
}
