//! `ssh:` steps: the server's config, the keys that may sign in, known hosts, and a key pair.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use groundhog_core::model::{Shell, SshSetting};
use groundhog_win::process::Proc;

use crate::exec::powershell;

const OPENSSH: &str = r"C:\Windows\System32\OpenSSH";

pub(crate) fn program_data_ssh() -> PathBuf {
    let pd = std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into());
    PathBuf::from(pd).join("ssh")
}

pub(crate) fn home_ssh() -> Result<PathBuf> {
    let home = std::env::var_os("USERPROFILE").context("USERPROFILE isn't set")?;
    Ok(PathBuf::from(home).join(".ssh"))
}

/// The value sshd uses for `key`: its first line outside any `Match` block.
fn current(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        let mut words = line.split_whitespace();
        let Some(word) = words.next() else { continue };
        if word.eq_ignore_ascii_case("match") {
            return None;
        }
        if word.eq_ignore_ascii_case(key) {
            return Some(words.collect::<Vec<_>>().join(" "));
        }
    }
    None
}

/// `text` with each keyword set: its first line replaced, or a commented-out one taken, or a
/// line added before the first `Match` block.
fn set_values(text: &str, values: &BTreeMap<String, String>) -> String {
    let nl = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let first_match = |lines: &[String]| {
        lines
            .iter()
            .position(|l| l.split_whitespace().next().is_some_and(|w| w.eq_ignore_ascii_case("match")))
            .unwrap_or(lines.len())
    };
    for (key, value) in values {
        let end = first_match(&lines);
        let want = format!("{key} {value}");
        let word = |l: &str| l.split_whitespace().next().map(str::to_owned);
        if let Some(i) = (0..end).find(|&i| word(&lines[i]).is_some_and(|w| w.eq_ignore_ascii_case(key))) {
            lines[i] = want;
        } else if let Some(i) = (0..end).find(|&i| {
            let l = lines[i].trim_start();
            l.strip_prefix('#').and_then(word).is_some_and(|w| w.eq_ignore_ascii_case(key))
        }) {
            lines[i] = want;
        } else {
            lines.insert(end, want);
        }
    }
    let mut out = lines.join(nl);
    out.push_str(nl);
    out
}

fn config_differs(values: &BTreeMap<String, String>) -> Result<bool> {
    let path = program_data_ssh().join("sshd_config");
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    Ok(values.iter().any(|(k, v)| {
        current(&text, k).as_deref() != Some(v.split_whitespace().collect::<Vec<_>>().join(" ").as_str())
    }))
}

/// A key line's type and key, without its comment.
fn key_id(line: &str) -> String {
    let words: Vec<&str> = line.split_whitespace().collect();
    // Options come first when given (`from="..." ssh-ed25519 AAAA...`).
    let at = words.iter().position(|w| w.starts_with("ssh-") || w.starts_with("ecdsa-") || w.starts_with("sk-"));
    match at {
        Some(i) => words[i..].iter().take(2).copied().collect::<Vec<_>>().join(" "),
        None => line.trim().to_owned(),
    }
}

/// The lines of `lines` that `path` doesn't have yet, compared by `id`.
fn missing(path: &PathBuf, lines: &[String], id: fn(&str) -> String) -> Vec<String> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let have: Vec<String> = text.lines().map(id).collect();
    lines.iter().filter(|l| !have.contains(&id(l))).cloned().collect()
}

fn append(path: &PathBuf, lines: &[String]) -> Result<()> {
    std::fs::create_dir_all(path.parent().expect("has a folder"))?;
    let mut text = std::fs::read_to_string(path).unwrap_or_default();
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    for l in lines {
        text.push_str(l);
        text.push('\n');
    }
    std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))
}

pub(crate) fn key_path(kind: &str) -> Result<PathBuf> {
    Ok(home_ssh()?.join(format!("id_{kind}")))
}

fn same_line(l: &str) -> String {
    l.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn ps(script: &str, log: &mut dyn FnMut(&str)) -> Result<()> {
    let out = powershell(Shell::Powershell, &format!("$ErrorActionPreference = 'Stop'\n{script}")).run(log)?;
    if out.code != 0 {
        bail!("PowerShell exited with {}", out.code);
    }
    Ok(())
}

pub fn differs(s: &SshSetting) -> Result<bool> {
    Ok(match s {
        SshSetting::ServerConfig { values } => config_differs(values)?,
        SshSetting::AuthorizedKeys { keys } => {
            !missing(&program_data_ssh().join("administrators_authorized_keys"), keys, key_id).is_empty()
        }
        SshSetting::KnownHosts { lines } => !missing(&home_ssh()?.join("known_hosts"), lines, same_line).is_empty(),
        SshSetting::Key { kind } => !key_path(kind)?.exists(),
    })
}

pub fn apply(s: &SshSetting, log: &mut dyn FnMut(&str)) -> Result<bool> {
    if !differs(s)? {
        return Ok(false);
    }
    match s {
        SshSetting::ServerConfig { values } => {
            let path = program_data_ssh().join("sshd_config");
            let old = match std::fs::read_to_string(&path) {
                Ok(t) => t,
                // sshd writes its config the first time it starts; until then, its default is it.
                Err(_) => std::fs::read_to_string(PathBuf::from(OPENSSH).join("sshd_config_default"))
                    .context("the OpenSSH server isn't installed (set ssh.server: true)")?,
            };
            std::fs::write(&path, set_values(&old, values)).with_context(|| format!("writing {}", path.display()))?;
            // sshd checks its config; one it won't start with is put back.
            let mut errors = Vec::new();
            let out = Proc::new(PathBuf::from(OPENSSH).join("sshd.exe"))
                .args(["-t"])
                .run(&mut |l| errors.push(l.to_owned()))?;
            if out.code != 0 {
                std::fs::write(&path, &old)?;
                bail!("sshd won't take it, so it was put back: {}", errors.join(" "));
            }
            ps(
                "if ((Get-Service sshd -ErrorAction SilentlyContinue).Status -eq 'Running') { Restart-Service sshd }",
                log,
            )?;
        }
        SshSetting::AuthorizedKeys { keys } => {
            let path = program_data_ssh().join("administrators_authorized_keys");
            append(&path, &missing(&path, keys, key_id))?;
            // sshd ignores the file unless only administrators and SYSTEM can write it.
            let out = Proc::new("icacls.exe")
                .args([path.display().to_string()])
                .args(["/inheritance:r", "/grant", "*S-1-5-32-544:F", "/grant", "*S-1-5-18:F"])
                .run(&mut |_| {})?;
            if out.code != 0 {
                bail!("icacls exited with {}", out.code);
            }
        }
        SshSetting::KnownHosts { lines } => {
            let path = home_ssh()?.join("known_hosts");
            append(&path, &missing(&path, lines, same_line))?;
        }
        SshSetting::Key { kind } => {
            let path = key_path(kind)?;
            std::fs::create_dir_all(path.parent().expect("has a folder"))?;
            let comment = format!(
                "{}@{}",
                std::env::var("USERNAME").unwrap_or_default(),
                std::env::var("COMPUTERNAME").unwrap_or_default()
            );
            let out = Proc::new(PathBuf::from(OPENSSH).join("ssh-keygen.exe"))
                .raw(Some(&format!(r#"-q -t {kind} -N "" -C "{comment}" -f "{}""#, path.display())))
                .run(log)?;
            if out.code != 0 {
                bail!("ssh-keygen exited with {}", out.code);
            }
            if let Ok(public) = std::fs::read_to_string(path.with_extension("pub")) {
                log(&format!("public key: {}", public.trim()));
            }
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edits_sshd_config_before_match_blocks() {
        let text = "#Port 22\nPasswordAuthentication yes\n\nMatch Group administrators\n  AuthorizedKeysFile x\n";
        let values = BTreeMap::from([
            ("Port".to_owned(), "2222".to_owned()),
            ("PasswordAuthentication".to_owned(), "no".to_owned()),
            ("PubkeyAuthentication".to_owned(), "yes".to_owned()),
        ]);
        let out = set_values(text, &values);
        assert_eq!(
            out,
            "Port 2222\nPasswordAuthentication no\n\nPubkeyAuthentication yes\nMatch Group administrators\n  AuthorizedKeysFile x\n"
        );
        assert_eq!(current(&out, "port").as_deref(), Some("2222"));
        assert_eq!(current(&out, "AuthorizedKeysFile"), None);
        assert_eq!(set_values(&out, &values), out);
    }

    #[test]
    fn compares_keys_without_comments() {
        assert_eq!(key_id("ssh-ed25519 AAAA me@laptop"), "ssh-ed25519 AAAA");
        assert_eq!(key_id(r#"from="10.0.0.*" ssh-rsa BBBB x"#), "ssh-rsa BBBB");
    }
}
