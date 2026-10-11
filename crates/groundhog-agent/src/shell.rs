//! `terminal:` and `powershell:` steps: Windows Terminal's settings, the execution policy,
//! Gallery modules, and Groundhog's block in the PowerShell profile.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use groundhog_core::model::{Shell, ShellSetting};
use groundhog_win::process::Proc;

use crate::dev::strip_jsonc;
use crate::exec::powershell;

/// Where the block in the profile starts and ends; what's between is Groundhog's.
const BEGIN: &str = "# >>> groundhog >>>";
const END: &str = "# <<< groundhog <<<";

/// Runs a script in Windows PowerShell and returns what it printed.
fn ps(script: &str, log: &mut dyn FnMut(&str)) -> Result<String> {
    let out = Proc {
        capture_stdout: true,
        ..powershell(Shell::Powershell, &format!("$ErrorActionPreference = 'Stop'\n{script}"))
    }
    .run(log)?;
    if out.code != 0 {
        bail!("PowerShell exited with {}", out.code);
    }
    Ok(out.stdout.trim().to_owned())
}

/// The policy each PowerShell sets for the machine, one line per PowerShell installed.
const READ_POLICY: &str = r#"
"$(Get-ExecutionPolicy -Scope LocalMachine)"
$pwsh = Get-Command pwsh.exe -ErrorAction SilentlyContinue
if ($pwsh) { & $pwsh.Source -NoProfile -NonInteractive -Command 'Get-ExecutionPolicy -Scope LocalMachine' } else { $null = 0 }
"#;

/// Sets the machine's policy. Set-ExecutionPolicy throws when a narrower scope overrides it
/// (this script's own `-ExecutionPolicy Bypass`, or Group Policy) even though it set it; the
/// step reads the policy back instead.
const SET_POLICY: &str = "try { Set-ExecutionPolicy -ExecutionPolicy $policy -Scope LocalMachine -Force } catch [System.Security.SecurityException] { }";

/// Windows Terminal's settings file, from the Store or winget's package.
pub(crate) fn terminal_settings_path() -> Result<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA").context("LOCALAPPDATA isn't set")?;
    let package = PathBuf::from(local).join(r"Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe");
    if !package.is_dir() {
        bail!("Windows Terminal isn't installed for this account (add Microsoft.WindowsTerminal to apps)");
    }
    Ok(package.join(r"LocalState\settings.json"))
}

/// Terminal's settings as they stand (none yet: empty; Terminal fills in the rest).
fn read_terminal() -> Result<(serde_json::Map<String, serde_json::Value>, bool)> {
    let path = terminal_settings_path()?;
    let Ok(text) = std::fs::read_to_string(&path) else { return Ok((serde_json::Map::new(), false)) };
    let (json, had_comments) = strip_jsonc(text.trim_start_matches('\u{feff}'));
    if json.trim().is_empty() {
        return Ok((serde_json::Map::new(), had_comments));
    }
    match serde_json::from_str(&json).with_context(|| format!("reading {}", path.display()))? {
        serde_json::Value::Object(map) => Ok((map, had_comments)),
        _ => bail!("{} isn't a JSON object", path.display()),
    }
}

/// `settings` with `top` and `defaults` put in; whether anything changed.
fn merge_terminal(
    settings: &mut serde_json::Map<String, serde_json::Value>,
    top: &BTreeMap<String, serde_json::Value>,
    defaults: &BTreeMap<String, serde_json::Value>,
) -> bool {
    let mut changed = false;
    for (k, v) in top {
        if settings.get(k) != Some(v) {
            settings.insert(k.clone(), v.clone());
            changed = true;
        }
    }
    if defaults.is_empty() {
        return changed;
    }
    let profiles = settings.entry("profiles").or_insert_with(|| serde_json::json!({}));
    // An old file has the profiles as a plain list.
    if let serde_json::Value::Array(list) = profiles {
        *profiles = serde_json::json!({ "list": std::mem::take(list) });
    }
    let Some(profiles) = profiles.as_object_mut() else {
        *profiles = serde_json::json!({ "defaults": defaults });
        return true;
    };
    let d = profiles.entry("defaults").or_insert_with(|| serde_json::json!({}));
    if !d.is_object() {
        *d = serde_json::json!({});
    }
    let d = d.as_object_mut().expect("an object");
    for (k, v) in defaults {
        if d.get(k) != Some(v) {
            d.insert(k.clone(), v.clone());
            changed = true;
        }
    }
    changed
}

/// The profile both PowerShells run for this account in every host.
pub(crate) fn profile_paths() -> Result<Vec<PathBuf>> {
    let docs = ps("[Environment]::GetFolderPath('MyDocuments')", &mut |_| {})?;
    if docs.is_empty() {
        bail!("this account has no Documents folder");
    }
    let docs = PathBuf::from(docs);
    Ok(vec![docs.join(r"WindowsPowerShell\profile.ps1"), docs.join(r"PowerShell\profile.ps1")])
}

/// `text` with Groundhog's block set to `block` (added at the end if it wasn't there).
fn with_block(text: &str, block: &str) -> String {
    let mut body = block.trim_end().to_owned();
    body = format!("{BEGIN}\n{body}\n{END}");
    if let (Some(start), Some(end)) = (text.find(BEGIN), text.find(END))
        && start < end
    {
        return format!("{}{body}{}", &text[..start], &text[end + END.len()..]);
    }
    let sep = if text.is_empty() || text.ends_with('\n') { "" } else { "\r\n" };
    format!("{text}{sep}{body}\r\n")
}

fn profile_differs(block: &str) -> Result<bool> {
    for path in profile_paths()? {
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let text = text.replace("\r\n", "\n");
        if with_block(&text, &block.replace("\r\n", "\n")) != text {
            return Ok(true);
        }
    }
    Ok(false)
}

/// PowerShell that sets each PowerShell's machine policy back to what it is now.
pub(crate) fn policy_undo_script() -> Result<String> {
    let now = ps(READ_POLICY, &mut |_| {})?;
    let mut lines = now.lines().map(str::trim);
    let windows = lines.next().unwrap_or("Undefined");
    let mut script = SET_POLICY.replace("$policy", windows);
    if let Some(seven) = lines.next() {
        script += &format!(
            "\n$pwsh = Get-Command pwsh.exe -ErrorAction SilentlyContinue\n\
             if ($pwsh) {{ & $pwsh.Source -NoProfile -NonInteractive -Command '{}' }} else {{ $null = 0 }}",
            SET_POLICY.replace("$policy", seven)
        );
    }
    Ok(script)
}

fn module_script(name: &str) -> (String, String) {
    (
        format!("if (Get-Module -ListAvailable -Name '{name}') {{ 'same' }} else {{ 'differs' }}"),
        format!(
            "[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12\n\
             if (-not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue | Where-Object {{ $_.Version -ge '2.8.5.201' }})) {{\n\
                 Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope AllUsers -Force | Out-Null\n\
             }}\n\
             Install-Module -Name '{name}' -Scope AllUsers -Repository PSGallery -Force -AllowClobber"
        ),
    )
}

pub fn differs(s: &ShellSetting) -> Result<bool> {
    match s {
        ShellSetting::Terminal { top, defaults } => {
            let (mut settings, _) = read_terminal()?;
            Ok(merge_terminal(&mut settings, top, defaults))
        }
        ShellSetting::ExecutionPolicy { policy } => {
            Ok(ps(READ_POLICY, &mut |_| {})?.lines().any(|l| !l.trim().eq_ignore_ascii_case(policy)))
        }
        ShellSetting::Module { name } => Ok(ps(&module_script(name).0, &mut |_| {})? != "same"),
        ShellSetting::Profile { text } => profile_differs(text),
    }
}

pub fn apply(s: &ShellSetting, log: &mut dyn FnMut(&str)) -> Result<bool> {
    if !differs(s)? {
        return Ok(false);
    }
    match s {
        ShellSetting::Terminal { top, defaults } => {
            let (mut settings, had_comments) = read_terminal()?;
            merge_terminal(&mut settings, top, defaults);
            let path = terminal_settings_path()?;
            std::fs::create_dir_all(path.parent().expect("has a folder"))?;
            let mut text = serde_json::to_string_pretty(&serde_json::Value::Object(settings))?;
            text.push('\n');
            std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
            if had_comments {
                log("its comments weren't kept");
            }
        }
        ShellSetting::ExecutionPolicy { policy } => {
            let set = SET_POLICY.replace("$policy", policy);
            ps(
                &format!(
                    "{set}\n\
                     $pwsh = Get-Command pwsh.exe -ErrorAction SilentlyContinue\n\
                     if ($pwsh) {{\n\
                         & $pwsh.Source -NoProfile -NonInteractive -Command '{set}'\n\
                         if ($LASTEXITCODE -ne 0) {{ throw \"PowerShell 7 couldn't set it (exit $LASTEXITCODE)\" }}\n\
                     }} else {{ $null = 0 }}"
                ),
                log,
            )?;
            if ps(READ_POLICY, &mut |_| {})?.lines().any(|l| !l.trim().eq_ignore_ascii_case(policy)) {
                bail!("the policy didn't change: Group Policy sets it on this machine");
            }
        }
        ShellSetting::Module { name } => {
            ps(&module_script(name).1, log)?;
        }
        ShellSetting::Profile { text: block } => {
            for path in profile_paths()? {
                let old = std::fs::read_to_string(&path).unwrap_or_default();
                let new = with_block(&old.replace("\r\n", "\n"), &block.replace("\r\n", "\n")).replace('\n', "\r\n");
                if new == old {
                    continue;
                }
                std::fs::create_dir_all(path.parent().expect("has a folder"))?;
                // With a BOM, so Windows PowerShell reads anything past ASCII as UTF-8.
                let bom = if new.starts_with('\u{feff}') { "" } else { "\u{feff}" };
                std::fs::write(&path, format!("{bom}{new}")).with_context(|| format!("writing {}", path.display()))?;
            }
            let policies = ps(READ_POLICY, &mut |_| {})?;
            if policies.lines().any(|l| l.trim().eq_ignore_ascii_case("Restricted")) {
                log(
                    "the execution policy is Restricted, so PowerShell won't run the profile (set powershell.execution-policy)",
                );
            }
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_the_rest_of_the_profile() {
        let first = with_block("Set-Alias ll ls\n", "Import-Module posh-git");
        assert_eq!(first, "Set-Alias ll ls\n# >>> groundhog >>>\nImport-Module posh-git\n# <<< groundhog <<<\r\n");
        let first = first.replace("\r\n", "\n");
        let again = with_block(&first, "Import-Module posh-git\n");
        assert_eq!(again, first);
        let changed = with_block(&format!("{first}# mine\n"), "oh-my-posh init pwsh | Invoke-Expression");
        assert!(changed.starts_with("Set-Alias ll ls\n# >>> groundhog >>>\noh-my-posh"));
        assert!(changed.ends_with("# <<< groundhog <<<\n# mine\n"));
    }

    #[test]
    fn merges_terminal_settings() {
        let mut s = serde_json::from_str::<serde_json::Map<_, _>>(
            r#"{"theme":"dark","profiles":[{"name":"Ubuntu"}],"keep":1}"#,
        )
        .unwrap();
        let top = BTreeMap::from([("theme".to_owned(), serde_json::json!("light"))]);
        let defaults = BTreeMap::from([("colorScheme".to_owned(), serde_json::json!("One Half Dark"))]);
        assert!(merge_terminal(&mut s, &top, &defaults));
        assert_eq!(s["theme"], "light");
        assert_eq!(s["keep"], 1);
        assert_eq!(s["profiles"]["list"][0]["name"], "Ubuntu");
        assert_eq!(s["profiles"]["defaults"]["colorScheme"], "One Half Dark");
        assert!(!merge_terminal(&mut s, &top, &defaults));
    }
}
