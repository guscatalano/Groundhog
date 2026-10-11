//! `developer:` steps: WSL distributions and VS Code extensions and settings, for the agent's
//! own account.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use groundhog_core::model::{DevSetting, Shell};
use groundhog_win::process::Proc;

use crate::exec::powershell;

/// VS Code's command line, installed for everyone or for this account.
const FIND_CODE: &str = r#"
$code = @("$env:ProgramFiles\Microsoft VS Code\bin\code.cmd", "$env:LOCALAPPDATA\Programs\Microsoft VS Code\bin\code.cmd") |
    Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $code) { throw "VS Code isn't installed (add Microsoft.VisualStudioCode to apps)" }
"#;

/// WSL's own record of this account's distributions.
const LXSS: &str = r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss";

/// (check, change) in PowerShell. Names and ids were checked to be plain when the file was
/// loaded.
fn scripts(d: &DevSetting) -> Option<(String, String)> {
    Some(match d {
        DevSetting::WslDistro { name } => (
            format!(
                "$names = @(Get-ChildItem '{LXSS}' -ErrorAction SilentlyContinue | ForEach-Object {{ (Get-ItemProperty $_.PSPath).DistributionName }})\n\
                 if ($names -contains '{name}') {{ 'same' }}"
            ),
            format!(
                "$env:WSL_UTF8 = '1'\n\
                 wsl.exe --install {name} --no-launch\n\
                 if ($LASTEXITCODE -ne 0) {{ throw \"wsl --install {name} exited with $LASTEXITCODE\" }}"
            ),
        ),
        DevSetting::WslDefault { name } => (
            format!(
                "$d = (Get-ItemProperty '{LXSS}' -ErrorAction SilentlyContinue).DefaultDistribution\n\
                 if ($d -and (Get-ItemProperty \"{LXSS}\\$d\" -ErrorAction SilentlyContinue).DistributionName -eq '{name}') {{ 'same' }}"
            ),
            format!(
                "$env:WSL_UTF8 = '1'\n\
                 wsl.exe --set-default {name}\n\
                 if ($LASTEXITCODE -ne 0) {{ throw \"wsl --set-default {name} exited with $LASTEXITCODE (is it installed?)\" }}"
            ),
        ),
        DevSetting::VsCodeExtension { id } => (
            format!("{FIND_CODE}\nif (@(& $code --list-extensions) -contains '{id}') {{ 'same' }}"),
            format!(
                "{FIND_CODE}\n& $code --install-extension '{id}' --force\n\
                 if ($LASTEXITCODE -ne 0) {{ throw \"VS Code couldn't install {id} (exit $LASTEXITCODE)\" }}"
            ),
        ),
        DevSetting::VsCodeSettings { .. } => return None,
    })
}

fn settings_path() -> Result<PathBuf> {
    let appdata = std::env::var_os("APPDATA").context("APPDATA isn't set")?;
    Ok(PathBuf::from(appdata).join(r"Code\User\settings.json"))
}

/// VS Code's settings as they stand (none yet: empty). The file is JSON with comments.
fn read_settings() -> Result<(serde_json::Map<String, serde_json::Value>, bool)> {
    let path = settings_path()?;
    let Ok(text) = std::fs::read_to_string(&path) else { return Ok((serde_json::Map::new(), false)) };
    let (json, had_comments) = strip_jsonc(&text);
    if json.trim().is_empty() {
        return Ok((serde_json::Map::new(), had_comments));
    }
    let value: serde_json::Value =
        serde_json::from_str(&json).with_context(|| format!("reading {}", path.display()))?;
    match value {
        serde_json::Value::Object(map) => Ok((map, had_comments)),
        _ => bail!("{} isn't a JSON object", path.display()),
    }
}

/// JSON with comments and trailing commas (VS Code's settings) as plain JSON, and whether it
/// had comments.
fn strip_jsonc(text: &str) -> (String, bool) {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let (mut i, mut comments) = (0, false);
    let mut in_string = false;
    while i < chars.len() {
        let c = chars[i];
        if in_string {
            out.push(c);
            if c == '\\' && i + 1 < chars.len() {
                out.push(chars[i + 1]);
                i += 1;
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
            out.push(c);
        } else if c == '/' && chars.get(i + 1) == Some(&'/') {
            comments = true;
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        } else if c == '/' && chars.get(i + 1) == Some(&'*') {
            comments = true;
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i += 2;
            continue;
        } else if c == ',' {
            // A trailing comma: the next thing that isn't space closes the object or array.
            let next = chars[i + 1..].iter().find(|c| !c.is_whitespace());
            if !matches!(next, Some('}') | Some(']')) {
                out.push(c);
            }
        } else {
            out.push(c);
        }
        i += 1;
    }
    (out, comments)
}

fn settings_differ(values: &BTreeMap<String, serde_json::Value>) -> Result<bool> {
    let (current, _) = read_settings()?;
    Ok(values.iter().any(|(k, v)| current.get(k) != Some(v)))
}

fn run_check(check: &str) -> Result<bool> {
    let out = Proc { capture_stdout: true, ..powershell(Shell::Powershell, check) }.run(&mut |_| {})?;
    if out.code != 0 {
        bail!("checking: PowerShell exited with {}", out.code);
    }
    Ok(out.stdout.trim() != "same")
}

pub fn differs(d: &DevSetting) -> Result<bool> {
    match (d, scripts(d)) {
        (DevSetting::VsCodeSettings { values }, _) => settings_differ(values),
        (_, Some((check, _))) => run_check(&check),
        (_, None) => unreachable!("every other setting has scripts"),
    }
}

pub fn apply(d: &DevSetting, log: &mut dyn FnMut(&str)) -> Result<bool> {
    if !differs(d)? {
        return Ok(false);
    }
    if let DevSetting::VsCodeSettings { values } = d {
        let (mut current, had_comments) = read_settings()?;
        for (k, v) in values {
            current.insert(k.clone(), v.clone());
        }
        let path = settings_path()?;
        std::fs::create_dir_all(path.parent().expect("has a folder"))?;
        let mut text = serde_json::to_string_pretty(&serde_json::Value::Object(current))?;
        text.push('\n');
        std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
        if had_comments {
            log("its comments weren't kept");
        }
        return Ok(true);
    }
    let (_, change) = scripts(d).expect("has scripts");
    let out = powershell(Shell::Powershell, &format!("$ErrorActionPreference = 'Stop'\n{change}")).run(log)?;
    if out.code != 0 {
        bail!("PowerShell exited with {}", out.code);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_jsonc() {
        let text = "{\n  // font\n  \"editor.fontSize\": 14, /* big */\n  \"a\": \"// not a comment\",\n  \"list\": [1, 2,],\n}\n";
        let (json, comments) = strip_jsonc(text);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(comments);
        assert_eq!(v["editor.fontSize"], 14);
        assert_eq!(v["a"], "// not a comment");
        assert_eq!(v["list"], serde_json::json!([1, 2]));
    }
}
