//! `capture machine`: a starting Groundhogfile written from this machine as it is. It holds
//! what can be read back reliably and leaves out what Windows sets up by itself, so applying it
//! to a fresh machine makes that machine like this one in the ways that matter, and applying it
//! here changes nothing.

use std::fmt::Write as _;
use std::path::Path;

use anyhow::{Context, Result, bail};
use groundhog_core::model::{PowerPlan, Shell};
use groundhog_win::process::Proc;
use serde::Deserialize;

use crate::exec::powershell;

/// Optional features worth carrying to another machine. The many Windows turns on by itself
/// are left out.
const FEATURES: &[&str] = &[
    "Microsoft-Windows-Subsystem-Linux",
    "VirtualMachinePlatform",
    "HypervisorPlatform",
    "Microsoft-Hyper-V-All",
    "Containers",
    "Containers-DisposableClientVM",
    "NetFx3",
    "IIS-WebServerRole",
    "TelnetClient",
    "TFTP",
    "Client-ProjFS",
];

/// winget packages that come with Windows or with other apps, left out of `apps`.
const PART_OF_WINDOWS: &[&str] = &[
    "Microsoft.365Copilot",
    "Microsoft.AppInstaller",
    "Microsoft.DesktopAppInstaller",
    "Microsoft.Edge",
    "Microsoft.EdgeWebView2Runtime",
    "Microsoft.DotNet.Native",
    "Microsoft.OneDrive",
    "Microsoft.Outlook",
    "Microsoft.Teams",
    "Microsoft.UI.Xaml",
    "Microsoft.VCLibs",
    "Microsoft.VCRedist",
    "Microsoft.WindowsAppRuntime",
    "Microsoft.WindowsTerminal",
];

/// Environment variables every account has; others are named (not their values) for review.
const USUAL_ENV: &[&str] = &["path", "temp", "tmp", "onedrive", "onedriveconsumer", "onedrivecommercial"];

/// Everything the script reads.
const FACTS: &str = r#"
$f = [ordered]@{}
$f.computer = $env:COMPUTERNAME
$f.timeZone = (Get-TimeZone).Id
$f.plan = if ((powercfg /getactivescheme) -match '([0-9a-f]{8}-[0-9a-f-]{27})') { $Matches[1] } else { '' }
$p = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -ErrorAction SilentlyContinue
$f.appsLight = $p.AppsUseLightTheme
$f.systemLight = $p.SystemUsesLightTheme
$a = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -ErrorAction SilentlyContinue
$f.taskbarAl = $a.TaskbarAl
$f.taskView = $a.ShowTaskViewButton
$f.devMode = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' -ErrorAction SilentlyContinue).AllowDevelopmentWithoutDevLicense
$f.longPaths = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -ErrorAction SilentlyContinue).LongPathsEnabled
$f.sudo = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Sudo' -ErrorAction SilentlyContinue).Enabled
$f.rdpDenied = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue).fDenyTSConnections
$f.wsl = @(Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss' -ErrorAction SilentlyContinue |
  ForEach-Object { (Get-ItemProperty $_.PSPath).DistributionName } | Where-Object { $_ -and $_ -notlike 'docker-desktop*' })
$f.features = @(try { Get-WindowsOptionalFeature -Online -ErrorAction Stop | Where-Object { "$($_.State)" -eq 'Enabled' } | ForEach-Object { $_.FeatureName } } catch { })
$f.sshServer = try { "$((Get-WindowsCapability -Online -Name 'OpenSSH.Server*' -ErrorAction Stop).State)" -eq 'Installed' } catch { $false }
$f.policy = "$(Get-ExecutionPolicy -Scope LocalMachine)"
$pwsh = Get-Command pwsh.exe -ErrorAction SilentlyContinue
$f.policy7 = if ($pwsh) { "$(& $pwsh.Source -NoProfile -NonInteractive -Command 'Get-ExecutionPolicy -Scope LocalMachine')".Trim() } else { $null }
$f.modules = @(try { Get-InstalledModule -ErrorAction Stop | Where-Object { $_.Repository -eq 'PSGallery' } | ForEach-Object { $_.Name } } catch { })
$code = @("$env:ProgramFiles\Microsoft VS Code\bin\code.cmd", "$env:LOCALAPPDATA\Programs\Microsoft VS Code\bin\code.cmd") |
  Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
$f.codeExtensions = @(if ($code) { & $code --list-extensions 2>$null })
$f.userPath = (Get-ItemProperty 'HKCU:\Environment' -ErrorAction SilentlyContinue).Path
$f.userEnv = @((Get-Item 'HKCU:\Environment').GetValueNames())
$f | ConvertTo-Json -Depth 4 -Compress
"#;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Facts {
    computer: String,
    time_zone: String,
    plan: String,
    apps_light: Option<u32>,
    system_light: Option<u32>,
    taskbar_al: Option<u32>,
    task_view: Option<u32>,
    dev_mode: Option<u32>,
    long_paths: Option<u32>,
    sudo: Option<u32>,
    rdp_denied: Option<u32>,
    wsl: Vec<String>,
    features: Vec<String>,
    ssh_server: bool,
    policy: String,
    policy7: Option<String>,
    modules: Vec<String>,
    code_extensions: Vec<String>,
    user_path: Option<String>,
    user_env: Vec<String>,
}

fn facts() -> Result<Facts> {
    let out = Proc { capture_stdout: true, ..powershell(Shell::Powershell, FACTS) }.run(&mut |_| {})?;
    if out.code != 0 {
        bail!("reading this machine's settings: PowerShell exited with {}", out.code);
    }
    let json = out.stdout.lines().rev().find(|l| l.trim_start().starts_with('{')).context("no settings read")?;
    serde_json::from_str(json).context("reading this machine's settings")
}

/// winget ids of what's installed from winget's own source, or why there are none.
fn winget_ids(work: &Path) -> Result<Vec<String>, String> {
    let file = work.join("winget-export.json");
    let _ = std::fs::create_dir_all(work);
    let out = Proc::new("winget.exe")
        .args(["export", "-o"])
        .args([file.display().to_string()])
        .args(["--source", "winget", "--accept-source-agreements", "--disable-interactivity"])
        .run(&mut |_| {})
        .map_err(|e| format!("winget isn't available ({e:#})"))?;
    let text = std::fs::read_to_string(&file).map_err(|_| format!("winget export failed ({})", out.code))?;
    let _ = std::fs::remove_file(&file);
    let json: serde_json::Value =
        serde_json::from_str(text.trim_start_matches('\u{feff}')).map_err(|e| e.to_string())?;
    let mut ids: Vec<String> = json["Sources"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|s| s["Packages"].as_array().into_iter().flatten())
        .filter_map(|p| p["PackageIdentifier"].as_str().map(str::to_owned))
        .collect();
    ids.sort_by_key(|i| i.to_ascii_lowercase());
    ids.dedup();
    Ok(ids)
}

/// A YAML scalar, quoted when YAML would read it as something else.
fn scalar(s: &str) -> String {
    let plain = !s.is_empty()
        && s.chars().all(|c| c.is_ascii_alphanumeric() || " ._-/\\()+".contains(c))
        && !s.starts_with([' ', '-'])
        && !s.ends_with(' ')
        && !["yes", "no", "true", "false", "on", "off", "null", "~"].contains(&s.to_ascii_lowercase().as_str())
        && s.parse::<f64>().is_err();
    if plain { s.to_owned() } else { format!("'{}'", s.replace('\'', "''")) }
}

fn list(items: &[String]) -> String {
    let quoted: Vec<String> = items.iter().map(|i| scalar(i)).collect();
    format!("[{}]", quoted.join(", "))
}

/// The captured file's text. `pins` names a Start layout saved next to it.
pub fn machine(work: &Path, pins: Option<&str>) -> Result<String> {
    let f = facts()?;
    let mut y = String::new();
    let today = humantime::format_rfc3339_seconds(std::time::SystemTime::now()).to_string();
    writeln!(
        y,
        "# Captured from {} on {} by groundhog-agent {}.",
        f.computer,
        &today[..10],
        env!("CARGO_PKG_VERSION")
    )?;
    writeln!(y, "# A starting point: read it through, drop what you don't want carried over, and add")?;
    writeln!(y, "# what can't be read back (secrets, files, settings inside apps).")?;
    writeln!(y, "version: 1")?;
    writeln!(y, "agent: '>={}'", env!("CARGO_PKG_VERSION"))?;

    writeln!(y)?;
    match winget_ids(work) {
        Ok(ids) => {
            let (system, mine): (Vec<String>, Vec<String>) = ids.into_iter().partition(|id| {
                PART_OF_WINDOWS.iter().any(|p| id.to_ascii_lowercase().starts_with(&p.to_ascii_lowercase()))
            });
            if mine.is_empty() {
                writeln!(y, "# apps: nothing installed from winget beyond what comes with Windows")?;
            } else {
                writeln!(y, "apps:")?;
                for id in &mine {
                    writeln!(y, "  - {}", scalar(id))?;
                }
            }
            if !system.is_empty() {
                writeln!(y, "  # left out, as part of Windows or of other apps: {}", system.join(", "))?;
            }
        }
        Err(why) => writeln!(y, "# apps: not captured: {why}")?,
    }

    let features: Vec<String> = FEATURES
        .iter()
        .filter(|n| f.features.iter().any(|x| x.eq_ignore_ascii_case(n)))
        .map(|n| (*n).to_owned())
        .collect();
    if !features.is_empty() {
        writeln!(y)?;
        writeln!(y, "features: {}", list(&features))?;
    } else if f.features.is_empty() {
        writeln!(y, "# features: not captured (reading them needs the agent elevated)")?;
    }

    writeln!(y)?;
    writeln!(y, "system:")?;
    writeln!(y, "  time-zone: {}", scalar(&f.time_zone))?;
    let plan = [PowerPlan::Balanced, PowerPlan::HighPerformance, PowerPlan::PowerSaver, PowerPlan::Ultimate]
        .into_iter()
        .find(|p| p.guid().eq_ignore_ascii_case(&f.plan));
    match plan {
        Some(PowerPlan::Balanced) | None => {}
        Some(p) => writeln!(y, "  power: {{ plan: {} }}", plan_key(p))?,
    }
    if f.rdp_denied == Some(0) {
        writeln!(y, "  remote-desktop: true")?;
    }

    let on = |v: Option<u32>| v.is_some_and(|v| v != 0);
    let mut dev = String::new();
    if on(f.dev_mode) {
        writeln!(dev, "  developer-mode: true")?;
    }
    if on(f.long_paths) {
        writeln!(dev, "  long-paths: true")?;
    }
    if let Some(mode) = f.sudo.and_then(|s| match s {
        1 => Some("new-window"),
        2 => Some("input-closed"),
        3 => Some("inline"),
        _ => None,
    }) {
        writeln!(dev, "  sudo: {mode}")?;
    }
    if !f.wsl.is_empty() {
        writeln!(dev, "  wsl:\n    distros: {}", list(&f.wsl))?;
    }
    if !f.code_extensions.is_empty() {
        writeln!(dev, "  vscode:\n    extensions:")?;
        for e in &f.code_extensions {
            writeln!(dev, "      - {}", scalar(e))?;
        }
    }
    if !dev.is_empty() {
        writeln!(y)?;
        writeln!(y, "developer:")?;
        y.push_str(&dev);
    }

    let mut desk = String::new();
    // Only what's been set: a fresh machine has none of these values, and Windows' defaults
    // apply.
    let mode = |light: u32| if light == 0 { "dark" } else { "light" };
    match (f.apps_light.map(mode), f.system_light.map(mode)) {
        (Some(apps), Some(windows)) if apps == windows => writeln!(desk, "  theme: {apps}")?,
        (Some(apps), Some(windows)) => writeln!(desk, "  theme: {{ apps: {apps}, windows: {windows} }}")?,
        (Some(apps), None) => writeln!(desk, "  theme: {{ apps: {apps} }}")?,
        (None, Some(windows)) => writeln!(desk, "  theme: {{ windows: {windows} }}")?,
        (None, None) => {}
    }
    let mut taskbar = Vec::new();
    if let Some(al) = f.taskbar_al {
        taskbar.push(format!("alignment: {}", if al == 0 { "left" } else { "center" }));
    }
    if let Some(tv) = f.task_view {
        taskbar.push(format!("task-view: {}", tv != 0));
    }
    if !taskbar.is_empty() {
        writeln!(desk, "  taskbar: {{ {} }}", taskbar.join(", "))?;
    }
    if let Some(pins) = pins {
        writeln!(desk, "  start: {{ pins-from: {} }}", scalar(pins))?;
    }
    if !desk.is_empty() {
        writeln!(y)?;
        writeln!(y, "desktop:")?;
        y.push_str(&desk);
    }

    let mut ps = String::new();
    match &f.policy7 {
        Some(seven) if !seven.eq_ignore_ascii_case(&f.policy) => writeln!(
            ps,
            "  # execution-policy: Windows PowerShell has {}, PowerShell 7 has {seven}; one setting sets both",
            f.policy
        )?,
        _ if !f.policy.is_empty() && !f.policy.eq_ignore_ascii_case("Undefined") => {
            writeln!(ps, "  execution-policy: {}", f.policy)?
        }
        _ => {}
    }
    if !f.modules.is_empty() {
        writeln!(ps, "  modules: {}", list(&f.modules))?;
    }
    if !ps.is_empty() {
        writeln!(y)?;
        writeln!(y, "powershell:")?;
        y.push_str(&ps);
    }

    if f.ssh_server {
        writeln!(y)?;
        writeln!(y, "ssh:")?;
        writeln!(y, "  server: true    # its keys and sshd_config aren't captured; add what you need")?;
    }

    let profile = std::env::var("USERPROFILE").unwrap_or_default();
    let path = path_entries(&f.user_path.unwrap_or_default(), &profile);
    if !path.is_empty() {
        writeln!(y)?;
        writeln!(y, "path:")?;
        for p in &path {
            writeln!(y, "  - {}", scalar(p))?;
        }
    }
    let names: Vec<&String> =
        f.user_env.iter().filter(|n| !USUAL_ENV.contains(&n.to_ascii_lowercase().as_str())).collect();
    if !names.is_empty() {
        let names: Vec<&str> = names.iter().map(|n| n.as_str()).collect();
        writeln!(y)?;
        writeln!(y, "# env: not captured, since values can be secrets. This account sets: {}", names.join(", "))?;
    }
    Ok(y)
}

/// This account's own PATH entries, written so they work for another account: tidied (stray
/// quotes and doubled backslashes some installers leave), once each, under `%USERPROFILE%`,
/// and without the ones Windows and apps add for themselves when installed.
fn path_entries(raw: &str, profile: &str) -> Vec<String> {
    let profile = profile.trim_end_matches('\\').to_ascii_lowercase();
    let mut out: Vec<String> = Vec::new();
    for p in raw.split(';') {
        let mut p = p.trim().trim_matches(['\'', '"']).to_owned();
        while p.contains(r"\\") {
            p = p.replace(r"\\", r"\");
        }
        let p = p.trim_end_matches('\\');
        if p.is_empty() {
            continue;
        }
        let p = match p.to_ascii_lowercase().strip_prefix(&profile) {
            Some(rest) if !profile.is_empty() && (rest.is_empty() || rest.starts_with('\\')) => {
                format!("%USERPROFILE%{}", &p[profile.len()..])
            }
            _ => p.to_owned(),
        };
        let l = p.to_ascii_lowercase();
        let added_by_others = [
            r"\microsoft\windowsapps",
            r"\microsoft\winget\",
            r"\.dotnet\tools",
            r"%userprofile%\appdata\local\programs\",
        ];
        if added_by_others.iter().any(|a| l.contains(a)) || out.iter().any(|o| o.eq_ignore_ascii_case(&p)) {
            continue;
        }
        out.push(p);
    }
    out
}

fn plan_key(p: PowerPlan) -> &'static str {
    match p {
        PowerPlan::Balanced => "balanced",
        PowerPlan::HighPerformance => "high-performance",
        PowerPlan::PowerSaver => "power-saver",
        PowerPlan::Ultimate => "ultimate",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_what_yaml_would_misread() {
        assert_eq!(scalar("Git.Git"), "Git.Git");
        assert_eq!(scalar("Pacific Standard Time"), "Pacific Standard Time");
        assert_eq!(scalar("on"), "'on'");
        assert_eq!(scalar("1.0"), "'1.0'");
        assert_eq!(scalar("C:\\Tools"), "'C:\\Tools'");
        assert_eq!(scalar("it's"), "'it''s'");
    }

    #[test]
    fn tidies_path_entries() {
        let raw = r"'C:\\Users\\me\\AppData\\Local\\tool\\bin;C:\Users\me\.cargo\bin;C:\Users\me\AppData\Local\Microsoft\WindowsApps;C:\Tools\;c:\tools;C:\Users\me\.dotnet\tools;C:\Users\me\AppData\Local\Programs\Microsoft VS Code\bin'";
        assert_eq!(
            path_entries(raw, r"C:\Users\me"),
            [r"%USERPROFILE%\AppData\Local\tool\bin", r"%USERPROFILE%\.cargo\bin", r"C:\Tools"]
        );
    }
}
