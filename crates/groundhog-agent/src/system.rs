//! The machine's own settings (`system:`): its name, time zone, power plan and Remote Desktop.
//! Each is a PowerShell check that prints `same` when Windows already has it, and the change.
//! Values were checked when the file was loaded and are quoted here besides.

use anyhow::{Result, bail};
use groundhog_core::model::{PowerKnob, Shell, SystemSetting};
use groundhog_win::process::Proc;

use crate::exec::powershell;

/// Text in a PowerShell single-quoted string.
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Remote Desktop's firewall rules, by their group's resource name (the same in every language).
const RDP_RULES: &str = "'@FirewallAPI.dll,-28752'";

/// (check, change) for a setting.
fn scripts(s: &SystemSetting) -> (String, String) {
    match s {
        SystemSetting::ComputerName { name } => (
            // The name it will have: a rename waits for the restart, so a second run doesn't redo it.
            format!(
                "$n = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName').ComputerName\n\
                 if ($n -ieq {q}) {{ 'same' }}",
                q = quote(name)
            ),
            format!("Rename-Computer -NewName {} -Force -WarningAction SilentlyContinue", quote(name)),
        ),
        SystemSetting::TimeZone { id } => (
            format!("if ((Get-TimeZone).Id -eq {}) {{ 'same' }}", quote(id)),
            format!(
                "if (-not (Get-TimeZone -ListAvailable | Where-Object Id -eq {q})) {{ throw \"Windows has no time zone {id}; tzutil /l lists them\" }}\n\
                 Set-TimeZone -Id {q}",
                q = quote(id)
            ),
        ),
        SystemSetting::PowerPlan { plan } => {
            let guid = plan.guid();
            (
                format!("if ((powercfg /getactivescheme) -match '{guid}') {{ 'same' }}"),
                // A plan Windows hides (High performance on many laptops, Ultimate on most
                // machines) is copied from its template under its own id first.
                format!(
                    "cmd /d /c \"powercfg /setactive {guid} >nul 2>&1\"\n\
                     if ($LASTEXITCODE -ne 0) {{\n\
                       cmd /d /c \"powercfg /duplicatescheme {guid} {guid} >nul 2>&1\"\n\
                       cmd /d /c \"powercfg /setactive {guid} >nul 2>&1\"\n\
                       if ($LASTEXITCODE -ne 0) {{ throw 'this machine has no {name} power plan' }}\n\
                     }}",
                    name = plan.name()
                ),
            )
        }
        SystemSetting::Power { knob, on_battery, value } => {
            let (sub, setting) = match knob {
                PowerKnob::Sleep => ("SUB_SLEEP", "STANDBYIDLE"),
                PowerKnob::ScreenOff => ("SUB_VIDEO", "VIDEOIDLE"),
                PowerKnob::Lid => ("SUB_BUTTONS", "LIDACTION"),
            };
            // powercfg's words are translated; the last two numbers it prints are the values
            // plugged in and on battery.
            let (index, which) = if *on_battery { ("-1", "dc") } else { ("-2", "ac") };
            (
                format!(
                    "$q = powercfg /query SCHEME_CURRENT {sub} {setting} | Out-String\n\
                     $hex = @([regex]::Matches($q, '0x[0-9a-fA-F]{{8}}') | ForEach-Object Value)\n\
                     # None: this machine doesn't have the setting (no lid on a desktop or VM)\n\
                     if ($hex.Count -lt 2 -or [Convert]::ToUInt32($hex[{index}], 16) -eq {value}) {{ 'same' }}"
                ),
                format!(
                    "cmd /d /c \"powercfg /set{which}valueindex SCHEME_CURRENT {sub} {setting} {value} >nul 2>&1\"\n\
                     if ($LASTEXITCODE -ne 0) {{ throw 'powercfg could not set {setting} on this machine' }}\n\
                     cmd /d /c \"powercfg /setactive SCHEME_CURRENT >nul 2>&1\""
                ),
            )
        }
        SystemSetting::Hibernation { on } => {
            let (want, word) = if *on { ("$true", "on") } else { ("$false", "off") };
            (
                format!(
                    "$h = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Power' -ErrorAction SilentlyContinue).HibernateEnabled\n\
                     if ([bool]$h -eq {want}) {{ 'same' }}"
                ),
                format!(
                    "cmd /d /c \"powercfg /hibernate {word} >nul 2>&1\"\n\
                     if ($LASTEXITCODE -ne 0) {{ throw 'powercfg could not turn hibernation {word} (some virtual machines have none)' }}"
                ),
            )
        }
        SystemSetting::RemoteDesktop { on } => {
            let key = "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server'";
            let (deny, rules) = if *on { (0, "Enable") } else { (1, "Disable") };
            let wrong = if *on { "False" } else { "True" };
            (
                format!(
                    "$deny = (Get-ItemProperty {key}).fDenyTSConnections\n\
                     $wrong = @(Get-NetFirewallRule -Group {RDP_RULES} -ErrorAction SilentlyContinue | Where-Object {{ \"$($_.Enabled)\" -eq '{wrong}' }})\n\
                     if ($deny -eq {deny} -and -not $wrong) {{ 'same' }}"
                ),
                format!(
                    "Set-ItemProperty {key} -Name fDenyTSConnections -Value {deny} -Type DWord\n\
                     # Network Level Authentication: sign in before a session is made\n\
                     Set-ItemProperty ({key} + '\\WinStations\\RDP-Tcp') -Name UserAuthentication -Value 1 -Type DWord\n\
                     {rules}-NetFirewallRule -Group {RDP_RULES}"
                ),
            )
        }
    }
}

/// Whether Windows differs from the setting.
pub fn differs(s: &SystemSetting) -> Result<bool> {
    let (check, _) = scripts(s);
    let out = Proc { capture_stdout: true, ..powershell(Shell::Powershell, &check) }.run(&mut |_| {})?;
    if out.code != 0 {
        bail!("checking: PowerShell exited with {}", out.code);
    }
    Ok(out.stdout.trim() != "same")
}

/// Makes the change if it's needed. Returns whether it changed anything.
pub fn apply(s: &SystemSetting, log: &mut dyn FnMut(&str)) -> Result<bool> {
    if !differs(s)? {
        return Ok(false);
    }
    let (_, change) = scripts(s);
    let out = powershell(Shell::Powershell, &format!("$ErrorActionPreference = 'Stop'\n{change}")).run(log)?;
    if out.code != 0 {
        bail!("PowerShell exited with {}", out.code);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use groundhog_core::model::PowerPlan;

    use super::*;

    #[test]
    fn checks_see_this_machines_own_settings_as_the_same() {
        // Read-only: asked for what this machine already has, each check finds nothing to do.
        let ps = |s: &str| {
            let out = Proc { capture_stdout: true, ..powershell(Shell::Powershell, s) }.run(&mut |_| {}).unwrap();
            out.stdout.trim().to_owned()
        };
        let zone = ps("(Get-TimeZone).Id");
        assert!(!differs(&SystemSetting::TimeZone { id: zone }).unwrap());
        let name = ps(
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName').ComputerName",
        );
        assert!(!differs(&SystemSetting::ComputerName { name: name.to_lowercase() }).unwrap());
        let active = ps("powercfg /getactivescheme");
        for plan in [PowerPlan::Balanced, PowerPlan::HighPerformance, PowerPlan::PowerSaver, PowerPlan::Ultimate] {
            assert_eq!(differs(&SystemSetting::PowerPlan { plan }).unwrap(), !active.contains(plan.guid()), "{plan:?}");
        }
        let sleep = ps("$q = powercfg /query SCHEME_CURRENT SUB_SLEEP STANDBYIDLE | Out-String; \
                        $h = @([regex]::Matches($q, '0x[0-9a-fA-F]{8}') | ForEach-Object Value); [Convert]::ToUInt32($h[-2], 16)");
        let value: u32 = sleep.parse().unwrap();
        assert!(!differs(&SystemSetting::Power { knob: PowerKnob::Sleep, on_battery: false, value }).unwrap());
        assert!(
            differs(&SystemSetting::Power { knob: PowerKnob::Sleep, on_battery: false, value: value + 60 }).unwrap()
        );
    }
}
