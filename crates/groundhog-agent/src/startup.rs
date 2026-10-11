//! What starts at sign-in, and scheduled tasks: PowerShell that finds the entries a name
//! matches and turns them off or on (or deletes tasks), checking first.
//!
//! Startup entries are switched the way Task Manager's Startup apps page does it, so they show
//! there as disabled and can be turned back on there: a `StartupApproved` value for programs in
//! the Run keys and Startup folders (first byte odd: disabled), and a startup task's `State`
//! for packaged apps (1: disabled by the user, 2: enabled).

use anyhow::{Result, bail};
use groundhog_core::model::{Shell, StartupItem, TaskRule, TaskState};
use groundhog_win::process::Proc;

use crate::exec::powershell;

/// Finds startup entries by name: a Run value's name, the program's description (what Task
/// Manager shows: `Microsoft OneDrive`), a Startup folder shortcut's name, or a packaged app's
/// name, family or Start menu name (`Microsoft Teams`). `*` and `?` work as wildcards.
const STARTUP: &str = r#"
function Test-Name($names) {
  foreach ($p in $Patterns) { foreach ($n in $names) { if ($n -and $n -like $p) { return $true } } }
  return $false
}
function Get-Description($command) {
  $exe = if ($command -match '^\s*"([^"]+)"') { $Matches[1] } elseif ($command -match '^\s*(\S+)') { $Matches[1] } else { '' }
  $exe = [Environment]::ExpandEnvironmentVariables($exe)
  if ($exe -and (Test-Path -LiteralPath $exe)) { (Get-Item -LiteralPath $exe).VersionInfo.FileDescription }
}
$startMenu = @{}
Get-StartApps | ForEach-Object { $startMenu[($_.AppID -split '!')[0]] = $_.Name }
# A packaged app's alias (...\WindowsApps\MSTeams_8wekyb3d8bbwe\ms-teams.exe) has no description
# to read; it goes by its app's names instead.
function Get-AppNames($command) {
  if ($command -match '\\WindowsApps\\([^\\]+_[a-z0-9]{13})\\') { $Matches[1], ($Matches[1] -split '_')[0], $startMenu[$Matches[1]] }
}
$found = @()
$explorer = 'Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved'
$runs = @(
  @{ Hive = 'HKCU:'; Key = 'Software\Microsoft\Windows\CurrentVersion\Run'; Approved = 'Run' },
  @{ Hive = 'HKLM:'; Key = 'Software\Microsoft\Windows\CurrentVersion\Run'; Approved = 'Run' },
  @{ Hive = 'HKLM:'; Key = 'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; Approved = 'Run32' }
)
foreach ($r in $runs) {
  $p = Get-ItemProperty "$($r.Hive)\$($r.Key)" -ErrorAction SilentlyContinue
  if (-not $p) { continue }
  foreach ($v in $p.PSObject.Properties | Where-Object Name -notlike 'PS*') {
    if (Test-Name (@($v.Name, (Get-Description $v.Value)) + @(Get-AppNames $v.Value))) {
      $found += @{ Kind = 'approved'; Key = "$($r.Hive)\$explorer\$($r.Approved)"; Name = $v.Name; Shown = $v.Name }
    }
  }
}
$folders = @(
  @{ Hive = 'HKCU:'; Dir = [Environment]::GetFolderPath('Startup') },
  @{ Hive = 'HKLM:'; Dir = [Environment]::GetFolderPath('CommonStartup') }
)
foreach ($f in $folders) {
  Get-ChildItem -LiteralPath $f.Dir -File -ErrorAction SilentlyContinue | ForEach-Object {
    if (Test-Name @($_.Name, $_.BaseName)) {
      $found += @{ Kind = 'approved'; Key = "$($f.Hive)\$explorer\StartupFolder"; Name = $_.Name; Shown = $_.BaseName }
    }
  }
}
$apps = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData'
Get-ChildItem $apps -ErrorAction SilentlyContinue | ForEach-Object {
  $family = $_.PSChildName
  Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
    $state = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).State
    if ($state -ne $null -and (Test-Name @($family, ($family -split '_')[0], $startMenu[$family], $_.PSChildName))) {
      $shown = if ($startMenu[$family]) { $startMenu[$family] } else { ($family -split '_')[0] }
      $found += @{ Kind = 'packaged'; Key = $_.PSPath; Name = 'State'; Shown = $shown; State = $state }
    }
  }
}
function Test-On($e) {
  if ($e.Kind -eq 'packaged') { return $e.State -eq 2 -or $e.State -eq 4 }
  $v = (Get-ItemProperty $e.Key -ErrorAction SilentlyContinue).($e.Name)
  return -not ($v -and ($v[0] -band 1))
}
$todo = @($found | Where-Object { (Test-On $_) -ne $Enable })
if ($Mode -eq 'check') { if (-not $todo) { 'same' }; return }
if (-not $found) { "nothing starting at sign-in matches $($Patterns -join ', ')" }
foreach ($e in $todo) {
  if ($e.Kind -eq 'packaged') {
    # 1: off, as the user turns it off; a policy's 3 and 4 are left alone.
    if ($e.State -eq 3 -or $e.State -eq 4) { "$($e.Shown) is set by a policy; left alone"; continue }
    Set-ItemProperty $e.Key -Name State -Value $(if ($Enable) { 2 } else { 1 }) -Type DWord
  } else {
    $bytes = if ($Enable) { [byte[]](2,0,0,0,0,0,0,0,0,0,0,0) } else { [byte[]](3,0,0,0) + [BitConverter]::GetBytes([DateTime]::UtcNow.ToFileTimeUtc()) }
    if (-not (Test-Path $e.Key)) { New-Item $e.Key -Force | Out-Null }
    Set-ItemProperty $e.Key -Name $e.Name -Value $bytes -Type Binary
  }
  "$(if ($Enable) { 'on' } else { 'off' }): $($e.Shown)"
}
"#;

/// Finds scheduled tasks by name: `\Folder\Name` patterns match the whole path, others the
/// name alone. Windows' own protected tasks refuse even administrators; those are named in the
/// error.
const TASKS: &str = r#"
$tasks = @(Get-ScheduledTask | Where-Object {
  $t = $_
  $Patterns | Where-Object { if ($_.StartsWith('\')) { "$($t.TaskPath)$($t.TaskName)" -like $_ } else { $t.TaskName -like $_ } }
})
$todo = @($tasks | Where-Object {
  $state = "$($_.State)"   # ($_ inside switch is the switch's own value)
  switch ($Want) { 'absent' { $true } 'disabled' { $state -ne 'Disabled' } 'enabled' { $state -eq 'Disabled' } }
})
if ($Mode -eq 'check') { if (-not $todo) { 'same' }; return }
if (-not $tasks) { "no scheduled task matches $($Patterns -join ', ')" }
$failed = @()
foreach ($t in $todo) {
  $full = "$($t.TaskPath)$($t.TaskName)"
  try {
    switch ($Want) {
      'absent' { Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -ErrorAction Stop }
      'disabled' { Disable-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop | Out-Null }
      'enabled' { Enable-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop | Out-Null }
    }
    "${Want}: $full"
  } catch { $failed += "$full ($($_.Exception.Message.Trim()))" }
}
if ($failed) { throw "Windows refused: $($failed -join '; ')" }
"#;

fn script(body: &str, vars: &str, check: bool) -> String {
    let mode = if check { "check" } else { "apply" };
    format!("$ErrorActionPreference = 'Stop'\n$Mode = '{mode}'\n{vars}\n{body}")
}

fn patterns(names: &[String]) -> String {
    let quoted: Vec<String> = names.iter().map(|n| format!("'{}'", n.replace('\'', "''"))).collect();
    format!("$Patterns = @({})", quoted.join(", "))
}

fn differs(script: &str) -> Result<bool> {
    let out = Proc { capture_stdout: true, ..powershell(Shell::Powershell, script) }.run(&mut |_| {})?;
    if out.code != 0 {
        bail!("PowerShell exited with {}", out.code);
    }
    Ok(out.stdout.trim() != "same")
}

fn apply(script: &str, log: &mut dyn FnMut(&str)) -> Result<()> {
    let out = powershell(Shell::Powershell, script).run(log)?;
    if out.code != 0 {
        bail!("PowerShell exited with {}", out.code);
    }
    Ok(())
}

fn startup_script(s: &StartupItem, check: bool) -> String {
    let enable = if s.enabled { "$true" } else { "$false" };
    script(STARTUP, &format!("{}\n$Enable = {enable}", patterns(std::slice::from_ref(&s.name))), check)
}

fn task_script(t: &TaskRule, check: bool) -> String {
    let want = match t.state {
        TaskState::Enabled => "enabled",
        TaskState::Disabled => "disabled",
        TaskState::Absent => "absent",
    };
    script(TASKS, &format!("{}\n$Want = '{want}'", patterns(std::slice::from_ref(&t.name))), check)
}

/// Whether a startup rule would change anything (an entry it matches isn't as wanted).
pub fn startup_differs(s: &StartupItem) -> Result<bool> {
    differs(&startup_script(s, true))
}

pub fn set_startup(s: &StartupItem, log: &mut dyn FnMut(&str)) -> Result<bool> {
    if !startup_differs(s)? {
        return Ok(false);
    }
    apply(&startup_script(s, false), log)?;
    Ok(true)
}

pub fn task_differs(t: &TaskRule) -> Result<bool> {
    differs(&task_script(t, true))
}

pub fn set_task(t: &TaskRule, log: &mut dyn FnMut(&str)) -> Result<bool> {
    if !task_differs(t)? {
        return Ok(false);
    }
    apply(&task_script(t, false), log)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_run_and_find_nothing_for_names_nobody_has() {
        // Read-only: no entry or task has these names, so there's nothing to do.
        let name = format!("groundhog-test-{}-'quoted'*", std::process::id());
        assert!(!startup_differs(&StartupItem { name: name.clone(), enabled: false }).unwrap());
        assert!(!task_differs(&TaskRule { name: name.clone(), state: TaskState::Disabled }).unwrap());
        assert!(!task_differs(&TaskRule { name: format!(r"\nowhere\{name}"), state: TaskState::Absent }).unwrap());
    }
}
