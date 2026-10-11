//! Default apps, the way Windows supports setting them: an associations file named by the
//! `DefaultAssociationsConfiguration` policy, which Windows applies to every account at each
//! sign-in. (Each user's own choice is protected against programs writing it directly.)
//!
//! The file names each app by its ProgId; people name apps. So each name is found among the
//! apps registered for that type (`RegisteredApplications`: browsers, mail and PDF readers
//! list what they open there), then as a ProgId given as is, then among the programs Windows
//! offers in "Open with" for that type, by the program's description or file name.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use groundhog_core::model::Shell;
use groundhog_win::process::Proc;

use crate::exec::powershell;

const SCRIPT: &str = r#"
$file = $env:ProgramData + '\groundhog\desktop\default-apps.xml'  # kept by `clean`
$policy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
$registered = @(foreach ($root in 'HKLM:', 'HKCU:') {
    $p = Get-ItemProperty "$root\SOFTWARE\RegisteredApplications" -ErrorAction SilentlyContinue
    if ($p) {
        foreach ($v in $p.PSObject.Properties | Where-Object Name -notlike 'PS*') {
            $cap = "$root\$($v.Value)"
            [pscustomobject]@{ Key = $v.Name; Name = (Get-ItemProperty $cap -ErrorAction SilentlyContinue).ApplicationName; Cap = $cap }
        }
    }
})
function Find-ProgId($kind, $app) {
    $section = if ($kind.StartsWith('.')) { 'FileAssociations' } else { 'URLAssociations' }
    foreach ($r in $registered) {
        if ($r.Key -like "$app*" -or $r.Name -eq $app) {
            $id = (Get-ItemProperty "$($r.Cap)\$section" -ErrorAction SilentlyContinue).$kind
            if ($id) { return @($id, $(if ($r.Name -and $r.Name -notlike '@*') { $r.Name } else { $r.Key })) }
        }
    }
    if (Test-Path -LiteralPath "Registry::HKEY_CLASSES_ROOT\$app") { return @($app, $app) }
    $offers = (Get-Item -LiteralPath "Registry::HKEY_CLASSES_ROOT\$kind\OpenWithProgids" -ErrorAction SilentlyContinue).Property
    foreach ($id in $offers) {
        $command = (Get-ItemProperty -LiteralPath "Registry::HKEY_CLASSES_ROOT\$id\shell\open\command" -ErrorAction SilentlyContinue).'(default)'
        $exe = if ($command -match '^\s*"([^"]+)"') { $Matches[1] } elseif ($command -match '^\s*(\S+)') { $Matches[1] } else { '' }
        $exe = [Environment]::ExpandEnvironmentVariables($exe)
        if (-not $exe -or -not (Test-Path -LiteralPath $exe)) { continue }
        $info = (Get-Item -LiteralPath $exe).VersionInfo
        if ($info.FileDescription -like $app -or $info.ProductName -like $app -or [IO.Path]::GetFileNameWithoutExtension($exe) -like $app) {
            return @($id, $(if ($info.ProductName) { $info.ProductName } else { $app }))
        }
    }
    $names = @($registered | Where-Object { (Get-ItemProperty "$($_.Cap)\$section" -ErrorAction SilentlyContinue).$kind } | ForEach-Object { if ($_.Name -and $_.Name -notlike '@*') { $_.Name } else { $_.Key } })
    throw "no app called $app opens $kind here$(if ($names) { ' (registered for it: ' + ($names -join ', ') + ')' })"
}
$lines = foreach ($kind in $Wanted.Keys | Sort-Object) {
    $found = Find-ProgId $kind $Wanted[$kind]
    $esc = { param($t) [Security.SecurityElement]::Escape($t) }
    "  <Association Identifier=""$(& $esc $kind)"" ProgId=""$(& $esc $found[0])"" ApplicationName=""$(& $esc $found[1])"" />"
}
$xml = "<?xml version=""1.0"" encoding=""UTF-8""?>`r`n<DefaultAssociations>`r`n" + ($lines -join "`r`n") + "`r`n</DefaultAssociations>`r`n"
$have = if (Test-Path -LiteralPath $file) { [IO.File]::ReadAllText($file) } else { '' }
$named = (Get-ItemProperty $policy -ErrorAction SilentlyContinue).DefaultAssociationsConfiguration
# What new accounts start with: dism keeps the imported file as OEMDefaultAssociations.xml.
$oem = $env:SystemRoot + '\System32\OEMDefaultAssociations.xml'
$imported = if (Test-Path -LiteralPath $oem) { [IO.File]::ReadAllText($oem) -replace '\s', '' } else { '' }
if ($have -eq $xml -and $named -eq $file -and $imported -eq ($xml -replace '\s', '')) { if ($Mode -eq 'check') { 'same' }; return }
if ($Mode -eq 'check') { return }
New-Item -ItemType Directory -Force (Split-Path $file) | Out-Null
[IO.File]::WriteAllText($file, $xml)
if (-not (Test-Path $policy)) { New-Item $policy -Force | Out-Null }
Set-ItemProperty $policy -Name DefaultAssociationsConfiguration -Value $file
cmd /d /c "dism.exe /online /import-defaultappassociations:`"$file`" >nul 2>&1"
if ($LASTEXITCODE -ne 0) { throw "dism couldn't import the default apps (exit $LASTEXITCODE)" }
$lines | ForEach-Object { $_.Trim() }
'changed'
"#;

fn script(wanted: &BTreeMap<String, String>, check: bool) -> String {
    let pairs: Vec<String> =
        wanted.iter().map(|(k, v)| format!("'{}' = '{}'", k.replace('\'', "''"), v.replace('\'', "''"))).collect();
    format!(
        "$ErrorActionPreference = 'Stop'\n$Mode = '{}'\n$Wanted = @{{ {} }}\n{SCRIPT}",
        if check { "check" } else { "apply" },
        pairs.join("; ")
    )
}

pub fn differs(wanted: &BTreeMap<String, String>) -> Result<bool> {
    let out = Proc { capture_stdout: true, ..powershell(Shell::Powershell, &script(wanted, true)) }.run(&mut |_| {})?;
    if out.code != 0 {
        bail!("checking the default apps: PowerShell exited with {}", out.code);
    }
    Ok(out.stdout.trim() != "same")
}

/// Writes the associations file and the policy naming it; Windows applies it at sign-in.
pub fn apply(wanted: &BTreeMap<String, String>, log: &mut dyn FnMut(&str)) -> Result<bool> {
    if !differs(wanted)? {
        return Ok(false);
    }
    let out = powershell(Shell::Powershell, &script(wanted, false)).run(log)?;
    if out.code != 0 {
        bail!("PowerShell exited with {}", out.code);
    }
    Ok(true)
}
