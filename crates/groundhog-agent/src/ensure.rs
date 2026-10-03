//! Steps carried out by short PowerShell scripts: certificates, services, firewall rules,
//! Defender exclusions and built-in apps, where the PowerShell modules Windows ships are the
//! supported interface.
//!
//! Every script follows one convention, so each one also answers "would this change
//! anything?" for `plan --check`:
//! - parameters arrive as environment variables (`$env:GH_NAME`), never spliced into the
//!   script, so no value needs quoting and none can inject code;
//! - the script prints `GROUNDHOG:CHANGED` when it changed something;
//! - with `$env:GH_CHECK` set it changes nothing and prints `GROUNDHOG:WOULD-CHANGE` instead.

use std::path::Path;

use anyhow::{Result, bail};
use groundhog_core::fetch::sha256_hex;
use groundhog_core::model::{
    CertScope, Certificate, DefenderExclusion, ExclusionKind, FirewallAction, FirewallDirection, FirewallProtocol,
    FirewallRule, Presence, Service, ServiceState, Shell, StartupType,
};
use groundhog_win::process::Proc;

const CHANGED: &str = "GROUNDHOG:CHANGED";
const WOULD_CHANGE: &str = "GROUNDHOG:WOULD-CHANGE";

/// Runs one of the scripts below. Returns whether it changed (or, checking, would change)
/// anything.
fn run(what: &str, script: &str, params: &[(&str, String)], check: bool, log: &mut dyn FnMut(&str)) -> Result<bool> {
    let mut env: Vec<(String, String)> = params.iter().map(|(k, v)| (format!("GH_{k}"), v.clone())).collect();
    if check {
        env.push(("GH_CHECK".into(), "1".into()));
    }
    let script = format!("$ErrorActionPreference = 'Stop'\n{script}");
    let proc = Proc { env, ..crate::exec::powershell(Shell::Powershell, &script) };
    let mut changed = false;
    let mut last: Vec<String> = Vec::new();
    let out = proc.run(&mut |line| match line.trim() {
        CHANGED | WOULD_CHANGE => changed = true,
        "" => {}
        other => {
            if !check {
                log(other);
            }
            last.push(other.to_owned());
            if last.len() > 6 {
                last.remove(0);
            }
        }
    })?;
    if out.code != 0 {
        bail!("{what} failed (exit {}): {}", out.code, last.join(" | "));
    }
    Ok(changed)
}

fn state(p: Presence) -> String {
    if p.is_present() { "present" } else { "absent" }.to_owned()
}

const CERTIFICATE: &str = r##"
$location = if ($env:GH_SCOPE -eq 'user') { 'CurrentUser' } else { 'LocalMachine' }
if ($env:GH_FILE) {
    $bytes = [IO.File]::ReadAllBytes($env:GH_FILE)
    $text = [Text.Encoding]::ASCII.GetString($bytes)
    if ($text -match '-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----') {
        $bytes = [Convert]::FromBase64String(($Matches[1] -replace '\s', ''))
    }
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$bytes)
    $thumb = $cert.Thumbprint
} else {
    $thumb = $env:GH_THUMBPRINT
}
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store($env:GH_STORE, $location)
$store.Open($(if ($env:GH_CHECK) { 'ReadOnly' } else { 'ReadWrite' }))
try {
    $found = @($store.Certificates | Where-Object { $_.Thumbprint -eq $thumb })
    if ($env:GH_STATE -eq 'absent') {
        if ($found.Count) {
            if ($env:GH_CHECK) { 'GROUNDHOG:WOULD-CHANGE' }
            else { foreach ($c in $found) { $store.Remove($c) }; "removed $thumb"; 'GROUNDHOG:CHANGED' }
        }
    } elseif (-not $found.Count) {
        if ($env:GH_CHECK) { 'GROUNDHOG:WOULD-CHANGE' }
        else { $store.Add($cert); "added $($cert.Subject) ($thumb)"; 'GROUNDHOG:CHANGED' }
    }
} finally {
    $store.Close()
}
"##;

/// `file` is the certificate on disk; `None` when removing by thumbprint.
pub fn certificate(c: &Certificate, file: Option<&Path>, check: bool, log: &mut dyn FnMut(&str)) -> Result<bool> {
    let params = [
        ("FILE", file.map(|f| f.to_string_lossy().into_owned()).unwrap_or_default()),
        ("THUMBPRINT", c.thumbprint.clone().unwrap_or_default()),
        ("STORE", c.store.system_name().to_owned()),
        ("SCOPE", if c.scope == CertScope::User { "user" } else { "machine" }.to_owned()),
        ("STATE", state(c.state)),
    ];
    run("certificate", CERTIFICATE, &params, check, log)
}

const SERVICE: &str = r##"
$name = $env:GH_NAME
$svc = Get-CimInstance Win32_Service -Filter "Name='$($name -replace "'", "''")'"
if (-not $svc) { $svc = Get-CimInstance Win32_Service | Where-Object { $_.DisplayName -eq $name } | Select-Object -First 1 }
if (-not $svc) { throw "there's no service named '$name'" }
$name = $svc.Name
$changed = $false
$would = $false
if ($env:GH_STARTUP) {
    $delayed = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$name" -Name DelayedAutostart -ErrorAction SilentlyContinue).DelayedAutostart -eq 1
    $current = switch ($svc.StartMode) {
        'Auto' { if ($delayed) { 'delayed' } else { 'automatic' } }
        'Manual' { 'manual' }
        'Disabled' { 'disabled' }
        default { "$_".ToLower() }
    }
    if ($current -ne $env:GH_STARTUP) {
        if ($env:GH_CHECK) { $would = $true }
        else {
            $arg = @{ automatic = 'auto'; delayed = 'delayed-auto'; manual = 'demand'; disabled = 'disabled' }[$env:GH_STARTUP]
            $out = & sc.exe config $name start= $arg
            if ($LASTEXITCODE -ne 0) { throw "sc.exe config $name start= $arg failed: $out" }
            "startup: $current -> $($env:GH_STARTUP)"
            $changed = $true
        }
    }
}
if ($env:GH_STATUS) {
    $running = (Get-Service -Name $name).Status -eq 'Running'
    $want = $env:GH_STATUS -eq 'running'
    if ($running -ne $want) {
        if ($env:GH_CHECK) { $would = $true }
        elseif ($want) { Start-Service -Name $name; 'started'; $changed = $true }
        else { Stop-Service -Name $name -Force; 'stopped'; $changed = $true }
    }
}
if ($would) { 'GROUNDHOG:WOULD-CHANGE' }
if ($changed) { 'GROUNDHOG:CHANGED' }
"##;

pub fn service(s: &Service, check: bool, log: &mut dyn FnMut(&str)) -> Result<bool> {
    let startup = s.startup.map(|t| match t {
        StartupType::Automatic => "automatic",
        StartupType::Delayed => "delayed",
        StartupType::Manual => "manual",
        StartupType::Disabled => "disabled",
    });
    let status = s.status.map(|st| match st {
        ServiceState::Running => "running",
        ServiceState::Stopped => "stopped",
    });
    let params = [
        ("NAME", s.name.clone()),
        ("STARTUP", startup.unwrap_or_default().to_owned()),
        ("STATUS", status.unwrap_or_default().to_owned()),
    ];
    run(&format!("service {}", s.name), SERVICE, &params, check, log)
}

/// A rule is found again by its display name. Its description holds a hash of everything
/// Groundhog set, so a rule that already matches is left alone and one that doesn't (or that
/// someone edited) is replaced.
const FIREWALL: &str = r##"
$name = $env:GH_NAME
$existing = @(Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)
if ($env:GH_STATE -eq 'absent') {
    if ($existing.Count) {
        if ($env:GH_CHECK) { 'GROUNDHOG:WOULD-CHANGE' }
        else { $existing | Remove-NetFirewallRule; "removed $($existing.Count) rule(s) named $name"; 'GROUNDHOG:CHANGED' }
    }
} else {
    $sig = "groundhog:$($env:GH_SIGNATURE)"
    if ($existing.Count -eq 1 -and $existing[0].Description -eq $sig) {
        # already as declared
    } elseif ($env:GH_CHECK) {
        'GROUNDHOG:WOULD-CHANGE'
    } else {
        if ($existing.Count) { $existing | Remove-NetFirewallRule }
        $p = @{
            DisplayName = $name; Description = $sig; Group = 'Groundhog'
            Direction = $env:GH_DIRECTION; Action = $env:GH_ACTION; Profile = $env:GH_PROFILE
        }
        if ($env:GH_PROTOCOL -ne 'Any') { $p.Protocol = $env:GH_PROTOCOL }
        if ($env:GH_PORTS) {
            if ($env:GH_DIRECTION -eq 'Inbound') { $p.LocalPort = $env:GH_PORTS -split ',' } else { $p.RemotePort = $env:GH_PORTS -split ',' }
        }
        if ($env:GH_PROGRAM) { $p.Program = [Environment]::ExpandEnvironmentVariables($env:GH_PROGRAM) }
        if ($env:GH_REMOTE) { $p.RemoteAddress = $env:GH_REMOTE -split ',' }
        New-NetFirewallRule @p | Out-Null
        "created rule $name"
        'GROUNDHOG:CHANGED'
    }
}
"##;

pub fn firewall(r: &FirewallRule, check: bool, log: &mut dyn FnMut(&str)) -> Result<bool> {
    let signature = sha256_hex(&serde_json::to_vec(r)?)[..16].to_owned();
    let profile = r
        .profile
        .split(',')
        .map(|p| {
            let mut c = p.chars();
            c.next().map(|f| f.to_ascii_uppercase().to_string() + c.as_str()).unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join(",");
    let params = [
        ("NAME", r.name.clone()),
        ("STATE", state(r.state)),
        ("SIGNATURE", signature),
        ("DIRECTION", if r.direction == FirewallDirection::In { "Inbound" } else { "Outbound" }.to_owned()),
        ("ACTION", if r.action == FirewallAction::Allow { "Allow" } else { "Block" }.to_owned()),
        ("PROFILE", profile),
        (
            "PROTOCOL",
            match r.protocol {
                FirewallProtocol::Tcp => "TCP",
                FirewallProtocol::Udp => "UDP",
                FirewallProtocol::Any => "Any",
            }
            .to_owned(),
        ),
        ("PORTS", r.ports.clone().unwrap_or_default()),
        ("PROGRAM", r.program.clone().unwrap_or_default()),
        ("REMOTE", r.remote.clone().unwrap_or_default()),
    ];
    run(&format!("firewall rule {}", r.name), FIREWALL, &params, check, log)
}

const DEFENDER: &str = r##"
$status = Get-MpComputerStatus -ErrorAction SilentlyContinue
if (-not $status -or -not $status.AntivirusEnabled) {
    "Microsoft Defender isn't the active antivirus here; nothing to do"
} else {
    $property = @{ path = 'ExclusionPath'; process = 'ExclusionProcess'; extension = 'ExclusionExtension' }[$env:GH_KIND]
    $value = [Environment]::ExpandEnvironmentVariables($env:GH_VALUE)
    $current = @((Get-MpPreference).$property) | Where-Object { $_ }
    if ($current | Where-Object { $_ -like 'N/A*' }) { throw "can't read Defender's exclusions; run the agent elevated" }
    $has = [bool]($current | Where-Object { $_ -ieq $value })
    $splat = @{ $property = $value }
    if ($env:GH_STATE -eq 'absent') {
        if ($has) {
            if ($env:GH_CHECK) { 'GROUNDHOG:WOULD-CHANGE' } else { Remove-MpPreference @splat; 'GROUNDHOG:CHANGED' }
        }
    } elseif (-not $has) {
        if ($env:GH_CHECK) { 'GROUNDHOG:WOULD-CHANGE' } else { Add-MpPreference @splat; 'GROUNDHOG:CHANGED' }
    }
}
"##;

pub fn defender(e: &DefenderExclusion, check: bool, log: &mut dyn FnMut(&str)) -> Result<bool> {
    let kind = match e.kind {
        ExclusionKind::Path => "path",
        ExclusionKind::Process => "process",
        ExclusionKind::Extension => "extension",
    };
    let params = [("KIND", kind.to_owned()), ("VALUE", e.value.clone()), ("STATE", state(e.state))];
    run("Defender exclusion", DEFENDER, &params, check, log)
}

/// Built-in Store apps: removed for every existing user and unprovisioned, so new profiles
/// don't get them either.
const REMOVE_APP: &str = r##"
$pattern = $env:GH_NAME
$provisioned = @(Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $pattern })
$installed = @(Get-AppxPackage -AllUsers | Where-Object { $_.Name -like $pattern })
if ($provisioned.Count -or $installed.Count) {
    if ($env:GH_CHECK) {
        'GROUNDHOG:WOULD-CHANGE'
    } else {
        foreach ($p in $provisioned) {
            Remove-AppxProvisionedPackage -Online -PackageName $p.PackageName -AllUsers | Out-Null
            "unprovisioned $($p.DisplayName)"
        }
        foreach ($a in $installed) {
            try { Remove-AppxPackage -Package $a.PackageFullName -AllUsers; "removed $($a.PackageFullName)" }
            catch { "couldn't remove $($a.PackageFullName): $($_.Exception.Message)" }
        }
        'GROUNDHOG:CHANGED'
    }
}
"##;

pub fn remove_app(name: &str, check: bool, log: &mut dyn FnMut(&str)) -> Result<bool> {
    run(&format!("removing {name}"), REMOVE_APP, &[("NAME", name.to_owned())], check, log)
}
