//! `defender:` and `bitlocker:` steps.

use anyhow::{Result, bail};
use groundhog_core::model::{BitLocker, DefenderSetting, Shell};
use groundhog_win::process::Proc;

use crate::exec::powershell;

/// A PowerShell string literal.
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn run_check(check: &str) -> Result<bool> {
    let script = format!("$ErrorActionPreference = 'Stop'\n{check}");
    let mut errors = Vec::new();
    let out = Proc { capture_stdout: true, ..powershell(Shell::Powershell, &script) }
        .run(&mut |l| errors.push(l.to_owned()))?;
    if out.code != 0 {
        bail!("checking: {}", errors.join(" "));
    }
    Ok(out.stdout.trim() != "same")
}

fn run(script: &str, log: &mut dyn FnMut(&str)) -> Result<()> {
    let out = powershell(Shell::Powershell, &format!("$ErrorActionPreference = 'Stop'\n{script}")).run(log)?;
    if out.code != 0 {
        bail!("PowerShell exited with {}", out.code);
    }
    Ok(())
}

/// (check, change) for a Defender preference.
fn defender_scripts(d: &DefenderSetting) -> (String, String) {
    match d {
        DefenderSetting::Pref { name, value, .. } => (
            format!("if ([int](Get-MpPreference).{name} -eq {value}) {{ 'same' }} else {{ 'differs' }}"),
            format!("Set-MpPreference -{name} {value}"),
        ),
        DefenderSetting::ScanTime { at } => (
            // Newer Defenders give a time of day as a DateTime, older ones as a TimeSpan.
            format!(
                "$t = (Get-MpPreference).ScanScheduleTime\n\
                 $now = if ($t -is [datetime]) {{ $t.ToString('HH:mm') }} else {{ '{{0:hh\\:mm}}' -f $t }}\n\
                 if ($now -eq '{at}') {{ 'same' }} else {{ 'differs' }}"
            ),
            format!("Set-MpPreference -ScanScheduleTime '{at}'"),
        ),
        DefenderSetting::AllowedApps { paths } => {
            let list: Vec<String> = paths.iter().map(|p| quote(p)).collect();
            let list = list.join(", ");
            (
                format!(
                    "$have = @((Get-MpPreference).ControlledFolderAccessAllowedApplications)\n\
                     if (-not (@({list}) | Where-Object {{ $have -notcontains $_ }})) {{ 'same' }} else {{ 'differs' }}"
                ),
                format!("Add-MpPreference -ControlledFolderAccessAllowedApplications @({list})"),
            )
        }
    }
}

pub fn defender_differs(d: &DefenderSetting) -> Result<bool> {
    run_check(&defender_scripts(d).0)
}

pub fn set_defender(d: &DefenderSetting, log: &mut dyn FnMut(&str)) -> Result<bool> {
    let (check, change) = defender_scripts(d);
    if !run_check(&check)? {
        return Ok(false);
    }
    run(&change, log)?;
    // Tamper Protection keeps some settings (cloud protection among them) as they are,
    // without an error.
    if run_check(&check)? {
        bail!(
            "Defender kept its setting: Tamper Protection guards it (turn that off in Windows Security first), or a policy sets it"
        );
    }
    Ok(true)
}

/// The system drive's encryption, and whether it has the protectors Groundhog adds.
const BITLOCKER_STATE: &str = r#"
$m = $env:SystemDrive
$v = Get-BitLockerVolume -MountPoint $m
$types = @($v.KeyProtector | ForEach-Object { "$($_.KeyProtectorType)" })
"#;

fn bitlocker_scripts(b: &BitLocker) -> (String, String) {
    if !b.on {
        return (
            format!(
                "{BITLOCKER_STATE}if (\"$($v.VolumeStatus)\" -in 'FullyDecrypted', 'DecryptionInProgress') {{ 'same' }} else {{ 'differs' }}"
            ),
            "Disable-BitLocker -MountPoint $env:SystemDrive -WarningAction SilentlyContinue | Out-Null".to_owned(),
        );
    }
    let check = format!(
        "{BITLOCKER_STATE}\
         $encrypting = \"$($v.VolumeStatus)\" -in 'FullyEncrypted', 'EncryptionInProgress'\n\
         $protected = \"$($v.ProtectionStatus)\" -eq 'On' -or \"$($v.VolumeStatus)\" -eq 'EncryptionInProgress'\n\
         if ($encrypting -and $protected -and $types -contains 'Tpm' -and $types -contains 'RecoveryPassword') {{ 'same' }} else {{ 'differs' }}"
    );
    let recovery = b.recovery_key.as_deref().unwrap_or_default();
    // The recovery password is never printed: the cmdlets' warnings that show it are dropped.
    let escrow = match recovery.to_ascii_lowercase().as_str() {
        "entra" => {
            "BackupToAAD-BitLockerKeyProtector -MountPoint $m -KeyProtectorId $rp.KeyProtectorId | Out-Null".to_owned()
        }
        "ad" => "Backup-BitLockerKeyProtector -MountPoint $m -KeyProtectorId $rp.KeyProtectorId | Out-Null".to_owned(),
        _ => format!(
            "$dir = {}\n\
             New-Item -ItemType Directory -Force -Path $dir | Out-Null\n\
             $file = Join-Path $dir \"BitLocker recovery $env:COMPUTERNAME $($rp.KeyProtectorId.Trim('{{}}')).txt\"\n\
             Set-Content -LiteralPath $file -Value \"BitLocker recovery password for $m on $env:COMPUTERNAME`r`nKey ID: $($rp.KeyProtectorId)`r`nRecovery password: $($rp.RecoveryPassword)\"\n\
             \"recovery password saved in $file\"",
            quote(recovery)
        ),
    };
    let change = format!(
        "{BITLOCKER_STATE}\
         $tpm = Get-Tpm\n\
         if (-not $tpm.TpmPresent -or -not $tpm.TpmReady) {{ throw 'this machine has no TPM ready for BitLocker' }}\n\
         if ($types -notcontains 'Tpm') {{\n\
             if (\"$($v.VolumeStatus)\" -eq 'FullyDecrypted') {{\n\
                 Enable-BitLocker -MountPoint $m -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector -SkipHardwareTest -WarningAction SilentlyContinue | Out-Null\n\
             }} else {{\n\
                 Add-BitLockerKeyProtector -MountPoint $m -TpmProtector -WarningAction SilentlyContinue | Out-Null\n\
             }}\n\
         }}\n\
         if ($types -notcontains 'RecoveryPassword') {{\n\
             Add-BitLockerKeyProtector -MountPoint $m -RecoveryPasswordProtector -WarningAction SilentlyContinue | Out-Null\n\
         }}\n\
         $v = Get-BitLockerVolume -MountPoint $m\n\
         $rp = $v.KeyProtector | Where-Object {{ \"$($_.KeyProtectorType)\" -eq 'RecoveryPassword' }} | Select-Object -First 1\n\
         {escrow}\n\
         if (\"$($v.ProtectionStatus)\" -eq 'Off' -and \"$($v.VolumeStatus)\" -eq 'FullyEncrypted') {{ Resume-BitLocker -MountPoint $m | Out-Null }}\n\
         \"$((Get-BitLockerVolume -MountPoint $m).VolumeStatus)\""
    );
    (check, change)
}

pub fn bitlocker_differs(b: &BitLocker) -> Result<bool> {
    run_check(&bitlocker_scripts(b).0)
}

pub fn set_bitlocker(b: &BitLocker, log: &mut dyn FnMut(&str)) -> Result<bool> {
    let (check, change) = bitlocker_scripts(b);
    if !run_check(&check)? {
        return Ok(false);
    }
    run(&change, log)?;
    Ok(true)
}
