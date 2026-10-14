//! `join:` steps: an Active Directory domain, Entra ID from a provisioning package, and the
//! prompt for a work or school account.

use anyhow::{Context, Result, bail};
use groundhog_core::fetch::{Fetcher, normalize_sha256, sha256_hex};
use groundhog_core::model::{JoinSetting, Shell};
use groundhog_win::process::Proc;

use crate::exec::powershell;

/// The environment variable the domain password reaches PowerShell in, so it's never on a
/// command line or in a script.
const PASSWORD_VAR: &str = "GROUNDHOG_JOIN_PASSWORD";

/// A PowerShell string literal.
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Prints `same` when the machine (or, for a work account, the agent's user) already is
/// where `j` wants it. `dsregcmd /status` reports both Entra ID and work accounts.
fn check_script(j: &JoinSetting) -> String {
    match j {
        JoinSetting::Domain { name, .. } => format!(
            "$cs = Get-CimInstance Win32_ComputerSystem\n\
             if ($cs.PartOfDomain -and $cs.Domain -eq {}) {{ 'same' }} else {{ 'differs' }}",
            quote(name)
        ),
        JoinSetting::Entra { .. } => {
            "if ((dsregcmd /status) -match '^\\s*AzureAdJoined\\s*:\\s*YES') { 'same' } else { 'differs' }".to_owned()
        }
        // Joined to Entra ID, the account that signed in is already the work account.
        JoinSetting::WorkAccount => "$s = dsregcmd /status\n\
             if ($s -match '^\\s*(WorkplaceJoined|AzureAdJoined)\\s*:\\s*YES') { 'same' } else { 'differs' }"
            .to_owned(),
    }
}

fn differs_by(script: &str) -> Result<bool> {
    let out = Proc { capture_stdout: true, ..powershell(Shell::Powershell, script) }.run(&mut |_| {})?;
    if out.code != 0 {
        bail!("checking: PowerShell exited with {}", out.code);
    }
    Ok(out.stdout.trim() != "same")
}

pub fn differs(j: &JoinSetting) -> Result<bool> {
    differs_by(&check_script(j))
}

/// Joins the domain with the account and password given. Takes effect after a restart.
pub fn join_domain(j: &JoinSetting, password: String, log: &mut dyn FnMut(&str)) -> Result<bool> {
    let JoinSetting::Domain { name, user, ou, .. } = j else { unreachable!("a domain join") };
    if !differs(j)? {
        return Ok(false);
    }
    let ou = ou.as_deref().map(|o| format!("$p.OUPath = {}\n", quote(o))).unwrap_or_default();
    let script = format!(
        "$ErrorActionPreference = 'Stop'\n\
         $cs = Get-CimInstance Win32_ComputerSystem\n\
         if ($cs.PartOfDomain) {{ throw \"this computer is in the $($cs.Domain) domain; it has to leave it first\" }}\n\
         $pw = ConvertTo-SecureString $env:{PASSWORD_VAR} -AsPlainText -Force\n\
         $p = @{{ DomainName = {name}; Credential = New-Object PSCredential({user}, $pw); Force = $true }}\n\
         {ou}\
         Add-Computer @p\n\
         'joined; Windows finishes after a restart'",
        name = quote(name),
        user = quote(user),
    );
    let mut proc = powershell(Shell::Powershell, &script);
    proc.env.push((PASSWORD_VAR.to_owned(), password));
    let out = proc.run(log)?;
    if out.code != 0 {
        bail!("couldn't join {name} (PowerShell exited with {})", out.code);
    }
    Ok(true)
}

/// Downloads the provisioning package into this account's own temp folder, never the shared
/// cache, installs it and deletes it: the token in it joins any machine to the tenant.
pub fn join_entra(j: &JoinSetting, fetcher: &dyn Fetcher, log: &mut dyn FnMut(&str)) -> Result<bool> {
    let JoinSetting::Entra { package, sha256 } = j else { unreachable!("an Entra ID join") };
    if !differs(j)? {
        return Ok(false);
    }
    let bytes = fetcher.fetch(package).with_context(|| format!("downloading {package}"))?;
    if let Some(pin) = sha256 {
        let actual = sha256_hex(&bytes);
        if actual != normalize_sha256(pin)? {
            bail!("{package} has sha256 {actual}, not the pinned {pin}");
        }
    }
    let path = std::env::temp_dir().join(format!("groundhog-join-{}.ppkg", std::process::id()));
    std::fs::write(&path, &bytes).with_context(|| format!("writing {}", path.display()))?;
    let script = format!(
        "$ErrorActionPreference = 'Stop'\n\
         Install-ProvisioningPackage -PackagePath {} -QuietInstall -ForceInstall | Out-Null\n\
         'installed the provisioning package'",
        quote(&path.display().to_string())
    );
    let out = powershell(Shell::Powershell, &script).run(log);
    let _ = std::fs::remove_file(&path);
    let out = out?;
    if out.code != 0 {
        bail!(
            "installing the provisioning package failed (PowerShell exited with {}); its log is in \
             %ProgramData%\\Microsoft\\Provisioning",
            out.code
        );
    }
    Ok(true)
}

/// Opens Settings at "Access work or school" for the agent's user, who signs in there: an
/// organization's sign-in (and its second factor) can't be done for them.
pub fn prompt_work_account(j: &JoinSetting, log: &mut dyn FnMut(&str)) -> Result<bool> {
    if !differs(j)? {
        return Ok(false);
    }
    let out = powershell(Shell::Powershell, "Start-Process 'ms-settings:workplace'").run(log)?;
    if out.code != 0 {
        bail!("couldn't open Settings (PowerShell exited with {})", out.code);
    }
    log("opened Settings > Accounts > Access work or school: select Connect and sign in there");
    Ok(true)
}
