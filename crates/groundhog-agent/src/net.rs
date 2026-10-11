//! `network:` steps: DNS servers, hosts file entries, mapped drives and Wi-Fi networks.

use anyhow::{Context, Result, bail};
use groundhog_core::model::{NetSetting, Shell};
use groundhog_win::process::Proc;
use groundhog_win::registry::{self, Data};

use crate::exec::powershell;

/// Text in a PowerShell single-quoted string.
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn hosts_path() -> std::path::PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    std::path::PathBuf::from(root).join(r"System32\drivers\etc\hosts")
}

/// The hosts file's lines that give `name` an address (not comments).
fn hosts_lines_for<'a>(text: &'a str, name: &str) -> Vec<&'a str> {
    text.lines()
        .filter(|l| {
            let l = l.split('#').next().unwrap_or("");
            let mut words = l.split_whitespace();
            words.next().is_some() && words.any(|w| w.eq_ignore_ascii_case(name))
        })
        .collect()
}

fn hosts_differs(name: &str, address: Option<&str>) -> Result<bool> {
    let text = std::fs::read_to_string(hosts_path()).unwrap_or_default();
    let lines = hosts_lines_for(&text, name);
    Ok(match address {
        None => !lines.is_empty(),
        Some(a) => !(lines.len() == 1 && lines[0].split_whitespace().next() == Some(a)),
    })
}

/// Takes out the lines that name `name` and, if there's an address, adds one line for it.
fn set_hosts(name: &str, address: Option<&str>) -> Result<()> {
    let path = hosts_path();
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let drop = hosts_lines_for(&text, name);
    let mut out: Vec<String> = text.lines().filter(|l| !drop.contains(l)).map(str::to_owned).collect();
    if let Some(a) = address {
        out.push(format!("{a}\t{name}\t# Groundhog"));
    }
    let mut new = out.join("\r\n");
    new.push_str("\r\n");
    std::fs::write(&path, new).with_context(|| format!("writing {}", path.display()))
}

/// A mapped drive as Windows keeps it for the account (restored at each sign-in).
fn drive_differs(letter: &str, path: Option<&str>) -> Result<bool> {
    let hkcu = registry::hkcu();
    let have = registry::get_string(&hkcu, &format!(r"Network\{letter}"), "RemotePath");
    Ok(match path {
        None => have.is_some(),
        Some(p) => !have.is_some_and(|h| h.eq_ignore_ascii_case(p)),
    })
}

fn set_drive(letter: &str, path: Option<&str>) -> Result<()> {
    let hkcu = registry::hkcu();
    let key = format!(r"Network\{letter}");
    let Some(path) = path else {
        registry::delete_key(&hkcu, &key)?;
        return Ok(());
    };
    registry::set_value(&hkcu, &key, Some("RemotePath"), &Data::String(path))?;
    registry::set_value(&hkcu, &key, Some("UserName"), &Data::String(""))?;
    registry::set_value(&hkcu, &key, Some("ProviderName"), &Data::String("Microsoft Windows Network"))?;
    registry::set_value(&hkcu, &key, Some("ProviderType"), &Data::Dword(0x20000))?;
    registry::set_value(&hkcu, &key, Some("ConnectionType"), &Data::Dword(1))?;
    registry::set_value(&hkcu, &key, Some("DeferFlags"), &Data::Dword(4))?;
    Ok(())
}

fn dns_scripts(adapter: &str, servers: &[String]) -> (String, String) {
    let want: Vec<String> = servers.iter().map(|s| quote(s)).collect();
    let head = format!(
        "$adapters = @(Get-NetAdapter -Name {a} -ErrorAction SilentlyContinue)\n\
         if (-not $adapters) {{ throw \"no network adapter is called {name} (Get-NetAdapter lists them)\" }}\n\
         $want = @({w})\n\
         $want4 = @($want | Where-Object {{ $_ -notmatch ':' }}); $want6 = @($want | Where-Object {{ $_ -match ':' }})",
        a = quote(adapter),
        name = adapter.replace('"', ""),
        w = want.join(", ")
    );
    (
        format!(
            "{head}\n$ok = $true\n\
             foreach ($a in $adapters) {{\n\
               if (-not $want) {{\n\
                 # Automatic: no servers of its own in its settings\n\
                 $ns = (Get-ItemProperty \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\$($a.InterfaceGuid)\" -ErrorAction SilentlyContinue).NameServer\n\
                 if ($ns) {{ $ok = $false }}\n\
               }} else {{\n\
                 $h4 = @((Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4).ServerAddresses)\n\
                 if (($h4 -join ',') -ne ($want4 -join ',')) {{ $ok = $false }}\n\
                 if ($want6) {{\n\
                   $h6 = @((Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv6).ServerAddresses)\n\
                   if (($h6 -join ',') -ne ($want6 -join ',')) {{ $ok = $false }}\n\
                 }}\n\
               }}\n\
             }}\n\
             if ($ok) {{ 'same' }}"
        ),
        format!(
            "{head}\n\
             foreach ($a in $adapters) {{\n\
               if ($want) {{ Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses $want }}\n\
               else {{ Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses }}\n\
               \"$($a.Name): $(if ($want) {{ $want -join ', ' }} else {{ 'automatic' }})\"\n\
             }}"
        ),
    )
}

/// The profile Windows keeps for a Wi-Fi network: WPA2 personal (which also joins WPA3
/// networks in transition mode), or open without a password.
fn wifi_profile(ssid: &str, password: Option<&str>, auto_connect: bool) -> String {
    let security = match password {
        Some(p) => format!(
            "<authEncryption><authentication>WPA2PSK</authentication><encryption>AES</encryption><useOneX>false</useOneX></authEncryption>\
             <sharedKey><keyType>passPhrase</keyType><protected>false</protected><keyMaterial>{p}</keyMaterial></sharedKey>"
        ),
        None => "<authEncryption><authentication>open</authentication><encryption>none</encryption><useOneX>false</useOneX></authEncryption>".to_owned(),
    };
    let mode = if auto_connect { "auto" } else { "manual" };
    format!(
        "<?xml version=\"1.0\"?>\
         <WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\">\
         <name>{ssid}</name><SSIDConfig><SSID><name>{ssid}</name></SSID></SSIDConfig>\
         <connectionType>ESS</connectionType><connectionMode>{mode}</connectionMode>\
         <MSM><security>{security}</security></MSM></WLANProfile>"
    )
}

fn netsh(args: &[&str]) -> Result<(i32, String)> {
    let out = Proc { capture_stdout: true, ..Proc::new("netsh.exe").args(args.iter().copied()) }.run(&mut |_| {})?;
    Ok((out.code, out.stdout))
}

fn wifi_differs(ssid: &str, present: bool) -> Result<bool> {
    let (code, _) = netsh(&["wlan", "show", "profiles", &format!("name={ssid}")])?;
    Ok((code == 0) != present)
}

fn set_wifi(
    ssid: &str,
    password: Option<&str>,
    auto_connect: bool,
    present: bool,
    work: &std::path::Path,
) -> Result<()> {
    if !present {
        let (code, out) = netsh(&["wlan", "delete", "profile", &format!("name={ssid}")])?;
        if code != 0 {
            bail!("netsh couldn't forget {ssid}: {}", out.trim());
        }
        return Ok(());
    }
    std::fs::create_dir_all(work)?;
    let file = work.join(format!("wifi-{}.xml", std::process::id()));
    std::fs::write(&file, wifi_profile(ssid, password, auto_connect))?;
    let result = netsh(&["wlan", "add", "profile", &format!("filename={}", file.display()), "user=all"]);
    let _ = std::fs::remove_file(&file); // it holds the password
    let (code, out) = result?;
    if code != 0 {
        bail!(
            "netsh couldn't add {ssid}: {} (Wi-Fi needs a wireless adapter and the WLAN AutoConfig service)",
            out.trim()
        );
    }
    Ok(())
}

fn run_ps_check(check: &str) -> Result<bool> {
    let out = Proc { capture_stdout: true, ..powershell(Shell::Powershell, check) }.run(&mut |_| {})?;
    if out.code != 0 {
        bail!("checking: PowerShell exited with {}", out.code);
    }
    Ok(out.stdout.trim() != "same")
}

/// Whether Windows differs. `password` is the Wi-Fi password with its secrets filled in.
pub fn differs(n: &NetSetting) -> Result<bool> {
    match n {
        NetSetting::Dns { adapter, servers } => run_ps_check(&dns_scripts(adapter, servers).0),
        NetSetting::HostsEntry { name, address } => hosts_differs(name, address.as_deref()),
        NetSetting::Drive { letter, path } => drive_differs(letter, path.as_deref()),
        NetSetting::Wifi { ssid, state, .. } => wifi_differs(ssid, state.is_present()),
    }
}

/// Makes the change if it's needed; returns whether it changed anything.
pub fn apply(
    n: &NetSetting,
    password: Option<&str>,
    work: &std::path::Path,
    log: &mut dyn FnMut(&str),
) -> Result<bool> {
    if !differs(n)? {
        return Ok(false);
    }
    match n {
        NetSetting::Dns { adapter, servers } => {
            let out = powershell(
                Shell::Powershell,
                &format!("$ErrorActionPreference = 'Stop'\n{}", dns_scripts(adapter, servers).1),
            )
            .run(log)?;
            if out.code != 0 {
                bail!("PowerShell exited with {}", out.code);
            }
        }
        NetSetting::HostsEntry { name, address } => set_hosts(name, address.as_deref())?,
        NetSetting::Drive { letter, path } => {
            set_drive(letter, path.as_deref())?;
            log("Windows maps it at the next sign-in");
        }
        NetSetting::Wifi { ssid, auto_connect, state, .. } => {
            set_wifi(ssid, password, *auto_connect, state.is_present(), work)?
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_lines_ignore_comments_and_match_whole_names() {
        let text = "# 10.0.0.1 build.local\n127.0.0.1 localhost\n10.0.0.5\tbuild.local other # Groundhog\n10.0.0.6 build.localx\n";
        assert_eq!(hosts_lines_for(text, "build.local"), ["10.0.0.5\tbuild.local other # Groundhog"]);
        assert!(hosts_lines_for(text, "nothere").is_empty());
    }

    #[test]
    fn wifi_profiles() {
        let wpa = wifi_profile("Office", Some("hunter22hunter"), true);
        assert!(
            wpa.contains("<authentication>WPA2PSK</authentication>")
                && wpa.contains("<keyMaterial>hunter22hunter</keyMaterial>")
        );
        assert!(wpa.contains("<connectionMode>auto</connectionMode>"));
        let open = wifi_profile("Cafe", None, false);
        assert!(open.contains("<authentication>open</authentication>") && !open.contains("sharedKey"));
    }

    #[test]
    fn dns_check_reads_this_machines_adapters() {
        // Read-only: an adapter nobody has fails with a clear message.
        let err =
            differs(&NetSetting::Dns { adapter: "groundhog-no-such-adapter".into(), servers: vec![] }).unwrap_err();
        assert!(format!("{err:#}").contains("exited"), "{err:#}");
    }
}
