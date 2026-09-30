//! `groundhog unattend`: an unattend file that gets a machine from "Windows Setup" or "sysprepped
//! template" to "the agent is applying a Groundhogfile", with nobody at the keyboard.
//!
//! The file covers only what has to happen before the agent can run: accept the license, skip
//! the setup screens, set the computer name, language and time zone, create the provisioning
//! account, log it on automatically, and on first logon install the agent, write its
//! `pending.json` and start it. Apps, files, registry and everything else stay in the
//! Groundhogfile, where the agent can resume after restarts, verify downloads and report.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use clap::{Args, ValueEnum};
use groundhog_core::pending::Pending;

use crate::{PendingOptions, secret_value};

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    /// A full answer file for installing from ISO/USB (save it as autounattend.xml on the media).
    Install,
    /// For sealing a template: `sysprep /generalize /oobe /unattend:<file>`.
    Sysprep,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Arch {
    X64,
    Arm64,
}

impl Arch {
    fn processor(self) -> &'static str {
        match self {
            Arch::X64 => "amd64",
            Arch::Arm64 => "arm64",
        }
    }

    fn agent_asset(self) -> &'static str {
        match self {
            Arch::X64 => "groundhog-agent-x64.exe",
            Arch::Arm64 => "groundhog-agent-arm64.exe",
        }
    }
}

#[derive(Args)]
pub struct UnattendArgs {
    /// The Groundhogfile to apply after the first logon: path, URL or zip, as the new machine
    /// will see it.
    source: String,
    #[arg(long, value_enum, default_value_t = Mode::Install)]
    mode: Mode,
    #[command(flatten)]
    pending: PendingOptions,
    /// The local administrator that logs on automatically and runs the agent.
    #[arg(long, default_value = "provisioner", value_name = "NAME")]
    autologon: String,
    /// That account's password, as NAME (read from the NAME environment variable) or NAME=value.
    /// Generated when omitted.
    #[arg(long, value_name = "NAME[=VALUE]")]
    autologon_password: Option<String>,
    /// How many automatic logons to allow; every restart during setup uses one.
    #[arg(long, default_value_t = 5, value_name = "N")]
    autologon_count: u32,
    /// `*` lets Windows pick a random name (the right choice for clones of one template).
    #[arg(long, default_value = "*", value_name = "NAME")]
    computer_name: String,
    #[arg(long, default_value = "en-US", value_name = "LOCALE")]
    locale: String,
    /// A Windows time zone id, such as "Pacific Standard Time".
    #[arg(long, default_value = "UTC", value_name = "ZONE")]
    timezone: String,
    #[arg(long, value_enum, default_value_t = Arch::X64)]
    arch: Arch,
    /// Where the machine downloads the agent from, if its image doesn't already have one
    /// (default: the latest GitHub release).
    #[arg(long, value_name = "URL")]
    agent_url: Option<String>,
    /// install: the edition to install, by name ("Windows 11 Pro") or image index.
    #[arg(long, value_name = "NAME|INDEX")]
    edition: Option<String>,
    /// install: a product key. Without one, Setup may ask.
    #[arg(long, value_name = "KEY")]
    product_key: Option<String>,
    /// install: ERASE this disk (usually 0) and partition it for UEFI. Without it, Setup asks
    /// where to install.
    #[arg(long, value_name = "DISK")]
    wipe_disk: Option<u32>,
    /// install: a folder of drivers Setup needs to see the disk, such as the VirtIO storage
    /// driver on the virtio-win ISO (E:\vioscsi\w11\amd64). Repeatable.
    #[arg(long = "driver-path", value_name = "PATH")]
    driver_paths: Vec<String>,
    /// install: skip Windows 11's TPM, Secure Boot, CPU and RAM checks (for VMs without them).
    #[arg(long)]
    bypass_hardware_checks: bool,
    /// Where to write the file (default: autounattend.xml for install, unattend.xml for sysprep).
    #[arg(short, long)]
    output: Option<PathBuf>,
}

/// Everything the file is made from, already validated.
#[derive(Debug, Clone)]
pub(crate) struct Config {
    pub mode: Mode,
    pub arch: Arch,
    pub pending: Pending,
    pub account: String,
    pub password: String,
    pub autologon_count: u32,
    pub computer_name: String,
    pub locale: String,
    pub timezone: String,
    pub agent_url: String,
    pub edition: Option<String>,
    pub product_key: Option<String>,
    pub wipe_disk: Option<u32>,
    pub driver_paths: Vec<String>,
    pub bypass_hardware_checks: bool,
}

/// Unattend command lines are limited to 1024 characters.
const MAX_COMMAND: usize = 1024;
/// pending.json is written in base64 pieces that each fit in one command.
const CHUNK: usize = 700;

pub fn run(args: UnattendArgs) -> Result<i32> {
    if args.mode == Mode::Sysprep {
        let install_only = [
            ("--edition", args.edition.is_some()),
            ("--product-key", args.product_key.is_some()),
            ("--wipe-disk", args.wipe_disk.is_some()),
            ("--driver-path", !args.driver_paths.is_empty()),
            ("--bypass-hardware-checks", args.bypass_hardware_checks),
        ];
        if let Some((flag, _)) = install_only.iter().find(|(_, set)| *set) {
            bail!("{flag} only applies to --mode install");
        }
    }
    let (password, generated) = match &args.autologon_password {
        Some(spec) => (secret_value(spec)?.1, false),
        None => (generate_password(20)?, true),
    };
    let cfg = Config {
        mode: args.mode,
        arch: args.arch,
        pending: args.pending.build(&args.source)?,
        account: args.autologon,
        password,
        autologon_count: args.autologon_count,
        computer_name: args.computer_name,
        locale: args.locale,
        timezone: args.timezone,
        agent_url: args.agent_url.unwrap_or_else(|| {
            format!("https://github.com/guscatalano/Groundhog/releases/latest/download/{}", args.arch.agent_asset())
        }),
        edition: args.edition,
        product_key: args.product_key,
        wipe_disk: args.wipe_disk,
        driver_paths: args.driver_paths,
        bypass_hardware_checks: args.bypass_hardware_checks,
    };
    let xml = render(&cfg)?;
    let output = args
        .output
        .unwrap_or_else(|| PathBuf::from(if cfg.mode == Mode::Install { "autounattend.xml" } else { "unattend.xml" }));
    std::fs::write(&output, xml).with_context(|| format!("writing {}", output.display()))?;

    println!("wrote {}", output.display());
    println!("  account {} logs on automatically up to {} times", cfg.account, cfg.autologon_count);
    if generated {
        println!("  its password was generated: {} (recoverable from the file)", cfg.password);
    }
    if let Some(disk) = cfg.wipe_disk {
        println!("  WARNING: Setup will erase disk {disk} without asking");
    }
    if !cfg.pending.secrets.is_empty() {
        println!("  the file carries secrets: keep it (and any media it's on) private");
    }
    match cfg.mode {
        Mode::Install => println!("  put it at the root of the install media as autounattend.xml"),
        Mode::Sysprep => {
            println!("  seal the template with: sysprep /generalize /oobe /shutdown /unattend:<this file>")
        }
    }
    Ok(0)
}

pub(crate) fn validate(cfg: &Config) -> Result<()> {
    let bad_name = |n: &str| {
        n.is_empty()
            || n.len() > 20
            || n.contains(['"', '/', '\\', '[', ']', ':', ';', '|', '=', ',', '+', '*', '?', '<', '>', '@'])
    };
    if bad_name(&cfg.account) {
        bail!("'{}' is not a valid local account name", cfg.account);
    }
    if cfg.computer_name != "*"
        && (cfg.computer_name.is_empty()
            || cfg.computer_name.len() > 15
            || !cfg.computer_name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
    {
        bail!("computer name '{}' must be '*' or up to 15 letters, digits and hyphens", cfg.computer_name);
    }
    if cfg.autologon_count == 0 {
        bail!("--autologon-count must be at least 1, or the agent never runs");
    }
    Ok(())
}

/// Passwords in unattend files are "hidden" by appending the element name and base64-encoding
/// the UTF-16 text. That's obfuscation, not encryption: anyone with the file can reverse it.
fn hide_password(password: &str) -> String {
    let bytes: Vec<u8> = format!("{password}Password").encode_utf16().flat_map(u16::to_le_bytes).collect();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// A PowerShell command line that needs no quoting inside the script (which uses ' only).
fn ps(script: &str) -> String {
    format!("powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"{script}\"")
}

fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// The first-logon commands: install the agent, write pending.json, register the logon task
/// (so runs continue after restarts) and start it now.
pub(crate) fn first_logon_commands(cfg: &Config) -> Result<Vec<(String, String)>> {
    let home = "($env:ProgramData+'\\groundhog')";
    let mut cmds = vec![
        (
            "Groundhog: create folders".to_owned(),
            ps(&format!("New-Item -ItemType Directory -Force ({home}+'\\bin') | Out-Null")),
        ),
        (
            "Groundhog: download the agent unless the image has one".to_owned(),
            ps(&format!(
                "$a={home}+'\\bin\\groundhog-agent.exe'; if (-not (Test-Path $a)) {{ $ProgressPreference='SilentlyContinue'; \
                 [Net.ServicePointManager]::SecurityProtocol='Tls12'; Invoke-WebRequest -UseBasicParsing -Uri {} -OutFile $a }}",
                ps_quote(&cfg.agent_url)
            )),
        ),
        (
            "Groundhog: pending.json (1/3)".to_owned(),
            ps(&format!("Remove-Item -ErrorAction SilentlyContinue ({home}+'\\pending.b64'); exit 0")),
        ),
    ];
    let json = serde_json::to_vec(&cfg.pending)?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(json);
    for chunk in b64.as_bytes().chunks(CHUNK) {
        let chunk = std::str::from_utf8(chunk).expect("base64 is ascii");
        cmds.push((
            "Groundhog: pending.json (2/3)".to_owned(),
            ps(&format!("Add-Content -NoNewline -Encoding ASCII -Path ({home}+'\\pending.b64') -Value '{chunk}'")),
        ));
    }
    cmds.push((
        "Groundhog: pending.json (3/3)".to_owned(),
        ps(&format!(
            "$d={home}; [IO.File]::WriteAllBytes($d+'\\pending.json', [Convert]::FromBase64String([IO.File]::ReadAllText($d+'\\pending.b64'))); \
             Remove-Item ($d+'\\pending.b64')"
        )),
    ));
    cmds.push((
        "Groundhog: register the logon task".to_owned(),
        ps(&format!("& ({home}+'\\bin\\groundhog-agent.exe') install-task")),
    ));
    cmds.push(("Groundhog: start applying".to_owned(), "schtasks.exe /Run /TN Groundhog\\RunPending".to_owned()));
    if !cfg.pending.secrets.is_empty() {
        // Setup keeps a copy of this file. It blanks password fields in it, but not the
        // secrets inside our pending.json commands.
        cmds.push((
            "Groundhog: remove Setup's copy of this file (it holds secrets)".to_owned(),
            ps("Remove-Item -Force -ErrorAction SilentlyContinue ($env:WINDIR+'\\Panther\\unattend.xml'),($env:WINDIR+'\\Panther\\Unattend\\unattend.xml'); exit 0"),
        ));
    }
    if let Some((_, long)) = cmds.iter().find(|(_, c)| c.len() > MAX_COMMAND) {
        bail!("a first-logon command is longer than the {MAX_COMMAND} characters Windows allows: {long}");
    }
    Ok(cmds)
}

pub(crate) fn render(cfg: &Config) -> Result<String> {
    validate(cfg)?;
    let arch = cfg.arch.processor();
    let component = |name: &str, body: &str| {
        format!(
            "    <component name=\"{name}\" processorArchitecture=\"{arch}\" publicKeyToken=\"31bf3856ad364e35\" \
             language=\"neutral\" versionScope=\"nonSxS\">\n{body}    </component>\n"
        )
    };
    let locale = esc(&cfg.locale);
    let locales = format!(
        "      <InputLocale>{locale}</InputLocale>\n      <SystemLocale>{locale}</SystemLocale>\n      \
         <UILanguage>{locale}</UILanguage>\n      <UserLocale>{locale}</UserLocale>\n"
    );

    let mut x = String::from(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
         <!-- Generated by groundhog unattend. Passwords below are only obfuscated: keep this file private. -->\n\
         <unattend xmlns=\"urn:schemas-microsoft-com:unattend\" xmlns:wcm=\"http://schemas.microsoft.com/WMIConfig/2002/State\">\n",
    );

    if cfg.mode == Mode::Install {
        x += "  <settings pass=\"windowsPE\">\n";
        x += &component(
            "Microsoft-Windows-International-Core-WinPE",
            &format!(
                "      <SetupUILanguage>\n        <UILanguage>{locale}</UILanguage>\n      </SetupUILanguage>\n{locales}"
            ),
        );
        if !cfg.driver_paths.is_empty() {
            let mut paths = String::from("      <DriverPaths>\n");
            for (i, p) in cfg.driver_paths.iter().enumerate() {
                paths += &format!(
                    "        <PathAndCredentials wcm:action=\"add\" wcm:keyValue=\"{}\">\n          <Path>{}</Path>\n        </PathAndCredentials>\n",
                    i + 1,
                    esc(p)
                );
            }
            paths += "      </DriverPaths>\n";
            x += &component("Microsoft-Windows-PnpCustomizationsWinPE", &paths);
        }

        let mut setup = String::new();
        if cfg.bypass_hardware_checks {
            setup += "      <RunSynchronous>\n";
            for (i, check) in
                ["BypassTPMCheck", "BypassSecureBootCheck", "BypassRAMCheck", "BypassCPUCheck"].iter().enumerate()
            {
                setup += &format!(
                    "        <RunSynchronousCommand wcm:action=\"add\">\n          <Order>{}</Order>\n          \
                     <Path>reg add HKLM\\SYSTEM\\Setup\\LabConfig /v {check} /t REG_DWORD /d 1 /f</Path>\n        </RunSynchronousCommand>\n",
                    i + 1
                );
            }
            setup += "      </RunSynchronous>\n";
        }
        if let Some(disk) = cfg.wipe_disk {
            setup += &format!(
                "      <DiskConfiguration>\n        <Disk wcm:action=\"add\">\n          <DiskID>{disk}</DiskID>\n          <WillWipeDisk>true</WillWipeDisk>\n          <CreatePartitions>\n\
                 \x20           <CreatePartition wcm:action=\"add\"><Order>1</Order><Type>EFI</Type><Size>260</Size></CreatePartition>\n\
                 \x20           <CreatePartition wcm:action=\"add\"><Order>2</Order><Type>MSR</Type><Size>16</Size></CreatePartition>\n\
                 \x20           <CreatePartition wcm:action=\"add\"><Order>3</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition>\n\
                 \x20         </CreatePartitions>\n          <ModifyPartitions>\n\
                 \x20           <ModifyPartition wcm:action=\"add\"><Order>1</Order><PartitionID>1</PartitionID><Format>FAT32</Format><Label>System</Label></ModifyPartition>\n\
                 \x20           <ModifyPartition wcm:action=\"add\"><Order>2</Order><PartitionID>2</PartitionID></ModifyPartition>\n\
                 \x20           <ModifyPartition wcm:action=\"add\"><Order>3</Order><PartitionID>3</PartitionID><Format>NTFS</Format><Label>Windows</Label><Letter>C</Letter></ModifyPartition>\n\
                 \x20         </ModifyPartitions>\n        </Disk>\n      </DiskConfiguration>\n"
            );
        }
        if cfg.edition.is_some() || cfg.wipe_disk.is_some() {
            setup += "      <ImageInstall>\n        <OSImage>\n";
            if let Some(edition) = &cfg.edition {
                let key = if edition.chars().all(|c| c.is_ascii_digit()) { "/IMAGE/INDEX" } else { "/IMAGE/NAME" };
                setup += &format!(
                    "          <InstallFrom>\n            <MetaData wcm:action=\"add\">\n              <Key>{key}</Key>\n              <Value>{}</Value>\n            </MetaData>\n          </InstallFrom>\n",
                    esc(edition)
                );
            }
            if let Some(disk) = cfg.wipe_disk {
                setup += &format!(
                    "          <InstallTo>\n            <DiskID>{disk}</DiskID>\n            <PartitionID>3</PartitionID>\n          </InstallTo>\n"
                );
            }
            setup += "        </OSImage>\n      </ImageInstall>\n";
        }
        setup += "      <UserData>\n        <AcceptEula>true</AcceptEula>\n";
        if let Some(key) = &cfg.product_key {
            setup += &format!(
                "        <ProductKey>\n          <Key>{}</Key>\n          <WillShowUI>OnError</WillShowUI>\n        </ProductKey>\n",
                esc(key)
            );
        }
        setup += "      </UserData>\n";
        x += &component("Microsoft-Windows-Setup", &setup);
        x += "  </settings>\n";
    }

    x += "  <settings pass=\"specialize\">\n";
    x += &component(
        "Microsoft-Windows-Shell-Setup",
        &format!(
            "      <ComputerName>{}</ComputerName>\n      <TimeZone>{}</TimeZone>\n",
            esc(&cfg.computer_name),
            esc(&cfg.timezone)
        ),
    );
    x += "  </settings>\n";

    x += "  <settings pass=\"oobeSystem\">\n";
    x += &component("Microsoft-Windows-International-Core", &locales);
    let hidden = hide_password(&cfg.password);
    let account = esc(&cfg.account);
    let mut shell = format!(
        "      <OOBE>\n        <HideEULAPage>true</HideEULAPage>\n        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>\n        \
         <HideOnlineAccountScreens>true</HideOnlineAccountScreens>\n        <HideLocalAccountScreen>true</HideLocalAccountScreen>\n        \
         <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>\n        <ProtectYourPC>3</ProtectYourPC>\n      </OOBE>\n      \
         <UserAccounts>\n        <LocalAccounts>\n          <LocalAccount wcm:action=\"add\">\n            <Name>{account}</Name>\n            \
         <DisplayName>{account}</DisplayName>\n            <Group>Administrators</Group>\n            <Password>\n              \
         <Value>{hidden}</Value>\n              <PlainText>false</PlainText>\n            </Password>\n          </LocalAccount>\n        \
         </LocalAccounts>\n      </UserAccounts>\n      <AutoLogon>\n        <Enabled>true</Enabled>\n        <LogonCount>{}</LogonCount>\n        \
         <Username>{account}</Username>\n        <Password>\n          <Value>{hidden}</Value>\n          <PlainText>false</PlainText>\n        \
         </Password>\n      </AutoLogon>\n      <FirstLogonCommands>\n",
        cfg.autologon_count
    );
    for (i, (description, command)) in first_logon_commands(cfg)?.iter().enumerate() {
        shell += &format!(
            "        <SynchronousCommand wcm:action=\"add\">\n          <Order>{}</Order>\n          <CommandLine>{}</CommandLine>\n          \
             <Description>{}</Description>\n          <RequiresUserInput>false</RequiresUserInput>\n        </SynchronousCommand>\n",
            i + 1,
            esc(command),
            esc(description)
        );
    }
    shell += "      </FirstLogonCommands>\n";
    x += &component("Microsoft-Windows-Shell-Setup", &shell);
    x += "  </settings>\n</unattend>\n";
    Ok(x)
}

/// A random password with upper and lower case letters, digits and symbols, from the OS's
/// secure random generator.
fn generate_password(len: usize) -> Result<String> {
    const SETS: [&[u8]; 4] = [b"ABCDEFGHJKLMNPQRSTUVWXYZ", b"abcdefghijkmnopqrstuvwxyz", b"23456789", b"!#%+-=?@^_"];
    let len = len.max(SETS.len());
    let mut rnd = vec![0u8; len * 2];
    getrandom::fill(&mut rnd).map_err(|e| anyhow::anyhow!("random generator: {e}"))?;
    let all: Vec<u8> = SETS.concat();
    let mut chars: Vec<u8> = SETS.iter().zip(&rnd).map(|(set, r)| set[*r as usize % set.len()]).collect();
    chars.extend((SETS.len()..len).map(|i| all[rnd[i] as usize % all.len()]));
    for i in (1..len).rev() {
        chars.swap(i, rnd[len + i] as usize % (i + 1));
    }
    Ok(String::from_utf8(chars).expect("ascii"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(mode: Mode) -> Config {
        Config {
            mode,
            arch: Arch::X64,
            pending: Pending {
                source: "https://cfg.test/dev.groundhog.yaml?a=1&b=2".into(),
                secrets: [("TESTER_PASSWORD".to_owned(), "s3cret & <x>".to_owned())].into(),
                allow_reboot: true,
                ..Pending::default()
            },
            account: "provisioner".into(),
            password: "Pa55word!".into(),
            autologon_count: 5,
            computer_name: "*".into(),
            locale: "en-US".into(),
            timezone: "UTC".into(),
            agent_url: "https://github.com/guscatalano/Groundhog/releases/latest/download/groundhog-agent-x64.exe"
                .into(),
            edition: Some("Windows 11 Pro".into()),
            product_key: None,
            wipe_disk: Some(0),
            driver_paths: vec![r"E:\vioscsi\w11\amd64".into()],
            bypass_hardware_checks: true,
        }
    }

    fn passes(xml: &str) -> Vec<String> {
        let doc = roxmltree::Document::parse(xml).expect("well-formed XML");
        doc.descendants()
            .filter(|n| n.has_tag_name("settings"))
            .map(|n| n.attribute("pass").unwrap().to_owned())
            .collect()
    }

    #[test]
    fn install_mode_has_setup_and_sysprep_mode_does_not() {
        let install = render(&config(Mode::Install)).unwrap();
        assert_eq!(passes(&install), ["windowsPE", "specialize", "oobeSystem"]);
        assert!(install.contains("<WillWipeDisk>true</WillWipeDisk>"));
        assert!(install.contains("<Value>Windows 11 Pro</Value>"));
        assert!(install.contains(r"<Path>E:\vioscsi\w11\amd64</Path>"));
        assert!(install.contains("BypassTPMCheck"));

        let sysprep = render(&Config {
            edition: None,
            wipe_disk: None,
            driver_paths: vec![],
            bypass_hardware_checks: false,
            ..config(Mode::Sysprep)
        })
        .unwrap();
        assert_eq!(passes(&sysprep), ["specialize", "oobeSystem"]);
        assert!(!sysprep.contains("WillWipeDisk"));
    }

    #[test]
    fn the_disk_is_only_wiped_when_asked() {
        let xml = render(&Config { wipe_disk: None, ..config(Mode::Install) }).unwrap();
        assert!(!xml.contains("DiskConfiguration") && !xml.contains("InstallTo"));
    }

    #[test]
    fn passwords_use_the_unattend_encoding() {
        let decoded = base64::engine::general_purpose::STANDARD.decode(hide_password("Pa55word!")).unwrap();
        let text = String::from_utf16(&decoded.chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<_>>())
            .unwrap();
        assert_eq!(text, "Pa55word!Password");
        assert!(!render(&config(Mode::Install)).unwrap().contains("Pa55word!"));
    }

    #[test]
    fn pending_json_survives_the_trip_through_first_logon_commands() {
        let cfg = config(Mode::Sysprep);
        let xml = render(&Config {
            edition: None,
            wipe_disk: None,
            driver_paths: vec![],
            bypass_hardware_checks: false,
            ..cfg.clone()
        })
        .unwrap();
        let doc = roxmltree::Document::parse(&xml).unwrap();
        let commands: Vec<String> =
            doc.descendants().filter(|n| n.has_tag_name("CommandLine")).map(|n| n.text().unwrap().to_owned()).collect();
        assert!(commands.iter().all(|c| c.len() <= MAX_COMMAND));
        let b64: String = commands
            .iter()
            .filter_map(|c| c.split("-Value '").nth(1).and_then(|rest| rest.split('\'').next()))
            .collect();
        let json = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
        let back: Pending = serde_json::from_slice(&json).unwrap();
        assert_eq!(back, cfg.pending);
        assert!(commands.last().unwrap().contains("Panther"), "secrets present: Setup's copy is removed");
    }

    #[test]
    fn a_large_pending_json_is_split_into_many_commands() {
        let mut cfg = config(Mode::Sysprep);
        cfg.pending.cache = (0..60).map(|i| format!(r"\\nas-{i}\groundhog-cache")).collect();
        let cmds = first_logon_commands(&cfg).unwrap();
        assert!(cmds.iter().filter(|(d, _)| d.contains("(2/3)")).count() > 2);
        assert!(cmds.iter().all(|(_, c)| c.len() <= MAX_COMMAND));
    }

    #[test]
    fn rejects_bad_names() {
        let err =
            render(&Config { computer_name: "this-name-is-way-too-long".into(), ..config(Mode::Sysprep) }).unwrap_err();
        assert!(err.to_string().contains("computer name"));
        assert!(render(&Config { account: "a/b".into(), ..config(Mode::Sysprep) }).is_err());
    }

    #[test]
    fn generated_passwords_are_complex() {
        let p = generate_password(20).unwrap();
        assert_eq!(p.len(), 20);
        assert!(p.chars().any(|c| c.is_ascii_uppercase()) && p.chars().any(|c| c.is_ascii_digit()));
    }
}
