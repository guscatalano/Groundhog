//! Carrying out steps on this machine.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use groundhog_core::content::ContentStore;
use groundhog_core::engine::{Action, Executor, Outcome, Step};
use groundhog_core::fetch::{file_name, file_url_to_path};
use groundhog_core::model::{App, FileCopy, HiveScope, RegistryData, RegistryType, RegistryValue, RunAction, Shell};
use groundhog_core::plugin::{PROTOCOL_VERSION, PluginRequest, PluginResponse};
use groundhog_core::report::Reporter;
use groundhog_win::env;
use groundhog_win::process::Proc;
use groundhog_win::registry::{self, Data, DefaultUserHive};
use groundhog_win::winget::{self, codes};
use url::Url;

/// Windows Installer and common convention: success, restart required.
const EXIT_REBOOT_REQUIRED: i32 = 3010;
/// Windows Installer: success, restart already initiated.
const EXIT_REBOOT_INITIATED: i32 = 1641;
/// Windows Installer: another installation is in progress.
const EXIT_INSTALL_IN_PROGRESS: i32 = 1618;

const WINGET_BOOTSTRAP: &str = r#"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module -Name Microsoft.WinGet.Client -Repository PSGallery -Scope AllUsers -Force | Out-Null
Repair-WinGetPackageManager -AllUsers -Latest -Force
"#;

pub struct WinExecutor<'a> {
    content: &'a ContentStore<'a>,
    work_dir: PathBuf,
    winget: Option<PathBuf>,
}

impl<'a> WinExecutor<'a> {
    pub fn new(content: &'a ContentStore<'a>, work_dir: PathBuf) -> Self {
        Self { content, work_dir, winget: None }
    }
}

impl Executor for WinExecutor<'_> {
    fn execute(&mut self, step: &Step, reporter: &dyn Reporter) -> Result<Outcome> {
        let log = &mut |line: &str| reporter.log(&format!("    {line}"));
        match &step.action {
            Action::EnsureWinget => self.ensure_winget(log),
            Action::App(App::Winget { id, version, args }) => {
                self.winget_install(id, version.as_deref(), args.as_deref(), log)
            }
            Action::App(App::Url { url, sha256, args, .. }) => {
                self.url_install(url, sha256.as_deref(), args.as_deref(), log)
            }
            Action::File(f) => self.copy(f, log),
            Action::Env { name, value } => {
                let changed = env::set_user_var(name, value)?;
                if changed {
                    env::broadcast_change();
                }
                Ok(Outcome::Done { changed })
            }
            Action::Path { dir } => {
                let changed = env::add_user_path(dir)?;
                if changed {
                    env::broadcast_change();
                }
                Ok(Outcome::Done { changed })
            }
            Action::Registry(r) => set_registry(r),
            Action::Run(r) => self.run_action(r, log),
        }
    }
}

impl WinExecutor<'_> {
    /// Fetches content (cache first when pinned) into `work/<kind>/<hash>/<name>`.
    fn download(&self, kind: &str, url: &Url, sha256: Option<&str>, log: &mut dyn FnMut(&str)) -> Result<PathBuf> {
        if sha256.is_none() && url.scheme() != "file" {
            log(&format!("warning: {url} is not pinned with sha256"));
        }
        let fetched = self.content.get(url, sha256)?;
        if fetched.from_cache {
            log("using cached copy");
        }
        let dir = self.work_dir.join(kind).join(&fetched.sha256[..16]);
        let path = dir.join(file_name(url));
        if !path.is_file() {
            std::fs::create_dir_all(&dir)?;
            std::fs::write(&path, &fetched.bytes).with_context(|| format!("writing {}", path.display()))?;
        }
        Ok(path)
    }

    fn winget(&self) -> Result<&Path> {
        self.winget.as_deref().context("winget is not available")
    }

    fn ensure_winget(&mut self, log: &mut dyn FnMut(&str)) -> Result<Outcome> {
        if let Some(path) = winget::locate() {
            self.winget = Some(path);
            return Ok(Outcome::Done { changed: false });
        }
        log("winget not found; installing it from PowerShell Gallery (Microsoft.WinGet.Client)");
        check_exit(powershell(Shell::Powershell, WINGET_BOOTSTRAP).run(log)?.code, "winget bootstrap")?;
        self.winget = Some(winget::locate().context("winget still not found after bootstrap")?);
        Ok(Outcome::Done { changed: true })
    }

    fn winget_install(
        &mut self,
        id: &str,
        version: Option<&str>,
        args: Option<&str>,
        log: &mut dyn FnMut(&str),
    ) -> Result<Outcome> {
        let winget = self.winget()?.to_path_buf();
        let common = ["--id", id, "--exact", "--accept-source-agreements", "--disable-interactivity"];

        let listed = Proc::new(&winget).args(["list"]).args(common).run(&mut |_| {})?;
        if listed.code == 0 {
            log("already installed");
            return Ok(Outcome::Done { changed: false });
        }

        let mut install =
            Proc::new(&winget).args(["install"]).args(common).args(["--silent", "--accept-package-agreements"]);
        if let Some(v) = version {
            install = install.args(["--version", v]);
        }
        let code = install.raw(args).run(log)?.code;
        match code {
            0 => Ok(Outcome::Done { changed: true }),
            codes::PACKAGE_ALREADY_INSTALLED | codes::INSTALL_ALREADY_INSTALLED | codes::UPDATE_NOT_APPLICABLE => {
                Ok(Outcome::Done { changed: false })
            }
            codes::INSTALL_REBOOT_REQUIRED_TO_FINISH | codes::INSTALL_REBOOT_INITIATED => Ok(Outcome::RebootRequired),
            codes::INSTALL_REBOOT_REQUIRED_FOR_INSTALL => Ok(Outcome::RetryAfterReboot),
            codes::NO_APPLICATIONS_FOUND => bail!("no winget package with id '{id}'"),
            other => bail!("winget install failed with {other:#010X}"),
        }
    }

    fn url_install(
        &mut self,
        url: &Url,
        sha256: Option<&str>,
        args: Option<&str>,
        log: &mut dyn FnMut(&str),
    ) -> Result<Outcome> {
        let installer = self.download("downloads", url, sha256, log)?;
        let path = installer.to_string_lossy().into_owned();
        let ext = installer.extension().and_then(|e| e.to_str()).unwrap_or_default().to_ascii_lowercase();
        let proc = match ext.as_str() {
            "msi" => Proc::new("msiexec.exe").args(["/i", path.as_str(), "/qn", "/norestart"]).raw(args),
            "msix" | "msixbundle" | "appx" | "appxbundle" => {
                powershell(Shell::Powershell, &format!("Add-AppxPackage -Path '{}'", path.replace('\'', "''")))
            }
            "exe" => Proc::new(&installer).raw(args),
            other => bail!("don't know how to install '.{other}' files (supported: msi, msix, appx, exe)"),
        };
        match proc.run(log)?.code {
            0 => Ok(Outcome::Done { changed: true }),
            EXIT_REBOOT_REQUIRED | EXIT_REBOOT_INITIATED => Ok(Outcome::RebootRequired),
            EXIT_INSTALL_IN_PROGRESS => bail!("another installation is in progress (1618); run again when it finishes"),
            code => bail!("installer exited with {code}"),
        }
    }

    fn copy(&mut self, f: &FileCopy, log: &mut dyn FnMut(&str)) -> Result<Outcome> {
        let dest = PathBuf::from(env::expand_path(&f.to)?);
        if f.from.scheme() == "file" {
            let src = file_url_to_path(&f.from)?;
            if src.is_dir() {
                return Ok(Outcome::Done { changed: copy_dir(&src, &dest)? });
            }
        }
        let bytes = self.content.get(&f.from, f.sha256.as_deref())?.bytes;
        let changed = write_if_different(&dest, &bytes)?;
        if changed {
            log(&format!("wrote {}", dest.display()));
        }
        Ok(Outcome::Done { changed })
    }

    fn run_action(&mut self, action: &RunAction, log: &mut dyn FnMut(&str)) -> Result<Outcome> {
        match action {
            RunAction::Command { command, shell } => {
                let proc = match shell {
                    Shell::Powershell | Shell::Pwsh => powershell(*shell, command),
                    Shell::Cmd => Proc::new("cmd.exe").args(["/d", "/s", "/c"]).raw(Some(&format!("\"{command}\""))),
                    Shell::Direct => bail!("'shell: direct' only applies to scripts"),
                };
                exit_to_outcome(proc.run(log)?.code, "command")
            }
            RunAction::Script { script, sha256, args, shell } => {
                let path = self.download("scripts", script, sha256.as_deref(), log)?;
                let shell = match shell {
                    Some(s) => *s,
                    None => shell_for(&path)?,
                };
                let p = path.to_string_lossy().into_owned();
                let mut proc = match shell {
                    Shell::Powershell | Shell::Pwsh => Proc::new(ps_exe(shell))
                        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", p.as_str()])
                        .raw(args.as_deref()),
                    Shell::Cmd => Proc::new("cmd.exe")
                        .args(["/d", "/s", "/c"])
                        .raw(Some(&format!("\"\"{p}\" {}\"", args.as_deref().unwrap_or_default()))),
                    Shell::Direct => Proc::new(&path).raw(args.as_deref()),
                };
                proc.cwd = path.parent().map(Path::to_path_buf);
                exit_to_outcome(proc.run(log)?.code, "script")
            }
            RunAction::Plugin { plugin, sha256, with } => {
                let exe = self.download("plugins", plugin, sha256.as_deref(), log)?;
                let scratch = self.work_dir.join("plugin-scratch");
                std::fs::create_dir_all(&scratch)?;
                let request = PluginRequest {
                    protocol: PROTOCOL_VERSION,
                    action: "apply".into(),
                    with: with.clone(),
                    work_dir: scratch.to_string_lossy().into_owned(),
                };
                let proc = Proc { stdin: Some(serde_json::to_vec(&request)?), capture_stdout: true, ..Proc::new(&exe) };
                let out = proc.run(log)?;
                let response: PluginResponse = serde_json::from_str(out.stdout.trim()).with_context(|| {
                    format!("plugin exited with {} and did not answer with valid JSON on stdout", out.code)
                })?;
                if !response.ok {
                    bail!("plugin failed: {}", response.message.unwrap_or_else(|| format!("exit code {}", out.code)));
                }
                Ok(if response.reboot_required {
                    Outcome::RebootRequired
                } else {
                    Outcome::Done { changed: response.changed }
                })
            }
        }
    }
}

fn set_registry(r: &RegistryValue) -> Result<Outcome> {
    let data = match (&r.data, r.kind) {
        (RegistryData::String(s), RegistryType::ExpandString) => Data::ExpandString(s),
        (RegistryData::String(s), _) => Data::String(s),
        (RegistryData::MultiString(v), _) => Data::MultiString(v),
        (RegistryData::Dword(n), _) => Data::Dword(*n),
        (RegistryData::Qword(n), _) => Data::Qword(*n),
    };
    let (root, sub) = registry::split_key(&r.key)?;
    let mut changed = false;
    for scope in &r.scope {
        changed |= match scope {
            HiveScope::CurrentUser => registry::set_value(&root, &sub, r.name.as_deref(), &data)?,
            HiveScope::DefaultUser => {
                let hive = DefaultUserHive::load()?;
                registry::set_value(hive.root(), &sub, r.name.as_deref(), &data)?
            }
        };
    }
    Ok(Outcome::Done { changed })
}

fn ps_exe(shell: Shell) -> &'static str {
    if shell == Shell::Pwsh { "pwsh.exe" } else { "powershell.exe" }
}

/// Runs an inline PowerShell command via `-EncodedCommand`, which sidesteps every quoting
/// problem a command line can have.
fn powershell(shell: Shell, command: &str) -> Proc {
    // Progress records would otherwise reach stderr as CLIXML noise.
    let command = format!(
        "$ProgressPreference = 'SilentlyContinue'
{command}"
    );
    let utf16: Vec<u8> = command.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);
    Proc::new(ps_exe(shell)).args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-OutputFormat",
        "Text",
        "-EncodedCommand",
        encoded.as_str(),
    ])
}

fn shell_for(path: &Path) -> Result<Shell> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or_default().to_ascii_lowercase();
    Ok(match ext.as_str() {
        "ps1" => Shell::Powershell,
        "cmd" | "bat" => Shell::Cmd,
        "exe" => Shell::Direct,
        other => bail!("cannot tell how to run '.{other}' scripts; set 'shell'"),
    })
}

/// Commands and scripts: 0 is success, 3010 asks for a restart, anything else fails.
fn exit_to_outcome(code: i32, what: &str) -> Result<Outcome> {
    match code {
        0 => Ok(Outcome::Done { changed: true }),
        EXIT_REBOOT_REQUIRED => Ok(Outcome::RebootRequired),
        _ => bail!("{what} exited with {code}"),
    }
}

fn check_exit(code: i32, what: &str) -> Result<()> {
    if code != 0 {
        bail!("{what} exited with {code}");
    }
    Ok(())
}

fn write_if_different(dest: &Path, bytes: &[u8]) -> Result<bool> {
    if std::fs::read(dest).is_ok_and(|current| current == bytes) {
        return Ok(false);
    }
    let dir = dest.parent().context("destination has no parent directory")?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let tmp = dest.with_extension("groundhog.tmp");
    std::fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, dest).with_context(|| format!("replacing {}", dest.display()))?;
    Ok(true)
}

fn copy_dir(src: &Path, dest: &Path) -> Result<bool> {
    let mut changed = false;
    for entry in std::fs::read_dir(src).with_context(|| format!("reading {}", src.display()))? {
        let entry = entry?;
        let target = dest.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            changed |= copy_dir(&entry.path(), &target)?;
        } else {
            changed |= write_if_different(&target, &std::fs::read(entry.path())?)?;
        }
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_directories_idempotently() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("a.txt"), "a").unwrap();
        std::fs::write(src.join("sub").join("b.txt"), "b").unwrap();
        let dest = dir.path().join("dest");

        assert!(copy_dir(&src, &dest).unwrap());
        assert!(!copy_dir(&src, &dest).unwrap());
        assert_eq!(std::fs::read_to_string(dest.join("sub").join("b.txt")).unwrap(), "b");
    }

    #[test]
    fn inline_powershell_survives_quotes() {
        let mut lines = Vec::new();
        let code = powershell(Shell::Powershell, r#"Write-Output "it's ""quoted"" & fine""#)
            .run(&mut |l| lines.push(l.to_owned()))
            .unwrap()
            .code;
        assert_eq!(code, 0);
        assert_eq!(lines, [r#"it's "quoted" & fine"#]);
    }

    #[test]
    fn exit_codes_map_to_outcomes() {
        assert!(matches!(exit_to_outcome(0, "x").unwrap(), Outcome::Done { changed: true }));
        assert!(matches!(exit_to_outcome(3010, "x").unwrap(), Outcome::RebootRequired));
        assert!(exit_to_outcome(1, "x").is_err());
    }
}
