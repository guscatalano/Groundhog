//! Carrying out steps on this machine.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use groundhog_core::archive;
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
    /// When this apply started, for checks that only look at what happened since.
    started: SystemTime,
}

impl<'a> WinExecutor<'a> {
    pub fn new(content: &'a ContentStore<'a>, work_dir: PathBuf) -> Self {
        Self { content, work_dir, winget: None, started: SystemTime::now() }
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
            Action::App(App::Url { url, sha256, resolved, args, .. }) => {
                self.url_install(url, sha256.as_deref().or(resolved.as_deref()), args.as_deref(), log)
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
            Action::Verify(c) => {
                crate::checks::run(c, self.started, log)?;
                Ok(Outcome::Done { changed: false })
            }
        }
    }
}

impl WinExecutor<'_> {
    /// Fetches content into `work/<kind>/<hash>/<name>`. `sha256` is the user's pin or, for
    /// unpinned references, the hash resolved at load time. Either way the bytes must match,
    /// so a "latest" URL that moves on mid-run fails instead of installing a different build.
    fn download(&self, kind: &str, url: &Url, sha256: Option<&str>, log: &mut dyn FnMut(&str)) -> Result<PathBuf> {
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
        let bytes = self.content.get(&f.from, f.sha256.as_deref().or(f.resolved.as_deref()))?.bytes;
        if f.extract {
            replace_with_zip(&bytes, &dest)?;
            log(&format!("unpacked into {}", dest.display()));
            return Ok(Outcome::Done { changed: true });
        }
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
            RunAction::Script { script, sha256, resolved, args, shell } => {
                let path = self.download("scripts", script, sha256.as_deref().or(resolved.as_deref()), log)?;
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
            RunAction::Plugin { plugin, sha256, resolved, with } => {
                let exe = self.download("plugins", plugin, sha256.as_deref().or(resolved.as_deref()), log)?;
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
///
/// PowerShell reduces any failure to exit code 1, which would hide a native program's 3010
/// ("restart required"). So when the last statement failed and it was a native program, its
/// own exit code is passed through. A success that merely left a non-zero `$LASTEXITCODE`
/// behind (robocopy, say) still exits 0, as it did before.
pub(crate) fn powershell(shell: Shell, command: &str) -> Proc {
    let script = format!(
        "$ProgressPreference = 'SilentlyContinue'\n\
         $global:LASTEXITCODE = 0\n\
         {command}\n\
         if (-not $?) {{ if ($LASTEXITCODE) {{ exit $LASTEXITCODE }} else {{ exit 1 }} }}\n\
         exit 0\n"
    );
    let utf16: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
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

/// Unpacks a zip into `dest`, replacing its previous contents as a whole: files the new
/// archive no longer has disappear, and a failure never leaves a half-unpacked folder.
///
/// The archive is unpacked next to `dest` first, then swapped in with two renames. Windows
/// allows the rename even while a program runs from the old folder; that program keeps
/// running from the renamed copy, which is removed once nothing holds it (on this run or a
/// later one). The rename fails only when a file inside is open without delete sharing, and
/// then nothing has changed.
fn replace_with_zip(bytes: &[u8], dest: &Path) -> Result<()> {
    let name = dest.file_name().context("destination has no folder name")?.to_string_lossy().into_owned();
    let sibling = |suffix: &str| dest.with_file_name(format!("{name}{suffix}"));
    let staging = sibling(".groundhog-new");
    let stamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_millis());
    let old = sibling(&format!(".groundhog-old-{stamp}"));

    remove_old_copies(dest, &name);
    if staging.exists() {
        std::fs::remove_dir_all(&staging).with_context(|| format!("removing leftover {}", staging.display()))?;
    }
    std::fs::create_dir_all(&staging).with_context(|| format!("creating {}", staging.display()))?;
    if let Err(e) = archive::unzip(bytes, &staging) {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(e);
    }

    if dest.exists()
        && let Err(e) = std::fs::rename(dest, &old)
    {
        let _ = std::fs::remove_dir_all(&staging);
        bail!("cannot replace {}: {e}. A program has a file in it open; stop it first", dest.display());
    }
    if let Err(e) = std::fs::rename(&staging, dest) {
        let _ = std::fs::rename(&old, dest);
        bail!("moving the new contents into {}: {e}", dest.display());
    }
    remove_old_copies(dest, &name);
    Ok(())
}

/// Best effort: previous versions set aside by [`replace_with_zip`] that nothing uses anymore.
fn remove_old_copies(dest: &Path, name: &str) {
    let Some(parent) = dest.parent() else { return };
    let Ok(entries) = std::fs::read_dir(parent) else { return };
    let prefix = format!("{name}.groundhog-old");
    for entry in entries.filter_map(Result::ok) {
        if entry.file_name().to_string_lossy().starts_with(&prefix) {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
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
    fn replacing_a_folder_drops_stale_files_and_survives_a_running_program() {
        let zip = |files: &[(&str, &str)]| {
            use std::io::Write;
            let mut bytes = Vec::new();
            let mut z = zip::ZipWriter::new(std::io::Cursor::new(&mut bytes));
            for (name, body) in files {
                z.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
                z.write_all(body.as_bytes()).unwrap();
            }
            z.finish().unwrap();
            bytes
        };
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("app");
        replace_with_zip(&zip(&[("a.txt", "1"), ("sub/stale.txt", "x")]), &dest).unwrap();
        replace_with_zip(&zip(&[("a.txt", "2")]), &dest).unwrap();
        assert_eq!(std::fs::read_to_string(dest.join("a.txt")).unwrap(), "2");
        assert!(!dest.join("sub").exists(), "files the new archive lacks are gone");

        // A program running from the folder doesn't block an update, even twice in a row.
        std::fs::copy(r"C:\Windows\System32\cmd.exe", dest.join("holder.exe")).unwrap();
        let mut holder = std::process::Command::new(dest.join("holder.exe"))
            .args(["/c", "ping -n 3 127.0.0.1 >nul"])
            .spawn()
            .unwrap();
        replace_with_zip(&zip(&[("a.txt", "3")]), &dest).unwrap();
        replace_with_zip(&zip(&[("a.txt", "4")]), &dest).unwrap();
        assert_eq!(std::fs::read_to_string(dest.join("a.txt")).unwrap(), "4");
        holder.wait().unwrap();

        // Once nothing holds the old copy, the next update cleans it up.
        replace_with_zip(&zip(&[("a.txt", "5")]), &dest).unwrap();
        let names: Vec<_> = std::fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, ["app"], "no leftovers");
    }

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
    fn inline_powershell_passes_native_exit_codes_through() {
        let code = |cmd: &str| powershell(Shell::Powershell, cmd).run(&mut |_| {}).unwrap().code;
        assert_eq!(code("cmd /c exit 3010"), 3010, "a failing native program keeps its code");
        assert_eq!(code("powershell -NoProfile -Command 'exit 7'"), 7);
        assert_eq!(code("cmd /c exit 1; Write-Output done"), 0, "a later success still succeeds");
        assert_eq!(code("Get-Item C:/does-not-exist-groundhog"), 1, "a failing cmdlet is 1");
        assert_eq!(code("throw 'boom'"), 1);
        assert_eq!(code("exit 5"), 5, "an explicit exit wins");
        assert_eq!(code("Write-Output ok"), 0);
    }

    #[test]
    fn exit_codes_map_to_outcomes() {
        assert!(matches!(exit_to_outcome(0, "x").unwrap(), Outcome::Done { changed: true }));
        assert!(matches!(exit_to_outcome(3010, "x").unwrap(), Outcome::RebootRequired));
        assert!(exit_to_outcome(1, "x").is_err());
    }
}
