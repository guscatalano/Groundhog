//! Carrying out steps on this machine.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use groundhog_core::archive;
use groundhog_core::content::ContentStore;
use groundhog_core::engine::{Action, Executor, Outcome, Probe, Step};
use groundhog_core::fetch::{file_name, file_url_to_path};
use groundhog_core::model::{
    App, Capability, Certificate, DesktopShortcut, EnvScope, Feature, FileCopy, HiveScope, LanguageSetting, LockScreen,
    Password, RegistryData, RegistryType, RegistryValue, RunAction, ScreenSaver, Shell, StartPins, Theme, ThemeMode,
    User, Wallpaper, WallpaperStyle,
};
use groundhog_core::plugin::{PROTOCOL_VERSION, PluginRequest, PluginResponse};
use groundhog_core::report::Reporter;
use groundhog_core::secret::{self, Part};
use groundhog_win::dism::{self, DismError};
use groundhog_win::process::Proc;
use groundhog_win::registry::{self, Data, DefaultUserHive};
use groundhog_win::winget::{self, codes};
use groundhog_win::{accounts, desktop, env, gpo};
use url::Url;

use crate::secrets::Secrets;

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
    secrets: crate::secrets::Secrets,
    /// Opened on first use: only needed for features and capabilities.
    dism: Option<dism::Session>,
    /// A servicing step in this run finished "after a restart", so Windows now reports a
    /// pending restart of our own making. The rest of the section carries on regardless.
    deferred_restart: bool,
}

impl<'a> WinExecutor<'a> {
    pub fn new(content: &'a ContentStore<'a>, work_dir: PathBuf, secrets: crate::secrets::Secrets) -> Self {
        Self {
            content,
            work_dir,
            winget: None,
            started: SystemTime::now(),
            secrets,
            dism: None,
            deferred_restart: false,
        }
    }
}

impl Executor for WinExecutor<'_> {
    fn execute(&mut self, step: &Step, reporter: &dyn Reporter) -> Result<Outcome> {
        let log = &mut |line: &str| reporter.log(&format!("    {line}"));
        // Pick up PATH changes earlier steps' installers made (they change the registry only).
        env::refresh_process_path();
        match &step.action {
            Action::EnsureWinget => self.ensure_winget(log),
            Action::App(App::Winget { id, version, args, timeout_ms, upgrade, state }) => {
                let want = WingetWant { version: version.as_deref(), upgrade: *upgrade, present: state.is_present() };
                self.winget_app(id, want, args.as_deref(), *timeout_ms, log)
            }
            Action::App(App::Url { url, sha256, resolved, args, timeout_ms, .. }) => {
                self.url_install(url, sha256.as_deref().or(resolved.as_deref()), args.as_deref(), *timeout_ms, log)
            }
            Action::File(f) => self.copy(f, log),
            Action::Env { name, value, scope, state } => {
                let changed = if state.is_present() {
                    env::set_var(env_scope(*scope), name, &fill(&self.secrets, value)?)?
                } else {
                    env::remove_var(env_scope(*scope), name)?
                };
                if changed {
                    env::broadcast_change();
                }
                Ok(Outcome::Done { changed })
            }
            Action::Path { dir, scope, state } => {
                let changed = if state.is_present() {
                    env::add_path(env_scope(*scope), dir)?
                } else {
                    env::remove_path(env_scope(*scope), dir)?
                };
                if changed {
                    env::broadcast_change();
                }
                Ok(Outcome::Done { changed })
            }
            Action::Registry(r) if !r.state.is_present() => delete_registry(r),
            Action::Registry(r) => set_registry(&fill_registry(&self.secrets, r)?),
            Action::Run(r) => self.run_action(r, log),
            Action::User(u) if !u.state.is_present() => {
                if !accounts::user_exists(&u.name)? {
                    return Ok(Outcome::Done { changed: false });
                }
                accounts::delete_user(&u.name)?;
                log(&format!("deleted {}", u.name));
                Ok(Outcome::Done { changed: true })
            }
            Action::User(u) => self.ensure_user(u, log),
            Action::Certificate(c) => self.certificate(c, false, log).map(|changed| Outcome::Done { changed }),
            Action::Service(s) => crate::ensure::service(s, false, log).map(|changed| Outcome::Done { changed }),
            Action::Firewall(r) => crate::ensure::firewall(r, false, log).map(|changed| Outcome::Done { changed }),
            Action::Defender(e) => crate::ensure::defender(e, false, log).map(|changed| Outcome::Done { changed }),
            Action::RemoveApp { name } => {
                crate::ensure::remove_app(name, false, log).map(|changed| Outcome::Done { changed })
            }
            Action::Feature(f) => self.ensure_feature(f, log),
            Action::Capability(c) => self.ensure_capability(c, log),
            Action::Wallpaper(w) => self.wallpaper(w, false).map(|changed| Outcome::Done { changed }),
            Action::Theme(t) => theme(t, false).map(|changed| Outcome::Done { changed }),
            Action::LockScreen(l) => self.lock_screen(l, false).map(|changed| Outcome::Done { changed }),
            Action::ScreenSaver(s) => screen_saver(s, false).map(|changed| Outcome::Done { changed }),
            Action::DoNotDisturb { on } => {
                let changed = desktop::set_do_not_disturb(*on, false)?;
                if changed {
                    log("Windows applies it at the next sign-in");
                }
                Ok(Outcome::Done { changed })
            }
            Action::StartPins(p) => self.start_pins(p, false).map(|changed| Outcome::Done { changed }),
            Action::DesktopShortcut(d) => {
                if !shortcut_differs(d)? {
                    return Ok(Outcome::Done { changed: false });
                }
                run_ps(&shortcut_scripts(d).1, log)?;
                Ok(Outcome::Done { changed: true })
            }
            Action::RestartExplorer { .. } => {
                // Only this session's Explorer: Windows starts it again by itself.
                let script = "$me = (Get-Process -Id $PID).SessionId\n\
                     $mine = Get-Process explorer -ErrorAction SilentlyContinue | Where-Object SessionId -eq $me\n\
                     if (-not $mine) { 'no Explorer running for this account; it shows them at sign-in'; return }\n\
                     $mine | Stop-Process -Force\n\
                     foreach ($i in 1..20) {\n\
                       Start-Sleep -Milliseconds 500\n\
                       if (Get-Process explorer -ErrorAction SilentlyContinue | Where-Object SessionId -eq $me) { return }\n\
                     }\n\
                     Start-Process explorer.exe";
                run_ps(script, log)?;
                Ok(Outcome::Done { changed: true })
            }
            Action::Language(l) => {
                if !language_differs(l)? {
                    return Ok(Outcome::Done { changed: false });
                }
                let (_, apply) = language_scripts(l);
                let out =
                    powershell(Shell::Powershell, &format!("$ErrorActionPreference = 'Stop'\n{apply}")).run(log)?;
                if out.code != 0 {
                    bail!("PowerShell exited with {}", out.code);
                }
                Ok(match l {
                    LanguageSetting::SystemLocale { .. }
                    | LanguageSetting::Utf8 { .. }
                    | LanguageSetting::Display { machine: true, .. } => self.restart_later_if(true),
                    LanguageSetting::Display { .. } => {
                        log("Windows shows it from the next sign-in");
                        Outcome::Done { changed: true }
                    }
                    _ => Outcome::Done { changed: true },
                })
            }
            Action::TrayIcon(t) => {
                let changed = match desktop::set_tray_icon(&t.program, t.shown, false)? {
                    desktop::TrayIcon::NotSeenYet => {
                        log(&format!(
                            "{} hasn't shown a tray icon yet; it's set on the next apply after it does",
                            t.program
                        ));
                        false
                    }
                    desktop::TrayIcon::AsWanted => false,
                    desktop::TrayIcon::Changed(_) => true,
                };
                Ok(Outcome::Done { changed })
            }
            Action::Verify(c) => {
                crate::checks::run(c, self.started, log)?;
                Ok(Outcome::Done { changed: false })
            }
        }
    }

    fn check(&mut self, step: &Step) -> Result<Probe> {
        let quiet = &mut |_: &str| {};
        let would = |changes: bool| if changes { Probe::WouldChange } else { Probe::Satisfied };
        Ok(match &step.action {
            Action::EnsureWinget => would(winget::locate().is_none()),
            Action::App(App::Winget { id, version, upgrade, state, .. }) => {
                let Some(winget) = winget::locate() else { return Ok(Probe::WouldChange) };
                match (installed_version(&winget, id)?, state.is_present()) {
                    (None, present) => would(present),
                    (Some(_), false) => Probe::WouldChange,
                    (Some(have), true) => match version {
                        Some(pin) => would(&have != pin),
                        None if *upgrade => would(upgrade_available(&winget, id)?),
                        None => Probe::Satisfied,
                    },
                }
            }
            Action::App(App::Url { .. }) => Probe::Unknown,
            Action::File(f) => self.check_file(f)?,
            Action::Env { name, value, scope, state } => {
                let scope = env_scope(*scope);
                if state.is_present() {
                    match fill(&self.secrets, value) {
                        Ok(value) => would(!env::var_matches(scope, name, &value)),
                        Err(_) => Probe::Unknown, // a secret this preview wasn't given
                    }
                } else {
                    would(env::var_exists(scope, name))
                }
            }
            Action::Path { dir, scope, state } => {
                would(env::path_contains(env_scope(*scope), dir)? != state.is_present())
            }
            Action::Registry(r) => check_registry(r, &self.secrets)?,
            Action::Run(_) | Action::Verify(_) => Probe::WillRun,
            Action::User(u) => would(accounts::user_exists(&u.name)? != u.state.is_present()),
            Action::Feature(f) => {
                self.dism()?;
                let state = self.dism.as_ref().expect("opened").feature_state(&f.name)?;
                would(state.is_on() != f.enabled)
            }
            Action::Capability(c) => {
                self.dism()?;
                let state = self.dism.as_ref().expect("opened").capability_state(&c.name)?;
                would(state.is_on() != c.present)
            }
            Action::Certificate(c) => would(self.certificate(c, true, quiet)?),
            Action::Wallpaper(w) => would(self.wallpaper(w, true)?),
            Action::Theme(t) => would(theme(t, true)?),
            Action::LockScreen(l) => would(self.lock_screen(l, true)?),
            Action::ScreenSaver(s) => would(screen_saver(s, true)?),
            Action::DoNotDisturb { on } => would(desktop::set_do_not_disturb(*on, true)?),
            Action::StartPins(p) => would(self.start_pins(p, true)?),
            Action::Language(l) => would(language_differs(l)?),
            Action::DesktopShortcut(d) => would(shortcut_differs(d)?),
            Action::RestartExplorer { .. } => Probe::Unknown,
            Action::TrayIcon(t) => match desktop::set_tray_icon(&t.program, t.shown, true)? {
                desktop::TrayIcon::NotSeenYet => Probe::Unknown,
                desktop::TrayIcon::AsWanted => Probe::Satisfied,
                desktop::TrayIcon::Changed(_) => Probe::WouldChange,
            },
            Action::Service(s) => would(crate::ensure::service(s, true, quiet)?),
            Action::Firewall(r) => would(crate::ensure::firewall(r, true, quiet)?),
            Action::Defender(e) => would(crate::ensure::defender(e, true, quiet)?),
            Action::RemoveApp { name } => would(crate::ensure::remove_app(name, true, quiet)?),
        })
    }
}

impl WinExecutor<'_> {
    fn check_file(&self, f: &FileCopy) -> Result<Probe> {
        let dest = PathBuf::from(env::expand_path(&f.to)?);
        if !f.state.is_present() {
            return Ok(if dest.exists() { Probe::WouldChange } else { Probe::Satisfied });
        }
        if let Some(content) = &f.content {
            let Ok(text) = fill(&self.secrets, content) else { return Ok(Probe::Unknown) };
            let same = std::fs::read(&dest).is_ok_and(|current| current == text.as_bytes());
            return Ok(if same { Probe::Satisfied } else { Probe::WouldChange });
        }
        // A file compares by hash, known without downloading anything. An archive to unpack
        // or a folder to copy can't be compared that cheaply.
        match (f.extract, f.sha256.as_deref().or(f.resolved.as_deref())) {
            (false, Some(hash)) if !dest.is_dir() => {
                let same = dest.is_file() && groundhog_core::fetch::sha256_file(&dest).is_ok_and(|h| h == hash);
                Ok(if same { Probe::Satisfied } else { Probe::WouldChange })
            }
            _ => Ok(if dest.exists() { Probe::Unknown } else { Probe::WouldChange }),
        }
    }
}

fn check_registry(r: &RegistryValue, secrets: &Secrets) -> Result<Probe> {
    let (root, sub) = registry::split_key(&r.key)?;
    let filled = match fill_registry(secrets, r) {
        Ok(f) => f,
        Err(_) => return Ok(Probe::Unknown),
    };
    if r.group_policy {
        return Ok(if group_policy(&filled, true)? { Probe::WouldChange } else { Probe::Satisfied });
    }
    let mut changes = false;
    for scope in &r.scope {
        let hive = match scope {
            HiveScope::CurrentUser => None,
            HiveScope::DefaultUser => Some(DefaultUserHive::load()?),
        };
        let root = hive.as_ref().map_or(&root, |h| h.root());
        changes |= if !r.state.is_present() {
            match &r.name {
                Some(name) => registry::value_exists(root, &sub, Some(name)),
                None => registry::key_exists(root, &sub),
            }
        } else {
            !registry::value_matches(root, &sub, r.name.as_deref(), &registry_data(&filled))
        };
    }
    Ok(if changes { Probe::WouldChange } else { Probe::Satisfied })
}

/// Whether winget knows a newer version of an installed package. Its exit code says nothing
/// here (0 even for "No installed package found"), so this looks for the package's row.
fn upgrade_available(winget: &Path, id: &str) -> Result<bool> {
    let args =
        ["list", "--id", id, "--exact", "--upgrade-available", "--accept-source-agreements", "--disable-interactivity"];
    let out = Proc { capture_stdout: true, ..Proc::new(winget).args(args) }.run(&mut |_| {})?;
    Ok(version_from_list(&out.stdout, id).is_some())
}

impl WinExecutor<'_> {
    /// Fetches content into `work/<kind>/<hash>/<name>`. `sha256` is the user's pin or, for
    /// unpinned references, the hash resolved at load time. Either way the bytes must match,
    /// so a "latest" URL that moves on mid-run fails instead of installing a different build.
    fn download(&self, kind: &str, url: &Url, sha256: Option<&str>, log: &mut dyn FnMut(&str)) -> Result<PathBuf> {
        let fetched = self.content.get_file(url, sha256)?;
        if fetched.from_cache {
            log("using cached copy");
        }
        // Installers care about their own file name (and extension), so each gets a folder
        // named for its content. A hard link costs nothing on the same volume.
        let dir = self.work_dir.join(kind).join(&fetched.sha256[..16]);
        let path = dir.join(file_name(url));
        if !path.is_file() {
            std::fs::create_dir_all(&dir)?;
            if std::fs::hard_link(&fetched.path, &path).is_err() {
                std::fs::copy(&fetched.path, &path).with_context(|| format!("writing {}", path.display()))?;
            }
        }
        Ok(path)
    }

    /// Where winget is. Found again when needed: on a later apply the "ensure winget" step is
    /// recorded as done and skipped, but a new or always-run app step still needs it.
    fn winget(&mut self) -> Result<&Path> {
        if self.winget.is_none() {
            self.winget = winget::locate();
        }
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

    /// Installs, upgrades, moves to a pinned version, or uninstalls a winget package,
    /// depending on what's there now.
    fn winget_app(
        &mut self,
        id: &str,
        want: WingetWant,
        args: Option<&str>,
        timeout_ms: Option<u64>,
        log: &mut dyn FnMut(&str),
    ) -> Result<Outcome> {
        let winget = self.winget()?.to_path_buf();
        let common = ["--id", id, "--exact", "--accept-source-agreements", "--disable-interactivity"];
        let installed = installed_version(&winget, id)?;

        if !want.present {
            if installed.is_none() {
                return Ok(Outcome::Done { changed: false });
            }
            let code = Proc::new(&winget)
                .args(["uninstall"])
                .args(common)
                .args(["--silent"])
                .raw(args)
                .timeout_ms(timeout_ms)
                .run(log)?
                .code;
            if code == codes::USER_SCOPE_NEEDS_UNELEVATED {
                // A per-user (often portable) package: winget only removes it from a process
                // that isn't elevated, so ask again as this user, unelevated.
                log("retrying as this user without elevation (winget's rule for per-user packages)");
                let mut unelevated: Vec<&str> = vec!["uninstall"];
                unelevated.extend(common);
                unelevated.push("--silent");
                let timeout = std::time::Duration::from_millis(timeout_ms.unwrap_or(10 * 60 * 1000));
                let (code, lines) = groundhog_win::tasks::run_unelevated(&winget, &unelevated, timeout)?;
                for line in lines.iter().map(|l| l.rsplit('\r').next().unwrap_or(l).trim()).filter(|l| !l.is_empty()) {
                    log(line);
                }
                return winget_outcome(code, id, "uninstall");
            }
            return winget_outcome(code, id, "uninstall");
        }

        let mut verb = "install";
        let mut extra: Vec<&str> = vec!["--silent", "--accept-package-agreements"];
        match (&installed, want.version, want.upgrade) {
            (Some(have), Some(pin), _) if have == pin => return Ok(Outcome::Done { changed: false }),
            (Some(have), Some(pin), _) => {
                // A different version is installed: move to the pinned one, up or down.
                log(&format!("installed {have}, pinned {pin}"));
                extra.extend(["--version", pin, "--force"]);
            }
            (Some(_), None, true) => verb = "upgrade",
            (Some(_), None, false) => {
                log("already installed");
                return Ok(Outcome::Done { changed: false });
            }
            (None, pin, _) => {
                if let Some(pin) = pin {
                    extra.extend(["--version", pin]);
                }
            }
        }
        let code =
            Proc::new(&winget).args([verb]).args(common).args(extra).raw(args).timeout_ms(timeout_ms).run(log)?.code;
        winget_outcome(code, id, verb)
    }

    fn url_install(
        &mut self,
        url: &Url,
        sha256: Option<&str>,
        args: Option<&str>,
        timeout_ms: Option<u64>,
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
        match proc.timeout_ms(timeout_ms).run(log)?.code {
            0 => Ok(Outcome::Done { changed: true }),
            EXIT_REBOOT_REQUIRED | EXIT_REBOOT_INITIATED => Ok(Outcome::RebootRequired),
            EXIT_INSTALL_IN_PROGRESS => bail!("another installation is in progress (1618); run again when it finishes"),
            code => bail!("installer exited with {code}"),
        }
    }

    fn dism(&mut self) -> Result<&dism::Session> {
        if std::env::var("USERNAME").is_ok_and(|u| u.eq_ignore_ascii_case("WDAGUtilityAccount")) {
            bail!("Windows features and capabilities can't be changed inside Windows Sandbox; use a VM");
        }
        if self.dism.is_none() {
            self.dism = Some(dism::Session::open(&self.work_dir.join("dism.log"))?);
        }
        Ok(self.dism.as_ref().expect("just opened"))
    }

    /// Brings a Windows optional feature to the wanted state. Checks the live state first, so
    /// it's idempotent even on a template where someone already enabled it.
    fn ensure_feature(&mut self, f: &Feature, log: &mut dyn FnMut(&str)) -> Result<Outcome> {
        let log_path = self.work_dir.join("dism.log");
        let deferred = self.deferred_restart;
        self.dism()?;
        let session = self.dism.as_ref().expect("just opened");
        let state = session.feature_state(&f.name).map_err(|e| explain(e, "feature", &f.name, &log_path))?;
        if state.is_on() == f.enabled {
            self.deferred_restart |= state.is_pending();
            return Ok(settled(state, log));
        }
        if !deferred && dism::servicing_reboot_pending() {
            log("Windows servicing is waiting for a restart; retrying after one");
            return Ok(Outcome::RetryAfterReboot);
        }
        let (sources, _mounted) = servicing_sources(self.content, &self.work_dir, &f.sources, log)?;
        let timeout = f.timeout_ms.map(std::time::Duration::from_millis);
        let mut progress = |pct: u32| log(&format!("{pct}%"));
        let result = if f.enabled {
            session.enable_feature(&f.name, f.all, &sources, f.limit_access, timeout, &mut progress)
        } else {
            session.disable_feature(&f.name, f.remove_payload, timeout, &mut progress)
        };
        let dism_says_restart = match result {
            Ok(restart) => restart,
            Err(e) => return pending_or(e, "feature", &f.name, &log_path, log),
        };
        let after = session.feature_state(&f.name).map_err(|e| explain(e, "feature", &f.name, &log_path))?;
        Ok(self.restart_later_if(dism_says_restart || after.is_pending() || dism::servicing_reboot_pending()))
    }

    fn ensure_capability(&mut self, c: &Capability, log: &mut dyn FnMut(&str)) -> Result<Outcome> {
        let log_path = self.work_dir.join("dism.log");
        let deferred = self.deferred_restart;
        self.dism()?;
        let session = self.dism.as_ref().expect("just opened");
        let state = session.capability_state(&c.name).map_err(|e| explain(e, "capability", &c.name, &log_path))?;
        if state.is_on() == c.present {
            self.deferred_restart |= state.is_pending();
            return Ok(settled(state, log));
        }
        if !deferred && dism::servicing_reboot_pending() {
            log("Windows servicing is waiting for a restart; retrying after one");
            return Ok(Outcome::RetryAfterReboot);
        }
        let (sources, _mounted) = servicing_sources(self.content, &self.work_dir, &c.sources, log)?;
        let timeout = c.timeout_ms.map(std::time::Duration::from_millis);
        let mut progress = |pct: u32| log(&format!("{pct}%"));
        let result = if c.present {
            session.add_capability(&c.name, &sources, c.limit_access, timeout, &mut progress)
        } else {
            session.remove_capability(&c.name, timeout, &mut progress)
        };
        let dism_says_restart = match result {
            Ok(restart) => restart,
            Err(e) => return pending_or(e, "capability", &c.name, &log_path, log),
        };
        let after = session.capability_state(&c.name).map_err(|e| explain(e, "capability", &c.name, &log_path))?;
        Ok(self.restart_later_if(dism_says_restart || after.is_pending() || dism::servicing_reboot_pending()))
    }

    /// DISM's return code, the item's state and CBS's own flag can each be the only one to show
    /// a restart is due, so any of them counts. The pre-check makes sure a restart that was
    /// already pending isn't mistaken for ours.
    /// Adds, or removes, a certificate. A certificate file is fetched like any other download
    /// (cache first, hash checked).
    fn certificate(&mut self, c: &Certificate, check: bool, log: &mut dyn FnMut(&str)) -> Result<bool> {
        let file = match &c.from {
            Some(from) => Some(self.content.get_file(from, c.sha256.as_deref().or(c.resolved.as_deref()))?.path),
            None => None,
        };
        crate::ensure::certificate(c, file.as_deref(), check, log)
    }

    /// The desktop picture and background color, for each user hive in scope. The picture is
    /// copied to `<home>\desktop`, a stable place every account can read (so the Default User
    /// profile can point at it too) that `clean` leaves alone.
    /// A picture's stable copy in `<home>\desktop`, fetched and copied unless only checking.
    /// `None` when checking and its content isn't known yet (it would change).
    fn desktop_picture(&self, from: &Url, known: Option<&str>, check: bool) -> Result<Option<String>> {
        let ext = Path::new(&file_name(from))
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_else(|| "jpg".into());
        let dir = self.work_dir.parent().unwrap_or(&self.work_dir).join("desktop");
        if check {
            return Ok(known.map(|hash| dir.join(format!("{}.{ext}", &hash[..16])).to_string_lossy().into_owned()));
        }
        let fetched = self.content.get_file(from, known)?;
        let path = dir.join(format!("{}.{ext}", &fetched.sha256[..16]));
        if !path.exists() {
            std::fs::create_dir_all(&dir)?;
            std::fs::copy(&fetched.path, &path).with_context(|| format!("writing {}", path.display()))?;
        }
        Ok(Some(path.to_string_lossy().into_owned()))
    }

    /// The machine's lock screen picture and idle lock.
    fn lock_screen(&mut self, l: &LockScreen, check: bool) -> Result<bool> {
        let mut changed = false;
        if let Some(image) = &l.image {
            match self.desktop_picture(image, l.sha256.as_deref().or(l.resolved.as_deref()), check)? {
                Some(picture) => changed |= desktop::set_lock_screen_image(&picture, check)?,
                None => changed = true,
            }
        }
        if let Some(secs) = l.lock_after_secs {
            changed |= desktop::set_lock_after(secs, check)?;
        }
        Ok(changed)
    }

    /// Start's pins, from a layout file, for this user and/or new accounts.
    fn start_pins(&mut self, p: &StartPins, check: bool) -> Result<bool> {
        let profiles = p.scope.iter().map(|s| match s {
            HiveScope::CurrentUser => desktop::Profile::Current,
            HiveScope::DefaultUser => desktop::Profile::Default,
        });
        let known = p.sha256.as_deref().or(p.resolved.as_deref());
        if check {
            // Without downloading: does each profile's file already have the layout's hash?
            let Some(known) = known else { return Ok(true) };
            for profile in profiles {
                let path = desktop::start_layout_path(profile)?;
                if !path.exists() || !groundhog_core::fetch::sha256_file(&path)?.eq_ignore_ascii_case(known) {
                    return Ok(true);
                }
            }
            return Ok(false);
        }
        let layout = std::fs::read(&self.content.get_file(&p.from, known)?.path)?;
        let mut changed = false;
        for profile in profiles {
            changed |= desktop::set_start_pins(&layout, profile)?;
        }
        Ok(changed)
    }

    fn wallpaper(&mut self, w: &Wallpaper, check: bool) -> Result<bool> {
        let picture = match &w.from {
            None => String::new(),
            Some(from) => match self.desktop_picture(from, w.sha256.as_deref().or(w.resolved.as_deref()), check)? {
                Some(picture) => picture,
                None => return Ok(true),
            },
        };
        let rgb = w.background.as_deref().map(|c| {
            let n = u32::from_str_radix(c.trim_start_matches('#'), 16).unwrap_or(0);
            ((n >> 16) as u8, (n >> 8) as u8, n as u8)
        });
        let style = match w.style {
            WallpaperStyle::Fill => desktop::Style::Fill,
            WallpaperStyle::Fit => desktop::Style::Fit,
            WallpaperStyle::Stretch => desktop::Style::Stretch,
            WallpaperStyle::Tile => desktop::Style::Tile,
            WallpaperStyle::Center => desktop::Style::Center,
            WallpaperStyle::Span => desktop::Style::Span,
        };
        let hkcu = registry::hkcu();
        let mut changed = false;
        for scope in &w.scope {
            let hive = match scope {
                HiveScope::CurrentUser => None,
                HiveScope::DefaultUser => Some(DefaultUserHive::load()?),
            };
            let root = hive.as_ref().map_or(&hkcu, |h| h.root());
            changed |= desktop::set_wallpaper(root, &picture, style, check)?;
            if let Some(rgb) = rgb {
                changed |= desktop::set_background(root, rgb, check)?;
            }
        }
        if changed && !check && w.scope.contains(&HiveScope::CurrentUser) {
            desktop::apply_now(&picture, rgb)?;
        }
        Ok(changed)
    }

    fn restart_later_if(&mut self, pending: bool) -> Outcome {
        if pending {
            self.deferred_restart = true;
            Outcome::DoneRestartLater { changed: true }
        } else {
            Outcome::Done { changed: true }
        }
    }

    /// Creates the account if it's missing; otherwise brings its settings in line, leaving the
    /// password alone unless asked to reset it. Passwords are never logged.
    fn ensure_user(&mut self, u: &User, log: &mut dyn FnMut(&str)) -> Result<Outcome> {
        let password = || -> Result<String> {
            match &u.password {
                Password::Generate => accounts::generate_password(24),
                Password::Secret(name) => {
                    self.secrets.get(name).cloned().ok_or_else(|| anyhow::anyhow!(crate::secrets::missing_hint(name)))
                }
            }
        };
        let mut changed = false;
        if accounts::user_exists(&u.name)? {
            if u.reset_password {
                accounts::set_password(&u.name, &password()?)?;
                log("password reset");
                changed = true;
            }
            changed |= accounts::set_password_never_expires(&u.name, u.password_never_expires)?;
        } else {
            accounts::create_user(&u.name, &password()?, u.password_never_expires)?;
            log(&format!("created {}", u.name));
            changed = true;
        }
        if let Some(full_name) = &u.full_name {
            accounts::set_full_name(&u.name, full_name)?;
        }
        for group in &u.groups {
            if accounts::add_to_group(&u.name, group)? {
                log(&format!("added to {group}"));
                changed = true;
            }
        }
        Ok(Outcome::Done { changed })
    }

    fn copy(&mut self, f: &FileCopy, log: &mut dyn FnMut(&str)) -> Result<Outcome> {
        let dest = PathBuf::from(env::expand_path(&f.to)?);
        if !f.state.is_present() {
            return remove_file_or_folder(&dest, log);
        }
        let Some(from) = &f.from else {
            // Inline content: secrets are filled in here and only here, on the way to `to`.
            let text = fill(&self.secrets, f.content.as_deref().unwrap_or_default())?;
            let changed = write_if_different(&dest, text.as_bytes())?;
            if changed {
                log(&format!("wrote {}", dest.display()));
            }
            return Ok(Outcome::Done { changed });
        };
        if from.scheme() == "file" {
            let src = file_url_to_path(from)?;
            if src.is_dir() {
                return Ok(Outcome::Done { changed: copy_dir(&src, &dest)? });
            }
        }
        let fetched = self.content.get_file(from, f.sha256.as_deref().or(f.resolved.as_deref()))?;
        if f.extract {
            replace_with_zip(&fetched.path, &dest, f.strip as usize)?;
            log(&format!("unpacked into {}", dest.display()));
            return Ok(Outcome::Done { changed: true });
        }
        let changed = copy_if_different(&fetched.path, &dest)?;
        if changed {
            log(&format!("wrote {}", dest.display()));
        }
        Ok(Outcome::Done { changed })
    }

    fn run_action(&mut self, action: &RunAction, log: &mut dyn FnMut(&str)) -> Result<Outcome> {
        let timeout_ms = action.timeout_ms();
        match action {
            RunAction::Command { command, shell, .. } => {
                let (command, secret_env) = secrets_as_env(&self.secrets, command, *shell)?;
                let proc = match shell {
                    Shell::Powershell | Shell::Pwsh => powershell(*shell, &command),
                    Shell::Cmd => cmd(&command)?,
                    Shell::Direct => bail!("'shell: direct' only applies to scripts"),
                };
                let proc = Proc { env: secret_env, ..proc };
                exit_to_outcome(proc.timeout_ms(timeout_ms).run(log)?.code, "command")
            }
            RunAction::Script { script, sha256, resolved, args, shell, .. } => {
                let path = self.download("scripts", script, sha256.as_deref().or(resolved.as_deref()), log)?;
                let shell = match shell {
                    Some(s) => *s,
                    None => shell_for(&path)?,
                };
                let p = path.to_string_lossy().into_owned();
                // Arguments are a command line by nature, so secrets in them are filled in as
                // text (and are visible to process listings: prefer reading them from env).
                let args = args.as_deref().map(|a| fill(&self.secrets, a)).transpose()?;
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
                exit_to_outcome(proc.timeout_ms(timeout_ms).run(log)?.code, "script")
            }
            RunAction::Plugin { plugin, sha256, resolved, with, .. } => {
                let exe = self.download("plugins", plugin, sha256.as_deref().or(resolved.as_deref()), log)?;
                let scratch = self.work_dir.join("plugin-scratch");
                std::fs::create_dir_all(&scratch)?;
                let request = PluginRequest {
                    protocol: PROTOCOL_VERSION,
                    action: "apply".into(),
                    with: with.clone(),
                    work_dir: scratch.to_string_lossy().into_owned(),
                };
                let proc = Proc {
                    stdin: Some(serde_json::to_vec(&request)?),
                    capture_stdout: true,
                    ..Proc::new(&exe).timeout_ms(timeout_ms)
                };
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

fn env_scope(scope: EnvScope) -> env::Scope {
    match scope {
        EnvScope::User => env::Scope::User,
        EnvScope::Machine => env::Scope::Machine,
    }
}

/// Deletes a file, or a folder and everything in it. A drive root or a folder Windows itself
/// depends on is refused: one typo in `to` shouldn't be able to wipe a machine.
fn remove_file_or_folder(dest: &Path, log: &mut dyn FnMut(&str)) -> Result<Outcome> {
    refuse_protected(dest)?;
    let meta = match std::fs::symlink_metadata(dest) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Outcome::Done { changed: false }),
        Err(e) => return Err(e).with_context(|| format!("reading {}", dest.display())),
    };
    if meta.is_dir() {
        std::fs::remove_dir_all(dest).with_context(|| format!("removing {}", dest.display()))?;
    } else {
        std::fs::remove_file(dest).with_context(|| format!("removing {}", dest.display()))?;
    }
    log(&format!("removed {}", dest.display()));
    Ok(Outcome::Done { changed: true })
}

fn refuse_protected(path: &Path) -> Result<()> {
    let norm = |p: &Path| p.to_string_lossy().trim_end_matches(['\\', '/']).to_ascii_lowercase();
    let target = norm(path);
    if path.components().count() <= 2 {
        bail!("refusing to remove {}: too close to the root of the drive", path.display());
    }
    let protected = [
        "SystemRoot",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramW6432",
        "ProgramData",
        "USERPROFILE",
        "PUBLIC",
        "APPDATA",
        "LOCALAPPDATA",
    ];
    for var in protected {
        if let Ok(dir) = std::env::var(var)
            && norm(Path::new(&dir)) == target
        {
            bail!("refusing to remove {}: it's %{var}%", path.display());
        }
    }
    let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
    if target == norm(Path::new(&format!("{system_drive}\\Users"))) {
        bail!("refusing to remove {}", path.display());
    }
    Ok(())
}

fn delete_registry(r: &RegistryValue) -> Result<Outcome> {
    if r.group_policy {
        return Ok(Outcome::Done { changed: group_policy(r, false)? });
    }
    let (root, sub) = registry::split_key(&r.key)?;
    let mut changed = false;
    for scope in &r.scope {
        let hive = match scope {
            HiveScope::CurrentUser => None,
            HiveScope::DefaultUser => Some(DefaultUserHive::load()?),
        };
        let root = hive.as_ref().map_or(&root, |h| h.root());
        changed |= match &r.name {
            Some(name) => registry::delete_value(root, &sub, Some(name))?,
            None => registry::delete_key(root, &sub)?,
        };
    }
    Ok(Outcome::Done { changed })
}

/// The screen saver for each user hive in scope; the running session picks it up at once.
fn screen_saver(s: &ScreenSaver, check: bool) -> Result<bool> {
    let program = s.program.as_deref().map(env::expand).transpose()?;
    let settings = desktop::ScreenSaver {
        enabled: s.enabled,
        timeout_secs: s.timeout_secs,
        secure: s.secure,
        program: program.as_deref(),
    };
    let hkcu = registry::hkcu();
    let mut changed = false;
    for scope in &s.scope {
        let hive = match scope {
            HiveScope::CurrentUser => None,
            HiveScope::DefaultUser => Some(DefaultUserHive::load()?),
        };
        let root = hive.as_ref().map_or(&hkcu, |h| h.root());
        changed |= desktop::set_screen_saver(root, &settings, check)?;
    }
    if changed && !check && s.scope.contains(&HiveScope::CurrentUser) {
        desktop::apply_screen_saver_now(&settings)?;
    }
    Ok(changed)
}

/// Light or dark mode for each user hive in scope; the running session switches at once.
fn theme(t: &Theme, check: bool) -> Result<bool> {
    let light = |m: Option<ThemeMode>| m.map(|m| m == ThemeMode::Light);
    let hkcu = registry::hkcu();
    let mut changed = false;
    for scope in &t.scope {
        let hive = match scope {
            HiveScope::CurrentUser => None,
            HiveScope::DefaultUser => Some(DefaultUserHive::load()?),
        };
        let root = hive.as_ref().map_or(&hkcu, |h| h.root());
        changed |= desktop::set_theme(root, light(t.apps), light(t.windows), check)?;
    }
    if changed && !check && t.scope.contains(&HiveScope::CurrentUser) {
        desktop::broadcast_theme_change();
    }
    Ok(changed)
}

/// What a winget app entry asks for.
#[derive(Clone, Copy)]
struct WingetWant<'a> {
    version: Option<&'a str>,
    upgrade: bool,
    present: bool,
}

fn winget_outcome(code: i32, id: &str, verb: &str) -> Result<Outcome> {
    match code {
        0 => Ok(Outcome::Done { changed: true }),
        codes::PACKAGE_ALREADY_INSTALLED | codes::INSTALL_ALREADY_INSTALLED | codes::UPDATE_NOT_APPLICABLE => {
            Ok(Outcome::Done { changed: false })
        }
        codes::INSTALL_REBOOT_REQUIRED_TO_FINISH | codes::INSTALL_REBOOT_INITIATED => Ok(Outcome::RebootRequired),
        codes::INSTALL_REBOOT_REQUIRED_FOR_INSTALL => Ok(Outcome::RetryAfterReboot),
        codes::NO_APPLICATIONS_FOUND if verb == "uninstall" => Ok(Outcome::Done { changed: false }),
        codes::NO_APPLICATIONS_FOUND => bail!("no winget package with id '{id}'"),
        other => bail!("winget {verb} failed with {other:#010X}"),
    }
}

/// The installed version of a winget package, `None` when it isn't installed. The version is
/// read from `winget list`: the token after the id on the package's row (`Unknown` and
/// `< 1.2` are what winget prints when it can't tell exactly).
fn installed_version(winget: &Path, id: &str) -> Result<Option<String>> {
    let out = Proc {
        capture_stdout: true,
        ..Proc::new(winget).args([
            "list",
            "--id",
            id,
            "--exact",
            "--accept-source-agreements",
            "--disable-interactivity",
        ])
    }
    .run(&mut |_| {})?;
    if out.code != 0 {
        return Ok(None);
    }
    Ok(Some(version_from_list(&out.stdout, id).unwrap_or_default()))
}

fn version_from_list(stdout: &str, id: &str) -> Option<String> {
    for line in stdout.lines() {
        // winget redraws a progress spinner with carriage returns; the row is after the last.
        let line = line.rsplit('\r').next().unwrap_or(line);
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if let Some(i) = tokens.iter().position(|t| t.eq_ignore_ascii_case(id)) {
            let version = tokens.get(i + 1)?;
            return Some(match *version {
                "<" | ">" => format!("{version} {}", tokens.get(i + 2).unwrap_or(&"")),
                v => v.to_owned(),
            });
        }
    }
    None
}

/// Puts secret values in place of `${secret:NAME}` (and undoes `$${secret:` escapes).
fn fill(secrets: &Secrets, s: &str) -> Result<String> {
    if !secret::mentions(s) {
        return Ok(s.to_owned());
    }
    secret::substitute(s, |name| secret_value(secrets, name))
}

fn secret_value(secrets: &Secrets, name: &str) -> Result<String> {
    secrets.get(name).cloned().ok_or_else(|| anyhow::anyhow!(crate::secrets::missing_hint(name)))
}

fn fill_registry(secrets: &Secrets, r: &RegistryValue) -> Result<RegistryValue> {
    let data = match &r.data {
        RegistryData::String(v) => RegistryData::String(fill(secrets, v)?),
        RegistryData::MultiString(vs) => {
            RegistryData::MultiString(vs.iter().map(|v| fill(secrets, v)).collect::<Result<_>>()?)
        }
        other => other.clone(),
    };
    Ok(RegistryValue { data, ..r.clone() })
}

/// For a command, a secret becomes a reference to an environment variable the child gets,
/// `GROUNDHOG_SECRET_<NAME>`, not text spliced into the script. That keeps the value off the
/// command line (`-EncodedCommand` is visible to process listings and command-line auditing)
/// and out of any batch file on disk, and a value containing quotes can't break or inject
/// into the script. So write it where a variable expands: bare or in double quotes in
/// PowerShell, not in single quotes.
fn secrets_as_env(secrets: &Secrets, command: &str, shell: Shell) -> Result<(String, Vec<(String, String)>)> {
    if !secret::mentions(command) {
        return Ok((command.to_owned(), Vec::new()));
    }
    let mut out = String::with_capacity(command.len());
    let mut vars = Vec::new();
    for part in secret::parse(command)? {
        match part {
            Part::Text(t) => out.push_str(t),
            Part::Secret(name) => {
                let var = format!("GROUNDHOG_SECRET_{name}");
                out.push_str(&match shell {
                    Shell::Cmd => format!("%{var}%"),
                    _ => format!("${{env:{var}}}"),
                });
                vars.push((var, secret_value(secrets, name)?));
            }
        }
    }
    Ok((out, vars))
}

/// Already in the wanted state; if that state still waits on a restart, one is owed.
fn settled(state: dism::State, log: &mut dyn FnMut(&str)) -> Outcome {
    if state.is_pending() {
        log("already done; finishes after a restart");
        Outcome::DoneRestartLater { changed: false }
    } else {
        Outcome::Done { changed: false }
    }
}

/// Feature and capability sources as DISM wants them: folders. Folders and shares pass
/// through; a `.zip` (local or at a URL) is fetched and unpacked once per content; an `.iso`
/// is mounted for as long as the returned guards live, and its usual payload folders offered.
fn servicing_sources(
    content: &ContentStore,
    work_dir: &Path,
    sources: &[String],
    log: &mut dyn FnMut(&str),
) -> Result<(Vec<String>, Vec<MountedIso>)> {
    let mut folders = Vec::new();
    let mut mounted = Vec::new();
    for source in sources {
        let source = env::expand_path(source)?;
        let lower = source.to_ascii_lowercase();
        let is_url = lower.starts_with("http://") || lower.starts_with("https://");
        let path_part = lower.split(['?', '#']).next().unwrap_or_default();
        let (is_zip, is_iso) = (path_part.ends_with(".zip"), path_part.ends_with(".iso"));
        if !(is_url || is_zip || is_iso) {
            folders.push(source);
            continue;
        }
        let url = if is_url {
            Url::parse(&source).with_context(|| format!("source '{source}'"))?
        } else {
            Url::from_file_path(&source).map_err(|_| anyhow::anyhow!("source '{source}' isn't a full path"))?
        };
        if is_url {
            log(&format!("fetching {source}"));
        }
        let fetched = content.get_file(&url, None)?;
        let dir = work_dir.join("sources").join(&fetched.sha256[..16]);
        if is_iso {
            // Mount-DiskImage goes by the file's extension, which the object store doesn't keep.
            std::fs::create_dir_all(&dir)?;
            let iso = dir.join("source.iso");
            if !iso.exists() && std::fs::hard_link(&fetched.path, &iso).is_err() {
                std::fs::copy(&fetched.path, &iso).with_context(|| format!("copying {}", iso.display()))?;
            }
            let mount = MountedIso::mount(&iso)?;
            log(&format!("mounted {source} as {}:", mount.letter));
            for sub in ["", "sources\\sxs", "LanguagesAndOptionalFeatures"] {
                let folder = format!("{}:\\{sub}", mount.letter);
                if Path::new(&folder).is_dir() {
                    folders.push(folder);
                }
            }
            mounted.push(mount);
        } else {
            let marker = dir.join(".groundhog-unpacked");
            if !marker.exists() {
                if dir.exists() {
                    std::fs::remove_dir_all(&dir)?;
                }
                std::fs::create_dir_all(&dir)?;
                log(&format!("unpacking {source}"));
                archive::unzip_file(&fetched.path, &dir, 0)?;
                std::fs::write(&marker, b"")?;
            }
            folders.push(dir.to_string_lossy().into_owned());
        }
    }
    Ok((folders, mounted))
}

/// An ISO mounted for one step; dismounted when dropped.
struct MountedIso {
    path: PathBuf,
    letter: char,
}

impl MountedIso {
    fn mount(iso: &Path) -> Result<Self> {
        let script = "(Mount-DiskImage -ImagePath $env:GH_ISO -PassThru | Get-Volume).DriveLetter";
        let proc = Proc {
            env: vec![("GH_ISO".into(), iso.to_string_lossy().into_owned())],
            capture_stdout: true,
            ..powershell(Shell::Powershell, script)
        };
        let out = proc.run(&mut |_| {})?;
        let letter = out.stdout.trim().chars().next().filter(char::is_ascii_alphabetic);
        match (out.code, letter) {
            (0, Some(letter)) => Ok(MountedIso { path: iso.to_path_buf(), letter }),
            _ => bail!("couldn't mount {} (exit {}): {}", iso.display(), out.code, out.stdout.trim()),
        }
    }
}

impl Drop for MountedIso {
    fn drop(&mut self) {
        let proc = Proc {
            env: vec![("GH_ISO".into(), self.path.to_string_lossy().into_owned())],
            ..powershell(Shell::Powershell, "Dismount-DiskImage -ImagePath $env:GH_ISO | Out-Null")
        };
        let _ = proc.run(&mut |_| {});
    }
}

/// "Servicing is busy until a restart" means try again after one; anything else is a failure.
fn pending_or(e: anyhow::Error, kind: &str, name: &str, log_path: &Path, log: &mut dyn FnMut(&str)) -> Result<Outcome> {
    if e.downcast_ref::<DismError>().is_some_and(|d| d.hresult == dism::codes::PENDING) {
        log("Windows servicing has a restart pending; retrying after one");
        return Ok(Outcome::RetryAfterReboot);
    }
    Err(explain(e, kind, name, log_path))
}

/// Turns DISM's most common failures into what to do about them.
fn explain(e: anyhow::Error, kind: &str, name: &str, log_path: &Path) -> anyhow::Error {
    let Some(d) = e.downcast_ref::<DismError>() else { return e };
    let hint = match d.hresult {
        dism::codes::UNKNOWN_UPDATE => format!(
            "there's no {kind} named '{name}' on this edition of Windows. Names are exact; \
             `dism /online /get-features` or `/get-capabilities` lists them (client and Server names differ)"
        ),
        dism::codes::SOURCE_MISSING => format!(
            "Windows couldn't find the files for {name}. Give 'source:' (the sources\\sxs folder of install \
             media for this exact build, or a Features on Demand folder), or allow Windows Update"
        ),
        dism::codes::WSUS_BLOCKED => {
            "a WSUS policy blocks downloading it. Give 'source:' with 'limit-access: true', or allow Windows \
             Update for optional content (policy RepairContentServerSource=2)"
                .to_owned()
        }
        dism::codes::DOWNLOAD_FAILED | dism::codes::NETWORK_BLOCKED => {
            "downloading it from Windows Update failed. Give 'source:' with 'limit-access: true' for offline machines"
                .to_owned()
        }
        _ => String::new(),
    };
    let logs = format!("details: {} and C:\\Windows\\Logs\\CBS\\CBS.log", log_path.display());
    if hint.is_empty() { anyhow::anyhow!("{e:#}; {logs}") } else { anyhow::anyhow!("{e:#}: {hint}; {logs}") }
}

/// A machine policy value set (or removed) through local Group Policy; the loader allows
/// `via: group-policy` only for named HKLM values.
fn group_policy(r: &RegistryValue, check: bool) -> Result<bool> {
    let (_, sub) = registry::split_key(&r.key)?;
    let name = r.name.as_deref().context("a group policy value needs a name")?;
    let data = r.state.is_present().then(|| registry_data(r));
    gpo::set_machine_value(&sub, name, data.as_ref(), check)
}

fn registry_data(r: &RegistryValue) -> Data<'_> {
    match (&r.data, r.kind) {
        (RegistryData::String(s), RegistryType::ExpandString) => Data::ExpandString(s),
        (RegistryData::String(s), _) => Data::String(s),
        (RegistryData::MultiString(v), _) => Data::MultiString(v),
        (RegistryData::Dword(n), _) => Data::Dword(*n),
        (RegistryData::Qword(n), _) => Data::Qword(*n),
        (RegistryData::Binary(b), _) => Data::Binary(b),
    }
}

fn set_registry(r: &RegistryValue) -> Result<Outcome> {
    if r.group_policy {
        return Ok(Outcome::Done { changed: group_policy(r, false)? });
    }
    let data = registry_data(r);
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

/// Runs a PowerShell script that changes something, stopping at its first error.
fn run_ps(script: &str, log: &mut dyn FnMut(&str)) -> Result<()> {
    let out = powershell(Shell::Powershell, &format!("$ErrorActionPreference = 'Stop'\n{script}")).run(log)?;
    if out.code != 0 {
        bail!("PowerShell exited with {}", out.code);
    }
    Ok(())
}

/// Text in a PowerShell single-quoted string.
fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn shortcut_differs(d: &DesktopShortcut) -> Result<bool> {
    let (check, _) = shortcut_scripts(d);
    let out = Proc { capture_stdout: true, ..powershell(Shell::Powershell, &check) }.run(&mut |_| {})?;
    if out.code != 0 {
        bail!("checking the {} shortcut: PowerShell exited with {}", d.name, out.code);
    }
    Ok(out.stdout.trim() != "same")
}

/// PowerShell for a desktop shortcut: a check that prints `same` when it's already as wanted,
/// and the change. Added ones go on the desktop every account shares; removing looks there and
/// on this user's own desktop.
fn shortcut_scripts(d: &DesktopShortcut) -> (String, String) {
    let file = ps_quote(&format!("{}.lnk", d.name));
    let public = format!("(Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) {file})");
    if !d.state.is_present() {
        let both = format!("@({public}, (Join-Path ([Environment]::GetFolderPath('Desktop')) {file}))");
        return (
            format!("if (-not ({both} | Where-Object {{ Test-Path -LiteralPath $_ }})) {{ 'same' }}"),
            format!(
                "{both} | Where-Object {{ Test-Path -LiteralPath $_ }} | ForEach-Object {{ Remove-Item -LiteralPath $_ -Force }}"
            ),
        );
    }
    let expand = |s: &str| format!("[Environment]::ExpandEnvironmentVariables({})", ps_quote(s));
    let target = expand(d.target.as_deref().unwrap_or_default());
    let args = ps_quote(d.args.as_deref().unwrap_or_default());
    let icon = d.icon.as_deref().map(|i| format!("$s.IconLocation = {}\n", expand(i))).unwrap_or_default();
    (
        format!(
            "$path = {public}\n\
             if (Test-Path -LiteralPath $path) {{\n\
               $s = (New-Object -ComObject WScript.Shell).CreateShortcut($path)\n\
               if ($s.TargetPath -eq {target} -and $s.Arguments -eq {args}) {{ 'same' }}\n\
             }}"
        ),
        format!(
            "$path = {public}\n\
             $s = (New-Object -ComObject WScript.Shell).CreateShortcut($path)\n\
             $s.TargetPath = {target}\n\
             $s.Arguments = {args}\n\
             $s.WorkingDirectory = Split-Path ({target})\n\
             {icon}$s.Save()"
        ),
    )
}

/// Whether a language setting differs from what Windows has now.
fn language_differs(l: &LanguageSetting) -> Result<bool> {
    let (check, _) = language_scripts(l);
    let out = Proc { capture_stdout: true, ..powershell(Shell::Powershell, &check) }.run(&mut |_| {})?;
    if out.code != 0 {
        bail!("checking the language settings: PowerShell exited with {}", out.code);
    }
    Ok(out.stdout.trim() != "same")
}

/// PowerShell for a language setting (the International and LanguagePackManagement modules,
/// as Settings uses them): a check that prints `same` when Windows already has it, and the
/// change. Tags and keyboards were checked to be plain letters, digits and dashes when the
/// file was loaded, so they're safe in quotes here.
fn language_scripts(l: &LanguageSetting) -> (String, String) {
    match l {
        LanguageSetting::Input { languages } => {
            // Built with New-WinUserLanguageList, so tags and default keyboards come out as
            // Windows writes them ('ja-JP' is kept as 'ja') and compare equal.
            let mut build = format!("$list = New-WinUserLanguageList '{}'\n", languages[0].tag);
            for l in &languages[1..] {
                build.push_str(&format!("$list.Add('{}')\n", l.tag));
            }
            for (i, l) in languages.iter().enumerate().filter(|(_, l)| !l.keyboards.is_empty()) {
                build.push_str(&format!("$list[{i}].InputMethodTips.Clear()\n"));
                for k in &l.keyboards {
                    build.push_str(&format!("$list[{i}].InputMethodTips.Add('{k}')\n"));
                }
            }
            let show = "$show = { param($l) ($l | ForEach-Object { $_.LanguageTag + '=' + ($_.InputMethodTips -join ',') }) -join ';' }";
            (
                format!("{build}{show}\nif ((& $show $list) -eq (& $show (Get-WinUserLanguageList))) {{ 'same' }}"),
                format!("{build}Set-WinUserLanguageList $list -Force -WarningAction SilentlyContinue"),
            )
        }
        LanguageSetting::Display { tag, machine } => {
            let installed = format!("[bool](Get-InstalledLanguage -Language '{tag}' | Where-Object {{ \"$($_.LanguagePacks)\" -match 'LpCab' }})");
            let system = if *machine { format!(" -and (Get-SystemPreferredUILanguage) -eq '{tag}'") } else { String::new() };
            (
                format!(
                    "$o = Get-WinUILanguageOverride\n\
                     $shown = if ($o) {{ $o.Name }} else {{ Get-SystemPreferredUILanguage }}\n\
                     if ({installed} -and $shown -eq '{tag}'{system}) {{ 'same' }}"
                ),
                format!(
                    "if (-not {installed}) {{ Install-Language '{tag}' | Out-Null }}\n\
                     Set-WinUILanguageOverride -Language '{tag}'{}",
                    if *machine { format!("\nSet-SystemPreferredUILanguage '{tag}'") } else { String::new() }
                ),
            )
        }
        LanguageSetting::Formats { tag } => {
            (format!("if ((Get-Culture).Name -eq '{tag}') {{ 'same' }}"), format!("Set-Culture '{tag}'"))
        }
        LanguageSetting::Location { region } => {
            let geo = format!("([Globalization.RegionInfo]::new('{region}').GeoId)");
            (format!("if ((Get-WinHomeLocation).GeoId -eq {geo}) {{ 'same' }}"), format!("Set-WinHomeLocation -GeoId {geo}"))
        }
        LanguageSetting::SystemLocale { tag } => {
            (format!("if ((Get-WinSystemLocale).Name -eq '{tag}') {{ 'same' }}"), format!("Set-WinSystemLocale '{tag}'"))
        }
        LanguageSetting::Utf8 { on } => {
            let want = if *on {
                "$want = @{ ACP = '65001'; OEMCP = '65001'; MACCP = '65001' }".to_owned()
            } else {
                // The system locale's own code pages.
                "$t = (Get-WinSystemLocale).TextInfo\n\
                 $want = @{ ACP = \"$($t.ANSICodePage)\"; OEMCP = \"$($t.OEMCodePage)\"; MACCP = \"$($t.MacCodePage)\" }"
                    .to_owned()
            };
            let key = r"HKLM:\SYSTEM\CurrentControlSet\Control\Nls\CodePage";
            (
                format!(
                    "{want}\n$have = Get-ItemProperty '{key}'\n\
                     if (-not ($want.Keys | Where-Object {{ $have.$_ -ne $want[$_] }})) {{ 'same' }}"
                ),
                format!("{want}\nforeach ($k in $want.Keys) {{ Set-ItemProperty '{key}' -Name $k -Value $want[$k] }}"),
            )
        }
        LanguageSetting::CopyToSystem => (
            "$d = Get-ItemProperty 'Registry::HKEY_USERS\\.DEFAULT\\Control Panel\\International' -ErrorAction SilentlyContinue\n\
             $dp = Get-ItemProperty 'Registry::HKEY_USERS\\.DEFAULT\\Keyboard Layout\\Preload' -ErrorAction SilentlyContinue\n\
             $up = Get-ItemProperty 'HKCU:\\Keyboard Layout\\Preload' -ErrorAction SilentlyContinue\n\
             if ($d.LocaleName -eq (Get-Culture).Name -and $dp.'1' -eq $up.'1') { 'same' }"
                .to_owned(),
            "Copy-UserInternationalSettingsToSystem -WelcomeScreen $true -NewUser $true".to_owned(),
        ),
    }
}

fn ps_exe(shell: Shell) -> &'static str {
    if shell == Shell::Pwsh { "pwsh.exe" } else { "powershell.exe" }
}

/// Runs an inline cmd command. `cmd /c` only runs the first line of what it's given, so a
/// multi-line command is written to a batch file and run from there. Leading `# title` lines
/// are Groundhog's naming convention, not cmd syntax, so they're left out of what cmd sees.
pub(crate) fn cmd(command: &str) -> Result<Proc> {
    let lines: Vec<&str> =
        command.lines().skip_while(|l| l.trim().is_empty() || l.trim_start().starts_with('#')).collect();
    if lines.len() <= 1 {
        let line = lines.first().copied().unwrap_or_default();
        return Ok(Proc::new("cmd.exe").args(["/d", "/s", "/c"]).raw(Some(&format!("\"{line}\""))));
    }
    let body = format!("@echo off\r\n{}\r\n", lines.join("\r\n"));
    let dir = std::env::temp_dir().join("groundhog").join("cmd");
    std::fs::create_dir_all(&dir)?;
    let batch = dir.join(format!("{}.cmd", &groundhog_core::fetch::sha256_hex(body.as_bytes())[..16]));
    std::fs::write(&batch, body).with_context(|| format!("writing {}", batch.display()))?;
    Ok(Proc::new("cmd.exe").args(["/d", "/s", "/c"]).raw(Some(&format!("\"\"{}\"\"", batch.display()))))
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

/// Copies `src` over `dest` unless they already match, through a temp file so `dest` is
/// never half-written. Compares sizes, then hashes, without reading either into memory.
fn copy_if_different(src: &Path, dest: &Path) -> Result<bool> {
    let same = match (std::fs::metadata(src), std::fs::metadata(dest)) {
        (Ok(a), Ok(b)) if a.len() == b.len() => {
            groundhog_core::fetch::sha256_file(src)? == groundhog_core::fetch::sha256_file(dest)?
        }
        _ => false,
    };
    if same {
        return Ok(false);
    }
    let dir = dest.parent().context("destination has no parent directory")?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let tmp = dest.with_extension("groundhog.tmp");
    std::fs::copy(src, &tmp).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, dest).with_context(|| format!("replacing {}", dest.display()))?;
    Ok(true)
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
fn replace_with_zip(zip: &Path, dest: &Path, strip: usize) -> Result<()> {
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
    if let Err(e) = archive::unzip_file(zip, &staging, strip) {
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
            changed |= copy_if_different(&entry.path(), &target)?;
        }
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use groundhog_core::model::InputLanguage;

    use super::*;

    #[test]
    fn shortcut_checks_read_the_desktop() {
        // Read-only: a shortcut nobody has is missing, and removing it is already done.
        let name = format!("groundhog-test-{}-'quoted'", std::process::id());
        let mut d = DesktopShortcut {
            name,
            target: Some(r"%SystemRoot%\notepad.exe".into()),
            args: None,
            icon: None,
            state: groundhog_core::model::Presence::Present,
        };
        assert!(shortcut_differs(&d).unwrap());
        d.state = groundhog_core::model::Presence::Absent;
        assert!(!shortcut_differs(&d).unwrap());
    }

    #[test]
    fn language_checks_see_this_machines_own_settings_as_the_same() {
        // Read-only: each check, asked for what this machine already has, finds nothing to do.
        let ps = |s: &str| {
            let out = Proc { capture_stdout: true, ..powershell(Shell::Powershell, s) }.run(&mut |_| {}).unwrap();
            out.stdout.trim().to_owned()
        };
        let culture = ps("(Get-Culture).Name");
        let locale = ps("(Get-WinSystemLocale).Name");
        let region =
            ps("$g = (Get-WinHomeLocation).GeoId; [Globalization.CultureInfo]::GetCultures('SpecificCultures') | \
             ForEach-Object { [Globalization.RegionInfo]::new($_.Name) } | Where-Object GeoId -eq $g | \
             Select-Object -First 1 -ExpandProperty TwoLetterISORegionName");
        let first = ps("(Get-WinUserLanguageList)[0].LanguageTag");
        let utf8 = ps("(Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage).ACP") == "65001";
        for l in [
            LanguageSetting::Formats { tag: culture.clone() },
            LanguageSetting::SystemLocale { tag: locale },
            LanguageSetting::Location { region },
            LanguageSetting::Utf8 { on: utf8 },
        ] {
            assert!(!language_differs(&l).unwrap(), "{l:?}");
        }
        assert!(
            language_differs(&LanguageSetting::Formats {
                tag: if culture == "fr-FR" { "de-DE" } else { "fr-FR" }.into()
            })
            .unwrap()
        );
        // A one-language list differs unless this machine types in exactly that one language.
        let only = LanguageSetting::Input { languages: vec![InputLanguage { tag: first, keyboards: Vec::new() }] };
        let count = ps("(Get-WinUserLanguageList).Count");
        if count == "1" {
            assert!(!language_differs(&only).unwrap());
        }
    }

    #[test]
    fn reads_the_installed_version_from_winget_list() {
        let out = "   - \r   \\ \r\nName         Id       Version     Available Source\n--------------------------------------------------\nGit          Git.Git  2.47.0      2.48.1    winget\n";
        assert_eq!(version_from_list(out, "git.git").as_deref(), Some("2.47.0"));
        let fuzzy = "Name Id Version\n------\nTool Vendor.Tool < 1.2.3 winget\n";
        assert_eq!(version_from_list(fuzzy, "Vendor.Tool").as_deref(), Some("< 1.2.3"));
        assert_eq!(version_from_list("No installed package found", "Git.Git"), None);
    }

    #[test]
    fn refuses_to_remove_roots_and_system_folders() {
        for p in [r"C:\", r"C:\Windows", r"C:\Users", r"C:\Program Files", r"C:\Program Files\"] {
            assert!(refuse_protected(Path::new(p)).is_err(), "{p}");
        }
        let profile = std::env::var("USERPROFILE").unwrap();
        assert!(refuse_protected(Path::new(&profile)).is_err());
        assert!(refuse_protected(Path::new(r"C:\tools\old")).is_ok());
        assert!(refuse_protected(Path::new(r"C:\Program Files\Old Tool")).is_ok());
    }

    fn secrets(pairs: &[(&str, &str)]) -> Secrets {
        pairs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect()
    }

    #[test]
    fn values_fill_in_text_but_commands_get_an_environment_variable() {
        let s = secrets(&[("TOKEN", "t0k-en")]);
        assert_eq!(fill(&s, r#"{"token": "${secret:TOKEN}"}"#).unwrap(), r#"{"token": "t0k-en"}"#);
        assert_eq!(fill(&s, "literal $${secret:TOKEN}").unwrap(), "literal ${secret:TOKEN}");
        assert!(fill(&s, "${secret:OTHER}").unwrap_err().to_string().contains("OTHER was not provided"));

        let (ps, env) = secrets_as_env(&s, "Set-Thing -Token ${secret:TOKEN}", Shell::Powershell).unwrap();
        assert_eq!(ps, "Set-Thing -Token ${env:GROUNDHOG_SECRET_TOKEN}");
        assert_eq!(env, [("GROUNDHOG_SECRET_TOKEN".to_owned(), "t0k-en".to_owned())]);
        assert!(!ps.contains("t0k-en"), "the value never enters the script text");
        let (cmd, _) = secrets_as_env(&s, "tool.exe --token \"${secret:TOKEN}\"", Shell::Cmd).unwrap();
        assert_eq!(cmd, "tool.exe --token \"%GROUNDHOG_SECRET_TOKEN%\"");
    }

    #[test]
    fn a_secret_with_quotes_reaches_powershell_intact_and_cant_inject() {
        // A value that would break or inject into a script if spliced in as text.
        let nasty = r#"p'a"ss; exit 7 $(exit 9)"#;
        let s = secrets(&[("PW", nasty)]);
        let script =
            format!("if (\"${{secret:PW}}\" -ceq '{}') {{ exit 0 }} else {{ exit 5 }}", nasty.replace('\'', "''"));
        let (command, env) = secrets_as_env(&s, &script, Shell::Powershell).unwrap();
        let proc = Proc { env, ..powershell(Shell::Powershell, &command) };
        assert_eq!(proc.run(&mut |_| {}).unwrap().code, 0);
        assert!(!proc.args.iter().any(|a| a.contains("ss; exit 7")), "not on the command line");
        let encoded = proc.args.last().unwrap();
        let decoded = base64::engine::general_purpose::STANDARD.decode(encoded).unwrap();
        let text =
            String::from_utf16_lossy(&decoded.chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<_>>());
        assert!(text.contains("${env:GROUNDHOG_SECRET_PW}"));
    }

    #[test]
    fn registry_strings_fill_and_numbers_pass_through() {
        let s = secrets(&[("K", "value-1")]);
        let r = RegistryValue {
            key: r"HKCU\Software\X".into(),
            name: Some("Token".into()),
            kind: RegistryType::String,
            data: RegistryData::MultiString(vec!["a=${secret:K}".into(), "b".into()]),
            scope: vec![HiveScope::CurrentUser],
            state: groundhog_core::model::Presence::Present,
            group_policy: false,
        };
        assert_eq!(
            fill_registry(&s, &r).unwrap().data,
            RegistryData::MultiString(vec!["a=value-1".into(), "b".into()])
        );
        let n = RegistryValue { data: RegistryData::Dword(3), ..r };
        assert_eq!(fill_registry(&s, &n).unwrap().data, RegistryData::Dword(3));
    }

    #[test]
    fn replacing_a_folder_drops_stale_files_and_survives_a_running_program() {
        let zips = tempfile::tempdir().unwrap();
        let zip = |files: &[(&str, &str)]| {
            use std::io::Write;
            let mut bytes = Vec::new();
            let mut z = zip::ZipWriter::new(std::io::Cursor::new(&mut bytes));
            for (name, body) in files {
                z.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
                z.write_all(body.as_bytes()).unwrap();
            }
            z.finish().unwrap();
            let path = zips.path().join(format!("{}.zip", files[0].1));
            std::fs::write(&path, bytes).unwrap();
            path
        };
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("app");
        replace_with_zip(&zip(&[("a.txt", "1"), ("sub/stale.txt", "x")]), &dest, 0).unwrap();
        replace_with_zip(&zip(&[("a.txt", "2")]), &dest, 0).unwrap();
        assert_eq!(std::fs::read_to_string(dest.join("a.txt")).unwrap(), "2");
        assert!(!dest.join("sub").exists(), "files the new archive lacks are gone");

        // A program running from the folder doesn't block an update, even twice in a row.
        std::fs::copy(r"C:\Windows\System32\cmd.exe", dest.join("holder.exe")).unwrap();
        let mut holder = std::process::Command::new(dest.join("holder.exe"))
            .args(["/c", "ping -n 3 127.0.0.1 >nul"])
            .spawn()
            .unwrap();
        replace_with_zip(&zip(&[("a.txt", "3")]), &dest, 0).unwrap();
        replace_with_zip(&zip(&[("a.txt", "4")]), &dest, 0).unwrap();
        assert_eq!(std::fs::read_to_string(dest.join("a.txt")).unwrap(), "4");
        holder.wait().unwrap();

        // Once nothing holds the old copy, the next update cleans it up.
        replace_with_zip(&zip(&[("a.txt", "5")]), &dest, 0).unwrap();
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
    fn multi_line_cmd_commands_run_every_line() {
        let mut lines = Vec::new();
        let out = cmd("# a title, not a command\necho one\necho two\nexit 7")
            .unwrap()
            .run(&mut |l| lines.push(l.to_owned()))
            .unwrap();
        assert_eq!(lines, ["one", "two"]);
        assert_eq!(out.code, 7, "the batch's own exit code comes through");

        let mut single = Vec::new();
        cmd("echo \"quoted & fine\"").unwrap().run(&mut |l| single.push(l.to_owned())).unwrap();
        assert_eq!(single, ["\"quoted & fine\""]);
    }

    #[test]
    fn exit_codes_map_to_outcomes() {
        assert!(matches!(exit_to_outcome(0, "x").unwrap(), Outcome::Done { changed: true }));
        assert!(matches!(exit_to_outcome(3010, "x").unwrap(), Outcome::RebootRequired));
        assert!(exit_to_outcome(1, "x").is_err());
    }
}
