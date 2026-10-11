//! Undo: before a step changes the machine, what it changes is noted, so `undo` can put it
//! back. One journal per Groundhogfile, in `<home>\undo\<source>`; for each thing changed only
//! the state from before the first change is kept, so undoing after several applies goes all
//! the way back.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use groundhog_core::engine::{Action, Probe, Step};
use groundhog_core::fetch::sha256_hex;
use groundhog_core::model::{
    App, DefenderSetting, ExclusionKind, HiveScope, NetSetting, Shell, ShellSetting, SshSetting, TaskState,
};
use groundhog_win::{env, registry};
use serde::{Deserialize, Serialize};

use crate::exec::{WinExecutor, powershell};

/// How to put one thing back.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum Op {
    /// A registry value as it was (type number and base64 bytes), or absent.
    /// `new_key`: the key wasn't there either, so it goes too once it's empty.
    Registry {
        key: String,
        name: Option<String>,
        prior: Option<(u32, String)>,
        #[serde(default)]
        new_key: bool,
    },
    Env {
        machine: bool,
        name: String,
        prior: Option<String>,
    },
    Path {
        machine: bool,
        dir: String,
        was_there: bool,
    },
    /// A file as it was (a copy kept in the journal's folder), or absent.
    File {
        path: PathBuf,
        backup: Option<String>,
    },
    PowerShell {
        script: String,
    },
    WingetUninstall {
        id: String,
    },
    /// Can't be undone; said so when undoing.
    Not {
        why: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    /// What was changed: entries for the same thing aren't noted twice.
    pub target: String,
    /// The step that changed it.
    pub step: String,
    pub op: Op,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Journal {
    pub entries: Vec<Entry>,
}

/// One Groundhogfile's journal and the file copies it keeps.
#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn for_source(home: &Path, source: &url::Url) -> Self {
        Self { dir: home.join("undo").join(&sha256_hex(source.as_str().as_bytes())[..16]) }
    }

    fn journal_path(&self) -> PathBuf {
        self.dir.join("journal.json")
    }

    pub fn load(&self) -> Result<Journal> {
        match std::fs::read(self.journal_path()) {
            Ok(bytes) => serde_json::from_slice(&bytes).context("reading the undo journal"),
            Err(_) => Ok(Journal::default()),
        }
    }

    fn save(&self, j: &Journal) -> Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        std::fs::write(self.journal_path(), serde_json::to_vec_pretty(j)?).context("writing the undo journal")
    }

    /// Adds entries for things not noted yet; what's noted keeps its earliest state.
    pub fn record(&self, entries: Vec<Entry>) -> Result<()> {
        let mut j = self.load()?;
        for e in entries {
            if !j.entries.iter().any(|x| x.target == e.target) {
                j.entries.push(e);
            }
        }
        self.save(&j)
    }

    /// A copy of `path` as it is now, unless one is kept already (that one is older).
    fn backup(&self, path: &Path) -> Result<Option<String>> {
        if !path.is_file() {
            return Ok(None);
        }
        let name = sha256_hex(path.to_string_lossy().to_ascii_lowercase().as_bytes())[..16].to_owned();
        let copy = self.dir.join("files").join(&name);
        if !copy.exists() {
            std::fs::create_dir_all(copy.parent().expect("has a folder"))?;
            std::fs::copy(path, &copy).with_context(|| format!("keeping a copy of {}", path.display()))?;
        }
        Ok(Some(name))
    }

    pub fn remove(&self) -> Result<()> {
        if self.dir.exists() {
            std::fs::remove_dir_all(&self.dir)?;
        }
        Ok(())
    }
}

fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// What a read-only PowerShell script prints.
fn ps_out(script: &str) -> Result<String> {
    let out = groundhog_win::process::Proc {
        capture_stdout: true,
        ..powershell(Shell::Powershell, &format!("$ErrorActionPreference = 'Stop'\n{script}"))
    }
    .run(&mut |_| {})?;
    if out.code != 0 {
        bail!("PowerShell exited with {}", out.code);
    }
    Ok(out.stdout.trim_end().to_owned())
}

/// What undoing `step` would take, found before it runs. Nothing when it changes nothing.
pub fn before(exec: &mut WinExecutor, step: &Step, store: &Store) -> Result<Vec<Entry>> {
    use groundhog_core::engine::Executor as _;
    if matches!(exec.check(step), Ok(Probe::Satisfied)) {
        return Ok(Vec::new());
    }
    let title = step.title.clone();
    let entry = |target: String, op: Op| Entry { target, step: title.clone(), op };
    let not = |why: &str| {
        vec![Entry { target: format!("step {}", step.id), step: title.clone(), op: Op::Not { why: why.to_owned() } }]
    };
    let file = |path: PathBuf| -> Result<Entry> {
        if path.is_dir() {
            return Ok(Entry {
                target: format!("file {}", path.display()),
                step: title.clone(),
                op: Op::Not { why: "a folder isn't put back".to_owned() },
            });
        }
        let backup = store.backup(&path)?;
        Ok(Entry {
            target: format!("file {}", path.display().to_string().to_ascii_lowercase()),
            step: title.clone(),
            op: Op::File { path, backup },
        })
    };
    Ok(match &step.action {
        Action::Registry(r) if r.group_policy => not("Group Policy values aren't put back"),
        Action::Registry(r) if r.name.is_none() && !r.state.is_present() => not("a deleted key isn't put back"),
        Action::Registry(r) => {
            let (root, sub) = registry::split_key(&r.key)?;
            let mut out = Vec::new();
            for scope in &r.scope {
                let target = format!("registry {}\\{}", r.key, r.name.as_deref().unwrap_or("(default)")).to_ascii_lowercase();
                match scope {
                    HiveScope::CurrentUser => {
                        let prior = registry::get_raw(&root, &sub, r.name.as_deref())
                            .map(|(t, b)| (t, base64::engine::general_purpose::STANDARD.encode(b)));
                        let new_key = !registry::key_exists(&root, &sub);
                        out.push(entry(target, Op::Registry { key: r.key.clone(), name: r.name.clone(), prior, new_key }));
                    }
                    HiveScope::DefaultUser => out.push(entry(
                        format!("default profile {target}"),
                        Op::Not { why: "values in the Default profile (for accounts made later) aren't put back".to_owned() },
                    )),
                }
            }
            out
        }
        Action::Env { name, scope, .. } => {
            let machine = matches!(scope, groundhog_core::model::EnvScope::Machine);
            let s = if machine { env::Scope::Machine } else { env::Scope::User };
            vec![entry(
                format!("env {} {}", if machine { "machine" } else { "user" }, name.to_ascii_lowercase()),
                Op::Env { machine, name: name.clone(), prior: env::get_var(s, name) },
            )]
        }
        Action::Path { dir, scope, .. } => {
            let machine = matches!(scope, groundhog_core::model::EnvScope::Machine);
            let s = if machine { env::Scope::Machine } else { env::Scope::User };
            vec![entry(
                format!("path {} {}", if machine { "machine" } else { "user" }, dir.to_ascii_lowercase()),
                Op::Path { machine, dir: dir.clone(), was_there: env::path_contains(s, dir)? },
            )]
        }
        Action::File(f) if f.extract => not("unpacked folders aren't put back"),
        Action::File(f) => vec![file(PathBuf::from(env::expand_path(&f.to)?))?],
        Action::Service(s) => {
            let key = format!(r"SYSTEM\CurrentControlSet\Services\{}", s.name);
            let (hklm, _) = registry::split_key(r"HKLM\SYSTEM")?;
            if !registry::key_exists(&hklm, &key) {
                return Ok(Vec::new());
            }
            let dword = |name: &str| {
                registry::get_raw(&hklm, &key, Some(name))
                    .and_then(|(_, b)| b.get(..4).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]])))
            };
            let (start, delayed) = (dword("Start").unwrap_or(3), dword("DelayedAutostart").unwrap_or(0));
            let mode = match (start, delayed) {
                (2, 1) => "delayed-auto",
                (2, _) => "auto",
                (4, _) => "disabled",
                _ => "demand",
            };
            let running = groundhog_win::system::service_status(&s.name)?
                .is_some_and(|st| st == groundhog_win::system::ServiceStatus::Running);
            let name = &s.name;
            let status = if running {
                format!("Start-Service -Name {}", quote(name))
            } else {
                format!("Stop-Service -Name {} -Force", quote(name))
            };
            vec![entry(
                format!("service {}", name.to_ascii_lowercase()),
                Op::PowerShell {
                    script: format!(
                        "cmd /d /c \"sc.exe config \"\"{name}\"\" start= {mode} >nul 2>&1\"\n\
                         if ($LASTEXITCODE -ne 0) {{ throw \"sc.exe config exited with $LASTEXITCODE\" }}\n{status}"
                    ),
                },
            )]
        }
        Action::Feature(f) => vec![entry(
            format!("feature {}", f.name.to_ascii_lowercase()),
            Op::PowerShell {
                script: if f.enabled {
                    format!("Disable-WindowsOptionalFeature -Online -FeatureName {} -NoRestart | Out-Null", quote(&f.name))
                } else {
                    format!("Enable-WindowsOptionalFeature -Online -FeatureName {} -NoRestart | Out-Null", quote(&f.name))
                },
            },
        )],
        Action::Capability(c) => vec![entry(
            format!("capability {}", c.name.to_ascii_lowercase()),
            Op::PowerShell {
                script: if c.present {
                    format!("Remove-WindowsCapability -Online -Name {} | Out-Null", quote(&c.name))
                } else {
                    format!("Add-WindowsCapability -Online -Name {} | Out-Null", quote(&c.name))
                },
            },
        )],
        Action::Defender(x) => {
            let kind = match x.kind {
                ExclusionKind::Path => "ExclusionPath",
                ExclusionKind::Process => "ExclusionProcess",
                ExclusionKind::Extension => "ExclusionExtension",
            };
            let verb = if x.state.is_present() { "Remove" } else { "Add" };
            vec![entry(
                format!("defender {kind} {}", x.value.to_ascii_lowercase()),
                Op::PowerShell { script: format!("{verb}-MpPreference -{kind} {}", quote(&x.value)) },
            )]
        }
        Action::Firewall(r) => {
            let existed = ps_out(&format!(
                "@(Get-NetFirewallRule -DisplayName {} -ErrorAction SilentlyContinue).Count",
                quote(&r.name)
            ))?;
            if existed.trim() != "0" {
                not("a firewall rule that was there already isn't put back as it was")
            } else {
                vec![entry(
                    format!("firewall {}", r.name.to_ascii_lowercase()),
                    Op::PowerShell { script: format!("Remove-NetFirewallRule -DisplayName {}", quote(&r.name)) },
                )]
            }
        }
        Action::App(App::Winget { id, state, .. }) if state.is_present() => {
            if exec.winget_installed(id)? {
                not("an upgrade isn't rolled back")
            } else {
                vec![entry(format!("winget {}", id.to_ascii_lowercase()), Op::WingetUninstall { id: id.clone() })]
            }
        }
        Action::App(App::Winget { .. }) => not("an uninstalled app isn't reinstalled"),
        Action::App(App::Url { .. }) => not("an app installed from a URL isn't uninstalled"),
        Action::DefenderSetting(d) => match d {
            DefenderSetting::Pref { name, .. } => {
                let prior = ps_out(&format!("[int](Get-MpPreference).{name}"))?;
                vec![entry(
                    format!("defender {}", name.to_ascii_lowercase()),
                    Op::PowerShell { script: format!("Set-MpPreference -{name} {}", prior.trim()) },
                )]
            }
            DefenderSetting::ScanTime { .. } => {
                let prior = ps_out(
                    "$t = (Get-MpPreference).ScanScheduleTime\n\
                     if ($t -is [datetime]) { $t.ToString('HH:mm') } else { '{0:hh\\:mm}' -f $t }",
                )?;
                vec![entry(
                    "defender scan time".to_owned(),
                    Op::PowerShell { script: format!("Set-MpPreference -ScanScheduleTime '{}'", prior.trim()) },
                )]
            }
            DefenderSetting::AllowedApps { paths } => {
                let list: Vec<String> = paths.iter().map(|p| quote(p)).collect();
                let missing = ps_out(&format!(
                    "$have = @((Get-MpPreference).ControlledFolderAccessAllowedApplications)\n\
                     @({}) | Where-Object {{ $have -notcontains $_ }}",
                    list.join(", ")
                ))?;
                let added: Vec<String> = missing.lines().filter(|l| !l.trim().is_empty()).map(|l| quote(l.trim())).collect();
                if added.is_empty() {
                    Vec::new()
                } else {
                    vec![entry(
                        format!("defender allowed apps {}", added.join(",").to_ascii_lowercase()),
                        Op::PowerShell {
                            script: format!(
                                "Remove-MpPreference -ControlledFolderAccessAllowedApplications @({})",
                                added.join(", ")
                            ),
                        },
                    )]
                }
            }
        },
        Action::Shell(ShellSetting::Terminal { .. }) => vec![file(crate::shell::terminal_settings_path()?)?],
        Action::Shell(ShellSetting::Profile { .. }) => {
            crate::shell::profile_paths()?.into_iter().map(file).collect::<Result<_>>()?
        }
        Action::Shell(ShellSetting::ExecutionPolicy { .. }) => {
            vec![entry("execution policy".to_owned(), Op::PowerShell { script: crate::shell::policy_undo_script()? })]
        }
        Action::Shell(ShellSetting::Module { name }) => vec![entry(
            format!("module {}", name.to_ascii_lowercase()),
            Op::PowerShell { script: format!("Uninstall-Module -Name {} -AllVersions -Force", quote(name)) },
        )],
        Action::Ssh(s) => match s {
            SshSetting::ServerConfig { .. } => vec![
                entry(
                    "sshd restart".to_owned(),
                    Op::PowerShell {
                        script: "if ((Get-Service sshd -ErrorAction SilentlyContinue).Status -eq 'Running') { Restart-Service sshd }"
                            .to_owned(),
                    },
                ),
                file(crate::ssh::program_data_ssh().join("sshd_config"))?,
            ],
            SshSetting::AuthorizedKeys { .. } => {
                vec![file(crate::ssh::program_data_ssh().join("administrators_authorized_keys"))?]
            }
            SshSetting::KnownHosts { .. } => vec![file(crate::ssh::home_ssh()?.join("known_hosts"))?],
            SshSetting::Key { kind } => {
                let key = crate::ssh::key_path(kind)?;
                vec![file(key.with_extension("pub"))?, file(key)?]
            }
        },
        Action::CreateTask(t) => {
            let (path, name) = t.path_and_name();
            let xml = ps_out(&format!(
                "$t = Get-ScheduledTask -TaskPath {} -TaskName {} -ErrorAction SilentlyContinue\n\
                 if ($t) {{ Export-ScheduledTask -TaskPath {0} -TaskName {1} }} else {{ $null = 0 }}",
                quote(path),
                quote(name)
            ))?;
            let script = if xml.trim().is_empty() {
                format!("Unregister-ScheduledTask -TaskPath {} -TaskName {} -Confirm:$false", quote(path), quote(name))
            } else {
                format!(
                    "Register-ScheduledTask -TaskPath {} -TaskName {} -Xml {} -Force | Out-Null",
                    quote(path),
                    quote(name),
                    quote(&xml)
                )
            };
            vec![entry(format!("task {}", t.name.to_ascii_lowercase()), Op::PowerShell { script })]
        }
        Action::ScheduledTask(t) => {
            let script = crate::startup::task_undo_script(t)?;
            if script.trim().is_empty() {
                Vec::new()
            } else {
                let verb = match t.state {
                    TaskState::Absent => "deleted",
                    TaskState::Disabled => "disabled",
                    TaskState::Enabled => "enabled",
                };
                vec![entry(format!("tasks {verb} {}", t.name.to_ascii_lowercase()), Op::PowerShell { script })]
            }
        }
        Action::Startup(s) => {
            let script = crate::startup::startup_undo_script(s)?;
            if script.trim().is_empty() {
                Vec::new()
            } else {
                vec![entry(format!("startup {}", s.name.to_ascii_lowercase()), Op::PowerShell { script })]
            }
        }
        Action::Network(NetSetting::HostsEntry { .. }) => {
            let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
            vec![file(PathBuf::from(root).join(r"System32\drivers\etc\hosts"))?]
        }
        Action::BitLocker(_) => not("BitLocker isn't turned off by undo (set bitlocker.system-drive: false)"),
        Action::User(_) => not("accounts aren't deleted or put back"),
        Action::Run(_) => not("commands can't be undone"),
        Action::RemoveApp { .. } => not("removed apps aren't reinstalled"),
        Action::Verify(_) | Action::EnsureWinget | Action::RestartExplorer { .. } => Vec::new(),
        other => not(&format!("{} settings aren't undone yet", groundhog_core::report::label(groundhog_core::engine::section(other)))),
    })
}

/// What an undo did.
#[derive(Debug, Default)]
pub struct Undone {
    pub undone: usize,
    pub kept: Vec<(String, String)>,
    pub failed: Vec<(String, String)>,
}

/// Puts back everything in the journal, newest first. What's put back (or can't ever be)
/// leaves the journal; what fails stays, for another try.
pub fn undo(exec: &mut WinExecutor, store: &Store, line: &mut dyn FnMut(&str, &str, &str)) -> Result<Undone> {
    let journal = store.load()?;
    let mut left = Vec::new();
    let mut done = Undone::default();
    for e in journal.entries.into_iter().rev() {
        let result = match &e.op {
            Op::Not { why } => {
                line("kept", &e.step, why);
                done.kept.push((e.step.clone(), why.clone()));
                continue;
            }
            op => put_back(exec, store, op),
        };
        match result {
            Ok(()) => {
                line("undone", &e.step, "");
                done.undone += 1;
            }
            Err(err) => {
                let msg = format!("{err:#}");
                line("failed", &e.step, &msg);
                done.failed.push((e.step.clone(), msg));
                left.push(e);
            }
        }
    }
    if left.is_empty() {
        store.remove()?;
    } else {
        left.reverse();
        store.save(&Journal { entries: left })?;
    }
    Ok(done)
}

fn put_back(exec: &mut WinExecutor, store: &Store, op: &Op) -> Result<()> {
    let log = &mut |_: &str| {};
    match op {
        Op::Registry { key, name, prior, new_key } => {
            let (root, sub) = registry::split_key(key)?;
            match prior {
                Some((vtype, data)) => {
                    let bytes = base64::engine::general_purpose::STANDARD.decode(data)?;
                    registry::set_raw(&root, &sub, name.as_deref(), *vtype, &bytes)?;
                }
                None => {
                    registry::delete_value(&root, &sub, name.as_deref())?;
                    if *new_key && registry::key_is_empty(&root, &sub) {
                        registry::delete_key(&root, &sub)?;
                    }
                }
            }
        }
        Op::Env { machine, name, prior } => {
            let s = if *machine { env::Scope::Machine } else { env::Scope::User };
            match prior {
                Some(v) => env::set_var(s, name, v)?,
                None => env::remove_var(s, name)?,
            };
            env::broadcast_change();
        }
        Op::Path { machine, dir, was_there } => {
            let s = if *machine { env::Scope::Machine } else { env::Scope::User };
            if *was_there {
                env::add_path(s, dir)?;
            } else {
                env::remove_path(s, dir)?;
            }
            env::broadcast_change();
        }
        Op::File { path, backup } => match backup {
            Some(name) => {
                std::fs::create_dir_all(path.parent().context("a file has a folder")?)?;
                std::fs::copy(store.dir.join("files").join(name), path)
                    .with_context(|| format!("putting back {}", path.display()))?;
            }
            None => {
                if path.is_file() {
                    std::fs::remove_file(path).with_context(|| format!("deleting {}", path.display()))?;
                }
            }
        },
        Op::PowerShell { script } => {
            let out = powershell(Shell::Powershell, &format!("$ErrorActionPreference = 'Stop'\n{script}")).run(log)?;
            if out.code != 0 {
                bail!("PowerShell exited with {}", out.code);
            }
        }
        Op::WingetUninstall { id } => exec.winget_uninstall(id, log)?,
        Op::Not { .. } => {}
    }
    Ok(())
}
