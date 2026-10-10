//! Turning a Groundhogfile into ordered steps and running them resumably.
//!
//! Each step's id is a hash of what it does. A run records completed ids in a state file, so
//! re-running after a reboot, a failure or an edit to the Groundhogfile skips what is already
//! done and runs only what is new or failed.

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::fetch::{file_name, sha256_hex};
use crate::loader::LoadedSource;
use crate::model::{
    App, Capability, CertScope, Certificate, Check, DefenderExclusion, EnvScope, Feature, FileCopy, FirewallRule,
    Groundhogfile, LanguageSetting, LockScreen, Presence, RegistryData, RegistryValue, RunAction, ScreenSaver, Service,
    ServiceState, StartPins, Theme, ThemeMode, TrayIcon, User, Wallpaper,
};
use crate::report::Reporter;
use crate::secret::{self, Redactor};

/// Stop asking for reboots after this many in one run; something is looping.
pub const MAX_REBOOTS: u32 = 5;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "action", rename_all = "kebab-case")]
pub enum Action {
    EnsureWinget,
    App(App),
    File(FileCopy),
    Env {
        name: String,
        value: String,
        #[serde(skip_serializing_if = "EnvScope::is_user")]
        scope: EnvScope,
        #[serde(skip_serializing_if = "Presence::is_present")]
        state: Presence,
    },
    Path {
        dir: String,
        #[serde(skip_serializing_if = "EnvScope::is_user")]
        scope: EnvScope,
        #[serde(skip_serializing_if = "Presence::is_present")]
        state: Presence,
    },
    Registry(RegistryValue),
    Run(RunAction),
    User(User),
    Feature(Feature),
    Capability(Capability),
    Verify(Check),
    Certificate(Certificate),
    Service(Service),
    Firewall(FirewallRule),
    Defender(DefenderExclusion),
    /// A built-in Store app to remove, by package name (wildcards allowed).
    RemoveApp {
        name: String,
    },
    Wallpaper(Wallpaper),
    Theme(Theme),
    LockScreen(LockScreen),
    ScreenSaver(ScreenSaver),
    TrayIcon(TrayIcon),
    /// Do Not Disturb on or off, for the agent's user, from the next sign-in.
    DoNotDisturb {
        on: bool,
    },
    /// Start's pinned apps, from a layout file.
    StartPins(StartPins),
    Language(LanguageSetting),
}

impl Action {
    /// Checks describe health, not changes, and `always: true` run steps ask for it: these
    /// run on every apply.
    pub fn always_runs(&self) -> bool {
        match self {
            Action::Verify(_) => true,
            Action::Run(r) => r.always(),
            // Whether there's a newer version changes without the file changing.
            Action::App(App::Winget { upgrade: true, .. }) => true,
            // Windows makes a program's tray entry only once it shows an icon, maybe after
            // this apply; looking again each time is cheap and catches it then.
            Action::TrayIcon(_) => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Step {
    pub id: String,
    pub title: String,
    pub action: Action,
}

fn title(action: &Action) -> String {
    let base = match action {
        Action::EnsureWinget => "ensure winget is available".into(),
        Action::App(App::Winget { id, state: Presence::Absent, .. }) => format!("uninstall {id} (winget)"),
        Action::App(App::Winget { id, version: Some(v), .. }) => format!("install {id} {v} (winget)"),
        Action::App(App::Winget { id, upgrade: true, .. }) => format!("install or upgrade {id} (winget)"),
        Action::App(App::Winget { id, .. }) => format!("install {id} (winget)"),
        Action::App(App::Url { id, url, .. }) => format!("install {id} from {}", file_name(url)),
        Action::File(FileCopy { state: Presence::Absent, to, .. }) => format!("remove {to}"),
        Action::File(FileCopy { from: None, to, .. }) => format!("write {to}"),
        Action::File(f @ FileCopy { from: Some(from), .. }) => {
            // A release's source archive is named after its tag; "source" reads better next to "@tag".
            let name = if f.release.is_some() && from.path().contains("/archive/refs/tags/") {
                "source".to_owned()
            } else {
                file_name(from)
            };
            format!("copy {name} -> {}", f.to)
        }
        Action::Env { name, scope, state, .. } => {
            let verb = if state.is_present() { "set" } else { "remove" };
            let machine = if *scope == EnvScope::Machine { "machine " } else { "" };
            format!("{verb} {machine}env {name}")
        }
        Action::Path { dir, scope, state } => {
            let which = if *scope == EnvScope::Machine { "machine PATH" } else { "PATH" };
            if state.is_present() { format!("add {dir} to {which}") } else { format!("remove {dir} from {which}") }
        }
        Action::Registry(RegistryValue { key, name: None, state: Presence::Absent, .. }) => {
            format!("delete key {key}")
        }
        Action::Registry(r) if !r.state.is_present() => {
            format!("delete {}\\{}", r.key, r.name.as_deref().unwrap_or("(default)"))
        }
        Action::Registry(r) => format!("set {}\\{}", r.key, r.name.as_deref().unwrap_or("(default)")),
        Action::Certificate(c) => {
            let what = c
                .from
                .as_ref()
                .map(file_name)
                .or_else(|| c.thumbprint.as_ref().map(|t| format!("certificate {}", &t[..8])))
                .unwrap_or_default();
            let scope = if c.scope == CertScope::Machine { "machine" } else { "user" };
            let store = c.store.system_name();
            if c.state.is_present() {
                format!("add {what} to {scope} {store} certificates")
            } else {
                format!("remove {what} from {scope} {store} certificates")
            }
        }
        Action::Service(s) => {
            let mut parts = Vec::new();
            if let Some(t) = s.startup {
                parts.push(format!("{t:?}").to_ascii_lowercase());
            }
            if let Some(st) = s.status {
                parts.push(format!("{st:?}").to_ascii_lowercase());
            }
            format!("service {}: {}", s.name, parts.join(", "))
        }
        Action::Firewall(r) if r.state.is_present() => format!("firewall rule {}", r.name),
        Action::Firewall(r) => format!("remove firewall rule {}", r.name),
        Action::Defender(e) => {
            let kind = format!("{:?}", e.kind).to_ascii_lowercase();
            if e.state.is_present() {
                format!("exclude {kind} {} from Defender", e.value)
            } else {
                format!("stop excluding {kind} {} from Defender", e.value)
            }
        }
        Action::RemoveApp { name } => format!("remove built-in app {name}"),
        Action::Wallpaper(w) => {
            let mut parts = Vec::new();
            if let Some(from) = &w.from {
                parts.push(format!("{} ({})", file_name(from), format!("{:?}", w.style).to_ascii_lowercase()));
            }
            if let Some(color) = &w.background {
                parts.push(format!("background {color}"));
            }
            format!("set wallpaper {}", parts.join(", "))
        }
        Action::LockScreen(l) => {
            let mut parts = Vec::new();
            if let Some(image) = &l.image {
                parts.push(format!("picture {}", file_name(image)));
            }
            if let Some(secs) = l.lock_after_secs {
                parts.push(format!("lock after {}", humantime::format_duration(std::time::Duration::from_secs(secs))));
            }
            format!("set lock screen: {}", parts.join(", "))
        }
        Action::DoNotDisturb { on } => {
            format!("turn Do Not Disturb {} (from the next sign-in)", if *on { "on" } else { "off" })
        }
        Action::StartPins(p) => format!("pin Start's apps as {} has them", file_name(&p.from)),
        Action::Language(l) => match l {
            LanguageSetting::Input { languages } => {
                let tags: Vec<&str> = languages.iter().map(|l| l.tag.as_str()).collect();
                format!("type in {}", tags.join(", "))
            }
            LanguageSetting::Display { tag, machine: false } => {
                format!("show Windows in {tag} (from the next sign-in)")
            }
            LanguageSetting::Display { tag, machine: true } => {
                format!("show Windows in {tag}, also at sign-in and for new accounts (after a restart)")
            }
            LanguageSetting::Formats { tag } => format!("use {tag} formats for dates, times and numbers"),
            LanguageSetting::Location { region } => format!("set the home location to {region}"),
            LanguageSetting::SystemLocale { tag } => {
                format!("use {tag} for programs that don't use Unicode (after a restart)")
            }
            LanguageSetting::Utf8 { on } => format!(
                "turn UTF-8 for programs that don't use Unicode {} (after a restart)",
                if *on { "on" } else { "off" }
            ),
            LanguageSetting::CopyToSystem => "copy these to the sign-in screen and new accounts".to_owned(),
        },
        Action::TrayIcon(t) if t.shown => format!("show {}'s icon on the taskbar", t.program),
        Action::TrayIcon(t) => format!("move {}'s icon to the overflow", t.program),
        Action::ScreenSaver(s) if !s.enabled => "turn the screen saver off".to_owned(),
        Action::ScreenSaver(s) => {
            let name =
                s.program.as_deref().map(|p| p.rsplit(['\\', '/']).next().unwrap_or(p)).unwrap_or("screen saver");
            let mut parts = vec![name.to_owned()];
            if let Some(secs) = s.timeout_secs {
                parts.push(format!("after {}", humantime::format_duration(std::time::Duration::from_secs(secs))));
            }
            if s.secure == Some(true) {
                parts.push("sign-in to resume".to_owned());
            }
            format!("set screen saver: {}", parts.join(", "))
        }
        Action::Theme(t) => match (t.apps, t.windows) {
            (Some(a), Some(w)) if a == w => format!("set {} theme", format!("{a:?}").to_ascii_lowercase()),
            (a, w) => {
                let part = |who: &str, m: Option<ThemeMode>| {
                    m.map(|m| format!("{who} {}", format!("{m:?}").to_ascii_lowercase()))
                };
                let parts: Vec<String> = [part("apps", a), part("windows", w)].into_iter().flatten().collect();
                format!("set theme: {}", parts.join(", "))
            }
        },
        Action::Run(RunAction::Command { command, .. }) => format!("run: {}", command_title(command)),
        Action::Run(RunAction::Script { script, .. }) => format!("run script {}", file_name(script)),
        Action::Run(RunAction::Plugin { plugin, .. }) => format!("run plugin {}", file_name(plugin)),
        Action::Verify(c) => format!("verify {}", check_title(c)),
        Action::Feature(f) if f.enabled => format!("enable feature {}", f.name),
        Action::Feature(f) => format!("disable feature {}", f.name),
        Action::Capability(c) if c.present => format!("add capability {}", c.name),
        Action::Capability(c) => format!("remove capability {}", c.name),
        Action::User(u) if !u.state.is_present() => format!("delete user {}", u.name),
        Action::User(u) if u.groups.is_empty() => format!("user {}", u.name),
        Action::User(u) => format!("user {} ({})", u.name, u.groups.join(", ")),
    };
    // Say which build a machine got: the GitHub release when there is one, otherwise the
    // content hash an unpinned reference resolved to.
    match build_label(action) {
        Some(label) => format!("{base} @{label}"),
        None => base,
    }
}

fn build_label(action: &Action) -> Option<String> {
    let (release, resolved) = match action {
        Action::App(App::Url { release, resolved, .. }) | Action::File(FileCopy { release, resolved, .. }) => {
            (release.as_deref(), resolved.as_deref())
        }
        Action::Certificate(Certificate { resolved, .. })
        | Action::Wallpaper(Wallpaper { resolved, .. })
        | Action::StartPins(StartPins { resolved, .. })
        | Action::LockScreen(LockScreen { resolved, .. }) => (None, resolved.as_deref()),
        Action::Run(RunAction::Script { resolved, .. } | RunAction::Plugin { resolved, .. }) => {
            (None, resolved.as_deref())
        }
        _ => (None, None),
    };
    release.map(str::to_owned).or_else(|| resolved.map(|h| h[..8].to_owned()))
}

fn check_title(c: &Check) -> String {
    match c {
        Check::Process { name, stable_for_ms: 0, .. } => format!("process {name} is running"),
        Check::Process { name, stable_for_ms, .. } => {
            format!("process {name} stays up {}s", stable_for_ms.div_ceil(1000))
        }
        Check::Service { name, status: ServiceState::Running, .. } => format!("service {name} is running"),
        Check::Service { name, status: ServiceState::Stopped, .. } => format!("service {name} is stopped"),
        Check::EventLog { provider, must_contain, must_not_contain, .. } => {
            let mut parts: Vec<String> = must_contain.iter().map(|t| format!("include '{t}'")).collect();
            parts.extend(must_not_contain.iter().map(|t| format!("have no '{t}'")));
            format!("{provider} events {}", parts.join(", "))
        }
        Check::Port { host, port, .. } => format!("{host}:{port} accepts connections"),
        Check::File { path, .. } => format!("{path} exists"),
        Check::Command { command, .. } => command_title(command),
    }
}

/// A leading `# comment` names a multi-line command; otherwise its first line does.
fn command_title(command: &str) -> String {
    let first = command.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or_default();
    let (text, is_comment) = match first.strip_prefix('#') {
        Some(comment) => (comment.trim(), true),
        None => (first, false),
    };
    let short: String = text.chars().take(60).collect();
    let more = short.len() < text.len() || (!is_comment && command.trim().lines().count() > 1);
    format!("{short}{}", if more { "…" } else { "" })
}

/// Orders the work: winget first if needed, then apps, files, env, PATH, registry, and
/// finally custom `run` actions, which may depend on everything before them.
///
/// Ids work like Docker's layer cache. Declarative steps (apps, files, env, PATH, registry)
/// are identified by their own content and are independent of each other. A `run` step is
/// imperative and may depend on anything before it, so its id also covers every earlier
/// step: when any of them changes (say a "latest" download resolves to a new build), that
/// run step and every later one run again.
pub fn plan(file: &Groundhogfile) -> Vec<Step> {
    plan_with_secrets(file, &|_| None)
}

/// Like [`plan`], for a run that has the secrets. A step that uses a secret also depends on
/// its value, so a rotated token reruns it, but the value itself must never be stored: the
/// id covers `fingerprint(name)`, a salted hash the agent computes. With no fingerprint (a
/// secret that wasn't supplied) the id covers that instead.
pub fn plan_with_secrets(file: &Groundhogfile, fingerprint: &dyn Fn(&str) -> Option<String>) -> Vec<Step> {
    // Accounts first: they depend on nothing, and later steps may assume they exist.
    let mut actions: Vec<Action> = file.users.iter().cloned().map(Action::User).collect();
    // Certificates early: installers and downloads may need an internal CA.
    actions.extend(file.certificates.iter().cloned().map(Action::Certificate));
    // Defender exclusions before the big installs and unpacks they speed up.
    actions.extend(file.defender_exclusions.iter().cloned().map(Action::Defender));
    // Windows features next: apps often need them (WSL for Docker, .NET 3.5 for old
    // installers), and their restarts are best taken before long installs, not in the middle.
    actions.extend(file.features.iter().cloned().map(Action::Feature));
    actions.extend(file.capabilities.iter().cloned().map(Action::Capability));
    actions.extend(file.remove_apps.iter().map(|name| Action::RemoveApp { name: name.clone() }));
    if file.apps.iter().any(|a| matches!(a, App::Winget { .. })) {
        actions.push(Action::EnsureWinget);
    }
    actions.extend(file.apps.iter().cloned().map(Action::App));
    actions.extend(file.files.iter().cloned().map(Action::File));
    actions.extend(file.env.iter().map(|(name, v)| Action::Env {
        name: name.clone(),
        value: v.value.clone(),
        scope: v.scope,
        state: v.state,
    }));
    actions.extend(file.path.iter().map(|p| Action::Path { dir: p.dir.clone(), scope: p.scope, state: p.state }));
    actions.extend(file.registry.iter().cloned().map(Action::Registry));
    actions.extend(file.language.iter().cloned().map(Action::Language));
    actions.extend(file.wallpaper.iter().cloned().map(Action::Wallpaper));
    actions.extend(file.theme.iter().cloned().map(Action::Theme));
    actions.extend(file.lock_screen.iter().cloned().map(Action::LockScreen));
    actions.extend(file.screen_saver.iter().cloned().map(Action::ScreenSaver));
    actions.extend(file.tray_icons.iter().cloned().map(Action::TrayIcon));
    actions.extend(file.do_not_disturb.map(|on| Action::DoNotDisturb { on }));
    actions.extend(file.start_pins.iter().cloned().map(Action::StartPins));
    // Services and firewall rules after apps, which often install what they refer to.
    actions.extend(file.services.iter().cloned().map(Action::Service));
    actions.extend(file.firewall.iter().cloned().map(Action::Firewall));
    actions.extend(file.run.iter().cloned().map(Action::Run));
    actions.extend(file.verify.iter().cloned().map(Action::Verify));

    let mut chain = String::new();
    actions
        .into_iter()
        .map(|action| {
            let mut own = sha256_hex(&serde_json::to_vec(&action).expect("actions serialize"));
            let secrets = secrets_in(&action);
            if !secrets.is_empty() {
                let prints: Vec<String> = secrets
                    .iter()
                    .map(|n| format!("{n}={}", fingerprint(n).unwrap_or_else(|| "unset".into())))
                    .collect();
                own = sha256_hex(format!("{own}|{}", prints.join("|")).as_bytes());
            }
            let id = match action {
                Action::Run(_) => sha256_hex(format!("{chain}{own}").as_bytes()),
                _ => own,
            }[..16]
                .to_owned();
            chain = sha256_hex(format!("{chain}{id}").as_bytes());
            Step { title: title(&action), id, action }
        })
        .collect()
}

/// The secrets an action refers to with `${secret:NAME}`. (User passwords aren't included:
/// an existing account's password is left alone, so rotating one isn't a reason to rerun.)
pub fn secrets_in(action: &Action) -> BTreeSet<String> {
    let texts: Vec<&str> = match action {
        Action::File(FileCopy { content: Some(c), .. }) => vec![c],
        Action::Env { value, .. } => vec![value],
        Action::Registry(r) => match &r.data {
            RegistryData::String(v) => vec![v],
            RegistryData::MultiString(vs) => vs.iter().map(String::as_str).collect(),
            RegistryData::Dword(_) | RegistryData::Qword(_) | RegistryData::Binary(_) => vec![],
        },
        Action::Run(RunAction::Command { command, .. }) => vec![command],
        Action::Run(RunAction::Script { args: Some(a), .. }) => vec![a],
        _ => vec![],
    };
    // Validated when the file was loaded, so a parse error can't happen here.
    texts.into_iter().flat_map(|t| secret::names(t).unwrap_or_default()).collect()
}

pub enum Outcome {
    Done {
        changed: bool,
    },
    /// The step completed but Windows must restart before later steps can run.
    RebootRequired,
    /// The step could not run until Windows restarts; run it again afterwards.
    RetryAfterReboot,
    /// The step is done but its change finishes only after a restart, which can wait until the
    /// rest of its section has run: five features then cost one restart, not five.
    DoneRestartLater {
        changed: bool,
    },
}

/// Steps that share a section can share one deferred restart.
fn section(action: &Action) -> &'static str {
    match action {
        Action::Feature(_) | Action::Capability(_) => "windows features",
        Action::User(_) => "users",
        Action::EnsureWinget | Action::App(_) | Action::RemoveApp { .. } => "apps",
        Action::Certificate(_) => "certificates",
        Action::Wallpaper(_)
        | Action::Theme(_)
        | Action::LockScreen(_)
        | Action::ScreenSaver(_)
        | Action::TrayIcon(_)
        | Action::DoNotDisturb { .. }
        | Action::StartPins(_) => "desktop",
        Action::Defender(_) => "defender",
        Action::Service(_) => "services",
        Action::Firewall(_) => "firewall",
        Action::File(_) => "files",
        Action::Env { .. } | Action::Path { .. } => "environment",
        Action::Registry(_) => "registry",
        Action::Language(_) => "language",
        Action::Run(_) => "run",
        Action::Verify(_) => "verify",
    }
}

/// Carries out steps on the actual machine. The agent implements this; tests fake it.
pub trait Executor {
    fn execute(&mut self, step: &Step, reporter: &dyn Reporter) -> Result<Outcome>;

    /// Whether the machine already matches the step, found without changing anything.
    fn check(&mut self, _step: &Step) -> Result<Probe> {
        Ok(Probe::Unknown)
    }
}

/// What a step would do now, for `plan --check`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    /// The machine already matches; applying would change nothing.
    Satisfied,
    /// Applying would change the machine.
    WouldChange,
    /// An imperative step (`run`) or a check: it runs, whatever the machine looks like.
    WillRun,
    /// Can't tell without doing it (an installer, an archive to unpack).
    Unknown,
}

/// A step's line in a preview.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Preview {
    /// Recorded as applied by an earlier run, so `apply` skips it.
    Applied,
    Probe(Probe),
    /// The check itself failed (say, a service that doesn't exist).
    Error(String),
}

/// What `apply` would do with each step: skip what's recorded as applied, and ask the
/// executor about the rest.
pub fn preview(steps: &[Step], exec: &mut dyn Executor, state_path: &Path) -> Vec<Preview> {
    let done: HashSet<String> = read_state(state_path)
        .iter()
        .flat_map(|p| p.steps.iter().filter(|s| s.status == StepStatus::Done).map(|s| s.id.clone()))
        .collect();
    steps
        .iter()
        .map(|step| {
            if done.contains(&step.id) && !step.action.always_runs() {
                return Preview::Applied;
            }
            match exec.check(step) {
                Ok(p) => Preview::Probe(p),
                Err(e) => Preview::Error(format!("{e:#}")),
            }
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunStatus {
    Running,
    Succeeded,
    Failed,
    RebootPending,
}

impl RunStatus {
    pub fn is_finished(self) -> bool {
        !matches!(self, RunStatus::Running)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StepStatus {
    Pending,
    Running,
    Done,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StepState {
    pub id: String,
    pub title: String,
    /// The part of the file it belongs to: `apps`, `files`, `registry`, `desktop`, ...
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub section: String,
    pub status: StepStatus,
    #[serde(default)]
    pub changed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunState {
    pub source: Url,
    pub status: RunStatus,
    pub started: String,
    pub updated: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default)]
    pub reboots: u32,
    pub steps: Vec<StepState>,
    #[serde(default)]
    pub sources: Vec<LoadedSource>,
    /// The agent version that produced this state.
    #[serde(default)]
    pub agent: String,
}

pub fn now() -> String {
    humantime::format_rfc3339_seconds(SystemTime::now()).to_string()
}

/// Where the state for a given source lives. One file per source URL, so different
/// Groundhogfiles applied to the same machine track progress independently.
pub fn state_file(state_dir: &Path, source: &Url) -> PathBuf {
    state_dir.join("runs").join(format!("{}.json", &sha256_hex(source.as_str().as_bytes())[..16]))
}

pub fn read_state(path: &Path) -> Option<RunState> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub fn write_json_atomic(path: &Path, value: &impl Serialize) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(value)?).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))
}

pub struct RunOptions<'a> {
    pub source: &'a Url,
    pub sources: Vec<LoadedSource>,
    pub state_path: &'a Path,
    /// Ignore previous progress and run every step again.
    pub fresh: bool,
    /// Scrubs secret values from every log line, status update and stored error message,
    /// whichever step or reporter they come from.
    pub redact: Redactor,
}

/// Passes everything through `redact` on its way to the real reporter.
struct Scrubbed<'a> {
    inner: &'a dyn Reporter,
    redact: &'a Redactor,
}

impl Reporter for Scrubbed<'_> {
    fn log(&self, line: &str) {
        self.inner.log(&self.redact.scrub(line));
    }
    fn note(&self, line: &str) {
        self.inner.note(&self.redact.scrub(line));
    }
    fn status(&self, state: &RunState) {
        self.inner.status(state);
    }
}

pub fn run(steps: &[Step], exec: &mut dyn Executor, reporter: &dyn Reporter, opts: RunOptions) -> Result<RunState> {
    let reporter = &Scrubbed { inner: reporter, redact: &opts.redact };
    let prior = if opts.fresh { None } else { read_state(opts.state_path) };
    let done: HashSet<String> = prior
        .iter()
        .flat_map(|p| p.steps.iter().filter(|s| s.status == StepStatus::Done).map(|s| s.id.clone()))
        .collect();
    let continuing = prior.as_ref().is_some_and(|p| p.status == RunStatus::RebootPending);

    let mut state = RunState {
        source: opts.source.clone(),
        status: RunStatus::Running,
        started: now(),
        updated: now(),
        message: None,
        reboots: if continuing { prior.as_ref().map_or(0, |p| p.reboots) } else { 0 },
        steps: steps
            .iter()
            .map(|s| {
                let already = done.contains(&s.id) && !s.action.always_runs();
                StepState {
                    id: s.id.clone(),
                    title: s.title.clone(),
                    section: section(&s.action).to_owned(),
                    status: if already { StepStatus::Done } else { StepStatus::Pending },
                    changed: false,
                    message: already.then(|| "already applied".to_owned()),
                }
            })
            .collect(),
        sources: opts.sources,
        agent: env!("CARGO_PKG_VERSION").to_owned(),
    };

    let save = |state: &mut RunState| -> Result<()> {
        state.updated = now();
        write_json_atomic(opts.state_path, state)?;
        reporter.status(state);
        Ok(())
    };

    let skipped = state.steps.iter().filter(|s| s.status == StepStatus::Done).count();
    if skipped > 0 {
        reporter.log(&format!("{skipped} of {} steps already applied", steps.len()));
    }
    save(&mut state)?;

    // Restart once, at the end of the section, for every step that asked to restart later.
    let pause = |state: &mut RunState, owed: &[String]| -> Result<()> {
        if state.reboots >= MAX_REBOOTS {
            state.status = RunStatus::Failed;
            state.message = Some(format!("gave up after {MAX_REBOOTS} reboots"));
        } else {
            state.reboots += 1;
            state.status = RunStatus::RebootPending;
            state.message = Some(format!("reboot required after: {}", owed.join("; ")));
        }
        save(state)
    };
    let mut owed: Vec<String> = Vec::new();
    let mut owed_section = "";

    for (i, step) in steps.iter().enumerate() {
        if state.steps[i].status == StepStatus::Done {
            continue;
        }
        if !owed.is_empty() && section(&step.action) != owed_section {
            pause(&mut state, &owed)?;
            return Ok(state);
        }
        state.steps[i].status = StepStatus::Running;
        reporter.log(&format!("[{}/{}] {}", i + 1, steps.len(), step.title));
        save(&mut state)?;

        match exec.execute(step, reporter) {
            Ok(Outcome::Done { changed }) => {
                state.steps[i].status = StepStatus::Done;
                state.steps[i].changed = changed;
                state.steps[i].message = (!changed).then(|| "already in desired state".to_owned());
            }
            Ok(Outcome::DoneRestartLater { changed }) => {
                state.steps[i].status = StepStatus::Done;
                state.steps[i].changed = changed;
                state.steps[i].message = Some("finishes after a restart".to_owned());
                owed.push(step.title.clone());
                owed_section = section(&step.action);
            }
            Ok(outcome @ (Outcome::RebootRequired | Outcome::RetryAfterReboot)) => {
                let retry = matches!(outcome, Outcome::RetryAfterReboot);
                state.steps[i].status = if retry { StepStatus::Pending } else { StepStatus::Done };
                state.steps[i].changed = !retry;
                state.steps[i].message =
                    Some(if retry { "will retry after reboot" } else { "reboot required" }.to_owned());
                if state.reboots >= MAX_REBOOTS {
                    state.status = RunStatus::Failed;
                    state.message = Some(format!("gave up after {MAX_REBOOTS} reboots"));
                } else {
                    state.reboots += 1;
                    state.status = RunStatus::RebootPending;
                    state.message = Some(format!("reboot required after: {}", step.title));
                }
                save(&mut state)?;
                return Ok(state);
            }
            Err(e) => {
                let msg = opts.redact.scrub(&format!("{e:#}"));
                reporter.log(&format!("  failed: {msg}"));
                state.steps[i].status = StepStatus::Failed;
                state.steps[i].message = Some(msg.clone());
                state.status = RunStatus::Failed;
                state.message = Some(format!("{}: {msg}", step.title));
                save(&mut state)?;
                return Ok(state);
            }
        }
        save(&mut state)?;
    }

    if !owed.is_empty() {
        pause(&mut state, &owed)?;
        return Ok(state);
    }
    state.status = RunStatus::Succeeded;
    let changed = state.steps.iter().filter(|s| s.changed).count();
    state.message = Some(format!("{} steps, {changed} changed", steps.len()));
    save(&mut state)?;
    Ok(state)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use anyhow::bail;

    use super::*;
    use crate::model::Shell;

    struct NullReporter;
    impl Reporter for NullReporter {
        fn log(&self, _: &str) {}
        fn status(&self, _: &RunState) {}
    }

    /// Records what ran; fails or asks for a reboot on chosen commands.
    #[derive(Default)]
    struct Fake {
        ran: RefCell<Vec<String>>,
        fail: Option<String>,
        reboot: Option<String>,
    }

    impl Executor for Fake {
        fn execute(&mut self, step: &Step, _: &dyn Reporter) -> Result<Outcome> {
            let Action::Run(RunAction::Command { command, .. }) = &step.action else { unreachable!() };
            self.ran.borrow_mut().push(command.clone());
            if self.fail.as_deref() == Some(command) {
                bail!("boom");
            }
            if self.reboot.take_if(|r| r == command).is_some() {
                return Ok(Outcome::RebootRequired);
            }
            Ok(Outcome::Done { changed: true })
        }
    }

    fn file(cmds: &[&str]) -> Groundhogfile {
        Groundhogfile {
            run: cmds
                .iter()
                .map(|c| RunAction::Command {
                    command: (*c).into(),
                    shell: Shell::Powershell,
                    timeout_ms: None,
                    always: false,
                })
                .collect(),
            ..Default::default()
        }
    }

    fn go(steps: &[Step], exec: &mut Fake, path: &Path) -> RunState {
        let url = Url::parse("https://cfg.test/g.yaml").unwrap();
        let opts =
            RunOptions { source: &url, sources: vec![], state_path: path, fresh: false, redact: Redactor::default() };
        run(steps, exec, &NullReporter, opts).unwrap()
    }

    #[test]
    fn run_steps_chain_like_docker_layers() {
        let a = plan(&file(&["one", "two"]));
        let appended = plan(&file(&["one", "two", "three"]));
        let prepended = plan(&file(&["zero", "one", "two"]));
        assert_eq!(a, plan(&file(&["one", "two"])), "stable");
        assert_eq!(a[..2], appended[..2], "appending keeps earlier ids");
        assert_ne!(a[0].id, prepended[1].id, "a change before a run step reruns it");
    }

    #[test]
    fn new_sections_take_their_place_in_the_order() {
        use crate::model::{CertStore, ExclusionKind, FirewallAction, FirewallDirection, FirewallProtocol};
        let mut g = file(&["late"]);
        g.services.push(Service { name: "Spooler".into(), startup: None, status: Some(ServiceState::Stopped) });
        g.firewall.push(FirewallRule {
            name: "web".into(),
            ports: Some("80".into()),
            protocol: FirewallProtocol::Tcp,
            direction: FirewallDirection::In,
            action: FirewallAction::Allow,
            program: None,
            profile: "any".into(),
            remote: None,
            state: Presence::Present,
        });
        g.remove_apps.push("Microsoft.BingNews".into());
        g.defender_exclusions.push(DefenderExclusion {
            kind: ExclusionKind::Path,
            value: "C:\\src".into(),
            state: Presence::Present,
        });
        g.certificates.push(Certificate {
            from: Some(Url::parse("https://pki.test/root.cer").unwrap()),
            sha256: None,
            resolved: None,
            thumbprint: None,
            store: CertStore::Root,
            scope: CertScope::Machine,
            state: Presence::Present,
        });
        g.apps.push(App::Winget {
            id: "Git.Git".into(),
            version: None,
            args: None,
            timeout_ms: None,
            upgrade: true,
            state: Presence::Present,
        });
        let steps = plan(&g);
        let titles: Vec<&str> = steps.iter().map(|s| s.title.as_str()).collect();
        assert_eq!(
            titles,
            [
                "add root.cer to machine Root certificates",
                "exclude path C:\\src from Defender",
                "remove built-in app Microsoft.BingNews",
                "ensure winget is available",
                "install or upgrade Git.Git (winget)",
                "service Spooler: stopped",
                "firewall rule web",
                "run: late",
            ]
        );
        assert!(steps[4].action.always_runs(), "an upgrading app checks for a new version every apply");
    }

    #[test]
    fn preview_skips_what_was_applied_and_asks_about_the_rest() {
        struct Prober;
        impl Executor for Prober {
            fn execute(&mut self, _: &Step, _: &dyn Reporter) -> Result<Outcome> {
                Ok(Outcome::Done { changed: true })
            }
            fn check(&mut self, step: &Step) -> Result<Probe> {
                match &step.action {
                    Action::Run(RunAction::Command { command, .. }) if command == "broken" => anyhow::bail!("nope"),
                    _ => Ok(Probe::WillRun),
                }
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let url = Url::parse("https://cfg.test/g.yaml").unwrap();
        let first = plan(&file(&["a"]));
        let opts =
            RunOptions { source: &url, sources: vec![], state_path: &path, fresh: false, redact: Redactor::default() };
        run(&first, &mut Prober, &NullReporter, opts).unwrap();

        let steps = plan(&file(&["a", "broken"]));
        let previews = preview(&steps, &mut Prober, &path);
        assert_eq!(previews[0], Preview::Applied);
        assert!(matches!(&previews[1], Preview::Error(e) if e == "nope"));
    }

    #[test]
    fn user_scope_keeps_the_step_ids_from_before_scopes() {
        // Ids are hashes of the serialized action: these must stay exactly what 0.10 wrote, or
        // every machine would rerun its env and PATH steps after updating.
        let env = Action::Env { name: "A".into(), value: "1".into(), scope: EnvScope::User, state: Presence::Present };
        let path = Action::Path { dir: r"C:\bin".into(), scope: EnvScope::User, state: Presence::Present };
        assert_eq!(serde_json::to_string(&env).unwrap(), r#"{"action":"env","name":"A","value":"1"}"#);
        assert_eq!(serde_json::to_string(&path).unwrap(), r#"{"action":"path","dir":"C:\\bin"}"#);
        let machine = Action::Path { dir: r"C:\bin".into(), scope: EnvScope::Machine, state: Presence::Present };
        assert_eq!(serde_json::to_string(&machine).unwrap(), r#"{"action":"path","dir":"C:\\bin","scope":"machine"}"#);
        assert_eq!(title(&machine), r"add C:\bin to machine PATH");
    }

    #[test]
    fn a_step_using_a_secret_reruns_when_its_fingerprint_changes() {
        let mut g = file(&[]);
        g.env.insert(
            "TOKEN".into(),
            crate::model::EnvVar { value: "${secret:T}".into(), scope: EnvScope::User, state: Presence::Present },
        );
        g.env.insert(
            "PLAIN".into(),
            crate::model::EnvVar { value: "x".into(), scope: EnvScope::User, state: Presence::Present },
        );
        let id = |fp: Option<&str>, name: &str| {
            plan_with_secrets(&g, &|_| fp.map(str::to_owned))
                .into_iter()
                .find(|s| s.title == format!("set env {name}"))
                .unwrap()
                .id
        };
        assert_ne!(id(Some("print-1"), "TOKEN"), id(Some("print-2"), "TOKEN"), "rotation reruns it");
        assert_eq!(id(Some("print-1"), "TOKEN"), id(Some("print-1"), "TOKEN"));
        assert_eq!(id(Some("print-1"), "PLAIN"), id(Some("print-2"), "PLAIN"), "others are unaffected");
        assert_eq!(id(None, "PLAIN"), id(Some("print-1"), "PLAIN"));
        let titles: Vec<String> = plan(&g).into_iter().map(|s| s.title).collect();
        assert!(titles.contains(&"set env TOKEN".to_owned()));
    }

    #[test]
    fn secret_values_are_scrubbed_from_logs_and_saved_state() {
        struct Leaky;
        impl Executor for Leaky {
            fn execute(&mut self, _: &Step, reporter: &dyn Reporter) -> Result<Outcome> {
                reporter.log("connecting with hunter2-token");
                bail!("server said: bad token hunter2-token");
            }
        }
        struct Capture(RefCell<Vec<String>>);
        impl Reporter for Capture {
            fn log(&self, line: &str) {
                self.0.borrow_mut().push(line.to_owned());
            }
            fn status(&self, state: &RunState) {
                self.0.borrow_mut().push(serde_json::to_string(state).unwrap());
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let url = Url::parse("https://cfg.test/g.yaml").unwrap();
        let secret = "hunter2-token".to_owned();
        let opts = RunOptions {
            source: &url,
            sources: vec![],
            state_path: &path,
            fresh: false,
            redact: Redactor::new([&secret]),
        };
        let seen = Capture(RefCell::new(vec![]));
        let state = run(&plan(&file(&["x"])), &mut Leaky, &seen, opts).unwrap();
        assert_eq!(state.status, RunStatus::Failed);
        let everything = seen.0.borrow().join("\n") + &std::fs::read_to_string(&path).unwrap();
        assert!(!everything.contains("hunter2"), "{everything}");
        assert!(everything.contains("bad token ***"));
    }

    #[test]
    fn declarative_steps_are_independent_and_run_steps_follow_them() {
        let with_file = |content: &str| {
            let mut g = file(&["unzip"]);
            g.env.insert(
                "A".into(),
                crate::model::EnvVar { value: "1".into(), scope: EnvScope::User, state: Presence::Present },
            );
            g.files.push(FileCopy {
                from: Some(Url::parse("https://dl.test/latest/app.zip").unwrap()),
                content: None,
                to: r"C:\app.zip".into(),
                sha256: None,
                resolved: Some(sha256_hex(content.as_bytes())),
                extract: false,
                strip: 0,
                release: None,
                state: Presence::Present,
            });
            plan(&g)
        };
        let (v1, v2) = (with_file("build 1"), with_file("build 2"));
        let env = |p: &[Step]| p.iter().find(|s| matches!(s.action, Action::Env { .. })).unwrap().id.clone();
        assert_ne!(v1[0].id, v2[0].id, "new build, new file step");
        assert_eq!(env(&v1), env(&v2), "unrelated declarative steps keep their ids");
        assert_ne!(v1.last().unwrap().id, v2.last().unwrap().id, "the run step after it reruns");
        assert!(v1[0].title.ends_with(&format!("@{}", &sha256_hex(b"build 1")[..8])));
    }

    #[test]
    fn verify_steps_run_on_every_apply() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut g = file(&["install"]);
        g.verify.push(Check::Port { host: "127.0.0.1".into(), port: 1, within_ms: 0 });
        let steps = plan(&g);
        assert_eq!(steps.last().unwrap().title, "verify 127.0.0.1:1 accepts connections");

        struct Count(Vec<String>);
        impl Executor for Count {
            fn execute(&mut self, step: &Step, _: &dyn Reporter) -> Result<Outcome> {
                self.0.push(step.title.clone());
                Ok(Outcome::Done { changed: false })
            }
        }
        let url = Url::parse("https://cfg.test/g.yaml").unwrap();
        let opts = || RunOptions {
            source: &url,
            sources: vec![],
            state_path: &path,
            fresh: false,
            redact: Redactor::default(),
        };
        let mut exec = Count(vec![]);
        run(&steps, &mut exec, &NullReporter, opts()).unwrap();
        run(&steps, &mut exec, &NullReporter, opts()).unwrap();
        assert_eq!(
            exec.0,
            ["run: install", "verify 127.0.0.1:1 accepts connections", "verify 127.0.0.1:1 accepts connections"]
        );
    }

    #[test]
    fn always_run_steps_run_on_every_apply_and_titles_show_releases() {
        let mut g = file(&["build"]);
        g.run.push(RunAction::Command {
            command: "dotnet test".into(),
            shell: Shell::Powershell,
            timeout_ms: Some(1000),
            always: true,
        });
        let steps = plan(&g);
        assert!(!steps[0].action.always_runs());
        assert!(steps[1].action.always_runs());

        let file_from_release = Action::File(FileCopy {
            from: Some(Url::parse("https://github.com/o/r/releases/download/1.0.268/release.zip").unwrap()),
            content: None,
            to: r"C:\app".into(),
            sha256: Some("ab".repeat(32)),
            resolved: None,
            extract: true,
            strip: 0,
            release: Some("1.0.268".into()),
            state: Presence::Present,
        });
        assert_eq!(title(&file_from_release), r"copy release.zip -> C:\app @1.0.268");
    }

    #[test]
    fn command_titles_prefer_a_leading_comment() {
        assert_eq!(command_title("# fetch the bundle\nInvoke-WebRequest x"), "fetch the bundle");
        assert_eq!(command_title("\n  Start-Sleep 12\n  Get-Process"), "Start-Sleep 12…");
        assert_eq!(command_title("echo hi"), "echo hi");
    }

    #[test]
    fn winget_is_ensured_only_when_needed() {
        let mut g = file(&[]);
        assert!(plan(&g).is_empty());
        g.apps.push(App::Winget {
            id: "git.git".into(),
            version: None,
            args: None,
            timeout_ms: None,
            upgrade: false,
            state: Presence::Present,
        });
        assert_eq!(plan(&g)[0].action, Action::EnsureWinget);
    }

    #[test]
    fn failure_stops_and_rerun_resumes_at_the_failed_step() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let steps = plan(&file(&["a", "b", "c"]));

        let mut exec = Fake { fail: Some("b".into()), ..Default::default() };
        let s = go(&steps, &mut exec, &path);
        assert_eq!(s.status, RunStatus::Failed);
        assert_eq!(*exec.ran.borrow(), ["a", "b"]);

        let mut exec = Fake::default();
        let s = go(&steps, &mut exec, &path);
        assert_eq!(s.status, RunStatus::Succeeded);
        assert_eq!(*exec.ran.borrow(), ["b", "c"]);
    }

    #[test]
    fn reboot_pauses_the_run_and_the_next_run_continues() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let steps = plan(&file(&["a", "b", "c"]));

        let mut exec = Fake { reboot: Some("a".into()), ..Default::default() };
        let s = go(&steps, &mut exec, &path);
        assert_eq!(s.status, RunStatus::RebootPending);
        assert_eq!(s.reboots, 1);

        let mut exec = Fake::default();
        let s = go(&steps, &mut exec, &path);
        assert_eq!(s.status, RunStatus::Succeeded);
        assert_eq!(*exec.ran.borrow(), ["b", "c"]);
    }

    #[test]
    fn retry_after_reboot_runs_the_step_again() {
        struct RetryOnce(bool, Vec<String>);
        impl Executor for RetryOnce {
            fn execute(&mut self, step: &Step, _: &dyn Reporter) -> Result<Outcome> {
                self.1.push(step.title.clone());
                Ok(if std::mem::take(&mut self.0) {
                    Outcome::RetryAfterReboot
                } else {
                    Outcome::Done { changed: true }
                })
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let url = Url::parse("https://cfg.test/g.yaml").unwrap();
        let steps = plan(&file(&["a"]));
        let opts = || RunOptions {
            source: &url,
            sources: vec![],
            state_path: &path,
            fresh: false,
            redact: Redactor::default(),
        };

        let mut exec = RetryOnce(true, vec![]);
        assert_eq!(run(&steps, &mut exec, &NullReporter, opts()).unwrap().status, RunStatus::RebootPending);
        let s = run(&steps, &mut exec, &NullReporter, opts()).unwrap();
        assert_eq!(s.status, RunStatus::Succeeded);
        assert_eq!(exec.1.len(), 2);
    }

    #[test]
    fn deferred_restarts_are_batched_per_section() {
        use crate::model::Feature;
        struct Features(Vec<String>);
        impl Executor for Features {
            fn execute(&mut self, step: &Step, _: &dyn Reporter) -> Result<Outcome> {
                self.0.push(step.title.clone());
                Ok(match step.action {
                    Action::Feature(_) => Outcome::DoneRestartLater { changed: true },
                    _ => Outcome::Done { changed: true },
                })
            }
        }
        let feature = |name: &str| Feature {
            name: name.into(),
            enabled: true,
            all: true,
            remove_payload: false,
            sources: vec![],
            limit_access: false,
            timeout_ms: None,
        };
        let mut g = file(&["after"]);
        g.features = vec![feature("A"), feature("B"), feature("C")];
        let steps = plan(&g);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let url = Url::parse("https://cfg.test/g.yaml").unwrap();
        let opts = || RunOptions {
            source: &url,
            sources: vec![],
            state_path: &path,
            fresh: false,
            redact: Redactor::default(),
        };

        let mut exec = Features(vec![]);
        let first = run(&steps, &mut exec, &NullReporter, opts()).unwrap();
        assert_eq!(first.status, RunStatus::RebootPending);
        assert_eq!(first.reboots, 1, "one restart for three features");
        assert_eq!(exec.0.len(), 3, "all features ran before the restart, the run step didn't");
        assert!(first.message.unwrap().contains("enable feature A; enable feature B; enable feature C"));

        let second = run(&steps, &mut exec, &NullReporter, opts()).unwrap();
        assert_eq!(second.status, RunStatus::Succeeded);
        assert_eq!(exec.0.last().unwrap(), "run: after");
        assert_eq!(exec.0.len(), 4);
    }

    #[test]
    fn edited_file_runs_only_new_steps() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        go(&plan(&file(&["a", "b"])), &mut Fake::default(), &path);

        let mut exec = Fake::default();
        go(&plan(&file(&["a", "b", "new"])), &mut exec, &path);
        assert_eq!(*exec.ran.borrow(), ["new"]);
    }
}
