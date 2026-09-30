//! Turning a Groundhogfile into ordered steps and running them resumably.
//!
//! Each step's id is a hash of what it does. A run records completed ids in a state file, so
//! re-running after a reboot, a failure or an edit to the Groundhogfile skips what is already
//! done and runs only what is new or failed.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::fetch::{file_name, sha256_hex};
use crate::loader::LoadedSource;
use crate::model::{App, Check, FileCopy, Groundhogfile, RegistryValue, RunAction, ServiceState, User};
use crate::report::Reporter;

/// Stop asking for reboots after this many in one run; something is looping.
pub const MAX_REBOOTS: u32 = 5;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "action", rename_all = "kebab-case")]
pub enum Action {
    EnsureWinget,
    App(App),
    File(FileCopy),
    Env { name: String, value: String },
    Path { dir: String },
    Registry(RegistryValue),
    Run(RunAction),
    User(User),
    Verify(Check),
}

impl Action {
    /// Checks describe health, not changes, and `always: true` run steps ask for it: these
    /// run on every apply.
    pub fn always_runs(&self) -> bool {
        match self {
            Action::Verify(_) => true,
            Action::Run(r) => r.always(),
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
        Action::App(App::Winget { id, version: Some(v), .. }) => format!("install {id} {v} (winget)"),
        Action::App(App::Winget { id, .. }) => format!("install {id} (winget)"),
        Action::App(App::Url { id, url, .. }) => format!("install {id} from {}", file_name(url)),
        Action::File(f) => {
            // A release's source archive is named after its tag; "source" reads better next to "@tag".
            let name = if f.release.is_some() && f.from.path().contains("/archive/refs/tags/") {
                "source".to_owned()
            } else {
                file_name(&f.from)
            };
            format!("copy {name} -> {}", f.to)
        }
        Action::Env { name, .. } => format!("set env {name}"),
        Action::Path { dir } => format!("add {dir} to PATH"),
        Action::Registry(r) => format!("set {}\\{}", r.key, r.name.as_deref().unwrap_or("(default)")),
        Action::Run(RunAction::Command { command, .. }) => format!("run: {}", command_title(command)),
        Action::Run(RunAction::Script { script, .. }) => format!("run script {}", file_name(script)),
        Action::Run(RunAction::Plugin { plugin, .. }) => format!("run plugin {}", file_name(plugin)),
        Action::Verify(c) => format!("verify {}", check_title(c)),
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
    // Accounts first: they depend on nothing, and later steps may assume they exist.
    let mut actions: Vec<Action> = file.users.iter().cloned().map(Action::User).collect();
    if file.apps.iter().any(|a| matches!(a, App::Winget { .. })) {
        actions.push(Action::EnsureWinget);
    }
    actions.extend(file.apps.iter().cloned().map(Action::App));
    actions.extend(file.files.iter().cloned().map(Action::File));
    actions.extend(file.env.iter().map(|(name, value)| Action::Env { name: name.clone(), value: value.clone() }));
    actions.extend(file.path.iter().map(|dir| Action::Path { dir: dir.clone() }));
    actions.extend(file.registry.iter().cloned().map(Action::Registry));
    actions.extend(file.run.iter().cloned().map(Action::Run));
    actions.extend(file.verify.iter().cloned().map(Action::Verify));

    let mut chain = String::new();
    actions
        .into_iter()
        .map(|action| {
            let own = sha256_hex(&serde_json::to_vec(&action).expect("actions serialize"));
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

pub enum Outcome {
    Done {
        changed: bool,
    },
    /// The step completed but Windows must restart before later steps can run.
    RebootRequired,
    /// The step could not run until Windows restarts; run it again afterwards.
    RetryAfterReboot,
}

/// Carries out steps on the actual machine. The agent implements this; tests fake it.
pub trait Executor {
    fn execute(&mut self, step: &Step, reporter: &dyn Reporter) -> Result<Outcome>;
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
}

pub fn run(steps: &[Step], exec: &mut dyn Executor, reporter: &dyn Reporter, opts: RunOptions) -> Result<RunState> {
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

    for (i, step) in steps.iter().enumerate() {
        if state.steps[i].status == StepStatus::Done {
            continue;
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
                let msg = format!("{e:#}");
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
        let opts = RunOptions { source: &url, sources: vec![], state_path: path, fresh: false };
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
    fn declarative_steps_are_independent_and_run_steps_follow_them() {
        let with_file = |content: &str| {
            let mut g = file(&["unzip"]);
            g.env.insert("A".into(), "1".into());
            g.files.push(FileCopy {
                from: Url::parse("https://dl.test/latest/app.zip").unwrap(),
                to: r"C:\app.zip".into(),
                sha256: None,
                resolved: Some(sha256_hex(content.as_bytes())),
                extract: false,
                strip: 0,
                release: None,
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
        let opts = || RunOptions { source: &url, sources: vec![], state_path: &path, fresh: false };
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
            from: Url::parse("https://github.com/o/r/releases/download/1.0.268/release.zip").unwrap(),
            to: r"C:\app".into(),
            sha256: Some("ab".repeat(32)),
            resolved: None,
            extract: true,
            strip: 0,
            release: Some("1.0.268".into()),
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
        g.apps.push(App::Winget { id: "git.git".into(), version: None, args: None, timeout_ms: None });
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
        let opts = || RunOptions { source: &url, sources: vec![], state_path: &path, fresh: false };

        let mut exec = RetryOnce(true, vec![]);
        assert_eq!(run(&steps, &mut exec, &NullReporter, opts()).unwrap().status, RunStatus::RebootPending);
        let s = run(&steps, &mut exec, &NullReporter, opts()).unwrap();
        assert_eq!(s.status, RunStatus::Succeeded);
        assert_eq!(exec.1.len(), 2);
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
