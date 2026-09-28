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
use crate::model::{App, FileCopy, Groundhogfile, RegistryValue, RunAction};
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
}

#[derive(Debug, Clone, PartialEq)]
pub struct Step {
    pub id: String,
    pub title: String,
    pub action: Action,
}

impl Step {
    fn new(action: Action) -> Self {
        let json = serde_json::to_vec(&action).expect("actions serialize");
        let id = sha256_hex(&json)[..16].to_owned();
        let title = title(&action);
        Self { id, title, action }
    }
}

fn title(action: &Action) -> String {
    match action {
        Action::EnsureWinget => "ensure winget is available".into(),
        Action::App(App::Winget { id, version: Some(v), .. }) => format!("install {id} {v} (winget)"),
        Action::App(App::Winget { id, .. }) => format!("install {id} (winget)"),
        Action::App(App::Url { id, url, .. }) => format!("install {id} from {}", file_name(url)),
        Action::File(f) => format!("copy {} -> {}", file_name(&f.from), f.to),
        Action::Env { name, .. } => format!("set env {name}"),
        Action::Path { dir } => format!("add {dir} to PATH"),
        Action::Registry(r) => format!("set {}\\{}", r.key, r.name.as_deref().unwrap_or("(default)")),
        Action::Run(RunAction::Command { command, .. }) => {
            let first = command.lines().next().unwrap_or_default();
            let short: String = first.chars().take(60).collect();
            let more = short.len() < command.len();
            format!("run: {short}{}", if more { "…" } else { "" })
        }
        Action::Run(RunAction::Script { script, .. }) => format!("run script {}", file_name(script)),
        Action::Run(RunAction::Plugin { plugin, .. }) => format!("run plugin {}", file_name(plugin)),
    }
}

/// Orders the work: winget first if needed, then apps, files, env, PATH, registry, and
/// finally custom `run` actions, which may depend on everything before them.
pub fn plan(file: &Groundhogfile) -> Vec<Step> {
    let mut actions = Vec::new();
    if file.apps.iter().any(|a| matches!(a, App::Winget { .. })) {
        actions.push(Action::EnsureWinget);
    }
    actions.extend(file.apps.iter().cloned().map(Action::App));
    actions.extend(file.files.iter().cloned().map(Action::File));
    actions.extend(file.env.iter().map(|(name, value)| Action::Env { name: name.clone(), value: value.clone() }));
    actions.extend(file.path.iter().map(|dir| Action::Path { dir: dir.clone() }));
    actions.extend(file.registry.iter().cloned().map(Action::Registry));
    actions.extend(file.run.iter().cloned().map(Action::Run));
    actions.into_iter().map(Step::new).collect()
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
                let already = done.contains(&s.id);
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
            run: cmds.iter().map(|c| RunAction::Command { command: (*c).into(), shell: Shell::Powershell }).collect(),
            ..Default::default()
        }
    }

    fn go(steps: &[Step], exec: &mut Fake, path: &Path) -> RunState {
        let url = Url::parse("https://cfg.test/g.yaml").unwrap();
        let opts = RunOptions { source: &url, sources: vec![], state_path: path, fresh: false };
        run(steps, exec, &NullReporter, opts).unwrap()
    }

    #[test]
    fn step_ids_are_stable_and_content_based() {
        let a = plan(&file(&["one", "two"]));
        let b = plan(&file(&["zero", "one", "two"]));
        assert_eq!(a[0].id, b[1].id);
        assert_ne!(a[0].id, a[1].id);
    }

    #[test]
    fn winget_is_ensured_only_when_needed() {
        let mut g = file(&[]);
        assert!(plan(&g).is_empty());
        g.apps.push(App::Winget { id: "git.git".into(), version: None, args: None });
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
