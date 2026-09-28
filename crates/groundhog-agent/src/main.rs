//! `groundhog-agent`: applies a Groundhogfile to the machine it runs on.
//!
//! It works on its own, with no host: copy it onto any Windows machine and point it at a
//! path, URL or zip bundle. Hosts (Sandbox, Hyper-V, Proxmox, ...) only start it and watch.

mod exec;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use groundhog_core::cache::{Cache, parse_cache_source};
use groundhog_core::content::ContentStore;
use groundhog_core::engine::{self, RunOptions, RunState, RunStatus, StepState, now, plan, state_file};
use groundhog_core::fetch::{DefaultFetcher, HeaderRule};
use groundhog_core::loader::{Loaded, Loader, source_ref};
use groundhog_core::pending::{PENDING_FILE, Pending, default_home};
use groundhog_core::report::{ConsoleReporter, FolderReporter, MultiReporter, Reporter, parse_report_sink};
use groundhog_win::process::Proc;
use groundhog_win::{tasks, token};

use crate::exec::WinExecutor;

/// Exit code when a restart is needed to continue (the Windows Installer convention).
const EXIT_REBOOT: i32 = 3010;

#[derive(Parser)]
#[command(name = "groundhog-agent", version, about = "Applies a Groundhogfile to this machine")]
struct Cli {
    /// Where state, downloads and the pending file live.
    #[arg(long, global = true, env = "GROUNDHOG_HOME")]
    home: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Apply a Groundhogfile (path, URL or zip bundle), resuming any earlier progress.
    Apply(ApplyArgs),
    /// Show the steps a Groundhogfile would run, without changing anything.
    Plan(SourceArgs),
    /// Apply the bootstrap file (`<home>\pending.json`) if there is one. Meant for a logon task.
    RunPending,
    /// Install this agent into <home>\bin and register a logon task that runs `run-pending`.
    InstallTask,
    /// Show the last result for each Groundhogfile applied on this machine.
    Status,
}

#[derive(Args)]
struct SourceArgs {
    /// Path, URL, or zip bundle of the Groundhogfile.
    source: String,
    /// Require the root document (or zip) to have this SHA-256.
    #[arg(long)]
    sha256: Option<String>,
    /// Content-addressed cache to try before the network: folder, UNC share or http(s) URL.
    /// Repeatable; tried in order.
    #[arg(long = "cache", value_name = "SOURCE")]
    cache: Vec<String>,
    /// Header for authenticated sources, as `Name: value` (sent only to the source's host) or
    /// `host=Name: value`. Repeatable.
    #[arg(long = "header", value_name = "HEADER")]
    headers: Vec<String>,
    /// Allow plain http:// for documents and downloads.
    #[arg(long)]
    allow_http: bool,
}

#[derive(Args)]
struct ApplyArgs {
    #[command(flatten)]
    source: SourceArgs,
    /// Also report progress here: a folder (status.json + agent.log) or an http(s) URL.
    #[arg(long = "report", value_name = "SINK")]
    report: Vec<String>,
    /// If a restart is needed, restart automatically and continue at the next logon.
    #[arg(long)]
    reboot: bool,
    /// Ignore earlier progress and run every step again.
    #[arg(long)]
    fresh: bool,
}

fn main() {
    let cli = Cli::parse();
    let home = cli.home.unwrap_or_else(default_home);
    let code = match run(&home, cli.command) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            1
        }
    };
    std::process::exit(code);
}

fn run(home: &Path, command: Command) -> Result<i32> {
    match command {
        Command::Apply(args) => {
            let pending = to_pending(&args.source, args.report, args.reboot)?;
            let state = apply(home, &pending, args.fresh)?;
            if state.status == RunStatus::RebootPending {
                if args.reboot {
                    schedule_continuation(home, &pending)?;
                    reboot()?;
                } else {
                    println!("A restart is required. Restart, then run the same command again to continue.");
                }
            }
            Ok(exit_code(state.status))
        }
        Command::Plan(args) => {
            let pending = to_pending(&args, Vec::new(), false)?;
            print_plan(home, &pending)?;
            Ok(0)
        }
        Command::RunPending => run_pending(home),
        Command::InstallTask => {
            let exe = install_self(home)?;
            let mut args = "run-pending".to_owned();
            if home != default_home() {
                args = format!(r#"--home "{}" {args}"#, home.display());
            }
            tasks::install_logon_task(&exe, &args, &mut |l| println!("{l}"))?;
            println!("Installed {} and task '{}'.", exe.display(), tasks::TASK_NAME);
            println!("Drop a {PENDING_FILE} into {} to have it applied at the next logon.", home.display());
            Ok(0)
        }
        Command::Status => {
            print_status(home)?;
            Ok(0)
        }
    }
}

fn to_pending(args: &SourceArgs, report: Vec<String>, allow_reboot: bool) -> Result<Pending> {
    let cwd = std::env::current_dir()?;
    let root = source_ref(&args.source, args.sha256.clone(), &cwd)?;
    let headers = args.headers.iter().map(|h| parse_header(h, root.url.host_str())).collect::<Result<_>>()?;
    Ok(Pending {
        // Absolute, so it still resolves when run from a logon task after a reboot.
        source: root.url.to_string(),
        sha256: args.sha256.clone(),
        cache: args.cache.clone(),
        report,
        headers,
        allow_reboot,
        allow_http: args.allow_http,
    })
}

fn parse_header(s: &str, default_host: Option<&str>) -> Result<HeaderRule> {
    let (left, value) = s.split_once(':').with_context(|| format!("header '{s}' must look like 'Name: value'"))?;
    let (host, name) = match left.split_once('=') {
        Some((host, name)) => (host.trim().to_owned(), name.trim().to_owned()),
        None => (
            default_host.context("a header without 'host=' needs an http(s) source to attach to")?.to_owned(),
            left.trim().to_owned(),
        ),
    };
    Ok(HeaderRule { host, name, value: value.trim().to_owned() })
}

struct Session {
    fetcher: DefaultFetcher,
    cache: Cache,
    reporter: MultiReporter,
}

impl Session {
    fn new(home: &Path, p: &Pending) -> Result<Self> {
        let cache = Cache::new(p.cache.iter().map(|c| parse_cache_source(c)).collect::<Result<_>>()?);
        let mut reporters: Vec<Box<dyn Reporter>> =
            vec![Box::new(ConsoleReporter), Box::new(FolderReporter { dir: home.join("last-run") })];
        for sink in &p.report {
            reporters.push(parse_report_sink(sink)?);
        }
        Ok(Self {
            fetcher: DefaultFetcher { headers: p.headers.clone(), allow_http: p.allow_http },
            cache,
            reporter: MultiReporter(reporters),
        })
    }

    fn load(&self, home: &Path, p: &Pending) -> Result<(url::Url, Loaded)> {
        let root = source_ref(&p.source, p.sha256.clone(), &std::env::current_dir()?)?;
        let content = ContentStore { fetcher: &self.fetcher, cache: &self.cache };
        let loader = Loader { content: &content, bundle_dir: home.join("bundles") };
        let loaded = loader.load(&root)?;
        Ok((root.url, loaded))
    }
}

fn apply(home: &Path, p: &Pending, fresh: bool) -> Result<RunState> {
    let session = Session::new(home, p)?;
    let reporter = &session.reporter;
    reporter.log(&format!("groundhog-agent {} applying {}", env!("CARGO_PKG_VERSION"), p.source));
    if !session.cache.is_empty() {
        reporter.log(&format!("cache: {}", session.cache.describe().join(", ")));
    }
    if !token::is_elevated() {
        reporter.log("warning: not running elevated; machine-wide installs and HKLM changes will fail");
    }

    let (url, loaded) = match session.load(home, p) {
        Ok(v) => v,
        Err(e) => {
            // Tell anyone watching, or a host would wait forever for a run that never starts.
            let state = failed_before_start(p, &e);
            reporter.log(&format!("failed: {e:#}"));
            reporter.status(&state);
            return Ok(state);
        }
    };

    let steps = plan(&loaded.file);
    let content = ContentStore { fetcher: &session.fetcher, cache: &session.cache };
    let mut exec = WinExecutor::new(&content, home.join("work"));
    let state = engine::run(
        &steps,
        &mut exec,
        reporter,
        RunOptions { source: &url, sources: loaded.sources, state_path: &state_file(home, &url), fresh },
    )?;
    reporter.log(&format!("{:?}: {}", state.status, state.message.as_deref().unwrap_or_default()));
    Ok(state)
}

fn failed_before_start(p: &Pending, e: &anyhow::Error) -> RunState {
    RunState {
        source: url::Url::parse(&p.source).unwrap_or_else(|_| url::Url::parse("about:invalid").expect("valid")),
        status: RunStatus::Failed,
        started: now(),
        updated: now(),
        message: Some(format!("{e:#}")),
        reboots: 0,
        steps: Vec::new(),
        sources: Vec::new(),
    }
}

fn run_pending(home: &Path) -> Result<i32> {
    let path = home.join(PENDING_FILE);
    let Ok(bytes) = std::fs::read(&path) else {
        println!("nothing pending ({} not found)", path.display());
        return Ok(0);
    };
    let pending: Pending = serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?;
    let state = apply(home, &pending, false)?;
    match state.status {
        RunStatus::RebootPending if pending.allow_reboot => reboot()?,
        RunStatus::RebootPending => println!("A restart is required; it will continue at the next logon."),
        // Done either way: don't retry a failure at every logon. The state file keeps details.
        RunStatus::Succeeded => std::fs::rename(&path, home.join("pending.done.json"))?,
        RunStatus::Failed => std::fs::rename(&path, home.join("pending.failed.json"))?,
        RunStatus::Running => {}
    }
    Ok(exit_code(state.status))
}

/// Makes `apply --reboot` continue by itself after the restart.
fn schedule_continuation(home: &Path, p: &Pending) -> Result<()> {
    engine::write_json_atomic(&home.join(PENDING_FILE), p)?;
    let exe = install_self(home)?;
    let mut args = "run-pending".to_owned();
    if home != default_home() {
        args = format!(r#"--home "{}" {args}"#, home.display());
    }
    tasks::install_logon_task(&exe, &args, &mut |l| println!("{l}"))
}

/// Copies the running agent to `<home>\bin`, so a logon task never points at a mapped folder
/// or download location that may be gone after a restart.
fn install_self(home: &Path) -> Result<PathBuf> {
    let current = std::env::current_exe()?;
    let bin = home.join("bin");
    std::fs::create_dir_all(&bin)?;
    let target = bin.join("groundhog-agent.exe");
    if !same_file(&current, &target) {
        std::fs::copy(&current, &target).with_context(|| format!("copying agent to {}", target.display()))?;
    }
    Ok(target)
}

fn same_file(a: &Path, b: &Path) -> bool {
    matches!((a.canonicalize(), b.canonicalize()), (Ok(x), Ok(y)) if x == y)
}

fn reboot() -> Result<()> {
    println!("Restarting in 15 seconds to continue setup...");
    let out = Proc::new("shutdown.exe")
        .args(["/r", "/t", "15", "/c", "Groundhog: restarting to continue setup"])
        .run(&mut |l| println!("{l}"))?;
    if out.code != 0 {
        bail!("shutdown exited with {}", out.code);
    }
    Ok(())
}

fn exit_code(status: RunStatus) -> i32 {
    match status {
        RunStatus::Succeeded => 0,
        RunStatus::RebootPending => EXIT_REBOOT,
        RunStatus::Failed | RunStatus::Running => 1,
    }
}

fn print_plan(home: &Path, p: &Pending) -> Result<()> {
    let session = Session::new(home, &Pending { report: Vec::new(), ..p.clone() })?;
    let (_, loaded) = session.load(home, p)?;
    for s in &loaded.sources {
        println!("source  {}  sha256:{}", s.url, s.sha256);
    }
    let steps = plan(&loaded.file);
    for (i, step) in steps.iter().enumerate() {
        println!("{:>3}. [{}] {}", i + 1, step.id, step.title);
    }
    Ok(())
}

fn print_status(home: &Path) -> Result<()> {
    let runs = home.join("runs");
    let Ok(entries) = std::fs::read_dir(&runs) else {
        println!("no runs recorded in {}", runs.display());
        return Ok(());
    };
    for entry in entries.filter_map(Result::ok) {
        let Some(state) = engine::read_state(&entry.path()) else { continue };
        println!("{:?}  {}  (updated {})", state.status, state.source, state.updated);
        if let Some(m) = &state.message {
            println!("    {m}");
        }
        let failed = state.steps.iter().filter(|s| s.status == engine::StepStatus::Failed);
        for StepState { title, message, .. } in failed {
            println!("    failed: {title}: {}", message.as_deref().unwrap_or_default());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_bind_to_the_source_host_by_default() {
        let h = parse_header("Authorization: Bearer abc:def", Some("cfg.test")).unwrap();
        assert_eq!(
            (h.host.as_str(), h.name.as_str(), h.value.as_str()),
            ("cfg.test", "Authorization", "Bearer abc:def")
        );
        let h = parse_header("other.test=X-Token: t", Some("cfg.test")).unwrap();
        assert_eq!(h.host, "other.test");
        assert!(parse_header("Authorization: x", None).is_err());
    }
}
