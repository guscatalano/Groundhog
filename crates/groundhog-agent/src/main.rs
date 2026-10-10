//! `groundhog-agent`: applies a Groundhogfile to the machine it runs on.
//!
//! It works on its own, with no host: copy it onto any Windows machine and point it at a
//! path, URL or zip bundle. Hosts (Sandbox, Hyper-V, Proxmox, ...) only start it and watch.

mod checks;
mod ensure;
mod exec;
mod secrets;
mod update;

use std::collections::BTreeSet;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use groundhog_core::cache::{Cache, CacheSource, FolderCache, parse_cache_source};
use groundhog_core::content::ContentStore;
use groundhog_core::engine::{self, RunOptions, RunState, RunStatus, StepState, now, plan, state_file};
use groundhog_core::fetch::{DefaultFetcher, HeaderRule};
use groundhog_core::loader::{Loaded, Loader, NeedsAgent, required_secrets, source_ref};
use groundhog_core::pending::{PENDING_FILE, Pending, default_home};
use groundhog_core::report::{
    ConsoleReporter, FolderReporter, HumanReporter, LOG_FILE, MultiReporter, Reporter, parse_report_sink,
};
use groundhog_core::secret::Redactor;
use groundhog_core::update::{Policy, Version};
use groundhog_win::process::Proc;
use groundhog_win::{console, tasks, token};

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
    Plan(PlanArgs),
    /// Apply the bootstrap file (`<home>\pending.json`) if there is one. Meant for a logon task.
    RunPending,
    /// Install this agent into <home>\bin and register a logon task that runs `run-pending`.
    InstallTask,
    /// Show the last result for each Groundhogfile applied on this machine.
    Status,
    /// Remove everything runs leave behind (results, state, logs, downloads, secrets), keeping
    /// the installed agent and its logon task. Run it before sealing a template, so clones
    /// start with no history, no cached downloads and their own secret salt.
    Clean,
    /// Update this agent now, without applying anything (for maintaining templates).
    Update {
        /// `latest`, or a version to move to.
        #[arg(long, default_value = "latest", value_name = "POLICY")]
        to: String,
        /// Where agent updates come from: an agent.json manifest, or a folder, share or URL
        /// holding one (default: GitHub releases).
        #[arg(long, value_name = "SOURCE")]
        from: Option<String>,
    },
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
    /// A value for `${var:NAME}` in the Groundhogfile, as `NAME=value`. Repeatable; wins over
    /// the file's own `vars`.
    #[arg(long = "var", value_name = "NAME=VALUE")]
    vars: Vec<String>,
}

#[derive(Args)]
struct PlanArgs {
    #[command(flatten)]
    source: SourceArgs,
    /// Also look at this machine and say, step by step, what applying would change: `ok`
    /// (already so), `change`, `run` (commands and checks always run), `done` (applied by an
    /// earlier run) or `?` (can't tell without doing it). Changes nothing.
    #[arg(long)]
    check: bool,
    /// Secrets for the check, as `apply --secrets-file` takes them; without them, steps that
    /// use a secret show as `?`.
    #[arg(long, value_name = "FILE")]
    secrets_file: Option<PathBuf>,
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
    /// Update this agent before applying: `--update` for the latest, `--update=0.5.0` to pin.
    /// Off unless given (the logon task's pending.json defaults to latest instead).
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "latest", value_name = "POLICY")]
    update: Option<String>,
    /// Where agent updates come from: an agent.json manifest, or a folder, share or URL
    /// holding one (default: GitHub releases).
    #[arg(long, value_name = "SOURCE")]
    update_from: Option<String>,
    /// A JSON file of secrets the Groundhogfile names, `{ "NAME": "value" }`. They can also
    /// come from GROUNDHOG_SECRET_<NAME> environment variables.
    #[arg(long, value_name = "FILE")]
    secrets_file: Option<PathBuf>,
    /// Show every step and what it did (what the log file in <home>\last-run always has),
    /// instead of a line for each part of the file.
    #[arg(long, short)]
    verbose: bool,
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
            let mut pending = to_pending(&args.source, args.report, args.reboot)?;
            pending.agent_update = Some(args.update.unwrap_or_else(|| "off".to_owned()));
            pending.agent_update_from = args.update_from;
            if let Some(file) = &args.secrets_file {
                pending.secrets = secrets::read_file(file)?;
            }
            let state = match apply(home, &pending, args.fresh, args.verbose)? {
                Applied::Ran(state) => *state,
                Applied::HandedOver(code) => return Ok(code),
            };
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
            let mut pending = to_pending(&args.source, Vec::new(), false)?;
            if let Some(file) = &args.secrets_file {
                pending.secrets = secrets::read_file(file)?;
            }
            print_plan(home, &pending, args.check)?;
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
        Command::Clean => {
            clean(home)?;
            Ok(0)
        }
        Command::Update { to, from } => {
            let settings = update::Settings { policy: Policy::parse(&to)?, from };
            let session = Session::new(home, &Pending { source: String::new(), ..Pending::default() }, false)?;
            let content = ContentStore { fetcher: &session.fetcher, cache: &session.cache };
            match update::update_now(&settings, home, &content, &session.reporter)? {
                Some(path) => println!("installed {}", path.display()),
                None => println!("groundhog-agent {} is up to date", Version::current()),
            }
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
        agent_update: None,
        agent_update_from: None,
        secrets: Default::default(),
        vars: args
            .vars
            .iter()
            .map(|s| {
                let (name, value) = s.split_once('=').with_context(|| format!("--var {s}: write it as NAME=value"))?;
                Ok((name.trim().to_owned(), value.to_owned()))
            })
            .collect::<Result<_>>()?,
    })
}

/// What `when:` conditions and built-in variables see: this machine.
fn machine_facts() -> groundhog_core::vars::Facts {
    let (build, server) = groundhog_win::system::windows_version();
    groundhog_core::vars::Facts {
        build,
        os: if server { "server" } else { "client" }.to_owned(),
        ..groundhog_core::vars::Facts::of_this_process()
    }
}

fn parse_header(s: &str, default_host: Option<&str>) -> Result<HeaderRule> {
    HeaderRule::parse(s, default_host)
}

struct Session {
    fetcher: DefaultFetcher,
    cache: Cache,
    reporter: MultiReporter,
}

impl Session {
    fn new(home: &Path, p: &Pending, verbose: bool) -> Result<Self> {
        // A local object store comes first: content fetched while loading (to resolve "latest"
        // URLs) is reused when the step runs instead of being downloaded twice.
        let mut sources: Vec<Box<dyn CacheSource>> = vec![Box::new(FolderCache { root: home.join("objects") })];
        for c in &p.cache {
            sources.push(parse_cache_source(c)?);
        }
        let cache = Cache::new(sources);
        // A header's value may be ${secret:NAME}, so a token can travel with the secrets
        // (scrubbed from pending.json on read) instead of in plain text beside them.
        let headers = if p.headers.iter().any(|h| groundhog_core::secret::mentions(&h.value)) {
            let secrets = secrets::gather(home, &p.secrets)?;
            p.headers
                .iter()
                .map(|h| {
                    let value = groundhog_core::secret::substitute(&h.value, |n| {
                        secrets.get(n).cloned().ok_or_else(|| anyhow::anyhow!(secrets::missing_hint(n)))
                    })
                    .with_context(|| format!("header {} for {}", h.name, h.host))?;
                    Ok(HeaderRule { value, ..h.clone() })
                })
                .collect::<Result<Vec<_>>>()?
        } else {
            p.headers.clone()
        };
        let console: Box<dyn Reporter> = if verbose { Box::new(ConsoleReporter) } else { Box::new(human(home)) };
        let mut reporters: Vec<Box<dyn Reporter>> =
            vec![console, Box::new(FolderReporter { dir: home.join("last-run") })];
        for sink in &p.report {
            reporters.push(parse_report_sink(sink, &headers)?);
        }
        Ok(Self {
            fetcher: DefaultFetcher { headers, allow_http: p.allow_http },
            cache,
            reporter: MultiReporter(reporters),
        })
    }

    fn load(&self, home: &Path, p: &Pending) -> Result<(url::Url, Loaded)> {
        let root = source_ref(&p.source, p.sha256.clone(), &std::env::current_dir()?)?;
        let content = ContentStore { fetcher: &self.fetcher, cache: &self.cache };
        let loader = Loader::new(&content, home.join("bundles")).with_facts(machine_facts()).with_vars(p.vars.clone());
        let loaded = loader.load(&root)?;
        Ok((root.url, loaded))
    }
}

enum Applied {
    Ran(Box<RunState>),
    /// A newer agent took over this run; its exit code is the result.
    HandedOver(i32),
}

/// The console as a person reads it: a line for each part of the file, redrawn in place and
/// in color when stdout is a console.
fn human(home: &Path) -> HumanReporter {
    let live = std::io::stdout().is_terminal();
    let color = live && std::env::var_os("NO_COLOR").is_none() && console::enable_colors();
    let width = console::width().unwrap_or(80);
    HumanReporter::new(Box::new(std::io::stdout()), live, color, width, Some(home.join("last-run").join(LOG_FILE)))
}

fn apply(home: &Path, p: &Pending, fresh: bool, verbose: bool) -> Result<Applied> {
    let session = Session::new(home, p, verbose)?;
    let reporter = &session.reporter;
    reporter.log(&format!("groundhog-agent {} applying {}", env!("CARGO_PKG_VERSION"), p.source));
    if !p.cache.is_empty() {
        reporter.log(&format!("cache: {}", p.cache.join(", ")));
    }
    if !token::is_elevated() {
        reporter.note("warning: not running elevated; machine-wide installs and HKLM changes will fail");
    }

    // Keep a template's frozen agent current before it reads a file written for a newer one.
    let settings = update::Settings {
        policy: Policy::parse(p.agent_update.as_deref().unwrap_or("latest"))?,
        from: p.agent_update_from.clone(),
    };
    let content = ContentStore { fetcher: &session.fetcher, cache: &session.cache };
    if let update::Outcome::HandedOver(code) = update::run(&settings, home, &content, reporter) {
        return Ok(Applied::HandedOver(code));
    }

    let loaded = session.load(home, p).and_then(|(url, loaded)| match &loaded.file.requires_agent {
        Some(required) if *required > Version::current() => {
            Err(anyhow::anyhow!(update::explain_requirement(required, &settings)))
        }
        _ => Ok((url, loaded)),
    });
    warn_about_clock_skew(reporter);
    let (url, loaded) = match loaded {
        Ok(v) => v,
        Err(e) => {
            let e = match e.downcast_ref::<NeedsAgent>() {
                Some(n) => anyhow::anyhow!(update::explain_requirement(&n.required, &settings)),
                None => e,
            };
            // Tell anyone watching, or a host would wait forever for a run that never starts.
            let state = failed_before_start(p, &e);
            reporter.note(&format!("failed: {e:#}"));
            reporter.status(&state);
            return Ok(Applied::Ran(Box::new(state)));
        }
    };

    let secrets = secrets::gather(home, &p.secrets)?;
    // Every ${secret:NAME} must have a usable value before anything changes. (Account
    // passwords are checked when an account needs one: an existing account doesn't.)
    let referenced: BTreeSet<String> = plan(&loaded.file).iter().flat_map(|s| engine::secrets_in(&s.action)).collect();
    let missing: Vec<&String> = referenced.iter().filter(|n| !secrets.contains_key(*n)).collect();
    let short: Vec<&String> = referenced
        .iter()
        .filter(|n| secrets.get(*n).is_some_and(|v| v.len() < groundhog_core::secret::MIN_REDACTABLE))
        .collect();
    let problem = if missing.len() == 1 {
        Some(secrets::missing_hint(missing[0]))
    } else if !missing.is_empty() {
        let names: Vec<&str> = missing.iter().map(|s| s.as_str()).collect();
        Some(format!(
            "secrets not provided: {}. Add them to \"secrets\" in pending.json (groundhog pending --secret NAME), \
             set GROUNDHOG_SECRET_<NAME>, or pass --secrets-file",
            names.join(", ")
        ))
    } else if !short.is_empty() {
        let names: Vec<&str> = short.iter().map(|s| s.as_str()).collect();
        Some(format!(
            "secrets shorter than {} characters can't be kept out of logs, so they can't be used in ${{secret:...}}: {}",
            groundhog_core::secret::MIN_REDACTABLE,
            names.join(", ")
        ))
    } else {
        None
    };
    if let Some(problem) = problem {
        let e = anyhow::anyhow!(problem);
        let state = failed_before_start(p, &e);
        reporter.note(&format!("failed: {e:#}"));
        reporter.status(&state);
        return Ok(Applied::Ran(Box::new(state)));
    }

    let prints = secrets::fingerprints(home, &secrets)?;
    let steps = engine::plan_with_secrets(&loaded.file, &|name| prints.get(name).cloned());
    let redact = Redactor::new(secrets.values());
    let mut exec = WinExecutor::new(&content, home.join("work"), secrets.clone());
    let state = engine::run(
        &steps,
        &mut exec,
        reporter,
        RunOptions { source: &url, sources: loaded.sources, state_path: &state_file(home, &url), fresh, redact },
    )?;
    reporter.log(&format!("{:?}: {}", state.status, state.message.as_deref().unwrap_or_default()));
    // Secrets outlive a run only while it's paused for a restart, encrypted for this user.
    match state.status {
        RunStatus::RebootPending => secrets::save_store(home, &secrets)?,
        _ => secrets::delete_store(home)?,
    }
    Ok(Applied::Ran(Box::new(state)))
}

/// Beyond this, a wrong clock is worth saying out loud.
const CLOCK_SKEW_WARNING_SECS: i64 = 5 * 60;

/// Says when this machine's clock is far from a server's. It only warns: a VM whose clock
/// is hours off gets certificate errors that look like anything but a clock problem, and
/// timestamps that disagree with the host's logs. Fixing it belongs to the template or the
/// hypervisor (or `groundhog:time-sync`), not to a run that happens to notice.
fn warn_about_clock_skew(reporter: &dyn Reporter) {
    let Some((skew, host)) = groundhog_core::fetch::observed_clock_skew() else { return };
    if skew.abs() < CLOCK_SKEW_WARNING_SECS {
        return;
    }
    let by = humantime::format_duration(std::time::Duration::from_secs(skew.unsigned_abs() / 60 * 60));
    let direction = if skew > 0 { "behind" } else { "ahead of" };
    reporter.note(&format!(
        "warning: this machine's clock is {by} {direction} {host}'s; certificates and timestamps can go wrong. \
         Turn on time sync (groundhog:time-sync), or fix the VM's clock setting"
    ));
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
        agent: env!("CARGO_PKG_VERSION").to_owned(),
    }
}

fn run_pending(home: &Path) -> Result<i32> {
    let path = home.join(PENDING_FILE);
    let Ok(bytes) = std::fs::read(&path) else {
        println!("nothing pending ({} not found)", path.display());
        return Ok(0);
    };
    let mut pending: Pending = serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?;
    // Take secrets out of the plain-text file right away; they live on only encrypted.
    if !pending.secrets.is_empty() {
        let mut stored = secrets::load_store(home)?;
        stored.extend(std::mem::take(&mut pending.secrets));
        secrets::save_store(home, &stored)?;
        engine::write_json_atomic(&path, &pending)?;
    }
    let state = match apply(home, &pending, false, false)? {
        Applied::Ran(state) => *state,
        // The newer agent handled the pending file, reboots included.
        Applied::HandedOver(code) => return Ok(code),
    };
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
    // Secrets were saved encrypted when the run paused; the plain-text file never holds them.
    engine::write_json_atomic(&home.join(PENDING_FILE), &Pending { secrets: Default::default(), ..p.clone() })?;
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

fn print_plan(home: &Path, p: &Pending, check: bool) -> Result<()> {
    let session = Session::new(home, &Pending { report: Vec::new(), ..p.clone() }, true)?;
    println!("groundhog-agent {}", Version::current());
    let (_, loaded) = session.load(home, p)?;
    for s in &loaded.sources {
        println!("source  {}  sha256:{}", s.url, s.sha256);
    }
    let needed = required_secrets(&loaded.file);
    if !needed.is_empty() {
        let have = secrets::gather(home, &p.secrets)?;
        let listed: Vec<String> = needed
            .iter()
            .map(|n| format!("{n} ({})", if have.contains_key(n) { "provided" } else { "missing" }))
            .collect();
        println!("secrets {}", listed.join(", "));
    }
    // The same check `apply` makes, so `plan` never passes a file this agent can't apply.
    if let Some(required) = &loaded.file.requires_agent
        && *required > Version::current()
    {
        bail!("this Groundhogfile needs groundhog-agent {required} or newer, and this is {}", Version::current());
    }
    if !check {
        for (i, step) in plan(&loaded.file).iter().enumerate() {
            println!("{:>3}. [{}] {}", i + 1, step.id, step.title);
        }
        return Ok(());
    }

    // The same step ids apply would use, so "applied by an earlier run" is exact.
    let secrets = secrets::gather(home, &p.secrets)?;
    let prints = secrets::fingerprints(home, &secrets)?;
    let steps = engine::plan_with_secrets(&loaded.file, &|name| prints.get(name).cloned());
    let url = source_ref(&p.source, p.sha256.clone(), &std::env::current_dir()?)?.url;
    let content = ContentStore { fetcher: &session.fetcher, cache: &session.cache };
    let mut exec = WinExecutor::new(&content, home.join("work"), secrets);
    let previews = engine::preview(&steps, &mut exec, &state_file(home, &url));
    let mut counts = std::collections::BTreeMap::<&str, usize>::new();
    for (i, (step, preview)) in steps.iter().zip(&previews).enumerate() {
        let (mark, note) = match preview {
            engine::Preview::Applied => ("done", String::new()),
            engine::Preview::Probe(engine::Probe::Satisfied) => ("ok", String::new()),
            engine::Preview::Probe(engine::Probe::WouldChange) => ("change", String::new()),
            engine::Preview::Probe(engine::Probe::WillRun) => ("run", String::new()),
            engine::Preview::Probe(engine::Probe::Unknown) => ("?", String::new()),
            engine::Preview::Error(e) => ("error", format!("  ({e})")),
        };
        *counts.entry(mark).or_default() += 1;
        println!("{:>3}. [{}] {mark:<6} {}{note}", i + 1, step.id, step.title);
    }
    let summary: Vec<String> = ["change", "run", "?", "error", "ok", "done"]
        .iter()
        .filter_map(|m| counts.get(m).map(|n| format!("{n} {m}")))
        .collect();
    println!("{}", summary.join(", "));
    Ok(())
}

/// What a run leaves in the home folder. `bin` (the installed agent) is kept.
const RUN_LEFTOVERS: &[&str] = &[
    PENDING_FILE,
    "pending.done.json",
    "pending.failed.json",
    secrets::STORE,
    secrets::SALT,
    "last-run",
    "runs",
    "objects",
    "work",
    "bundles",
    "versions",
];

fn clean(home: &Path) -> Result<()> {
    if home.join(PENDING_FILE).exists() {
        println!("note: removing a queued {PENDING_FILE}; it will not be applied");
    }
    let mut removed = 0;
    for name in RUN_LEFTOVERS {
        let path = home.join(name);
        let result = if path.is_dir() {
            std::fs::remove_dir_all(&path)
        } else if path.exists() {
            std::fs::remove_file(&path)
        } else {
            continue;
        };
        result.with_context(|| format!("removing {}", path.display()))?;
        println!("removed {}", path.display());
        removed += 1;
    }
    // Copies an update set aside; one still running (this one, say) stays until next time.
    if let Ok(entries) = std::fs::read_dir(home.join("bin")) {
        for entry in entries.filter_map(Result::ok) {
            if entry.file_name().to_string_lossy().contains(".old-") && std::fs::remove_file(entry.path()).is_ok() {
                println!("removed {}", entry.path().display());
                removed += 1;
            }
        }
    }
    if removed == 0 {
        println!("nothing to clean in {}", home.display());
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
        println!("{:?}  {}  (updated {}, agent {})", state.status, state.source, state.updated, state.agent);
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
    fn clean_leaves_only_the_installed_agent() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        for d in ["bin", "last-run", "runs", "objects/sha256", "work/downloads", "bundles", "versions/0.1.0"] {
            std::fs::create_dir_all(home.join(d)).unwrap();
        }
        for f in [
            "bin/groundhog-agent.exe",
            "bin/groundhog-agent.exe.old-1",
            "pending.json",
            "pending.done.json",
            "pending.failed.json",
            "secrets.bin",
            "secret-salt.bin",
            "runs/x.json",
        ] {
            std::fs::write(home.join(f), "x").unwrap();
        }
        clean(home).unwrap();
        let left: Vec<String> = walk(home);
        assert_eq!(left, ["bin", "bin/groundhog-agent.exe"]);
        clean(home).unwrap();

        fn walk(root: &Path) -> Vec<String> {
            let mut out = Vec::new();
            let mut stack = vec![root.to_path_buf()];
            while let Some(d) = stack.pop() {
                for e in std::fs::read_dir(&d).unwrap().filter_map(Result::ok) {
                    let p = e.path();
                    out.push(p.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/"));
                    if p.is_dir() {
                        stack.push(p);
                    }
                }
            }
            out.sort();
            out
        }
    }

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
