//! `groundhog`: the optional host side. It starts a target (Windows Sandbox for now; Hyper-V
//! and Proxmox next), hands the agent a Groundhogfile, and watches progress. Everything that
//! changes the target is done by `groundhog-agent` inside it.

mod mirror;
mod sandbox;
mod unattend;
mod watch;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use groundhog_core::cache::Cache;
use groundhog_core::content::ContentStore;
use groundhog_core::engine::{plan, write_json_atomic};
use groundhog_core::fetch::DefaultFetcher;
use groundhog_core::loader::{Loader, source_ref};
use groundhog_core::pending::{PENDING_FILE, Pending};

#[derive(Parser)]
#[command(name = "groundhog", version, about = "Brings fresh Windows machines to a known state")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Load a Groundhogfile and list the steps it would run.
    Plan {
        /// Path, URL or zip bundle.
        source: String,
        #[arg(long)]
        sha256: Option<String>,
        #[arg(long)]
        allow_http: bool,
    },
    /// Start a Windows Sandbox and apply a Groundhogfile inside it.
    Sandbox(sandbox::SandboxArgs),
    /// Write a pending.json bootstrap file for a templated VM (see docs/templates.md).
    Pending(PendingArgs),
    /// Write an unattend file that installs Windows (or finishes a sysprepped template) and
    /// then hands the machine to the agent (see docs/unattend.md).
    Unattend(Box<unattend::UnattendArgs>),
    /// Copy a release's agents and agent.json into a folder or share, to use as an update
    /// source (`--update-from` / `agentUpdateFrom`) that doesn't need GitHub.
    MirrorAgent(mirror::MirrorArgs),
}

#[derive(Args)]
struct PendingArgs {
    /// Path, URL or zip bundle, as the agent inside the VM will see it.
    source: String,
    #[command(flatten)]
    options: PendingOptions,
    /// Where to write the file.
    #[arg(short, long, default_value = PENDING_FILE)]
    output: PathBuf,
}

/// What goes into a pending.json besides the source; shared by `pending` and `unattend`.
#[derive(Args)]
pub(crate) struct PendingOptions {
    #[arg(long)]
    sha256: Option<String>,
    /// Cache sources as seen from inside the VM (UNC share or http URL). Repeatable.
    #[arg(long = "cache")]
    cache: Vec<String>,
    /// Report sinks as seen from inside the VM. Repeatable.
    #[arg(long = "report")]
    report: Vec<String>,
    /// Do not restart the VM automatically when a step needs it.
    #[arg(long)]
    no_reboot: bool,
    #[arg(long)]
    allow_http: bool,
    /// How the agent keeps itself current before applying: latest (the default), off, or a
    /// version to pin to.
    #[arg(long, value_name = "POLICY")]
    agent_update: Option<String>,
    /// Where agent updates come from, as seen from inside the VM: an agent.json manifest, or a
    /// folder, share or URL holding one (see `groundhog mirror-agent`). Default: GitHub releases.
    #[arg(long, value_name = "SOURCE")]
    agent_update_from: Option<String>,
    /// A secret the Groundhogfile names: `NAME=value`, or just `NAME` to take the value from
    /// the NAME environment variable (keeps it off the command line). Repeatable. The agent
    /// removes secrets from pending.json as soon as it reads it; until then the file holds
    /// them in plain text, so treat it like a password.
    #[arg(long = "secret", value_name = "NAME[=VALUE]")]
    secrets: Vec<String>,
}

impl PendingOptions {
    pub(crate) fn build(&self, source: &str) -> Result<Pending> {
        if let Some(policy) = &self.agent_update {
            groundhog_core::update::Policy::parse(policy)?;
        }
        Ok(Pending {
            source: source.to_owned(),
            sha256: self.sha256.clone(),
            cache: self.cache.clone(),
            report: self.report.clone(),
            headers: Vec::new(),
            allow_reboot: !self.no_reboot,
            allow_http: self.allow_http,
            agent_update: self.agent_update.clone(),
            agent_update_from: self.agent_update_from.clone(),
            secrets: self.secrets.iter().map(|s| secret_value(s)).collect::<Result<_>>()?,
        })
    }
}

/// `NAME=value`, or `NAME` with the value taken from the NAME environment variable.
pub(crate) fn secret_value(spec: &str) -> Result<(String, String)> {
    match spec.split_once('=') {
        Some((name, value)) => Ok((name.to_owned(), value.to_owned())),
        None => std::env::var(spec)
            .map(|v| (spec.to_owned(), v))
            .with_context(|| format!("secret {spec}: no environment variable named {spec}")),
    }
}

fn main() {
    let code = match run(Cli::parse().command) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            1
        }
    };
    std::process::exit(code);
}

fn run(command: Command) -> Result<i32> {
    match command {
        Command::Plan { source, sha256, allow_http } => {
            let root = source_ref(&source, sha256, &std::env::current_dir()?)?;
            let fetcher = DefaultFetcher { headers: Vec::new(), allow_http };
            let cache = Cache::default();
            let content = ContentStore { fetcher: &fetcher, cache: &cache };
            let scratch = std::env::temp_dir().join("groundhog-plan");
            let loaded = Loader { content: &content, bundle_dir: scratch }.load(&root)?;
            for s in &loaded.sources {
                println!("source  {}  sha256:{}", s.url, s.sha256);
            }
            for (i, step) in plan(&loaded.file).iter().enumerate() {
                println!("{:>3}. [{}] {}", i + 1, step.id, step.title);
            }
            Ok(0)
        }
        Command::Sandbox(args) => sandbox::run(args),
        Command::Pending(a) => {
            let pending = a.options.build(&a.source)?;
            write_json_atomic(&a.output, &pending).with_context(|| format!("writing {}", a.output.display()))?;
            println!("wrote {}", a.output.display());
            Ok(0)
        }
        Command::Unattend(args) => unattend::run(*args),
        Command::MirrorAgent(args) => mirror::run(args),
    }
}
