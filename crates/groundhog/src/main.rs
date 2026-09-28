//! `groundhog`: the optional host side. It starts a target (Windows Sandbox for now; Hyper-V
//! and Proxmox next), hands the agent a Groundhogfile, and watches progress. Everything that
//! changes the target is done by `groundhog-agent` inside it.

mod sandbox;
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
}

#[derive(Args)]
struct PendingArgs {
    /// Path, URL or zip bundle, as the agent inside the VM will see it.
    source: String,
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
    /// Where to write the file.
    #[arg(short, long, default_value = PENDING_FILE)]
    output: PathBuf,
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
            let pending = Pending {
                source: a.source,
                sha256: a.sha256,
                cache: a.cache,
                report: a.report,
                headers: Vec::new(),
                allow_reboot: !a.no_reboot,
                allow_http: a.allow_http,
            };
            write_json_atomic(&a.output, &pending).with_context(|| format!("writing {}", a.output.display()))?;
            println!("wrote {}", a.output.display());
            Ok(0)
        }
    }
}
