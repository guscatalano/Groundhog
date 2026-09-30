//! Windows Sandbox provider.
//!
//! Generates a `.wsb` file that maps the agent, the Groundhogfile's folder, an optional cache
//! and a status folder into the sandbox, and runs the agent at logon. Sandbox logs on by
//! itself and is thrown away on close, so there is no template to maintain.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::Args;

use crate::watch;

const IN_AGENT: &str = r"C:\groundhog\agent";
const IN_BUNDLE: &str = r"C:\groundhog\bundle";
const IN_CACHE: &str = r"C:\groundhog\cache";
const IN_STATUS: &str = r"C:\groundhog\status";

#[derive(Args)]
pub struct SandboxArgs {
    /// Path, URL or zip bundle of the Groundhogfile.
    source: String,
    /// Host folder to use as a shared, writable cache (created if missing). Downloads made in
    /// one sandbox are reused by the next.
    #[arg(long)]
    cache: Option<PathBuf>,
    /// The groundhog-agent.exe to run inside (default: next to this executable).
    #[arg(long)]
    agent: Option<PathBuf>,
    /// Folder to map as the bundle, when a local Groundhogfile references files outside its
    /// own folder (e.g. `extends: ../base.yaml`). Default: the Groundhogfile's folder.
    #[arg(long)]
    map_root: Option<PathBuf>,
    #[arg(long, default_value_t = 8192)]
    memory_mb: u32,
    /// Allow plain http:// inside the sandbox.
    #[arg(long)]
    allow_http: bool,
    /// Only write the .wsb file and print its path.
    #[arg(long)]
    no_launch: bool,
    /// Launch, but don't follow progress.
    #[arg(long)]
    no_wait: bool,
}

#[derive(Debug, PartialEq)]
pub(crate) struct Mapping {
    pub host: PathBuf,
    pub sandbox: &'static str,
    pub read_only: bool,
}

#[derive(Debug)]
pub(crate) struct Wsb {
    pub memory_mb: u32,
    pub mappings: Vec<Mapping>,
    pub logon_command: String,
}

impl Wsb {
    pub fn render(&self) -> String {
        let mut x = String::from("<Configuration>\n");
        x += &format!("  <MemoryInMB>{}</MemoryInMB>\n  <MappedFolders>\n", self.memory_mb);
        for m in &self.mappings {
            x += &format!(
                "    <MappedFolder>\n      <HostFolder>{}</HostFolder>\n      <SandboxFolder>{}</SandboxFolder>\n      <ReadOnly>{}</ReadOnly>\n    </MappedFolder>\n",
                xml_escape(&m.host.to_string_lossy()),
                xml_escape(m.sandbox),
                m.read_only
            );
        }
        x += "  </MappedFolders>\n  <LogonCommand>\n";
        x += &format!("    <Command>{}</Command>\n", xml_escape(&self.logon_command));
        x += "  </LogonCommand>\n</Configuration>\n";
        x
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
}

/// Decides what to map for the source and how the agent inside should refer to it.
pub(crate) fn map_source(source: &str, map_root: Option<&Path>) -> Result<(Option<Mapping>, String)> {
    let is_url = (source.contains("://") && !source.starts_with("file://")) || source.starts_with("groundhog:");
    if is_url {
        return Ok((None, source.to_owned()));
    }
    let path = std::path::absolute(source).with_context(|| format!("resolving {source}"))?;
    if !path.exists() {
        bail!("{} does not exist", path.display());
    }
    let root = match map_root {
        Some(r) => std::path::absolute(r)?,
        None if path.is_dir() => path.clone(),
        None => path.parent().context("source has no parent folder")?.to_path_buf(),
    };
    let rel = path
        .strip_prefix(&root)
        .with_context(|| format!("{} is not inside --map-root {}", path.display(), root.display()))?;
    let inside =
        if rel.as_os_str().is_empty() { IN_BUNDLE.to_owned() } else { format!(r"{IN_BUNDLE}\{}", rel.display()) };
    Ok((Some(Mapping { host: root, sandbox: IN_BUNDLE, read_only: true }), inside))
}

pub fn run(args: SandboxArgs) -> Result<i32> {
    let agent = match &args.agent {
        Some(a) => a.clone(),
        None => std::env::current_exe()?.with_file_name("groundhog-agent.exe"),
    };
    if !agent.is_file() {
        bail!("agent not found at {} (build it, or pass --agent)", agent.display());
    }

    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from).context("LOCALAPPDATA not set")?;
    let staging = base.join("groundhog").join("sandbox").join(stamp.to_string());
    let (agent_dir, status_dir) = (staging.join("agent"), staging.join("status"));
    std::fs::create_dir_all(&agent_dir)?;
    std::fs::create_dir_all(&status_dir)?;
    // Copy the agent so rebuilding it on the host never fights a running sandbox for the file.
    std::fs::copy(&agent, agent_dir.join("groundhog-agent.exe"))?;

    let mut mappings = vec![
        Mapping { host: agent_dir, sandbox: IN_AGENT, read_only: true },
        Mapping { host: status_dir.clone(), sandbox: IN_STATUS, read_only: false },
    ];
    let (bundle, inside_source) = map_source(&args.source, args.map_root.as_deref())?;
    mappings.extend(bundle);

    let mut agent_args = format!(r#"apply "{inside_source}" --report {IN_STATUS}"#);
    if let Some(cache) = &args.cache {
        std::fs::create_dir_all(cache)?;
        mappings.push(Mapping { host: std::path::absolute(cache)?, sandbox: IN_CACHE, read_only: false });
        agent_args += &format!(" --cache {IN_CACHE}");
    }
    if args.allow_http {
        agent_args += " --allow-http";
    }

    // `start` gives the agent a visible console window; `/k` keeps it open to read afterwards.
    let wsb = Wsb {
        memory_mb: args.memory_mb,
        mappings,
        logon_command: format!(
            r#"cmd.exe /c start "groundhog" cmd.exe /k {IN_AGENT}\groundhog-agent.exe {agent_args}"#
        ),
    };
    let wsb_path = staging.join("groundhog.wsb");
    std::fs::write(&wsb_path, wsb.render())?;
    println!("sandbox config: {}", wsb_path.display());
    if args.no_launch {
        return Ok(0);
    }

    let exe = PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into()))
        .join(r"System32\WindowsSandbox.exe");
    if !exe.is_file() {
        bail!("Windows Sandbox is not installed; enable the 'Windows Sandbox' optional feature");
    }
    let status = std::process::Command::new("cmd.exe").args(["/c", "start", ""]).arg(&wsb_path).status()?;
    if !status.success() {
        bail!("failed to launch Windows Sandbox");
    }
    if args.no_wait {
        println!("status folder: {}", status_dir.display());
        return Ok(0);
    }

    let state = watch::follow(&status_dir);
    println!("{:?}: {}", state.status, state.message.as_deref().unwrap_or_default());
    Ok(watch::exit_code(&state))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_escaped_wsb() {
        let wsb = Wsb {
            memory_mb: 4096,
            mappings: vec![Mapping { host: r"C:\a&b".into(), sandbox: IN_AGENT, read_only: true }],
            logon_command: r#"cmd /c start "x" y.exe"#.into(),
        };
        let xml = wsb.render();
        assert!(xml.contains(r"<HostFolder>C:\a&amp;b</HostFolder>"));
        assert!(xml.contains("<Command>cmd /c start &quot;x&quot; y.exe</Command>"));
        assert!(xml.contains("<ReadOnly>true</ReadOnly>"));
    }

    #[test]
    fn maps_local_sources_and_passes_urls_through() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("team");
        std::fs::create_dir_all(&sub).unwrap();
        let file = sub.join("dev.yaml");
        std::fs::write(&file, "").unwrap();

        let (m, inside) = map_source(file.to_str().unwrap(), None).unwrap();
        assert_eq!(m.unwrap().host, sub);
        assert_eq!(inside, r"C:\groundhog\bundle\dev.yaml");

        let (m, inside) = map_source(file.to_str().unwrap(), Some(dir.path())).unwrap();
        assert_eq!(m.unwrap().host, dir.path());
        assert_eq!(inside, r"C:\groundhog\bundle\team\dev.yaml");

        let (m, _) = map_source("groundhog:windbg", None).unwrap();
        assert!(m.is_none());
        let (m, inside) = map_source("https://cfg.test/dev.yaml", None).unwrap();
        assert!(m.is_none());
        assert_eq!(inside, "https://cfg.test/dev.yaml");

        assert!(map_source(file.to_str().unwrap(), Some(&sub.join("elsewhere"))).is_err());
    }
}
