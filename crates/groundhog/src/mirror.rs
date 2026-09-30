//! `groundhog mirror-agent`: copies a release's agents and `agent.json` into a folder, so a
//! share or internal web server can serve agent updates without anyone reaching GitHub.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Args;
use groundhog_core::cache::Cache;
use groundhog_core::content::ContentStore;
use groundhog_core::engine::write_json_atomic;
use groundhog_core::fetch::DefaultFetcher;
use groundhog_core::update::{self, MANIFEST_FILE, Manifest, Policy, Version};

#[derive(Args)]
pub struct MirrorArgs {
    /// Folder or UNC share to fill. Agents point at it with `--update-from`.
    dir: PathBuf,
    /// `latest`, or the release version to mirror.
    #[arg(long, default_value = "latest", value_name = "VERSION")]
    version: String,
    /// Copy from this update source instead of GitHub releases (another mirror, say).
    #[arg(long, value_name = "SOURCE")]
    from: Option<String>,
}

pub fn run(args: MirrorArgs) -> Result<i32> {
    let policy = match Policy::parse(&args.version)? {
        Policy::Off => bail!("--version must be latest or a version"),
        p => p,
    };
    let manifest_url = update::manifest_url(args.from.as_deref(), &policy, &std::env::current_dir()?)?;
    let fetcher = DefaultFetcher::default();
    let cache = Cache::default();
    let content = ContentStore { fetcher: &fetcher, cache: &cache };

    let bytes = content.get(&manifest_url, None).with_context(|| format!("reading {manifest_url}"))?.bytes;
    let manifest: Manifest = serde_json::from_slice(&bytes).with_context(|| format!("parsing {manifest_url}"))?;
    let version = Version::parse(&manifest.version)?;
    if let Policy::Pinned(wanted) = &policy
        && *wanted != version
    {
        bail!("{manifest_url} is version {version}, not {wanted}");
    }

    std::fs::create_dir_all(&args.dir).with_context(|| format!("creating {}", args.dir.display()))?;
    for (arch, entry) in &manifest.agents {
        let url = manifest_url.join(&entry.file)?;
        // Verified against the manifest's hash before anything is written.
        let file = content.get(&url, Some(&entry.sha256)).with_context(|| format!("downloading {url}"))?;
        let name = std::path::Path::new(&entry.file).file_name().context("manifest file name")?;
        let dest = args.dir.join(name);
        std::fs::write(&dest, &file.bytes).with_context(|| format!("writing {}", dest.display()))?;
        println!("{arch:>6}  {}", dest.display());
    }

    // Written last, and pointing at the files by bare name, so the folder only ever advertises
    // agents that are fully in place next to it.
    let local = Manifest {
        version: manifest.version.clone(),
        agents: manifest
            .agents
            .into_iter()
            .map(|(arch, mut e)| {
                e.file = std::path::Path::new(&e.file)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or(e.file);
                (arch, e)
            })
            .collect(),
    };
    write_json_atomic(&args.dir.join(MANIFEST_FILE), &local)?;
    println!("mirrored groundhog-agent {version} into {}", args.dir.display());
    println!("agents update from it with: --update-from \"{}\"", args.dir.display());
    Ok(0)
}
