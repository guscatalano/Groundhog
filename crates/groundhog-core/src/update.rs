//! Finding a newer agent. Anything that serves an `agent.json` manifest is an update source:
//! GitHub releases publish one, and so can a folder, a UNC share or any web server holding a
//! copy of the release files. That lets a lab mirror the agent instead of reaching GitHub.

use std::cmp::Ordering;
use std::fmt;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::content::ContentStore;
use crate::fetch::{normalize_sha256, parse_location};

/// Where agents come from when no other source is configured.
pub const GITHUB_RELEASES: &str = "https://github.com/guscatalano/Groundhog/releases";
pub const MANIFEST_FILE: &str = "agent.json";

/// A release version: `major.minor.patch`, optionally with a `-pre` suffix that sorts before
/// the same version without one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub parts: [u64; 3],
    pub pre: Option<String>,
}

impl Version {
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim().trim_start_matches('v');
        let (core, pre) = match s.split_once('-') {
            Some((c, p)) => (c, Some(p.to_owned())),
            None => (s, None),
        };
        let nums: Vec<&str> = core.split('.').collect();
        if nums.is_empty() || nums.len() > 3 {
            bail!("invalid version '{s}': expected major.minor.patch");
        }
        let mut parts = [0u64; 3];
        for (i, n) in nums.iter().enumerate() {
            parts[i] = n.parse().map_err(|_| anyhow!("invalid version '{s}': expected major.minor.patch"))?;
        }
        Ok(Self { parts, pre })
    }

    /// The version this binary was built as.
    pub fn current() -> Self {
        Self::parse(env!("CARGO_PKG_VERSION")).expect("crate version is valid")
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.parts.cmp(&other.parts).then_with(|| match (&self.pre, &other.pre) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(a), Some(b)) => a.cmp(b),
        })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c] = self.parts;
        write!(f, "{a}.{b}.{c}")?;
        if let Some(p) = &self.pre {
            write!(f, "-{p}")?;
        }
        Ok(())
    }
}

/// A Groundhogfile's `agent:` line: the oldest agent that understands it. Written `">=0.5.0"`,
/// or just `"0.5.0"`, which means the same.
pub fn parse_requirement(s: &str) -> Result<Version> {
    let v = s.trim();
    let v = v.strip_prefix(">=").unwrap_or(v);
    if v.starts_with(['<', '>', '=', '~', '^']) {
        bail!("'agent: {s}' is not supported; write the oldest agent version that works, as '>=0.5.0'");
    }
    Version::parse(v).with_context(|| format!("in 'agent: {s}'"))
}

/// How the agent keeps itself current.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Policy {
    Off,
    /// Whatever the source offers, when it's newer than this agent.
    Latest,
    /// Exactly this version, up or down.
    Pinned(Version),
}

impl Policy {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s.trim() {
            "off" | "never" => Policy::Off,
            "latest" => Policy::Latest,
            v => Policy::Pinned(
                Version::parse(v).map_err(|_| anyhow!("agent update policy '{s}' must be latest, off or a version"))?,
            ),
        })
    }
}

impl fmt::Display for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Policy::Off => f.write_str("off"),
            Policy::Latest => f.write_str("latest"),
            Policy::Pinned(v) => write!(f, "{v}"),
        }
    }
}

/// `agent.json`: which version a source serves, and the agent for each architecture.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: String,
    pub agents: std::collections::BTreeMap<String, ManifestEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// Relative to the manifest, like every other reference in Groundhog.
    pub file: String,
    pub sha256: String,
}

/// This machine's architecture, as manifests name it.
pub fn arch() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        _ => "x64",
    }
}

/// The manifest URL for a source: the manifest itself, or a folder, share or URL that holds
/// one. Without a source, GitHub releases (the latest one, or the pinned version's).
pub fn manifest_url(from: Option<&str>, policy: &Policy, cwd: &std::path::Path) -> Result<Url> {
    let Some(from) = from else {
        return Ok(match policy {
            Policy::Pinned(v) => Url::parse(&format!("{GITHUB_RELEASES}/download/v{v}/{MANIFEST_FILE}"))?,
            _ => Url::parse(&format!("{GITHUB_RELEASES}/latest/download/{MANIFEST_FILE}"))?,
        });
    };
    let mut url = parse_location(from, cwd)?;
    if !url.path().to_ascii_lowercase().ends_with(".json") {
        if !url.path().ends_with('/') {
            url.set_path(&format!("{}/", url.path()));
        }
        url = url.join(MANIFEST_FILE)?;
    }
    Ok(url)
}

/// An agent that should replace this one.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub version: Version,
    pub url: Url,
    pub sha256: String,
}

/// Asks the source what it serves and decides whether to switch to it: `latest` moves only
/// forward, a pinned version moves to exactly that version, `off` never asks.
pub fn find_update(
    content: &ContentStore,
    manifest: &Url,
    policy: &Policy,
    current: &Version,
) -> Result<Option<Candidate>> {
    if *policy == Policy::Off {
        return Ok(None);
    }
    let bytes = content.get(manifest, None).with_context(|| format!("reading {manifest}"))?.bytes;
    let m: Manifest = serde_json::from_slice(&bytes).with_context(|| format!("parsing {manifest}"))?;
    let offered = Version::parse(&m.version).with_context(|| format!("version in {manifest}"))?;

    let wanted = match policy {
        Policy::Off => unreachable!(),
        Policy::Latest => offered > *current,
        Policy::Pinned(v) => {
            if offered != *v {
                bail!("{manifest} serves {offered}, but the agent is pinned to {v}");
            }
            offered != *current
        }
    };
    if !wanted {
        return Ok(None);
    }
    let entry = m.agents.get(arch()).ok_or_else(|| anyhow!("{manifest} has no agent for {}", arch()))?;
    Ok(Some(Candidate {
        version: offered,
        url: manifest.join(&entry.file).with_context(|| format!("resolving {}", entry.file))?,
        sha256: normalize_sha256(&entry.sha256)?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::Cache;
    use crate::fetch::testing::MapFetcher;

    #[test]
    fn versions_order_like_releases() {
        let v = |s| Version::parse(s).unwrap();
        assert!(v("0.10.0") > v("0.9.9"));
        assert!(v("v1.0.0") > v("1.0.0-rc.1"));
        assert!(v("1.0.0-rc.2") > v("1.0.0-rc.1"));
        assert_eq!(v("0.5"), v("0.5.0"));
        assert_eq!(v("0.5.0-rc.1").to_string(), "0.5.0-rc.1");
        assert!(Version::parse("five").is_err());
    }

    #[test]
    fn requirements_are_minimum_versions() {
        assert_eq!(parse_requirement(">=0.5.0").unwrap(), Version::parse("0.5.0").unwrap());
        assert_eq!(parse_requirement("0.5.0").unwrap(), Version::parse("0.5.0").unwrap());
        assert!(parse_requirement("^0.5").unwrap_err().to_string().contains("not supported"));
    }

    #[test]
    fn policies_parse() {
        assert_eq!(Policy::parse("latest").unwrap(), Policy::Latest);
        assert_eq!(Policy::parse("off").unwrap(), Policy::Off);
        assert_eq!(Policy::parse("0.4.2").unwrap(), Policy::Pinned(Version::parse("0.4.2").unwrap()));
        assert!(Policy::parse("sometimes").is_err());
    }

    #[test]
    fn sources_resolve_to_a_manifest() {
        let cwd = std::path::Path::new(r"C:\work");
        let latest = manifest_url(None, &Policy::Latest, cwd).unwrap();
        assert_eq!(latest.as_str(), "https://github.com/guscatalano/Groundhog/releases/latest/download/agent.json");
        let pinned = manifest_url(None, &Policy::parse("0.5.0").unwrap(), cwd).unwrap();
        assert_eq!(pinned.as_str(), "https://github.com/guscatalano/Groundhog/releases/download/v0.5.0/agent.json");
        assert_eq!(
            manifest_url(Some(r"\\nas\gh\agent"), &Policy::Latest, cwd).unwrap().as_str(),
            "file://nas/gh/agent/agent.json"
        );
        assert_eq!(
            manifest_url(Some("https://mirror.lan/gh/"), &Policy::Latest, cwd).unwrap().as_str(),
            "https://mirror.lan/gh/agent.json"
        );
        assert_eq!(
            manifest_url(Some("https://mirror.lan/custom.json"), &Policy::Latest, cwd).unwrap().as_str(),
            "https://mirror.lan/custom.json"
        );
    }

    fn feed(version: &str) -> MapFetcher {
        let manifest = format!(
            r#"{{ "version": "{version}", "agents": {{
                "x64": {{ "file": "groundhog-agent-x64.exe", "sha256": "{0}" }},
                "arm64": {{ "file": "groundhog-agent-arm64.exe", "sha256": "{0}" }} }} }}"#,
            "a".repeat(64)
        );
        MapFetcher::default().with("https://mirror.lan/gh/agent.json", manifest)
    }

    fn decide(fetcher: &MapFetcher, policy: &str, current: &str) -> Result<Option<Candidate>> {
        let cache = Cache::default();
        let content = ContentStore { fetcher, cache: &cache };
        let url = Url::parse("https://mirror.lan/gh/agent.json").unwrap();
        find_update(&content, &url, &Policy::parse(policy)?, &Version::parse(current)?)
    }

    #[test]
    fn latest_updates_only_to_something_newer() {
        let c = decide(&feed("0.6.0"), "latest", "0.5.0").unwrap().unwrap();
        assert_eq!(c.version.to_string(), "0.6.0");
        assert!(c.url.as_str().starts_with("https://mirror.lan/gh/groundhog-agent-"));
        assert!(decide(&feed("0.5.0"), "latest", "0.5.0").unwrap().is_none());
        assert!(decide(&feed("0.4.0"), "latest", "0.5.0").unwrap().is_none(), "never downgrades on latest");
        assert!(decide(&feed("9.9.9"), "off", "0.5.0").unwrap().is_none());
    }

    #[test]
    fn pinned_moves_to_exactly_that_version() {
        assert_eq!(decide(&feed("0.4.0"), "0.4.0", "0.5.0").unwrap().unwrap().version.to_string(), "0.4.0");
        assert!(decide(&feed("0.4.0"), "0.4.0", "0.4.0").unwrap().is_none());
        let err = decide(&feed("0.6.0"), "0.4.0", "0.5.0").unwrap_err();
        assert!(err.to_string().contains("pinned to 0.4.0"), "{err}");
    }
}
