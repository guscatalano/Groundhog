//! `github:` references: files and installers from GitHub releases, resolved through the
//! releases API.
//!
//! ```text
//! github:OWNER/REPO@latest/ASSET     the newest release (with `prerelease: true`, including prereleases)
//! github:OWNER/REPO@TAG/ASSET        a specific release
//! github:OWNER/REPO@latest/source    that release's source code, as a zip
//! ```
//!
//! Each release is looked up once per load, so several references to `@latest` in one file,
//! such as an app and its source code, always resolve to the same release. When GitHub
//! publishes an asset's SHA-256 (its `digest`), that becomes the pin: the download is verified
//! and can come from a cache, and `plan` doesn't have to download it to know what it is.

use std::cell::RefCell;
use std::collections::HashMap;

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use url::Url;

use crate::fetch::{Fetcher, normalize_sha256};

pub const SCHEME: &str = "github";
/// Marks a reference as allowed to resolve to a prerelease (set from `prerelease: true`).
const PRERELEASE_QUERY: &str = "prerelease";

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Ref {
    Latest,
    Tag(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asset {
    Named(String),
    /// The release's source code (`archive/refs/tags/<tag>.zip`).
    Source,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubRef {
    pub owner: String,
    pub repo: String,
    pub reference: Ref,
    pub asset: Asset,
    pub prerelease: bool,
}

pub fn is_github(url: &Url) -> bool {
    url.scheme() == SCHEME
}

/// Records `prerelease: true` on a `github:` reference.
pub fn allow_prerelease(url: &mut Url) {
    url.set_query(Some(PRERELEASE_QUERY));
}

pub fn parse(url: &Url) -> Result<GithubRef> {
    let bad = || anyhow!("'{url}' should look like github:OWNER/REPO@latest/ASSET or github:OWNER/REPO@TAG/ASSET");
    let (repo_part, rest) = url.path().split_once('@').ok_or_else(bad)?;
    let (owner, repo) = repo_part.split_once('/').ok_or_else(bad)?;
    let (reference, asset) = rest.split_once('/').ok_or_else(bad)?;
    if [owner, repo, reference, asset].iter().any(|s| s.is_empty() || s.contains('/')) {
        return Err(bad());
    }
    Ok(GithubRef {
        owner: owner.to_owned(),
        repo: repo.to_owned(),
        reference: if reference == "latest" { Ref::Latest } else { Ref::Tag(reference.to_owned()) },
        asset: if asset == "source" { Asset::Source } else { Asset::Named(asset.to_owned()) },
        prerelease: url.query() == Some(PRERELEASE_QUERY),
    })
}

#[derive(Debug, Clone, PartialEq)]
pub struct Resolved {
    pub url: Url,
    /// GitHub's published digest for the asset, when it has one.
    pub sha256: Option<String>,
    pub tag: String,
}

#[derive(Debug, Clone, Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    assets: Vec<ReleaseAsset>,
}

#[derive(Debug, Clone, Deserialize)]
struct ReleaseAsset {
    name: String,
    browser_download_url: String,
    #[serde(default)]
    digest: Option<String>,
}

pub struct Resolver<'a> {
    fetcher: &'a dyn Fetcher,
    api: Url,
    releases: RefCell<HashMap<(String, String, Ref, bool), Release>>,
}

impl<'a> Resolver<'a> {
    pub fn new(fetcher: &'a dyn Fetcher) -> Self {
        Self::with_api(fetcher, Url::parse("https://api.github.com/").expect("valid"))
    }

    pub fn with_api(fetcher: &'a dyn Fetcher, api: Url) -> Self {
        Self { fetcher, api, releases: RefCell::new(HashMap::new()) }
    }

    pub fn resolve(&self, url: &Url) -> Result<Resolved> {
        let r = parse(url)?;
        let base = format!("https://github.com/{}/{}", r.owner, r.repo);

        // The source of a named tag needs no lookup; everything else asks for the release.
        if let (Asset::Source, Ref::Tag(tag)) = (&r.asset, &r.reference) {
            return Ok(Resolved {
                url: Url::parse(&format!("{base}/archive/refs/tags/{tag}.zip"))?,
                sha256: None,
                tag: tag.clone(),
            });
        }
        let release = self.release(&r)?;
        match &r.asset {
            Asset::Source => Ok(Resolved {
                url: Url::parse(&format!("{base}/archive/refs/tags/{}.zip", release.tag_name))?,
                sha256: None,
                tag: release.tag_name,
            }),
            Asset::Named(name) => {
                let asset = release.assets.iter().find(|a| a.name == *name).ok_or_else(|| {
                    let names: Vec<_> = release.assets.iter().map(|a| a.name.as_str()).collect();
                    anyhow!(
                        "release {} of {}/{} has no asset '{name}' (it has: {})",
                        release.tag_name,
                        r.owner,
                        r.repo,
                        if names.is_empty() { "none".to_owned() } else { names.join(", ") }
                    )
                })?;
                Ok(Resolved {
                    url: Url::parse(&asset.browser_download_url)?,
                    sha256: asset.digest.as_deref().and_then(|d| normalize_sha256(d).ok()),
                    tag: release.tag_name.clone(),
                })
            }
        }
    }

    fn release(&self, r: &GithubRef) -> Result<Release> {
        let key = (r.owner.clone(), r.repo.clone(), r.reference.clone(), r.prerelease);
        if let Some(found) = self.releases.borrow().get(&key) {
            return Ok(found.clone());
        }
        let repo = format!("repos/{}/{}/releases", r.owner, r.repo);
        let release = match (&r.reference, r.prerelease) {
            (Ref::Tag(tag), _) => self.get(&format!("{repo}/tags/{tag}"))?,
            (Ref::Latest, false) => self.get(&format!("{repo}/latest")).map_err(|e| {
                // GitHub's "latest" skips prereleases, so a repo that only publishes them has none.
                if !format!("{e:#}").contains("404") {
                    return e;
                }
                e.context(format!(
                    "{}/{} has no latest release; if its releases are prereleases, add 'prerelease: true'",
                    r.owner, r.repo
                ))
            })?,
            (Ref::Latest, true) => {
                // Newest first; drafts aren't downloadable.
                let all: Vec<Release> = self.get(&format!("{repo}?per_page=30"))?;
                all.into_iter()
                    .find(|rel| !rel.draft)
                    .ok_or_else(|| anyhow!("{}/{} has no releases", r.owner, r.repo))?
            }
        };
        self.releases.borrow_mut().insert(key, release.clone());
        Ok(release)
    }

    fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = self.api.join(path)?;
        let bytes = self.fetcher.fetch(&url).map_err(|e| {
            let text = format!("{e:#}");
            if text.contains("http status: 403") || text.contains("http status: 429") {
                // What GitHub answers once an address has used up its requests.
                return e.context(format!(
                    "asking GitHub: {url}: refused, most likely its limit of 60 requests an hour from one \
                     address without a token. Wait for it to reset, or pass one: \
                     --header \"api.github.com=Authorization: Bearer <token>\""
                ));
            }
            e.context(format!("asking GitHub: {url}"))
        })?;
        serde_json::from_slice(&bytes).with_context(|| format!("unexpected answer from {url}"))
    }
}

/// Only files and installers can come from `github:`.
pub fn reject(url: &Url, place: &str) -> Result<()> {
    if is_github(url) {
        bail!("'{url}': github: sources work in 'files' and 'apps', not {place}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetch::testing::MapFetcher;

    const API: &str = "https://api.github.com/repos/o/r/releases";

    fn gh(s: &str, prerelease: bool) -> Url {
        let mut u = Url::parse(s).unwrap();
        if prerelease {
            allow_prerelease(&mut u);
        }
        u
    }

    fn release(tag: &str, prerelease: bool) -> String {
        format!(
            r#"{{ "tag_name": "{tag}", "prerelease": {prerelease}, "draft": false, "assets": [
                {{ "name": "release.zip", "browser_download_url": "https://github.com/o/r/releases/download/{tag}/release.zip",
                   "digest": "sha256:{}" }},
                {{ "name": "old.zip", "browser_download_url": "https://github.com/o/r/releases/download/{tag}/old.zip" }} ] }}"#,
            "ab".repeat(32)
        )
    }

    #[test]
    fn parses_references() {
        let r = parse(&gh("github:guscatalano/findneedle@latest/release.zip", true)).unwrap();
        assert_eq!((r.owner.as_str(), r.repo.as_str()), ("guscatalano", "findneedle"));
        assert_eq!((r.reference, r.asset, r.prerelease), (Ref::Latest, Asset::Named("release.zip".into()), true));
        assert_eq!(parse(&gh("github:o/r@1.0.267/source", false)).unwrap().asset, Asset::Source);
        for bad in ["github:o/r/release.zip", "github:o@latest/x", "github:o/r@latest", "github:o/r@latest/a/b"] {
            assert!(parse(&gh(bad, false)).is_err(), "{bad}");
        }
    }

    #[test]
    fn missing_and_refused_say_which() {
        // No such release: maybe it only publishes prereleases.
        let none = Resolver::new(&MapFetcher::default()).resolve(&gh("github:o/r@latest/a.zip", false)).unwrap_err();
        assert!(format!("{none:#}").contains("add 'prerelease: true'"), "{none:#}");

        // GitHub refusing (its rate limit) is not a missing release.
        struct Refused;
        impl crate::fetch::Fetcher for Refused {
            fn fetch(&self, url: &Url) -> Result<Vec<u8>> {
                Err(anyhow!("GET {url}: http status: 403"))
            }
        }
        let refused = Resolver::new(&Refused).resolve(&gh("github:o/r@latest/a.zip", false)).unwrap_err();
        let text = format!("{refused:#}");
        assert!(text.contains("60 requests an hour") && !text.contains("prerelease"), "{text}");
    }

    #[test]
    fn latest_asset_uses_the_published_digest() {
        let f = MapFetcher::default().with(&format!("{API}/latest"), release("1.0.300", false));
        let r = Resolver::new(&f).resolve(&gh("github:o/r@latest/release.zip", false)).unwrap();
        assert_eq!(r.url.as_str(), "https://github.com/o/r/releases/download/1.0.300/release.zip");
        assert_eq!(r.sha256.as_deref(), Some("ab".repeat(32).as_str()));
        assert_eq!(r.tag, "1.0.300");

        let old = Resolver::new(&f).resolve(&gh("github:o/r@latest/old.zip", false)).unwrap();
        assert_eq!(old.sha256, None, "no digest published: resolved by content instead");
    }

    #[test]
    fn prereleases_and_source_come_from_one_release_lookup() {
        let list = format!("[{}, {}]", release("1.0.268", true), release("1.0.267", true));
        let f = MapFetcher::default().with(&format!("{API}?per_page=30"), list);
        let resolver = Resolver::new(&f);
        let app = resolver.resolve(&gh("github:o/r@latest/release.zip", true)).unwrap();
        let src = resolver.resolve(&gh("github:o/r@latest/source", true)).unwrap();
        assert_eq!(app.tag, "1.0.268");
        assert_eq!(src.url.as_str(), "https://github.com/o/r/archive/refs/tags/1.0.268.zip");
        assert_eq!(f.requests.lock().unwrap().len(), 1, "one API call for both");
    }

    #[test]
    fn explains_prerelease_only_repos_and_missing_assets() {
        let err =
            Resolver::new(&MapFetcher::default()).resolve(&gh("github:o/r@latest/release.zip", false)).unwrap_err();
        assert!(format!("{err:#}").contains("prerelease: true"), "{err:#}");

        let f = MapFetcher::default().with(&format!("{API}/tags/1.0.267"), release("1.0.267", true));
        let err = Resolver::new(&f).resolve(&gh("github:o/r@1.0.267/nope.zip", false)).unwrap_err();
        assert!(err.to_string().contains("has no asset 'nope.zip' (it has: release.zip, old.zip)"), "{err}");
    }

    #[test]
    fn a_tagged_source_needs_no_lookup() {
        let f = MapFetcher::default();
        let r = Resolver::new(&f).resolve(&gh("github:o/r@v2.0/source", false)).unwrap();
        assert_eq!(r.url.as_str(), "https://github.com/o/r/archive/refs/tags/v2.0.zip");
        assert!(f.requests.lock().unwrap().is_empty());
    }
}
