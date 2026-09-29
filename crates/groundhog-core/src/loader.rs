//! Loading a Groundhogfile from a path, URL or zip bundle, following `extends`.

use std::collections::HashMap;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::content::ContentStore;
use crate::fetch::{self, file_url_to_path};
use crate::model::{
    App, CURRENT_VERSION, FileCopy, Groundhogfile, HiveScope, RegistryData, RegistryType, RegistryValue, RunAction,
    Shell, SourceRef, raw,
};

/// File names looked for when a source is a directory or a zip bundle, in order.
pub const ROOT_FILE_NAMES: &[&str] = &["groundhog.yaml", "groundhog.yml", "groundhog.json", "Groundhogfile"];

const MAX_EXTENDS_DEPTH: usize = 16;
const EXTRACTED_MARKER: &str = ".groundhog-extracted";

/// Every document that went into a loaded Groundhogfile, with the hash of what was read.
/// Together they act as a lock record for the run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadedSource {
    pub url: Url,
    pub sha256: String,
}

#[derive(Debug)]
pub struct Loaded {
    pub file: Groundhogfile,
    pub sources: Vec<LoadedSource>,
}

pub struct Loader<'a> {
    pub content: &'a ContentStore<'a>,
    /// Where zip bundles are extracted.
    pub bundle_dir: PathBuf,
}

impl Loader<'_> {
    pub fn load(&self, root: &SourceRef) -> Result<Loaded> {
        let mut sources = Vec::new();
        let mut file = self.load_ref(root, &mut Vec::new(), &mut sources)?;
        self.resolve_unpinned(&mut file, &mut sources)?;
        Ok(Loaded { file, sources })
    }

    /// Fills in `resolved` for every reference without a `sha256` pin by fetching it now.
    /// Steps are identified by what they do, so this is what makes a "latest" URL (or an
    /// edited local script) run again when its content changes, and only then.
    fn resolve_unpinned(&self, file: &mut Groundhogfile, sources: &mut Vec<LoadedSource>) -> Result<()> {
        let mut seen: HashMap<Url, String> = HashMap::new();
        let mut resolve = |url: &Url, pinned: &Option<String>, slot: &mut Option<String>| -> Result<()> {
            if pinned.is_some() {
                return Ok(());
            }
            let hash = match seen.get(url) {
                Some(h) => h.clone(),
                None => {
                    let hash = if url.scheme() == "file" && file_url_to_path(url)?.is_dir() {
                        tree_hash(&file_url_to_path(url)?)?
                    } else {
                        self.content.get(url, None).with_context(|| format!("resolving {url}"))?.sha256
                    };
                    sources.push(LoadedSource { url: url.clone(), sha256: hash.clone() });
                    seen.insert(url.clone(), hash.clone());
                    hash
                }
            };
            *slot = Some(hash);
            Ok(())
        };
        for app in &mut file.apps {
            if let App::Url { url, sha256, resolved, .. } = app {
                resolve(url, sha256, resolved)?;
            }
        }
        for f in &mut file.files {
            resolve(&f.from, &f.sha256, &mut f.resolved)?;
        }
        for r in &mut file.run {
            match r {
                RunAction::Script { script: url, sha256, resolved, .. }
                | RunAction::Plugin { plugin: url, sha256, resolved, .. } => resolve(url, sha256, resolved)?,
                RunAction::Command { .. } => {}
            }
        }
        Ok(())
    }

    fn load_ref(&self, r: &SourceRef, stack: &mut Vec<Url>, sources: &mut Vec<LoadedSource>) -> Result<Groundhogfile> {
        let mut url = r.url.clone();
        let mut sha256 = r.sha256.clone();

        if url.path().to_ascii_lowercase().ends_with(".zip") {
            let zip = self.content.get(&url, sha256.as_deref())?;
            sources.push(LoadedSource { url: url.clone(), sha256: zip.sha256.clone() });
            let dir = self.bundle_dir.join(&zip.sha256[..16]);
            extract_zip(&zip.bytes, &dir).with_context(|| format!("extracting {url}"))?;
            url = find_root_file(&dir)?;
            sha256 = None; // the pin applied to the zip
        } else if url.scheme() == "file" {
            let path = file_url_to_path(&url)?;
            if path.is_dir() {
                url = find_root_file(&path)?;
            }
        }

        if stack.contains(&url) {
            let chain: Vec<_> = stack.iter().chain([&url]).map(Url::as_str).collect();
            bail!("extends cycle: {}", chain.join(" -> "));
        }
        if stack.len() >= MAX_EXTENDS_DEPTH {
            bail!("extends nested deeper than {MAX_EXTENDS_DEPTH} levels at {url}");
        }

        let doc = self.content.get(&url, sha256.as_deref())?;
        sources.push(LoadedSource { url: url.clone(), sha256: doc.sha256.clone() });
        let raw = parse(&doc.bytes, &url)?;

        if let Some(v) = raw.version
            && v > CURRENT_VERSION
        {
            bail!("{url} needs Groundhogfile version {v}; this agent supports up to {CURRENT_VERSION}");
        }

        stack.push(url.clone());
        let mut merged = Groundhogfile::default();
        for base in raw.extends.into_vec() {
            let base = resolve_source_ref(&url, base)?;
            let base = self.load_ref(&base, stack, sources).with_context(|| format!("loading base of {url}"))?;
            merged = merge(merged, base);
        }
        stack.pop();

        let own = resolve(&url, raw.apps, raw.files, raw.env, raw.path, raw.registry, raw.run)
            .with_context(|| format!("in {url}"))?;
        Ok(merge(merged, own))
    }
}

/// A hash over a directory's relative paths and file contents, in a stable order.
fn tree_hash(dir: &Path) -> Result<String> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) -> Result<()> {
        for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
            let path = entry?.path();
            if path.is_dir() {
                walk(root, &path, out)?;
            } else {
                let rel = path.strip_prefix(root).expect("under root").to_string_lossy().replace('\\', "/");
                out.push((rel, path));
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    walk(dir, dir, &mut files)?;
    files.sort();
    let mut manifest = Vec::new();
    for (rel, path) in files {
        let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        manifest.extend_from_slice(format!("{rel}\0{}\0", fetch::sha256_hex(&bytes)).as_bytes());
    }
    Ok(fetch::sha256_hex(&manifest))
}

fn parse(bytes: &[u8], url: &Url) -> Result<raw::File> {
    let text = std::str::from_utf8(bytes).with_context(|| format!("{url} is not UTF-8"))?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    if url.path().to_ascii_lowercase().ends_with(".json") {
        serde_json::from_str(text).with_context(|| format!("parsing {url}"))
    } else if text.trim().is_empty() {
        Ok(raw::File::default())
    } else {
        serde_norway::from_str(text).with_context(|| format!("parsing {url}"))
    }
}

fn find_root_file(dir: &Path) -> Result<Url> {
    let found = |d: &Path| ROOT_FILE_NAMES.iter().map(|n| d.join(n)).find(|p| p.is_file());
    let mut path = found(dir);
    if path.is_none() {
        // GitHub-style archives wrap everything in a single top-level folder.
        let entries: Vec<_> =
            std::fs::read_dir(dir)?.filter_map(Result::ok).filter(|e| e.file_name() != EXTRACTED_MARKER).collect();
        if let [only] = entries.as_slice()
            && only.path().is_dir()
        {
            path = found(&only.path());
        }
    }
    let path = path
        .ok_or_else(|| anyhow!("no Groundhogfile in {} (looked for {})", dir.display(), ROOT_FILE_NAMES.join(", ")))?;
    Url::from_file_path(&path).map_err(|_| anyhow!("bad path {}", path.display()))
}

fn extract_zip(bytes: &[u8], dir: &Path) -> Result<()> {
    let marker = dir.join(EXTRACTED_MARKER);
    if marker.exists() {
        return Ok(()); // same hash, same content
    }
    if dir.exists() {
        std::fs::remove_dir_all(dir)?;
    }
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let rel = entry.enclosed_name().ok_or_else(|| anyhow!("unsafe path in zip: {}", entry.name()))?;
        let out = dir.join(rel);
        if entry.is_dir() {
            std::fs::create_dir_all(&out)?;
        } else {
            if let Some(parent) = out.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut f = std::fs::File::create(&out)?;
            std::io::copy(&mut entry, &mut f)?;
        }
    }
    std::fs::write(marker, b"")?;
    Ok(())
}

/// Resolves a reference relative to the document it appears in, like a link on a web page.
/// Absolute Windows paths and full URLs are taken as-is.
pub fn resolve_ref(base: &Url, reference: &str) -> Result<Url> {
    let b = reference.as_bytes();
    let is_drive_path = b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/');
    if is_drive_path || reference.starts_with(r"\\") {
        return Url::from_file_path(reference).map_err(|_| anyhow!("bad path '{reference}'"));
    }
    if reference.contains("://") {
        return Url::parse(reference).with_context(|| format!("invalid URL '{reference}'"));
    }
    base.join(reference).with_context(|| format!("cannot resolve '{reference}' against {base}"))
}

fn resolve_source_ref(base: &Url, r: raw::SourceRef) -> Result<SourceRef> {
    let (s, sha256) = match r {
        raw::SourceRef::Short(s) => (s, None),
        raw::SourceRef::Full { source, sha256 } => (source, sha256),
    };
    Ok(SourceRef { url: resolve_ref(base, &s)?, sha256: pin(sha256)? })
}

/// Validates and normalizes an optional hash pin, so typos fail at load time, not mid-run.
fn pin(sha256: Option<String>) -> Result<Option<String>> {
    sha256.map(|s| fetch::normalize_sha256(&s)).transpose()
}

fn resolve(
    base: &Url,
    apps: Vec<raw::App>,
    files: Vec<raw::FileCopy>,
    env: std::collections::BTreeMap<String, String>,
    path: Vec<String>,
    registry: Vec<raw::RegistryValue>,
    run: Vec<raw::RunAction>,
) -> Result<Groundhogfile> {
    let apps = apps
        .into_iter()
        .map(|a| {
            Ok(match a {
                raw::App::Short(id) => App::Winget { id, version: None, args: None },
                raw::App::Full(f) => match f.url {
                    Some(u) => {
                        if f.version.is_some() {
                            bail!("app '{}': 'version' only applies to winget apps", f.id);
                        }
                        App::Url {
                            id: f.id,
                            url: resolve_ref(base, &u)?,
                            sha256: pin(f.sha256)?,
                            resolved: None,
                            args: f.args,
                        }
                    }
                    None => {
                        if f.sha256.is_some() {
                            bail!("app '{}': 'sha256' only applies to apps with a 'url'", f.id);
                        }
                        App::Winget { id: f.id, version: f.version, args: f.args }
                    }
                },
            })
        })
        .collect::<Result<_>>()?;

    let files = files
        .into_iter()
        .map(|f| Ok(FileCopy { from: resolve_ref(base, &f.from)?, to: f.to, sha256: pin(f.sha256)?, resolved: None }))
        .collect::<Result<_>>()?;

    if let Some(bad) = env.keys().find(|k| k.is_empty() || k.contains('=')) {
        bail!("invalid environment variable name '{bad}'");
    }

    let registry = registry.into_iter().map(resolve_registry).collect::<Result<_>>()?;

    let run = run
        .into_iter()
        .map(|r| {
            Ok(match r {
                raw::RunAction::Short(command) => RunAction::Command { command, shell: Shell::Powershell },
                raw::RunAction::Command { shell: Shell::Direct, .. } => {
                    bail!("'shell: direct' only applies to scripts; use cmd, powershell or pwsh for commands")
                }
                raw::RunAction::Command { command, shell } => RunAction::Command { command, shell },
                raw::RunAction::Script { script, sha256, args, shell } => RunAction::Script {
                    script: resolve_ref(base, &script)?,
                    sha256: pin(sha256)?,
                    resolved: None,
                    args,
                    shell,
                },
                raw::RunAction::Plugin { plugin, sha256, with } => RunAction::Plugin {
                    plugin: resolve_ref(base, &plugin)?,
                    sha256: pin(sha256)?,
                    resolved: None,
                    with,
                },
            })
        })
        .collect::<Result<_>>()?;

    Ok(Groundhogfile { apps, files, env, path, registry, run })
}

fn resolve_registry(r: raw::RegistryValue) -> Result<RegistryValue> {
    let key = r.key.replace('/', "\\");
    let root = key.split('\\').next().unwrap_or_default().to_ascii_uppercase();
    let is_hkcu = matches!(root.as_str(), "HKCU" | "HKEY_CURRENT_USER");
    let known = is_hkcu
        || matches!(root.as_str(), "HKLM" | "HKEY_LOCAL_MACHINE" | "HKCR" | "HKEY_CLASSES_ROOT" | "HKU" | "HKEY_USERS");
    if !known {
        bail!("registry key '{key}' must start with HKCU, HKLM, HKCR or HKU");
    }

    let mut scope = r.scope.map(raw::OneOrMany::into_vec).unwrap_or_else(|| vec![HiveScope::CurrentUser]);
    scope.sort();
    scope.dedup();
    if !is_hkcu && scope.contains(&HiveScope::DefaultUser) {
        bail!("registry key '{key}': scope 'default-user' only applies to HKCU keys");
    }

    let bad = |what: &str| anyhow!("registry value {key}\\{}: {what}", r.name.as_deref().unwrap_or("(default)"));
    let data = match (r.kind, r.value) {
        (RegistryType::String | RegistryType::ExpandString, raw::Scalar::Str(s)) => RegistryData::String(s),
        (RegistryType::String | RegistryType::ExpandString, raw::Scalar::Int(n)) => RegistryData::String(n.to_string()),
        (RegistryType::MultiString, raw::Scalar::List(v)) => RegistryData::MultiString(v),
        (RegistryType::MultiString, raw::Scalar::Str(s)) => RegistryData::MultiString(vec![s]),
        (RegistryType::Dword, v) => RegistryData::Dword(
            u32::try_from(scalar_to_u64(v).ok_or_else(|| bad("expected a number"))?)
                .map_err(|_| bad("does not fit in a dword"))?,
        ),
        (RegistryType::Qword, v) => RegistryData::Qword(scalar_to_u64(v).ok_or_else(|| bad("expected a number"))?),
        (kind, _) => return Err(bad(&format!("value does not match type {kind:?}"))),
    };

    Ok(RegistryValue { key, name: r.name.filter(|n| !n.is_empty()), kind: r.kind, data, scope })
}

fn scalar_to_u64(v: raw::Scalar) -> Option<u64> {
    match v {
        raw::Scalar::Int(n) => Some(n),
        raw::Scalar::Str(s) => {
            let s = s.trim();
            match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                Some(hex) => u64::from_str_radix(hex, 16).ok(),
                None => s.parse().ok(),
            }
        }
        raw::Scalar::List(_) => None,
    }
}

/// Layers `top` over `base`. Entries that identify the same thing (app id, file destination,
/// registry value, env var) are replaced by `top`'s version; everything else accumulates.
pub fn merge(base: Groundhogfile, top: Groundhogfile) -> Groundhogfile {
    let eq = |a: &str, b: &str| a.eq_ignore_ascii_case(b);

    let mut apps: Vec<App> = base.apps.into_iter().filter(|b| !top.apps.iter().any(|t| eq(t.id(), b.id()))).collect();
    apps.extend(top.apps);

    let mut files: Vec<FileCopy> =
        base.files.into_iter().filter(|b| !top.files.iter().any(|t| eq(&t.to, &b.to))).collect();
    files.extend(top.files);

    let mut env = base.env;
    env.extend(top.env);

    let mut path = base.path;
    for p in top.path {
        if !path.iter().any(|x| eq(x.trim_end_matches('\\'), p.trim_end_matches('\\'))) {
            path.push(p);
        }
    }

    let same_value = |a: &RegistryValue, b: &RegistryValue| {
        eq(&a.key, &b.key) && eq(a.name.as_deref().unwrap_or(""), b.name.as_deref().unwrap_or(""))
    };
    let mut registry: Vec<RegistryValue> =
        base.registry.into_iter().filter(|b| !top.registry.iter().any(|t| same_value(t, b))).collect();
    registry.extend(top.registry);

    let mut run = base.run;
    run.extend(top.run);

    Groundhogfile { apps, files, env, path, registry, run }
}

/// Convenience for callers: turns user input plus an optional pin into a [`SourceRef`].
pub fn source_ref(input: &str, sha256: Option<String>, cwd: &Path) -> Result<SourceRef> {
    Ok(SourceRef { url: fetch::parse_location(input, cwd)?, sha256 })
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::cache::Cache;
    use crate::fetch::sha256_hex;
    use crate::fetch::testing::MapFetcher;

    fn load_with(fetcher: &MapFetcher, root: &str, bundle_dir: &Path) -> Result<Loaded> {
        let cache = Cache::default();
        let content = ContentStore { fetcher, cache: &cache };
        let loader = Loader { content: &content, bundle_dir: bundle_dir.to_path_buf() };
        loader.load(&source_ref(root, None, bundle_dir)?)
    }

    #[test]
    fn short_and_full_forms_resolve_against_the_document_url() {
        let f = MapFetcher::default()
            .with(
                "https://cfg.test/dev/groundhog.yaml",
                r#"
apps:
  - git.git
  - id: tool
    url: ../dl/tool.msi
    sha256: "sha256:ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
files:
  - from: config/.gitconfig
    to: ~/.gitconfig
registry:
  - key: HKCU\Software\X
    name: N
    type: dword
    value: "0x10"
    scope: [default-user, current-user]
run:
  - echo hi
  - script: scripts/post.ps1
  - plugin: https://plugins.test/p.exe
    with: { a: 1 }
"#,
            )
            .with("https://cfg.test/dev/config/.gitconfig", "[core]")
            .with("https://cfg.test/dev/scripts/post.ps1", "echo")
            .with("https://plugins.test/p.exe", "MZ");
        let dir = tempfile::tempdir().unwrap();
        let loaded = load_with(&f, "https://cfg.test/dev/groundhog.yaml", dir.path()).unwrap();
        let g = loaded.file;

        assert_eq!(g.apps[0], App::Winget { id: "git.git".into(), version: None, args: None });
        let App::Url { url, .. } = &g.apps[1] else { panic!() };
        assert_eq!(url.as_str(), "https://cfg.test/dl/tool.msi");
        assert_eq!(g.files[0].from.as_str(), "https://cfg.test/dev/config/.gitconfig");
        assert_eq!(g.registry[0].data, RegistryData::Dword(16));
        assert_eq!(g.registry[0].scope, vec![HiveScope::CurrentUser, HiveScope::DefaultUser]);
        assert_eq!(g.run[0], RunAction::Command { command: "echo hi".into(), shell: Shell::Powershell });
        let RunAction::Script { script, .. } = &g.run[1] else { panic!() };
        assert_eq!(script.as_str(), "https://cfg.test/dev/scripts/post.ps1");
        // The document plus the three unpinned references it resolved; the pinned app is untouched.
        assert_eq!(loaded.sources.len(), 4);
    }

    #[test]
    fn extends_merges_base_first_and_top_wins() {
        let f = MapFetcher::default()
            .with(
                "https://cfg.test/base.yaml",
                "apps: [git.git, { id: microsoft.powershell, version: '7.4' }]\nenv: { A: base, B: base }\npath: ['C:\\tools\\']\nrun: [base-cmd]\nfiles: [{ from: gitconfig, to: ~/.gitconfig }]",
            )
            .with(
                "https://cfg.test/team/dev.json",
                r#"{ "extends": "../base.yaml", "apps": [{ "id": "Microsoft.PowerShell" }], "env": { "B": "top" },
                    "path": ["c:\\tools"], "run": ["top-cmd"] }"#,
            )
            .with("https://cfg.test/gitconfig", "[core]");
        let dir = tempfile::tempdir().unwrap();
        let loaded = load_with(&f, "https://cfg.test/team/dev.json", dir.path()).unwrap();
        let g = loaded.file;

        let ids: Vec<_> = g.apps.iter().map(App::id).collect();
        assert_eq!(ids, ["git.git", "Microsoft.PowerShell"]);
        assert_eq!(g.env["A"], "base");
        assert_eq!(g.env["B"], "top");
        assert_eq!(g.path, ["C:\\tools\\"]);
        assert_eq!(g.run.len(), 2);
        assert_eq!(g.files[0].from.as_str(), "https://cfg.test/gitconfig");
        assert_eq!(loaded.sources.len(), 3);
    }

    #[test]
    fn unpinned_references_resolve_to_their_content() {
        let yaml = "files: [{ from: https://dl.test/latest/app.zip, to: C:/a.zip }, { from: https://dl.test/latest/app.zip, to: C:/b.zip }]\napps: [{ id: t, url: https://dl.test/t.msi, sha256: '0000000000000000000000000000000000000000000000000000000000000000' }]";
        let v1 = MapFetcher::default()
            .with("https://cfg.test/g.yaml", yaml)
            .with("https://dl.test/latest/app.zip", "build 1");
        let dir = tempfile::tempdir().unwrap();
        let loaded = load_with(&v1, "https://cfg.test/g.yaml", dir.path()).unwrap();

        assert_eq!(loaded.file.files[0].resolved.as_deref(), Some(sha256_hex(b"build 1").as_str()));
        let App::Url { resolved, .. } = &loaded.file.apps[0] else { panic!() };
        assert_eq!(*resolved, None, "pinned entries are never fetched at load time");
        let fetched = v1.requests.lock().unwrap().iter().filter(|u| u.contains("app.zip")).count();
        assert_eq!(fetched, 1, "the same URL is fetched once");

        let v2 = MapFetcher::default()
            .with("https://cfg.test/g.yaml", yaml)
            .with("https://dl.test/latest/app.zip", "build 2");
        let again = load_with(&v2, "https://cfg.test/g.yaml", dir.path()).unwrap();
        assert_ne!(again.file.files[0].resolved, loaded.file.files[0].resolved);
    }

    #[test]
    fn local_folders_resolve_to_a_tree_hash() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("cfg/sub")).unwrap();
        std::fs::write(dir.path().join("cfg/sub/a.txt"), "one").unwrap();
        std::fs::write(dir.path().join("groundhog.yaml"), "files: [{ from: cfg, to: C:/cfg }]").unwrap();
        let root = dir.path().join("groundhog.yaml");
        let first = load_with(&MapFetcher::default(), root.to_str().unwrap(), dir.path()).unwrap();

        std::fs::write(dir.path().join("cfg/sub/a.txt"), "two").unwrap();
        let second = load_with(&MapFetcher::default(), root.to_str().unwrap(), dir.path()).unwrap();
        assert!(first.file.files[0].resolved.is_some());
        assert_ne!(first.file.files[0].resolved, second.file.files[0].resolved);
    }

    #[test]
    fn detects_extends_cycles() {
        let f = MapFetcher::default()
            .with("https://cfg.test/a.yaml", "extends: b.yaml")
            .with("https://cfg.test/b.yaml", "extends: a.yaml");
        let dir = tempfile::tempdir().unwrap();
        let err = load_with(&f, "https://cfg.test/a.yaml", dir.path()).unwrap_err();
        assert!(format!("{err:#}").contains("extends cycle"), "{err:#}");
    }

    #[test]
    fn rejects_unknown_fields_and_bad_values() {
        let f = MapFetcher::default()
            .with("https://cfg.test/typo.yaml", "aps: [git.git]")
            .with("https://cfg.test/reg.yaml", "registry: [{ key: HKLM\\X, value: 1, scope: default-user }]");
        let dir = tempfile::tempdir().unwrap();
        assert!(load_with(&f, "https://cfg.test/typo.yaml", dir.path()).is_err());
        let err = load_with(&f, "https://cfg.test/reg.yaml", dir.path()).unwrap_err();
        assert!(format!("{err:#}").contains("default-user"), "{err:#}");
    }

    #[test]
    fn loads_directories_and_github_style_zips() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(src.join("config")).unwrap();
        std::fs::write(src.join("config").join("a.txt"), "a").unwrap();
        std::fs::write(src.join("groundhog.yaml"), "files: [{ from: config/a.txt, to: C:\\a.txt }]").unwrap();

        let loaded = load_with(&MapFetcher::default(), src.to_str().unwrap(), dir.path()).unwrap();
        assert!(loaded.file.files[0].from.as_str().ends_with("/src/config/a.txt"));

        let mut zip_bytes = Vec::new();
        {
            let mut z = zip::ZipWriter::new(Cursor::new(&mut zip_bytes));
            let opts = zip::write::SimpleFileOptions::default();
            z.start_file("devbox-main/groundhog.yaml", opts).unwrap();
            z.write_all(b"apps: [git.git]").unwrap();
            z.finish().unwrap();
        }
        let sha = sha256_hex(&zip_bytes);
        let f = MapFetcher::default().with("https://github.test/devbox/main.zip", zip_bytes);
        let cache = Cache::default();
        let content = ContentStore { fetcher: &f, cache: &cache };
        let loader = Loader { content: &content, bundle_dir: dir.path().join("bundles") };
        let r = SourceRef { url: Url::parse("https://github.test/devbox/main.zip").unwrap(), sha256: Some(sha) };
        let loaded = loader.load(&r).unwrap();
        assert_eq!(loaded.file.apps[0].id(), "git.git");
        assert_eq!(loaded.sources.len(), 2);

        let wrong = SourceRef { sha256: Some("0".repeat(64)), ..r };
        assert!(format!("{:#}", loader.load(&wrong).unwrap_err()).contains("hash mismatch"));
    }
}
