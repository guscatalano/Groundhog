//! Loading a Groundhogfile from a path, URL or zip bundle, following `extends`.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::archive;
use crate::content::ContentStore;
use crate::fetch::{self, file_url_to_path};
use crate::github;
use crate::library;
use crate::model::{
    App, CURRENT_VERSION, Capability, CertScope, CertStore, Certificate, Check, DefenderExclusion, DesktopShortcut,
    EnvScope, EnvVar, ExclusionKind, Feature, FileCopy, FirewallProtocol, FirewallRule, Groundhogfile, HiveScope,
    InputLanguage, LanguageSetting, LockScreen, Password, PathEntry, Presence, RegistryData, RegistryType,
    RegistryValue, RunAction, ScreenSaver, Service, ServiceState, Shell, SourceRef, StartPins, Theme, ThemeMode,
    TrayIcon, User, Wallpaper, WallpaperStyle, raw,
};
use crate::secret;
use crate::update::{self, Version};
use crate::vars::{self, Facts};

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

/// A fetched document: its bytes and their SHA-256.
type Doc = Rc<(Vec<u8>, String)>;

pub struct Loader<'a> {
    pub content: &'a ContentStore<'a>,
    /// Where zip bundles are extracted.
    pub bundle_dir: PathBuf,
    /// The machine `when:` conditions and built-in variables describe.
    pub facts: Facts,
    /// Variables from the caller (`--var`, `pending.json`); they win over a file's own.
    pub vars: BTreeMap<String, String>,
    /// Documents already fetched, so the variables pass and the real load fetch each once.
    docs: RefCell<HashMap<Url, Doc>>,
}

impl<'a> Loader<'a> {
    pub fn new(content: &'a ContentStore<'a>, bundle_dir: PathBuf) -> Self {
        Self { content, bundle_dir, facts: Facts::default(), vars: BTreeMap::new(), docs: RefCell::default() }
    }

    pub fn with_facts(self, facts: Facts) -> Self {
        Self { facts, ..self }
    }

    pub fn with_vars(self, vars: BTreeMap<String, String>) -> Self {
        Self { vars, ..self }
    }

    pub fn load(&self, root: &SourceRef) -> Result<Loaded> {
        let vars = self.variables(root)?;
        let mut sources = Vec::new();
        let mut file = self.load_ref(root, &mut Vec::new(), &mut sources, &vars)?;
        self.resolve_unpinned(&mut file, &mut sources)?;
        Ok(Loaded { file, sources })
    }

    /// Every variable a load sees: the files' own `vars` (a file's own win over its bases',
    /// so a file can override a library's default), then the caller's, then the built-ins.
    fn variables(&self, root: &SourceRef) -> Result<BTreeMap<String, String>> {
        let mut vars = self.collect_vars(root, &mut Vec::new())?;
        for (name, value) in &self.vars {
            if !vars::valid_name(name) {
                bail!("variable name '{name}' should be letters, digits, '_' and '-'");
            }
            vars.insert(name.clone(), value.clone());
        }
        if let Some(name) = vars.keys().find(|n| vars::RESERVED.contains(&n.as_str())) {
            bail!("'{name}' is a built-in variable and can't be redefined");
        }
        vars.extend(self.facts.builtin_vars());
        Ok(vars)
    }

    /// First pass: `vars` across the `extends` tree, bases first. A document that doesn't
    /// parse is skipped here; the real load reports its error with line numbers.
    fn collect_vars(&self, r: &SourceRef, stack: &mut Vec<Url>) -> Result<BTreeMap<String, String>> {
        let (url, sha256) = self.locate(r, None)?;
        if stack.contains(&url) || stack.len() >= MAX_EXTENDS_DEPTH {
            return Ok(BTreeMap::new()); // the real load explains
        }
        let doc = self.document(&url, sha256.as_deref())?;
        let Some(value) = parse_value(&doc.0, &url) else { return Ok(BTreeMap::new()) };
        let mut vars = BTreeMap::new();
        if let Some(extends) = value.get("extends")
            && let Ok(bases) = serde_json::from_value::<raw::OneOrMany<raw::SourceRef>>(extends.clone())
        {
            stack.push(url.clone());
            for base in bases.into_vec() {
                let base = resolve_source_ref(&url, base)?;
                vars.extend(self.collect_vars(&base, stack)?);
            }
            stack.pop();
        }
        if let Some(own) = value.get("vars") {
            let serde_json::Value::Object(own) = own else { bail!("{url}: 'vars' is a map of names to values") };
            for (name, v) in own {
                if !vars::valid_name(name) {
                    bail!("{url}: variable name '{name}' should be letters, digits, '_' and '-'");
                }
                let text = match v {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    serde_json::Value::Bool(b) => b.to_string(),
                    _ => bail!("{url}: variable '{name}' should be a string or a number"),
                };
                vars.insert(name.clone(), text);
            }
        }
        Ok(vars)
    }

    /// Where a reference's document is: library names expanded, zip bundles unpacked, and a
    /// folder's root file found. Returns the document URL and the pin that applies to it.
    fn locate(&self, r: &SourceRef, sources: Option<&mut Vec<LoadedSource>>) -> Result<(Url, Option<String>)> {
        let mut url = r.url.clone();
        let mut sha256 = r.sha256.clone();
        if library::is_library(&url) {
            url = library::expand(&url)?;
        }
        if url.path().to_ascii_lowercase().ends_with(".zip") {
            let zip = self.document(&url, sha256.as_deref())?;
            if let Some(sources) = sources {
                sources.push(LoadedSource { url: url.clone(), sha256: zip.1.clone() });
            }
            let dir = self.bundle_dir.join(&zip.1[..16]);
            extract_zip(&zip.0, &dir).with_context(|| format!("extracting {url}"))?;
            url = find_root_file(&dir)?;
            sha256 = None; // the pin applied to the zip
        } else if url.scheme() == "file" {
            let path = file_url_to_path(&url)?;
            if path.is_dir() {
                url = find_root_file(&path)?;
            }
        }
        Ok((url, sha256))
    }

    fn document(&self, url: &Url, sha256: Option<&str>) -> Result<Doc> {
        if let Some(doc) = self.docs.borrow().get(url) {
            // Remembered from earlier in this load, but a pin still has to match.
            if let Some(pin) = sha256 {
                let pin = fetch::normalize_sha256(pin)?;
                if pin != doc.1 {
                    bail!("hash mismatch for {url}: expected {pin}, got {}", doc.1);
                }
            }
            return Ok(doc.clone());
        }
        let fetched = self.content.get(url, sha256)?;
        let doc = Rc::new((fetched.bytes, fetched.sha256));
        self.docs.borrow_mut().insert(url.clone(), doc.clone());
        Ok(doc)
    }

    /// Fills in `resolved` for every reference without a `sha256` pin by fetching it now.
    /// Steps are identified by what they do, so this is what makes a "latest" URL (or an
    /// edited local script) run again when its content changes, and only then.
    fn resolve_unpinned(&self, file: &mut Groundhogfile, sources: &mut Vec<LoadedSource>) -> Result<()> {
        // github: references first: they become ordinary URLs, pinned by GitHub's own digest
        // when it publishes one, and then flow through the content resolution below.
        let gh = github::Resolver::new(self.content.fetcher);
        let from_github = |url: &mut Url, sha256: &mut Option<String>, release: &mut Option<String>| -> Result<()> {
            if github::is_github(url) {
                let r = gh.resolve(url).with_context(|| format!("resolving {url}"))?;
                *url = r.url;
                if sha256.is_none() {
                    *sha256 = r.sha256;
                }
                *release = Some(r.tag);
            }
            Ok(())
        };
        for app in &mut file.apps {
            if let App::Url { url, sha256, release, .. } = app {
                from_github(url, sha256, release)?;
            }
        }
        for f in &mut file.files {
            if let Some(from) = &mut f.from {
                from_github(from, &mut f.sha256, &mut f.release)?;
            }
        }
        for c in &mut file.certificates {
            if let Some(from) = &mut c.from {
                from_github(from, &mut c.sha256, &mut None)?;
            }
        }
        if let Some(Wallpaper { from: Some(from), sha256, .. }) = &mut file.wallpaper {
            from_github(from, sha256, &mut None)?;
        }
        if let Some(StartPins { from, sha256, .. }) = &mut file.start_pins {
            from_github(from, sha256, &mut None)?;
        }
        if let Some(LockScreen { image: Some(image), sha256, .. }) = &mut file.lock_screen {
            from_github(image, sha256, &mut None)?;
        }

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
                        self.content.get_file(url, None).with_context(|| format!("resolving {url}"))?.sha256
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
            if let Some(from) = &f.from {
                resolve(from, &f.sha256, &mut f.resolved)?;
            }
        }
        for c in &mut file.certificates {
            if let Some(from) = &c.from {
                resolve(from, &c.sha256, &mut c.resolved)?;
            }
        }
        if let Some(Wallpaper { from: Some(from), sha256, resolved, .. }) = &mut file.wallpaper {
            resolve(from, sha256, resolved)?;
        }
        if let Some(StartPins { from, sha256, resolved, .. }) = &mut file.start_pins {
            resolve(from, sha256, resolved)?;
        }
        if let Some(LockScreen { image: Some(image), sha256, resolved, .. }) = &mut file.lock_screen {
            resolve(image, sha256, resolved)?;
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

    fn load_ref(
        &self,
        r: &SourceRef,
        stack: &mut Vec<Url>,
        sources: &mut Vec<LoadedSource>,
        vars: &BTreeMap<String, String>,
    ) -> Result<Groundhogfile> {
        let (url, sha256) = self.locate(r, Some(sources))?;

        if stack.contains(&url) {
            let chain: Vec<_> = stack.iter().chain([&url]).map(Url::as_str).collect();
            bail!("extends cycle: {}", chain.join(" -> "));
        }
        if stack.len() >= MAX_EXTENDS_DEPTH {
            bail!("extends nested deeper than {MAX_EXTENDS_DEPTH} levels at {url}");
        }

        let doc = self.document(&url, sha256.as_deref())?;
        sources.push(LoadedSource { url: url.clone(), sha256: doc.1.clone() });
        let mut raw = parse(&doc.0, &url, vars, &self.facts)?;

        if let Some(v) = raw.version
            && v > CURRENT_VERSION
        {
            bail!("{url} needs Groundhogfile version {v}; this agent supports up to {CURRENT_VERSION}");
        }

        stack.push(url.clone());
        let mut merged = Groundhogfile::default();
        for base in std::mem::take(&mut raw.extends).into_vec() {
            let base = resolve_source_ref(&url, base)?;
            let base = self.load_ref(&base, stack, sources, vars).with_context(|| format!("loading base of {url}"))?;
            merged = merge(merged, base);
        }
        stack.pop();

        let own = resolve(&url, raw).with_context(|| format!("in {url}"))?;
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

/// A Groundhogfile asked for a newer agent than the one reading it. Returned (inside the
/// error chain) whenever the file declares `agent:`, even if the rest of it doesn't parse:
/// a newer file often uses keys an older agent has never heard of, and "update the agent"
/// is the useful answer there, not "unknown field".
#[derive(Debug)]
pub struct NeedsAgent {
    pub required: Version,
}

impl std::fmt::Display for NeedsAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "this Groundhogfile needs groundhog-agent {} or newer", self.required)
    }
}

impl std::error::Error for NeedsAgent {}

fn parse(bytes: &[u8], url: &Url, vars: &BTreeMap<String, String>, facts: &Facts) -> Result<raw::File> {
    let text = std::str::from_utf8(bytes).with_context(|| format!("{url} is not UTF-8"))?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let is_json = url.path().to_ascii_lowercase().ends_with(".json");
    let strict = if vars::needed(text) {
        // Conditions and variables are applied to the document tree, then it's read as usual.
        // (Errors from this path can't point at a line, which is why only these files use it.)
        let value: Result<serde_json::Value> = if is_json {
            serde_json::from_str(text).map_err(anyhow::Error::from)
        } else {
            serde_norway::from_str(text).map_err(anyhow::Error::from)
        };
        value.and_then(|mut v| {
            vars::preprocess(&mut v, vars, facts)?;
            serde_json::from_value(v).map_err(anyhow::Error::from)
        })
    } else if is_json {
        serde_json::from_str(text).map_err(anyhow::Error::from)
    } else if text.trim().is_empty() {
        Ok(raw::File::default())
    } else {
        serde_norway::from_str(text).map_err(anyhow::Error::from)
    };
    strict.map_err(|e| {
        let e = e.context(format!("parsing {url}"));
        match peek_agent_requirement(text, is_json) {
            Some(required) if required > Version::current() => {
                anyhow::Error::new(NeedsAgent { required }).context(format!("{e:#}"))
            }
            _ => e,
        }
    })
}

/// The document as a JSON-like tree, or `None` when it doesn't parse.
fn parse_value(bytes: &[u8], url: &Url) -> Option<serde_json::Value> {
    let text = std::str::from_utf8(bytes).ok()?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    if text.trim().is_empty() {
        return Some(serde_json::Value::Object(Default::default()));
    }
    if url.path().to_ascii_lowercase().ends_with(".json") {
        serde_json::from_str(text).ok()
    } else {
        serde_norway::from_str(text).ok()
    }
}

/// Reads just the top-level `agent:` value, ignoring everything this version doesn't know.
fn peek_agent_requirement(text: &str, is_json: bool) -> Option<Version> {
    #[derive(Deserialize)]
    struct Peek {
        agent: Option<String>,
    }
    let peek: Peek = if is_json { serde_json::from_str(text).ok()? } else { serde_norway::from_str(text).ok()? };
    update::parse_requirement(&peek.agent?).ok()
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
    std::fs::create_dir_all(dir)?;
    archive::unzip(bytes, dir)?;
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

fn resolve(base: &Url, raw: raw::File) -> Result<Groundhogfile> {
    let raw::File {
        apps,
        files,
        env,
        path,
        registry,
        run,
        verify,
        agent,
        users,
        features,
        capabilities,
        certificates,
        services,
        firewall,
        defender_exclusions,
        remove_apps,
        desktop,
        uac,
        language,
        ..
    } = raw;
    let requires_agent = agent.as_deref().map(update::parse_requirement).transpose()?;
    let apps = apps.into_iter().map(|a| resolve_app(base, a)).collect::<Result<_>>()?;
    let mut files: Vec<FileCopy> = files.into_iter().map(|f| resolve_file(base, f)).collect::<Result<_>>()?;

    if let Some(bad) = env.keys().find(|k| k.is_empty() || k.contains('=')) {
        bail!("invalid environment variable name '{bad}'");
    }
    let env = env
        .into_iter()
        .map(|(name, v)| {
            let var = match v {
                raw::StringOr::Short(value) => EnvVar { value, scope: EnvScope::User, state: Presence::Present },
                raw::StringOr::Full(f) => {
                    let state = f.state.unwrap_or_default();
                    let value = match (state, f.value) {
                        (Presence::Present, Some(v)) => v,
                        (Presence::Present, None) => bail!("env {name}: needs a 'value'"),
                        (Presence::Absent, None) => String::new(),
                        (Presence::Absent, Some(_)) => bail!("env {name}: 'value' doesn't go with 'state: absent'"),
                    };
                    EnvVar { value, scope: f.scope, state }
                }
            };
            if var.scope == EnvScope::Machine && var.state.is_present() && name.eq_ignore_ascii_case("path") {
                bail!("env: add to the machine PATH with `path:` entries (scope: machine); this would replace it");
            }
            Ok((name, var))
        })
        .collect::<Result<_>>()?;
    let path = path
        .into_iter()
        .map(|p| match p {
            raw::StringOr::Short(dir) => PathEntry { dir, scope: EnvScope::User, state: Presence::Present },
            raw::StringOr::Full(f) => PathEntry { dir: f.dir, scope: f.scope, state: f.state.unwrap_or_default() },
        })
        .collect();

    let mut registry: Vec<RegistryValue> = registry.into_iter().map(resolve_registry).collect::<Result<_>>()?;
    if let Some(uac) = uac {
        registry.extend(resolve_uac(uac).context("uac")?);
    }
    let language = match language {
        Some(l) => resolve_language(l, &mut registry).context("language")?,
        None => Vec::new(),
    };

    let run = run
        .into_iter()
        .enumerate()
        .map(|(i, r)| match r {
            raw::RunAction::Short(command) => {
                Ok(RunAction::Command { command, shell: Shell::Powershell, timeout_ms: None, always: false })
            }
            raw::RunAction::Full(r) => resolve_run(base, r).with_context(|| format!("run[{i}]")),
        })
        .collect::<Result<_>>()?;

    let verify = verify
        .into_iter()
        .enumerate()
        .map(|(i, c)| resolve_check(c).with_context(|| format!("verify[{i}]")))
        .collect::<Result<_>>()?;

    let users = users
        .into_iter()
        .enumerate()
        .map(|(i, u)| resolve_user(u).with_context(|| format!("users[{i}]")))
        .collect::<Result<_>>()?;

    let features = features
        .into_iter()
        .enumerate()
        .map(|(i, f)| resolve_feature(base, f).with_context(|| format!("features[{i}]")))
        .collect::<Result<_>>()?;
    let capabilities = capabilities
        .into_iter()
        .enumerate()
        .map(|(i, c)| resolve_capability(base, c).with_context(|| format!("capabilities[{i}]")))
        .collect::<Result<_>>()?;

    let certificates = certificates
        .into_iter()
        .enumerate()
        .map(|(i, c)| resolve_certificate(base, c).with_context(|| format!("certificates[{i}]")))
        .collect::<Result<_>>()?;
    let services = services.into_iter().map(resolve_service).collect::<Result<_>>()?;
    let firewall = firewall.into_iter().map(resolve_firewall).collect::<Result<_>>()?;
    let defender_exclusions = defender_exclusions.into_iter().map(resolve_exclusion).collect::<Result<_>>()?;
    if remove_apps.iter().any(|a| a.trim().is_empty()) {
        bail!("remove-apps: an entry is empty");
    }
    let DesktopParts {
        wallpaper,
        theme,
        lock_screen,
        screen_saver,
        registry: desktop_registry,
        files: desktop_files,
        tray_icons,
        do_not_disturb,
        start_pins,
        shortcuts: desktop_shortcuts,
    } = match desktop {
        Some(d) => resolve_desktop(base, d).context("desktop")?,
        None => DesktopParts {
            wallpaper: None,
            theme: None,
            lock_screen: None,
            screen_saver: None,
            registry: Vec::new(),
            files: Vec::new(),
            tray_icons: Vec::new(),
            do_not_disturb: None,
            start_pins: None,
            shortcuts: Vec::new(),
        },
    };
    registry.extend(desktop_registry);
    files.extend(desktop_files);

    let file = Groundhogfile {
        users,
        certificates,
        defender_exclusions,
        features,
        capabilities,
        remove_apps,
        apps,
        files,
        env,
        path,
        registry,
        wallpaper,
        theme,
        lock_screen,
        screen_saver,
        tray_icons,
        do_not_disturb,
        start_pins,
        desktop_shortcuts,
        language,
        services,
        firewall,
        run,
        verify,
        requires_agent,
    };
    check_secret_references(&file)?;
    Ok(file)
}

fn resolve_app(base: &Url, a: raw::App) -> Result<App> {
    let f = match a {
        raw::App::Short(id) => {
            return Ok(App::Winget {
                id,
                version: None,
                args: None,
                timeout_ms: None,
                upgrade: false,
                state: Presence::Present,
            });
        }
        raw::App::Full(f) => f,
    };
    let timeout_ms = f.timeout.map(duration_ms).transpose()?;
    let state = f.state.unwrap_or_default();
    match f.url {
        Some(u) => {
            if f.version.is_some() || f.upgrade {
                bail!("app '{}': 'version' and 'upgrade' only apply to winget apps", f.id);
            }
            if !state.is_present() {
                bail!(
                    "app '{}': 'state: absent' only applies to winget apps; a direct installer doesn't say how \
                     to uninstall it (use a 'run' step with its uninstaller)",
                    f.id
                );
            }
            let mut url = resolve_ref(base, &u)?;
            if f.prerelease {
                if !github::is_github(&url) {
                    bail!("app '{}': 'prerelease' only applies to github: sources", f.id);
                }
                github::allow_prerelease(&mut url);
            }
            Ok(App::Url {
                id: f.id,
                url,
                sha256: pin(f.sha256)?,
                resolved: None,
                release: None,
                args: f.args,
                timeout_ms,
            })
        }
        None => {
            if f.sha256.is_some() || f.prerelease {
                bail!("app '{}': 'sha256' and 'prerelease' only apply to apps with a 'url'", f.id);
            }
            if f.upgrade && f.version.is_some() {
                bail!("app '{}': give 'version' (stay on it) or 'upgrade: true' (follow new releases), not both", f.id);
            }
            if !state.is_present() && (f.version.is_some() || f.upgrade) {
                bail!("app '{}': 'version' and 'upgrade' don't go with 'state: absent'", f.id);
            }
            Ok(App::Winget { id: f.id, version: f.version, args: f.args, timeout_ms, upgrade: f.upgrade, state })
        }
    }
}

fn resolve_file(base: &Url, f: raw::FileCopy) -> Result<FileCopy> {
    let state = f.state.unwrap_or_default();
    let options = [
        ("from", f.from.is_some()),
        ("content", f.content.is_some()),
        ("sha256", f.sha256.is_some()),
        ("extract", f.extract),
        ("strip", f.strip.is_some()),
        ("prerelease", f.prerelease),
    ];
    let removal = |to: String| FileCopy {
        from: None,
        content: None,
        to,
        sha256: None,
        resolved: None,
        extract: false,
        strip: 0,
        release: None,
        state: Presence::Absent,
    };
    if !state.is_present() {
        if let Some((opt, _)) = options.iter().find(|(_, set)| *set) {
            bail!("file {}: '{opt}' doesn't go with 'state: absent', which only needs 'to'", f.to);
        }
        return Ok(removal(f.to));
    }
    let from_text = match (f.from, &f.content) {
        (Some(from), None) => from,
        (None, Some(content)) => {
            if let Some((opt, _)) = options[2..].iter().find(|(_, set)| *set) {
                bail!("file {}: '{opt}' only applies to files with 'from'", f.to);
            }
            secret::parse(content).with_context(|| format!("file {}", f.to))?;
            return Ok(FileCopy { content: f.content, state: Presence::Present, ..removal(f.to) });
        }
        (Some(_), Some(_)) => bail!("file {}: give 'from' or 'content', not both", f.to),
        (None, None) => bail!("file {}: needs 'from' (a path or URL) or 'content' (the text)", f.to),
    };
    let mut from = resolve_ref(base, &from_text)?;
    if f.prerelease {
        if !github::is_github(&from) {
            bail!("'{from_text}': 'prerelease' only applies to github: sources");
        }
        github::allow_prerelease(&mut from);
    }
    let path = from.path().to_ascii_lowercase();
    let is_zip = path.ends_with(".zip") || (github::is_github(&from) && path.ends_with("/source"));
    if f.extract && !is_zip {
        bail!("'{from_text}': 'extract' needs a .zip file");
    }
    if f.strip.is_some() && !f.extract {
        bail!("'{from_text}': 'strip' only applies with 'extract: true'");
    }
    Ok(FileCopy {
        from: Some(from),
        content: None,
        to: f.to,
        sha256: pin(f.sha256)?,
        resolved: None,
        extract: f.extract,
        strip: f.strip.unwrap_or(0),
        release: None,
        state: Presence::Present,
    })
}

fn resolve_certificate(base: &Url, c: raw::Certificate) -> Result<Certificate> {
    let state = c.state.unwrap_or_default();
    let store = c.store.unwrap_or(CertStore::Root);
    let scope = c.scope.unwrap_or_default();
    if scope == CertScope::User && store == CertStore::Root && state.is_present() {
        bail!(
            "adding to the user's Root store makes Windows ask someone to confirm on screen, so it can't be \
             done unattended; use scope: machine"
        );
    }
    let (from, thumbprint) = match (c.from, c.thumbprint) {
        (Some(from), None) => (Some(resolve_ref(base, &from)?), None),
        (None, Some(t)) => {
            if state.is_present() {
                bail!("certificate {t}: adding one needs 'from' (the file); a thumbprint alone can only remove one");
            }
            let t: String = t.chars().filter(|c| !matches!(c, ' ' | ':')).collect::<String>().to_ascii_uppercase();
            if t.len() != 40 || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
                bail!("certificate thumbprint '{t}' should be 40 hex characters (the SHA-1 thumbprint)");
            }
            (None, Some(t))
        }
        (Some(_), Some(_)) => bail!("a certificate takes 'from' or 'thumbprint', not both"),
        (None, None) => bail!("a certificate needs 'from' (the file) or, to remove one, 'thumbprint'"),
    };
    if from.is_none() && c.sha256.is_some() {
        bail!("'sha256' only applies to a certificate with 'from'");
    }
    Ok(Certificate { from, sha256: pin(c.sha256)?, resolved: None, thumbprint, store, scope, state })
}

fn resolve_service(s: raw::Service) -> Result<Service> {
    if s.name.trim().is_empty() {
        bail!("services: an entry has no name");
    }
    if s.startup.is_none() && s.status.is_none() {
        bail!("service {}: give 'startup', 'status' or both", s.name);
    }
    Ok(Service { name: s.name, startup: s.startup, status: s.status })
}

fn resolve_firewall(r: raw::FirewallRule) -> Result<FirewallRule> {
    let state = r.state.unwrap_or_default();
    let name = r.name;
    if name.trim().is_empty() {
        bail!("firewall: a rule has no name");
    }
    if !state.is_present() {
        let given = [
            ("port", r.port.is_some()),
            ("protocol", r.protocol.is_some()),
            ("direction", r.direction.is_some()),
            ("action", r.action.is_some()),
            ("program", r.program.is_some()),
            ("profile", r.profile.is_some()),
            ("remote", r.remote.is_some()),
        ];
        if let Some((opt, _)) = given.iter().find(|(_, set)| *set) {
            bail!("firewall rule {name}: '{opt}' doesn't go with 'state: absent', which only needs 'name'");
        }
    }
    let ports = match r.port {
        None => None,
        Some(raw::Ports::One(n)) => Some(n.to_string()),
        Some(raw::Ports::Text(t)) => Some(t),
        Some(raw::Ports::List(items)) => Some(
            items
                .into_iter()
                .map(|i| match i {
                    raw::Scalar::Int(n) => Ok(n.to_string()),
                    raw::Scalar::Str(s) => Ok(s),
                    raw::Scalar::List(_) => bail!("firewall rule {name}: a port list can't nest"),
                })
                .collect::<Result<Vec<_>>>()?
                .join(","),
        ),
    };
    if let Some(p) = &ports
        && (p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit() || b == b',' || b == b'-'))
    {
        bail!("firewall rule {name}: ports look like 8791, 80,443 or 8000-8100, not '{p}'");
    }
    let protocol = r.protocol.unwrap_or_default();
    if ports.is_some() && protocol == FirewallProtocol::Any {
        bail!("firewall rule {name}: ports need protocol tcp or udp");
    }
    let profile = match r.profile.map(raw::OneOrMany::into_vec) {
        None => "any".to_owned(),
        Some(list) => {
            let list: Vec<String> = list.iter().map(|p| p.trim().to_ascii_lowercase()).collect();
            if let Some(bad) = list.iter().find(|p| !matches!(p.as_str(), "any" | "domain" | "private" | "public")) {
                bail!("firewall rule {name}: profile '{bad}' isn't any, domain, private or public");
            }
            list.join(",")
        }
    };
    Ok(FirewallRule {
        name,
        ports,
        protocol,
        direction: r.direction.unwrap_or_default(),
        action: r.action.unwrap_or_default(),
        program: r.program,
        profile,
        remote: r.remote.map(|r| r.into_vec().join(",")),
        state,
    })
}

/// Everything `desktop:` resolves to.
struct DesktopParts {
    wallpaper: Option<Wallpaper>,
    theme: Option<Theme>,
    lock_screen: Option<LockScreen>,
    screen_saver: Option<ScreenSaver>,
    /// Taskbar and Start settings, which are plain registry values.
    registry: Vec<RegistryValue>,
    /// The taskbar's pin list.
    files: Vec<FileCopy>,
    tray_icons: Vec<TrayIcon>,
    do_not_disturb: Option<bool>,
    start_pins: Option<StartPins>,
    shortcuts: Vec<DesktopShortcut>,
}

/// A picture reference (wallpaper, lock screen), checked to look like one.
fn picture_url(base: &Url, from: &str, what: &str) -> Result<Url> {
    let url = resolve_ref(base, from)?;
    let name = url.path().to_ascii_lowercase();
    let pictures = [".jpg", ".jpeg", ".png", ".bmp", ".gif", ".tif", ".tiff", ".jfif"];
    if !github::is_github(&url) && !pictures.iter().any(|ext| name.ends_with(ext)) {
        bail!("{what} '{from}' should be a picture (.jpg, .png, .bmp, …)");
    }
    Ok(url)
}

/// Built-in screen savers by short name; anything else is a path to a `.scr`.
fn screen_saver_program(name: &str) -> Result<String> {
    let builtin = match name.to_ascii_lowercase().as_str() {
        "blank" => "scrnsave.scr",
        "bubbles" => "Bubbles.scr",
        "mystify" => "Mystify.scr",
        "ribbons" => "Ribbons.scr",
        "photos" => "PhotoScreensaver.scr",
        "3d-text" => "ssText3d.scr",
        _ if name.to_ascii_lowercase().ends_with(".scr") => return Ok(name.to_owned()),
        _ => bail!("screen saver '{name}' isn't blank, bubbles, mystify, ribbons, photos, 3d-text or a .scr path"),
    };
    Ok(format!(r"%SystemRoot%\System32\{builtin}"))
}

fn resolve_desktop(base: &Url, d: raw::Desktop) -> Result<DesktopParts> {
    let mut scope = d.scope.map(raw::OneOrMany::into_vec).unwrap_or_else(|| vec![HiveScope::CurrentUser]);
    scope.sort();
    scope.dedup();

    let background = d.background.map(|c| parse_color(&c)).transpose()?;
    let picture = match d.wallpaper {
        None => None,
        Some(raw::StringOr::Short(from)) => Some((from, None)),
        Some(raw::StringOr::Full(w)) => Some((w.from, w.sha256)),
    };
    if picture.is_none() && d.wallpaper_style.is_some() {
        bail!("'wallpaper-style' needs a 'wallpaper' (a picture)");
    }
    let wallpaper = match picture {
        Some((from, sha256)) => {
            let url = picture_url(base, &from, "wallpaper")?;
            Some(Wallpaper {
                from: Some(url),
                sha256: pin(sha256)?,
                resolved: None,
                style: d.wallpaper_style.unwrap_or_default(),
                background,
                scope: scope.clone(),
            })
        }
        // Only a color: a plain desktop of that color.
        None => background.map(|background| Wallpaper {
            from: None,
            sha256: None,
            resolved: None,
            style: WallpaperStyle::default(),
            background: Some(background),
            scope: scope.clone(),
        }),
    };

    let theme = d.theme.map(|t| match t {
        raw::StringOr::Short(mode) => {
            let mode = match mode.to_ascii_lowercase().as_str() {
                "dark" => ThemeMode::Dark,
                "light" => ThemeMode::Light,
                other => bail!("theme '{other}' isn't dark or light (or {{ apps: …, windows: … }})"),
            };
            Ok(Theme { apps: Some(mode), windows: Some(mode), scope: scope.clone() })
        }
        raw::StringOr::Full(f) => {
            if f.apps.is_none() && f.windows.is_none() {
                bail!("theme needs 'apps', 'windows' or both");
            }
            Ok(Theme { apps: f.apps, windows: f.windows, scope: scope.clone() })
        }
    });
    let lock_screen = d
        .lock_screen
        .map(|l| -> Result<LockScreen> {
            let (image, sha256) = match l.image {
                None => (None, None),
                Some(raw::StringOr::Short(from)) => (Some(picture_url(base, &from, "lock screen image")?), None),
                Some(raw::StringOr::Full(w)) => (Some(picture_url(base, &w.from, "lock screen image")?), w.sha256),
            };
            if image.is_none() && l.lock_after.is_none() {
                bail!("lock-screen needs 'image', 'lock-after' or both");
            }
            let lock_after_secs = l.lock_after.map(duration_ms).transpose()?.map(|ms| ms / 1000);
            Ok(LockScreen { image, sha256: pin(sha256)?, resolved: None, lock_after_secs })
        })
        .transpose()
        .context("lock-screen")?;

    let screen_saver = d
        .screen_saver
        .map(|s| -> Result<ScreenSaver> {
            let enabled = s.enabled.unwrap_or(true);
            if !enabled && (s.timeout.is_some() || s.secure.is_some() || s.program.is_some()) {
                bail!("'enabled: false' turns the screen saver off; the other settings don't go with it");
            }
            let program = match (enabled, s.program) {
                (false, _) => None,
                (true, Some(p)) => Some(screen_saver_program(&p)?),
                (true, None) => Some(screen_saver_program("blank")?),
            };
            let timeout_secs = s.timeout.map(duration_ms).transpose()?.map(|ms| (ms / 1000).max(60));
            Ok(ScreenSaver { enabled, timeout_secs, secure: s.secure, program, scope: scope.clone() })
        })
        .transpose()
        .context("screen-saver")?;

    let mut registry = Vec::new();
    let mut files = Vec::new();
    if let Some(t) = d.taskbar {
        resolve_taskbar(t, &scope, &mut registry, &mut files).context("taskbar")?;
    }
    let mut start_pins = None;
    if let Some(mut s) = d.start {
        if let Some(pins) = s.pins_from.take() {
            let (from, sha256) = match pins {
                raw::StringOr::Short(from) => (from, None),
                raw::StringOr::Full(f) => (f.from, f.sha256),
            };
            let url = resolve_ref(base, &from).context("start: pins-from")?;
            start_pins = Some(StartPins { from: url, sha256: pin(sha256)?, resolved: None, scope: scope.clone() });
        }
        registry.extend(resolve_start(s, &scope, start_pins.is_some()).context("start")?);
    }
    let mut do_not_disturb = None;
    if let Some(n) = d.notifications {
        do_not_disturb = n.do_not_disturb;
        registry.extend(resolve_notifications(n, &scope).context("notifications")?);
    }
    let mut tray_icons = Vec::new();
    if let Some(t) = d.tray {
        resolve_tray(t, &scope, &mut registry, &mut tray_icons).context("tray")?;
    }
    let mut shortcuts = Vec::new();
    if let Some(i) = d.icons {
        resolve_icons(i, &scope, &mut registry, &mut shortcuts).context("icons")?;
    }

    Ok(DesktopParts {
        wallpaper,
        theme: theme.transpose()?,
        lock_screen,
        screen_saver,
        registry,
        files,
        tray_icons,
        do_not_disturb,
        start_pins,
        shortcuts,
    })
}

fn dword(key: &str, name: &str, value: u32, scope: &[HiveScope]) -> RegistryValue {
    RegistryValue {
        key: key.to_owned(),
        name: Some(name.to_owned()),
        kind: RegistryType::Dword,
        data: RegistryData::Dword(value),
        scope: scope.to_vec(),
        state: Presence::Present,
        group_policy: false,
    }
}

const EXPLORER_ADVANCED: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced";
const EXPLORER_POLICIES: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer";
/// Where the taskbar pins go for everyone (named by the Start layout policy), next to the
/// desktop pictures so `clean` leaves it.
pub(crate) const TASKBAR_POLICY_FILE: &str = r"%ProgramData%\groundhog\desktop\taskbar.xml";
/// Read once, when a new profile is created from the Default one.
const TASKBAR_DEFAULT_PROFILE_FILE: &str =
    r"%SystemDrive%\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml";

fn resolve_taskbar(
    t: raw::TaskbarFull,
    scope: &[HiveScope],
    registry: &mut Vec<RegistryValue>,
    files: &mut Vec<FileCopy>,
) -> Result<()> {
    let before = registry.len() + files.len();
    if let Some(a) = t.alignment {
        registry.push(dword(EXPLORER_ADVANCED, "TaskbarAl", a as u32, scope));
    }
    if let Some(s) = t.search {
        registry.push(dword(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Search",
            "SearchboxTaskbarMode",
            s as u32,
            scope,
        ));
    }
    if let Some(v) = t.task_view {
        registry.push(dword(EXPLORER_ADVANCED, "ShowTaskViewButton", u32::from(v), scope));
    }
    if let Some(v) = t.clock_seconds {
        registry.push(dword(EXPLORER_ADVANCED, "ShowSecondsInSystemClock", u32::from(v), scope));
    }
    // Windows guards the per-user widgets switch (TaskbarDa) against programs, so this is the
    // machine policy instead, which only Group Policy itself may write: `false` turns widgets
    // off, `true` lifts the policy.
    if let Some(on) = t.widgets {
        let mut v =
            dword(r"HKLM\SOFTWARE\Policies\Microsoft\Dsh", "AllowNewsAndInterests", 0, &[HiveScope::CurrentUser]);
        v.group_policy = true;
        if on {
            v.state = Presence::Absent;
            v.data = RegistryData::String(String::new());
        }
        registry.push(v);
    }
    match (t.pins, t.pins_for) {
        (None, Some(_)) => bail!("'pins-for' needs 'pins'"),
        (None, None) => {}
        (Some(pins), pins_for) => {
            let content = taskbar_layout(&pins)?;
            let to = match pins_for.unwrap_or_default() {
                raw::PinsFor::Everyone => {
                    registry.push(RegistryValue {
                        key: EXPLORER_POLICIES.to_owned(),
                        name: Some("StartLayoutFile".to_owned()),
                        kind: RegistryType::ExpandString,
                        data: RegistryData::String(TASKBAR_POLICY_FILE.to_owned()),
                        scope: vec![HiveScope::CurrentUser],
                        state: Presence::Present,
                        group_policy: false,
                    });
                    registry.push(dword(EXPLORER_POLICIES, "LockedStartLayout", 1, &[HiveScope::CurrentUser]));
                    TASKBAR_POLICY_FILE
                }
                raw::PinsFor::NewAccounts => TASKBAR_DEFAULT_PROFILE_FILE,
            };
            files.push(FileCopy {
                from: None,
                content: Some(content),
                to: to.to_owned(),
                sha256: None,
                resolved: None,
                extract: false,
                strip: 0,
                release: None,
                state: Presence::Present,
            });
        }
    }
    if registry.len() + files.len() == before {
        bail!("needs at least one of 'alignment', 'search', 'task-view', 'clock-seconds', 'widgets' or 'pins'");
    }
    Ok(())
}

/// Short names for apps people pin most, so a file needn't spell out package ids.
const PIN_ALIASES: &[(&str, &str)] = &[
    ("file-explorer", "Microsoft.Windows.Explorer"),
    ("edge", "MSEdge"),
    ("terminal", "Microsoft.WindowsTerminal_8wekyb3d8bbwe!App"),
    ("notepad", "Microsoft.WindowsNotepad_8wekyb3d8bbwe!App"),
    ("paint", "Microsoft.Paint_8wekyb3d8bbwe!App"),
    ("settings", "windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel"),
    ("store", "Microsoft.WindowsStore_8wekyb3d8bbwe!App"),
    ("calculator", "Microsoft.WindowsCalculator_8wekyb3d8bbwe!App"),
];

/// The taskbar pins as a Start layout file that replaces Windows' own pins. Each pin is an
/// alias, a shortcut (`….lnk`), a packaged app's id (`…!App`), or a desktop app's id, as
/// `Get-StartApps` lists them.
fn taskbar_layout(pins: &[String]) -> Result<String> {
    let mut items = String::new();
    for pin in pins {
        let pin = pin.trim();
        if pin.is_empty() {
            bail!("a pin is empty");
        }
        let id = PIN_ALIASES.iter().find(|(alias, _)| *alias == pin).map_or(pin, |(_, id)| id);
        let id = xml_escape(id);
        let item = if id.to_ascii_lowercase().ends_with(".lnk") {
            format!(r#"<taskbar:DesktopApp DesktopApplicationLinkPath="{id}"/>"#)
        } else if id.contains('!') {
            format!(r#"<taskbar:UWA AppUserModelID="{id}"/>"#)
        } else {
            format!(r#"<taskbar:DesktopApp DesktopApplicationID="{id}"/>"#)
        };
        items.push_str("        ");
        items.push_str(&item);
        items.push('\n');
    }
    Ok(format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<!-- Written by Groundhog: the taskbar's pinned apps. -->
<LayoutModificationTemplate xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification" xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout" Version="1">
  <CustomTaskbarLayoutCollection PinListPlacement="Replace">
    <defaultlayout:TaskbarLayout>
      <taskbar:TaskbarPinList>
{items}      </taskbar:TaskbarPinList>
    </defaultlayout:TaskbarLayout>
  </CustomTaskbarLayoutCollection>
</LayoutModificationTemplate>
"#
    ))
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('"', "&quot;").replace('<', "&lt;").replace('>', "&gt;")
}

const NOTIFICATION_SETTINGS: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings";

/// The switches in Settings > System > Notifications.
fn resolve_notifications(n: raw::NotificationsFull, scope: &[HiveScope]) -> Result<Vec<RegistryValue>> {
    let mut out = Vec::new();
    if let Some(v) = n.enabled {
        out.push(dword(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications",
            "ToastEnabled",
            u32::from(v),
            scope,
        ));
    }
    if let Some(v) = n.sounds {
        out.push(dword(NOTIFICATION_SETTINGS, "NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND", u32::from(v), scope));
    }
    if let Some(v) = n.lock_screen {
        out.push(dword(NOTIFICATION_SETTINGS, "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK", u32::from(v), scope));
    }
    for (app, on) in n.apps.unwrap_or_default() {
        if app.trim().is_empty() || app.contains('\\') {
            bail!(
                "'{app}' isn't an app id (one of the names under Settings > Notifications, like MSTeams_8wekyb3d8bbwe!MSTeams)"
            );
        }
        out.push(dword(&format!(r"{NOTIFICATION_SETTINGS}\{app}"), "Enabled", u32::from(on), scope));
    }
    if out.is_empty() && n.do_not_disturb.is_none() {
        bail!("needs at least one of 'enabled', 'sounds', 'lock-screen', 'do-not-disturb' or 'apps'");
    }
    Ok(out)
}

/// The notification area: which programs' icons sit on the taskbar, and the touch keyboard
/// button.
fn resolve_tray(
    t: raw::TrayFull,
    scope: &[HiveScope],
    registry: &mut Vec<RegistryValue>,
    icons: &mut Vec<TrayIcon>,
) -> Result<()> {
    let before = registry.len();
    if let Some(v) = t.touch_keyboard {
        registry.push(dword(r"HKCU\Software\Microsoft\TabletTip\1.7", "TipbandDesiredVisibility", u32::from(v), scope));
    }
    for (programs, shown) in [(t.show.unwrap_or_default(), true), (t.hide.unwrap_or_default(), false)] {
        for program in programs {
            let program = program.trim().to_owned();
            if program.is_empty() {
                bail!("a program is empty");
            }
            if icons.iter().any(|i| i.program.eq_ignore_ascii_case(&program)) {
                bail!("{program} is listed twice");
            }
            icons.push(TrayIcon { program, shown });
        }
    }
    if registry.len() == before && icons.is_empty() {
        bail!("needs at least one of 'show', 'hide' or 'touch-keyboard'");
    }
    Ok(())
}

const START_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Start";

/// The folders Start can show next to the power button, as Settings stores them (found by
/// turning each on in Settings, Windows 11 25H2).
const START_FOLDERS: &[(&str, &str)] = &[
    ("settings", "52730886-51AA-4243-9F7B-2776584659D4"),
    ("file-explorer", "148A24BC-D60C-4289-A080-6ED9BBA24882"),
    ("documents", "2D34D5CE-FA5A-4543-82F2-22E6EAF7773C"),
    ("downloads", "E367B32F-89DE-4355-BFCE-61F37B18A937"),
    ("music", "B00B0620-7F51-4C32-AA1E-34CC547F7315"),
    ("pictures", "383F07A0-E80A-4C80-B05A-86DB845DBC4D"),
    ("videos", "42B3A5C5-7D86-42F4-80A4-93FACA7A88B5"),
    ("network", "FE758144-080D-42AE-8BDA-34ED97B66394"),
    ("personal-folder", "74BDB04A-F94A-4F68-8BD6-4398071DA8BC"),
];

/// A GUID's 16 bytes as Windows stores them: the first three groups little-endian.
fn guid_bytes(guid: &str) -> Vec<u8> {
    let hex: String = guid.chars().filter(|c| *c != '-').collect();
    let b = parse_hex(&hex).expect("a constant GUID");
    let mut out = Vec::with_capacity(16);
    out.extend(b[0..4].iter().rev());
    out.extend(b[4..6].iter().rev());
    out.extend(b[6..8].iter().rev());
    out.extend(&b[8..16]);
    out
}

fn resolve_start(s: raw::StartFull, scope: &[HiveScope], has_pins: bool) -> Result<Vec<RegistryValue>> {
    let values = [
        ("Start_TrackDocs", s.recommended_files),
        ("Start_TrackProgs", s.most_used_apps),
        ("Start_IrisRecommendations", s.recommendations),
        ("Start_AccountNotifications", s.account_notifications),
    ];
    let mut out: Vec<RegistryValue> = values
        .into_iter()
        .filter_map(|(name, v)| v.map(|v| dword(EXPLORER_ADVANCED, name, u32::from(v), scope)))
        .collect();
    if let Some(shown) = s.recently_added {
        out.push(dword(START_KEY, "ShowRecentList", u32::from(shown), scope));
    }
    if let Some(folders) = s.folders {
        let mut bytes = Vec::new();
        for f in &folders {
            let guid = START_FOLDERS.iter().find(|(name, _)| name.eq_ignore_ascii_case(f.trim())).map(|(_, g)| g);
            let Some(guid) = guid else {
                let names: Vec<_> = START_FOLDERS.iter().map(|(n, _)| *n).collect();
                bail!("'{f}' isn't one of Start's folders: {}", names.join(", "));
            };
            bytes.extend(guid_bytes(guid));
        }
        out.push(RegistryValue {
            key: START_KEY.to_owned(),
            name: Some("VisiblePlaces".to_owned()),
            kind: RegistryType::Binary,
            data: RegistryData::Binary(bytes),
            scope: scope.to_vec(),
            state: Presence::Present,
            group_policy: false,
        });
    }
    if out.is_empty() && !has_pins {
        bail!(
            "needs at least one of 'pins-from', 'recommended-files', 'most-used-apps', 'recommendations',              'recently-added', 'account-notifications' or 'folders'"
        );
    }
    Ok(out)
}

/// `#RRGGBB` (or `RRGGBB`), normalized to upper case with the `#`.
fn parse_color(c: &str) -> Result<String> {
    let hex = c.trim().trim_start_matches('#');
    if hex.len() != 6 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("color '{c}' should look like #203040");
    }
    Ok(format!("#{}", hex.to_ascii_uppercase()))
}

fn resolve_exclusion(e: raw::StringOr<raw::DefenderExclusion>) -> Result<DefenderExclusion> {
    let e = match e {
        raw::StringOr::Short(path) => {
            return Ok(DefenderExclusion { kind: ExclusionKind::Path, value: path, state: Presence::Present });
        }
        raw::StringOr::Full(e) => e,
    };
    let state = e.state.unwrap_or_default();
    let (kind, value) = match (e.path, e.process, e.extension) {
        (Some(v), None, None) => (ExclusionKind::Path, v),
        (None, Some(v), None) => (ExclusionKind::Process, v),
        (None, None, Some(v)) => (ExclusionKind::Extension, v),
        _ => bail!("a defender exclusion is one of 'path', 'process' or 'extension'"),
    };
    if value.trim().is_empty() {
        bail!("a defender exclusion is empty");
    }
    Ok(DefenderExclusion { kind, value, state })
}

/// `${secret:NAME}` may appear in inline file `content`, `env` values, registry string values,
/// and run commands and script `args`. Anywhere else it would reach the machine as literal
/// text, so it's an error, as is a malformed reference.
fn check_secret_references(g: &Groundhogfile) -> Result<()> {
    let misplaced = |what: &str, s: &str| -> Result<()> {
        if secret::mentions(s) {
            bail!(
                "{what}: ${{secret:...}} can't be used here, only in files 'content', env values, \
                 registry string values, and run commands and args"
            );
        }
        Ok(())
    };
    for app in &g.apps {
        let (App::Winget { id, args, .. } | App::Url { id, args, .. }) = app;
        misplaced(&format!("app {id}"), args.as_deref().unwrap_or_default())?;
    }
    for f in &g.files {
        misplaced(&format!("file {}", f.to), &f.to)?;
    }
    for (name, v) in &g.env {
        secret::parse(&v.value).with_context(|| format!("env {name}"))?;
        if v.scope == EnvScope::Machine && secret::mentions(&v.value) {
            bail!("env {name}: a secret can't go in a machine-scope variable, which every account can read");
        }
    }
    for p in &g.path {
        misplaced(&format!("path {}", p.dir), &p.dir)?;
    }
    for r in &g.registry {
        let what = format!("registry {}\\{}", r.key, r.name.as_deref().unwrap_or("(default)"));
        misplaced(&what, &r.key)?;
        misplaced(&what, r.name.as_deref().unwrap_or_default())?;
        match &r.data {
            RegistryData::String(v) => drop(secret::parse(v).with_context(|| what.clone())?),
            RegistryData::MultiString(vs) => {
                for v in vs {
                    secret::parse(v).with_context(|| what.clone())?;
                }
            }
            RegistryData::Dword(_) | RegistryData::Qword(_) | RegistryData::Binary(_) => {}
        }
    }
    for (i, r) in g.run.iter().enumerate() {
        match r {
            RunAction::Command { command, .. } => drop(secret::parse(command).with_context(|| format!("run[{i}]"))?),
            RunAction::Script { args, .. } => {
                drop(secret::parse(args.as_deref().unwrap_or_default()).with_context(|| format!("run[{i}]"))?)
            }
            RunAction::Plugin { plugin, with, .. } => misplaced(&format!("plugin {plugin}"), &with.to_string())?,
        }
    }
    Ok(())
}

/// A payload source for DISM: a folder or share the machine itself can reach. A relative path
/// resolves next to the Groundhogfile, which only works when that is a local file.
fn servicing_source(base: &Url, s: &str) -> Result<String> {
    let b = s.as_bytes();
    let absolute = (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/'))
        || s.starts_with(r"\\")
        || s.starts_with('%');
    if absolute {
        return Ok(s.to_owned());
    }
    if s.contains("://") {
        // A .zip or .iso at a URL is fetched (streamed) and unpacked or mounted by the agent.
        if !(s.starts_with("https://") || s.starts_with("http://")) {
            bail!("'{s}': a source URL must be http(s)");
        }
        return Ok(s.to_owned());
    }
    if base.scheme() != "file" {
        bail!("'{s}': a relative source only works when the Groundhogfile is a local file; give a full path or share");
    }
    let dir = file_url_to_path(base)?.parent().map(Path::to_path_buf).unwrap_or_default();
    Ok(dir.join(s).to_string_lossy().into_owned())
}

fn resolve_feature(base: &Url, f: raw::StringOr<raw::Feature>) -> Result<Feature> {
    let f = match f {
        raw::StringOr::Short(name) => raw::Feature {
            name,
            state: None,
            all: None,
            remove_payload: None,
            source: None,
            limit_access: None,
            timeout: None,
        },
        raw::StringOr::Full(f) => f,
    };
    if f.name.trim().is_empty() {
        bail!("a feature needs a name");
    }
    let enabled = f.state != Some(raw::FeatureState::Disabled);
    if enabled && f.remove_payload.is_some() {
        bail!("feature {}: 'remove-payload' only applies with 'state: disabled'", f.name);
    }
    if !enabled && (f.all.is_some() || f.source.is_some() || f.limit_access.is_some()) {
        bail!("feature {}: 'all', 'source' and 'limit-access' only apply when enabling", f.name);
    }
    let sources = f.source.map(raw::OneOrMany::into_vec).unwrap_or_default();
    Ok(Feature {
        enabled,
        all: enabled && f.all.unwrap_or(true),
        remove_payload: f.remove_payload.unwrap_or(false),
        sources: sources.iter().map(|s| servicing_source(base, s)).collect::<Result<_>>()?,
        limit_access: f.limit_access.unwrap_or(false),
        timeout_ms: f.timeout.map(duration_ms).transpose()?,
        name: f.name,
    })
}

fn resolve_capability(base: &Url, c: raw::StringOr<raw::Capability>) -> Result<Capability> {
    let c = match c {
        raw::StringOr::Short(name) => {
            raw::Capability { name, state: None, source: None, limit_access: None, timeout: None }
        }
        raw::StringOr::Full(c) => c,
    };
    if c.name.trim().is_empty() {
        bail!("a capability needs a name");
    }
    let present = c.state != Some(raw::CapabilityState::Removed);
    if !present && (c.source.is_some() || c.limit_access.is_some()) {
        bail!("capability {}: 'source' and 'limit-access' only apply when adding", c.name);
    }
    // Capability names carry a version (OpenSSH.Server~~~~0.0.1.0); almost all are 0.0.1.0,
    // so a bare name gets that. Anything else must be written out in full.
    let name = if c.name.contains('~') { c.name } else { format!("{}~~~~0.0.1.0", c.name) };
    let sources = c.source.map(raw::OneOrMany::into_vec).unwrap_or_default();
    Ok(Capability {
        name,
        present,
        sources: sources.iter().map(|s| servicing_source(base, s)).collect::<Result<_>>()?,
        limit_access: c.limit_access.unwrap_or(false),
        timeout_ms: c.timeout.map(duration_ms).transpose()?,
    })
}

fn resolve_user(u: raw::User) -> Result<User> {
    // Windows' own rules for local account names.
    if u.name.trim().is_empty()
        || u.name.len() > 20
        || u.name.contains(['"', '/', '\\', '[', ']', ':', ';', '|', '=', ',', '+', '*', '?', '<', '>', '@'])
    {
        bail!(
            "'{}' is not a valid local account name (up to 20 characters, none of \" / \\ [ ] : ; | = , + * ? < > @)",
            u.name
        );
    }
    let state = u.state.unwrap_or_default();
    if !state.is_present() && (u.password.is_some() || u.groups.is_some() || u.full_name.is_some() || u.reset_password)
    {
        bail!("user '{}': 'state: absent' deletes the account and only needs 'name'", u.name);
    }
    let password = match u.password {
        None => Password::Generate,
        Some(raw::StringOr::Short(s)) if s == "generate" => Password::Generate,
        // `${secret:NAME}` on its own is the same as `{ secret: NAME }`.
        Some(raw::StringOr::Short(s)) if matches!(secret::parse(&s).as_deref(), Ok([secret::Part::Secret(_)])) => {
            let name = secret::names(&s)?.into_iter().next().expect("one reference");
            Password::Secret(name)
        }
        Some(raw::StringOr::Short(_)) => bail!(
            "user '{}': a password can't be written in a Groundhogfile; use 'generate', or ${{secret:NAME}} \
             (or {{ secret: NAME }}) and supply NAME at run time",
            u.name
        ),
        Some(raw::StringOr::Full(r)) => {
            if r.secret.is_empty() || !r.secret.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                bail!("user '{}': secret names use letters, digits and _ ('{}')", u.name, r.secret);
            }
            Password::Secret(r.secret)
        }
    };
    Ok(User {
        name: u.name,
        full_name: u.full_name,
        password,
        groups: u.groups.map(raw::OneOrMany::into_vec).unwrap_or_default(),
        password_never_expires: u.password_never_expires.unwrap_or(true),
        reset_password: u.reset_password,
        state,
    })
}

/// Every secret a Groundhogfile needs at run time.
pub fn required_secrets(file: &Groundhogfile) -> std::collections::BTreeSet<String> {
    let mut names: std::collections::BTreeSet<String> =
        crate::engine::plan(file).iter().flat_map(|s| crate::engine::secrets_in(&s.action)).collect();
    names.extend(file.users.iter().filter_map(|u| match &u.password {
        Password::Secret(name) => Some(name.clone()),
        Password::Generate => None,
    }));
    names
}

fn resolve_run(base: &Url, r: raw::RunFull) -> Result<RunAction> {
    let kinds = [("command", r.command.is_some()), ("script", r.script.is_some()), ("plugin", r.plugin.is_some())];
    let set: Vec<&str> = kinds.iter().filter(|(_, on)| *on).map(|(k, _)| *k).collect();
    let kind = match set.as_slice() {
        [one] => *one,
        [] => bail!("a run entry needs one of: command, script, plugin"),
        many => bail!("a run entry can only be one kind, but this one sets {}", many.join(" and ")),
    };
    let allowed: &[&str] = match kind {
        "command" => &["shell"],
        "script" => &["shell", "args", "sha256"],
        _ => &["sha256", "with"],
    };
    let given = [
        ("shell", r.shell.is_some()),
        ("args", r.args.is_some()),
        ("sha256", r.sha256.is_some()),
        ("with", r.with.is_some()),
    ];
    if let Some((opt, _)) = given.iter().find(|(opt, on)| *on && !allowed.contains(opt)) {
        bail!("'{opt}' doesn't apply to {kind} entries");
    }

    let timeout_ms = r.timeout.map(duration_ms).transpose()?;
    let always = r.always;
    Ok(match kind {
        "command" => {
            let shell = r.shell.unwrap_or_default();
            if shell == Shell::Direct {
                bail!("'shell: direct' only applies to scripts; use cmd, powershell or pwsh for commands");
            }
            RunAction::Command { command: r.command.expect("kind"), shell, timeout_ms, always }
        }
        "script" => {
            let script = resolve_ref(base, &r.script.expect("kind"))?;
            github::reject(&script, "'run' scripts")?;
            RunAction::Script {
                script,
                sha256: pin(r.sha256)?,
                resolved: None,
                args: r.args,
                shell: r.shell,
                timeout_ms,
                always,
            }
        }
        _ => {
            let plugin = resolve_ref(base, &r.plugin.expect("kind"))?;
            github::reject(&plugin, "'run' plugins")?;
            RunAction::Plugin {
                plugin,
                sha256: pin(r.sha256)?,
                resolved: None,
                with: r.with.unwrap_or(serde_json::Value::Null),
                timeout_ms,
                always,
            }
        }
    })
}

/// How long a check keeps retrying before it fails, unless it says otherwise. Checks usually
/// run right after an install, so a little grace beats a hand-written `Start-Sleep`.
const DEFAULT_WITHIN_MS: u64 = 30_000;

fn resolve_check(c: raw::Check) -> Result<Check> {
    let kinds = [
        ("process", c.process.is_some()),
        ("service", c.service.is_some()),
        ("eventlog", c.eventlog.is_some()),
        ("port", c.port.is_some()),
        ("file", c.file.is_some()),
        ("command", c.command.is_some()),
    ];
    let set: Vec<&str> = kinds.iter().filter(|(_, on)| *on).map(|(k, _)| *k).collect();
    let kind = match set.as_slice() {
        [one] => *one,
        [] => bail!("a check needs one of: process, service, eventlog, port, file, command"),
        many => bail!("a check can only be one kind, but this one sets {}", many.join(" and ")),
    };

    // Options that only make sense for some kinds.
    let allowed: &[&str] = match kind {
        "process" => &["stable-for", "within"],
        "service" => &["status", "within"],
        "eventlog" => &["within"],
        "port" => &["host", "within"],
        "file" => &["within"],
        _ => &["shell", "within"],
    };
    let given = [
        ("host", c.host.is_some()),
        ("status", c.status.is_some()),
        ("shell", c.shell.is_some()),
        ("stable-for", c.stable_for.is_some()),
        ("within", c.within.is_some()),
    ];
    if let Some((opt, _)) = given.iter().find(|(opt, on)| *on && !allowed.contains(opt)) {
        bail!("'{opt}' doesn't apply to {kind} checks");
    }

    let within_ms = match c.within {
        Some(d) => duration_ms(d)?,
        None => DEFAULT_WITHIN_MS,
    };
    Ok(match kind {
        "process" => Check::Process {
            name: c.process.expect("kind"),
            stable_for_ms: c.stable_for.map(duration_ms).transpose()?.unwrap_or(0),
            within_ms,
        },
        "service" => Check::Service {
            name: c.service.expect("kind"),
            status: c.status.unwrap_or(ServiceState::Running),
            within_ms,
        },
        "eventlog" => {
            let e = c.eventlog.expect("kind");
            let must_contain = e.must_contain.map(raw::OneOrMany::into_vec).unwrap_or_default();
            let must_not_contain = e.must_not_contain.map(raw::OneOrMany::into_vec).unwrap_or_default();
            if must_contain.is_empty() && must_not_contain.is_empty() {
                bail!("an eventlog check needs 'must-contain' or 'must-not-contain'");
            }
            Check::EventLog {
                log: e.log.unwrap_or_else(|| "Application".to_owned()),
                provider: e.provider,
                must_contain,
                must_not_contain,
                since: e.since,
                within_ms,
            }
        }
        "port" => Check::Port {
            host: c.host.unwrap_or_else(|| "127.0.0.1".to_owned()),
            port: c.port.expect("kind"),
            within_ms,
        },
        "file" => Check::File { path: c.file.expect("kind"), within_ms },
        _ => {
            let shell = c.shell.unwrap_or_default();
            if shell == Shell::Direct {
                bail!("'shell: direct' only applies to scripts");
            }
            Check::Command { command: c.command.expect("kind"), shell, within_ms }
        }
    })
}

fn duration_ms(d: raw::Duration) -> Result<u64> {
    let ms = match d {
        raw::Duration::Seconds(s) => s.saturating_mul(1000),
        raw::Duration::Text(t) => {
            let parsed = humantime::parse_duration(t.trim())
                .map_err(|e| anyhow!("invalid duration '{t}' ({e}); use e.g. 30s, 2m or 500ms"))?;
            u64::try_from(parsed.as_millis()).unwrap_or(u64::MAX)
        }
    };
    Ok(ms)
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
    let group_policy = r.via == Some(raw::RegistryVia::GroupPolicy);
    if group_policy && !matches!(root.as_str(), "HKLM" | "HKEY_LOCAL_MACHINE") {
        bail!("registry key '{key}': 'via: group-policy' is for HKLM keys (the machine's policy)");
    }

    let state = r.state.unwrap_or_default();
    let name = r.name.filter(|n| !n.is_empty());
    let shown = name.clone().unwrap_or_else(|| "(default)".to_owned());
    let bad = |what: &str| anyhow!("registry value {key}\\{shown}: {what}");
    if !state.is_present() {
        if r.value.is_some() {
            bail!("registry value {key}: 'value' doesn't go with 'state: absent'");
        }
        // Without a name, absent deletes the whole key: refuse the top of a hive, where one
        // typo would take out half the machine.
        if name.is_none() && key.split('\\').filter(|p| !p.is_empty()).count() < 3 {
            bail!("registry key {key}: refusing to delete a key this close to the root of the hive");
        }
        if group_policy && name.is_none() {
            bail!("registry key {key}: 'via: group-policy' removes values, not whole keys");
        }
        return Ok(RegistryValue {
            key,
            name,
            kind: r.kind,
            data: RegistryData::String(String::new()),
            scope,
            state,
            group_policy,
        });
    }
    let value = r.value.ok_or_else(|| anyhow!("registry value {key}: needs a 'value' (or 'state: absent')"))?;
    let data = match (r.kind, value) {
        (RegistryType::String | RegistryType::ExpandString, raw::Scalar::Str(s)) => RegistryData::String(s),
        (RegistryType::String | RegistryType::ExpandString, raw::Scalar::Int(n)) => RegistryData::String(n.to_string()),
        (RegistryType::MultiString, raw::Scalar::List(v)) => RegistryData::MultiString(v),
        (RegistryType::MultiString, raw::Scalar::Str(s)) => RegistryData::MultiString(vec![s]),
        (RegistryType::Dword, v) => RegistryData::Dword(
            u32::try_from(scalar_to_u64(v).ok_or_else(|| bad("expected a number"))?)
                .map_err(|_| bad("does not fit in a dword"))?,
        ),
        (RegistryType::Qword, v) => RegistryData::Qword(scalar_to_u64(v).ok_or_else(|| bad("expected a number"))?),
        (RegistryType::Binary, raw::Scalar::Str(s)) => RegistryData::Binary(
            parse_hex(&s).ok_or_else(|| bad("expected hex bytes, like \"86 08 73 52\" or \"86087352\""))?,
        ),
        (kind, _) => return Err(bad(&format!("value does not match type {kind:?}"))),
    };

    Ok(RegistryValue { key, name, kind: r.kind, data, scope, state, group_policy })
}

const UAC_KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";

/// `uac:` as the policy values it stands for. A `level` picks the Control Panel slider's
/// values; `admin-prompt` and `secure-desktop` given alongside it win over the level's.
/// `language:` as one step per setting; the switch hotkey is plain registry values.
fn resolve_language(l: raw::Language, registry: &mut Vec<RegistryValue>) -> Result<Vec<LanguageSetting>> {
    let mut out = Vec::new();
    if let Some(input) = l.input {
        if input.is_empty() {
            bail!("'input' needs at least one language");
        }
        let languages = input
            .into_iter()
            .map(|i| {
                let (tag, keyboards) = match i {
                    raw::StringOr::Short(tag) => (tag, Vec::new()),
                    raw::StringOr::Full(f) => (f.language, f.keyboards),
                };
                for k in &keyboards {
                    let ok = k.contains(':') && k.chars().all(|c| c.is_ascii_hexdigit() || "{}:-".contains(c));
                    if !ok {
                        bail!("keyboard '{k}' should look like 0409:00000409 (as Get-WinUserLanguageList shows them)");
                    }
                }
                Ok(InputLanguage { tag: language_tag(&tag)?, keyboards })
            })
            .collect::<Result<_>>()?;
        out.push(LanguageSetting::Input { languages });
    }
    if let Some(keys) = l.switch_hotkey {
        // Settings > Time & language > Typing > Advanced keyboard settings > Input language hot keys.
        let value = match keys {
            raw::SwitchHotkey::AltShift => "1",
            raw::SwitchHotkey::CtrlShift => "2",
            raw::SwitchHotkey::None => "3",
            raw::SwitchHotkey::Grave => "4",
        };
        let mut names = vec!["Hotkey", "Language Hotkey"];
        if keys == raw::SwitchHotkey::None {
            names.push("Layout Hotkey");
        }
        for name in names {
            registry.push(RegistryValue {
                key: r"HKCU\Keyboard Layout\Toggle".to_owned(),
                name: Some(name.to_owned()),
                kind: RegistryType::String,
                data: RegistryData::String(value.to_owned()),
                scope: vec![HiveScope::CurrentUser],
                state: Presence::Present,
                group_policy: false,
            });
        }
    }
    let welcome = l.welcome_screen.unwrap_or(false);
    if let Some(tag) = l.display {
        out.push(LanguageSetting::Display { tag: language_tag(&tag)?, machine: welcome });
    }
    if let Some(tag) = l.formats {
        out.push(LanguageSetting::Formats { tag: language_tag(&tag)? });
    }
    if let Some(region) = l.location {
        if region.len() != 2 || !region.bytes().all(|b| b.is_ascii_alphabetic()) {
            bail!("location '{region}' should be a two-letter country or region code, like US or GB");
        }
        out.push(LanguageSetting::Location { region: region.to_ascii_uppercase() });
    }
    if let Some(tag) = l.system_locale {
        out.push(LanguageSetting::SystemLocale { tag: language_tag(&tag)? });
    }
    if let Some(on) = l.utf8 {
        out.push(LanguageSetting::Utf8 { on });
    }
    if welcome {
        out.push(LanguageSetting::CopyToSystem);
    }
    if out.is_empty() && l.switch_hotkey.is_none() {
        bail!("needs at least one setting");
    }
    Ok(out)
}

/// A language tag as Windows takes them (`en-US`, `ja-JP`, `zh-Hans-CN`, `sr-Latn-RS`).
fn language_tag(tag: &str) -> Result<String> {
    let parts: Vec<&str> = tag.split('-').collect();
    let ok = (2..=3).contains(&parts[0].len())
        && parts[0].bytes().all(|b| b.is_ascii_alphabetic())
        && parts[1..].iter().all(|p| (2..=8).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_alphanumeric()));
    if !ok {
        bail!("'{tag}' isn't a language tag like en-US or ja-JP");
    }
    Ok(tag.to_owned())
}

/// Where Explorer keeps which of Windows' own icons the desktop shows (0 shown, 1 hidden).
pub(crate) const DESKTOP_ICONS_KEY: &str =
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel";

/// Windows' own desktop icons become registry values; shortcuts, steps of their own.
fn resolve_icons(
    i: raw::IconsFull,
    scope: &[HiveScope],
    registry: &mut Vec<RegistryValue>,
    shortcuts: &mut Vec<DesktopShortcut>,
) -> Result<()> {
    let builtin = [
        ("{20D04FE0-3AEA-1069-A2D8-08002B30309D}", i.this_pc),
        ("{645FF040-5081-101B-9F08-00AA002F954E}", i.recycle_bin),
        ("{59031a47-3f72-44a7-89c5-5595fe6b30ee}", i.user_files),
        ("{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}", i.network),
        ("{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}", i.control_panel),
    ];
    for (guid, shown) in builtin {
        if let Some(shown) = shown {
            registry.push(dword(DESKTOP_ICONS_KEY, guid, u32::from(!shown), scope));
        }
    }
    let name_ok = |n: &str| !n.trim().is_empty() && !n.contains(['\\', '/', ':', '*', '?', '"', '<', '>', '|']);
    for s in i.add.unwrap_or_default() {
        if !name_ok(&s.name) {
            bail!("'{}' can't be a shortcut's name", s.name);
        }
        if s.target.trim().is_empty() {
            bail!("shortcut '{}' needs a 'target'", s.name);
        }
        shortcuts.push(DesktopShortcut {
            name: s.name,
            target: Some(s.target),
            args: s.args,
            icon: s.icon,
            state: Presence::Present,
        });
    }
    for name in i.remove.unwrap_or_default() {
        if !name_ok(&name) {
            bail!("'{name}' can't be a shortcut's name");
        }
        // Edge's updater puts its shortcut back on every update, unless its policy says not to.
        if name.eq_ignore_ascii_case("Microsoft Edge") {
            registry.push(dword(
                r"HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate",
                "CreateDesktopShortcutDefault",
                0,
                &[HiveScope::CurrentUser],
            ));
        }
        shortcuts.push(DesktopShortcut { name, target: None, args: None, icon: None, state: Presence::Absent });
    }
    Ok(())
}

fn resolve_uac(u: raw::Uac) -> Result<Vec<RegistryValue>> {
    let (mut admin, mut secure) = match u.level {
        None => (None, None),
        Some(raw::UacLevel::AlwaysNotify) => (Some(raw::AdminPrompt::ConsentOnSecureDesktop as u32), Some(true)),
        Some(raw::UacLevel::Default) => (Some(raw::AdminPrompt::ConsentForNonWindowsBinaries as u32), Some(true)),
        Some(raw::UacLevel::NoDim) => (Some(raw::AdminPrompt::ConsentForNonWindowsBinaries as u32), Some(false)),
        Some(raw::UacLevel::NeverNotify) => (Some(raw::AdminPrompt::ElevateWithoutPrompting as u32), Some(false)),
    };
    admin = u.admin_prompt.map(|a| a as u32).or(admin);
    secure = u.secure_desktop.or(secure);
    let values = [
        ("EnableLUA", u.enabled.map(u32::from)),
        ("ConsentPromptBehaviorAdmin", admin),
        ("ConsentPromptBehaviorUser", u.user_prompt.map(|p| p as u32)),
        ("PromptOnSecureDesktop", secure.map(u32::from)),
    ];
    let out: Vec<RegistryValue> = values
        .into_iter()
        .filter_map(|(name, v)| v.map(|v| dword(UAC_KEY, name, v, &[HiveScope::CurrentUser])))
        .collect();
    if out.is_empty() {
        bail!("needs at least one of 'level', 'admin-prompt', 'user-prompt', 'secure-desktop' or 'enabled'");
    }
    Ok(out)
}

/// Hex bytes, optionally separated by spaces, commas or dashes: `86 08 73`, `86,08,73`, `860873`.
fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let digits: String = s.chars().filter(|c| !(c.is_whitespace() || matches!(c, ',' | '-'))).collect();
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    (0..digits.len()).step_by(2).map(|i| u8::from_str_radix(digits.get(i..i + 2)?, 16).ok()).collect()
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
pub fn merge(base: Groundhogfile, mut top: Groundhogfile) -> Groundhogfile {
    let eq = |a: &str, b: &str| a.eq_ignore_ascii_case(b);

    // An entry exactly like one the base has keeps the base's place: two templates built on
    // the same one (python and node on dev-core) still install its apps first.
    fn drop_repeats<T: PartialEq>(base: &[T], top: &mut Vec<T>) {
        top.retain(|t| !base.contains(t));
    }
    drop_repeats(&base.apps, &mut top.apps);
    drop_repeats(&base.files, &mut top.files);
    drop_repeats(&base.registry, &mut top.registry);
    drop_repeats(&base.users, &mut top.users);
    drop_repeats(&base.features, &mut top.features);
    drop_repeats(&base.capabilities, &mut top.capabilities);

    let mut apps: Vec<App> = base.apps.into_iter().filter(|b| !top.apps.iter().any(|t| eq(t.id(), b.id()))).collect();
    apps.extend(top.apps);

    let mut files: Vec<FileCopy> =
        base.files.into_iter().filter(|b| !top.files.iter().any(|t| eq(&t.to, &b.to))).collect();
    files.extend(top.files);

    let mut env = base.env;
    env.extend(top.env);

    // An entry already there stays as the base wrote it; `state: absent` on top takes it back.
    let same_dir = |a: &PathEntry, b: &PathEntry| {
        a.scope == b.scope && eq(a.dir.trim_end_matches('\\'), b.dir.trim_end_matches('\\'))
    };
    let mut path = base.path;
    for p in top.path {
        match path.iter_mut().find(|x| same_dir(x, &p)) {
            Some(existing) if existing.state != p.state => *existing = p,
            Some(_) => {}
            None => path.push(p),
        }
    }

    let same_value = |a: &RegistryValue, b: &RegistryValue| {
        eq(&a.key, &b.key) && eq(a.name.as_deref().unwrap_or(""), b.name.as_deref().unwrap_or(""))
    };
    let mut registry: Vec<RegistryValue> =
        base.registry.into_iter().filter(|b| !top.registry.iter().any(|t| same_value(t, b))).collect();
    registry.extend(top.registry);

    // Commands and checks add up, but one the base already has isn't repeated: a file that
    // extends two templates built on the same one gets that one's steps once.
    let mut run = base.run;
    for r in top.run {
        if !run.contains(&r) {
            run.push(r);
        }
    }

    let mut verify = base.verify;
    for c in top.verify {
        if !verify.contains(&c) {
            verify.push(c);
        }
    }

    let mut users: Vec<User> =
        base.users.into_iter().filter(|b| !top.users.iter().any(|t| eq(&t.name, &b.name))).collect();
    users.extend(top.users);

    let mut features: Vec<Feature> =
        base.features.into_iter().filter(|b| !top.features.iter().any(|t| eq(&t.name, &b.name))).collect();
    features.extend(top.features);

    let mut capabilities: Vec<Capability> =
        base.capabilities.into_iter().filter(|b| !top.capabilities.iter().any(|t| eq(&t.name, &b.name))).collect();
    capabilities.extend(top.capabilities);

    let same_cert = |a: &Certificate, b: &Certificate| {
        a.store == b.store && a.scope == b.scope && a.from == b.from && a.thumbprint == b.thumbprint
    };
    let mut certificates: Vec<Certificate> =
        base.certificates.into_iter().filter(|b| !top.certificates.iter().any(|t| same_cert(t, b))).collect();
    certificates.extend(top.certificates);

    let mut services: Vec<Service> =
        base.services.into_iter().filter(|b| !top.services.iter().any(|t| eq(&t.name, &b.name))).collect();
    services.extend(top.services);

    let mut firewall: Vec<FirewallRule> =
        base.firewall.into_iter().filter(|b| !top.firewall.iter().any(|t| eq(&t.name, &b.name))).collect();
    firewall.extend(top.firewall);

    let same_exclusion = |a: &DefenderExclusion, b: &DefenderExclusion| a.kind == b.kind && eq(&a.value, &b.value);
    let mut defender_exclusions: Vec<DefenderExclusion> = base
        .defender_exclusions
        .into_iter()
        .filter(|b| !top.defender_exclusions.iter().any(|t| same_exclusion(t, b)))
        .collect();
    defender_exclusions.extend(top.defender_exclusions);

    let mut remove_apps = base.remove_apps;
    for a in top.remove_apps {
        if !remove_apps.iter().any(|x| eq(x, &a)) {
            remove_apps.push(a);
        }
    }

    // The strictest requirement wins: a base that needs a newer agent still needs it.
    let requires_agent = base.requires_agent.max(top.requires_agent);

    // Desktop settings: the later file wins, setting by setting.
    let wallpaper = top.wallpaper.or(base.wallpaper);
    let lock_screen = top.lock_screen.or(base.lock_screen);
    let screen_saver = top.screen_saver.or(base.screen_saver);
    let mut tray_icons: Vec<TrayIcon> =
        base.tray_icons.into_iter().filter(|b| !top.tray_icons.iter().any(|t| eq(&t.program, &b.program))).collect();
    tray_icons.extend(top.tray_icons);
    let do_not_disturb = top.do_not_disturb.or(base.do_not_disturb);
    let start_pins = top.start_pins.or(base.start_pins);
    let mut desktop_shortcuts: Vec<DesktopShortcut> = base
        .desktop_shortcuts
        .into_iter()
        .filter(|b| !top.desktop_shortcuts.iter().any(|t| eq(&t.name, &b.name)))
        .collect();
    desktop_shortcuts.extend(top.desktop_shortcuts);
    // Setting by setting: the top file's display language replaces the base's, and so on.
    let mut language: Vec<LanguageSetting> =
        base.language.into_iter().filter(|b| !top.language.iter().any(|t| t.order() == b.order())).collect();
    language.extend(top.language);
    language.sort_by_key(LanguageSetting::order);
    let theme = match (base.theme, top.theme) {
        (Some(b), Some(t)) => Some(Theme { apps: t.apps.or(b.apps), windows: t.windows.or(b.windows), scope: t.scope }),
        (b, t) => t.or(b),
    };

    Groundhogfile {
        users,
        certificates,
        defender_exclusions,
        features,
        capabilities,
        remove_apps,
        apps,
        files,
        env,
        path,
        registry,
        wallpaper,
        theme,
        lock_screen,
        screen_saver,
        tray_icons,
        do_not_disturb,
        start_pins,
        desktop_shortcuts,
        language,
        services,
        firewall,
        run,
        verify,
        requires_agent,
    }
}

/// Convenience for callers: turns user input plus an optional pin into a [`SourceRef`].
pub fn source_ref(input: &str, sha256: Option<String>, cwd: &Path) -> Result<SourceRef> {
    Ok(SourceRef { url: fetch::parse_location(input, cwd)?, sha256 })
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use super::*;
    use crate::cache::Cache;
    use crate::fetch::sha256_hex;
    use crate::fetch::testing::MapFetcher;

    fn load_with(fetcher: &MapFetcher, root: &str, bundle_dir: &Path) -> Result<Loaded> {
        let cache = Cache::default();
        let content = ContentStore { fetcher, cache: &cache };
        let loader = Loader::new(&content, bundle_dir.to_path_buf());
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

        assert_eq!(
            g.apps[0],
            App::Winget {
                id: "git.git".into(),
                version: None,
                args: None,
                timeout_ms: None,
                upgrade: false,
                state: Presence::Present
            }
        );
        let App::Url { url, .. } = &g.apps[1] else { panic!() };
        assert_eq!(url.as_str(), "https://cfg.test/dl/tool.msi");
        assert_eq!(g.files[0].from.as_ref().unwrap().as_str(), "https://cfg.test/dev/config/.gitconfig");
        assert_eq!(g.registry[0].data, RegistryData::Dword(16));
        assert_eq!(g.registry[0].scope, vec![HiveScope::CurrentUser, HiveScope::DefaultUser]);
        assert_eq!(
            g.run[0],
            RunAction::Command { command: "echo hi".into(), shell: Shell::Powershell, timeout_ms: None, always: false }
        );
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
        assert_eq!(g.env["A"].value, "base");
        assert_eq!(g.env["B"].value, "top");
        assert_eq!(g.path.iter().map(|p| p.dir.as_str()).collect::<Vec<_>>(), ["C:\\tools\\"]);
        assert_eq!(g.run.len(), 2);
        assert_eq!(g.files[0].from.as_ref().unwrap().as_str(), "https://cfg.test/gitconfig");
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
    fn parses_verify_checks_with_defaults() {
        let f = MapFetcher::default().with(
            "https://cfg.test/g.yaml",
            r#"
verify:
  - process: rdpeek-agent
    stable-for: 8s
    within: 1m
  - service: RdpeekAgentSvc
  - eventlog: { provider: RdpeekAgentSvc, must-not-contain: '0xC0000142' }
  - port: 3389
  - file: C:\rdpeek\bundle\rdpeek-agent.exe
    within: 5
  - command: Test-Path C:\x
"#,
        );
        let dir = tempfile::tempdir().unwrap();
        let v = load_with(&f, "https://cfg.test/g.yaml", dir.path()).unwrap().file.verify;
        assert_eq!(v[0], Check::Process { name: "rdpeek-agent".into(), stable_for_ms: 8000, within_ms: 60_000 });
        assert_eq!(
            v[1],
            Check::Service {
                name: "RdpeekAgentSvc".into(),
                status: ServiceState::Running,
                within_ms: DEFAULT_WITHIN_MS
            }
        );
        let Check::EventLog { log, must_not_contain, since, .. } = &v[2] else { panic!() };
        assert_eq!(
            (log.as_str(), must_not_contain.as_slice(), *since),
            ("Application", &["0xC0000142".to_owned()][..], crate::model::EventsSince::Apply)
        );
        assert_eq!(v[3], Check::Port { host: "127.0.0.1".into(), port: 3389, within_ms: DEFAULT_WITHIN_MS });
        assert!(matches!(&v[4], Check::File { within_ms: 5000, .. }));
        assert!(matches!(&v[5], Check::Command { shell: Shell::Powershell, .. }));
    }

    #[test]
    fn rejects_malformed_checks_with_useful_errors() {
        let cases = [
            ("verify: [{ process: a, service: b }]", "only be one kind"),
            ("verify: [{ within: 5s }]", "needs one of"),
            ("verify: [{ service: a, stable-for: 5s }]", "'stable-for' doesn't apply to service checks"),
            ("verify: [{ process: a, within: soon }]", "invalid duration"),
            ("verify: [{ eventlog: { provider: p } }]", "must-contain"),
            ("verify: [{ proces: a }]", "unknown field"),
            ("files: [{ from: a.txt, to: C:/a, extract: true }]", "needs a .zip"),
        ];
        let dir = tempfile::tempdir().unwrap();
        for (yaml, want) in cases {
            let f = MapFetcher::default().with("https://cfg.test/g.yaml", yaml).with("https://cfg.test/a.txt", "x");
            let err = format!("{:#}", load_with(&f, "https://cfg.test/g.yaml", dir.path()).unwrap_err());
            assert!(err.contains(want), "{yaml}: expected '{want}' in: {err}");
        }
    }

    #[test]
    fn verify_accumulates_across_extends() {
        let f = MapFetcher::default()
            .with("https://cfg.test/base.yaml", "verify: [{ port: 22 }]")
            .with("https://cfg.test/top.yaml", "extends: base.yaml\nverify: [{ port: 3389 }]");
        let dir = tempfile::tempdir().unwrap();
        let v = load_with(&f, "https://cfg.test/top.yaml", dir.path()).unwrap().file.verify;
        let ports: Vec<_> = v.iter().map(|c| if let Check::Port { port, .. } = c { *port } else { 0 }).collect();
        assert_eq!(ports, [22, 3389]);
    }

    #[test]
    fn agent_requirements_are_read_and_merged() {
        let f = MapFetcher::default()
            .with("https://cfg.test/base.yaml", "agent: '>=0.2.0'")
            .with("https://cfg.test/top.yaml", "extends: base.yaml\nagent: 0.1.0");
        let dir = tempfile::tempdir().unwrap();
        let g = load_with(&f, "https://cfg.test/top.yaml", dir.path()).unwrap().file;
        assert_eq!(g.requires_agent, Some(Version::parse("0.2.0").unwrap()), "the higher requirement wins");
    }

    #[test]
    fn a_file_for_a_newer_agent_says_so_instead_of_unknown_field() {
        let f = MapFetcher::default()
            .with("https://cfg.test/future.yaml", "agent: '>=99.0.0'\nsome-future-key: [1, 2]")
            .with("https://cfg.test/typo.yaml", "agent: '>=0.0.1'\naps: [git.git]");
        let dir = tempfile::tempdir().unwrap();

        let err = load_with(&f, "https://cfg.test/future.yaml", dir.path()).unwrap_err();
        let needs = err.downcast_ref::<NeedsAgent>().expect("a NeedsAgent error");
        assert_eq!(needs.required, Version::parse("99.0.0").unwrap());
        assert!(format!("{err:#}").contains("unknown field"), "the parse error is kept for context: {err:#}");

        // An old enough requirement doesn't excuse a typo.
        let err = load_with(&f, "https://cfg.test/typo.yaml", dir.path()).unwrap_err();
        assert!(err.downcast_ref::<NeedsAgent>().is_none());
    }

    #[test]
    fn run_entries_take_timeout_and_always_and_reject_typos() {
        let f = MapFetcher::default()
            .with("https://cfg.test/g.yaml", "run:\n  - command: dotnet test\n    timeout: 30m\n    always: true")
            .with("https://cfg.test/typo.yaml", "run:\n  - command: dotnet test\n    timout: 30m")
            .with("https://cfg.test/two.yaml", "run:\n  - command: a\n    script: b.ps1")
            .with("https://cfg.test/opt.yaml", "run:\n  - command: a\n    args: -x");
        let dir = tempfile::tempdir().unwrap();
        let g = load_with(&f, "https://cfg.test/g.yaml", dir.path()).unwrap().file;
        assert_eq!(g.run[0].timeout_ms(), Some(30 * 60 * 1000));
        assert!(g.run[0].always());

        let err = |url: &str| format!("{:#}", load_with(&f, url, dir.path()).unwrap_err());
        assert!(
            err("https://cfg.test/typo.yaml").contains("unknown field `timout`"),
            "{}",
            err("https://cfg.test/typo.yaml")
        );
        assert!(err("https://cfg.test/two.yaml").contains("only be one kind"));
        assert!(err("https://cfg.test/opt.yaml").contains("'args' doesn't apply to command entries"));
    }

    #[test]
    fn github_sources_resolve_to_one_release_with_digests() {
        let release = format!(
            r#"[{{ "tag_name": "1.0.268", "prerelease": true, "draft": false, "assets": [
                {{ "name": "release.zip", "browser_download_url": "https://github.com/o/r/releases/download/1.0.268/release.zip",
                   "digest": "sha256:{}" }} ] }}]"#,
            "cd".repeat(32)
        );
        let f = MapFetcher::default()
            .with(
                "https://cfg.test/g.yaml",
                r#"
files:
  - from: github:o/r@latest/release.zip
    prerelease: true
    to: C:\app
    extract: true
  - from: github:o/r@latest/source
    prerelease: true
    to: C:\src
    extract: true
    strip: 1
"#,
            )
            .with("https://api.github.com/repos/o/r/releases?per_page=30", release)
            .with("https://github.com/o/r/archive/refs/tags/1.0.268.zip", "zip bytes");
        let dir = tempfile::tempdir().unwrap();
        let g = load_with(&f, "https://cfg.test/g.yaml", dir.path()).unwrap().file;

        assert_eq!(
            g.files[0].from.as_ref().unwrap().as_str(),
            "https://github.com/o/r/releases/download/1.0.268/release.zip"
        );
        assert_eq!(g.files[0].sha256.as_deref(), Some("cd".repeat(32).as_str()), "GitHub's digest pins it");
        assert_eq!(g.files[0].resolved, None, "so plan doesn't download it");
        assert_eq!(g.files[1].from.as_ref().unwrap().as_str(), "https://github.com/o/r/archive/refs/tags/1.0.268.zip");
        assert!(g.files[1].resolved.is_some(), "source zips have no digest and are resolved by content");
        assert_eq!((g.files[0].release.as_deref(), g.files[1].release.as_deref()), (Some("1.0.268"), Some("1.0.268")));
        assert_eq!(g.files[1].strip, 1);
        let requests = f.requests.lock().unwrap();
        assert_eq!(requests.iter().filter(|u| u.contains("api.github.com")).count(), 1);
        assert!(!requests.iter().any(|u| u.ends_with("/release.zip")), "the pinned asset wasn't downloaded");
    }

    #[test]
    fn rejects_misplaced_github_options() {
        let cases = [
            ("files: [{ from: https://x.test/a.zip, to: C:/a, prerelease: true }]", "only applies to github:"),
            (
                "files: [{ from: https://x.test/a.zip, to: C:/a, strip: 1 }]",
                "'strip' only applies with 'extract: true'",
            ),
            ("run: [{ script: 'github:o/r@latest/x.ps1' }]", "not 'run' scripts"),
        ];
        let dir = tempfile::tempdir().unwrap();
        for (yaml, want) in cases {
            let f = MapFetcher::default().with("https://cfg.test/g.yaml", yaml).with("https://x.test/a.zip", "z");
            let err = format!("{:#}", load_with(&f, "https://cfg.test/g.yaml", dir.path()).unwrap_err());
            assert!(err.contains(want), "{yaml}: expected '{want}' in: {err}");
        }
    }

    #[test]
    fn users_take_secrets_or_generate_and_refuse_literal_passwords() {
        let f = MapFetcher::default()
            .with(
                "https://cfg.test/g.yaml",
                "users:\n  - name: tester\n    password: { secret: TESTER_PASSWORD }\n    groups: [Remote Desktop Users]\n  - name: svc\n    password: generate\n  - name: bare",
            )
            .with("https://cfg.test/literal.yaml", "users: [{ name: a, password: hunter2 }]")
            .with("https://cfg.test/badname.yaml", "users: [{ name: 'a/b' }]")
            .with("https://cfg.test/typo.yaml", "users: [{ name: a, groop: [Users] }]");
        let dir = tempfile::tempdir().unwrap();
        let g = load_with(&f, "https://cfg.test/g.yaml", dir.path()).unwrap().file;
        assert_eq!(g.users[0].password, Password::Secret("TESTER_PASSWORD".into()));
        assert_eq!(g.users[0].groups, ["Remote Desktop Users"]);
        assert!(g.users[0].password_never_expires, "defaults to never expiring");
        assert_eq!((&g.users[1].password, &g.users[2].password), (&Password::Generate, &Password::Generate));
        assert_eq!(required_secrets(&g).into_iter().collect::<Vec<_>>(), ["TESTER_PASSWORD"]);

        let err = |u: &str| format!("{:#}", load_with(&f, u, dir.path()).unwrap_err());
        assert!(err("https://cfg.test/literal.yaml").contains("can't be written in a Groundhogfile"));
        assert!(err("https://cfg.test/badname.yaml").contains("not a valid local account name"));
        assert!(err("https://cfg.test/typo.yaml").contains("unknown field `groop`"));
    }

    #[test]
    fn features_and_capabilities_parse_with_defaults_and_checks() {
        let f = MapFetcher::default().with(
            "https://cfg.test/g.yaml",
            r#"
features:
  - Microsoft-Windows-Subsystem-Linux
  - name: NetFx3
    source: \\nas\media\sources\sxs
    limit-access: true
    timeout: 30m
  - name: SMB1Protocol
    state: disabled
    remove-payload: true
capabilities:
  - OpenSSH.Server
  - name: Language.Basic~~~de-DE~0.0.1.0
  - name: App.StepsRecorder
    state: removed
"#,
        );
        let dir = tempfile::tempdir().unwrap();
        let g = load_with(&f, "https://cfg.test/g.yaml", dir.path()).unwrap().file;
        assert!(g.features[0].enabled && g.features[0].all, "enabled with /All by default");
        assert_eq!(g.features[1].sources, [r"\\nas\media\sources\sxs"]);
        assert!(g.features[1].limit_access);
        assert_eq!(g.features[1].timeout_ms, Some(30 * 60 * 1000));
        assert!(!g.features[2].enabled && g.features[2].remove_payload && !g.features[2].all);
        assert_eq!(g.capabilities[0].name, "OpenSSH.Server~~~~0.0.1.0", "bare names get the usual version");
        assert_eq!(g.capabilities[1].name, "Language.Basic~~~de-DE~0.0.1.0", "full names are kept");
        assert!(!g.capabilities[2].present);

        let bad = [
            ("features: [{ name: X, remove-payload: true }]", "only applies with 'state: disabled'"),
            ("features: [{ name: X, state: disabled, source: C:/x }]", "only apply when enabling"),
            ("features: [{ name: X, source: 'ftp://x.test/fod.zip' }]", "must be http(s)"),
            ("features: [{ name: X, source: relative\\sxs }]", "only works when the Groundhogfile is a local file"),
            ("capabilities: [{ name: X, state: removed, limit-access: true }]", "only apply when adding"),
            ("features: [{ name: X, stat: enabled }]", "unknown field `stat`"),
        ];
        for (yaml, want) in bad {
            let f = MapFetcher::default().with("https://cfg.test/b.yaml", yaml);
            let err = format!("{:#}", load_with(&f, "https://cfg.test/b.yaml", dir.path()).unwrap_err());
            assert!(err.contains(want), "{yaml}: expected '{want}' in: {err}");
        }
    }

    #[test]
    fn new_sections_and_removal_parse() {
        let f = MapFetcher::default()
            .with(
                "https://cfg.test/g.yaml",
                r#"
users:
  - { name: old-account, state: absent }
certificates:
  - from: corp-root.cer
  - { thumbprint: "aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd", store: ca, state: absent }
defender-exclusions:
  - C:\src
  - process: devenv.exe
  - { extension: .obj, state: absent }
remove-apps: [Microsoft.BingNews, Clipchamp.*]
apps:
  - { id: Old.App, state: absent }
  - { id: Git.Git, upgrade: true }
files:
  - { to: C:\old\thing, state: absent }
env:
  OLD: { state: absent }
path:
  - { dir: C:\old\bin, state: absent }
registry:
  - { key: HKCU\Software\Old\Sub, state: absent }
  - { key: HKCU\Software\X, name: Gone, state: absent }
services:
  - { name: Spooler, startup: disabled, status: stopped }
firewall:
  - { name: Deskhand, port: 8791 }
  - { name: Web, port: [80, 443], profile: [domain, private], remote: LocalSubnet }
  - { name: Old rule, state: absent }
"#,
            )
            .with("https://cfg.test/corp-root.cer", "certificate bytes");
        let dir = tempfile::tempdir().unwrap();
        let g = load_with(&f, "https://cfg.test/g.yaml", dir.path()).unwrap().file;
        assert_eq!(g.users[0].state, Presence::Absent);
        assert_eq!(g.certificates[0].store, CertStore::Root);
        assert!(g.certificates[0].resolved.is_some(), "an unpinned certificate is hashed at load");
        assert_eq!(g.certificates[1].thumbprint.as_deref(), Some("AABBCCDDEEFF00112233445566778899AABBCCDD"));
        let kinds: Vec<ExclusionKind> = g.defender_exclusions.iter().map(|e| e.kind).collect();
        assert_eq!(kinds, [ExclusionKind::Path, ExclusionKind::Process, ExclusionKind::Extension]);
        assert_eq!(g.remove_apps, ["Microsoft.BingNews", "Clipchamp.*"]);
        assert!(matches!(&g.apps[0], App::Winget { state: Presence::Absent, .. }));
        assert!(matches!(&g.apps[1], App::Winget { upgrade: true, .. }));
        assert_eq!(g.files[0].state, Presence::Absent);
        assert_eq!(g.env["OLD"].state, Presence::Absent);
        assert_eq!(g.path[0].state, Presence::Absent);
        assert!(g.registry.iter().all(|r| r.state == Presence::Absent));
        assert_eq!(g.firewall[0].ports.as_deref(), Some("8791"));
        assert_eq!(
            (g.firewall[1].ports.as_deref(), g.firewall[1].profile.as_str()),
            (Some("80,443"), "domain,private")
        );
        assert_eq!(g.firewall[2].state, Presence::Absent);
        assert_eq!(g.services[0].startup, Some(crate::model::StartupType::Disabled));

        let dir = tempfile::tempdir().unwrap();
        for (bad, why) in [
            ("apps: [{ id: x, url: 'https://x.test/a.msi', state: absent }]", "only applies to winget apps"),
            ("apps: [{ id: x, version: '1.0', upgrade: true }]", "not both"),
            ("files: [{ to: C:\\x, content: y, state: absent }]", "only needs 'to'"),
            ("env: { A: { value: x, state: absent } }", "doesn't go with"),
            ("registry: [{ key: HKLM\\SOFTWARE, state: absent }]", "close to the root"),
            ("registry: [{ key: HKCU\\Software\\X, name: N }]", "needs a 'value'"),
            ("users: [{ name: a, groups: [Users], state: absent }]", "only needs 'name'"),
            ("certificates: [{ from: a.cer, scope: user }]", "use scope: machine"),
            ("certificates: [{ thumbprint: 'AABB' , state: absent }]", "40 hex"),
            ("certificates: [{ thumbprint: 'AABBCCDDEEFF00112233445566778899AABBCCDD' }]", "needs 'from'"),
            ("services: [{ name: X }]", "'startup', 'status' or both"),
            ("firewall: [{ name: X, port: 'eighty' }]", "ports look like"),
            ("firewall: [{ name: X, port: 80, protocol: any }]", "need protocol tcp or udp"),
            ("firewall: [{ name: X, port: 80, state: absent }]", "only needs 'name'"),
            ("firewall: [{ name: X, profile: work }]", "isn't any, domain"),
            ("defender-exclusions: [{ path: a, process: b }]", "one of 'path'"),
        ] {
            let f = MapFetcher::default().with("https://cfg.test/bad.yaml", bad);
            let err = format!("{:#}", load_with(&f, "https://cfg.test/bad.yaml", dir.path()).unwrap_err());
            assert!(err.contains(why), "{bad}: {err}");
        }
    }

    #[test]
    fn desktop_settings_parse_and_merge() {
        let f = MapFetcher::default()
            .with(
                "https://cfg.test/base.yaml",
                "desktop: { theme: light, wallpaper: lab.jpg, wallpaper-style: fit, background: '#203040' }",
            )
            .with("https://cfg.test/lab.jpg", "jpeg bytes")
            .with(
                "https://cfg.test/top.yaml",
                "extends: base.yaml\ndesktop: { theme: { windows: dark }, scope: [current-user, default-user] }",
            );
        let dir = tempfile::tempdir().unwrap();
        let g = load_with(&f, "https://cfg.test/top.yaml", dir.path()).unwrap().file;
        let w = g.wallpaper.unwrap();
        assert_eq!((w.style, w.background.as_deref()), (WallpaperStyle::Fit, Some("#203040")));
        assert!(w.resolved.is_some(), "the picture is hashed at load");
        let t = g.theme.unwrap();
        assert_eq!((t.apps, t.windows), (Some(ThemeMode::Light), Some(ThemeMode::Dark)), "merged setting by setting");
        assert_eq!(t.scope, [HiveScope::CurrentUser, HiveScope::DefaultUser]);

        let locks = MapFetcher::default()
            .with(
                "https://cfg.test/l.yaml",
                "desktop:\n  lock-screen: { image: lock.png, lock-after: 15m }\n  screen-saver: { timeout: 10m, secure: true, program: mystify }",
            )
            .with("https://cfg.test/lock.png", "png bytes");
        let g = load_with(&locks, "https://cfg.test/l.yaml", dir.path()).unwrap().file;
        let l = g.lock_screen.unwrap();
        assert_eq!((l.lock_after_secs, l.resolved.is_some()), (Some(900), true));
        let s = g.screen_saver.unwrap();
        assert_eq!((s.enabled, s.timeout_secs, s.secure), (true, Some(600), Some(true)));
        assert_eq!(s.program.as_deref(), Some(r"%SystemRoot%\System32\Mystify.scr"));
        let off =
            MapFetcher::default().with("https://cfg.test/o.yaml", "desktop: { screen-saver: { enabled: false } }");
        let s = load_with(&off, "https://cfg.test/o.yaml", dir.path()).unwrap().file.screen_saver.unwrap();
        assert_eq!((s.enabled, s.program), (false, None));

        let only_color = MapFetcher::default().with("https://cfg.test/c.yaml", "desktop: { background: 0a0b0c }");
        let g = load_with(&only_color, "https://cfg.test/c.yaml", dir.path()).unwrap().file;
        assert_eq!(g.wallpaper.unwrap().background.as_deref(), Some("#0A0B0C"));

        for (bad, why) in [
            ("desktop: { theme: purple }", "isn't dark or light"),
            ("desktop: { background: red }", "should look like #203040"),
            ("desktop: { wallpaper-style: fill }", "needs a 'wallpaper'"),
            ("desktop: { wallpaper: notes.txt }", "should be a picture"),
            ("desktop: { wallpapr: a.jpg }", "unknown field"),
            ("desktop: { lock-screen: {} }", "'image', 'lock-after' or both"),
            ("desktop: { screen-saver: { enabled: false, timeout: 5m } }", "don't go with it"),
            ("desktop: { screen-saver: { program: aquarium } }", "isn't blank, bubbles"),
            ("desktop: { lock-screen: { image: lock.txt } }", "should be a picture"),
        ] {
            let f = MapFetcher::default().with("https://cfg.test/bad.yaml", bad);
            let err = format!("{:#}", load_with(&f, "https://cfg.test/bad.yaml", dir.path()).unwrap_err());
            assert!(err.contains(why), "{bad}: {err}");
        }
    }

    #[test]
    fn desktop_icons_and_shortcuts() {
        let f = MapFetcher::default().with(
            "https://cfg.test/i.yaml",
            "desktop:\n  icons:\n    this-pc: true\n    recycle-bin: false\n    add: [{ name: FindNeedle, target: 'C:\\FN\\FindNeedleUX.exe' }]\n    remove: [Microsoft Edge]\n  taskbar: { pins: [file-explorer] }",
        );
        let dir = tempfile::tempdir().unwrap();
        let g = load_with(&f, "https://cfg.test/i.yaml", dir.path()).unwrap().file;
        let icon = |guid: &str| {
            g.registry
                .iter()
                .find(|r| r.key == DESKTOP_ICONS_KEY && r.name.as_deref() == Some(guid))
                .unwrap()
                .data
                .clone()
        };
        assert_eq!(icon("{20D04FE0-3AEA-1069-A2D8-08002B30309D}"), RegistryData::Dword(0), "this PC shown");
        assert_eq!(icon("{645FF040-5081-101B-9F08-00AA002F954E}"), RegistryData::Dword(1), "recycle bin hidden");
        assert!(g.registry.iter().any(|r| r.name.as_deref() == Some("CreateDesktopShortcutDefault")));
        let states: Vec<(&str, bool)> =
            g.desktop_shortcuts.iter().map(|s| (s.name.as_str(), s.state.is_present())).collect();
        assert_eq!(states, [("FindNeedle", true), ("Microsoft Edge", false)]);

        // One restart of Explorer, after the desktop's other steps, to show pins and icons now.
        let plan = crate::engine::plan(&g);
        let titles: Vec<&str> = plan.iter().map(|s| s.title.as_str()).collect();
        let restart = titles.iter().position(|t| t.starts_with("restart Explorer")).expect("restart step");
        assert_eq!(titles.iter().filter(|t| t.starts_with("restart Explorer")).count(), 1);
        assert!(titles.iter().position(|t| t.starts_with("put a FindNeedle")).unwrap() < restart);

        let bad = MapFetcher::default().with("https://cfg.test/b.yaml", "desktop: { icons: { remove: ['a/b'] } }");
        assert!(load_with(&bad, "https://cfg.test/b.yaml", dir.path()).is_err());
    }

    #[test]
    fn language_settings_parse_merge_and_order() {
        let f = MapFetcher::default()
            .with(
                "https://cfg.test/base.yaml",
                "language:\n  input: [en-US, { language: ja-JP, keyboards: ['0411:{03B5835F-F03C-411B-9CE2-AA23E1171E36}{A76C93D9-5523-4E90-AAFA-4DB112F9AC76}'] }]\n  switch-hotkey: none\n  formats: en-GB\n  utf-8: true\n  welcome-screen: true\n  display: de-DE",
            )
            .with("https://cfg.test/top.yaml", "extends: base.yaml\nlanguage: { formats: fr-FR, location: fr }")
            .with("https://cfg.test/bad.yaml", "language: { display: \"en-US'; rm\" }");
        let dir = tempfile::tempdir().unwrap();

        let g = load_with(&f, "https://cfg.test/base.yaml", dir.path()).unwrap().file;
        let LanguageSetting::Input { languages } = &g.language[0] else { panic!("{:?}", g.language) };
        assert_eq!((languages[0].tag.as_str(), languages[1].keyboards.len()), ("en-US", 1));
        assert_eq!(g.language[1], LanguageSetting::Display { tag: "de-DE".into(), machine: true });
        assert_eq!(g.language.last(), Some(&LanguageSetting::CopyToSystem));
        let toggles: Vec<&str> =
            g.registry.iter().filter(|r| r.key.ends_with(r"\Toggle")).filter_map(|r| r.name.as_deref()).collect();
        assert_eq!(toggles, ["Hotkey", "Language Hotkey", "Layout Hotkey"]);

        // The top file replaces formats, adds a location, and the order holds.
        let top = load_with(&f, "https://cfg.test/top.yaml", dir.path()).unwrap().file;
        let orders: Vec<u8> = top.language.iter().map(LanguageSetting::order).collect();
        assert_eq!(orders, [0, 1, 2, 3, 5, 6]);
        assert!(top.language.contains(&LanguageSetting::Formats { tag: "fr-FR".into() }));
        assert!(top.language.contains(&LanguageSetting::Location { region: "FR".into() }));

        let err = load_with(&f, "https://cfg.test/bad.yaml", dir.path()).unwrap_err();
        assert!(format!("{err:#}").contains("isn't a language tag"), "{err:#}");
    }

    #[test]
    fn start_pins_come_from_a_layout_file() {
        let f = MapFetcher::default()
            .with("https://cfg.test/layouts/start2.bin", "layout bytes")
            .with(
                "https://cfg.test/base.yaml",
                "desktop:\n  start: { pins-from: layouts/start2.bin, recently-added: false }\n  scope: [current-user, default-user]",
            )
            .with("https://cfg.test/only.yaml", "desktop: { start: { pins-from: layouts/start2.bin } }")
            .with("https://cfg.test/top.yaml", "extends: base.yaml\ndesktop: { start: { recommendations: false } }");
        let dir = tempfile::tempdir().unwrap();

        let g = load_with(&f, "https://cfg.test/base.yaml", dir.path()).unwrap().file;
        let pins = g.start_pins.as_ref().unwrap();
        assert_eq!(pins.from.as_str(), "https://cfg.test/layouts/start2.bin");
        assert_eq!(pins.resolved.as_deref(), Some(crate::fetch::sha256_hex(b"layout bytes").as_str()));
        assert_eq!(pins.scope, vec![HiveScope::CurrentUser, HiveScope::DefaultUser]);
        let hide = g.registry.iter().find(|r| r.name.as_deref() == Some("ShowRecentList")).unwrap();
        assert_eq!((hide.key.as_str(), &hide.data), (START_KEY, &RegistryData::Dword(0)));

        // pins-from alone is enough, and an extending file keeps the base's pins.
        let only = load_with(&f, "https://cfg.test/only.yaml", dir.path()).unwrap().file;
        assert_eq!(only.start_pins.unwrap().scope, vec![HiveScope::CurrentUser]);
        let top = load_with(&f, "https://cfg.test/top.yaml", dir.path()).unwrap().file;
        assert!(top.start_pins.is_some());
        let plan = crate::engine::plan(&top);
        assert!(plan.iter().any(|s| s.title.starts_with("pin Start's apps as start2.bin has them @")), "{plan:#?}");
    }

    #[test]
    fn taskbar_and_start_become_registry_values_and_a_pin_list() {
        let f = MapFetcher::default().with(
            "https://cfg.test/t.yaml",
            "desktop:\n  taskbar:\n    alignment: left\n    search: icon\n    task-view: false\n    widgets: false\n    pins: [file-explorer, terminal, 'C:\\Tools\\R&D.lnk', 'Vendor.App_abc!App', MSEdge]\n  start: { recommendations: false, recommended-files: false }\n  scope: [current-user, default-user]",
        );
        let dir = tempfile::tempdir().unwrap();
        let g = load_with(&f, "https://cfg.test/t.yaml", dir.path()).unwrap().file;
        let value = |name: &str| g.registry.iter().find(|r| r.name.as_deref() == Some(name)).unwrap();
        assert_eq!(value("TaskbarAl").data, RegistryData::Dword(0));
        assert_eq!(value("TaskbarAl").scope, vec![HiveScope::CurrentUser, HiveScope::DefaultUser]);
        assert_eq!(value("SearchboxTaskbarMode").data, RegistryData::Dword(1));
        assert_eq!(value("ShowTaskViewButton").data, RegistryData::Dword(0));
        assert_eq!(value("AllowNewsAndInterests").data, RegistryData::Dword(0));
        assert!(value("AllowNewsAndInterests").key.starts_with("HKLM"));
        assert!(value("AllowNewsAndInterests").group_policy, "only Group Policy may write it");
        assert!(!value("TaskbarAl").group_policy);
        assert_eq!(value("Start_IrisRecommendations").data, RegistryData::Dword(0));
        assert_eq!(value("Start_TrackDocs").data, RegistryData::Dword(0));
        assert_eq!(value("StartLayoutFile").data, RegistryData::String(TASKBAR_POLICY_FILE.to_owned()));

        assert_eq!(g.files.len(), 1);
        assert_eq!(g.files[0].to, TASKBAR_POLICY_FILE);
        let xml = g.files[0].content.as_deref().unwrap();
        for item in [
            r#"<taskbar:DesktopApp DesktopApplicationID="Microsoft.Windows.Explorer"/>"#,
            r#"<taskbar:UWA AppUserModelID="Microsoft.WindowsTerminal_8wekyb3d8bbwe!App"/>"#,
            r#"<taskbar:DesktopApp DesktopApplicationLinkPath="C:\Tools\R&amp;D.lnk"/>"#,
            r#"<taskbar:UWA AppUserModelID="Vendor.App_abc!App"/>"#,
            r#"<taskbar:DesktopApp DesktopApplicationID="MSEdge"/>"#,
        ] {
            assert!(xml.contains(item), "{item} missing from\n{xml}");
        }
        assert!(xml.find("Explorer").unwrap() < xml.find("MSEdge").unwrap(), "pins keep their order");

        let f = MapFetcher::default().with(
            "https://cfg.test/n.yaml",
            "desktop: { taskbar: { pins: [notepad], pins-for: new-accounts, widgets: true } }",
        );
        let g = load_with(&f, "https://cfg.test/n.yaml", dir.path()).unwrap().file;
        assert_eq!(g.files[0].to, TASKBAR_DEFAULT_PROFILE_FILE);
        assert!(!g.registry.iter().any(|r| r.name.as_deref() == Some("StartLayoutFile")), "no policy for new accounts");
        assert_eq!(g.registry[0].state, Presence::Absent, "widgets: true lifts the policy");

        for (bad, why) in [
            ("desktop: { taskbar: {} }", "needs at least one"),
            ("desktop: { taskbar: { pins-for: everyone } }", "'pins-for' needs 'pins'"),
            ("desktop: { taskbar: { alignment: right } }", "unknown variant"),
            ("desktop: { taskbar: { pins: [''] } }", "a pin is empty"),
            ("desktop: { start: {} }", "needs at least one"),
            ("desktop: { start: { pins: [edge] } }", "unknown field"),
            (r"registry: [{ key: HKCU\X, name: N, value: 1, via: group-policy }]", "is for HKLM keys"),
            (r"registry: [{ key: HKLM\SOFTWARE\X\Y, state: absent, via: group-policy }]", "not whole keys"),
        ] {
            let f = MapFetcher::default().with("https://cfg.test/bad.yaml", bad);
            let err = format!("{:#}", load_with(&f, "https://cfg.test/bad.yaml", dir.path()).unwrap_err());
            assert!(err.contains(why), "{bad}: {err}");
        }
    }

    #[test]
    fn notifications_and_tray_parse_and_merge() {
        let f = MapFetcher::default()
            .with(
                "https://cfg.test/base.yaml",
                "desktop:\n  notifications: { enabled: true, sounds: false, lock-screen: false, do-not-disturb: true, apps: { MSTeams_8wekyb3d8bbwe!MSTeams: false } }\n  tray: { show: [OneDrive.exe, Teams.exe], touch-keyboard: false }\n  taskbar: { clock-seconds: true }",
            )
            .with(
                "https://cfg.test/top.yaml",
                "extends: base.yaml\ndesktop: { tray: { hide: [onedrive.exe] } }",
            );
        let dir = tempfile::tempdir().unwrap();
        let g = load_with(&f, "https://cfg.test/top.yaml", dir.path()).unwrap().file;
        let value = |name: &str| g.registry.iter().find(|r| r.name.as_deref() == Some(name)).unwrap();
        assert_eq!(value("ToastEnabled").data, RegistryData::Dword(1));
        assert_eq!(value("NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND").data, RegistryData::Dword(0));
        assert_eq!(value("NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK").data, RegistryData::Dword(0));
        assert_eq!(value("ShowSecondsInSystemClock").data, RegistryData::Dword(1));
        assert_eq!(value("TipbandDesiredVisibility").data, RegistryData::Dword(0));
        let teams = g.registry.iter().find(|r| r.key.ends_with(r"\MSTeams_8wekyb3d8bbwe!MSTeams")).unwrap();
        assert_eq!((teams.name.as_deref(), &teams.data), (Some("Enabled"), &RegistryData::Dword(0)));

        assert_eq!(g.do_not_disturb, Some(true));
        // Start's folders, byte for byte as Settings wrote Settings + Downloads.
        let places = MapFetcher::default()
            .with("https://cfg.test/p.yaml", "desktop: { start: { folders: [settings, Downloads] } }");
        let p = load_with(&places, "https://cfg.test/p.yaml", dir.path()).unwrap().file;
        let expected = parse_hex(
            "86 08 73 52 aa 51 43 42 9f 7b 27 76 58 46 59 d4 2f b3 67 e3 de 89 55 43 bf ce 61 f3 7b 18 a9 37",
        )
        .unwrap();
        assert_eq!(p.registry[0].data, RegistryData::Binary(expected));
        assert_eq!(p.registry[0].name.as_deref(), Some("VisiblePlaces"));
        let bad = MapFetcher::default().with("https://cfg.test/b.yaml", "desktop: { start: { folders: [games] } }");
        let err = format!("{:#}", load_with(&bad, "https://cfg.test/b.yaml", dir.path()).unwrap_err());
        assert!(err.contains("isn't one of Start's folders"), "{err}");
        let hex = MapFetcher::default()
            .with("https://cfg.test/h.yaml", r"registry: [{ key: HKCU\X, name: B, type: binary, value: '0a,0B ff' }]");
        let h = load_with(&hex, "https://cfg.test/h.yaml", dir.path()).unwrap().file;
        assert_eq!(h.registry[0].data, RegistryData::Binary(vec![0x0a, 0x0b, 0xff]));
        assert!(!g.registry.iter().any(|r| r.key.contains("CloudStore")), "not a plain registry value");

        // The later file's hide replaces the base's show for the same program.
        assert_eq!(
            g.tray_icons,
            vec![
                TrayIcon { program: "Teams.exe".into(), shown: true },
                TrayIcon { program: "onedrive.exe".into(), shown: false },
            ]
        );

        for (bad, why) in [
            ("desktop: { notifications: {} }", "needs at least one"),
            (r"desktop: { notifications: { apps: { 'C:\x.exe': false } } }", "isn't an app id"),
            ("desktop: { tray: {} }", "needs at least one"),
            ("desktop: { tray: { show: [a.exe], hide: [A.EXE] } }", "listed twice"),
            ("desktop: { tray: { always-show-all: true } }", "unknown field"),
        ] {
            let f = MapFetcher::default().with("https://cfg.test/bad.yaml", bad);
            let err = format!("{:#}", load_with(&f, "https://cfg.test/bad.yaml", dir.path()).unwrap_err());
            assert!(err.contains(why), "{bad}: {err}");
        }
    }

    #[test]
    fn uac_becomes_policy_values_and_merges_setting_by_setting() {
        let f = MapFetcher::default()
            .with("https://cfg.test/base.yaml", "uac: { level: always-notify, user-prompt: deny }")
            .with("https://cfg.test/top.yaml", "extends: base.yaml\nuac: { secure-desktop: false }");
        let dir = tempfile::tempdir().unwrap();
        let g = load_with(&f, "https://cfg.test/top.yaml", dir.path()).unwrap().file;
        let mut got: Vec<(String, RegistryData)> =
            g.registry.iter().map(|r| (r.name.clone().unwrap(), r.data.clone())).collect();
        got.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            got,
            vec![
                ("ConsentPromptBehaviorAdmin".to_owned(), RegistryData::Dword(2)),
                ("ConsentPromptBehaviorUser".to_owned(), RegistryData::Dword(0)),
                ("PromptOnSecureDesktop".to_owned(), RegistryData::Dword(0)),
            ]
        );
        assert!(g.registry.iter().all(|r| r.key == UAC_KEY));

        let f = MapFetcher::default()
            .with("https://cfg.test/u.yaml", "uac: { level: never-notify, admin-prompt: consent }");
        let g = load_with(&f, "https://cfg.test/u.yaml", dir.path()).unwrap().file;
        let admin = g.registry.iter().find(|r| r.name.as_deref() == Some("ConsentPromptBehaviorAdmin")).unwrap();
        assert_eq!(admin.data, RegistryData::Dword(4), "an explicit admin-prompt wins over the level");

        for (bad, why) in [
            ("uac: {}", "needs at least one"),
            ("uac: { level: off }", "unknown variant"),
            ("uac: { user-prompt: consent }", "unknown variant"),
        ] {
            let f = MapFetcher::default().with("https://cfg.test/bad.yaml", bad);
            let err = format!("{:#}", load_with(&f, "https://cfg.test/bad.yaml", dir.path()).unwrap_err());
            assert!(err.contains(why), "{bad}: {err}");
        }
    }

    #[test]
    fn conditions_and_variables_apply_across_extends() {
        let f = MapFetcher::default()
            .with(
                "https://cfg.test/lib.yaml",
                "vars: { port: '8791', name: lib }\nfirewall: [{ name: '${var:name}', port: '${var:port}' }]\npath: ['C:\\Kits\\${var:arch}']",
            )
            .with(
                "https://cfg.test/top.yaml",
                "extends: lib.yaml\nvars: { port: '9000' }\napps:\n  - always\n  - { id: arm-tool, when: { arch: arm64 } }\n  - { id: new-tool, when: { build: '>=26100' } }",
            );
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::default();
        let content = ContentStore { fetcher: &f, cache: &cache };
        let facts = Facts { arch: "x64".into(), build: 26100, os: "client".into() };
        let load = |vars: &[(&str, &str)]| {
            let loader = Loader::new(&content, dir.path().join("b"))
                .with_facts(facts.clone())
                .with_vars(vars.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect());
            loader.load(&source_ref("https://cfg.test/top.yaml", None, dir.path()).unwrap())
        };
        let g = load(&[]).unwrap().file;
        assert_eq!(g.firewall[0].ports.as_deref(), Some("9000"), "the top file overrides the library's default");
        assert_eq!(g.firewall[0].name, "lib");
        assert_eq!(g.path[0].dir, "C:\\Kits\\x64", "built-in arch");
        let ids: Vec<&str> = g.apps.iter().map(App::id).collect();
        assert_eq!(ids, ["always", "new-tool"], "the arm64-only app is dropped on x64");

        let g = load(&[("port", "1234")]).unwrap().file;
        assert_eq!(g.firewall[0].ports.as_deref(), Some("1234"), "--var wins over every file");
        let err = format!("{:#}", load(&[("arch", "arm64")]).unwrap_err());
        assert!(err.contains("built-in variable"), "{err}");

        let f = MapFetcher::default().with("https://cfg.test/u.yaml", "path: ['${var:nope}']");
        let content = ContentStore { fetcher: &f, cache: &cache };
        let loader = Loader::new(&content, dir.path().join("c"));
        let err = format!(
            "{:#}",
            loader.load(&source_ref("https://cfg.test/u.yaml", None, dir.path()).unwrap()).unwrap_err()
        );
        assert!(err.contains("unknown variable 'nope'"), "{err}");
    }

    #[test]
    fn secrets_can_be_referenced_in_content_env_registry_and_run() {
        let f = MapFetcher::default()
            .with(
                "https://cfg.test/g.yaml",
                r#"
users:
  - { name: tester, password: "${secret:TESTER_PW}" }
files:
  - to: C:\ProgramData\Deskhand\deskhand.json
    content: |
      { "token": "${secret:DESKHAND_TOKEN}", "port": 8791 }
env:
  OPENAI_API_KEY: ${secret:API_KEY}
registry:
  - { key: HKCU\Software\X, name: T, value: "${secret:DESKHAND_TOKEN}" }
run:
  - command: Set-Thing -Key ${secret:API_KEY}
  - { script: s.ps1, args: "-Key ${secret:SCRIPT_KEY}" }
"#,
            )
            .with("https://cfg.test/s.ps1", "param($Key)");
        let dir = tempfile::tempdir().unwrap();
        let g = load_with(&f, "https://cfg.test/g.yaml", dir.path()).unwrap().file;
        assert_eq!(g.users[0].password, Password::Secret("TESTER_PW".into()));
        assert!(g.files[0].from.is_none());
        assert!(g.files[0].content.as_deref().unwrap().contains("${secret:DESKHAND_TOKEN}"), "kept as written");
        assert_eq!(
            required_secrets(&g).into_iter().collect::<Vec<_>>(),
            ["API_KEY", "DESKHAND_TOKEN", "SCRIPT_KEY", "TESTER_PW"]
        );
    }

    #[test]
    fn secrets_are_refused_where_they_would_leak_or_be_ignored() {
        let dir = tempfile::tempdir().unwrap();
        for (bad, why) in [
            ("env: { K: { value: '${secret:A}', scope: machine } }", "every account can read"),
            ("apps: [{ id: x, args: '--key ${secret:A}' }]", "can't be used here"),
            ("files: [{ to: 'C:\\${secret:A}', content: x }]", "can't be used here"),
            ("path: ['C:\\${secret:A}']", "can't be used here"),
            ("run: [{ plugin: p.exe, with: { k: '${secret:A}' } }]", "can't be used here"),
            ("env: { K: '${secret:A-B}' }", "letters, digits and '_'"),
            ("files: [{ to: C:\\a, content: '${secret:A' }]", "unterminated"),
            ("files: [{ to: C:\\a }]", "needs 'from'"),
            ("files: [{ to: C:\\a, from: x, content: y }]", "not both"),
            ("files: [{ to: C:\\a, content: y, extract: true }]", "only applies to files with 'from'"),
            ("users: [{ name: a, password: hunter2 }]", "${secret:NAME}"),
        ] {
            let f = MapFetcher::default().with("https://cfg.test/bad.yaml", bad).with("https://cfg.test/p.exe", "x");
            let err = format!("{:#}", load_with(&f, "https://cfg.test/bad.yaml", dir.path()).unwrap_err());
            assert!(err.contains(why), "{bad}: {err}");
        }
    }

    #[test]
    fn env_and_path_take_a_machine_scope() {
        let f = MapFetcher::default().with(
            "https://cfg.test/g.yaml",
            r"
env:
  A: user-value
  B: { value: machine-value, scope: machine }
path:
  - C:\user\bin
  - { dir: 'C:\Program Files\Tool', scope: machine }
  - { dir: C:\user\bin, scope: machine }
",
        );
        let dir = tempfile::tempdir().unwrap();
        let g = load_with(&f, "https://cfg.test/g.yaml", dir.path()).unwrap().file;
        assert_eq!(g.env["A"], EnvVar { value: "user-value".into(), scope: EnvScope::User, state: Presence::Present });
        assert_eq!(
            g.env["B"],
            EnvVar { value: "machine-value".into(), scope: EnvScope::Machine, state: Presence::Present }
        );
        let scopes: Vec<_> = g.path.iter().map(|p| (p.dir.as_str(), p.scope)).collect();
        assert_eq!(
            scopes,
            [
                (r"C:\user\bin", EnvScope::User),
                (r"C:\Program Files\Tool", EnvScope::Machine),
                (r"C:\user\bin", EnvScope::Machine),
            ]
        );

        for (bad, why) in [
            ("env: { PATH: { value: 'C:\\x', scope: machine } }", "would replace it"),
            ("env: { A: { value: x, scop: machine } }", "unknown field `scop`"),
            ("path: [{ dir: x, scope: system }]", "unknown variant `system`"),
        ] {
            let f = MapFetcher::default().with("https://cfg.test/bad.yaml", bad);
            let err = format!("{:#}", load_with(&f, "https://cfg.test/bad.yaml", dir.path()).unwrap_err());
            assert!(err.contains(why), "{bad}: {err}");
        }
    }

    #[test]
    fn library_files_parse_and_extend_only_each_other() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../library");
        let mut count = 0;
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if !name.ends_with(".groundhog.yaml") {
                continue;
            }
            let url = library::expand(
                &Url::parse(&format!("groundhog:{}", name.trim_end_matches(".groundhog.yaml"))).unwrap(),
            )
            .unwrap_or_else(|e| panic!("{name}: {e:#}"));
            let mut raw =
                parse(&std::fs::read(&path).unwrap(), &url, &Facts::default().builtin_vars(), &Facts::default())
                    .unwrap_or_else(|e| panic!("{e:#}"));
            for base in std::mem::take(&mut raw.extends).into_vec() {
                let base = resolve_source_ref(&url, base).unwrap();
                let file = base.url.path_segments().unwrap().next_back().unwrap().to_owned();
                assert!(dir.join(&file).is_file(), "{name} extends {file}, which isn't in library/");
            }
            resolve(&url, raw).unwrap_or_else(|e| panic!("{name}: {e:#}"));
            count += 1;
        }
        assert!(count >= 5, "found only {count} library files");
    }

    #[test]
    fn library_names_load_from_the_library() {
        let v = env!("CARGO_PKG_VERSION");
        let lib = format!("https://raw.githubusercontent.com/guscatalano/Groundhog/v{v}/library");
        let f = MapFetcher::default()
            .with(
                &format!("{lib}/bundle.groundhog.yaml"),
                "extends: [part.groundhog.yaml]
apps: [b]",
            )
            .with(&format!("{lib}/part.groundhog.yaml"), "apps: [a]")
            .with(
                "https://cfg.test/top.yaml",
                "extends: groundhog:bundle
apps: [c]",
            );
        let dir = tempfile::tempdir().unwrap();
        let loaded = load_with(&f, "https://cfg.test/top.yaml", dir.path()).unwrap();
        let ids: Vec<_> = loaded
            .file
            .apps
            .iter()
            .map(|a| match a {
                App::Winget { id, .. } => id.as_str(),
                App::Url { .. } => "url",
            })
            .collect();
        assert_eq!(ids, ["a", "b", "c"]);
        let direct = load_with(&f, "groundhog:bundle", dir.path()).unwrap();
        assert_eq!(direct.file.apps.len(), 2);
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
    fn templates_sharing_a_base_run_its_steps_once() {
        let f = MapFetcher::default()
            .with(
                "https://cfg.test/core.yaml",
                "apps: [Git.Git]\nrun: [{ command: git config x }]\nverify: [{ file: C:\\git.exe }]",
            )
            .with("https://cfg.test/node.yaml", "extends: core.yaml\napps: [Node]\nrun: [{ command: npm i }]")
            .with("https://cfg.test/py.yaml", "extends: core.yaml\napps: [Python]\nrun: [{ command: pip i }]")
            .with("https://cfg.test/me.yaml", "extends: [node.yaml, py.yaml]");
        let dir = tempfile::tempdir().unwrap();
        let file = load_with(&f, "https://cfg.test/me.yaml", dir.path()).unwrap().file;
        let commands: Vec<&str> = file
            .run
            .iter()
            .map(|r| match r {
                RunAction::Command { command, .. } => command.as_str(),
                _ => "",
            })
            .collect();
        assert_eq!(commands, ["git config x", "npm i", "pip i"]);
        assert_eq!(file.verify.len(), 1);
        // The shared base's apps stay first.
        let apps: Vec<&str> = file.apps.iter().map(App::id).collect();
        assert_eq!(apps, ["Git.Git", "Node", "Python"]);
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
        assert!(loaded.file.files[0].from.as_ref().unwrap().as_str().ends_with("/src/config/a.txt"));

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
        let loader = Loader::new(&content, dir.path().join("bundles"));
        let r = SourceRef { url: Url::parse("https://github.test/devbox/main.zip").unwrap(), sha256: Some(sha) };
        let loaded = loader.load(&r).unwrap();
        assert_eq!(loaded.file.apps[0].id(), "git.git");
        assert_eq!(loaded.sources.len(), 2);

        let wrong = SourceRef { sha256: Some("0".repeat(64)), ..r };
        assert!(format!("{:#}", loader.load(&wrong).unwrap_err()).contains("hash mismatch"));
    }
}
