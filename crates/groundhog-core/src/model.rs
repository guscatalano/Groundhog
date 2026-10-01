//! The Groundhogfile model.
//!
//! There are two layers:
//! - `raw::*` mirrors what a user writes (YAML or JSON). Relative references are plain strings,
//!   and many entries accept either a short string form or a full object form.
//! - The public types below are the *resolved* form: every relative reference has been turned
//!   into an absolute URL against the file it came from, so a merged Groundhogfile no longer
//!   depends on where each piece was loaded from.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use url::Url;

pub const CURRENT_VERSION: u32 = 1;

/// A fully loaded and merged Groundhogfile.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Groundhogfile {
    pub users: Vec<User>,
    pub features: Vec<Feature>,
    pub capabilities: Vec<Capability>,
    pub apps: Vec<App>,
    pub files: Vec<FileCopy>,
    pub env: BTreeMap<String, EnvVar>,
    pub path: Vec<PathEntry>,
    pub registry: Vec<RegistryValue>,
    pub run: Vec<RunAction>,
    pub verify: Vec<Check>,
    /// The oldest agent that understands this file (the highest `agent:` across `extends`).
    #[serde(skip)]
    pub requires_agent: Option<crate::update::Version>,
}

/// A Windows optional feature (`NetFx3`, `Microsoft-Windows-Subsystem-Linux`, ...).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Feature {
    pub name: String,
    pub enabled: bool,
    /// Also enable the features it depends on (DISM's /All).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub all: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub remove_payload: bool,
    /// Folders or shares holding the payload (`sources\sxs` of matching install media).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
    /// Never ask Windows Update for the payload.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub limit_access: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

/// A Windows capability, also called a Feature on Demand (`OpenSSH.Server~~~~0.0.1.0`, ...).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Capability {
    pub name: String,
    pub present: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub limit_access: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

/// A local user account. Existing accounts are brought in line (groups, password expiry) but
/// their password is left alone unless `reset_password` is set.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct User {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    pub password: Password,
    /// Local groups the user is added to. Membership in other groups is left alone.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    pub password_never_expires: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub reset_password: bool,
}

/// Where a password comes from. Never the password itself: a Groundhogfile is shared, logged
/// and cached, so passwords are supplied at run time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Password {
    /// Random, known to nobody: for accounts no one types into.
    Generate,
    /// Supplied at run time under this name (pending.json `secrets`, or `GROUNDHOG_SECRET_<NAME>`).
    Secret(String),
}

/// A health check. Unlike every other step, checks run on every apply, after everything else,
/// and a failed check fails the apply.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "check", rename_all = "kebab-case")]
pub enum Check {
    /// A process with this image name (`.exe` optional) is running and, with `stable_for_ms`,
    /// keeps the same PID for that long.
    Process {
        name: String,
        stable_for_ms: u64,
        within_ms: u64,
    },
    Service {
        name: String,
        status: ServiceState,
        within_ms: u64,
    },
    /// Looks at events from `provider` in `log`. Text matching is a case-insensitive substring
    /// test against each event's rendered message. `must_contain` waits up to `within_ms` for
    /// the events to show up; a `must_not_contain` match fails at once.
    EventLog {
        log: String,
        provider: String,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        must_contain: Vec<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        must_not_contain: Vec<String>,
        since: EventsSince,
        within_ms: u64,
    },
    /// Something accepts TCP connections on `host:port`.
    Port {
        host: String,
        port: u16,
        within_ms: u64,
    },
    File {
        path: String,
        within_ms: u64,
    },
    /// Anything else: the check passes when the command exits 0.
    Command {
        command: String,
        shell: Shell,
        within_ms: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceState {
    Running,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EventsSince {
    /// Only events logged since this apply started, so old failures don't count.
    #[default]
    Apply,
    /// Any event still in the log.
    Any,
}

/// A reference to another resource, optionally pinned to a content hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRef {
    pub url: Url,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "source", rename_all = "kebab-case")]
pub enum App {
    /// Installed with `winget install --id <id> --exact`.
    Winget {
        id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        version: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        args: Option<String>,
        /// Kill the step (and everything it started) if it runs longer than this.
        #[serde(skip_serializing_if = "Option::is_none")]
        timeout_ms: Option<u64>,
    },
    /// An installer fetched from a URL (or found in a cache by hash) and run directly.
    Url {
        id: String,
        url: Url,
        #[serde(skip_serializing_if = "Option::is_none")]
        sha256: Option<String>,
        /// Content hash found at load time when `sha256` is not pinned. Part of the step's
        /// identity, so a new "latest" build makes the step run again.
        #[serde(skip_serializing_if = "Option::is_none")]
        resolved: Option<String>,
        /// The GitHub release a `github:` reference resolved to, for logs and step identity.
        #[serde(skip_serializing_if = "Option::is_none")]
        release: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        args: Option<String>,
        /// Kill the step (and everything it started) if it runs longer than this.
        #[serde(skip_serializing_if = "Option::is_none")]
        timeout_ms: Option<u64>,
    },
}

impl App {
    pub fn id(&self) -> &str {
        match self {
            App::Winget { id, .. } | App::Url { id, .. } => id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FileCopy {
    /// Where the file comes from. `None` for inline `content`. Serialized exactly as before
    /// inline content existed, so step ids of `from:` files don't change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<Url>,
    /// The file's text, written as UTF-8. May contain `${secret:NAME}` references, filled in
    /// only when the step runs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// Destination; may contain `~` and `%VARS%`, expanded on the target machine.
    pub to: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Content hash found at load time when `sha256` is not pinned. Part of the step's
    /// identity, so a new "latest" build makes the step run again.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved: Option<String>,
    /// `from` is a zip; unpack it into the folder `to`, replacing what was there.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub extract: bool,
    /// With `extract`: leading folders to drop from every path in the zip.
    #[serde(skip_serializing_if = "is_zero")]
    pub strip: u32,
    /// The GitHub release a `github:` reference resolved to, for logs and step identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release: Option<String>,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RegistryType {
    String,
    ExpandString,
    MultiString,
    Dword,
    Qword,
}

/// Where an environment variable or PATH entry is stored.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnvScope {
    /// `HKCU\Environment`: the account the agent runs as.
    #[default]
    User,
    /// The system environment: every account, including services and SYSTEM.
    Machine,
}

impl EnvScope {
    pub fn is_user(&self) -> bool {
        *self == EnvScope::User
    }
}

/// An environment variable's value. `scope` is left out of the serialized form when it's the
/// default, so step ids from before machine scope existed don't change.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EnvVar {
    pub value: String,
    #[serde(skip_serializing_if = "EnvScope::is_user")]
    pub scope: EnvScope,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PathEntry {
    pub dir: String,
    #[serde(skip_serializing_if = "EnvScope::is_user")]
    pub scope: EnvScope,
}

/// Which user hives a `HKCU\...` value is written to. Ignored for other roots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HiveScope {
    /// The user the agent runs as.
    CurrentUser,
    /// `C:\Users\Default\NTUSER.DAT`, so profiles created later get the value too.
    DefaultUser,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RegistryValue {
    /// Full key path, e.g. `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`.
    pub key: String,
    /// Value name; `None` means the key's default value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub kind: RegistryType,
    pub data: RegistryData,
    pub scope: Vec<HiveScope>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum RegistryData {
    String(String),
    MultiString(Vec<String>),
    Dword(u32),
    Qword(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Shell {
    /// Windows PowerShell 5.1, present on every Windows install.
    #[default]
    Powershell,
    Pwsh,
    Cmd,
    /// Run the file itself (for `.exe` scripts).
    Direct,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum RunAction {
    /// An inline command.
    Command {
        command: String,
        shell: Shell,
        /// Kill the step (and everything it started) if it runs longer than this.
        #[serde(skip_serializing_if = "Option::is_none")]
        timeout_ms: Option<u64>,
        /// Run on every apply, not only when something changed (a test run, say).
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        always: bool,
    },
    /// A script fetched relative to the Groundhogfile and run from a local copy.
    Script {
        script: Url,
        #[serde(skip_serializing_if = "Option::is_none")]
        sha256: Option<String>,
        /// Content hash found at load time when `sha256` is not pinned. Part of the step's
        /// identity, so a new "latest" build makes the step run again.
        #[serde(skip_serializing_if = "Option::is_none")]
        resolved: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        args: Option<String>,
        shell: Option<Shell>,
        /// Kill the step (and everything it started) if it runs longer than this.
        #[serde(skip_serializing_if = "Option::is_none")]
        timeout_ms: Option<u64>,
        /// Run on every apply, not only when something changed (a test run, say).
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        always: bool,
    },
    /// An external executable speaking the plugin protocol (see [`crate::plugin`]).
    Plugin {
        plugin: Url,
        #[serde(skip_serializing_if = "Option::is_none")]
        sha256: Option<String>,
        /// Content hash found at load time when `sha256` is not pinned. Part of the step's
        /// identity, so a new "latest" build makes the step run again.
        #[serde(skip_serializing_if = "Option::is_none")]
        resolved: Option<String>,
        with: serde_json::Value,
        /// Kill the step (and everything it started) if it runs longer than this.
        #[serde(skip_serializing_if = "Option::is_none")]
        timeout_ms: Option<u64>,
        /// Run on every apply, not only when something changed (a test run, say).
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        always: bool,
    },
}

impl RunAction {
    pub fn timeout_ms(&self) -> Option<u64> {
        match self {
            RunAction::Command { timeout_ms, .. }
            | RunAction::Script { timeout_ms, .. }
            | RunAction::Plugin { timeout_ms, .. } => *timeout_ms,
        }
    }

    pub fn always(&self) -> bool {
        match self {
            RunAction::Command { always, .. } | RunAction::Script { always, .. } | RunAction::Plugin { always, .. } => {
                *always
            }
        }
    }
}

/// What the user writes. Only the loader uses these.
pub(crate) mod raw {
    use std::collections::BTreeMap;

    use serde::Deserialize;

    use super::{EnvScope, EventsSince, HiveScope, RegistryType, ServiceState, Shell};

    #[derive(Debug, Default, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct File {
        pub version: Option<u32>,
        /// The oldest agent version that understands this file, as `">=0.5.0"`.
        pub agent: Option<String>,
        #[serde(default)]
        pub extends: OneOrMany<SourceRef>,
        #[serde(default)]
        pub apps: Vec<App>,
        #[serde(default)]
        pub files: Vec<FileCopy>,
        #[serde(default)]
        pub env: BTreeMap<String, StringOr<EnvFull>>,
        #[serde(default)]
        pub path: Vec<StringOr<PathFull>>,
        #[serde(default)]
        pub registry: Vec<RegistryValue>,
        #[serde(default)]
        pub run: Vec<RunAction>,
        #[serde(default)]
        pub verify: Vec<Check>,
        #[serde(default)]
        pub users: Vec<User>,
        #[serde(default)]
        pub features: Vec<StringOr<Feature>>,
        #[serde(default)]
        pub capabilities: Vec<StringOr<Capability>>,
    }

    #[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
    #[serde(rename_all = "kebab-case")]
    pub enum FeatureState {
        Enabled,
        Disabled,
    }

    #[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
    #[serde(rename_all = "kebab-case")]
    pub enum CapabilityState {
        Present,
        Removed,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "kebab-case")]
    pub struct Feature {
        pub name: String,
        pub state: Option<FeatureState>,
        pub all: Option<bool>,
        pub remove_payload: Option<bool>,
        pub source: Option<OneOrMany<String>>,
        pub limit_access: Option<bool>,
        pub timeout: Option<Duration>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "kebab-case")]
    pub struct Capability {
        pub name: String,
        pub state: Option<CapabilityState>,
        pub source: Option<OneOrMany<String>>,
        pub limit_access: Option<bool>,
        pub timeout: Option<Duration>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "kebab-case")]
    pub struct User {
        pub name: String,
        pub full_name: Option<String>,
        pub password: Option<StringOr<SecretRef>>,
        pub groups: Option<OneOrMany<String>>,
        pub password_never_expires: Option<bool>,
        #[serde(default)]
        pub reset_password: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SecretRef {
        pub secret: String,
    }

    /// One flat shape for every check kind, so a typo gets a precise "unknown field" error;
    /// the loader then checks that exactly one kind key is set and the options fit it.
    #[derive(Debug, Default, Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "kebab-case")]
    pub struct Check {
        pub process: Option<String>,
        pub service: Option<String>,
        pub eventlog: Option<EventLog>,
        pub port: Option<u16>,
        pub file: Option<String>,
        pub command: Option<String>,
        pub host: Option<String>,
        pub status: Option<ServiceState>,
        pub shell: Option<Shell>,
        pub stable_for: Option<Duration>,
        pub within: Option<Duration>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "kebab-case")]
    pub struct EventLog {
        pub provider: String,
        pub log: Option<String>,
        #[serde(default)]
        pub must_contain: Option<OneOrMany<String>>,
        #[serde(default)]
        pub must_not_contain: Option<OneOrMany<String>>,
        #[serde(default)]
        pub since: EventsSince,
    }

    /// `30s`, `2m`, `500ms`, or a bare number of seconds.
    #[derive(Debug, Deserialize)]
    #[serde(untagged)]
    pub enum Duration {
        Seconds(u64),
        Text(String),
    }

    #[derive(Debug, Deserialize)]
    #[serde(untagged)]
    pub enum OneOrMany<T> {
        One(T),
        Many(Vec<T>),
    }

    impl<T> Default for OneOrMany<T> {
        fn default() -> Self {
            OneOrMany::Many(Vec::new())
        }
    }

    impl<T> OneOrMany<T> {
        pub fn into_vec(self) -> Vec<T> {
            match self {
                OneOrMany::One(t) => vec![t],
                OneOrMany::Many(v) => v,
            }
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(untagged)]
    pub enum SourceRef {
        Short(String),
        Full { source: String, sha256: Option<String> },
    }

    /// `- git.git` is shorthand for a winget id.
    pub type App = StringOr<AppFull>;

    /// An entry written either as a bare string (the short form) or as a map. Unlike
    /// `#[serde(untagged)]`, a map that fails to parse keeps its own error ("unknown field
    /// `timout`") instead of a generic "did not match any variant".
    #[derive(Debug)]
    pub enum StringOr<T> {
        Short(String),
        Full(T),
    }

    impl<'de, T: Deserialize<'de>> Deserialize<'de> for StringOr<T> {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V<T>(std::marker::PhantomData<T>);
            impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for V<T> {
                type Value = StringOr<T>;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("a string or a map")
                }
                fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                    Ok(StringOr::Short(v.to_owned()))
                }
                fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                    T::deserialize(serde::de::value::MapAccessDeserializer::new(map)).map(StringOr::Full)
                }
            }
            d.deserialize_any(V(std::marker::PhantomData))
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct EnvFull {
        pub value: String,
        #[serde(default)]
        pub scope: EnvScope,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct PathFull {
        pub dir: String,
        #[serde(default)]
        pub scope: EnvScope,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    #[serde(rename_all = "kebab-case")]
    pub struct AppFull {
        pub id: String,
        pub version: Option<String>,
        pub url: Option<String>,
        pub sha256: Option<String>,
        pub args: Option<String>,
        pub timeout: Option<Duration>,
        #[serde(default)]
        pub prerelease: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct FileCopy {
        pub from: Option<String>,
        pub content: Option<String>,
        pub to: String,
        pub sha256: Option<String>,
        #[serde(default)]
        pub extract: bool,
        pub strip: Option<u32>,
        #[serde(default)]
        pub prerelease: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct RegistryValue {
        pub key: String,
        pub name: Option<String>,
        #[serde(rename = "type", default = "default_reg_type")]
        pub kind: RegistryType,
        pub value: Scalar,
        #[serde(default)]
        pub scope: Option<OneOrMany<HiveScope>>,
    }

    fn default_reg_type() -> RegistryType {
        RegistryType::String
    }

    #[derive(Debug, Deserialize)]
    #[serde(untagged)]
    pub enum Scalar {
        Int(u64),
        Str(String),
        List(Vec<String>),
    }

    /// `- winget upgrade --all` is shorthand for a PowerShell command.
    pub type RunAction = StringOr<RunFull>;

    /// One flat shape for every kind of `run` entry, so a typo (`timout:`) is an "unknown
    /// field" error instead of being silently ignored; the loader then checks that exactly one
    /// of `command`, `script` and `plugin` is set and that the options fit it.
    #[derive(Debug, Default, Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "kebab-case")]
    pub struct RunFull {
        pub command: Option<String>,
        pub script: Option<String>,
        pub plugin: Option<String>,
        pub shell: Option<Shell>,
        pub args: Option<String>,
        pub sha256: Option<String>,
        pub with: Option<serde_json::Value>,
        pub timeout: Option<Duration>,
        #[serde(default)]
        pub always: bool,
    }
}
