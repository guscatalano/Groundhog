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
    pub apps: Vec<App>,
    pub files: Vec<FileCopy>,
    pub env: BTreeMap<String, String>,
    pub path: Vec<String>,
    pub registry: Vec<RegistryValue>,
    pub run: Vec<RunAction>,
    pub verify: Vec<Check>,
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
        #[serde(skip_serializing_if = "Option::is_none")]
        args: Option<String>,
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
    pub from: Url,
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
    Command { command: String, shell: Shell },
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
    },
}

/// What the user writes. Only the loader uses these.
pub(crate) mod raw {
    use std::collections::BTreeMap;

    use serde::Deserialize;

    use super::{EventsSince, HiveScope, RegistryType, ServiceState, Shell};

    #[derive(Debug, Default, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct File {
        pub version: Option<u32>,
        #[serde(default)]
        pub extends: OneOrMany<SourceRef>,
        #[serde(default)]
        pub apps: Vec<App>,
        #[serde(default)]
        pub files: Vec<FileCopy>,
        #[serde(default)]
        pub env: BTreeMap<String, String>,
        #[serde(default)]
        pub path: Vec<String>,
        #[serde(default)]
        pub registry: Vec<RegistryValue>,
        #[serde(default)]
        pub run: Vec<RunAction>,
        #[serde(default)]
        pub verify: Vec<Check>,
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

    #[derive(Debug, Deserialize)]
    #[serde(untagged)]
    pub enum App {
        /// `- git.git` is shorthand for a winget id.
        Short(String),
        Full(AppFull),
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct AppFull {
        pub id: String,
        pub version: Option<String>,
        pub url: Option<String>,
        pub sha256: Option<String>,
        pub args: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct FileCopy {
        pub from: String,
        pub to: String,
        pub sha256: Option<String>,
        #[serde(default)]
        pub extract: bool,
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

    #[derive(Debug, Deserialize)]
    #[serde(untagged)]
    pub enum RunAction {
        /// `- winget upgrade --all` is shorthand for a PowerShell command.
        Short(String),
        Command {
            command: String,
            #[serde(default)]
            shell: Shell,
        },
        Script {
            script: String,
            sha256: Option<String>,
            args: Option<String>,
            shell: Option<Shell>,
        },
        Plugin {
            plugin: String,
            sha256: Option<String>,
            #[serde(default)]
            with: serde_json::Value,
        },
    }
}
