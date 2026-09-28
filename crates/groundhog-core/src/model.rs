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
        #[serde(skip_serializing_if = "Option::is_none")]
        args: Option<String>,
        shell: Option<Shell>,
    },
    /// An external executable speaking the plugin protocol (see [`crate::plugin`]).
    Plugin {
        plugin: Url,
        #[serde(skip_serializing_if = "Option::is_none")]
        sha256: Option<String>,
        with: serde_json::Value,
    },
}

/// What the user writes. Only the loader uses these.
pub(crate) mod raw {
    use std::collections::BTreeMap;

    use serde::Deserialize;

    use super::{HiveScope, RegistryType, Shell};

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
