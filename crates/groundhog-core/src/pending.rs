//! The bootstrap file a host drops into a templated VM.
//!
//! A template has the agent installed with a logon task running `groundhog-agent run-pending`.
//! That command does nothing unless this file exists, so a host provider only has to write it
//! (through Hyper-V PowerShell Direct, the QEMU guest agent, a mapped folder, ...) and log on.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::fetch::HeaderRule;

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Pending {
    /// Path, URL or zip bundle, exactly as `groundhog-agent apply` takes it.
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cache: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub report: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<HeaderRule>,
    #[serde(default = "yes")]
    pub allow_reboot: bool,
    #[serde(default)]
    pub allow_http: bool,
    /// How the agent keeps itself current before applying: `latest` (the default here, since a
    /// template's agent is otherwise frozen at bake time), `off`, or a version to pin to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_update: Option<String>,
    /// Where new agents come from: an `agent.json` manifest, or a folder, share or URL holding
    /// one. Default: GitHub releases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_update_from: Option<String>,
    /// Values for the secrets a Groundhogfile names (`password: { secret: NAME }`). The agent
    /// removes them from this file as soon as it reads it.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub secrets: std::collections::BTreeMap<String, String>,
    /// Values for `${var:NAME}`, overriding the Groundhogfile's own (per-machine values such
    /// as a name or a port).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub vars: std::collections::BTreeMap<String, String>,
}

fn yes() -> bool {
    true
}

/// `%ProgramData%\groundhog`, the agent's default home for state and the pending file.
pub fn default_home() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("groundhog")
}

pub const PENDING_FILE: &str = "pending.json";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_pending_file_defaults() {
        let p: Pending = serde_json::from_str(r#"{ "source": "https://cfg.test/dev.yaml" }"#).unwrap();
        assert!(p.allow_reboot);
        assert!(p.cache.is_empty());
    }
}
