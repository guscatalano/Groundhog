//! The plugin protocol: how the agent talks to external step executables.
//!
//! The agent starts the plugin with no arguments, writes one [`PluginRequest`] as JSON to its
//! stdin and closes it. The plugin writes one [`PluginResponse`] as JSON to stdout and exits.
//! Anything on stderr is copied to the agent's log. A plugin can be written in any language;
//! this is how custom steps (late-bound COM, vendor tools, ...) extend the agent without
//! changing it.

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginRequest {
    pub protocol: u32,
    /// Always `"apply"` in protocol 1.
    pub action: String,
    /// The step's `with:` block, passed through untouched.
    pub with: serde_json::Value,
    /// A scratch directory the plugin may use.
    pub work_dir: String,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginResponse {
    pub ok: bool,
    #[serde(default)]
    pub changed: bool,
    #[serde(default)]
    pub reboot_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}
