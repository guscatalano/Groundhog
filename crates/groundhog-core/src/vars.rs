//! Conditions (`when:`) and variables (`${var:NAME}`).
//!
//! Both are handled on the document as written, before it's read as a Groundhogfile, so they
//! work on any entry of any section without every entry type knowing about them:
//! - a list entry (or an `env` value) with `when: { arch: arm64 }` is dropped unless the
//!   machine matches;
//! - `${var:NAME}` in any string is replaced by the variable's value.
//!
//! Most files use neither, and they skip this pass entirely, which keeps the exact line and
//! column in their error messages.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use serde_json::Value;

/// What a Groundhogfile can ask about the machine it's applied to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    /// `x64`, `arm64` or `x86`.
    pub arch: String,
    /// The Windows build number (`26100`), or 0 when unknown (planning on another machine).
    pub build: u32,
    /// `client` or `server`.
    pub os: String,
}

impl Default for Facts {
    fn default() -> Self {
        Self::of_this_process()
    }
}

impl Facts {
    /// What can be known without asking Windows: the architecture. The agent fills in the rest.
    pub fn of_this_process() -> Self {
        let arch = match std::env::consts::ARCH {
            "x86_64" => "x64",
            "aarch64" => "arm64",
            "x86" => "x86",
            other => other,
        };
        Facts { arch: arch.to_owned(), build: 0, os: "client".to_owned() }
    }

    /// The variables every file gets: `${var:arch}`, `${var:build}`, `${var:os}`.
    pub fn builtin_vars(&self) -> BTreeMap<String, String> {
        let mut vars = BTreeMap::from([("arch".to_owned(), self.arch.clone()), ("os".to_owned(), self.os.clone())]);
        if self.build > 0 {
            vars.insert("build".to_owned(), self.build.to_string());
        }
        vars
    }
}

/// Built-in variable names, which files and callers can't redefine.
pub const RESERVED: &[&str] = &["arch", "build", "os"];

pub fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Whether a document needs this pass at all.
pub fn needed(text: &str) -> bool {
    text.contains("when") || text.contains("${var:")
}

const OPEN: &str = "${var:";

/// Applies `when:` and `${var:...}` to a whole document. `vars` itself is left as written.
pub fn preprocess(doc: &mut Value, vars: &BTreeMap<String, String>, facts: &Facts) -> Result<()> {
    let Value::Object(top) = doc else { return Ok(()) };
    for (key, value) in top.iter_mut() {
        if key == "vars" {
            continue;
        }
        if key == "env"
            && let Value::Object(env) = value
        {
            // env is a map, so its entries are values rather than list items.
            let mut keep = serde_json::Map::new();
            for (name, mut v) in std::mem::take(env) {
                if take_when(&mut v, facts).with_context(|| format!("env {name}"))? {
                    walk(&mut v, vars, facts)?;
                    keep.insert(name, v);
                }
            }
            *env = keep;
            continue;
        }
        walk(value, vars, facts).with_context(|| format!("in {key}"))?;
    }
    Ok(())
}

fn walk(value: &mut Value, vars: &BTreeMap<String, String>, facts: &Facts) -> Result<()> {
    match value {
        Value::String(s) => *s = substitute(s, vars)?,
        Value::Array(items) => {
            let mut keep = Vec::with_capacity(items.len());
            for mut item in std::mem::take(items) {
                if take_when(&mut item, facts)? {
                    walk(&mut item, vars, facts)?;
                    keep.push(item);
                }
            }
            *items = keep;
        }
        Value::Object(map) => {
            for v in map.values_mut() {
                walk(v, vars, facts)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Removes a `when:` from an entry and says whether the entry applies to this machine.
fn take_when(item: &mut Value, facts: &Facts) -> Result<bool> {
    let Value::Object(map) = item else { return Ok(true) };
    match map.remove("when") {
        None => Ok(true),
        Some(when) => matches(&when, facts),
    }
}

fn matches(when: &Value, facts: &Facts) -> Result<bool> {
    let Value::Object(conditions) = when else {
        bail!("'when' is a map of conditions, like {{ arch: arm64 }} or {{ build: \">=26100\" }}");
    };
    for (key, wanted) in conditions {
        let ok = match key.as_str() {
            "arch" => one_of(wanted, &facts.arch, "arch")?,
            "os" => one_of(wanted, &facts.os, "os")?,
            "build" => {
                if facts.build == 0 {
                    bail!("'when: build' can't be checked: the Windows build of the target isn't known here");
                }
                let text = match wanted {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    _ => bail!("'when: build' is a number or a comparison like \">=26100\""),
                };
                build_matches(&text, facts.build)?
            }
            other => bail!("unknown condition '{other}' in 'when' (known: arch, build, os)"),
        };
        if !ok {
            return Ok(false);
        }
    }
    Ok(true)
}

fn one_of(wanted: &Value, actual: &str, what: &str) -> Result<bool> {
    let options: Vec<&str> = match wanted {
        Value::String(s) => vec![s.as_str()],
        Value::Array(list) => list.iter().filter_map(Value::as_str).collect(),
        _ => bail!("'when: {what}' is a value or a list of values"),
    };
    Ok(options.iter().any(|o| o.eq_ignore_ascii_case(actual)))
}

fn build_matches(text: &str, build: u32) -> Result<bool> {
    let text = text.trim();
    let (op, number) = [">=", "<=", ">", "<", "="]
        .iter()
        .find_map(|op| text.strip_prefix(op).map(|rest| (*op, rest)))
        .unwrap_or(("=", text));
    let n: u32 = number.trim().parse().with_context(|| format!("'when: build' value '{text}' isn't a build number"))?;
    Ok(match op {
        ">=" => build >= n,
        "<=" => build <= n,
        ">" => build > n,
        "<" => build < n,
        _ => build == n,
    })
}

/// Replaces `${var:NAME}`; `$${var:` writes a literal `${var:`.
pub fn substitute(s: &str, vars: &BTreeMap<String, String>) -> Result<String> {
    if !s.contains(OPEN) {
        return Ok(s.to_owned());
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find(OPEN) {
        if rest[..i].ends_with('$') {
            out.push_str(&rest[..i - 1]);
            out.push_str(OPEN);
            rest = &rest[i + OPEN.len()..];
            continue;
        }
        out.push_str(&rest[..i]);
        let after = &rest[i + OPEN.len()..];
        let end = after.find('}').with_context(|| format!("unterminated ${{var:...}} in '{s}'"))?;
        let name = &after[..end];
        let value = vars.get(name).with_context(|| {
            format!("unknown variable '{name}': define it under 'vars:', or pass it with --var {name}=... (built in: arch, build, os)")
        })?;
        out.push_str(value);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> Facts {
        Facts { arch: "arm64".into(), build: 26100, os: "client".into() }
    }

    #[test]
    fn when_drops_entries_for_other_machines() {
        let mut doc: Value = serde_json::from_str(
            r#"{
              "apps": ["always", {"id": "arm-only", "when": {"arch": "arm64"}}, {"id": "x64-only", "when": {"arch": "x64"}},
                       {"id": "new", "when": {"build": ">=26100", "os": ["client"]}}, {"id": "old", "when": {"build": "<22000"}}],
              "env": {"A": {"value": "1", "when": {"arch": "x64"}}, "B": "2"}
            }"#,
        )
        .unwrap();
        preprocess(&mut doc, &BTreeMap::new(), &facts()).unwrap();
        assert_eq!(doc["apps"], serde_json::json!(["always", {"id": "arm-only"}, {"id": "new"}]));
        assert_eq!(doc["env"], serde_json::json!({"B": "2"}));
    }

    #[test]
    fn variables_fill_strings_everywhere_but_vars() {
        let vars = BTreeMap::from([("port".to_owned(), "8791".to_owned()), ("arch".to_owned(), "arm64".to_owned())]);
        let mut doc: Value = serde_json::from_str(
            r#"{"vars": {"port": "8791"}, "path": ["C:\\Kits\\${var:arch}"], "run": ["echo ${var:port} $${var:port}"]}"#,
        )
        .unwrap();
        preprocess(&mut doc, &vars, &facts()).unwrap();
        assert_eq!(doc["path"][0], "C:\\Kits\\arm64");
        assert_eq!(doc["run"][0], "echo 8791 ${var:port}");
        let err = substitute("${var:nope}", &vars).unwrap_err().to_string();
        assert!(err.contains("unknown variable 'nope'"), "{err}");
    }

    #[test]
    fn bad_conditions_are_errors() {
        for bad in [r#"{"arch": 1}"#, r#"{"cpu": "x64"}"#, r#""x64""#, r#"{"build": "new"}"#] {
            let when: Value = serde_json::from_str(bad).unwrap();
            assert!(matches(&when, &facts()).is_err(), "{bad}");
        }
        let unknown_build = Facts { build: 0, ..facts() };
        assert!(matches(&serde_json::json!({"build": ">=1"}), &unknown_build).is_err());
    }
}
