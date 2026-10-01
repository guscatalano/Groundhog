//! `${secret:NAME}` references inside string values.
//!
//! A Groundhogfile never contains a secret, only a reference to one. The loaded model keeps
//! the reference text as written, so plans, titles, state files and cached content only ever
//! show `${secret:NAME}`; the agent puts the value in at the moment a step runs.
//!
//! `$${secret:` writes a literal `${secret:` that isn't a reference.

use std::collections::BTreeSet;

use anyhow::{Result, bail};

const OPEN: &str = "${secret:";
const ESCAPED: &str = "$${secret:";

/// Secret names: letters, digits and `_`, so they also work as environment variable names
/// (`GROUNDHOG_SECRET_<NAME>`).
pub fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// One piece of a string: literal text, or a reference by name.
#[derive(Debug, PartialEq, Eq)]
pub enum Part<'a> {
    Text(&'a str),
    Secret(&'a str),
}

/// Splits a string into text and references. Fails on a malformed reference rather than
/// passing it through, so a typo can't turn into a literal `${secret:...}` on the machine.
pub fn parse(s: &str) -> Result<Vec<Part<'_>>> {
    let mut parts = Vec::new();
    let mut rest = s;
    while let Some(i) = rest.find(OPEN) {
        if rest[..i].ends_with('$') {
            // `$${secret:` is the escape: emit `${secret:` as text (dropping one `$`).
            parts.push(Part::Text(&rest[..i - 1]));
            parts.push(Part::Text(OPEN));
            rest = &rest[i + OPEN.len()..];
            continue;
        }
        parts.push(Part::Text(&rest[..i]));
        let after = &rest[i + OPEN.len()..];
        let Some(end) = after.find('}') else {
            bail!("unterminated ${{secret:...}} in '{}'", shorten(s));
        };
        let name = &after[..end];
        if !valid_name(name) {
            bail!("'${{secret:{name}}}': secret names are letters, digits and '_'");
        }
        parts.push(Part::Secret(name));
        rest = &after[end + 1..];
    }
    parts.push(Part::Text(rest));
    parts.retain(|p| *p != Part::Text(""));
    Ok(parts)
}

/// The names a string refers to.
pub fn names(s: &str) -> Result<BTreeSet<String>> {
    Ok(parse(s)?
        .into_iter()
        .filter_map(|p| match p {
            Part::Secret(n) => Some(n.to_owned()),
            Part::Text(_) => None,
        })
        .collect())
}

/// Builds the string with each reference replaced by `value(name)`, and escapes undone.
pub fn substitute(s: &str, mut value: impl FnMut(&str) -> Result<String>) -> Result<String> {
    let mut out = String::with_capacity(s.len());
    for part in parse(s)? {
        match part {
            Part::Text(t) => out.push_str(t),
            Part::Secret(n) => out.push_str(&value(n)?),
        }
    }
    Ok(out)
}

/// Whether a string contains a reference (or an escape, which also needs `substitute`).
pub fn mentions(s: &str) -> bool {
    s.contains(OPEN) || s.contains(ESCAPED)
}

fn shorten(s: &str) -> String {
    let short: String = s.chars().take(60).collect();
    if short.len() < s.len() { format!("{short}…") } else { short }
}

/// Values shorter than this can't be scrubbed from logs without mangling them (think of a
/// secret "1"), so they're refused where a reference would put them into the machine.
pub const MIN_REDACTABLE: usize = 4;

/// Replaces known secret values with `***` in anything headed for a log, a status file or a
/// report sink.
#[derive(Debug, Default, Clone)]
pub struct Redactor {
    /// Longest first, so a value containing another is replaced whole.
    values: Vec<String>,
}

impl Redactor {
    pub fn new<'a>(values: impl IntoIterator<Item = &'a String>) -> Self {
        let mut values: Vec<String> = values
            .into_iter()
            .filter(|v| v.len() >= MIN_REDACTABLE)
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        values.sort_by_key(|v| std::cmp::Reverse(v.len()));
        Self { values }
    }

    pub fn scrub(&self, s: &str) -> String {
        let mut out = s.to_owned();
        for v in &self.values {
            if out.contains(v.as_str()) {
                out = out.replace(v.as_str(), "***");
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_references_and_keeps_escapes_literal() {
        assert_eq!(parse("a ${secret:TOKEN} b").unwrap(), [Part::Text("a "), Part::Secret("TOKEN"), Part::Text(" b")]);
        assert_eq!(names("${secret:A}${secret:B}${secret:A}").unwrap().into_iter().collect::<Vec<_>>(), ["A", "B"]);
        assert!(names("plain").unwrap().is_empty());
        assert!(names("$${secret:A}").unwrap().is_empty());
        let sub = |s| substitute(s, |n| Ok(format!("<{n}>"))).unwrap();
        assert_eq!(sub("x=${secret:A}; y=$${secret:B}"), "x=<A>; y=${secret:B}");
        assert_eq!(sub("$env:X and ${env:Y}"), "$env:X and ${env:Y}");
    }

    #[test]
    fn malformed_references_fail() {
        for bad in ["${secret:A", "${secret:}", "${secret:A-B}", "${secret:A B}"] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn redaction_replaces_values_longest_first_and_skips_tiny_ones() {
        let vals = ["abcd".to_owned(), "abcdef".to_owned(), "x".to_owned()];
        let r = Redactor::new(&vals);
        assert_eq!(r.scrub("token abcdef and abcd and x"), "token *** and *** and x");
        assert_eq!(Redactor::default().scrub("abcd"), "abcd");
    }
}
