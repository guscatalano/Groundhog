//! The built-in library: `groundhog:NAME` names a ready-made Groundhogfile from this project's
//! `library/` folder, to apply as it is or to `extends`.
//!
//! By default it's the library as of this agent's own release, so a library file never needs a
//! newer agent than the one reading it. `groundhog:NAME@REF` picks a tag or branch instead.

use anyhow::{Result, bail};
use url::Url;

pub const SCHEME: &str = "groundhog";
const RAW: &str = "https://raw.githubusercontent.com/guscatalano/Groundhog";

pub fn is_library(url: &Url) -> bool {
    url.scheme() == SCHEME
}

/// `groundhog:NAME[@REF]` to the library file's URL.
pub fn expand(url: &Url) -> Result<Url> {
    let spec = url.path();
    let (name, reference) = match spec.split_once('@') {
        Some((name, reference)) => (name, reference.to_owned()),
        None => (spec, format!("v{}", env!("CARGO_PKG_VERSION"))),
    };
    let name_ok = !name.is_empty() && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !name_ok {
        bail!("'{url}': library names are lowercase letters, digits and '-', like groundhog:windows-internals");
    }
    let ref_ok = !reference.is_empty()
        && !reference.split('/').any(|s| s.is_empty() || s == "." || s == "..")
        && reference.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b));
    if !ref_ok {
        bail!("'{url}': '{reference}' isn't a tag or branch name");
    }
    Ok(Url::parse(&format!("{RAW}/{reference}/library/{name}.groundhog.yaml"))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exp(s: &str) -> Result<String> {
        expand(&Url::parse(s)?).map(String::from)
    }

    #[test]
    fn names_map_to_the_library_at_this_release() {
        let v = env!("CARGO_PKG_VERSION");
        assert_eq!(
            exp("groundhog:windows-internals").unwrap(),
            format!("{RAW}/v{v}/library/windows-internals.groundhog.yaml")
        );
        assert_eq!(exp("groundhog:sysinternals@main").unwrap(), format!("{RAW}/main/library/sysinternals.groundhog.yaml"));
        assert_eq!(exp("groundhog:windbg@v0.10.0").unwrap(), format!("{RAW}/v0.10.0/library/windbg.groundhog.yaml"));
    }

    #[test]
    fn rejects_odd_names_and_refs() {
        for bad in ["groundhog:", "groundhog:Sys", "groundhog:a/b", "groundhog:a@", "groundhog:a@../x", "groundhog:a@x y"] {
            assert!(exp(bad).is_err(), "{bad}");
        }
    }
}
