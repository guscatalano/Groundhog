//! Run-time secrets (passwords a Groundhogfile refers to by name).
//!
//! They arrive in `pending.json` (from the host), in `GROUNDHOG_SECRET_<NAME>` environment
//! variables, or in a `--secrets-file`. They must never sit on disk in plain text, so:
//! - the agent removes them from `pending.json` as soon as it reads it, and
//! - keeps them DPAPI-encrypted (for this user only) in `<home>\secrets.bin` while a run is
//!   paused for a restart, deleting that file once the run finishes either way.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use groundhog_win::dpapi;

pub type Secrets = BTreeMap<String, String>;

const STORE: &str = "secrets.bin";
const ENV_PREFIX: &str = "GROUNDHOG_SECRET_";

fn store(home: &Path) -> PathBuf {
    home.join(STORE)
}

pub fn load_store(home: &Path) -> Result<Secrets> {
    let path = store(home);
    let Ok(sealed) = std::fs::read(&path) else { return Ok(Secrets::new()) };
    let plain = dpapi::unprotect(&sealed).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&plain).context("secrets store is corrupt")
}

pub fn save_store(home: &Path, secrets: &Secrets) -> Result<()> {
    if secrets.is_empty() {
        return delete_store(home);
    }
    std::fs::create_dir_all(home)?;
    let sealed = dpapi::protect(&serde_json::to_vec(secrets)?)?;
    std::fs::write(store(home), sealed).context("saving secrets")
}

pub fn delete_store(home: &Path) -> Result<()> {
    match std::fs::remove_file(store(home)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e).context("removing the secrets store"),
        _ => Ok(()),
    }
}

/// Everything available to this run: what an earlier, restarted run saved, then environment
/// variables, then what came with the request (the newest source wins).
pub fn gather(home: &Path, supplied: &Secrets) -> Result<Secrets> {
    let mut all = load_store(home)?;
    for (key, value) in std::env::vars() {
        if let Some(name) = key.strip_prefix(ENV_PREFIX)
            && !name.is_empty()
        {
            all.insert(name.to_owned(), value);
        }
    }
    all.extend(supplied.iter().map(|(k, v)| (k.clone(), v.clone())));
    Ok(all)
}

const SALT: &str = "secret-salt.bin";

/// A salted hash of each secret's value, for step ids: a step that uses a secret reruns when
/// the value changes, and the id can't be used to test guesses at it. The salt is random,
/// made once per machine and kept DPAPI-encrypted, because the state files holding the ids
/// sit under ProgramData, which every user can read. If the salt can't be read (another
/// account, a damaged file), a new one is made and steps that use secrets run once more.
pub fn fingerprints(home: &Path, secrets: &Secrets) -> Result<BTreeMap<String, String>> {
    if secrets.is_empty() {
        return Ok(BTreeMap::new());
    }
    let path = home.join(SALT);
    let salt = match std::fs::read(&path).ok().and_then(|sealed| dpapi::unprotect(&sealed).ok()) {
        Some(salt) => salt,
        None => {
            let salt = groundhog_win::accounts::random_bytes(32)?;
            std::fs::create_dir_all(home)?;
            std::fs::write(&path, dpapi::protect(&salt)?).context("saving the secret salt")?;
            salt
        }
    };
    Ok(secrets
        .iter()
        .map(|(name, value)| {
            let mut input = salt.clone();
            input.extend_from_slice(name.as_bytes());
            input.push(0);
            input.extend_from_slice(value.as_bytes());
            (name.clone(), groundhog_core::fetch::sha256_hex(&input))
        })
        .collect())
}

/// Reads `{ "NAME": "value", ... }` from a file (for `apply --secrets-file`).
pub fn read_file(path: &Path) -> Result<Secrets> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("{} must be a JSON object of names to values", path.display()))
}

pub fn missing_hint(name: &str) -> String {
    format!(
        "secret {name} was not provided: add it to \"secrets\" in pending.json (groundhog pending --secret {name}), \
         set {ENV_PREFIX}{name}, or pass --secrets-file"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_store_round_trips_encrypted_and_goes_away() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = Secrets::from([("TESTER_PASSWORD".to_owned(), "correct horse".to_owned())]);
        save_store(dir.path(), &secrets).unwrap();
        let raw = std::fs::read(dir.path().join(STORE)).unwrap();
        assert!(!raw.windows(13).any(|w| w == b"correct horse"), "not plain text on disk");
        assert_eq!(load_store(dir.path()).unwrap(), secrets);
        delete_store(dir.path()).unwrap();
        assert!(load_store(dir.path()).unwrap().is_empty());
        delete_store(dir.path()).unwrap();
    }

    #[test]
    fn fingerprints_follow_the_value_and_hide_it() {
        let dir = tempfile::tempdir().unwrap();
        let one = Secrets::from([("TOKEN".to_owned(), "abc123".to_owned())]);
        let two = Secrets::from([("TOKEN".to_owned(), "rotated".to_owned())]);
        let a = fingerprints(dir.path(), &one).unwrap();
        assert_eq!(a, fingerprints(dir.path(), &one).unwrap(), "stable for the same value");
        assert_ne!(a["TOKEN"], fingerprints(dir.path(), &two).unwrap()["TOKEN"], "changes when rotated");
        assert_ne!(a["TOKEN"], groundhog_core::fetch::sha256_hex(b"abc123"), "salted");
        let other = tempfile::tempdir().unwrap();
        assert_ne!(a, fingerprints(other.path(), &one).unwrap(), "each machine has its own salt");
        let raw = std::fs::read(dir.path().join(SALT)).unwrap();
        assert!(raw.len() > 32, "stored encrypted, not as the bare 32 bytes");
    }

    #[test]
    fn newer_sources_win() {
        let dir = tempfile::tempdir().unwrap();
        save_store(
            dir.path(),
            &Secrets::from([("A".to_owned(), "stored".to_owned()), ("B".to_owned(), "stored".to_owned())]),
        )
        .unwrap();
        let all = gather(dir.path(), &Secrets::from([("B".to_owned(), "supplied".to_owned())])).unwrap();
        assert_eq!((all["A"].as_str(), all["B"].as_str()), ("stored", "supplied"));
    }
}
