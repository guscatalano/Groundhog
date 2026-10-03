//! Resolving content: cache first (when the hash is known), then the network, with every
//! byte verified and written back to writable caches.

use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use url::Url;

use crate::cache::Cache;
use crate::fetch::{Fetcher, HashingWriter, file_url_to_path, normalize_sha256, sha256_file, verify_sha256};

pub struct Fetched {
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub from_cache: bool,
}

pub struct ContentStore<'a> {
    pub fetcher: &'a dyn Fetcher,
    pub cache: &'a Cache,
}

/// Content on disk: in a local cache, the original `file://` path, or a temporary file.
pub struct FetchedFile {
    pub path: PathBuf,
    pub sha256: String,
    pub from_cache: bool,
}

impl ContentStore<'_> {
    /// Like [`ContentStore::get`], but streamed to disk: for installers, archives and other
    /// files that can be gigabytes. Downloads are hashed as they arrive and land in the first
    /// local cache (the agent's own object store), so a later step reuses them.
    pub fn get_file(&self, url: &Url, sha256: Option<&str>) -> Result<FetchedFile> {
        let pinned = sha256.map(normalize_sha256).transpose()?;
        if let Some(pinned) = &pinned {
            if let Some(path) = self.cache.local_file(pinned) {
                return Ok(FetchedFile { path, sha256: pinned.clone(), from_cache: true });
            }
            let staging = staging_file(pinned)?;
            if self.cache.fetch_file(pinned, &staging) {
                let path = self.cache.put_file(pinned, &staging).unwrap_or(staging);
                return Ok(FetchedFile { path, sha256: pinned.clone(), from_cache: true });
            }
        }
        if url.scheme() == "file" {
            // Already local: hash it in place.
            let path = file_url_to_path(url)?;
            let actual = sha256_file(&path)?;
            check_pin(&actual, pinned.as_deref(), url)?;
            return Ok(FetchedFile { path, sha256: actual, from_cache: false });
        }
        let staging = staging_file(&crate::fetch::sha256_hex(url.as_str().as_bytes()))?;
        let file = std::fs::File::create(&staging).with_context(|| format!("creating {}", staging.display()))?;
        let mut out = HashingWriter::new(std::io::BufWriter::new(file));
        let result = self.fetcher.fetch_to(url, &mut out).and_then(|()| out.flush().context("writing download"));
        let actual = out.finish();
        if let Err(e) = result.and_then(|()| check_pin(&actual, pinned.as_deref(), url)) {
            let _ = std::fs::remove_file(&staging);
            return Err(e);
        }
        let path = self.cache.put_file(&actual, &staging).unwrap_or(staging.clone());
        if path != staging {
            let _ = std::fs::remove_file(&staging);
        }
        Ok(FetchedFile { path, sha256: actual, from_cache: false })
    }

    pub fn get(&self, url: &Url, sha256: Option<&str>) -> Result<Fetched> {
        if let Some(pinned) = sha256 {
            let pinned = normalize_sha256(pinned)?;
            if let Some(bytes) = self.cache.get(&pinned) {
                return Ok(Fetched { bytes, sha256: pinned, from_cache: true });
            }
        }
        let bytes = self.fetcher.fetch(url)?;
        let sha256 = verify_sha256(&bytes, sha256, url)?;
        // Local files are already local; only cache what came over the network.
        if url.scheme() != "file" {
            self.cache.put(&sha256, &bytes);
        }
        Ok(Fetched { bytes, sha256, from_cache: false })
    }
}

fn check_pin(actual: &str, pinned: Option<&str>, url: &Url) -> Result<()> {
    match pinned {
        Some(expected) if expected != actual => bail!("hash mismatch for {url}: expected {expected}, got {actual}"),
        _ => Ok(()),
    }
}

/// A temp file for a download in progress, unique to this process.
fn staging_file(key: &str) -> Result<PathBuf> {
    let dir = std::env::temp_dir().join("groundhog-downloads");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir.join(format!("{}.{}.part", &key[..16.min(key.len())], std::process::id())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::FolderCache;
    use crate::fetch::sha256_hex;
    use crate::fetch::testing::MapFetcher;

    #[test]
    fn files_stream_into_the_local_store_and_are_reused() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(vec![Box::new(FolderCache { root: dir.path().join("objects") })]);
        let fetcher = MapFetcher::default().with("https://dl.test/big.bin", "payload");
        let store = ContentStore { fetcher: &fetcher, cache: &cache };
        let url = Url::parse("https://dl.test/big.bin").unwrap();

        let first = store.get_file(&url, None).unwrap();
        assert_eq!(first.sha256, sha256_hex(b"payload"));
        assert!(first.path.starts_with(dir.path().join("objects")), "{}", first.path.display());
        assert_eq!(std::fs::read(&first.path).unwrap(), b"payload");

        let again = store.get_file(&url, Some(&first.sha256)).unwrap();
        assert!(again.from_cache);
        assert_eq!(fetcher.requests.lock().unwrap().len(), 1, "the second one came from the store");

        let wrong = "0".repeat(64);
        let fresh = Cache::default();
        let store = ContentStore { fetcher: &fetcher, cache: &fresh };
        let err = store.get_file(&url, Some(&wrong)).err().unwrap();
        assert!(err.to_string().contains("hash mismatch"), "{err}");
    }
}
