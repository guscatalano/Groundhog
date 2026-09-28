//! Content-addressed caches.
//!
//! Every source uses the same layout, `<root>/sha256/<hex>`, and every hit is re-verified
//! against its hash. A cache can therefore be a mapped folder, an SMB share or a dumb static
//! HTTP server, and never has to be trusted.

use std::path::PathBuf;

use anyhow::{Context, Result};
use url::Url;

use crate::fetch::{self, DefaultFetcher, Fetcher, sha256_hex};

pub trait CacheSource: Send + Sync {
    fn describe(&self) -> String;
    fn get(&self, sha256: &str) -> Option<Vec<u8>>;
    /// Stores content if the source is writable. Read-only sources do nothing.
    fn put(&self, _sha256: &str, _bytes: &[u8]) -> Result<()> {
        Ok(())
    }
}

/// A local folder or UNC share.
pub struct FolderCache {
    pub root: PathBuf,
}

impl FolderCache {
    fn entry(&self, sha256: &str) -> PathBuf {
        self.root.join("sha256").join(sha256)
    }
}

impl CacheSource for FolderCache {
    fn describe(&self) -> String {
        self.root.display().to_string()
    }

    fn get(&self, sha256: &str) -> Option<Vec<u8>> {
        std::fs::read(self.entry(sha256)).ok()
    }

    fn put(&self, sha256: &str, bytes: &[u8]) -> Result<()> {
        let path = self.entry(sha256);
        if path.exists() {
            return Ok(());
        }
        let dir = path.parent().expect("entry has a parent");
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        // Write to a temp name first so a concurrent reader never sees a partial file.
        let tmp = dir.join(format!("{sha256}.{}.tmp", std::process::id()));
        std::fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
        if std::fs::rename(&tmp, &path).is_err() {
            // Another writer won the race; their copy has the same content.
            let _ = std::fs::remove_file(&tmp);
        }
        Ok(())
    }
}

/// A read-only HTTP(S) server with the same layout.
pub struct HttpCache {
    pub base: Url,
    fetcher: DefaultFetcher,
}

impl HttpCache {
    pub fn new(mut base: Url) -> Self {
        if !base.path().ends_with('/') {
            base.set_path(&format!("{}/", base.path()));
        }
        // Content is verified by hash, so plain http on a lab network is fine here.
        Self { base, fetcher: DefaultFetcher { headers: Vec::new(), allow_http: true } }
    }
}

impl CacheSource for HttpCache {
    fn describe(&self) -> String {
        self.base.to_string()
    }

    fn get(&self, sha256: &str) -> Option<Vec<u8>> {
        let url = self.base.join(&format!("sha256/{sha256}")).ok()?;
        self.fetcher.fetch(&url).ok()
    }
}

/// Parses a `--cache` argument: an `http(s)://` URL or a folder path (local or UNC).
pub fn parse_cache_source(s: &str) -> Result<Box<dyn CacheSource>> {
    if s.starts_with("http://") || s.starts_with("https://") {
        let url = Url::parse(s).with_context(|| format!("invalid cache URL '{s}'"))?;
        return Ok(Box::new(HttpCache::new(url)));
    }
    if s.starts_with("file://") {
        let url = Url::parse(s).with_context(|| format!("invalid cache URL '{s}'"))?;
        return Ok(Box::new(FolderCache { root: fetch::file_url_to_path(&url)? }));
    }
    Ok(Box::new(FolderCache { root: PathBuf::from(s) }))
}

/// An ordered list of cache sources, tried first to last.
#[derive(Default)]
pub struct Cache {
    sources: Vec<Box<dyn CacheSource>>,
}

impl Cache {
    pub fn new(sources: Vec<Box<dyn CacheSource>>) -> Self {
        Self { sources }
    }

    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    pub fn describe(&self) -> Vec<String> {
        self.sources.iter().map(|s| s.describe()).collect()
    }

    /// Returns content whose hash matches, skipping any source with a corrupt entry.
    pub fn get(&self, sha256: &str) -> Option<Vec<u8>> {
        self.sources.iter().filter_map(|s| s.get(sha256)).find(|bytes| sha256_hex(bytes) == sha256)
    }

    /// Best-effort write-back to every writable source.
    pub fn put(&self, sha256: &str, bytes: &[u8]) {
        for s in &self.sources {
            let _ = s.put(sha256, bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folder_cache_round_trips_and_rejects_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(vec![Box::new(FolderCache { root: dir.path().to_path_buf() })]);
        let sha = sha256_hex(b"payload");

        assert!(cache.get(&sha).is_none());
        cache.put(&sha, b"payload");
        assert_eq!(cache.get(&sha).unwrap(), b"payload");

        std::fs::write(dir.path().join("sha256").join(&sha), b"tampered").unwrap();
        assert!(cache.get(&sha).is_none());
    }

    #[test]
    fn parses_cache_arguments() {
        assert_eq!(parse_cache_source("https://cache.lan/gh").unwrap().describe(), "https://cache.lan/gh/");
        assert_eq!(parse_cache_source(r"\\nas\gh").unwrap().describe(), r"\\nas\gh");
    }
}
