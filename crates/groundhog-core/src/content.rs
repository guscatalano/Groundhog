//! Resolving content: cache first (when the hash is known), then the network, with every
//! byte verified and written back to writable caches.

use anyhow::Result;
use url::Url;

use crate::cache::Cache;
use crate::fetch::{Fetcher, normalize_sha256, verify_sha256};

pub struct Fetched {
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub from_cache: bool,
}

pub struct ContentStore<'a> {
    pub fetcher: &'a dyn Fetcher,
    pub cache: &'a Cache,
}

impl ContentStore<'_> {
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
