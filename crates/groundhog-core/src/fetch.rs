//! Fetching bytes from `file://`, `https://` (and, when allowed, `http://`) URLs.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ureq::tls::{RootCerts, TlsConfig, TlsProvider};
use url::Url;

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Normalizes a user-supplied hash (`sha256:` prefix and case are tolerated).
pub fn normalize_sha256(s: &str) -> Result<String> {
    let s = s.trim();
    let s = s.strip_prefix("sha256:").unwrap_or(s).to_ascii_lowercase();
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("invalid sha256 '{s}': expected 64 hex characters");
    }
    Ok(s)
}

pub fn verify_sha256(bytes: &[u8], expected: Option<&str>, what: &Url) -> Result<String> {
    let actual = sha256_hex(bytes);
    if let Some(expected) = expected {
        let expected = normalize_sha256(expected)?;
        if actual != expected {
            bail!("hash mismatch for {what}: expected {expected}, got {actual}");
        }
    }
    Ok(actual)
}

/// A header sent only to one host, so a token for a private server never leaks to
/// third-party URLs a Groundhogfile happens to reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderRule {
    pub host: String,
    pub name: String,
    pub value: String,
}

pub trait Fetcher: Send + Sync {
    fn fetch(&self, url: &Url) -> Result<Vec<u8>>;
}

#[derive(Debug, Default, Clone)]
pub struct DefaultFetcher {
    pub headers: Vec<HeaderRule>,
    /// Plain `http://` is refused unless this is set. Content fetched by hash (caches)
    /// is verified anyway, so caches get their own fetcher with this enabled.
    pub allow_http: bool,
}

impl Fetcher for DefaultFetcher {
    fn fetch(&self, url: &Url) -> Result<Vec<u8>> {
        match url.scheme() {
            "file" => {
                let path = file_url_to_path(url)?;
                std::fs::read(&path).with_context(|| format!("reading {}", path.display()))
            }
            "https" => self.http_get(url),
            "http" if self.allow_http => self.http_get(url),
            "http" => bail!("refusing plain http for {url} (use https, or allow insecure http)"),
            other => bail!("unsupported URL scheme '{other}' in {url}"),
        }
    }
}

impl DefaultFetcher {
    fn http_get(&self, url: &Url) -> Result<Vec<u8>> {
        let host = url.host_str().unwrap_or_default();
        let mut req = http_agent().get(url.as_str());
        for rule in self.headers.iter().filter(|r| r.host.eq_ignore_ascii_case(host)) {
            req = req.header(&rule.name, &rule.value);
        }
        let mut resp = req.call().with_context(|| format!("GET {url}"))?;
        resp.body_mut()
            .with_config()
            .limit(4 * 1024 * 1024 * 1024)
            .read_to_vec()
            .with_context(|| format!("reading body of {url}"))
    }
}

/// The shared HTTP client. TLS goes through Windows (schannel) and trusts the machine's
/// certificate store, so internal servers signed by an enterprise CA work like they do in a
/// browser on the same machine.
pub fn http_agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        let tls = TlsConfig::builder().provider(TlsProvider::NativeTls).root_certs(RootCerts::PlatformVerifier).build();
        ureq::Agent::config_builder().tls_config(tls).build().into()
    })
}

pub fn file_url_to_path(url: &Url) -> Result<PathBuf> {
    url.to_file_path().map_err(|_| anyhow!("not a local file URL: {url}"))
}

/// Turns what a user typed (a path, relative or absolute, or a URL) into a URL.
pub fn parse_location(input: &str, cwd: &Path) -> Result<Url> {
    let looks_like_url = (input.contains("://") && !is_windows_path(input))
        || input.starts_with(&format!("{}:", crate::library::SCHEME));
    if looks_like_url {
        return Url::parse(input).with_context(|| format!("invalid URL '{input}'"));
    }
    let path = Path::new(input);
    let abs = if path.is_absolute() { path.to_path_buf() } else { cwd.join(path) };
    let abs = std::path::absolute(&abs).unwrap_or(abs);
    Url::from_file_path(&abs).map_err(|_| anyhow!("cannot convert path '{}' to a URL", abs.display()))
}

fn is_windows_path(s: &str) -> bool {
    let b = s.as_bytes();
    (b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':') || s.starts_with(r"\\")
}

/// Last path segment of a URL, used to name downloaded files.
pub fn file_name(url: &Url) -> String {
    url.path_segments()
        .and_then(|mut s| s.next_back().map(str::to_owned))
        .filter(|s| !s.is_empty())
        .map(|s| percent_encoding::percent_decode_str(&s).decode_utf8_lossy().into_owned())
        .unwrap_or_else(|| "download".to_owned())
}

#[cfg(test)]
pub(crate) mod testing {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    /// Serves canned responses for `https://` URLs and reads `file://` from disk.
    #[derive(Default)]
    pub struct MapFetcher {
        pub responses: HashMap<String, Vec<u8>>,
        pub requests: Mutex<Vec<String>>,
    }

    impl MapFetcher {
        pub fn with(mut self, url: &str, body: impl Into<Vec<u8>>) -> Self {
            self.responses.insert(url.to_owned(), body.into());
            self
        }
    }

    impl Fetcher for MapFetcher {
        fn fetch(&self, url: &Url) -> Result<Vec<u8>> {
            self.requests.lock().unwrap().push(url.to_string());
            if url.scheme() == "file" {
                return DefaultFetcher::default().fetch(url);
            }
            self.responses.get(url.as_str()).cloned().ok_or_else(|| anyhow!("404 {url}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_paths_and_urls() {
        let cwd = Path::new(r"C:\work");
        assert_eq!(parse_location("https://x.test/a.yaml", cwd).unwrap().as_str(), "https://x.test/a.yaml");
        assert_eq!(parse_location("groundhog:windbg", cwd).unwrap().as_str(), "groundhog:windbg");
        assert_eq!(parse_location("dev.yaml", cwd).unwrap().as_str(), "file:///C:/work/dev.yaml");
        assert_eq!(parse_location(r"D:\b\c.yaml", cwd).unwrap().as_str(), "file:///D:/b/c.yaml");
        assert_eq!(parse_location(r"\\nas\share\x.yaml", cwd).unwrap().as_str(), "file://nas/share/x.yaml");
    }

    #[test]
    fn refuses_plain_http_by_default() {
        let err = DefaultFetcher::default().fetch(&Url::parse("http://x.test/a").unwrap()).unwrap_err();
        assert!(err.to_string().contains("refusing plain http"));
    }

    #[test]
    fn verifies_hashes() {
        let url = Url::parse("https://x.test/a").unwrap();
        let good = sha256_hex(b"hi");
        assert!(verify_sha256(b"hi", Some(&format!("sha256:{}", good.to_uppercase())), &url).is_ok());
        assert!(verify_sha256(b"bye", Some(&good), &url).is_err());
    }

    /// Hits the network; run with `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn fetches_over_https_with_the_windows_tls_stack() {
        let body = DefaultFetcher::default().fetch(&Url::parse("https://github.com/").unwrap()).unwrap();
        assert!(!body.is_empty());
    }

    #[test]
    fn names_files_from_urls() {
        assert_eq!(file_name(&Url::parse("https://x.test/dl/My%20Setup.msi?x=1").unwrap()), "My Setup.msi");
        assert_eq!(file_name(&Url::parse("https://x.test/").unwrap()), "download");
    }
}
