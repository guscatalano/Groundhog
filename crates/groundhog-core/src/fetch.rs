//! Fetching bytes from `file://`, `https://` (and, when allowed, `http://`) URLs.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

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

impl HeaderRule {
    /// `Name: value` (for `default_host`, the source's own host) or `host=Name: value`. The
    /// value may be `${secret:NAME}`, filled in by the agent from its secrets.
    pub fn parse(s: &str, default_host: Option<&str>) -> Result<HeaderRule> {
        let (left, value) = s.split_once(':').with_context(|| format!("header '{s}' must look like 'Name: value'"))?;
        let (host, name) = match left.split_once('=') {
            Some((host, name)) => (host.trim().to_owned(), name.trim().to_owned()),
            None => (
                default_host.context("a header without 'host=' needs an http(s) source to attach to")?.to_owned(),
                left.trim().to_owned(),
            ),
        };
        Ok(HeaderRule { host, name, value: value.trim().to_owned() })
    }
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
        if let Some(date) = resp.headers().get("date").and_then(|v| v.to_str().ok()) {
            note_server_date(host, date);
        }
        resp.body_mut()
            .with_config()
            .limit(4 * 1024 * 1024 * 1024)
            .read_to_vec()
            .with_context(|| format!("reading body of {url}"))
    }
}

/// How far ahead of this machine's clock a server's was, in seconds (negative: this machine
/// is ahead), and which server: taken from the first HTTP response with a `Date` header. Only
/// for a warning; a machine whose clock is hours off gets baffling TLS errors and timestamps.
pub fn observed_clock_skew() -> Option<(i64, String)> {
    CLOCK_SKEW.get().cloned()
}

static CLOCK_SKEW: OnceLock<(i64, String)> = OnceLock::new();

fn note_server_date(host: &str, value: &str) {
    let (Some(server), Ok(now)) = (parse_http_date(value), SystemTime::now().duration_since(UNIX_EPOCH)) else {
        return;
    };
    let _ = CLOCK_SKEW.set((server - now.as_secs() as i64, host.to_owned()));
}

/// Seconds since 1970 for an HTTP date in its standard form, `Thu, 01 Oct 2026 07:38:37 GMT`.
fn parse_http_date(s: &str) -> Option<i64> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    let [_, day, month, year, time, "GMT"] = parts.as_slice() else { return None };
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let month = MONTHS.iter().position(|m| m == month)? as i64 + 1;
    let (day, year): (i64, i64) = (day.parse().ok()?, year.parse().ok()?);
    let hms: Vec<i64> = time.split(':').map(|n| n.parse().ok()).collect::<Option<_>>()?;
    let [h, m, sec] = hms.as_slice() else { return None };
    // Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + m * 60 + sec)
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
    fn parses_http_dates() {
        // Checked against `[DateTimeOffset]::Parse(...).ToUnixTimeSeconds()`.
        assert_eq!(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(parse_http_date("Thu, 01 Oct 2026 07:38:37 GMT"), Some(1_790_840_317));
        assert_eq!(parse_http_date("Tue, 29 Feb 2028 23:59:59 GMT"), Some(1_835_481_599));
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"), Some(784_111_777));
        for bad in ["", "Thu, 01 Oct 2026 07:38:37 PST", "Thu, 01 Foo 2026 07:38:37 GMT", "Thu, 01 Oct 2026 07:38 GMT"]
        {
            assert_eq!(parse_http_date(bad), None, "{bad}");
        }
    }

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
