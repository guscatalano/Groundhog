//! Where progress goes: the console, a status folder a host can watch, or an HTTP endpoint.

use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};
use url::Url;

use crate::engine::{RunState, now, write_json_atomic};

pub trait Reporter {
    fn log(&self, line: &str);
    fn status(&self, state: &RunState);
}

pub struct ConsoleReporter;

impl Reporter for ConsoleReporter {
    fn log(&self, line: &str) {
        println!("{line}");
    }
    fn status(&self, _: &RunState) {}
}

/// Writes `status.json` (replaced atomically) and appends to `agent.log`.
/// A host watching a mapped or shared folder needs nothing else.
pub struct FolderReporter {
    pub dir: PathBuf,
}

pub const STATUS_FILE: &str = "status.json";
pub const LOG_FILE: &str = "agent.log";

impl Reporter for FolderReporter {
    fn log(&self, line: &str) {
        let _ = std::fs::create_dir_all(&self.dir);
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(self.dir.join(LOG_FILE)) {
            let _ = writeln!(f, "{} {line}", now());
        }
    }
    fn status(&self, state: &RunState) {
        let _ = write_json_atomic(&self.dir.join(STATUS_FILE), state);
    }
}

/// POSTs the status JSON on every change. Best effort: a dead endpoint never fails a run.
pub struct HttpReporter {
    pub url: Url,
}

impl Reporter for HttpReporter {
    fn log(&self, _: &str) {}
    fn status(&self, state: &RunState) {
        if let Ok(body) = serde_json::to_vec(state) {
            let _ = crate::fetch::http_agent()
                .post(self.url.as_str())
                .header("content-type", "application/json")
                .send(&body[..]);
        }
    }
}

#[derive(Default)]
pub struct MultiReporter(pub Vec<Box<dyn Reporter>>);

impl Reporter for MultiReporter {
    fn log(&self, line: &str) {
        self.0.iter().for_each(|r| r.log(line));
    }
    fn status(&self, state: &RunState) {
        self.0.iter().for_each(|r| r.status(state));
    }
}

/// Parses a `--report` argument: an `http(s)://` URL or a folder path.
pub fn parse_report_sink(s: &str) -> Result<Box<dyn Reporter>> {
    if s.starts_with("http://") || s.starts_with("https://") {
        let url = Url::parse(s).with_context(|| format!("invalid report URL '{s}'"))?;
        return Ok(Box::new(HttpReporter { url }));
    }
    Ok(Box::new(FolderReporter { dir: PathBuf::from(s) }))
}
