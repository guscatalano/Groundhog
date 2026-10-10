//! Where progress goes: the console, a status folder a host can watch, or an HTTP endpoint.

use std::collections::VecDeque;
use std::io::Write;
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use url::Url;

use crate::engine::{RunState, RunStatus, StepState, StepStatus, now, write_json_atomic};

pub trait Reporter {
    /// A line of detail: every step and what it did.
    fn log(&self, line: &str);
    /// A line a person should see however little they asked for: warnings, failures.
    fn note(&self, line: &str) {
        self.log(line);
    }
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
    /// Sent with every POST: the `headers` rules whose host is this URL's host.
    pub headers: Vec<(String, String)>,
}

impl Reporter for HttpReporter {
    fn log(&self, _: &str) {}
    fn status(&self, state: &RunState) {
        if let Ok(body) = serde_json::to_vec(state) {
            let mut request =
                crate::fetch::http_agent().post(self.url.as_str()).header("content-type", "application/json");
            for (name, value) in &self.headers {
                request = request.header(name.as_str(), value.as_str());
            }
            let _ = request.send(&body[..]);
        }
    }
}

#[derive(Default)]
pub struct MultiReporter(pub Vec<Box<dyn Reporter>>);

impl Reporter for MultiReporter {
    fn log(&self, line: &str) {
        self.0.iter().for_each(|r| r.log(line));
    }
    fn note(&self, line: &str) {
        self.0.iter().for_each(|r| r.note(line));
    }
    fn status(&self, state: &RunState) {
        self.0.iter().for_each(|r| r.status(state));
    }
}

/// Parses a `--report` argument: an `http(s)://` URL or a folder path. An HTTP sink sends the
/// `headers` rules for its host, the same rules that authenticate downloads from that host.
pub fn parse_report_sink(s: &str, headers: &[crate::fetch::HeaderRule]) -> Result<Box<dyn Reporter>> {
    if s.starts_with("http://") || s.starts_with("https://") {
        let url = Url::parse(s).with_context(|| format!("invalid report URL '{s}'"))?;
        let host = url.host_str().unwrap_or_default();
        let headers = headers
            .iter()
            .filter(|r| r.host.eq_ignore_ascii_case(host))
            .map(|r| (r.name.clone(), r.value.clone()))
            .collect();
        return Ok(Box::new(HttpReporter { url, headers }));
    }
    Ok(Box::new(FolderReporter { dir: PathBuf::from(s) }))
}

/// What a person at a console sees by default: a line for each part of the file (files,
/// settings, desktop, ...) as it finishes, the step in progress, and a summary. The detail
/// (`log`) goes only to the log file, or to the console with `--verbose`.
pub struct HumanReporter {
    out: Mutex<Box<dyn Write + Send>>,
    /// Redraw the step in progress in place (the output is a console, not a file or pipe).
    live: bool,
    color: bool,
    width: usize,
    /// Where the detail is, for when something fails.
    log_file: Option<PathBuf>,
    progress: Mutex<Progress>,
}

#[derive(Default)]
struct Progress {
    started: Option<Instant>,
    header: bool,
    /// Sections printed for good.
    printed: usize,
    /// When the section in progress started.
    section_started: Option<(usize, Instant)>,
    /// Characters of the in-progress line on screen, to clear it.
    live_len: usize,
    finished: bool,
    /// The step in progress, and the last lines of its output: shown if it fails.
    step: Option<String>,
    output: VecDeque<String>,
}

/// Width of the section names column.
const LABEL: usize = 17;
/// Output lines of a failed step to show.
const OUTPUT_TAIL: usize = 5;

impl HumanReporter {
    pub fn new(out: Box<dyn Write + Send>, live: bool, color: bool, width: usize, log_file: Option<PathBuf>) -> Self {
        Self { out: Mutex::new(out), live, color, width: width.max(40), log_file, progress: Mutex::default() }
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.color { format!("\x1b[{code}m{text}\x1b[0m") } else { text.to_owned() }
    }

    fn write(&self, p: &mut Progress, text: &str) {
        let mut out = self.out.lock().unwrap_or_else(|e| e.into_inner());
        if p.live_len > 0 {
            let _ = write!(out, "\r{}\r", " ".repeat(p.live_len));
            p.live_len = 0;
        }
        let _ = writeln!(out, "{text}");
        let _ = out.flush();
    }

    fn draw_live(&self, p: &mut Progress, text: &str) {
        let text: String = text.chars().take(self.width - 1).collect();
        let len = text.chars().count();
        let pad = " ".repeat(p.live_len.saturating_sub(len));
        let mut out = self.out.lock().unwrap_or_else(|e| e.into_inner());
        let _ = write!(out, "\r{}{pad}", self.paint("2", &text));
        let _ = out.flush();
        p.live_len = len;
    }

    fn section_line(&self, icon: &str, steps: &[StepState], took: Option<Duration>) -> String {
        let label = format!("{:<LABEL$}", label(&steps[0].section));
        let mut detail = summary(&steps[0].section, steps);
        if steps.iter().any(needs_restart) {
            detail.push_str(", restart needed");
        }
        let took =
            took.filter(|d| *d >= Duration::from_secs(1)).map(|d| self.paint("2", &elapsed(d))).unwrap_or_default();
        format!("  {icon} {label}{detail:<30}{took}").trim_end().to_owned()
    }
}

impl Reporter for HumanReporter {
    fn log(&self, line: &str) {
        // A step's own output comes indented under it.
        if let Some(output) = line.strip_prefix("    ") {
            let mut p = self.progress.lock().unwrap_or_else(|e| e.into_inner());
            if p.output.len() == OUTPUT_TAIL {
                p.output.pop_front();
            }
            p.output.push_back(output.trim_end().to_owned());
        }
    }

    fn note(&self, line: &str) {
        let mut p = self.progress.lock().unwrap_or_else(|e| e.into_inner());
        let line = if line.starts_with("warning:") {
            self.paint("33", line)
        } else if line.starts_with("failed:") || line.starts_with("error:") {
            self.paint("31", line)
        } else {
            line.to_owned()
        };
        self.write(&mut p, &line);
    }

    fn status(&self, state: &RunState) {
        let mut p = self.progress.lock().unwrap_or_else(|e| e.into_inner());
        if p.finished || state.steps.is_empty() {
            return;
        }
        let now = Instant::now();
        let started = *p.started.get_or_insert(now);
        if !p.header {
            p.header = true;
            let name = state.source.path_segments().and_then(|mut s| s.next_back()).filter(|s| !s.is_empty());
            let name = name.map_or_else(|| state.source.to_string(), str::to_owned);
            let count = self.paint("2", &format!("({} steps)", state.steps.len()));
            self.write(&mut p, &format!("\n  Applying {} {count}\n", self.paint("1", &name)));
        }

        let sections = sections(&state.steps);
        while let Some(range) = sections.get(p.printed) {
            let steps = &state.steps[range.clone()];
            if !steps.iter().all(|s| s.status == StepStatus::Done) {
                let begun = steps.iter().any(|s| s.status != StepStatus::Pending);
                if begun && p.section_started.is_none_or(|(i, _)| i != p.printed) {
                    p.section_started = Some((p.printed, now));
                }
                break;
            }
            let took = p.section_started.filter(|(i, _)| *i == p.printed).map(|(_, t)| now - t);
            let icon = if steps.iter().any(needs_restart) {
                self.paint("33", "\u{21bb}")
            } else {
                self.paint("32", "\u{2714}")
            };
            let line = self.section_line(&icon, steps, took);
            self.write(&mut p, &line);
            p.printed += 1;
        }

        if state.status == RunStatus::Running {
            if self.live
                && let Some(range) = sections.get(p.printed)
                && let Some(k) = state.steps[range.clone()].iter().position(|s| s.status == StepStatus::Running)
            {
                let step = &state.steps[range.start + k];
                let text =
                    format!("  \u{203a} {:<LABEL$}{}/{}  {}", label(&step.section), k + 1, range.len(), step.title);
                self.draw_live(&mut p, &text);
            }
            if let Some(step) = state.steps.iter().find(|s| s.status == StepStatus::Running)
                && p.step.as_deref() != Some(&step.id)
            {
                p.step = Some(step.id.clone());
                p.output.clear();
            }
            return;
        }

        p.finished = true;
        if let Some(range) = sections.get(p.printed) {
            let steps = &state.steps[range.clone()];
            if let Some(failed) = steps.iter().find(|s| s.status == StepStatus::Failed) {
                let line =
                    format!("  {} {:<LABEL$}{}", self.paint("31", "\u{2717}"), label(&failed.section), failed.title);
                self.write(&mut p, &line);
                let message = failed.message.as_deref().unwrap_or_default();
                let said = |l: &String| message.lines().any(|m| m.trim() == l.trim());
                let output: Vec<String> = p.output.iter().filter(|l| !said(l)).cloned().collect();
                for l in output {
                    self.write(&mut p, &format!("      {}", self.paint("2", &l)));
                }
                for l in message.lines() {
                    self.write(&mut p, &format!("      {}", self.paint("31", l)));
                }
            } else if steps.iter().any(|s| s.status != StepStatus::Pending) {
                let done = steps.iter().filter(|s| s.status == StepStatus::Done).count();
                let label = format!("{:<LABEL$}", label(&steps[0].section));
                let line =
                    format!("  {} {label}{done} of {} done, restart needed", self.paint("33", "\u{21bb}"), steps.len());
                self.write(&mut p, &line);
            }
        }

        let took = elapsed(now - started);
        let changed = state.steps.iter().filter(|s| s.changed).count();
        let unchanged = state.steps.len() - changed;
        let done = self.paint("32", "Done");
        let summary = match state.status {
            RunStatus::Succeeded if changed == 0 => {
                format!("{done} in {took}: nothing to change, it was all already set.")
            }
            RunStatus::Succeeded if unchanged == 0 => format!("{done} in {took}: {changed} changed."),
            RunStatus::Succeeded => format!("{done} in {took}: {changed} changed, {unchanged} already set."),
            RunStatus::RebootPending => {
                format!("{} after {took}: Windows needs a restart to go on.", self.paint("33", "Paused"))
            }
            _ => {
                let log = self.log_file.as_ref().map(|f| format!(" Details: {}", f.display())).unwrap_or_default();
                format!("{} after {took}.{log}", self.paint("31", "Failed"))
            }
        };
        self.write(&mut p, &format!("\n  {summary}\n"));
    }
}

fn needs_restart(step: &StepState) -> bool {
    matches!(step.message.as_deref(), Some(m) if m.contains("restart") || m.contains("reboot"))
}

/// The runs of consecutive steps from the same part of the file.
fn sections(steps: &[StepState]) -> Vec<Range<usize>> {
    let mut out: Vec<Range<usize>> = Vec::new();
    for (i, s) in steps.iter().enumerate() {
        match out.last_mut() {
            Some(r) if steps[r.start].section == s.section => r.end = i + 1,
            _ => out.push(i..i + 1),
        }
    }
    out
}

fn label(section: &str) -> &'static str {
    match section {
        "users" => "Accounts",
        "certificates" => "Certificates",
        "defender" => "Defender",
        "windows features" => "Windows features",
        "apps" => "Apps",
        "files" => "Files",
        "environment" => "Environment",
        "registry" => "Settings",
        "desktop" => "Desktop",
        "services" => "Services",
        "firewall" => "Firewall",
        "run" => "Commands",
        "verify" => "Checks",
        _ => "Steps",
    }
}

/// "2 installed, 1 already installed": what a finished section did, in its own words.
fn summary(section: &str, steps: &[StepState]) -> String {
    let n = steps.len();
    let changed = steps.iter().filter(|s| s.changed).count();
    let (did, already) = match section {
        "verify" => return format!("{n} passed"),
        "run" => ("ran", "already ran"),
        "apps" => ("installed", "already installed"),
        "files" => ("copied", "already there"),
        "users" => ("set up", "already set up"),
        _ => ("changed", "already set"),
    };
    match (changed, n - changed) {
        (c, 0) => format!("{c} {did}"),
        (0, u) => format!("{u} {already}"),
        (c, u) => format!("{c} {did}, {u} {already}"),
    }
}

fn elapsed(d: Duration) -> String {
    let secs = d.as_secs();
    match secs {
        0..10 => format!("{:.1}s", d.as_secs_f64()),
        10..60 => format!("{secs}s"),
        _ => format!("{}m {:02}s", secs / 60, secs % 60),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl Buf {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    fn step(section: &str, title: &str, status: StepStatus, changed: bool) -> StepState {
        StepState { id: title.into(), title: title.into(), section: section.into(), status, changed, message: None }
    }

    fn state(status: RunStatus, steps: Vec<StepState>) -> RunState {
        RunState {
            source: Url::parse("https://example.com/cfg/neon.groundhog.yaml").unwrap(),
            status,
            started: now(),
            updated: now(),
            message: None,
            reboots: 0,
            steps,
            sources: Vec::new(),
            agent: "0.0.0".into(),
        }
    }

    #[test]
    fn a_line_per_section_and_a_summary() {
        use StepStatus::*;
        let buf = Buf::default();
        let r = HumanReporter::new(Box::new(buf.clone()), false, false, 100, None);
        r.log("[1/5] set HKCU\\Something");
        r.status(&state(
            RunStatus::Running,
            vec![
                step("files", "copy a", Done, true),
                step("files", "copy b", Running, false),
                step("registry", "set x", Pending, false),
                step("registry", "set y", Pending, false),
                step("verify", "verify a", Pending, false),
            ],
        ));
        r.note("warning: careful");
        r.status(&state(
            RunStatus::Succeeded,
            vec![
                step("files", "copy a", Done, true),
                step("files", "copy b", Done, false),
                step("registry", "set x", Done, true),
                step("registry", "set y", Done, true),
                step("verify", "verify a", Done, true),
            ],
        ));
        let out = buf.text();
        let lines: Vec<&str> = out.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines[0], "  Applying neon.groundhog.yaml (5 steps)");
        assert_eq!(lines[1], "warning: careful");
        assert_eq!(lines[2], "  \u{2714} Files            1 copied, 1 already there");
        assert_eq!(lines[3], "  \u{2714} Settings         2 changed");
        assert_eq!(lines[4], "  \u{2714} Checks           1 passed");
        assert!(
            lines[5].starts_with("  Done in ") && lines[5].ends_with(": 4 changed, 1 already set."),
            "{}",
            lines[5]
        );
        assert_eq!(lines.len(), 6);
    }

    #[test]
    fn a_failure_shows_the_step_and_its_error() {
        let buf = Buf::default();
        let r = HumanReporter::new(Box::new(buf.clone()), false, false, 100, Some(PathBuf::from(r"C:\gh\agent.log")));
        let git = step("apps", "install Git.Git (winget)", StepStatus::Done, true);
        let mut foo = step("apps", "install Foo.Bar (winget)", StepStatus::Running, false);
        r.status(&state(RunStatus::Running, vec![git.clone(), foo.clone()]));
        for l in [
            "[2/2] install Foo.Bar (winget)",
            "    a",
            "    b",
            "    c",
            "    d",
            "    e",
            "    f",
            "    winget exited with 1",
        ] {
            r.log(l);
        }
        foo.status = StepStatus::Failed;
        foo.message = Some("winget exited with 1\nno package found".into());
        r.status(&state(RunStatus::Failed, vec![git, foo]));
        let out = buf.text();
        assert!(out.contains("  \u{2717} Apps             install Foo.Bar (winget)\n"), "{out}");
        // The last of its output (but not what the error already says), then the error.
        assert!(
            out.contains("\n      c\n      d\n      e\n      f\n      winget exited with 1\n      no package found\n"),
            "{out}"
        );
        assert!(out.contains("Failed after ") && out.contains(r"Details: C:\gh\agent.log"), "{out}");
    }

    #[test]
    fn a_restart_pauses_the_run() {
        use StepStatus::*;
        let buf = Buf::default();
        let r = HumanReporter::new(Box::new(buf.clone()), false, false, 100, None);
        let mut wsl = step("windows features", "enable WSL", Done, true);
        wsl.message = Some("reboot required".into());
        r.status(&state(RunStatus::RebootPending, vec![wsl, step("windows features", "enable VMP", Pending, false)]));
        let out = buf.text();
        assert!(out.contains("  \u{21bb} Windows features 1 of 2 done, restart needed\n"), "{out}");
        assert!(out.contains("Paused after "), "{out}");
    }
}
