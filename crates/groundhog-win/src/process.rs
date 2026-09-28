//! Running child processes with their output streamed line by line.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;

use anyhow::{Context, Result};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug, Default, Clone)]
pub struct Proc {
    pub program: PathBuf,
    pub args: Vec<String>,
    /// Appended verbatim after `args`, for installer switches and `cmd /c` lines that must
    /// not be re-quoted.
    pub raw_args: Option<String>,
    pub cwd: Option<PathBuf>,
    pub stdin: Option<Vec<u8>>,
    /// Return stdout instead of streaming it (plugins answer on stdout).
    pub capture_stdout: bool,
}

pub struct Output {
    pub code: i32,
    pub stdout: String,
}

impl Proc {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self { program: program.into(), ..Default::default() }
    }

    pub fn args<I: IntoIterator<Item = S>, S: Into<String>>(mut self, args: I) -> Self {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub fn raw(mut self, raw: Option<&str>) -> Self {
        self.raw_args = raw.filter(|s| !s.trim().is_empty()).map(str::to_owned);
        self
    }

    /// Runs to completion, calling `on_line` for each line of stderr (and of stdout unless
    /// captured). Returns the exit code.
    pub fn run(&self, on_line: &mut dyn FnMut(&str)) -> Result<Output> {
        let mut cmd = Command::new(&self.program);
        cmd.args(&self.args)
            .stdin(if self.stdin.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .creation_flags(CREATE_NO_WINDOW);
        if let Some(raw) = &self.raw_args {
            cmd.raw_arg(raw);
        }
        if let Some(cwd) = &self.cwd {
            cmd.current_dir(cwd);
        }
        let mut child = cmd.spawn().with_context(|| format!("starting {}", self.program.display()))?;

        if let (Some(input), Some(mut stdin)) = (self.stdin.clone(), child.stdin.take()) {
            std::thread::spawn(move || {
                let _ = stdin.write_all(&input);
            });
        }

        let (tx, rx) = mpsc::channel::<(bool, String)>();
        let pump = |stream: Box<dyn Read + Send>, is_stdout: bool, tx: mpsc::Sender<(bool, String)>| {
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream);
                let mut buf = Vec::new();
                while reader.read_until(b'\n', &mut buf).unwrap_or(0) > 0 {
                    let _ = tx.send((is_stdout, String::from_utf8_lossy(&buf).into_owned()));
                    buf.clear();
                }
            })
        };
        let t1 = pump(Box::new(child.stdout.take().expect("piped")), true, tx.clone());
        let t2 = pump(Box::new(child.stderr.take().expect("piped")), false, tx);

        let mut stdout = String::new();
        for (is_stdout, line) in rx {
            if is_stdout && self.capture_stdout {
                stdout.push_str(&line);
                continue;
            }
            if let Some(clean) = clean_line(&line) {
                on_line(clean);
            }
        }
        let _ = (t1.join(), t2.join());
        let status = child.wait().context("waiting for process")?;
        Ok(Output { code: status.code().unwrap_or(-1), stdout })
    }
}

/// Drops progress-bar noise: carriage-return redraws keep only their final state, and
/// spinner-only lines (`-`, `\`, `|`, `/`) and blank lines are skipped.
fn clean_line(line: &str) -> Option<&str> {
    let line = line.trim_end_matches(['\r', '\n']);
    let line = line.rsplit('\r').next().unwrap_or(line).trim_end();
    let t = line.trim();
    if t.is_empty() || (t.len() == 1 && "-\\|/".contains(t)) {
        return None;
    }
    Some(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streams_lines_and_exit_code() {
        let mut lines = Vec::new();
        let out = Proc::new("cmd.exe")
            .args(["/d", "/c"])
            .raw(Some("echo one & echo two 1>&2 & exit 3"))
            .run(&mut |l| lines.push(l.to_owned()))
            .unwrap();
        assert_eq!(out.code, 3);
        lines.sort();
        assert_eq!(lines, ["one", "two"]);
    }

    #[test]
    fn captures_stdout_and_feeds_stdin() {
        let proc =
            Proc { stdin: Some(b"hello".to_vec()), capture_stdout: true, ..Proc::new("findstr.exe").args(["."]) };
        let out = proc.run(&mut |_| {}).unwrap();
        assert_eq!(out.stdout.trim(), "hello");
    }

    #[test]
    fn cleans_progress_noise() {
        assert_eq!(clean_line("  |  \r\n"), None);
        assert_eq!(clean_line("10%\r50%\r100%\r\n"), Some("100%"));
    }
}
