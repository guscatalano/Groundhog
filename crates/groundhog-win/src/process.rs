//! Running child processes with their output streamed line by line.

use std::collections::VecDeque;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation, SetInformationJobObject,
    TerminateJobObject,
};

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
    /// Kill the process, and every process it started, if it runs longer than this.
    pub timeout: Option<Duration>,
}

#[derive(Debug)]
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

    pub fn timeout_ms(mut self, ms: Option<u64>) -> Self {
        self.timeout = ms.map(Duration::from_millis);
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
        // With a timeout, the process runs in a job, so a timeout ends everything it started.
        // Killing only the process isn't enough: an installer's children keep its output
        // pipes open, and we would wait on them forever.
        let job = match self.timeout {
            Some(_) => Some(Job::containing(&child)?),
            None => None,
        };

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
        let mut recent: VecDeque<String> = VecDeque::new();
        let mut deadline = self.timeout.map(|t| Instant::now() + t);
        let mut timed_out = false;
        loop {
            let (is_stdout, line) = match deadline {
                None => match rx.recv() {
                    Ok(m) => m,
                    Err(_) => break,
                },
                Some(d) => match rx.recv_timeout(d.saturating_duration_since(Instant::now())) {
                    Ok(m) => m,
                    Err(RecvTimeoutError::Disconnected) => break,
                    Err(RecvTimeoutError::Timeout) => {
                        timed_out = true;
                        deadline = None; // keep reading what's left until the pipes close
                        if let Some(job) = &job {
                            job.terminate();
                        }
                        continue;
                    }
                },
            };
            if is_stdout && self.capture_stdout {
                stdout.push_str(&line);
                continue;
            }
            if let Some(clean) = clean_line(&line) {
                on_line(clean);
                if recent.len() == 5 {
                    recent.pop_front();
                }
                recent.push_back(clean.to_owned());
            }
        }
        let _ = (t1.join(), t2.join());
        let status = child.wait().context("waiting for process")?;
        if timed_out {
            let limit = self.timeout.unwrap_or_default();
            let tail = Vec::from(recent).join(" / ");
            if tail.is_empty() {
                bail!("{} timed out after {}s and was stopped", self.program.display(), limit.as_secs());
            }
            bail!(
                "{} timed out after {}s and was stopped; last output: {tail}",
                self.program.display(),
                limit.as_secs()
            );
        }
        Ok(Output { code: status.code().unwrap_or(-1), stdout })
    }
}

/// A Windows job object holding a process and everything it starts, so they can be ended
/// together. It's also set to end them if the agent itself goes away.
struct Job(HANDLE);

impl Job {
    fn containing(child: &Child) -> Result<Self> {
        // SAFETY: no security attributes and no name: a fresh anonymous job.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            bail!("creating a job object: {}", io::Error::last_os_error());
        }
        let job = Job(handle);
        // SAFETY: plain data, zeroed, then one flag set.
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: the buffer is a JOBOBJECT_EXTENDED_LIMIT_INFORMATION of the size we pass.
        let ok = unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            bail!("configuring a job object: {}", io::Error::last_os_error());
        }
        // Anything the child starts from here on joins the job too. (A grandchild started in
        // the instant between spawn and this call would escape; nothing we run is that quick.)
        // SAFETY: both handles are valid for the duration of the call.
        if unsafe { AssignProcessToJobObject(job.0, child.as_raw_handle() as HANDLE) } == 0 {
            bail!("putting the process in a job: {}", io::Error::last_os_error());
        }
        Ok(job)
    }

    fn terminate(&self) {
        // SAFETY: we own the job handle.
        unsafe { TerminateJobObject(self.0, 1) };
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // SAFETY: we own the handle and close it once.
        unsafe { CloseHandle(self.0) };
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
    fn a_timeout_stops_the_whole_process_tree() {
        // cmd starts ping as a child; both must go, or the pipes stay open and this hangs.
        let started = Instant::now();
        let err = Proc::new("cmd.exe")
            .args(["/d", "/c"])
            .raw(Some("echo working & ping -n 30 127.0.0.1 >nul"))
            .timeout_ms(Some(1500))
            .run(&mut |_| {})
            .unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(10), "took {:?}", started.elapsed());
        assert!(err.to_string().contains("timed out after 1s"), "{err}");
        assert!(err.to_string().contains("last output: working"), "{err}");

        let fast = Proc::new("cmd.exe").args(["/d", "/c"]).raw(Some("exit 4")).timeout_ms(Some(10_000));
        assert_eq!(fast.run(&mut |_| {}).unwrap().code, 4, "finishing in time behaves as before");
    }

    #[test]
    fn cleans_progress_noise() {
        assert_eq!(clean_line("  |  \r\n"), None);
        assert_eq!(clean_line("10%\r50%\r100%\r\n"), Some("100%"));
    }
}
