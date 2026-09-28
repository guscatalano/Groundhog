//! Following an agent's progress through a status folder (see `FolderReporter`).
//! Any provider that can share a folder with the target, or copy one out, can use this.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::time::Duration;

use groundhog_core::engine::{RunState, RunStatus};
use groundhog_core::report::{LOG_FILE, STATUS_FILE};

/// Prints new log lines until the run finishes; returns its final state.
pub fn follow(dir: &Path) -> RunState {
    let mut offset = 0u64;
    let mut announced = false;
    loop {
        offset = print_new_lines(&dir.join(LOG_FILE), offset);
        if let Some(state) = read_status(dir)
            && state.status.is_finished()
        {
            print_new_lines(&dir.join(LOG_FILE), offset);
            return state;
        }
        if offset == 0 && !announced {
            println!("waiting for the agent to start...");
            announced = true;
        }
        std::thread::sleep(Duration::from_millis(750));
    }
}

fn read_status(dir: &Path) -> Option<RunState> {
    serde_json::from_slice(&std::fs::read(dir.join(STATUS_FILE)).ok()?).ok()
}

fn print_new_lines(path: &Path, offset: u64) -> u64 {
    let Ok(mut f) = std::fs::File::open(path) else { return offset };
    if f.seek(SeekFrom::Start(offset)).is_err() {
        return offset;
    }
    let mut buf = Vec::new();
    if f.read_to_end(&mut buf).is_err() {
        return offset;
    }
    // Only consume complete lines; a partial last line is printed next time.
    let complete = buf.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
    for line in String::from_utf8_lossy(&buf[..complete]).lines() {
        println!("{line}");
    }
    offset + complete as u64
}

pub fn exit_code(state: &RunState) -> i32 {
    match state.status {
        RunStatus::Succeeded => 0,
        RunStatus::RebootPending => 3010,
        RunStatus::Failed | RunStatus::Running => 1,
    }
}
