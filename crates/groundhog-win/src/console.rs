//! The console the agent writes to.

use windows_sys::Win32::System::Console::{
    CONSOLE_SCREEN_BUFFER_INFO, ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode, GetConsoleScreenBufferInfo,
    GetStdHandle, STD_OUTPUT_HANDLE, SetConsoleMode,
};

/// Turns on escape sequences (colors) for stdout. False when it isn't a console or the
/// console can't (before Windows 10).
pub fn enable_colors() -> bool {
    // SAFETY: plain calls on our own stdout handle.
    unsafe {
        let out = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut mode = 0;
        if GetConsoleMode(out, &mut mode) == 0 {
            return false;
        }
        mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0
            || SetConsoleMode(out, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
    }
}

/// Columns visible in the console window, if stdout is one.
pub fn width() -> Option<usize> {
    // SAFETY: as above; the struct is plain data the call fills in.
    unsafe {
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = std::mem::zeroed();
        if GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &mut info) == 0 {
            return None;
        }
        usize::try_from(info.srWindow.Right - info.srWindow.Left + 1).ok()
    }
}
