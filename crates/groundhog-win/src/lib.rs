//! Safe wrappers over the Windows APIs Groundhog needs. All `unsafe` code in the project lives
//! in this crate, behind small functions that can be read and reviewed on their own.

pub mod env;
pub mod process;
pub mod registry;
pub mod system;
pub mod tasks;
pub mod token;
pub mod winget;

pub(crate) fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
