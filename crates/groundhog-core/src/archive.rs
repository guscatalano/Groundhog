//! Unpacking zip archives safely: entries that would land outside the target folder
//! (`..\..\evil.exe`, absolute paths) are refused rather than written.

use std::io::Cursor;
use std::path::Path;

use anyhow::{Context, Result, anyhow};

/// Unpacks `bytes` into `dir`, which must already exist and should be empty.
pub fn unzip(bytes: &[u8], dir: &Path) -> Result<()> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).context("not a valid zip file")?;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let rel = entry.enclosed_name().ok_or_else(|| anyhow!("unsafe path in zip: {}", entry.name()))?;
        let out = dir.join(rel);
        if entry.is_dir() {
            std::fs::create_dir_all(&out)?;
        } else {
            if let Some(parent) = out.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut f = std::fs::File::create(&out).with_context(|| format!("creating {}", out.display()))?;
            std::io::copy(&mut entry, &mut f)?;
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn zip_of(files: &[(&str, &str)]) -> Vec<u8> {
    use std::io::Write;
    let mut bytes = Vec::new();
    let mut z = zip::ZipWriter::new(Cursor::new(&mut bytes));
    for (name, body) in files {
        z.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
        z.write_all(body.as_bytes()).unwrap();
    }
    z.finish().unwrap();
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpacks_nested_entries() {
        let dir = tempfile::tempdir().unwrap();
        unzip(&zip_of(&[("a.txt", "a"), ("sub/b.txt", "b")]), dir.path()).unwrap();
        assert_eq!(std::fs::read_to_string(dir.path().join("sub/b.txt")).unwrap(), "b");
    }

    #[test]
    fn refuses_entries_that_escape() {
        let dir = tempfile::tempdir().unwrap();
        let err = unzip(&zip_of(&[("../escape.txt", "x")]), &dir.path().join("inner")).unwrap_err();
        assert!(err.to_string().contains("unsafe path"), "{err}");
        assert!(!dir.path().join("escape.txt").exists());
    }
}
