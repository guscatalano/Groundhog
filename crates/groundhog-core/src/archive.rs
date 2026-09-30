//! Unpacking zip archives safely: entries that would land outside the target folder
//! (`..\..\evil.exe`, absolute paths) are refused rather than written.

use std::io::Cursor;
use std::path::Path;

use anyhow::{Context, Result, anyhow};

/// Unpacks `bytes` into `dir`, which must already exist and should be empty.
pub fn unzip(bytes: &[u8], dir: &Path) -> Result<()> {
    unzip_stripped(bytes, dir, 0)
}

/// Unpacks like [`unzip`], dropping the first `strip` folders of every path, the way
/// `tar --strip-components` does. GitHub source archives wrap everything in a
/// `repo-<ref>\` folder whose name changes with every version; `strip: 1` removes it.
pub fn unzip_stripped(bytes: &[u8], dir: &Path, strip: usize) -> Result<()> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).context("not a valid zip file")?;
    let mut written = 0usize;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let enclosed = entry.enclosed_name().ok_or_else(|| anyhow!("unsafe path in zip: {}", entry.name()))?;
        let rel: std::path::PathBuf = enclosed.components().skip(strip).collect();
        if rel.as_os_str().is_empty() {
            continue; // one of the stripped folders itself
        }
        written += 1;
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
    if strip > 0 && written == 0 {
        anyhow::bail!("nothing left in the zip after stripping {strip} folder level(s)");
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
    fn strips_leading_folders() {
        let dir = tempfile::tempdir().unwrap();
        let zip = zip_of(&[
            ("findneedle-1.0.267/", ""),
            ("findneedle-1.0.267/src/a.cs", "a"),
            ("findneedle-1.0.267/README.md", "r"),
        ]);
        unzip_stripped(&zip, dir.path(), 1).unwrap();
        assert_eq!(std::fs::read_to_string(dir.path().join("src/a.cs")).unwrap(), "a");
        assert!(dir.path().join("README.md").is_file());
        assert!(!dir.path().join("findneedle-1.0.267").exists());

        let err = unzip_stripped(&zip_of(&[("top/a.txt", "a")]), &dir.path().join("x"), 2).unwrap_err();
        assert!(err.to_string().contains("nothing left"), "{err}");
    }

    #[test]
    fn refuses_entries_that_escape() {
        let dir = tempfile::tempdir().unwrap();
        let err = unzip(&zip_of(&[("../escape.txt", "x")]), &dir.path().join("inner")).unwrap_err();
        assert!(err.to_string().contains("unsafe path"), "{err}");
        assert!(!dir.path().join("escape.txt").exists());
    }
}
