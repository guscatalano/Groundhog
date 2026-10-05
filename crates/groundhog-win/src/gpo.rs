//! Local Group Policy: the machine's own policy file, as gpedit edits it.
//!
//! Some policy keys are guarded against programs: the User Choice Protection driver refuses
//! writes to them even from administrators and SYSTEM. The Group Policy engine is the writer it
//! lets through, so for those keys Groundhog edits `Registry.pol` and has the engine apply it.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use winreg::RegKey;
use winreg::enums::HKEY_LOCAL_MACHINE;

use crate::registry::{self, Data};

const SIGNATURE: &[u8; 4] = b"PReg";
const VERSION: u32 = 1;
/// The registry client-side extension and gpedit's snap-in for it. `gpt.ini` has to list them,
/// or the engine skips the machine's registry policy.
const REGISTRY_CSE: &str = "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]";

/// One value in a `Registry.pol` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub key: String,
    pub value: String,
    pub kind: u32,
    pub data: Vec<u8>,
}

impl Entry {
    fn is(&self, key: &str, value: &str) -> bool {
        self.key.eq_ignore_ascii_case(key) && self.value.eq_ignore_ascii_case(value)
    }
}

/// Reads a `Registry.pol` file: a header, then `[key;value;type;size;data]` entries whose
/// text and separators are UTF-16.
pub fn parse(bytes: &[u8]) -> Result<Vec<Entry>> {
    if bytes.len() < 8 || &bytes[..4] != SIGNATURE {
        bail!("not a Registry.pol file");
    }
    let mut r = Reader { bytes, pos: 8 };
    let mut entries = Vec::new();
    while r.pos < bytes.len() {
        r.char('[')?;
        let key = r.string()?;
        r.char(';')?;
        let value = r.string()?;
        r.char(';')?;
        let kind = r.u32()?;
        r.char(';')?;
        let size = r.u32()? as usize;
        r.char(';')?;
        let data = r.take(size)?.to_vec();
        r.char(']')?;
        entries.push(Entry { key, value, kind, data });
    }
    Ok(entries)
}

pub fn serialize(entries: &[Entry]) -> Vec<u8> {
    let mut out = SIGNATURE.to_vec();
    out.extend(VERSION.to_le_bytes());
    let text = |out: &mut Vec<u8>, s: &str| out.extend(s.encode_utf16().flat_map(u16::to_le_bytes));
    for e in entries {
        text(&mut out, "[");
        text(&mut out, &e.key);
        text(&mut out, "\0;");
        text(&mut out, &e.value);
        text(&mut out, "\0;");
        out.extend(e.kind.to_le_bytes());
        text(&mut out, ";");
        out.extend((e.data.len() as u32).to_le_bytes());
        text(&mut out, ";");
        out.extend(&e.data);
        text(&mut out, "]");
    }
    out
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        let end = self.pos.checked_add(n).filter(|&e| e <= self.bytes.len()).context("Registry.pol is cut short")?;
        let s = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn char(&mut self, c: char) -> Result<()> {
        let at = self.pos;
        if self.u16()? != c as u16 {
            bail!("Registry.pol: expected '{c}' at byte {at}");
        }
        Ok(())
    }

    /// A null-terminated UTF-16 string.
    fn string(&mut self) -> Result<String> {
        let mut units = Vec::new();
        loop {
            match self.u16()? {
                0 => break,
                u => units.push(u),
            }
        }
        Ok(String::from_utf16_lossy(&units))
    }
}

/// `gpt.ini` with the machine policy's version bumped (the engine applies only new versions) and
/// the registry extension listed.
pub fn bump_gpt_ini(text: &str) -> String {
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let general = match lines.iter().position(|l| l.trim().eq_ignore_ascii_case("[General]")) {
        Some(i) => i,
        None => {
            lines.insert(0, "[General]".to_owned());
            0
        }
    };
    let section_end = lines
        .iter()
        .skip(general + 1)
        .position(|l| l.trim_start().starts_with('['))
        .map_or(lines.len(), |p| p + general + 1);
    let find = |lines: &[String], name: &str| {
        (general + 1..section_end)
            .find(|&i| lines[i].split_once('=').is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case(name)))
    };

    match find(&lines, "gPCMachineExtensionNames") {
        Some(i) if lines[i].contains("35378EAC-683F-11D2-A89A-00C04FBBCFA2") => {}
        Some(i) => {
            let (k, v) = lines[i].split_once('=').expect("found by its '='");
            lines[i] = format!("{k}={REGISTRY_CSE}{}", v.trim());
        }
        None => lines.insert(general + 1, format!("gPCMachineExtensionNames={REGISTRY_CSE}")),
    }
    // The low 16 bits count machine policy changes, the high 16 user policy changes.
    let section_end = lines
        .iter()
        .skip(general + 1)
        .position(|l| l.trim_start().starts_with('['))
        .map_or(lines.len(), |p| p + general + 1);
    let version_at = (general + 1..section_end)
        .find(|&i| lines[i].split_once('=').is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case("Version")));
    let old = version_at.and_then(|i| lines[i].split_once('=')?.1.trim().parse::<u32>().ok()).unwrap_or(0);
    let new = (old & 0xFFFF_0000) | ((old & 0xFFFF) + 1) & 0xFFFF;
    let new = if new & 0xFFFF == 0 { new | 1 } else { new };
    match version_at {
        Some(i) => lines[i] = format!("Version={new}"),
        None => lines.insert(general + 1, format!("Version={new}")),
    }
    let mut out = lines.join("\r\n");
    out.push_str("\r\n");
    out
}

fn policy_dir() -> PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    PathBuf::from(root).join("System32").join("GroupPolicy")
}

/// Sets (`Some`) or removes (`None`) one value of the machine's local policy, under
/// `HKLM\<key>`. Returns whether anything changed, or with `check`, would; a change is applied
/// at once by the Group Policy engine.
pub fn set_machine_value(key: &str, name: &str, data: Option<&Data>, check: bool) -> Result<bool> {
    let dir = policy_dir();
    let pol_path = dir.join("Machine").join("Registry.pol");
    let mut entries = match std::fs::read(&pol_path) {
        Ok(bytes) => parse(&bytes).with_context(|| format!("reading {}", pol_path.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e).with_context(|| format!("reading {}", pol_path.display())),
    };
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let at = entries.iter().position(|e| e.is(key, name));
    let file_changes = match (data, at) {
        (Some(d), Some(i)) => {
            let (kind, bytes) = d.raw();
            entries[i].kind != kind || entries[i].data != bytes
        }
        (Some(_), None) => true,
        (None, at) => at.is_some(),
    };
    // A file that already says so but was never applied (or was undone by hand) still needs
    // the engine to run.
    let live_differs = match data {
        Some(d) => !registry::value_matches(&hklm, key, Some(name), d),
        None => false,
    };
    if !file_changes && !live_differs {
        return Ok(false);
    }
    if check {
        return Ok(true);
    }

    if file_changes {
        match (data, at) {
            (Some(d), at) => {
                let (kind, data) = d.raw();
                let entry = Entry { key: key.to_owned(), value: name.to_owned(), kind, data };
                match at {
                    Some(i) => entries[i] = entry,
                    None => entries.push(entry),
                }
            }
            (None, Some(i)) => drop(entries.remove(i)),
            (None, None) => {}
        }
        std::fs::create_dir_all(pol_path.parent().expect("has a parent"))?;
        std::fs::write(&pol_path, serialize(&entries)).with_context(|| format!("writing {}", pol_path.display()))?;
        let gpt = dir.join("gpt.ini");
        let old = std::fs::read_to_string(&gpt).unwrap_or_default();
        std::fs::write(&gpt, bump_gpt_ini(&old)).with_context(|| format!("writing {}", gpt.display()))?;
    }
    apply()?;
    if let Some(d) = data
        && !registry::value_matches(&hklm, key, Some(name), d)
    {
        bail!("Group Policy didn't set HKLM\\{key}\\{name}; a domain policy may be overriding it");
    }
    Ok(true)
}

/// Has the Group Policy engine apply the machine policy now.
fn apply() -> Result<()> {
    let out = Command::new("gpupdate.exe")
        .args(["/target:computer", "/force", "/wait:120"])
        .stdin(Stdio::null())
        .output()
        .context("running gpupdate")?;
    if !out.status.success() {
        bail!("gpupdate failed: {}", String::from_utf8_lossy(&out.stdout).trim());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_pol_round_trips() {
        let entries = vec![
            Entry {
                key: r"SOFTWARE\Policies\Microsoft\Dsh".into(),
                value: "AllowNewsAndInterests".into(),
                kind: 4,
                data: 0u32.to_le_bytes().to_vec(),
            },
            // Data that happens to contain the ']' separator must survive.
            Entry { key: r"SOFTWARE\X".into(), value: "**del.Y".into(), kind: 1, data: vec![b']', 0, 0, 0] },
        ];
        let bytes = serialize(&entries);
        assert_eq!(&bytes[..8], b"PReg\x01\0\0\0");
        assert_eq!(parse(&bytes).unwrap(), entries);
        assert_eq!(parse(&serialize(&[])).unwrap(), vec![]);
        assert!(parse(b"nope").is_err());
        assert!(parse(&bytes[..bytes.len() - 3]).is_err());
    }

    #[test]
    fn gpt_ini_gets_a_new_machine_version_and_the_registry_extension() {
        let fresh = bump_gpt_ini("");
        assert!(fresh.contains(&format!("gPCMachineExtensionNames={REGISTRY_CSE}")), "{fresh}");
        assert!(fresh.contains("Version=1\r\n"), "{fresh}");
        assert!(fresh.starts_with("[General]"));

        // User policy changes live in the high 16 bits and are kept.
        let existing = "[General]\r\nVersion=131075\r\ngPCMachineExtensionNames=[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]\r\ndisplayName=Local\r\n";
        let bumped = bump_gpt_ini(existing);
        assert!(bumped.contains("Version=131076\r\n"), "{bumped}");
        assert!(bumped.contains(&format!("gPCMachineExtensionNames={REGISTRY_CSE}[{{827D319E")), "{bumped}");
        assert!(bumped.contains("displayName=Local"));

        // Already listed: left alone, and the machine count wraps without reaching zero.
        let listed = format!("[General]\nVersion=65535\ngPCMachineExtensionNames={REGISTRY_CSE}\n");
        let bumped = bump_gpt_ini(&listed);
        assert_eq!(bumped.matches("35378EAC").count(), 1);
        assert!(bumped.contains("Version=1\r\n"), "{bumped}");
    }
}
