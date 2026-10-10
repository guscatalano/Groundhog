//! The Groundhogfile model.
//!
//! There are two layers:
//! - `raw::*` mirrors what a user writes (YAML or JSON). Relative references are plain strings,
//!   and many entries accept either a short string form or a full object form.
//! - The public types below are the *resolved* form: every relative reference has been turned
//!   into an absolute URL against the file it came from, so a merged Groundhogfile no longer
//!   depends on where each piece was loaded from.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use url::Url;

pub const CURRENT_VERSION: u32 = 1;

/// A fully loaded and merged Groundhogfile.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Groundhogfile {
    pub users: Vec<User>,
    pub certificates: Vec<Certificate>,
    pub defender_exclusions: Vec<DefenderExclusion>,
    pub features: Vec<Feature>,
    pub capabilities: Vec<Capability>,
    /// Built-in Store apps to remove, by package name (wildcards allowed).
    pub remove_apps: Vec<String>,
    pub apps: Vec<App>,
    pub files: Vec<FileCopy>,
    pub env: BTreeMap<String, EnvVar>,
    pub path: Vec<PathEntry>,
    pub registry: Vec<RegistryValue>,
    pub wallpaper: Option<Wallpaper>,
    pub theme: Option<Theme>,
    pub lock_screen: Option<LockScreen>,
    pub screen_saver: Option<ScreenSaver>,
    pub tray_icons: Vec<TrayIcon>,
    /// Do Not Disturb for the agent's user; Windows applies it at the next sign-in.
    pub do_not_disturb: Option<bool>,
    pub start_pins: Option<StartPins>,
    pub desktop_shortcuts: Vec<DesktopShortcut>,
    pub language: Vec<LanguageSetting>,
    pub services: Vec<Service>,
    pub firewall: Vec<FirewallRule>,
    pub run: Vec<RunAction>,
    pub verify: Vec<Check>,
    /// The oldest agent that understands this file (the highest `agent:` across `extends`).
    #[serde(skip)]
    pub requires_agent: Option<crate::update::Version>,
}

/// Whether something should exist. Left out of the serialized form when `present`, so the
/// step ids of everything written before `state: absent` existed don't change.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Presence {
    #[default]
    Present,
    Absent,
}

impl Presence {
    pub fn is_present(&self) -> bool {
        *self == Presence::Present
    }
}

/// A certificate to trust (or distrust, or remove).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Certificate {
    /// The certificate file (`.cer`/`.crt`, DER or PEM). `None` when removing by thumbprint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Content hash found at load time when `sha256` is not pinned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved: Option<String>,
    /// Upper-case hex SHA-1 thumbprint, for removal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    pub store: CertStore,
    pub scope: CertScope,
    #[serde(skip_serializing_if = "Presence::is_present")]
    pub state: Presence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertStore {
    /// Trusted root authorities.
    Root,
    /// Intermediate authorities.
    Ca,
    /// Personal.
    My,
    TrustedPeople,
    TrustedPublisher,
    /// Explicitly distrusted.
    Disallowed,
}

impl CertStore {
    /// The store's name in the Windows API (`Cert:\LocalMachine\<name>`).
    pub fn system_name(self) -> &'static str {
        match self {
            CertStore::Root => "Root",
            CertStore::Ca => "CA",
            CertStore::My => "My",
            CertStore::TrustedPeople => "TrustedPeople",
            CertStore::TrustedPublisher => "TrustedPublisher",
            CertStore::Disallowed => "Disallowed",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertScope {
    #[default]
    Machine,
    User,
}

/// A Windows service's start type and, optionally, whether it runs.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Service {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub startup: Option<StartupType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<ServiceState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StartupType {
    Automatic,
    /// Automatic, started shortly after boot.
    Delayed,
    Manual,
    Disabled,
}

/// A Windows Firewall rule, found again by its name.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FirewallRule {
    pub name: String,
    /// Ports as Windows writes them: `8791`, `80,443`, `8000-8100`. Empty: any port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ports: Option<String>,
    pub protocol: FirewallProtocol,
    pub direction: FirewallDirection,
    pub action: FirewallAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    /// `any`, or a comma list of `domain`, `private`, `public`.
    pub profile: String,
    /// Remote addresses: `any`, `LocalSubnet`, `10.0.0.0/8`, a comma list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    #[serde(skip_serializing_if = "Presence::is_present")]
    pub state: Presence,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FirewallProtocol {
    #[default]
    Tcp,
    Udp,
    Any,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FirewallDirection {
    #[default]
    In,
    Out,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FirewallAction {
    #[default]
    Allow,
    Block,
}

/// Something Microsoft Defender's real-time scanning leaves alone.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DefenderExclusion {
    pub kind: ExclusionKind,
    pub value: String,
    #[serde(skip_serializing_if = "Presence::is_present")]
    pub state: Presence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExclusionKind {
    Path,
    Process,
    Extension,
}

/// The desktop picture and/or solid background color.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Wallpaper {
    /// The picture (path or URL). `None`: no picture, just the background color.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Content hash found at load time when `sha256` is not pinned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved: Option<String>,
    pub style: WallpaperStyle,
    /// `#RRGGBB`, upper case.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background: Option<String>,
    pub scope: Vec<HiveScope>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WallpaperStyle {
    #[default]
    Fill,
    Fit,
    Stretch,
    Tile,
    Center,
    Span,
}

/// The lock screen, for the whole machine: its picture, and how long the machine may sit idle
/// before it locks.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LockScreen {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Content hash found at load time when `sha256` is not pinned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock_after_secs: Option<u64>,
}

/// The screen saver, per user.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ScreenSaver {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure: Option<bool>,
    /// The `.scr` to run, as a full path (may contain `%VARS%`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    pub scope: Vec<HiveScope>,
}

/// Whether a program's notification-area icon sits on the taskbar or in the overflow (^),
/// for the agent's user. Windows keeps one entry per program, made the first time it shows
/// an icon.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TrayIcon {
    /// A program's file name (`OneDrive.exe`) or full path.
    pub program: String,
    /// On the taskbar (`true`) or in the overflow.
    pub shown: bool,
}

/// A shortcut on the desktop every account shares (`C:\Users\Public\Desktop`), or one taken
/// off it and this user's desktop.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DesktopShortcut {
    /// The shortcut's name, as the desktop shows it (the file is `<name>.lnk`).
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    pub state: Presence,
}

/// One of the `language:` settings; each is its own step.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "setting", rename_all = "kebab-case")]
pub enum LanguageSetting {
    /// The languages to type in, in order, each with its keyboards (none: Windows' default).
    Input { languages: Vec<InputLanguage> },
    /// Windows' display language for the agent's user, its language pack installed first;
    /// `machine` also makes it the sign-in screen's and new accounts' (after a restart).
    Display { tag: String, machine: bool },
    /// Formats for dates, times, numbers and currency.
    Formats { tag: String },
    /// Home location, as a two-letter country or region code.
    Location { region: String },
    /// The language for programs that don't use Unicode (after a restart).
    SystemLocale { tag: String },
    /// UTF-8 as the code page for programs that don't use Unicode (after a restart).
    Utf8 { on: bool },
    /// Copies the agent user's settings to the sign-in screen and to new accounts.
    CopyToSystem,
}

impl LanguageSetting {
    /// The order they're applied in: input before display (setting the list can change the
    /// display language), the system locale before UTF-8 (it resets the code pages), and the
    /// copy to the sign-in screen last.
    pub fn order(&self) -> u8 {
        match self {
            LanguageSetting::Input { .. } => 0,
            LanguageSetting::Display { .. } => 1,
            LanguageSetting::Formats { .. } => 2,
            LanguageSetting::Location { .. } => 3,
            LanguageSetting::SystemLocale { .. } => 4,
            LanguageSetting::Utf8 { .. } => 5,
            LanguageSetting::CopyToSystem => 6,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InputLanguage {
    /// A language tag: `en-US`, `ja-JP`.
    pub tag: String,
    /// Input method tips (`0409:00000409`); empty: the language's default keyboard or IME.
    pub keyboards: Vec<String>,
}

/// Start's pinned apps, as a layout file (`start2.bin`) taken from a machine pinned by hand.
/// Windows keeps them in that file only, in a format of its own.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StartPins {
    pub from: Url,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Content hash found at load time when `sha256` is not pinned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved: Option<String>,
    pub scope: Vec<HiveScope>,
}

/// Light or dark mode, for apps and for Windows itself (taskbar, Start, notifications).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Theme {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apps: Option<ThemeMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub windows: Option<ThemeMode>,
    pub scope: Vec<HiveScope>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ThemeMode {
    Light,
    Dark,
}

/// A Windows optional feature (`NetFx3`, `Microsoft-Windows-Subsystem-Linux`, ...).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Feature {
    pub name: String,
    pub enabled: bool,
    /// Also enable the features it depends on (DISM's /All).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub all: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub remove_payload: bool,
    /// Folders or shares holding the payload (`sources\sxs` of matching install media).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
    /// Never ask Windows Update for the payload.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub limit_access: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

/// A Windows capability, also called a Feature on Demand (`OpenSSH.Server~~~~0.0.1.0`, ...).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Capability {
    pub name: String,
    pub present: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub limit_access: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

/// A local user account. Existing accounts are brought in line (groups, password expiry) but
/// their password is left alone unless `reset_password` is set.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct User {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    pub password: Password,
    /// Local groups the user is added to. Membership in other groups is left alone.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    pub password_never_expires: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub reset_password: bool,
    #[serde(skip_serializing_if = "Presence::is_present")]
    pub state: Presence,
}

/// Where a password comes from. Never the password itself: a Groundhogfile is shared, logged
/// and cached, so passwords are supplied at run time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Password {
    /// Random, known to nobody: for accounts no one types into.
    Generate,
    /// Supplied at run time under this name (pending.json `secrets`, or `GROUNDHOG_SECRET_<NAME>`).
    Secret(String),
}

/// A health check. Unlike every other step, checks run on every apply, after everything else,
/// and a failed check fails the apply.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "check", rename_all = "kebab-case")]
pub enum Check {
    /// A process with this image name (`.exe` optional) is running and, with `stable_for_ms`,
    /// keeps the same PID for that long.
    Process {
        name: String,
        stable_for_ms: u64,
        within_ms: u64,
    },
    Service {
        name: String,
        status: ServiceState,
        within_ms: u64,
    },
    /// Looks at events from `provider` in `log`. Text matching is a case-insensitive substring
    /// test against each event's rendered message. `must_contain` waits up to `within_ms` for
    /// the events to show up; a `must_not_contain` match fails at once.
    EventLog {
        log: String,
        provider: String,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        must_contain: Vec<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        must_not_contain: Vec<String>,
        since: EventsSince,
        within_ms: u64,
    },
    /// Something accepts TCP connections on `host:port`.
    Port {
        host: String,
        port: u16,
        within_ms: u64,
    },
    File {
        path: String,
        within_ms: u64,
    },
    /// Anything else: the check passes when the command exits 0.
    Command {
        command: String,
        shell: Shell,
        within_ms: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceState {
    Running,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EventsSince {
    /// Only events logged since this apply started, so old failures don't count.
    #[default]
    Apply,
    /// Any event still in the log.
    Any,
}

/// A reference to another resource, optionally pinned to a content hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRef {
    pub url: Url,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "source", rename_all = "kebab-case")]
pub enum App {
    /// Installed with `winget install --id <id> --exact`.
    Winget {
        id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        version: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        args: Option<String>,
        /// Kill the step (and everything it started) if it runs longer than this.
        #[serde(skip_serializing_if = "Option::is_none")]
        timeout_ms: Option<u64>,
        /// Upgrade an installed copy whenever a newer version is available.
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        upgrade: bool,
        /// `absent`: uninstall it.
        #[serde(skip_serializing_if = "Presence::is_present")]
        state: Presence,
    },
    /// An installer fetched from a URL (or found in a cache by hash) and run directly.
    Url {
        id: String,
        url: Url,
        #[serde(skip_serializing_if = "Option::is_none")]
        sha256: Option<String>,
        /// Content hash found at load time when `sha256` is not pinned. Part of the step's
        /// identity, so a new "latest" build makes the step run again.
        #[serde(skip_serializing_if = "Option::is_none")]
        resolved: Option<String>,
        /// The GitHub release a `github:` reference resolved to, for logs and step identity.
        #[serde(skip_serializing_if = "Option::is_none")]
        release: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        args: Option<String>,
        /// Kill the step (and everything it started) if it runs longer than this.
        #[serde(skip_serializing_if = "Option::is_none")]
        timeout_ms: Option<u64>,
    },
}

impl App {
    pub fn id(&self) -> &str {
        match self {
            App::Winget { id, .. } | App::Url { id, .. } => id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FileCopy {
    /// Where the file comes from. `None` for inline `content`. Serialized exactly as before
    /// inline content existed, so step ids of `from:` files don't change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<Url>,
    /// The file's text, written as UTF-8. May contain `${secret:NAME}` references, filled in
    /// only when the step runs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// Destination; may contain `~` and `%VARS%`, expanded on the target machine.
    pub to: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Content hash found at load time when `sha256` is not pinned. Part of the step's
    /// identity, so a new "latest" build makes the step run again.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved: Option<String>,
    /// `from` is a zip; unpack it into the folder `to`, replacing what was there.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub extract: bool,
    /// With `extract`: leading folders to drop from every path in the zip.
    #[serde(skip_serializing_if = "is_zero")]
    pub strip: u32,
    /// The GitHub release a `github:` reference resolved to, for logs and step identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release: Option<String>,
    /// `absent`: delete `to` (a file, or a folder and everything in it).
    #[serde(skip_serializing_if = "Presence::is_present")]
    pub state: Presence,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RegistryType {
    String,
    ExpandString,
    MultiString,
    Dword,
    Qword,
    /// Raw bytes, written in YAML as hex (`"86 08 73 52"`).
    Binary,
}

/// Where an environment variable or PATH entry is stored.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnvScope {
    /// `HKCU\Environment`: the account the agent runs as.
    #[default]
    User,
    /// The system environment: every account, including services and SYSTEM.
    Machine,
}

impl EnvScope {
    pub fn is_user(&self) -> bool {
        *self == EnvScope::User
    }
}

/// An environment variable's value. `scope` is left out of the serialized form when it's the
/// default, so step ids from before machine scope existed don't change.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EnvVar {
    pub value: String,
    #[serde(skip_serializing_if = "EnvScope::is_user")]
    pub scope: EnvScope,
    #[serde(skip_serializing_if = "Presence::is_present")]
    pub state: Presence,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PathEntry {
    pub dir: String,
    #[serde(skip_serializing_if = "EnvScope::is_user")]
    pub scope: EnvScope,
    #[serde(skip_serializing_if = "Presence::is_present")]
    pub state: Presence,
}

/// Which user hives a `HKCU\...` value is written to. Ignored for other roots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HiveScope {
    /// The user the agent runs as.
    CurrentUser,
    /// `C:\Users\Default\NTUSER.DAT`, so profiles created later get the value too.
    DefaultUser,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RegistryValue {
    /// Full key path, e.g. `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`.
    pub key: String,
    /// Value name; `None` means the key's default value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub kind: RegistryType,
    pub data: RegistryData,
    pub scope: Vec<HiveScope>,
    /// `absent`: delete the value, or the whole key when there's no `name`.
    #[serde(skip_serializing_if = "Presence::is_present")]
    pub state: Presence,
    /// Written through the machine's local Group Policy rather than directly, for policy keys
    /// Windows guards against programs.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub group_policy: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum RegistryData {
    String(String),
    MultiString(Vec<String>),
    Dword(u32),
    Qword(u64),
    Binary(Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Shell {
    /// Windows PowerShell 5.1, present on every Windows install.
    #[default]
    Powershell,
    Pwsh,
    Cmd,
    /// Run the file itself (for `.exe` scripts).
    Direct,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum RunAction {
    /// An inline command.
    Command {
        command: String,
        shell: Shell,
        /// Kill the step (and everything it started) if it runs longer than this.
        #[serde(skip_serializing_if = "Option::is_none")]
        timeout_ms: Option<u64>,
        /// Run on every apply, not only when something changed (a test run, say).
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        always: bool,
    },
    /// A script fetched relative to the Groundhogfile and run from a local copy.
    Script {
        script: Url,
        #[serde(skip_serializing_if = "Option::is_none")]
        sha256: Option<String>,
        /// Content hash found at load time when `sha256` is not pinned. Part of the step's
        /// identity, so a new "latest" build makes the step run again.
        #[serde(skip_serializing_if = "Option::is_none")]
        resolved: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        args: Option<String>,
        shell: Option<Shell>,
        /// Kill the step (and everything it started) if it runs longer than this.
        #[serde(skip_serializing_if = "Option::is_none")]
        timeout_ms: Option<u64>,
        /// Run on every apply, not only when something changed (a test run, say).
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        always: bool,
    },
    /// An external executable speaking the plugin protocol (see [`crate::plugin`]).
    Plugin {
        plugin: Url,
        #[serde(skip_serializing_if = "Option::is_none")]
        sha256: Option<String>,
        /// Content hash found at load time when `sha256` is not pinned. Part of the step's
        /// identity, so a new "latest" build makes the step run again.
        #[serde(skip_serializing_if = "Option::is_none")]
        resolved: Option<String>,
        with: serde_json::Value,
        /// Kill the step (and everything it started) if it runs longer than this.
        #[serde(skip_serializing_if = "Option::is_none")]
        timeout_ms: Option<u64>,
        /// Run on every apply, not only when something changed (a test run, say).
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        always: bool,
    },
}

impl RunAction {
    pub fn timeout_ms(&self) -> Option<u64> {
        match self {
            RunAction::Command { timeout_ms, .. }
            | RunAction::Script { timeout_ms, .. }
            | RunAction::Plugin { timeout_ms, .. } => *timeout_ms,
        }
    }

    pub fn always(&self) -> bool {
        match self {
            RunAction::Command { always, .. } | RunAction::Script { always, .. } | RunAction::Plugin { always, .. } => {
                *always
            }
        }
    }
}

/// What the user writes. Only the loader uses these.
pub(crate) mod raw {
    use std::collections::BTreeMap;

    use serde::Deserialize;

    use super::{
        CertScope, CertStore, EnvScope, EventsSince, FirewallAction, FirewallDirection, FirewallProtocol, HiveScope,
        Presence, RegistryType, ServiceState, Shell, StartupType, ThemeMode, WallpaperStyle,
    };

    #[derive(Debug, Default, Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "kebab-case")]
    pub struct File {
        pub version: Option<u32>,
        /// The oldest agent version that understands this file, as `">=0.5.0"`.
        pub agent: Option<String>,
        #[serde(default)]
        pub extends: OneOrMany<SourceRef>,
        #[serde(default)]
        pub apps: Vec<App>,
        #[serde(default)]
        pub files: Vec<FileCopy>,
        #[serde(default)]
        pub env: BTreeMap<String, StringOr<EnvFull>>,
        #[serde(default)]
        pub path: Vec<StringOr<PathFull>>,
        #[serde(default)]
        pub registry: Vec<RegistryValue>,
        #[serde(default)]
        pub run: Vec<RunAction>,
        #[serde(default)]
        pub verify: Vec<Check>,
        #[serde(default)]
        pub users: Vec<User>,
        #[serde(default)]
        pub features: Vec<StringOr<Feature>>,
        #[serde(default)]
        pub capabilities: Vec<StringOr<Capability>>,
        /// Values for `${var:NAME}`. Read in a pass of their own before the rest of the file
        /// (see `vars.rs`); declared here so the strict reader accepts the key.
        #[serde(default)]
        #[allow(dead_code)]
        pub vars: BTreeMap<String, String>,
        #[serde(default)]
        pub certificates: Vec<Certificate>,
        #[serde(default)]
        pub services: Vec<Service>,
        #[serde(default)]
        pub firewall: Vec<FirewallRule>,
        #[serde(default)]
        pub defender_exclusions: Vec<StringOr<DefenderExclusion>>,
        #[serde(default)]
        pub remove_apps: Vec<String>,
        pub desktop: Option<Desktop>,
        pub uac: Option<Uac>,
        pub language: Option<Language>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "kebab-case")]
    pub struct Language {
        pub input: Option<Vec<StringOr<InputFull>>>,
        pub switch_hotkey: Option<SwitchHotkey>,
        pub display: Option<String>,
        pub formats: Option<String>,
        pub location: Option<String>,
        pub system_locale: Option<String>,
        #[serde(rename = "utf-8")]
        pub utf8: Option<bool>,
        pub welcome_screen: Option<bool>,
    }

    /// The desktop's icons: Windows' own, and shortcuts.
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "kebab-case")]
    pub struct IconsFull {
        pub this_pc: Option<bool>,
        pub recycle_bin: Option<bool>,
        pub user_files: Option<bool>,
        pub network: Option<bool>,
        pub control_panel: Option<bool>,
        /// Shortcuts to put on the desktop every account shares.
        pub add: Option<Vec<ShortcutFull>>,
        /// Shortcuts to take off, by name (`Microsoft Edge`).
        pub remove: Option<Vec<String>>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ShortcutFull {
        pub name: String,
        pub target: String,
        pub args: Option<String>,
        pub icon: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct InputFull {
        pub language: String,
        pub keyboards: Vec<String>,
    }

    /// The keys that switch between input languages (Win+Space always does).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum SwitchHotkey {
        AltShift,
        CtrlShift,
        Grave,
        None,
    }

    /// User Account Control policy. Becomes values under
    /// `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`.
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "kebab-case")]
    pub struct Uac {
        pub level: Option<UacLevel>,
        pub admin_prompt: Option<AdminPrompt>,
        pub user_prompt: Option<UserPrompt>,
        pub secure_desktop: Option<bool>,
        pub enabled: Option<bool>,
    }

    /// The four positions of the slider in Control Panel.
    #[derive(Debug, Clone, Copy, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum UacLevel {
        AlwaysNotify,
        Default,
        NoDim,
        NeverNotify,
    }

    /// ConsentPromptBehaviorAdmin, named as in Group Policy.
    #[derive(Debug, Clone, Copy, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum AdminPrompt {
        ElevateWithoutPrompting = 0,
        CredentialsOnSecureDesktop = 1,
        ConsentOnSecureDesktop = 2,
        Credentials = 3,
        Consent = 4,
        ConsentForNonWindowsBinaries = 5,
    }

    /// ConsentPromptBehaviorUser, named as in Group Policy.
    #[derive(Debug, Clone, Copy, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum UserPrompt {
        Deny = 0,
        CredentialsOnSecureDesktop = 1,
        Credentials = 3,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "kebab-case")]
    pub struct Desktop {
        pub theme: Option<StringOr<ThemeFull>>,
        pub wallpaper: Option<StringOr<WallpaperFull>>,
        pub wallpaper_style: Option<WallpaperStyle>,
        pub background: Option<String>,
        pub lock_screen: Option<LockScreenFull>,
        pub screen_saver: Option<ScreenSaverFull>,
        pub taskbar: Option<TaskbarFull>,
        pub start: Option<StartFull>,
        pub notifications: Option<NotificationsFull>,
        pub tray: Option<TrayFull>,
        pub icons: Option<IconsFull>,
        pub scope: Option<OneOrMany<HiveScope>>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "kebab-case")]
    pub struct TaskbarFull {
        pub alignment: Option<TaskbarAlignment>,
        pub search: Option<TaskbarSearch>,
        pub task_view: Option<bool>,
        pub widgets: Option<bool>,
        pub pins: Option<Vec<String>>,
        pub pins_for: Option<PinsFor>,
        pub clock_seconds: Option<bool>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "kebab-case")]
    pub struct NotificationsFull {
        pub enabled: Option<bool>,
        pub sounds: Option<bool>,
        pub lock_screen: Option<bool>,
        pub do_not_disturb: Option<bool>,
        /// App id (as in Settings' notification list) to on/off.
        pub apps: Option<BTreeMap<String, bool>>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "kebab-case")]
    pub struct TrayFull {
        pub show: Option<Vec<String>>,
        pub hide: Option<Vec<String>>,
        pub touch_keyboard: Option<bool>,
    }

    #[derive(Debug, Clone, Copy, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum TaskbarAlignment {
        Left = 0,
        Center = 1,
    }

    /// SearchboxTaskbarMode.
    #[derive(Debug, Clone, Copy, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum TaskbarSearch {
        Hidden = 0,
        Icon = 1,
        Box = 2,
        IconAndLabel = 3,
    }

    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum PinsFor {
        /// The Start layout policy: every account, at its next sign-in.
        #[default]
        Everyone,
        /// The Default profile: accounts created later, which may then change them.
        NewAccounts,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "kebab-case")]
    pub struct StartFull {
        pub recommended_files: Option<bool>,
        pub most_used_apps: Option<bool>,
        pub recommendations: Option<bool>,
        pub account_notifications: Option<bool>,
        /// The folders next to the power button, by name.
        pub folders: Option<Vec<String>>,
        /// "Recently added" apps under Recommended.
        pub recently_added: Option<bool>,
        /// The pinned apps: a `start2.bin` taken from a machine pinned by hand.
        pub pins_from: Option<StringOr<WallpaperFull>>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "kebab-case")]
    pub struct LockScreenFull {
        pub image: Option<StringOr<WallpaperFull>>,
        pub lock_after: Option<Duration>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "kebab-case")]
    pub struct ScreenSaverFull {
        pub enabled: Option<bool>,
        pub timeout: Option<Duration>,
        pub secure: Option<bool>,
        pub program: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ThemeFull {
        pub apps: Option<ThemeMode>,
        pub windows: Option<ThemeMode>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct WallpaperFull {
        pub from: String,
        pub sha256: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "kebab-case")]
    pub struct Certificate {
        pub from: Option<String>,
        pub sha256: Option<String>,
        pub thumbprint: Option<String>,
        pub store: Option<CertStore>,
        pub scope: Option<CertScope>,
        pub state: Option<Presence>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "kebab-case")]
    pub struct Service {
        pub name: String,
        pub startup: Option<StartupType>,
        pub status: Option<ServiceState>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "kebab-case")]
    pub struct FirewallRule {
        pub name: String,
        pub port: Option<Ports>,
        pub protocol: Option<FirewallProtocol>,
        pub direction: Option<FirewallDirection>,
        pub action: Option<FirewallAction>,
        pub program: Option<String>,
        pub profile: Option<OneOrMany<String>>,
        pub remote: Option<OneOrMany<String>>,
        pub state: Option<Presence>,
    }

    /// `8791`, `"8000-8100"` or `[80, 443]`.
    #[derive(Debug, Deserialize)]
    #[serde(untagged)]
    pub enum Ports {
        One(u64),
        Text(String),
        List(Vec<Scalar>),
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "kebab-case")]
    pub struct DefenderExclusion {
        pub path: Option<String>,
        pub process: Option<String>,
        pub extension: Option<String>,
        pub state: Option<Presence>,
    }

    #[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
    #[serde(rename_all = "kebab-case")]
    pub enum FeatureState {
        Enabled,
        Disabled,
    }

    #[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
    #[serde(rename_all = "kebab-case")]
    pub enum CapabilityState {
        Present,
        Removed,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "kebab-case")]
    pub struct Feature {
        pub name: String,
        pub state: Option<FeatureState>,
        pub all: Option<bool>,
        pub remove_payload: Option<bool>,
        pub source: Option<OneOrMany<String>>,
        pub limit_access: Option<bool>,
        pub timeout: Option<Duration>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "kebab-case")]
    pub struct Capability {
        pub name: String,
        pub state: Option<CapabilityState>,
        pub source: Option<OneOrMany<String>>,
        pub limit_access: Option<bool>,
        pub timeout: Option<Duration>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "kebab-case")]
    pub struct User {
        pub name: String,
        pub full_name: Option<String>,
        pub password: Option<StringOr<SecretRef>>,
        pub groups: Option<OneOrMany<String>>,
        pub password_never_expires: Option<bool>,
        #[serde(default)]
        pub reset_password: bool,
        pub state: Option<Presence>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SecretRef {
        pub secret: String,
    }

    /// One flat shape for every check kind, so a typo gets a precise "unknown field" error;
    /// the loader then checks that exactly one kind key is set and the options fit it.
    #[derive(Debug, Default, Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "kebab-case")]
    pub struct Check {
        pub process: Option<String>,
        pub service: Option<String>,
        pub eventlog: Option<EventLog>,
        pub port: Option<u16>,
        pub file: Option<String>,
        pub command: Option<String>,
        pub host: Option<String>,
        pub status: Option<ServiceState>,
        pub shell: Option<Shell>,
        pub stable_for: Option<Duration>,
        pub within: Option<Duration>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "kebab-case")]
    pub struct EventLog {
        pub provider: String,
        pub log: Option<String>,
        #[serde(default)]
        pub must_contain: Option<OneOrMany<String>>,
        #[serde(default)]
        pub must_not_contain: Option<OneOrMany<String>>,
        #[serde(default)]
        pub since: EventsSince,
    }

    /// `30s`, `2m`, `500ms`, or a bare number of seconds.
    #[derive(Debug, Deserialize)]
    #[serde(untagged)]
    pub enum Duration {
        Seconds(u64),
        Text(String),
    }

    #[derive(Debug, Deserialize)]
    #[serde(untagged)]
    pub enum OneOrMany<T> {
        One(T),
        Many(Vec<T>),
    }

    impl<T> Default for OneOrMany<T> {
        fn default() -> Self {
            OneOrMany::Many(Vec::new())
        }
    }

    impl<T> OneOrMany<T> {
        pub fn into_vec(self) -> Vec<T> {
            match self {
                OneOrMany::One(t) => vec![t],
                OneOrMany::Many(v) => v,
            }
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(untagged)]
    pub enum SourceRef {
        Short(String),
        Full { source: String, sha256: Option<String> },
    }

    /// `- git.git` is shorthand for a winget id.
    pub type App = StringOr<AppFull>;

    /// An entry written either as a bare string (the short form) or as a map. Unlike
    /// `#[serde(untagged)]`, a map that fails to parse keeps its own error ("unknown field
    /// `timout`") instead of a generic "did not match any variant".
    #[derive(Debug)]
    pub enum StringOr<T> {
        Short(String),
        Full(T),
    }

    impl<'de, T: Deserialize<'de>> Deserialize<'de> for StringOr<T> {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V<T>(std::marker::PhantomData<T>);
            impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for V<T> {
                type Value = StringOr<T>;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("a string or a map")
                }
                fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                    Ok(StringOr::Short(v.to_owned()))
                }
                fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                    T::deserialize(serde::de::value::MapAccessDeserializer::new(map)).map(StringOr::Full)
                }
            }
            d.deserialize_any(V(std::marker::PhantomData))
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct EnvFull {
        pub value: Option<String>,
        #[serde(default)]
        pub scope: EnvScope,
        pub state: Option<Presence>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct PathFull {
        pub dir: String,
        #[serde(default)]
        pub scope: EnvScope,
        pub state: Option<Presence>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    #[serde(rename_all = "kebab-case")]
    pub struct AppFull {
        pub id: String,
        pub version: Option<String>,
        pub url: Option<String>,
        pub sha256: Option<String>,
        pub args: Option<String>,
        pub timeout: Option<Duration>,
        #[serde(default)]
        pub prerelease: bool,
        #[serde(default)]
        pub upgrade: bool,
        pub state: Option<Presence>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct FileCopy {
        pub from: Option<String>,
        pub content: Option<String>,
        pub state: Option<Presence>,
        pub to: String,
        pub sha256: Option<String>,
        #[serde(default)]
        pub extract: bool,
        pub strip: Option<u32>,
        #[serde(default)]
        pub prerelease: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct RegistryValue {
        pub key: String,
        pub name: Option<String>,
        #[serde(rename = "type", default = "default_reg_type")]
        pub kind: RegistryType,
        pub value: Option<Scalar>,
        #[serde(default)]
        pub scope: Option<OneOrMany<HiveScope>>,
        pub state: Option<Presence>,
        pub via: Option<RegistryVia>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum RegistryVia {
        Registry,
        GroupPolicy,
    }

    fn default_reg_type() -> RegistryType {
        RegistryType::String
    }

    #[derive(Debug, Deserialize)]
    #[serde(untagged)]
    pub enum Scalar {
        Int(u64),
        Str(String),
        List(Vec<String>),
    }

    /// `- winget upgrade --all` is shorthand for a PowerShell command.
    pub type RunAction = StringOr<RunFull>;

    /// One flat shape for every kind of `run` entry, so a typo (`timout:`) is an "unknown
    /// field" error instead of being silently ignored; the loader then checks that exactly one
    /// of `command`, `script` and `plugin` is set and that the options fit it.
    #[derive(Debug, Default, Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "kebab-case")]
    pub struct RunFull {
        pub command: Option<String>,
        pub script: Option<String>,
        pub plugin: Option<String>,
        pub shell: Option<Shell>,
        pub args: Option<String>,
        pub sha256: Option<String>,
        pub with: Option<serde_json::Value>,
        pub timeout: Option<Duration>,
        #[serde(default)]
        pub always: bool,
    }
}
