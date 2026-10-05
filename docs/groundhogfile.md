# Groundhogfile reference

A Groundhogfile is YAML (`.yaml`/`.yml`, or no extension) or JSON (`.json`). Unknown keys are
errors, so typos fail at load time instead of being ignored.

Steps run in this order: `users`, `certificates`, `defender-exclusions`, `features`,
`capabilities`, `remove-apps`, winget bootstrap (if any winget apps), `apps`, `files`, `env`,
`path`, `registry` (with `uac`), `desktop`, `services`, `firewall`, `run`, then the `verify` checks.

**Removing things.** Most entries take `state: absent` (the default is `present`): an app is
uninstalled, a file or folder deleted, an env var, PATH entry, registry value or key, user,
certificate, firewall rule or Defender exclusion removed. Deleting an entry from a Groundhogfile
leaves the machine as it is; to take something back, say `state: absent`. A file that
`extends` another can do that for anything the base added.

## Previewing: `plan --check`

`groundhog-agent plan <file> --check` looks at this machine and says, step by step, what
`apply` would do, without changing anything:

```
  9. [1c3ec175f551f30b] ok     ensure winget is available
 10. [4fcd80fd8de0ff0b] change install jqlang.jq 1.7.1 (winget)
 17. [575a6e94dfa43102] change service Spooler: disabled, stopped
 20. [48a63590bffe7213] run    verify C:\ghtools\config.json exists
18 change, 1 run, 1 ok
```

`ok` means already so, `change` that applying would change it, `run` a command or check (they
always run), `done` a step an earlier `apply` recorded (it's skipped), and `?` that it can't
tell without doing it (a direct installer, a zip to unpack over an existing folder). Steps that
use secrets show as `?` unless the check is given them (`--secrets-file`).

## When steps run again

The agent records every step it finishes. On the next `apply` it runs only steps that are new
or different, so the rules for "different" matter:

- **Declarative steps** (`apps`, `files`, `env`, `path`, `registry`) are identified by their own
  definition, **including the content they fetch**. They're independent of each other.
- **`run` steps work like Docker layers.** A `run` step's identity also covers every step before
  it. When anything earlier changes, that `run` step and every later one run again.
- **`verify` checks run on every apply**, changed or not, because they describe health rather
  than changes.
- **Pinned vs. latest.** A reference with `sha256` is pinned: it always means those exact bytes,
  and it can come from a cache. A reference without `sha256` **follows whatever the URL serves
  now**. The agent fetches it while loading the file, and a new build makes the step run again.
  `plan` and the logs show what it resolved to, such as `copy app.zip -> C:\app.zip @3f2a9c1e`.
  The same applies to local files and folders, so editing a local script reruns it.

So this downloads, unpacks and reinstalls on every apply after a new release, does nothing
otherwise, and checks the result every time:

```yaml
files:
  - from: https://github.com/owner/repo/releases/latest/download/app.zip
    to: C:\app\current
    extract: true
run:
  - C:\app\current\install.ps1
verify:
  - process: app
    stable-for: 8s
```

Because unpinned references are fetched at load time, `plan` needs network access for them,
and a broken link fails before anything changes. If a "latest" URL moves on between loading and
the step running, the step fails rather than installing a build you didn't plan.

## `version`

```yaml
version: 1
```

Optional. An agent refuses files that need a newer version than it supports.

## `agent`

```yaml
agent: ">=0.5.0"
```

Optional: the oldest `groundhog-agent` that understands this file. Set it when you use a
feature added in a later release. An older agent that reads the file then says exactly that,
"this Groundhogfile needs groundhog-agent 0.5.0 or newer", instead of failing on a key it
doesn't know. With [agent updates](templates.md#keeping-the-templates-agent-current) on, it
will usually have updated itself before reading the file. The highest `agent:` across `extends`
applies. Agents older than 0.5.0 don't know this key and reject it.

## `extends`

```yaml
extends: ../base.groundhog.yaml
# or several, applied in order, each optionally pinned:
extends:
  - https://example.com/base.yaml
  - source: https://example.com/dotnet.yaml
    sha256: 3e02260a...
```

Bases load first and this file is layered on top:
- An **app** with the same id (case-insensitive) replaces the base's.
- A **file** with the same destination replaces the base's.
- A **registry value** with the same key and name replaces the base's.
- **env** vars override.
- **path** entries are added if not already present.
- **run** actions and **verify** checks accumulate (base first).

Cycles are detected.

### The built-in library

`groundhog:NAME` names a ready-made Groundhogfile from Groundhog's own
[`library/`](../library) folder. Extend one and add your own on top, or apply one as it is:

```yaml
extends: groundhog:windows-internals
apps:
  - Microsoft.VisualStudioCode
```

```powershell
groundhog-agent apply groundhog:windows-internals
```

It's the library as of the agent's release, so it never needs a newer agent than the one
reading it, and it changes only when the agent does (the template's agent keeps itself
current). `groundhog:NAME@main` follows the latest library instead, and
`groundhog:NAME@v0.10.0` pins one release. The files are plain Groundhogfiles on GitHub, so a
machine that can't reach GitHub can use a copy from your own share by path instead.

| Name | What it sets up |
| --- | --- |
| `windows-internals` | All of the below. |
| `sysinternals` | Sysinternals Suite in `C:\Program Files\Sysinternals`, on the machine PATH, EULA accepted (also for SYSTEM). |
| `windbg` | WinDbg. |
| `debuggers` | Debugging Tools for Windows (`cdb`, `kd`, `gflags`, `umdh`, `symchk`, `dbgsrv`, …) from the Windows SDK, on the machine PATH. |
| `ttd` | Time Travel Debugging's recorder, `TTD.exe`. |
| `wpt` | Windows Performance Toolkit (WPR, WPA, xperf) from the Windows ADK. |
| `dotnet-diag` | .NET 10 SDK with `dotnet-dump`, `dotnet-gcdump`, `dotnet-trace` and `dotnet-counters`. |
| `symbols` | Machine-wide `_NT_SYMBOL_PATH` for Microsoft's symbol server, cached in `C:\Symbols`. |
| `crash-dumps` | Full dumps of crashing programs in `C:\CrashDumps`; kernel dumps kept. |
| `explorer-dev` | Explorer shows extensions, hidden and system files, and full paths. |
| `quiet-windows` | No "finish setting up your device", Microsoft account or backup nags, no tips, suggestions or ads in Start, Settings, Explorer and the lock screen, no widgets, no feedback prompts, no silently installed apps, no web results in Start search. For this user and new ones. Not part of `windows-internals`. |
| `time-sync` | Windows Time runs at boot, corrects even a large error in one go, and is checked against time.windows.com. Not part of `windows-internals`. Needs outbound NTP (UDP 123). |

## Conditions and variables

```yaml
vars:
  port: "8791"
  tools: C:\Tools

firewall:
  - name: Deskhand
    port: ${var:port}
path:
  - ${var:tools}\bin
  - C:\Program Files (x86)\Windows Kits\10\Debuggers\${var:arch}
apps:
  - id: Vendor.ArmBuild
    when: { arch: arm64 }             # only on ARM64 machines
  - id: Vendor.NewThing
    when: { build: ">=26100", os: client }
env:
  LEGACY_MODE:
    value: "1"
    when: { build: "<22000" }
```

**`when:`** on any list entry, or an `env` value, keeps it only on machines that match every
condition: `arch` (`x64`, `arm64`, `x86`, or a list), `build` (the Windows build number, exact
or with `>=`, `<=`, `>`, `<`), `os` (`client` or `server`). An entry that doesn't match is left
out, as if it weren't written.

**`${var:NAME}`** works in any string. Values come from, strongest first:
1. the caller: `groundhog-agent apply … --var port=9000`, or `vars` in `pending.json`
   (`groundhog pending … --var port=9000`), for per-machine values;
2. `vars:` in the file being applied;
3. `vars:` in the files it `extends`, so a library can declare a default its users override;
4. built in: `${var:arch}`, `${var:build}`, `${var:os}` (reserved names).

An unknown variable is a load error. `$${var:` writes a literal `${var:`. Files that use
neither `when` nor variables are read exactly as before, with line numbers in their errors.

## `users`

```yaml
users:
  - name: tester
    full-name: UI Test User            # optional
    password: { secret: TESTER_PASSWORD }
    groups: [Remote Desktop Users]     # added to these; other memberships are left alone
  - name: svc-agent
    password: generate                 # random, known to nobody (also the default)
    password-never-expires: true       # the default: Windows' 42-day expiry would break unattended logons
  - name: old-tester
    state: absent                      # delete the account (its profile folder stays)
```

Local accounts, created if missing. An existing account is brought in line (groups, password
expiry), but **its password is left alone** unless `reset-password: true` is set. Account
names follow Windows' rules: up to 20 characters, none of `" / \ [ ] : ; | = , + * ? < > @`.

Built-in groups can be given by their English names (`Administrators`, `Users`,
`Remote Desktop Users`, `Remote Management Users`, …) on any Windows display language; they're
resolved by their fixed SIDs, so `Administrators` still works where the group is called
`Administratoren`. Other names are used as given. Creating accounts needs the agent elevated.

## Secrets

**A secret never goes in a Groundhogfile.** Files are shared, cached and logged. Name it
instead, as `${secret:NAME}`, and supply the value when the file is applied. A password is
`generate`d or named the same way (`password: ${secret:NAME}`, or `{ secret: NAME }`).
References work in these places:

```yaml
files:
  - to: C:\ProgramData\Deskhand\deskhand.json
    content: |                              # inline file content
      { "token": "${secret:DESKHAND_TOKEN}", "port": 8791 }
env:
  OPENAI_API_KEY: ${secret:OPENAI_KEY}      # user-scope env values
registry:
  - key: HKCU\Software\Tool
    name: ApiKey
    value: ${secret:TOOL_KEY}               # string, expand-string and multi-string values
run:
  - command: Connect-Thing -Token "${secret:API_TOKEN}"
  - script: setup.ps1
    args: -Key ${secret:SETUP_KEY}
```

- **Only there.** A reference anywhere else (`to`, app `args`, plugin `with`, paths) is a load
  error, so it can't reach the machine as literal text. So is a machine-scope env value, which
  every account can read.
- **In `run` commands the value isn't spliced into the script.** The reference becomes an
  environment variable the command gets, `${env:GROUNDHOG_SECRET_NAME}` in PowerShell or
  `%GROUNDHOG_SECRET_NAME%` in cmd. That keeps it off the command line, where process
  listings and command-line auditing see it, and a value with quotes in it can't break or
  inject into the script. Write the reference where a variable expands: bare or inside double
  quotes, **not inside single quotes**. Script `args` are a command line by nature, so there the
  value is filled in as text; a script can read `$env:GROUNDHOG_SECRET_NAME` instead.
- **Never shown.** `plan`, step titles, `status.json` and the agent's state only ever contain
  `${secret:NAME}`. Values are scrubbed (as `***`) from every log line and error message,
  including a program's own output. Values shorter than 4 characters can't be scrubbed
  reliably, so a reference to one is refused.
- **Rotation works.** A step that uses a secret runs again when the value changes, and only
  then. Its identity includes a salted hash of the value; the salt is random per machine and
  kept encrypted, so the stored ids can't be used to test guesses.
- **Missing values stop the run before it starts**, naming every missing secret. (An account's
  password is only needed when the account is created or reset.)
- `$${secret:` writes a literal `${secret:`.
- **Declare `agent: ">=0.12.0"`** in a file that uses references. Older agents don't know them
  and would write the text `${secret:NAME}` itself into env, registry or commands; with the
  requirement they stop and say they need updating (and update themselves from
  `pending.json`).

Values are supplied when the file is applied:

| Where | How |
| --- | --- |
| `pending.json` (templated VMs) | `"secrets": { "TESTER_PASSWORD": "…" }`, written by `groundhog pending --secret TESTER_PASSWORD` (the value comes from the `TESTER_PASSWORD` environment variable, which keeps it off the command line) or `--secret NAME=value` |
| Environment | `GROUNDHOG_SECRET_TESTER_PASSWORD` |
| A file | `groundhog-agent apply … --secrets-file secrets.json` with `{ "TESTER_PASSWORD": "…" }` |

The agent takes secrets out of `pending.json` as soon as it reads it. They're never logged or
recorded in state. If a run pauses for a restart, they're kept until it finishes, encrypted
with DPAPI so only the same account on the same machine can read them, and then deleted.
`plan` lists the secrets a file needs and whether each one is provided.

### Authenticated downloads and report sinks

`--header` (and `headers` in `pending.json`) attaches a header to every request to one host:
downloads from it, and status POSTs to an `http(s)` `--report` sink on it. A header's value
can be a secret, so a token travels with the secrets rather than in plain text:

```powershell
groundhog pending https://cfg.example/dev.yaml --report https://status.example/vm42 `
  --header "status.example=Authorization: Bearer `${secret:STATUS_TOKEN}" --secret STATUS_TOKEN
```

## `certificates`

```yaml
certificates:
  - from: certs/corp-root.cer          # .cer/.crt, DER or PEM; a path or URL, like `files`
  - from: https://pki.example/issuing.crt
    store: ca                           # root (default) | ca | my | trusted-people | trusted-publisher | disallowed
  - from: certs/legacy-root.cer
    state: absent                       # remove it again
  - thumbprint: 1A2B3C...               # or remove one by its SHA-1 thumbprint
    store: root
    state: absent
```

Public certificates, for trusting an internal CA or a test signer. They go in the machine's
stores (`scope: machine`, the default); `scope: user` works for every store except `root`,
where Windows insists on an on-screen confirmation. Certificates run early, before installers
that may download from an internal server; the agent's *own* downloads happen before any step,
so a template that fetches from an internal HTTPS server needs the CA baked in.

## `defender-exclusions`

```yaml
defender-exclusions:
  - C:\src                              # a path (a string is a path)
  - process: devenv.exe
  - extension: .obj
  - { path: C:\old, state: absent }
```

Folders, processes and file types Microsoft Defender's real-time scanning leaves alone, which
can make builds and big unpacks much faster. `%VARS%` are expanded. When Defender isn't the
active antivirus, these steps do nothing and say so. Needs the agent elevated.

## `features` and `capabilities`

Windows optional features (`Microsoft-Windows-Subsystem-Linux`, `VirtualMachinePlatform`,
`NetFx3`, `IIS-WebServerRole`, …) and capabilities, also called Features on Demand
(`OpenSSH.Server`, `Rsat.*`, …).

```yaml
features:
  - Microsoft-Windows-Subsystem-Linux          # short form: enable it
  - name: NetFx3
    source: \\nas\media\26100\sources\sxs       # a folder or share with the payload; one or a list
    limit-access: true                          # never ask Windows Update
    timeout: 30m
  - name: IIS-WebServerRole
    all: true                                   # the default: enable the features it depends on
  - name: SMB1Protocol
    state: disabled                             # enabled (default) | disabled
    remove-payload: true                        # disabled only: also delete its files

capabilities:
  - OpenSSH.Server                              # short for OpenSSH.Server~~~~0.0.1.0
  - name: Language.Basic~~~de-DE~0.0.1.0        # other versions: write the full name
    source: \\nas\fod\26100-amd64
    limit-access: true
  - name: App.StepsRecorder
    state: removed                              # present (default) | removed
```

They run right after `users` and before `apps`, because apps often need them (WSL or
`VirtualMachinePlatform` for Docker, `NetFx3` for older installers), and their restarts are
best taken before long installs.

- **Live state first:** every step checks the feature's current state and does nothing if it's
  already right, so it's safe on templates where someone already enabled it.
- **One restart for the lot:** a feature that finishes only after a restart doesn't restart
  the machine right away. The agent finishes the rest of the features and capabilities first,
  then restarts once and continues.
- **Pending servicing:** if Windows is already waiting for a restart from earlier servicing,
  the step restarts first and then runs.
- **Names are exact** and differ between client and Server Windows (`Microsoft-Hyper-V-All` vs
  `Microsoft-Hyper-V`). `dism /online /get-features` and `dism /online /get-capabilities` list
  them. A capability name without `~` gets the usual version, `~~~~0.0.1.0`.
- **Where payloads come from:** without `source:`, Windows gets anything it doesn't have on
  disk (`NetFx3`, most capabilities) from **Windows Update**, or from WSUS / Windows Update for
  Business when the machine is managed. That needs nothing from you but internet access, but
  it's slow: on a fresh Windows 11 VM, `NetFx3` and `OpenSSH.Server` each took about half an
  hour, mostly spent working out which parts of the Features on Demand catalog apply. That's a
  good reason to [bake them into the template](templates.md#baking-a-base-layer), or to give
  a local `source:`.
  `source:` is for machines that can't do that (offline, or WSUS without the payloads, error
  `0x800F0954`): a folder or share with the `sources\sxs` folder of install media for this
  exact Windows build (for `NetFx3`), or an unpacked Features on Demand repository
  ("Languages and Optional Features" ISO). A relative path works when the Groundhogfile is a
  local file. A source can also be:
  - a **`.iso`** (a path or an `http(s)` URL): mounted for the step, and its root,
    `sources\sxs` and `LanguagesAndOptionalFeatures` folders offered to Windows;
  - a **`.zip`** (a path or URL): unpacked once into the agent's work folder;
  - any **`http(s)` URL** to one of those: downloaded straight to disk (streamed, so a
    multi-gigabyte repository never sits in memory) and reused from the agent's object store.
- **Needs the agent elevated.** Not supported inside Windows Sandbox (the step fails
  immediately with that explanation).

Common failures, and what the error suggests:

| Code | Meaning |
| --- | --- |
| `0x800F080C` | No feature or capability by that name on this edition. |
| `0x800F081F` | The payload wasn't found: give `source:`, or allow Windows Update. |
| `0x800F0954` | A WSUS policy blocks the download: give `source:` with `limit-access: true`. |
| `0x800F0906`, `0x800F0907` | Download from Windows Update failed or is blocked. |

Details are in `%ProgramData%\groundhog\work\dism.log` and `C:\Windows\Logs\CBS\CBS.log`.

## `remove-apps`

```yaml
remove-apps:
  - Microsoft.BingNews              # package names, as Get-AppxPackage shows them
  - Clipchamp.*                     # wildcards work
```

Built-in Store apps are removed for every existing user and unprovisioned, so profiles created
later don't get them either. Removal runs before `apps`.

## `apps`

```yaml
apps:
  - Git.Git                         # winget id
  - id: Microsoft.DotNet.SDK.10
    version: 10.0.100               # stay on exactly this version (up or down)
    args: --scope machine           # extra winget arguments, verbatim
  - id: BurntSushi.ripgrep.MSVC
    upgrade: true                   # upgrade whenever a newer version is out
  - id: Old.Tool
    state: absent                   # uninstall it
  - id: internal-tool               # a direct installer
    url: https://files.example.com/tool.msi
    sha256: <64 hex>                # pin a build (and allow caching); omit to follow latest
    args: ADDLOCAL=ALL              # installer arguments, verbatim
```

**winget apps**, as `winget list --id <id> --exact` sees them:
- Without `version`, an installed app is left as it is.
- With `version`, a different installed version is replaced with that one, up or down.
- With `upgrade: true`, the app is upgraded whenever winget has a newer version; that step
  runs on every apply. (`version` and `upgrade` don't go together.)
- With `state: absent`, it's uninstalled. A package installed per user (portable tools such
  as ripgrep or jq usually are) can't be uninstalled by an elevated process, which the agent
  is; the agent then retries as the same user, unelevated, through a one-off scheduled task.

If winget is missing, the agent installs it first (via the `Microsoft.WinGet.Client` PowerShell
module). Direct installers can't be uninstalled with `state: absent` (they don't say how); use a
`run` step with the vendor's uninstaller.

**URL apps** support:

| Type | How it's run |
|---|---|
| `.msi` | `msiexec /i … /qn /norestart` |
| `.msix`, `.msixbundle`, `.appx`, `.appxbundle` | `Add-AppxPackage` |
| `.exe` | run with `args` (pass the installer's own silent switch) |

Exit code 3010 or 1641 means a restart is needed.

## `files`

```yaml
files:
  - from: config/.gitconfig          # relative to this Groundhogfile
    to: ~/.gitconfig                 # ~ and %VARS% are expanded on the target
  - from: config/vscode              # a local directory is copied recursively
    to: '%APPDATA%\Code\User'
  - from: https://example.com/profile.ps1
    to: ~/Documents/PowerShell/Microsoft.PowerShell_profile.ps1
    sha256: <64 hex>
  - to: C:\ProgramData\Tool\config.json
    content: |                       # or the text itself, written as UTF-8
      { "endpoint": "https://api.example", "key": "${secret:TOOL_KEY}" }
  - to: C:\Tools\old-version
    state: absent                    # delete a file, or a folder and everything in it
```

A file whose contents already match is left alone. `content` can hold
[secret references](#secrets); `from` files are copied as they are. Downloads stream to disk,
so a file of any size is fine.

`state: absent` refuses a drive root and the folders Windows depends on (`C:\Windows`,
`C:\Program Files`, `C:\Users`, the user profile, `ProgramData`, …), so a typo in `to` can't
take out the machine.

### Unpacking archives

```yaml
files:
  - from: https://example.com/releases/latest/download/app.zip
    to: C:\app\current               # a folder
    extract: true
```

With `extract: true`, `from` must be a `.zip`, and `to` is the folder it unpacks into. The
folder is **replaced as a whole**: files the new archive doesn't contain are removed, and a
failure never leaves a half-unpacked mix. The agent unpacks next to the folder and then swaps
it in. A program still running from the old folder keeps working from a renamed copy, which is
removed once it's no longer in use. If a file in the folder is held open in a way that blocks
the swap, the step fails before anything changes.

`strip: 2` drops that many leading folders from every path in the zip, the way
`tar --strip-components` does. GitHub source archives wrap everything in a folder named after
the version (`findneedle-1.0.267\`); `strip: 1` removes it, so paths stay the same across
versions.

### Files from GitHub releases

```yaml
files:
  - from: github:guscatalano/findneedle@latest/release.zip   # an asset of the newest release
    prerelease: true                                         # count prereleases as "newest"
    to: C:\fn\app
    extract: true
  - from: github:guscatalano/findneedle@latest/source        # that same release's source code
    prerelease: true
    to: C:\fn\src
    extract: true
    strip: 1
```

`github:OWNER/REPO@REF/ASSET` asks GitHub's releases API for a release: `@latest`, or a tag
such as `@1.0.267`. `ASSET` is an asset's file name, or `source` for the release's source code
as a zip. This works in `files:` and in `apps:` (`url: github:…`).

- **Consistent:** each release is looked up once per load, so every `@latest` in a file (an
  app and the source of its tests, say) resolves to the same release.
- **Prereleases:** GitHub's own "latest" ignores prereleases. A repository that only publishes
  prereleases has no latest release until you add `prerelease: true`, and the error says so.
- **Verified without downloading:** when GitHub publishes an asset's SHA-256 (its digest), that
  becomes the pin. The download is checked against it and can come from a cache, and `plan`
  knows the build without downloading it. Source archives have no published digest, so they're
  resolved by content like any other unpinned download.
- **Readable:** `plan` and the logs show the release tag, as in
  `copy release.zip -> C:\fn\app @1.0.267`.
- **Rate limits:** unauthenticated API calls are limited to 60 an hour per IP address. For
  more, pass a token for the API host:
  `--header "api.github.com=Authorization: Bearer <token>"`.

## `env` and `path`

```yaml
env:
  DOTNET_CLI_TELEMETRY_OPTOUT: "1"
  TOOLS: '%USERPROFILE%\tools'        # stored as REG_EXPAND_SZ when it contains %
  _NT_SYMBOL_PATH:                    # machine-wide: every account and service sees it
    value: srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
    scope: machine
  OLD_SETTING: { state: absent }      # remove a variable
path:
  - C:\tools\bin
  - dir: C:\Program Files\Sysinternals
    scope: machine
  - { dir: C:\old\bin, state: absent }   # take one folder out; the rest stays as it is
```

By default these are the agent user's own variables (`HKCU\Environment`). `scope: machine`
writes the system environment instead, which every account, service and SYSTEM starts with;
that needs the agent elevated. `path` entries are appended if missing and otherwise never
reordered, and a machine PATH that can't be read is left alone rather than rewritten.
`env: PATH` with `scope: machine` is refused, since it would replace the whole system PATH.

Running programs are notified of the change, but a program that's already running keeps the
environment it started with: one that needs a new PATH entry must be restarted, or re-read
it from the registry.

**A folder on the machine PATH must be writable only by administrators**, such as one under
`C:\Program Files`. If ordinary users can write to it (a new folder directly under `C:\`
usually can be), any of them can plant a program that administrators and services then run.

## `registry`

```yaml
registry:
  - key: HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced
    name: HideFileExt                # omit for the key's default value
    type: dword                      # string (default), expand-string, multi-string, dword, qword
    value: 0                         # numbers may also be "0x10"
    scope: [current-user, default-user]
  - key: HKCU\Software\Vendor\Tool
    name: Telemetry
    state: absent                    # delete one value
  - key: HKCU\Software\Vendor\OldTool
    state: absent                    # no name: delete the key and everything under it
```

Roots: `HKCU`, `HKLM`, `HKCR`, `HKU` (or their long names). Deleting a whole key is refused
within two levels of a hive's root (`HKLM\SOFTWARE` itself, say).

`scope` applies only to `HKCU` keys:
- `current-user` (default): the account the agent runs as.
- `default-user`: `C:\Users\Default\NTUSER.DAT`, so profiles created **later** get the value
  too. Requires the agent to run elevated.

**`via: group-policy`** writes an `HKLM` value through the machine's local Group Policy, as
gpedit would: into `%SystemRoot%\System32\GroupPolicy\Machine\Registry.pol`, then applied with
`gpupdate`. Use it for policy keys Windows guards against programs, which refuse direct
writes even from administrators ("Access is denied" for a key Administrators have full control
of), such as `HKLM\SOFTWARE\Policies\Microsoft\Dsh`. `state: absent` takes the value out of
the local policy, and Group Policy removes it. A domain policy that sets the same value wins.

```yaml
registry:
  - key: HKLM\SOFTWARE\Policies\Microsoft\Dsh
    name: AllowNewsAndInterests
    type: dword
    value: 0
    via: group-policy
```

## `desktop`

```yaml
desktop:
  theme: dark                       # dark | light, or { apps: dark, windows: light }
  wallpaper: images/lab.jpg         # a picture: a path or URL, like `files` (or { from, sha256 })
  wallpaper-style: fill             # fill (default) | fit | stretch | tile | center | span
  background: "#203040"             # solid color: alone, or around a fit/center picture
  lock-screen:                      # for the whole machine
    image: images/lock.jpg          # a picture, like `wallpaper`
    lock-after: 15m                 # lock after this much idle time, for every account
  screen-saver:
    timeout: 10m                    # start after this much idle time (at least 1m)
    secure: true                    # resuming needs a sign-in
    program: blank                  # blank (default) | bubbles | mystify | ribbons | photos | 3d-text | a .scr path
    # enabled: false                # or turn it off
  taskbar:
    alignment: left                 # left | center
    search: icon                    # hidden | icon | box | icon-and-label
    task-view: false
    widgets: false                  # for the whole machine
    pins: [file-explorer, terminal, edge]   # replaces Windows' own taskbar pins
    pins-for: everyone              # everyone (default) | new-accounts
  start:
    recommendations: false          # tips, shortcuts and new apps
    recommended-files: false        # recent files in Start and Explorer, jump lists
    most-used-apps: false
    account-notifications: false
  scope: [current-user, default-user]
```

The light or dark mode (for apps, and for Windows itself: taskbar, Start), the desktop
picture, and the solid background color. For the account the agent runs as they take effect
at once, as when changed in Settings; `default-user` sets them for profiles created later.
The picture is copied to `%ProgramData%\groundhog\desktop`, where every account can read it,
and `groundhog-agent clean` leaves it there, so a template's wallpaper survives sealing.

The **lock screen** settings are machine-wide (`scope` doesn't apply): the picture every
account sees at sign-in, written where the Personalization CSP (Intune, MDM) writes it, and
the idle time after which Windows locks ("Interactive logon: Machine inactivity limit"). The
**screen saver** is per user, like the wallpaper.

The **taskbar** and **Start** settings are the switches in Settings → Personalization, per
user like the wallpaper; for the agent's own account the taskbar changes at once. `widgets:
false` is the machine policy that turns widgets off (Windows doesn't let programs flip the
per-user switch); `widgets: true` lifts that policy, leaving the choice to each user.

**Taskbar pins** replace the apps Windows pins. Each is one of:
- a short name: `file-explorer`, `edge`, `terminal`, `notepad`, `paint`, `settings`, `store`,
  `calculator`;
- an app id, as `Get-StartApps` lists them: `Microsoft.WindowsTerminal_8wekyb3d8bbwe!App`,
  `MSEdge`;
- a shortcut: `%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Visual Studio Code.lnk`.

With `pins-for: everyone` they're the Start layout policy: every account gets them at its
next sign-in (not at once, even for the agent's own account), and existing accounts too.
`new-accounts` writes them to the Default profile instead: accounts created later start with
them and may change them, and existing accounts are left alone. `scope` doesn't apply to pins.

**Start's pinned apps can't be set.** Windows 11 takes them only from MDM (Intune and the
like): it ignores the same pin list written as a policy or into the Default profile, and
refuses programs that try to pin or unpin. Groundhog sets what Start shows besides the pins.

A later file overrides an earlier one setting by setting: a file that extends a base with
`theme: light` can say `theme: { windows: dark }` and keep the base's light apps.

## `uac`

```yaml
uac:
  level: default              # always-notify | default | no-dim | never-notify (the Control Panel slider)
  admin-prompt: consent       # how administrators are asked; overrides the level's choice
  user-prompt: credentials    # deny | credentials-on-secure-desktop | credentials
  secure-desktop: true        # dim the screen for the prompt; overrides the level's choice
  # enabled: false            # turn UAC off entirely (see below)
```

User Account Control policy, for the whole machine. Each setting is optional, and each is
the Group Policy setting of the same name under "User Account Control" (security options):

| Setting | Value | Values |
|---|---|---|
| `admin-prompt` | ConsentPromptBehaviorAdmin | `elevate-without-prompting`, `credentials-on-secure-desktop`, `consent-on-secure-desktop`, `credentials`, `consent`, `consent-for-non-windows-binaries` (Windows' default) |
| `user-prompt` | ConsentPromptBehaviorUser | `deny`, `credentials-on-secure-desktop`, `credentials` |
| `secure-desktop` | PromptOnSecureDesktop | `true`, `false` |
| `enabled` | EnableLUA | `true`, `false` |

`level` sets `admin-prompt` and `secure-desktop` as the slider does: `always-notify` is
consent on the secure desktop; `default` asks for consent for programs that aren't part of
Windows, on the secure desktop; `no-dim` is the same without the secure desktop;
`never-notify` elevates without asking.

They're written as registry values under
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` (so `plan` shows them as
registry steps), and a later file overrides an earlier one setting by setting. The prompt
settings take effect at once. **`enabled: false` takes effect only after a restart**, and
it does more than silence prompts: every administrator then runs everything with full rights,
and Store apps and Edge stop working. `never-notify` is almost always what's wanted instead,
and on a disposable test VM it is what lets automation click through elevation.

## `services`

```yaml
services:
  - name: Spooler                  # the service name (or its display name)
    startup: disabled              # automatic | delayed | manual | disabled
    status: stopped                # running | stopped
  - name: MyAgentSvc
    status: running
```

Brings an existing service's start type and state in line; at least one of them is needed.
Stopping a service also stops the services that depend on it. Services run after `apps` (which
often install them) and before `run`; a service a `run` step creates is that step's business.

## `firewall`

```yaml
firewall:
  - name: Deskhand                 # the rule's name: how it's found again
    port: 8791                     # or "8000-8100", or [80, 443]; omit for any port
    protocol: tcp                  # tcp (default) | udp | any
    direction: in                  # in (default) | out
    action: allow                  # allow (default) | block
    program: '%ProgramFiles%\Deskhand\deskhand.exe'   # optional
    profile: [domain, private]     # any (default) | domain | private | public
    remote: LocalSubnet            # optional: addresses or ranges, one or a list
  - name: Old rule
    state: absent
```

Windows Firewall rules, created in a `Groundhog` group. A rule is found by its name; one that
doesn't match what's written (or that someone edited) is replaced, and one that does is left
alone. Ports are local for inbound rules and remote for outbound ones.

## `run`

```yaml
run:
  - git config --global init.defaultBranch main    # shorthand: Windows PowerShell command
  - command: echo hi
    shell: cmd                                     # powershell (default), pwsh, cmd
  - script: scripts/setup.ps1                      # fetched, then run from a local copy
    args: -Mode Full
    sha256: <64 hex>
  - plugin: plugins/configure-thing.exe            # see below
    with: { any: [structured, data] }
  - command: dotnet test C:\src\Tests.csproj
    timeout: 30m                                   # stop it (and everything it started) after 30 minutes
    always: true                                   # run on every apply, not only when something changed
```

`timeout` works on every kind of `run` entry and on `apps` (`timeout: 20m`). When it's reached,
the step and **every process it started** are stopped, and the step fails with its last few
lines of output. Without a timeout, a hung installer or build would stall an unattended VM
forever.

`always: true` runs the step on every apply. Normally a finished step is skipped until
something about it changes; this is for steps whose point is to run each time, such as a test
suite.

Unknown keys in a `run` entry are errors (`timout:` is reported, not ignored), and each entry
must set exactly one of `command`, `script` or `plugin`.

For commands and scripts, exit code 0 means success, 3010 means a restart is needed, and anything
else fails the step. A script's shell comes from its extension (`.ps1`, `.cmd`/`.bat`, `.exe`)
unless `shell` is set (`direct` runs the file itself).

For inline PowerShell commands, if the last statement is a program that fails, its own exit code
is kept. So a final `msiexec …` or `cmd /c …` that returns 3010 asks for a restart, instead of
PowerShell reducing it to 1. `.ps1` scripts run with `-File` and report whatever they `exit`
with; end them with `exit $LASTEXITCODE` to pass a program's code through.

Each `run` entry is a separate process, so `$ErrorActionPreference` and variables don't carry
over between entries. If a multi-line command starts with a `# comment`, the comment becomes the
step's name in `plan` and the logs. That works for every shell: with `shell: cmd`, those
leading `#` lines are left out of what cmd runs, and a multi-line command runs as a batch file,
so every line runs (`cmd /c` alone would only run the first).

Environment variables from `env:` and `path:` are stored for the user, and running programs are
told about the change. But a process that was **already running** keeps the environment it
started with, and so does everything it starts later. A remote command runner or agent service
started before the apply won't see the new values. Set the variable in that command itself when
it matters (`$env:NAME = '…'; …`).

### Plugins

A plugin is any executable that speaks this protocol:

1. The agent writes one JSON request to the plugin's stdin:
   ```json
   { "protocol": 1, "action": "apply", "with": { ... }, "workDir": "C:\\..." }
   ```
2. The plugin prints one JSON response to stdout:
   ```json
   { "ok": true, "changed": true, "rebootRequired": false, "message": "optional" }
   ```
3. stderr is copied to the agent's log.

Plugins can be written in any language. They're the extension point for anything the built-in
steps don't cover, such as a C# helper for late-bound COM.

## `verify`

Health checks. They run after everything else **on every apply**, and a failed check fails the
apply, with its reason in the log and status. Each check retries until it passes or `within`
runs out (default `30s`), so there's no need for `Start-Sleep` before a check.

```yaml
verify:
  - process: rdpeek-agent          # image name; .exe optional
    stable-for: 8s                 # one PID must stay alive this long (catches crash loops)
    within: 1m
  - service: RdpeekAgentSvc
    status: running                # running (default) or stopped
  - eventlog:
      provider: RdpeekAgentSvc
      log: Application             # default
      must-not-contain: '0xC0000142'   # one string or a list
      must-contain: '(startup, Native)'  # optional; waits up to `within` for it to appear
      since: apply                 # apply (default): only events from this run; any: whole log
    within: 1m                     # like every check (default 30s)
  - port: 3389                     # something accepts TCP connections
    host: 127.0.0.1                # default
  - file: C:\rdpeek\bundle\rdpeek-agent.exe
  - command: |
      # anything else: passes when it exits 0
      if ([version](Get-Item C:\app\app.exe).VersionInfo.FileVersion -lt [version]'2.0') { exit 1 }
    shell: powershell              # default; also pwsh, cmd
```

A `command` check passes on exit code 0, and PowerShell exits 0 even when an expression
evaluates to `$false`. So a bare comparison always passes; `exit 1` (or `throw`) explicitly
when the check should fail.

Durations can be written like `30s`, `2m` or `500ms`; a bare number means seconds. Each check
has exactly one kind (`process`, `service`, `eventlog`, `port`, `file`, `command`), and options
that don't apply to that kind are an error.

Event log matching is a case-insensitive substring test against each event's rendered message
and its data fields, so it works for providers without a message file and on any Windows
display language. No events, or a provider that has never logged anything, count as "contains
nothing": a `must-not-contain` check passes. A `must-contain` pattern is waited for, up to
`within`, because a service may log "started" a moment after its process appears. A
`must-not-contain` match fails the check at once.
