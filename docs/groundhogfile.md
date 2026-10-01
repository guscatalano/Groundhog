# Groundhogfile reference

A Groundhogfile is YAML (`.yaml`/`.yml`, or no extension) or JSON (`.json`). Unknown keys are
errors, so typos fail at load time instead of being ignored.

Steps run in this order: `users`, `features`, `capabilities`, winget bootstrap (if any winget
apps), `apps`, `files`, `env`, `path`, `registry`, `run`, then the `verify` checks.

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
```

Local accounts, created if missing. An existing account is brought in line (groups, password
expiry), but **its password is left alone** unless `reset-password: true` is set. Account
names follow Windows' rules: up to 20 characters, none of `" / \ [ ] : ; | = , + * ? < > @`.

Built-in groups can be given by their English names (`Administrators`, `Users`,
`Remote Desktop Users`, `Remote Management Users`, …) on any Windows display language; they're
resolved by their fixed SIDs, so `Administrators` still works where the group is called
`Administratoren`. Other names are used as given. Creating accounts needs the agent elevated.

### Secrets

**A password never goes in a Groundhogfile.** Files are shared, cached and logged. A password
is either `generate`d or named, `{ secret: NAME }`, and supplied when the file is applied:

| Where | How |
| --- | --- |
| `pending.json` (templated VMs) | `"secrets": { "TESTER_PASSWORD": "…" }`, written by `groundhog pending --secret TESTER_PASSWORD` (the value comes from the `TESTER_PASSWORD` environment variable, which keeps it off the command line) or `--secret NAME=value` |
| Environment | `GROUNDHOG_SECRET_TESTER_PASSWORD` |
| A file | `groundhog-agent apply … --secrets-file secrets.json` with `{ "TESTER_PASSWORD": "…" }` |

The agent takes secrets out of `pending.json` as soon as it reads it. They're never logged or
recorded in state. If a run pauses for a restart, they're kept until it finishes, encrypted
with DPAPI so only the same account on the same machine can read them, and then deleted.
`plan` lists the secrets a file needs and whether each one is provided.

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
  ("Languages and Optional Features" ISO). A mounted ISO works as a drive path
  (`D:\sources\sxs`). A relative path works when the Groundhogfile is a local file. Zip and
  web sources aren't supported yet; these repositories are gigabytes.
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

## `apps`

```yaml
apps:
  - Git.Git                         # winget id
  - id: Microsoft.DotNet.SDK.10
    version: 10.0.100               # optional
    args: --scope machine           # extra winget arguments, verbatim
  - id: internal-tool               # a direct installer
    url: https://files.example.com/tool.msi
    sha256: <64 hex>                # pin a build (and allow caching); omit to follow latest
    args: ADDLOCAL=ALL              # installer arguments, verbatim
```

**winget apps** are skipped if `winget list --id <id> --exact` finds them. If winget is missing,
the agent installs it first (via the `Microsoft.WinGet.Client` PowerShell module).

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
```

A file whose contents already match is left alone.

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
path:
  - C:\tools\bin
  - dir: C:\Program Files\Sysinternals
    scope: machine
```

By default these are the agent user's own variables (`HKCU\Environment`). `scope: machine`
writes the system environment instead, which every account, service and SYSTEM starts with;
that needs the agent elevated. `path` entries are appended if missing, never reordered or
removed, and a machine PATH that can't be read is left alone rather than rewritten.
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
```

Roots: `HKCU`, `HKLM`, `HKCR`, `HKU` (or their long names).

`scope` applies only to `HKCU` keys:
- `current-user` (default): the account the agent runs as.
- `default-user`: `C:\Users\Default\NTUSER.DAT`, so profiles created **later** get the value
  too. Requires the agent to run elevated.

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
