# Groundhogfile reference

A Groundhogfile is YAML (`.yaml`/`.yml`, or no extension) or JSON (`.json`). Unknown keys are
errors, so typos fail at load time instead of being ignored.

Steps run in this order: winget bootstrap (if any winget apps), `apps`, `files`, `env`, `path`,
`registry`, `run`, then the `verify` checks.

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

## `env` and `path`

```yaml
env:
  DOTNET_CLI_TELEMETRY_OPTOUT: "1"
  TOOLS: '%USERPROFILE%\tools'        # stored as REG_EXPAND_SZ when it contains %
path:
  - C:\tools\bin
```

These are user-level variables (`HKCU\Environment`). Running programs are notified of the change.

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
```

For commands and scripts, exit code 0 means success, 3010 means a restart is needed, and anything
else fails the step. A script's shell comes from its extension (`.ps1`, `.cmd`/`.bat`, `.exe`)
unless `shell` is set (`direct` runs the file itself).

For inline PowerShell commands, if the last statement is a program that fails, its own exit code
is kept. So a final `msiexec …` or `cmd /c …` that returns 3010 asks for a restart, instead of
PowerShell reducing it to 1. `.ps1` scripts run with `-File` and report whatever they `exit`
with; end them with `exit $LASTEXITCODE` to pass a program's code through.

Each `run` entry is a separate process, so `$ErrorActionPreference` and variables don't carry
over between entries. If a multi-line command starts with a `# comment`, the comment becomes the
step's name in `plan` and the logs.

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
