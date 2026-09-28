# Groundhogfile reference

A Groundhogfile is YAML (`.yaml`/`.yml`, or no extension) or JSON (`.json`). Unknown keys are
errors, so typos fail at load time instead of being ignored.

Steps run in this order: winget bootstrap (if any winget apps), `apps`, `files`, `env`, `path`,
`registry`, then `run`.

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
- **run** actions accumulate (base first).

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
    sha256: <64 hex>                # recommended; enables caching
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
