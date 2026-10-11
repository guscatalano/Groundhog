# Groundhog

Bring a fresh Windows machine to a known state: apps, config files, environment, registry and
custom setup steps, described in one file and applied the same way every time. Think of it as a
Dockerfile for a Windows sandbox or VM.

```yaml
# groundhog.yaml
extends: https://example.com/team/base.groundhog.yaml

apps:
  - Git.Git
  - Microsoft.VisualStudioCode

files:
  - from: config/.gitconfig
    to: ~/.gitconfig

registry:
  - key: HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced
    name: HideFileExt
    type: dword
    value: 0
    scope: [current-user, default-user]

run:
  - script: scripts/post-setup.ps1
```

## Two programs

| | What it does |
|---|---|
| **`groundhog-agent.exe`** | Runs **on the machine being set up** and does all the work. It stands alone: copy it anywhere and point it at a Groundhogfile. It's a single ~2 MB file with no runtime to install. |
| **`groundhog.exe`** | Optional **host** side. It starts a target (Windows Sandbox today; Hyper-V and Proxmox next), gives the agent a Groundhogfile and follows its progress. |

## Install

**Apply a Groundhogfile in one line**, on a machine with nothing installed. This fetches the
right agent for the machine, checks it against the release's published hash, asks for
elevation if needed, and applies the file:

```powershell
& ([scriptblock]::Create((irm https://github.com/guscatalano/Groundhog/releases/latest/download/apply.ps1))) https://example.com/dev.groundhog.yaml
```

The file can be written on the spot too. For example, to set the desktop background:

```powershell
# a solid color, and dark mode
"desktop: { background: '#2E7D32', theme: dark }" | Set-Content $env:TEMP\bg.yaml; & ([scriptblock]::Create((irm https://github.com/guscatalano/Groundhog/releases/latest/download/apply.ps1))) $env:TEMP\bg.yaml

# a picture from the web (downloaded, then kept in %ProgramData%\groundhog\desktop)
"desktop: { wallpaper: 'https://example.com/lab.jpg', wallpaper-style: fill }" | Set-Content $env:TEMP\bg.yaml; & ([scriptblock]::Create((irm https://github.com/guscatalano/Groundhog/releases/latest/download/apply.ps1))) $env:TEMP\bg.yaml

# a ready-made sample from this repo (see examples/desktop)
& ([scriptblock]::Create((irm https://github.com/guscatalano/Groundhog/releases/latest/download/apply.ps1))) https://raw.githubusercontent.com/guscatalano/Groundhog/main/examples/desktop/windows-wallpaper.groundhog.yaml
```

Or download from [Releases](https://github.com/guscatalano/Groundhog/releases/latest):

| Asset | Use |
|---|---|
| `groundhog-agent-x64.exe` / `-arm64.exe` | The agent alone. Drop it into any machine or template. |
| `groundhog-x64.zip` / `-arm64.zip` | Host CLI plus the agent, for `groundhog sandbox` and friends. |
| `SHA256SUMS.txt` | Checksums. Builds also carry GitHub build provenance (`gh attestation verify <file> -R guscatalano/Groundhog`). |

The latest agent always lives at a stable URL, handy for bootstrapping VMs:

```powershell
Invoke-WebRequest https://github.com/guscatalano/Groundhog/releases/latest/download/groundhog-agent-x64.exe -OutFile groundhog-agent.exe
```

The binaries aren't code-signed yet, so SmartScreen may warn on first run.

## Releasing

1. Bump `version` in the root `Cargo.toml`.
2. Add a section for it to [`CHANGELOG.md`](CHANGELOG.md), written for people using Groundhog.
   It becomes the release notes.
3. Commit, then tag and push:

   ```powershell
   git tag v0.5.0; git push origin v0.5.0
   ```

The `Release` workflow checks that the tag matches the version and that the changelog has a
section for it. Then it builds x64 and ARM64, smoke-tests them, and publishes the release with
those notes plus download and verification instructions. Tags with a `-` (such as
`v0.5.0-rc.1`) are published as prereleases. `scripts/release-notes.sh vX.Y.Z` previews the
notes locally.

## Quick start

```powershell
cargo build --release

# See what would happen (changes nothing):
target\release\groundhog-agent.exe plan examples\dev\groundhog.yaml

# Apply it to this machine (run elevated):
target\release\groundhog-agent.exe apply examples\dev\groundhog.yaml

# Or apply it inside a fresh Windows Sandbox, with a download cache shared across sandboxes:
target\release\groundhog.exe sandbox examples\dev\groundhog.yaml --cache C:\groundhog-cache
```

Or start from the [built-in library](docs/groundhogfile.md#the-built-in-library): a machine
for Windows internals work (Sysinternals, WinDbg and the console debuggers, TTD, the
Performance Toolkit, .NET diagnostics, symbols, crash dumps) is one line:

```powershell
groundhog-agent apply groundhog:windows-internals
```

Developer machines too: `dev-core` (Git, GitHub CLI, VS Code, PowerShell 7, the usual command
line tools), with `dotnet`, `vs`, `node`, `python`, `rust`, `containers` and `ai` on top, and
`firefox` (with uBlock Origin and Bitwarden, and without the first-run prompts).
Combine them in your own file:

```yaml
extends: [groundhog:python, groundhog:node, groundhog:ai]
```

## Sources: path, URL or zip

The agent takes a local path, a directory, an `https://` URL, or a `.zip` bundle (local or remote).
In a directory or zip, it looks for `groundhog.yaml`, `groundhog.yml`, `groundhog.json` or
`Groundhogfile`. GitHub archive zips work as-is:

```powershell
groundhog-agent apply https://github.com/you/devbox/archive/refs/heads/main.zip --sha256 <hash>
```

Relative references (`files`, `script`, `plugin`, `extends`) resolve against the file they appear
in, like links on a web page. That makes a Groundhogfile and its config folder portable between
disk, a web server and a zip.

`--sha256` pins the root document (or zip), and every `sha256:` in the file pins what it
references. HTTPS uses Windows' own TLS stack and certificate store, so internal servers signed
by an enterprise CA work. For private sources, `--header "Authorization: Bearer ..."` is sent only to the
source's own host.

## Caching

`--cache` (repeatable) adds content-addressed caches, tried in order before the network: a
folder, a UNC share or an `http(s)://` URL, all laid out as `<root>/sha256/<hash>`. Every hit is
re-verified, so a cache never has to be trusted. Writable folder caches are filled as the agent
downloads, so the first machine warms the cache for the rest. Only pinned content can come from
a cache.

## Checking the result

`verify:` checks run at the end of **every** apply and fail it if the machine isn't healthy:

```yaml
verify:
  - process: my-agent
    stable-for: 8s          # catches crash loops
  - service: MyAgentSvc
  - eventlog: { provider: MyAgentSvc, must-not-contain: '0xC0000142' }
  - port: 3389
```

Each check retries until it passes or its deadline (`within`, default 30s) runs out. See
[the reference](docs/groundhogfile.md#verify).

## What you see

`apply` shows a line for each part of the file as it finishes, and the step in progress:

```
  Applying neon.groundhog.yaml (47 steps)

  ✔ Files            2 copied, 1 already there    5.2s
  ✔ Environment      1 changed
  ✔ Settings         37 changed                   1.1s
  ✔ Desktop          3 changed
  ✔ Commands         1 ran                        1.5s
  ✔ Checks           2 passed

  Done in 21s: 46 changed, 1 already set.
```

If a step fails, it shows that step, the last of its output and the error. `--verbose` (`-v`)
shows every step and what it did instead; the log in `%ProgramData%\groundhog\last-run`
always has that detail.

## Resuming, reboots and re-runs

Each step's id is a hash of what it does, including the content it fetches. The agent records
finished steps, so running again:
- after a **failure** resumes at the failed step,
- after a **restart** continues where it stopped,
- after an **edit** runs only new or changed steps,
- after a **new release** behind an unpinned "latest" URL runs that step again, plus every `run`
  step after it (Docker-style layers).

Pin a download with `sha256` to lock it to one build; leave the pin off to follow latest. See
[When steps run again](docs/groundhogfile.md#when-steps-run-again).

When a step needs a restart, `apply` exits with **3010**. With `--reboot`, it restarts and
continues by itself at the next logon.

## Templated VMs (Hyper-V, Proxmox, anything)

Install the agent in the template once (`groundhog-agent install-task` plus autologon). Each clone
then applies whatever `pending.json` a host drops in. See [docs/templates.md](docs/templates.md).

**The template doesn't go stale.** Before each run from `pending.json`, the agent updates itself
from GitHub releases, or from your own folder or share (`groundhog mirror-agent` fills one), and
hands over to the new version. Clones pick up new Groundhogfile features without rebaking. A
manual `apply` only updates with `--update`, and `groundhog-agent update` updates on demand.
Details, pinning and trust: [Keeping the template's agent current](docs/templates.md#keeping-the-templates-agent-current).

**Starting from nothing:** `groundhog unattend` writes an answer file that installs Windows from ISO
(or finishes each clone of a sysprepped template), creates the provisioning account, turns on
autologon, and starts the agent on first logon. See [docs/unattend.md](docs/unattend.md).

## More

- [docs/groundhogfile.md](docs/groundhogfile.md): full file reference
- [docs/design.md](docs/design.md): architecture and roadmap
- [docs/templates.md](docs/templates.md): preparing VM templates
- [docs/unattend.md](docs/unattend.md): answer files for unattended installs and sysprepped templates

## Layout

```
crates/groundhog-core    model, loading (path/URL/zip, extends), cache, resumable engine
crates/groundhog-win     all Windows API code (registry, hives, env, processes, tasks)
crates/groundhog-agent   the agent executable
crates/groundhog         the host executable and providers
examples/                sample Groundhogfiles
```
