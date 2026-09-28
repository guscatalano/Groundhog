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

Download from [Releases](https://github.com/guscatalano/Groundhog/releases/latest):

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

Bump `version` in the root `Cargo.toml`, commit, then tag and push:

```powershell
git tag v0.2.0; git push origin v0.2.0
```

The `Release` workflow builds x64 and ARM64, smoke-tests them, and publishes the release. Tags
with a `-` (such as `v0.2.0-rc.1`) are published as prereleases.

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

## Resuming, reboots and re-runs

Each step's id is a hash of what it does. The agent records finished steps, so running again:
- after a **failure** resumes at the failed step,
- after a **restart** continues where it stopped,
- after an **edit** runs only new or changed steps.

When a step needs a restart, `apply` exits with **3010**. With `--reboot`, it restarts and
continues by itself at the next logon.

## Templated VMs (Hyper-V, Proxmox, anything)

Install the agent in the template once (`groundhog-agent install-task` plus autologon). Each clone
then applies whatever `pending.json` a host drops in. See [docs/templates.md](docs/templates.md).

## More

- [docs/groundhogfile.md](docs/groundhogfile.md): full file reference
- [docs/design.md](docs/design.md): architecture and roadmap
- [docs/templates.md](docs/templates.md): preparing VM templates

## Layout

```
crates/groundhog-core    model, loading (path/URL/zip, extends), cache, resumable engine
crates/groundhog-win     all Windows API code (registry, hives, env, processes, tasks)
crates/groundhog-agent   the agent executable
crates/groundhog         the host executable and providers
examples/                sample Groundhogfiles
```
