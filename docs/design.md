# Design

## Goal

Bring a **fresh** Windows machine to a known state, repeatably: apps, their configuration,
environment, registry and custom steps. The main targets are throwaway environments: Windows
Sandbox, and VMs cloned from a template on Hyper-V, Proxmox or anything else.

## Principles

1. **The agent is the product.** `groundhog-agent` does all the work and needs nothing but the
   Groundhogfile. A host is a convenience that starts machines and watches, never a requirement.
2. **Declarative, ordered, resumable.** A Groundhogfile describes the end state. The agent turns
   it into ordered steps whose ids are hashes of what they do. Recorded progress makes re-runs
   (after failure, restart or edit) do only what's left.
   - A step's identity includes the **content** it references, not just the text. Unpinned
     references ("latest" URLs, local scripts) are fetched and hashed at load time, so a new
     build is a new step.
   - `run` steps chain like Docker layers: each one's id covers every step before it, because
     imperative steps usually depend on what came earlier (unpack after download, configure
     after install). Declarative steps stay independent.
3. **Content-addressed everything.** Anything pinned by `sha256` can come from any cache and is
   verified on arrival. Caches are plain folders or static web servers and need no trust.
4. **Location-independent files.** References resolve relative to the document they appear in,
   so the same Groundhogfile works from disk, a URL or a zip.
5. **Windows code in one place.** All `unsafe` Win32 code lives in `groundhog-win`, behind small
   safe functions.

## Components

```
                 host (optional)                           target machine
┌───────────────────────────────────────┐     ┌────────────────────────────────────────┐
│ groundhog.exe                         │     │ groundhog-agent.exe                    │
│  providers: sandbox (hyperv, proxmox) │     │  load: path | URL | zip, extends       │
│  • create/restore target              │────▶│  plan: ordered, content-hashed steps   │
│  • deliver agent + source / pending   │     │  run:  resumable, reboot-aware         │
│  • follow status folder / endpoint    │◀────│  report: console, folder, http         │
└───────────────────────────────────────┘     └────────────────────────────────────────┘
                     │                                         │
                     └────── cache: folder | SMB | http ───────┘
```

### Crates

- **groundhog-core**: the model, loader, fetcher, caches, engine, reporters, plugin protocol
  and pending-file format. It never touches the machine it runs on.
- **groundhog-win**: tokens and privileges, registry (including loading the Default User hive),
  user env and PATH with change broadcast, process running, winget discovery, and the logon task.
- **groundhog-agent**: CLI plus `WinExecutor`, which carries out each step type.
- **groundhog**: host CLI and providers.

### Why the agent runs inside the target

Installers, `HKCU`, `%AppData%`, Store/MSIX packages and winget all want a real logged-on user
session. Remote execution channels (PowerShell Direct, the QEMU guest agent, WinRM) run
non-interactively or as SYSTEM, where much of that fails. So the host only **delivers and
triggers**: the Sandbox `LogonCommand`, or a logon scheduled task in a template. The agent then
does the work as the user, elevated.

### Reboots

A step can return "done, restart needed" (for example MSI 3010) or "restart, then retry" (winget's
`REBOOT_REQUIRED_FOR_INSTALL`). The run stops with status `reboot-pending` and exit code 3010.
With `--reboot`, or from a pending file, the agent writes `pending.json`, installs its logon
task, restarts, and continues. It gives up after 5 restarts in one run.

## Roadmap

- **Proxmox provider**: clone a template (linked clone), write `pending.json` through the QEMU
  guest agent, start it, and follow a report endpoint. Snapshots after base layers act like
  Docker layer caching.
- **Hyper-V provider**: the same, through PowerShell Direct and checkpoints.
- **`groundhog capture`**: generate a Groundhogfile from an existing machine (winget export
  plus a catalog of where known apps keep their settings).
- **`groundhog cache serve`**: a tiny static server for a cache folder.
- **Lock mode**: re-apply exactly the hashes recorded by an earlier run.
- **`stop:` on `files:` entries**: stop named services or processes before replacing files, and
  restart services afterwards (Restart Manager can report who holds a file).
- More built-in steps: services, optional features, ACLs, symlinks, file associations.
- Signed Groundhogfiles, checked against a key built into a template.
- **Stronger agent-update trust**: today an update is accepted when its SHA-256 matches the
  source's `agent.json`, which trusts whoever controls the source. Verifying GitHub's build
  provenance attestations, or code-signing the binaries and checking the signature, would
  also protect against a compromised source.
