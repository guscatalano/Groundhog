# Changelog

What changed in each release, written for people using Groundhog. The release workflow
publishes each version's section below as its GitHub release notes, and refuses to publish a
version that has no section here.

## [0.14.0] - 2026-10-03

### Added
- **Removing things: `state: absent`.** Apps (winget uninstall), files and folders, env vars,
  PATH entries, registry values and whole keys, users, certificates, firewall rules and
  Defender exclusions can be taken back. Deleting an entry from a file still leaves the
  machine alone; `state: absent` is how to undo, and a file that `extends` another can undo
  what the base added. Guards refuse to delete a drive root, Windows' own folders, or a
  registry key near the top of a hive.
- **`remove-apps:`** removes built-in Store apps (`Microsoft.BingNews`, `Clipchamp.*`) for every
  user and unprovisions them so new profiles don't get them.
- **`certificates:`** trusts (or removes) public certificates in the machine's stores: an
  internal root CA, an intermediate, a test signer. DER or PEM, from a path or URL.
- **`services:`** sets a service's start type (automatic, delayed, manual, disabled) and
  whether it runs.
- **`firewall:`** Windows Firewall rules by name: ports, protocol, direction, program,
  profiles, remote addresses. A rule that drifted is replaced; one that matches is left alone.
- **`defender-exclusions:`** paths, processes and extensions Microsoft Defender skips.
- **Conditions and variables.** `when: { arch: arm64, build: ">=26100", os: client }` on any
  entry keeps it only on matching machines. `${var:NAME}` works in any string, with values
  from `vars:` (a file overrides the library it extends), `--var`/`pending.json` (per
  machine), and built-ins `${var:arch}`, `${var:build}`, `${var:os}`.
- **`plan --check`** shows, step by step, what `apply` would do on this machine (`ok`,
  `change`, `run`, `done`, `?`) without changing anything.
- **winget versions and upgrades.** A `version` is now enforced: a different installed
  version is replaced with that one, up or down. `upgrade: true` follows new releases on
  every apply.
- **Feature and capability sources** can be a `.zip`, an `.iso` (mounted for the step) or an
  `http(s)` URL to either.

### Upgrading
- **A winget `version` is now enforced.** Before, an installed app was left alone whatever its
  version; now a different version is replaced with the pinned one (up or down) the next time
  that step runs. Steps already applied aren't rerun just by updating the agent, but check
  your pins before editing a file that has them.

### Changed
- **Downloads stream to disk.** Installers, archives and files are hashed as they arrive
  instead of being held in memory; a 192 MB archive peaks at 13 MB of agent memory.
- The `debuggers` library entry uses `${var:arch}`, so it works on ARM64 too.

### Fixed
- **A winget app added to a file after its first apply failed** with "winget is not
  available": the step that locates winget was recorded as done and skipped. (Present since
  0.1.0.)
- `state: absent` for a per-user winget package (most portable tools): winget won't uninstall
  one from an elevated process, so the agent retries as the same user, unelevated.

## [0.13.1] - 2026-10-01

### Added
- **A warning when the machine's clock is off.** The agent compares its clock with the `Date`
  of the first server it downloads from and says so when they differ by more than 5 minutes
  ("this machine's clock is 7h behind raw.githubusercontent.com's"). A VM whose clock starts
  hours off otherwise gets certificate errors and timestamps that look like anything but a
  clock problem. It only warns; it never changes the clock.
- **`groundhog:time-sync`** turns on Windows Time, lets it correct a large error in one go,
  syncs now and checks the result against time.windows.com. Tested on a fleet VM that booted
  7 hours slow. It doesn't change how Windows reads the hardware clock, which has to match the
  hypervisor's setting.

## [0.13.0] - 2026-10-01

### Added
- **`groundhog-agent clean`** removes everything runs leave in the agent's folder (results,
  state, logs, cached downloads, secrets and the secret salt) and keeps the installed agent and
  its logon task. Run it before sealing a template: otherwise every clone starts with the
  template build's `pending.done.json`, so a host that watches for it reports a run as
  finished before any has started, and clones carry the template's download cache and share
  one secret salt. [docs/templates.md](docs/templates.md#baking-a-base-layer) now includes it.

## [0.12.0] - 2026-10-01

### Added
- **Secrets anywhere a config needs one.** `${secret:NAME}` works in inline file `content`,
  `env` values, registry string values, and `run` commands and script `args`, so an API key
  or a per-VM token can be part of a declarative setup:
  ```yaml
  agent: ">=0.12.0"
  files:
    - to: C:\ProgramData\Deskhand\deskhand.json
      content: |
        { "token": "${secret:DESKHAND_TOKEN}", "port": 8791 }
  ```
  Values come from the same places as before (`pending.json`, `GROUNDHOG_SECRET_<NAME>`,
  `--secrets-file`), and the same rules hold: never logged, never stored, encrypted only
  while a run waits for a restart.
  - Plans, titles, `status.json` and state only ever show `${secret:NAME}`, and values are
    scrubbed (`***`) from every log line and error, a program's own output included.
  - A step that uses a secret reruns when the value changes, so a rotated token lands. The
    step's identity holds a salted hash of the value; the salt is per machine and kept
    encrypted.
  - In `run` commands the value reaches the command as an environment variable
    (`${env:GROUNDHOG_SECRET_NAME}`), not as script text, keeping it off the command line and
    safe from quotes in the value. Write the reference where variables expand, not inside
    single quotes.
  - A missing secret stops the run before anything changes, naming all of them. References
    anywhere else, malformed ones, secrets in machine-wide env, and values shorter than 4
    characters (too short to scrub) are refused.
  - `password: ${secret:NAME}` is the same as `{ secret: NAME }`.
- **Inline file content:** `files:` entries take `content:` (the text) instead of `from:`.
- **Authenticated report sinks.** `--header` rules now also apply to status POSTs to a report
  sink on that host, a header's value can be `${secret:NAME}`, and `groundhog pending` takes
  `--header`.

### Upgrading
- Add `agent: ">=0.12.0"` to a Groundhogfile that uses `${secret:...}`. An older agent doesn't
  know references and would write the text `${secret:NAME}` into env, registry or commands;
  with the requirement it says it needs updating instead (and updates itself from
  `pending.json`).

## [0.11.0] - 2026-09-30

### Added
- **Machine-wide `env` and `path`.** `scope: machine` puts a variable or PATH entry in the
  system environment, which every account, service and SYSTEM sees, instead of the agent
  user's own:
  ```yaml
  env:
    _NT_SYMBOL_PATH: { value: 'srv*C:\Symbols*https://msdl.microsoft.com/download/symbols', scope: machine }
  path:
    - { dir: 'C:\Program Files\Sysinternals', scope: machine }
  ```
  Entries are only ever appended, and a machine PATH that can't be read is left alone rather
  than rewritten. Existing user-scope steps keep their ids, so they don't run again.
- **More of the debugging toolchain in the library:** `debuggers` (cdb, kd, gflags, umdh,
  symchk, dbgsrv from the Windows SDK's Debugging Tools only), `ttd` (`TTD.exe`) and
  `dotnet-diag` (.NET 10 SDK with dotnet-dump, -gcdump, -trace and -counters).
  `windows-internals` now includes all three, so tools that drive these programs, such as an
  MCP debugging server, find everything they expect.

### Changed
- **`sysinternals` moved to `C:\Program Files\Sysinternals` and onto the machine PATH**, and
  accepts the EULA for SYSTEM too, so services and SYSTEM shells find the tools without a
  prompt. A folder on the machine PATH must be writable only by administrators, which
  `C:\Tools` isn't. A copy in `C:\Tools\Sysinternals` from 0.10 is left in place; delete it
  when nothing uses it.
- `symbols` sets `_NT_SYMBOL_PATH` machine-wide.

## [0.10.1] - 2026-09-30

### Fixed
- **Features and capabilities that need a restart could finish without one.** Windows reports
  "done, restart needed" in a way 0.9.0 and 0.10.0 missed, so such a step counted as complete,
  the run could end as succeeded with Windows still waiting for a restart, and the next
  feature restarted the machine first instead of the section restarting once at its end (the
  0.10.0 fix didn't cover this). Found by testing on a fresh Windows 11 VM: enabling WSL and
  `HypervisorPlatform` now takes one restart, after both.

## [0.10.0] - 2026-09-30

### Added
- **A built-in library of Groundhogfiles.** `groundhog:NAME` names one, to apply as it is or
  to build on with `extends`:
  ```powershell
  groundhog-agent apply groundhog:windows-internals
  ```
  The first set is for Windows internals work: `sysinternals`, `windbg`, `wpt` (Windows
  Performance Toolkit), `symbols`, `crash-dumps` and `explorer-dev`, and `windows-internals`
  with all of them. A name means the library as of the agent's own release;
  `groundhog:NAME@main` follows the latest one. See
  [the library](docs/groundhogfile.md#the-built-in-library).

### Fixed
- **Features that finish after a restart restarted the machine one by one again.** The first
  one left Windows "waiting for a restart", which the next feature took as a reason to restart
  first. The agent now knows that restart is its own, finishes the section, and restarts once.

### Documentation
- `features:` and `capabilities:` don't need install media: without `source:`, payloads come
  from Windows Update (or WSUS). Tested on a fresh Windows 11 VM, including the restart and
  the logon task picking the run back up. It's slow (about half an hour each for `NetFx3` and
  `OpenSSH.Server`), so the docs now say when a local source or a baked template pays off.

## [0.9.0] - 2026-09-30

### Added
- **`features:` and `capabilities:`** enable or disable Windows optional features (WSL,
  `VirtualMachinePlatform`, `NetFx3`, IIS, …) and add or remove capabilities / Features on
  Demand (`OpenSSH.Server`, RSAT, languages, …). They run after `users` and before `apps`.
  Each step checks the live state first, so they're safe on machines where someone already
  did it. Payloads can come from a folder or share (`source:`, with `limit-access: true` to
  keep Windows Update out of it). Common DISM failures come with what to do about them.
- **One restart for a batch of features.** Features that finish after a restart no longer
  restart the machine one by one: the agent completes the rest of the section, restarts once
  and continues.
- A "bake a base layer" recipe for templates in [docs/templates.md](docs/templates.md).

### Notes
- This uses the DISM API directly (typed state, exact error codes, clean cancellation for
  `timeout:`), so the agent must run elevated, as it does from the template's logon task. Not
  supported inside Windows Sandbox.

## [0.8.0] - 2026-09-30

### Added
- **`groundhog unattend`** writes a Windows answer file that goes from Windows Setup (or a
  sysprepped template) to "the agent is applying a Groundhogfile" with nobody at the keyboard:
  it skips the setup screens, sets the computer name, language and time zone, creates the
  provisioning account with autologon, and on first logon installs the agent, writes
  `pending.json` and starts it.
  - `--mode install` for ISO/USB installs: edition, product key, VirtIO and other storage
    drivers (`--driver-path`), Windows 11 hardware-check bypass, and disk partitioning only
    with an explicit `--wipe-disk N`.
  - `--mode sysprep` for sealing templates; each clone gets its own name and bootstrap.
  - Secrets can be embedded with `--secret`; Setup's own copy of the file is then deleted on
    first logon. See [docs/unattend.md](docs/unattend.md) for the security trade-offs.

  Not yet verified through a complete Windows Setup run; try it on a throwaway VM first.

## [0.7.0] - 2026-09-30

### Added
- **`users:`** creates local accounts and adds them to groups. Existing accounts are brought in
  line without touching their password (unless `reset-password: true`). Built-in groups work by
  their English names on any display language (`Administrators`, `Remote Desktop Users`, …).
  Passwords don't expire by default, so unattended logons keep working.
- **Secrets.** A Groundhogfile names a password (`password: { secret: NAME }`) or has one
  generated (`password: generate`), and never contains one. Values come from `pending.json`
  (`groundhog pending --secret NAME`), `GROUNDHOG_SECRET_<NAME>` environment variables, or
  `apply --secrets-file`. The agent removes them from `pending.json` as soon as it reads it,
  never logs them, keeps them DPAPI-encrypted only while a run is paused for a restart, and
  deletes them when it finishes. `plan` lists which secrets a file needs and whether they're
  provided.

## [0.6.0] - 2026-09-30

### Added
- **`github:` sources** for `files:` and `apps:`: `github:OWNER/REPO@latest/ASSET`, a tag
  instead of `latest`, or `source` for a release's source code. With `prerelease: true`,
  repositories that only publish prereleases work too (GitHub's own "latest" ignores them).
  Every `@latest` in a file resolves to the same release, so an app and the source of its tests
  can't drift apart. Assets with a published digest are pinned by it, so `plan` doesn't
  download them, and the logs show the release tag (`@1.0.267`).
- **`strip: N` with `extract`** drops leading folders from the zip's paths, such as the
  `repo-1.0.267\` folder GitHub source archives wrap everything in.
- **`timeout:` on `run` entries and `apps`.** A step that runs too long is stopped along with
  every process it started, and fails with its last lines of output.
- **`always: true` on `run` entries**, for steps that should run on every apply, such as a test
  suite.

### Fixed
- **Multi-line `shell: cmd` commands ran only their first line.** They now run as a batch file,
  and a leading `# title` line is no longer passed to cmd. This affects `run` entries and
  `command` checks.
- A typo in a `run` or `apps` entry (`timout: 5m`) is now reported as an unknown field instead
  of being silently ignored or reported as "did not match any variant".
- `plan` now reports a Groundhogfile's `agent:` requirement, as `apply` does.

## [0.5.0] - 2026-09-30

### Added
- **The agent keeps itself current.** Before each run from `pending.json` (the logon task in a
  VM template), it checks for a newer agent, verifies it against the release's SHA-256, swaps
  it in and hands the run over, so a template no longer goes stale when Groundhog gains
  features. If anything goes wrong (no network, a bad hash), the run carries on with the
  current agent. Set `agentUpdate` in `pending.json` to `latest` (the default there), `off`,
  or a version to pin to.
- **Serve updates yourself.** `agentUpdateFrom` (or `--update-from`) points at any folder, share
  or web server holding `agent.json` and the agent exes, so clones never need GitHub.
  `groundhog mirror-agent <folder>` fills one from a release.
- `groundhog-agent apply --update[=VERSION]` updates before a manual run (off by default), and
  `groundhog-agent update` updates on demand, for maintaining templates.
- **`agent: ">=0.5.0"` in a Groundhogfile** declares the oldest agent that understands it. An
  older agent says so, instead of failing on an unknown key.
- Releases include `agent.json`, the manifest agents update from.
- `status` shows which agent version produced each result.

### Upgrading
- Rebake templates once with 0.5.0. Older agents can't update themselves, and they reject
  `pending.json` files and Groundhogfiles that use the new keys.

## [0.4.0] - 2026-09-30

### Changed
- **Event log checks wait for `must-contain`.** A `verify:` event log check now retries until
  the text it needs shows up, up to `within` (default 30s), like every other check. A service
  that logs "started" a moment after its process appears no longer fails the check.
  `must-not-contain` still fails at once.

  ```yaml
  verify:
    - eventlog: { provider: RdpeekAgentSvc, must-contain: '(startup, Native)' }
      within: 1m
  ```

### Fixed
- The error for an option that doesn't fit a check now reads "doesn't apply to service
  checks" instead of "…to a service check" (which read "a eventlog check" for event logs).

## [0.3.0] - 2026-09-28

### Added
- **`verify:` health checks** that run at the end of every apply and fail it when the machine
  isn't healthy: `process` (with `stable-for` to catch crash loops), `service`, `eventlog`
  (`must-contain` / `must-not-contain`, only events from this run by default), `port`, `file`
  and `command`. Checks retry until `within` (default 30s), so no `Start-Sleep` guesses.
- **`extract: true` on `files:`** unpacks a zip into a folder and swaps it in as a whole:
  files the new archive dropped disappear, and a failed unpack leaves the old folder intact. A
  program still running from the old folder keeps a renamed copy and doesn't block the update.

### Notes
- Event log checks read events in a way that works on any Windows display language, and treat
  "no events" or an unknown provider as "contains nothing". That's the trap a hand-written
  `Get-WinEvent` check falls into.

## [0.2.0] - 2026-09-28

### Added
- **Follow "latest" URLs.** A download without `sha256` follows whatever the URL serves now,
  such as `…/releases/latest/download/app.zip`. It's fetched while loading, so a new build makes
  the step run again, and `plan` and the logs show which build it resolved to (`@3f2a9c1e`).
  Local scripts and folders work the same way: editing one reruns its step.
- **Docker-style reruns for `run` steps.** A `run` step also reruns when anything before it
  changed, so unpack and install steps follow their download automatically.
- A leading `# comment` names a multi-line command in `plan` and the logs.

### Fixed
- Inline PowerShell commands keep a failing program's own exit code, so an installer's `3010`
  (restart required) is no longer reduced to `1`.

## [0.1.0] - 2026-09-28

First release.

- **`groundhog-agent`**: a standalone ~1.6 MB agent with no runtime. It applies a Groundhogfile
  (YAML or JSON, from a path, URL or zip) to the machine it runs on: winget and direct-URL
  apps, config files, user env and PATH, registry values (including the Default User profile),
  and custom `run` steps (commands, scripts, plugins).
- Resumes after failures and restarts, and runs only new or changed steps on the next apply.
- Content-addressed caches (folder, UNC share or HTTP) and `sha256` pinning.
- **`groundhog`** host CLI: `sandbox` applies a Groundhogfile inside a fresh Windows Sandbox,
  and `pending` writes the bootstrap file for templated VMs (Proxmox, Hyper-V, …).
- HTTPS uses Windows' own TLS and certificate store, so enterprise CAs work.

[0.14.0]: https://github.com/guscatalano/Groundhog/compare/v0.13.1...v0.14.0
[0.13.1]: https://github.com/guscatalano/Groundhog/compare/v0.13.0...v0.13.1
[0.13.0]: https://github.com/guscatalano/Groundhog/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/guscatalano/Groundhog/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/guscatalano/Groundhog/compare/v0.10.1...v0.11.0
[0.10.1]: https://github.com/guscatalano/Groundhog/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/guscatalano/Groundhog/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/guscatalano/Groundhog/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/guscatalano/Groundhog/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/guscatalano/Groundhog/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/guscatalano/Groundhog/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/guscatalano/Groundhog/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/guscatalano/Groundhog/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/guscatalano/Groundhog/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/guscatalano/Groundhog/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/guscatalano/Groundhog/releases/tag/v0.1.0
