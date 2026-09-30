# Changelog

What changed in each release, written for people using Groundhog. The release workflow
publishes each version's section below as its GitHub release notes, and refuses to publish a
version that has no section here.

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

[0.8.0]: https://github.com/guscatalano/Groundhog/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/guscatalano/Groundhog/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/guscatalano/Groundhog/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/guscatalano/Groundhog/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/guscatalano/Groundhog/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/guscatalano/Groundhog/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/guscatalano/Groundhog/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/guscatalano/Groundhog/releases/tag/v0.1.0
