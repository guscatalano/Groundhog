# Changelog

What changed in each release, written for people using Groundhog. The release workflow
publishes each version's section below as its GitHub release notes, and refuses to publish a
version that has no section here.

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

[0.5.0]: https://github.com/guscatalano/Groundhog/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/guscatalano/Groundhog/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/guscatalano/Groundhog/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/guscatalano/Groundhog/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/guscatalano/Groundhog/releases/tag/v0.1.0
