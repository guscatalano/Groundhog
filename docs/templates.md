# Preparing a VM template

Any hypervisor works (Hyper-V, Proxmox, VMware, …). The template carries the agent and a logon
task. Each clone does nothing until a host drops a `pending.json` into it.

## One-time template setup

**Shortcut:** `groundhog unattend` writes an answer file that does steps 1–3 for you, either
while installing from ISO (`--mode install`) or on every clone of a sysprepped template
(`--mode sysprep`). See [Unattend files](unattend.md). The manual steps:

1. Install Windows and create a local **provisioning account** (an administrator).
2. Turn on **autologon** for that account, for example with Sysinternals Autologon (which stores
   the password as an LSA secret) or `Winlogon` registry values. The password is stored
   recoverably, which is fine for disposable VMs but worth knowing.
3. Copy `groundhog-agent.exe` (0.5.0 or later, so it can
   [keep itself current](#keeping-the-templates-agent-current)) into the VM and run, as that
   account in an elevated prompt:
   ```powershell
   groundhog-agent install-task
   ```
   This copies the agent to `%ProgramData%\groundhog\bin` and registers the logon task
   `Groundhog\RunPending`, which runs elevated in the user's session 15 seconds after logon.
4. **Proxmox:** install the virtio drivers and the **QEMU guest agent** from the virtio-win ISO,
   and enable the guest agent in the VM options. That lets the host write files into clones.
5. Generalize if needed (sysprep with an unattend file that keeps autologon), then convert to a
   template.

## Per clone

Write `%ProgramData%\groundhog\pending.json` into the clone before, or right after, its first
boot. `groundhog pending` generates one:

```powershell
groundhog pending https://example.com/dev.groundhog.yaml `
  --cache \\nas\groundhog-cache --report \\nas\groundhog-status\vm42 -o pending.json
```

```json
{
  "source": "https://example.com/dev.groundhog.yaml",
  "cache": ["\\\\nas\\groundhog-cache"],
  "report": ["\\\\nas\\groundhog-status\\vm42"]
}
```

Ways to get it into the clone:
- **Hyper-V:** `Copy-VMFile`, or `Copy-Item -ToSession (New-PSSession -VMName …)`.
- **Proxmox:** `qm guest exec` / the guest agent's `file-write` API
  (`POST /nodes/{node}/qemu/{vmid}/agent/file-write`).
- **Anything:** attach a small ISO or disk containing it, or bake a per-clone value into
  cloudbase-init user data.

If the Groundhogfile names secrets (such as a user's password), add them with
`--secret NAME`, which reads the value from the `NAME` environment variable on the host. Until
the agent reads `pending.json`, the file holds them in plain text, so treat it like a password
in transit. The agent removes them from the file immediately and keeps them only encrypted,
and only until the run finishes. See [Secrets](groundhogfile.md#secrets).

At logon the agent applies it and renames it to `pending.done.json` or `pending.failed.json`.
If a restart is needed it restarts and continues at the next logon. Progress goes to every
`report` sink as `status.json` plus `agent.log`, or JSON POSTs for `http(s)` sinks.

## Keeping the template's agent current

The agent baked into a template would otherwise be frozen at bake time, and newer Groundhogfiles
would stop working in new clones. So **before each run from `pending.json`, the agent updates
itself**:

1. It asks the update source what it offers (`agent.json`).
2. If that's newer, it downloads the new agent and checks its SHA-256 against the manifest.
3. It swaps the new agent in place of the running one (a running exe can be renamed, just not
   overwritten) and hands the run over to it.

The template's copy in `%ProgramData%\groundhog\bin` stays current, so every later clone starts
from the updated agent. If anything goes wrong (no network, a bad hash, an unreachable
source), the run carries on with the agent it has, and logs why. **Updating never fails a run.**

Control it per clone in `pending.json`:

```json
{
  "source": "https://example.com/dev.groundhog.yaml",
  "agentUpdate": "latest",
  "agentUpdateFrom": "\\\\nas\\groundhog\\agent"
}
```

| Field | Values | Default |
| --- | --- | --- |
| `agentUpdate` | `latest` (move forward when a newer one appears), a version such as `0.5.0` (move to exactly that one, up or down), or `off` | `latest` |
| `agentUpdateFrom` | An `agent.json` URL, or a folder, UNC share or URL holding one | GitHub releases |

`groundhog pending` writes them with `--agent-update` and `--agent-update-from`.

### Serving updates yourself

Any folder, share or web server holding `agent.json` and the agent exes it names is an update
source. To mirror a release into one, so clones never need GitHub:

```powershell
groundhog mirror-agent \\nas\groundhog\agent                  # the latest release
groundhog mirror-agent \\nas\groundhog\agent --version 0.5.0  # or a specific one
```

It downloads the agents, verifies them against the release's manifest, and writes
`agent.json` **last**, so the folder never advertises an agent that isn't fully there. You can
also copy a release's `agent.json` and `groundhog-agent-*.exe` assets by hand; they're all
together on each release page.

### What still has to be baked once

Self-update arrived in **0.5.0**. A template baked with an older agent can't update itself, and
it rejects Groundhogfiles or `pending.json` files that use newer keys. Rebake it once with 0.5.0
or later; after that, the template keeps itself current.

### Trust

An update is a program that runs elevated at logon, so know where it comes from. The agent
only installs a file whose SHA-256 matches the manifest it read over HTTPS (or from your share).
That stops corruption and tampering in transit, but it trusts whoever controls the source: the
GitHub repository, or your share. Point `agentUpdateFrom` at a share only trusted admins can
write to. Pin a version (`"agentUpdate": "0.5.0"`) when you want to review each release before
clones pick it up.
