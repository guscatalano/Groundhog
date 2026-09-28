# Preparing a VM template

Any hypervisor works (Hyper-V, Proxmox, VMware, …). The template carries the agent and a logon
task. Each clone does nothing until a host drops a `pending.json` into it.

## One-time template setup

1. Install Windows and create a local **provisioning account** (an administrator).
2. Turn on **autologon** for that account, for example with Sysinternals Autologon (which stores
   the password as an LSA secret) or `Winlogon` registry values. The password is stored
   recoverably, which is fine for disposable VMs but worth knowing.
3. Copy `groundhog-agent.exe` into the VM and run, as that account in an elevated prompt:
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

At logon the agent applies it and renames it to `pending.done.json` or `pending.failed.json`.
If a restart is needed it restarts and continues at the next logon. Progress goes to every
`report` sink as `status.json` plus `agent.log`, or JSON POSTs for `http(s)` sinks.
