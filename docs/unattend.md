# Unattend files

`groundhog unattend` writes a Windows answer file that takes a machine from Windows Setup, or
from a sysprepped template, to "the agent is applying a Groundhogfile", with nobody at the
keyboard.

The file covers **only what has to happen before the agent can run**:
- accept the license and skip the setup screens;
- set the computer name, language and time zone;
- create the provisioning account and log it on automatically;
- on first logon, install the agent, write its `pending.json`, register its logon task and
  start it.

Everything else (apps, files, registry, `run`, `verify`) stays in the Groundhogfile. Commands in
an unattend file have no retries, no status and no resume; the agent has all three.

> **Status (v0.8.0):** the generated XML is checked in tests (structure, password encoding,
> 1,024-character command limit), and its first-logon commands were run for real outside Setup:
> they download the agent and rebuild `pending.json` byte for byte. A complete Windows Setup
> run from one of these files has **not** been verified yet. Try it on a throwaway VM first.

## Two modes

### `--mode install`: from ISO or USB

```powershell
groundhog unattend https://example.com/dev.groundhog.yaml --mode install `
  --edition "Windows 11 Pro" --wipe-disk 0 `
  --driver-path E:\vioscsi\w11\amd64 --bypass-hardware-checks `
  --timezone "Pacific Standard Time" -o autounattend.xml
```

Put `autounattend.xml` at the root of the install media (a USB stick, or a small second ISO
attached to the VM). Setup finds it automatically.

| Option | What it does |
| --- | --- |
| `--edition` | Which image to install, by name (`Windows 11 Pro`) or index (`6`). Without it, Setup asks. |
| `--product-key` | Without one, some media ask for a key. |
| `--wipe-disk N` | **Erases disk N** and partitions it for UEFI (EFI, MSR, Windows). Without it, Setup asks where to install. Legacy BIOS/MBR isn't supported. |
| `--driver-path` | A folder of drivers Setup needs to see the disk. Proxmox VirtIO disks need `vioscsi` (or `viostor`) from the virtio-win ISO, e.g. `E:\vioscsi\w11\amd64`. Repeatable. |
| `--bypass-hardware-checks` | Skips Windows 11's TPM, Secure Boot, CPU and RAM checks, for VMs that don't emulate them. |

### `--mode sysprep`: sealing a template

```powershell
groundhog unattend https://example.com/dev.groundhog.yaml --mode sysprep -o C:\unattend.xml
sysprep /generalize /oobe /shutdown /unattend:C:\unattend.xml
```

Every clone of the sealed template runs the file's per-clone part: a new computer name (`*`
means random, which is right for clones), the account, autologon, and the agent bootstrap. If
the template already has an agent in `%ProgramData%\groundhog\bin`, it isn't downloaded again;
it [updates itself](templates.md#keeping-the-templates-agent-current) instead.

## Common options

| Option | Default | What it does |
| --- | --- | --- |
| `--autologon NAME` | `provisioner` | The local administrator that logs on automatically and runs the agent. |
| `--autologon-password NAME` | generated | Read from the `NAME` environment variable (or `NAME=value`). Generated when omitted, and printed once. |
| `--autologon-count N` | `5` | How many automatic logons; every restart during setup uses one. |
| `--computer-name` | `*` | Up to 15 letters, digits and hyphens, or `*` for a random name. |
| `--locale` | `en-US` | Language for Setup, the system and the user. |
| `--timezone` | `UTC` | A Windows time zone id (`tzutil /l` lists them). |
| `--arch` | `x64` | `x64` or `arm64`: the components' architecture, and which agent to download. |
| `--agent-url` | latest release | Where the new machine downloads the agent, e.g. your own mirror. |

`pending.json` options work as with `groundhog pending`: `--cache`, `--report`, `--secret`,
`--agent-update`, `--agent-update-from`, `--no-reboot`, `--sha256`, `--allow-http`.

## Security

- **Passwords in unattend files are only obfuscated** (base64 of UTF-16 text), not encrypted.
  Anyone who can read the file, or the install media it's on, can recover the autologon
  password. That's acceptable for disposable lab VMs; keep the file private anyway.
- **Secrets travel inside the file.** With `--secret`, the values are embedded in the
  first-logon commands that write `pending.json`. Setup keeps a copy of the answer file in
  `C:\Windows\Panther`. It blanks password fields in that copy but not our commands, so when
  secrets are present, the last first-logon command deletes that copy. A sysprep file you
  passed yourself (`/unattend:C:\unattend.xml`) stays where you put it; delete it after
  sealing. Once the agent has read `pending.json`, secrets live only DPAPI-encrypted and only
  until the run finishes (see [Secrets](groundhogfile.md#secrets)).
- The provisioning account is a local administrator with autologon. For disposable VMs that's
  the point; don't use this on machines people keep.

## What happens on first logon

1. Create `%ProgramData%\groundhog\bin`.
2. Download the agent, unless the image already has one.
3. Write `pending.json`, in base64 pieces (Windows limits each command to 1,024 characters).
4. `groundhog-agent install-task`: the logon task that continues runs after restarts.
5. `schtasks /Run` to start applying now, in the background, so the desktop isn't held up.
6. If secrets were embedded, delete Setup's copy of the answer file.

From there, progress is in `%ProgramData%\groundhog\last-run`, or wherever `--report` points.
