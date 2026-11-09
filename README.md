<div align="center">

<img src="https://i.ibb.co/Nd3YR7Sn/Untitled.png" alt="0net 2.0" width="600">

<br>
<br>

![platforms](https://img.shields.io/badge/platforms-windows%20%7C%20linux%20%7C%20android%20%7C%20iot-blue)
![crypto](https://img.shields.io/badge/crypto-HKDF--SHA256%20%2B%20AES--128--CBC%20%2B%20HMAC-green)

<br>

[What this is](#what-this-is) · [Architecture](#architecture) · [Protocol](#protocol) · [Capabilities](#capabilities) · [OPSEC](#detection--opsec)

</div>

---
## What this is

0net 2.0 is a ground-up rewrite of 0net, a proof-of-concept C2 framework. [Version 1.0](https://github.com/Prvvv/0net) was a PHP front end and a text file: the server wrote `pico-wifi.txt` (named after the [Raspberry Pi Pico](https://www.raspberrypi.com/products/raspberry-pi-pico/)'s Wi-Fi module), bots read it, results were appended to `responses.txt`, and commands were encrypted with a Vigenère cipher. It worked, and it was a demo.

2.0 replaces the file drop with an actual protocol and the cipher with something that isn't a puzzle. Four implants share one design language across Windows, Linux, Android and embedded IoT: a compact encrypted beacon, per-device enrollment, and an operator console that streams results live.

---

## Architecture

| | Windows | Linux | Android |
|---|---|---|---|
| Language | PowerShell + cmd.exe | Python 3 | Kotlin |
| Delivery | `.bat` polyglot | `.sh` polyglot | signed APK |
| Poll default | 3 s ± jitter | 3 s ± jitter | 2 s |
| Elevation | opportunistic | opportunistic | opportunistic (`su`) |
| VM guard | yes | yes | no |
| Screenshot | .NET GDI | X11 / 9 tool fallback | camera intent |
| Shell | persistent `cmd.exe` cwd | persistent cwd | persistent `su`/`sh` |


---

## Protocol

---








## Capabilities

<details>
<summary><b>Windows</b></summary>

| Command | Effect |
|---|---|
| `info` | Full system report to `reports/` |
| `shellcmd <cmd>` | Run via `cmd.exe`, output to temp file |
| `screenshot` | Full-display capture → `loot/` |
| `sleep <sec>` | Change poll interval |
| `updateserver <url>` | Repoint the implant |
| `updatekey <key>` | Rotate the payload key |
| `forget` | Clear the device secret, force re-enroll |
| `remove` | **Destructive.** Strip persistence, delete artefacts, exit |

</details>

<details>
<summary><b>Linux</b></summary>

| Command | Effect |
|---|---|
| `info` | Full system report to `reports/` |
| `shellcmd <cmd>` | Run via `/bin/sh` with persistent cwd |
| `screenshot` | X11 capture → `loot/` |
| `sleep <sec>` | Change poll interval |
| `updateserver <url>` | Repoint the implant |
| `updatekey <key>` | Rotate the payload key |
| `forget` | Clear the device secret, force re-enroll |
| `remove` | **Destructive.** Strip persistence, delete artefacts, exit |

</details>

<details>
<summary><b>Android</b></summary>

| Command | Effect |
|---|---|
| `info` | Full device report |
| `listen_start` / `listen_stop` | Live telemetry stream |
| `contacts` / `sms` / `calllog` | JSON dumps |
| `photo` / `audio` / `video` | Capture and upload |
| `file <path>` | Exfiltrate a path |
| `location` | Last known fix |
| `shellstart` / `shellcmd` / `shellint` / `shellstop` | Persistent shell with streamed output |
| `fallback <urls>` | Set fallback server list |
| `updatekey` / `updateserver` | Rotate key / repoint |
| `remove` | **Destructive.** Uninstall intent, disable all components, wipe, kill |

</details>

---
## Operator console

<details>
<summary><b>Linux / Windows server</b></summary>

| Command | Effect |
|---|---|
| `show` | List connected clients |
| `info` | Pull full system info from everyone |
| `<ID\|IP> <cmd>` | Run a command on one client |
| `<cmd>` | Broadcast to everyone |
| `\<cmd>` | Forced broadcast, even if the name is reserved |
| `shell <ID>` | Interactive shell, `shell <other>` switches target |
| `shot [ID]` | Screenshot to `loot/` |
| `sleep <sec> [ID]` | Change poll interval |
| `remove <ID\|IP>` | **Destructive.** Block and self-destruct |
| `unblock <ID\|IP>` | Lift a block |
| `revoke <ID>` | Drop secret, force re-enroll |
| `setkey <key>` | Rotate the fleet key |
| `updateserver <url>` | Push a new server URL |
| `config` / `log` / `loot` / `clear` | Local inspection |

<img src="https://i.ibb.co/k6wkLM1G/windows.png">

</details>

<details>
<summary><b>Android server</b></summary>

| Command | Effect |
|---|---|
| `show` | List clients |
| `info` | Request full info |
| `<id> <cmd>` | Target a client |
| `listen <id>` | Live telemetry dashboard, Ctrl-C to stop |
| `shell <id>` | Persistent shell, `!int` for SIGINT |
| `setkey` / `updateserver` / `fallback` | Rotation and repointing |
| `remove <id>` | **Destructive.** Block and self-destruct |
| `config` / `clear` | Local inspection |

</details>

---

## IoT console (0net-IoT)

<img src="https://i.ibb.co/Q765Mx2t/iot.png">

A Tk desktop application for managing IoT and embedded gear, routers, switches, APs, cameras, printers, NAS, UPS, PLC/SCADA front ends. **Nothing executes on the target.** This plane is a manager, not an implant: it probes, classifies, geolocates and opens terminals. It stores what it finds encrypted at rest and shares cleanly with a second operator.

State lives in `~/.0net`: `devices.enc` (AES-256-GCM), `.master` (32-byte key, `0600`), `config.json`, `0net.log`. The directory is created `0700`.

<details>
<summary><b>Operations</b></summary>

| Action | Effect |
|---|---|
| Add device | Manual entry: IP, port, type, vendor, model, serial, credentials, notes |
| Bulk add | One per line, `a.b.c.d-a.b.c.d` range, or CIDR. Probes first, adds only responders |
| Edit / multi-edit | Single record, or tick-a-field bulk apply across a selection |
| Delete | Removes locally, undo toast for five seconds |
| Ping | TCP connect to the stored port, records latency |
| Pulse | Rotating sweep, one host per interval, 6 s per-host cooldown |
| Terminal | Telnet session, IAC stripped, multi-select opens tabs |
| Map | Plots every geolocated device, click for a record popup |
| Share | Encrypted `.0share` export, fresh 32-byte key each generation |
| Import | Verify, preview, then merge with optional overwrite of duplicates |
| Search / filter / sort | Free text across every field, online/offline chips, any column |
| Copy IPs | Selected addresses to clipboard |

</details>

<details>
<summary><b>Bulk add options</b></summary>

| Option | Default | Effect |
|---|---|---|
| Send newline to elicit a banner | on | Most devices stay silent until they receive input |
| Reject error banners | on | Discards `timeout`, `login failed`, `connection refused`, ~250 other failure strings |
| Capture banner into notes | on | Stores the first 500 bytes of the response |
| Auto-detect type from banner | on | Maps banner keywords to a device class |
| Slow sweep | on | 8 workers, 250 ms spacing — single-session devices stop dropping |

Fast mode is 32 workers, no spacing. Batch caps at 1024 addresses; ranges are truncated with a warning.

</details>

<details>
<summary><b>Storage and sharing</b></summary>

- The store is a single AES-256-GCM blob with `0net-store-v2` as AAD. Truncation and AAD mismatch both fail loudly.
- A plaintext `devices.csv` from 1.0 is migrated on first run. **The old file is left in place**, delete it once you have verified the list.
- Share files are self-describing: format tag, version, cipher, KDF, creation time, device count, credential flag. All of it is authenticated as AAD.
- The share key is 32 bytes, base32, grouped in fours for transcription, and is **not** in the file. Every click of Generate mints a new one and retires the last.
- Import previews before it commits and flags IP collisions. Overwrite is opt-in.

</details>

---

## Quick start
<details>
<summary><b>IoT</b></summary>

Requirements: Python 3.9+, Tk, `cryptography`. `requests` for geolocation, `tkintermapview` + `Pillow` for the map.

```bash
pip install cryptography requests tkintermapview Pillow
python3 0net_iot.py


































---

## Quick start
<details>
<summary><b>Linux</b></summary>

Requirements: Python 3.9+. Root on the server side is recommended so `reports/` and `loot/` are writable.

**Server**

1. Set `SERVER_ENCRYPTION_KEY_STR` in `server.py` to a 16-character key.
2. Start it:

```bash
python3 server.py
```

It binds `[::]:3000`


**Client**

1. Set `BUILD`, `SERVER` and `KEYSTR` at the top of `client.sh`. `KEYSTR` must match the server key exactly.
2. Run it:

```bash
chmod +x client.sh
./client.sh
```

3. Confirm it is up:

```bash
./0net2.sh --status
./0net2.sh --show
```

`--show` keeps it in the foreground with console output. `--kill` stops it, `--uninstall` strips persistence and removes every artefact.


</details>

<details>
<summary><b>Windows</b></summary>


Requirements: Windows 10/11, Python 3.9+ The client runs under the logged-on user and needs no elevation.

**Server**

1. Set `SERVER_ENCRYPTION_KEY_STR` in `server.py` to a 16-character key.
2. Start it:

```powershell
python server.py
```

It binds `127.0.0.1:3000`

**Client**

1. Set `$Server` and `$KeyStr` near the top of the `.bat`. `$KeyStr` must match the server key exactly.
2. Run the `.bat`.

It extracts the PowerShell payload to `%LOCALAPPDATA%\Microsoft\Diagnostics`, writes `launch.vbs`, installs persistence and starts hidden. Nothing appears on screen.

**Notes**

- `$VmBlock = $true` by default. On a hypervisor the implant reports in, wipes itself and stays dark. Delete `%LOCALAPPDATA%\Microsoft\Diagnostics\vm.block` to re-arm, or set it to `$false`.
- Run `client.ps1 -Show` for a console window, `-Status`-style output via `-Test`, `-Kill` to stop, `-Uninstall` to strip persistence and artefacts.


</details>

<details>
<summary><b>Android</b></summary>

Requirements: a Linux build host (the builder pulls Linux JDK and SDK archives), Python 3.9+, `unzip`, `tar`, and `adb`. The output is a release APK signed with a keystore the builder generates once at `~/.keys/onet-release.jks`.

**Server**

Use the Android server, not the Windows or Linux one — it speaks a different protocol.

1. Set `ENCRYPTION_KEY` at the top of `server.py` to exactly 16 characters.
2. Start it:

```bash
python3 server.py
```

It binds `0.0.0.0:3000`.

**Client**

1. Set `SERVER_URL` and `ENCRYPTION_KEY` at the top of `client.py`. The key must be exactly 16 characters and must match the server.
2. Build:

```bash
python3 client.py
```

The builder installs JDK 17 and the Android SDK into `/jdk17` and `/android-sdk` on first run, then produces `appxyz*.apk`.

**Notes**

- First launch walks the permission prompts, asks for battery-optimisation exemption and exact-alarm access, then disables its own launcher entry, the app disappears from the drawer and the icon is transparent.
- Background location is granted via a redirect to the app settings page on Android 11+, not a dialog. Grant it manually.
- `remove` sends an uninstall intent, so the operator still has to tap through the confirmation.

</details>

## Detection & OPSEC

<details>
<summary><b>Windows</b></summary>

**Anonymisation**
- Starts through `wscript.exe //B //NoLogo` → PowerShell `-WindowStyle Hidden`. No console ever appears.
- Payload sits in `%LOCALAPPDATA%\Microsoft\Diagnostics`, which reads as a Microsoft component rather than a tool directory.
- User-Agent is a current Chrome-on-Win64 string; traffic rides the tunnel over TLS.

**Anti-exploitation** (hard to take over or kill)
- Named mutex `Local\RemoteDiagnosticsClient` enforces single instance; the incumbent kills stale siblings before re-arming.
- Three independent persistence mechanisms; a fourth surviving copy is unlikely, so a partial clean-up restores on next logon.
- Requires no elevation, so it survives UAC-restricted sessions.
- `remove` strips Run key, task, shortcut, config, launcher and payload, then exits.

**Anti-detection**
- VM guard: SMBIOS, BIOS, baseboard, disk enumeration and guest-tool process checks. Any single hit burns the box and it never returns.
- Command output is redirected to a temp file rather than a pipe, so a launched GUI app cannot stall the poll loop and trip a timeout-based detector.
- Log truncates at 512 KB; delivered command IDs cap at 2000 in memory.

</details>

<details>
<summary><b>Linux</b></summary>

**Anonymisation**
- Double-fork daemonise, `setsid`, stdio to `/dev/null`. No controlling terminal.
- Runs as `python3 /…/client.py`, so it shows as an interpreter, not a named binary.
- `launch.sh` reconstructs `DISPLAY`, `XAUTHORITY` and `WAYLAND_DISPLAY` so it can reach a desktop session from cron or systemd where those are absent.
- Chrome-on-X11 User-Agent with a distro token; TLS to the tunnel.

**Anti-exploitation**
- `fcntl` exclusive lock with a 30-second retry loop. The holder is authoritative and a competing start loses instead of racing.
- Three persistence mechanisms across systemd user units, XDG autostart and crontab.
- Three AES backends with graceful degradation: `cryptography`, then `pycryptodome`, then pure Python. The implant still works on a box with no crypto packages.
- Screenshot chain has nine external tools plus `xwd`/`convert` plus a raw `XGetImage` path, so it succeeds without any of them installed.
- `remove` disables all three persistence mechanisms, deletes config, launcher, script and ID, then `rmtree`s the temp directory.

**Anti-detection**
- VM guard across DMI, CPUID hypervisor flag, kernel modules, virtio device nodes, SCSI strings, guest-tool processes and `/.dockerenv`.
- Poll jitter up to 800 ms; exponential backoff to 60 s on failure.
- Per-install `MID:` salt means cloned images do not collide on one ID.

</details>

<details>
<summary><b>Android</b></summary>

**Anonymisation**
- Icon and label are transparent and empty; after first launch `MainActivity` disables itself and the app leaves the drawer entirely.
- Notification channel is `IMPORTANCE_MIN`, `VISIBILITY_SECRET`, no sound, no vibration, no badge — collapsed under "silent" if noticed at all.
- `okhttp/4.9.0` User-Agent.

**Anti-exploitation**
- Sticky foreground service, persisted `JobScheduler` every 15 minutes, `setAndAllowWhileIdle` alarm chain every 5 minutes, boot receivers for `BOOT_COMPLETED` and vendor quick-boot variants.
- `onTaskRemoved` schedules an exact restart 1.5 s out, so swiping the task away does not stop it.
- Four watchdogs restart the poll loop, the wake lock, the telemetry job and the shell independently.
- Server fallback list survives a primary going dark.
- `remove` fires an uninstall intent, clears prefs and files, disables every component and kills the process.

**Anti-detection**
- Battery-optimisation exemption and exact-alarm access are requested up front so doze does not silently starve the poll.
- No VM guard — an emulator is treated as a real device.

</details>

### Summary

| | Windows | Linux | Android |
|---|---|---|---|
| Hides from user | yes | partial | yes |
| VM guard | yes | yes | no |
| Persistence layers | 3 | 3 | 5 |
| Per-device secret | yes | yes | no |
| Replay defence | nonce | nonce | timestamp only |
| Self-destruct | yes | yes | yes |

> **Operational responsibility.** Compromise of the server, leakage of a fleet key or an enrolled sec (Dont be lazy!!!)


## Legal

<span style="font-size:0.5em;">
Provided as-is for research and authorised security testing. Deploy only on systems you own or have written permission to test. No warranty; the operator is responsible for authorisation and for anything the framework does on a host. Not a substitute for a formal pentest engagement.</span>


