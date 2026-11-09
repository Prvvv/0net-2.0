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


---

## What this is


---

## Architecture



**Component matrix**

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


<details>
<summary><b>Wire format, auth and crypto</b></summary>

**Transport.** 

**Endpoints.** 

**Derivation.** 

**Payload.** 

**Auth.** 

**Enrollment.**

**Rotation.**

**Identity.** 

**Replay surface.** 

</details>

<details>
<summary><b>Request and response examples</b></summary>


</details>

<details>
<summary><b>Key material</b></summary>




</details>

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

## Persistence & evasion

<details>
<summary><b>Linux</b></summary>


Paths: 

</details>

<details>
<summary><b>Windows</b></summary>


Paths: 

</details>

<details>
<summary><b>Android</b></summary>


</details>

<details>
<summary><b>VM guard (Windows / Linux)</b></summary>

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

## IoT console

---

## Quick start
<details>
<summary><b>Linux</b></summary>

**Server**


**Client**


</details>

<details>
<summary><b>Windows</b></summary>

**Server**


**Client**


</details>

<details>
<summary><b>Android</b></summary>


</details>

---

## Detection & OPSEC



---

## Repository layout


---

## Legal

