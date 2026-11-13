import base64
import csv
import io
import ipaddress
import json
import logging
import os
import queue
import re
import secrets
import socket
import struct
import subprocess
import sys
import threading
import time
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from tkinter import ttk, messagebox, scrolledtext, filedialog

try:
    import requests
except ImportError:
    requests = None

try:
    import tkintermapview
except ImportError:
    tkintermapview = None

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.fernet import Fernet
except ImportError:
    print("This needs the 'cryptography' package: cryptography")
    sys.exit(1)


# ---------------------------------------------------------------- paths

APP_DIR = Path.home() / ".0net"
APP_DIR.mkdir(parents=True, exist_ok=True)
STORE_PATH = APP_DIR / "devices.enc"
MASTER_KEY_PATH = APP_DIR / ".master"
OLD_FERNET_KEY = APP_DIR / ".key"
CONFIG_PATH = APP_DIR / "config.json"
LOG_PATH = APP_DIR / "0net.log"

# where we look for an old plaintext CSV to migrate
OLD_CSV_PATHS = [APP_DIR / "devices.csv", Path.cwd() / "devices.csv"]

_handler = RotatingFileHandler(LOG_PATH, maxBytes=2_000_000, backupCount=3)
_handler.setFormatter(logging.Formatter(
    "%(asctime)s %(levelname)s %(name)s: %(message)s"))
logging.basicConfig(level=logging.INFO, handlers=[_handler])
log = logging.getLogger("0net")

CGNAT = ipaddress.ip_network("100.64.0.0/10")

http = requests.Session() if requests else None
if http:
    http.headers["User-Agent"] = "0net/2.2"


# ---------------------------------------------------------------- crypto

STORE_AAD = b"0net-store-v2"
SHARE_FORMAT = "0net-share"
SHARE_VERSION = 1


def load_master_key():
    if MASTER_KEY_PATH.exists():
        try:
            k = base64.b64decode(MASTER_KEY_PATH.read_bytes().strip())
            if len(k) == 32:
                return k
            log.warning("master key wrong size, regenerating")
        except Exception:
            log.exception("couldn't read master key")
    k = secrets.token_bytes(32)
    try:
        MASTER_KEY_PATH.write_bytes(base64.b64encode(k))
        MASTER_KEY_PATH.chmod(0o600)
    except Exception:
        log.exception("couldn't save master key (data won't persist)")
    return k


MASTER_KEY = load_master_key()


# ---------------------------------------------------------------- csv

CSV_HEAD = ["ip", "type", "vendor", "model", "port", "username",
            "password", "serial", "notes", "city", "country",
            "lat", "lon", "isp", "online", "last_checked", "added"]


def csv_bytes(devices):
    buf = io.StringIO()
    buf.write("# schema=2\n")
    w = csv.writer(buf)
    w.writerow(CSV_HEAD)
    for d in devices:
        loc = d.get("location") or {}
        w.writerow([
            d.get("ip", ""), d.get("type", ""), d.get("vendor", ""),
            d.get("model", ""), d.get("port", 23), d.get("username", ""),
            d.get("password", ""), d.get("serial", ""), d.get("notes", ""),
            loc.get("city", ""), loc.get("country", ""),
            loc.get("lat", 0), loc.get("lon", 0), loc.get("isp", ""),
            "true" if d.get("online") else "false",
            d.get("last_checked", ""), d.get("added", ""),
        ])
    return buf.getvalue().encode("utf-8")


def parse_csv(data):
    text = data.decode("utf-8", errors="replace")
    text = "\n".join(l for l in text.splitlines() if not l.startswith("#"))
    out, skipped = [], 0
    for row in csv.DictReader(io.StringIO(text)):
        ip = (row.get("ip") or "").strip()
        if not ip or not valid_ip(ip):
            skipped += 1
            continue
        port = safe_int(row.get("port"), 23)
        if not valid_port(port):
            port = 23
        try:
            lat = float(row.get("lat") or 0)
            lon = float(row.get("lon") or 0)
        except ValueError:
            lat, lon = 0.0, 0.0
        out.append({
            "ip": ip,
            "type": row.get("type") or "",
            "vendor": row.get("vendor") or "",
            "model": row.get("model") or "",
            "port": port,
            "username": row.get("username") or "",
            "password": row.get("password") or "",
            "serial": row.get("serial") or "",
            "notes": row.get("notes") or "",
            "location": {"city": row.get("city") or "",
                         "country": row.get("country") or "",
                         "lat": lat, "lon": lon,
                         "isp": row.get("isp") or ""},
            "online": str(row.get("online", "false")).lower() == "true",
            "latency_ms": None,
            "last_checked": row.get("last_checked") or "",
            "added": row.get("added") or "",
        })
    if skipped:
        log.warning("skipped %d bad row(s) in csv", skipped)
    return out


def save_store(devices):
    payload = csv_bytes(devices)
    nonce = secrets.token_bytes(12)
    ct = AESGCM(MASTER_KEY).encrypt(nonce, payload, STORE_AAD)
    tmp = STORE_PATH.with_suffix(".enc.tmp")
    tmp.write_bytes(nonce + ct)
    try:
        tmp.chmod(0o600)
    except OSError:
        pass
    os.replace(tmp, STORE_PATH)


def load_store():
    if not STORE_PATH.exists():
        return None
    blob = STORE_PATH.read_bytes()
    if len(blob) < 28:
        raise RuntimeError("store truncated")
    return parse_csv(AESGCM(MASTER_KEY).decrypt(blob[:12], blob[12:],
                                                STORE_AAD))


def load_legacy_csv(path):
    """Read old plaintext csv. Decrypts enc: fields if the old Fernet
    key is still around, otherwise blanks them."""
    fernet = None
    if OLD_FERNET_KEY.exists():
        try:
            fernet = Fernet(OLD_FERNET_KEY.read_bytes())
        except Exception:
            log.exception("legacy key unreadable, blanking secrets")
    raw = path.read_text(encoding="utf-8", errors="replace")
    devices = parse_csv(raw.encode("utf-8"))
    for d in devices:
        for f in ("username", "password"):
            v = d[f]
            if v.startswith("enc:"):
                if not fernet:
                    d[f] = ""
                else:
                    try:
                        d[f] = fernet.decrypt(v[4:].encode()).decode()
                    except Exception:
                        d[f] = ""
    return devices


# ---------------------------------------------------------------- share

class ShareError(Exception):
    pass


def make_share(devices, include_creds=True):
    """Returns (key_bytes, file_bytes). Fresh key each call."""
    share = []
    for d in devices:
        share.append({
            "ip": d.get("ip", ""),
            "type": d.get("type", ""),
            "vendor": d.get("vendor", ""),
            "model": d.get("model", ""),
            "port": safe_int(d.get("port"), 23),
            "username": d.get("username", "") if include_creds else "",
            "password": d.get("password", "") if include_creds else "",
            "serial": d.get("serial", ""),
            "notes": d.get("notes", ""),
            "location": dict(d.get("location") or {}),
            "online": bool(d.get("online")),
            "latency_ms": d.get("latency_ms"),
            "last_checked": d.get("last_checked", ""),
            "added": d.get("added", ""),
        })
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    meta = {
        "format": SHARE_FORMAT,
        "version": SHARE_VERSION,
        "cipher": "AES-256-GCM",
        "kdf": "none",
        "created": datetime.now(timezone.utc).replace(
            microsecond=0).isoformat(),
        "device_count": len(share),
        "includes_credentials": bool(include_creds),
    }
    aad = json.dumps(meta, sort_keys=True,
                     separators=(",", ":")).encode()
    ct = AESGCM(key).encrypt(nonce, csv_bytes(share), aad)
    env = dict(meta)
    env["nonce"] = base64.b64encode(nonce).decode()
    env["payload"] = base64.b64encode(ct).decode()
    return key, json.dumps(env, indent=2).encode()


def open_share(file_bytes, key_bytes):
    """Returns list of devices. Raises ShareError on any problem."""
    if not isinstance(key_bytes, (bytes, bytearray)) or len(key_bytes) != 32:
        raise ShareError("key must be exactly 32 bytes")
    try:
        env = json.loads(file_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ShareError("not a 0net share file") from e
    if not isinstance(env, dict) or env.get("format") != SHARE_FORMAT:
        raise ShareError("not a 0net share file")
    if env.get("version") != SHARE_VERSION:
        raise ShareError(f"unsupported share version {env.get('version')}")
    try:
        nonce = base64.b64decode(env["nonce"], validate=True)
        ct = base64.b64decode(env["payload"], validate=True)
    except (KeyError, ValueError) as e:
        raise ShareError("share file is missing fields") from e
    if len(nonce) != 12:
        raise ShareError("bad nonce length")
    meta = {k: v for k, v in env.items() if k not in ("nonce", "payload")}
    aad = json.dumps(meta, sort_keys=True, separators=(",", ":")).encode()
    try:
        payload = AESGCM(key_bytes).decrypt(nonce, ct, aad)
    except Exception as e:
        raise ShareError(
            "decryption failed — wrong key, or the file was modified") from e
    return parse_csv(payload)


def format_key(key_bytes):
    s = base64.b32encode(key_bytes).decode().rstrip("=")
    return "-".join(s[i:i + 4] for i in range(0, len(s), 4))


_KEY_JUNK = re.compile(r"[\s\-_.]+")


def parse_key(s):
    if not isinstance(s, str):
        return None
    clean = _KEY_JUNK.sub("", s).upper()
    if not clean:
        return None
    pad = (-len(clean)) % 8
    try:
        k = base64.b32decode(clean + "=" * pad)
    except Exception:
        return None
    return k if len(k) == 32 else None


# ---------------------------------------------------------------- misc

def valid_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def is_public(s):
    try:
        o = ipaddress.ip_address(s)
    except ValueError:
        return False
    if o.version == 4 and o in CGNAT:
        return False
    try:
        return o.is_global
    except Exception:
        return not (o.is_private or o.is_loopback or o.is_link_local
                    or o.is_multicast or o.is_reserved)


def safe_int(v, default=0):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def valid_port(p):
    try:
        return 1 <= int(p) <= 65535
    except (TypeError, ValueError):
        return False


def telnet_strip(data):
    """Strip IAC sequences. Also handles SB...SE."""
    IAC, SB, SE = 255, 250, 240
    out = bytearray()
    i, n = 0, len(data)
    while i < n:
        b = data[i]
        if b != IAC:
            if 32 <= b < 127 or b in (9, 10, 13):
                out.append(b)
            i += 1
            continue
        if i + 1 >= n:
            break
        cmd = data[i + 1]
        if cmd == IAC:
            out.append(IAC)
            i += 2
        elif cmd == SB:
            i += 2
            while i + 1 < n and not (data[i] == IAC and data[i + 1] == SE):
                i += 1
            i += 2
        elif cmd in (251, 252, 253, 254):
            i += 3
        else:
            i += 2
    return out.decode("utf-8", errors="replace")


def close_socket(s):
    if not s:
        return
    try:
        s.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        s.close()
    except OSError:
        pass


def make_socket(ip, port, timeout):
    try:
        fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                     struct.pack("ii", 1, 0))
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.settimeout(timeout)
        return s
    except OSError:
        return None


# ---------------------------------------------------------------- banner filter

REJECT_PHRASES = [
    "timeout", "timed out", "time-out", "unreachable",
    "no route to host", "network unreachable", "host unreachable",
    "destination unreachable", "host down", "server down", "device down",
    "not responding", "not available", "no response", "no reply", "no answer",
    "cannot connect", "could not connect", "unable to connect",
    "can't connect", "cant connect", "connection refused", "connection reset",
    "connection closed", "connection failed", "connection aborted",
    "connection dropped", "connection error", "connection lost",
    "connection terminated", "connection timed out",
    "connection attempt failed", "login incorrect", "login failed",
    "incorrect login", "wrong login", "bad login", "invalid login",
    "login error", "login denied", "login aborted", "user incorrect",
    "wrong user", "unknown user", "user not found", "no such user",
    "invalid user", "username incorrect", "invalid username",
    "password incorrect", "incorrect password", "wrong password",
    "password failed", "bad password", "invalid password",
    "password denied", "password rejected", "password required",
    "password authentication failed", "authentication failed",
    "authentication error", "authentication rejected",
    "authentication timeout", "authentication required", "auth failed",
    "auth error", "auth rejected", "logon failure", "logon failed",
    "unauthorized access", "authorization failed", "access denied",
    "access blocked", "access forbidden", "permission denied",
    "not permitted", "unauthorized", "forbidden",
    "too many failed attempts", "too many attempts", "account locked",
    "account disabled", "service unavailable", "service not available",
    "service down", "service error", "server error", "internal error",
    "internal server error", "503 service", "502 bad gateway",
    "500 internal", "504 gateway", "408 request", "bad gateway",
    "gateway timeout", "bad command", "unknown command", "invalid command",
    "command not found", "command rejected", "syntax error", "parse error",
    "protocol error", "protocol mismatch", "unsupported protocol",
    "unsupported command", "unsupported option", "not supported",
    "not implemented", "unknown host", "unknown service",
    "host key verification failed", "handshake failed", "handshake error",
    "negotiation failed", "negotiation error", "too many connections",
    "too many sessions", "maximum connections", "max connections",
    "connection limit", "session limit", "no more connections",
    "no free sessions", "out of memory", "memory allocation failed",
    "resource unavailable", "resource exhausted", "buffer overflow",
    "queue full", "table full", "overloaded", "too busy", "system busy",
    "try again later", "please try again", "temporarily unavailable",
    "port busy", "port in use", "port is busy", "port already open",
    "port not available", "port unavailable", "port disabled",
    "port closed", "port error", "port failure", "serial port busy",
    "serial port in use", "serial port error", "serial port unavailable",
    "com port", "com port busy", "com port in use", "line busy",
    "line error", "line failure", "device busy", "device in use",
    "device not ready", "device error", "device unavailable",
    "modem busy", "modem error", "modem not responding", "no dial tone",
    "no carrier", "no answer", "failed to", "has failed", "error:",
    "error -", "error code", "errno", "fatal:", "fatal error",
    "critical error", "exception", "traceback", "stack trace",
    "segmentation fault", "segfault", "cannot open", "cannot access",
    "unable to open", "unable to access", "unable to process",
    "unable to complete", "malformed", "corrupt", "rejected", "refused",
    "aborted", "terminated", "cisco ios", "ios-xe", "ios-xr",
    "% invalid input", "% incomplete command", "% ambiguous command",
    "% unknown command", "% authorization failed",
    "% authentication failed", "bad secrets", "enable password",
    "hp procurve", "aruba os", "arubanetworks", "junos",
    "juniper networks", "brocade icx", "brocade communications",
    "mikrotik routeros", "windows login", "ntlm", "kerberos",
    "ssh-2.0-", "ssh-1.99-", "intrusion detected", "intrusion attempt",
    "malicious", "attack detected", "blacklist", "blacklisted",
    "denylist", "firewall blocked", "rate limited", "rate limit",
    "captcha", "challenge response", "tos violation",
]

# short alpha phrases need word boundaries so e.g. "refused" doesn't
# match inside a longer word
_REJECT_SHORT_RE = [re.compile(r"(?<![a-z])" + re.escape(p) + r"(?![a-z])")
                    for p in REJECT_PHRASES
                    if len(p) <= 6 and p.isalpha()]
_REJECT_LONG = [p for p in REJECT_PHRASES
                if not (len(p) <= 6 and p.isalpha())]


def is_reject_banner(banner):
    if not banner:
        return False
    b = banner.lower()
    for r in _REJECT_SHORT_RE:
        if r.search(b):
            return True
    return any(p in b for p in _REJECT_LONG)


# ---------------------------------------------------------------- probe

def probe(ip, port, timeout=1.5, send_newline=True, require_banner=False,
          reject_errors=False):
    start = time.time()
    s = None
    try:
        s = make_socket(ip, port, timeout)
        if not s:
            return False, None, None
        if s.connect_ex((ip, port)) != 0:
            return False, None, None
        latency = (time.time() - start) * 1000.0

        got = False
        parts = []
        closed = False

        s.settimeout(1.0)
        try:
            d = s.recv(2048)
            if d:
                got = True
                parts.append(telnet_strip(d))
            else:
                closed = True
        except socket.timeout:
            pass
        except OSError:
            closed = True

        if send_newline and not closed:
            try:
                s.sendall(b"\r\n")
            except OSError:
                closed = True
            if not closed:
                time.sleep(0.08)
                s.settimeout(1.5)
                try:
                    d = s.recv(2048)
                    if d:
                        got = True
                        parts.append(telnet_strip(d))
                    else:
                        closed = True
                except socket.timeout:
                    pass
                except OSError:
                    closed = True

        still_open = False
        if not closed:
            try:
                s.settimeout(0.15)
                peek = s.recv(1, socket.MSG_PEEK)
                if peek == b"":
                    closed = True
                else:
                    still_open = True
            except socket.timeout:
                still_open = True
            except OSError:
                still_open = False

        responsive = got or (not require_banner and still_open and not closed)
        if not responsive:
            return False, None, None

        banner = " ".join(p.strip() for p in parts if p.strip()).strip() or None
        if reject_errors and is_reject_banner(banner):
            return False, None, None
        return True, latency, banner
    except OSError:
        log.debug("probe %s:%s failed", ip, port, exc_info=True)
        return False, None, None
    finally:
        close_socket(s)


BANNER_TYPES = [
    ("cisco asa", "Firewall"), ("pfsense", "Firewall"),
    ("firewall", "Firewall"), ("access point", "Wireless AP"),
    ("wireless", "Wireless AP"), ("routeros", "Router"),
    ("mikrotik", "Router"), ("router", "Router"),
    ("ruckus", "Layer 2 Switch"), ("brocade", "Layer 2 Switch"),
    ("icx", "Layer 2 Switch"), ("switch", "Layer 2 Switch"),
    ("aruba", "Wireless AP"), ("ubiquiti", "Wireless AP"),
    ("cisco", "Managed Switch"), ("juniper", "Router"),
    ("synology", "NAS"), ("qnap", "NAS"), ("nas", "NAS"),
    ("ubuntu", "Server"), ("debian", "Server"),
    ("centos", "Server"), ("linux", "Server"),
    ("windows", "Server"), ("camera", "IP Camera"),
    ("printer", "Printer"), ("ups", "UPS"),
    ("scada", "SCADA"), ("plc", "PLC"),
]


def guess_type(banner):
    if not banner:
        return None
    b = banner.lower()
    for kw, t in BANNER_TYPES:
        if kw in b:
            return t
    return None


PROBE_COOLDOWN = 6.0
PULSE_INTERVAL = 10.0
GEO_RETRY_AFTER = 300
GEO_RETRY_TICK = 60
GEO_MIN_GAP = 0.35


# ---------------------------------------------------------------- geo lookup

class GeoLookup:
    """Single background thread. Rate limited to stay polite."""

    def __init__(self):
        self.jobs = queue.Queue()
        self.results = queue.Queue()
        self.seen = set()
        self.alive = True
        threading.Thread(target=self._run, daemon=True).start()

    def submit(self, ip):
        if ip in self.seen:
            return
        self.seen.add(ip)
        if not is_public(ip):
            self.results.put((ip, {"city": "Local", "country": "Internal",
                                   "lat": 0.0, "lon": 0.0, "isp": "Private"}))
            return
        self.jobs.put(ip)

    def forget(self, ip):
        self.seen.discard(ip)

    def _run(self):
        last = 0.0
        while self.alive:
            try:
                ip = self.jobs.get(timeout=0.5)
            except queue.Empty:
                continue
            gap = time.time() - last
            if gap < GEO_MIN_GAP:
                time.sleep(GEO_MIN_GAP - gap)
            self.results.put((ip, self._lookup(ip)))
            last = time.time()

    @staticmethod
    def _lookup(ip):
        blank = {"city": "Unknown", "country": "Unknown",
                 "lat": 0.0, "lon": 0.0, "isp": "Unknown"}
        if not http:
            return blank
        try:
            r = http.get(f"https://ipwho.is/{ip}", timeout=6)
            if r.status_code != 200:
                return blank
            j = r.json()
            if not j.get("success"):
                return blank
            conn = j.get("connection") or {}
            return {
                "city": j.get("city") or "Unknown",
                "country": j.get("country") or "Unknown",
                "lat": float(j.get("latitude") or 0.0),
                "lon": float(j.get("longitude") or 0.0),
                "isp": conn.get("isp") or conn.get("org") or "Unknown",
            }
        except Exception:
            log.debug("geo lookup failed for %s", ip, exc_info=True)
            return blank


# ---------------------------------------------------------------- toast

class Toast:
    def __init__(self, root, text, action_label=None, action=None):
        self.root = root
        self.action = action
        self.frame = tk.Frame(root, bg="#111827")
        self.frame.place(relx=0.5, rely=1.0, anchor="s", y=-34)
        tk.Label(self.frame, text=text, bg="#111827", fg="#fff",
                 font=("TkDefaultFont", 9)).pack(side=tk.LEFT,
                                                 padx=(14, 8), pady=8)
        if action_label:
            tk.Button(self.frame, text=action_label, command=self._fire,
                      bg="#2563eb", fg="#fff", activebackground="#1d4ed8",
                      activeforeground="#fff", relief=tk.FLAT, bd=0,
                      font=("TkDefaultFont", 9, "bold"),
                      padx=10, pady=3, cursor="hand2"
                      ).pack(side=tk.LEFT, padx=(0, 10))
        self.timer = root.after(5000, self.dismiss)

    def _fire(self):
        try:
            if self.action:
                self.action()
        finally:
            self.dismiss()

    def dismiss(self):
        try:
            self.root.after_cancel(self.timer)
        except Exception:
            pass
        try:
            self.frame.destroy()
        except Exception:
            pass


# ---------------------------------------------------------------- columns

@dataclass
class Col:
    key: str
    label: str
    width: int
    sortable: bool = True
    stretch: bool = False


# ---------------------------------------------------------------- main app

class App:
    BG, BAR, BORDER = "#f7f8fa", "#ffffff", "#e5e7eb"
    ACCENT, ACCENT2 = "#2563eb", "#1d4ed8"
    TEXT, DIM, MUTE = "#111827", "#6b7280", "#9ca3af"
    OK, BAD = "#059669", "#dc2626"
    ROW_ALT, SEL = "#fafbfc", "#dbeafe"

    COLUMNS = [
        Col("status",  "Status",       80),
        Col("ip",      "IP Address",  140),
        Col("port",    "Port",         55),
        Col("type",    "Device Type", 180),
        Col("vendor",  "Vendor",      140),
        Col("model",   "Model",       180),
        Col("country", "Country",     100),
        Col("city",    "City",        110),
        Col("isp",     "ISP",         150),
        Col("latency", "Latency",      80),
        Col("serial",  "Serial",      130),
        Col("last",    "Last Check",  140),
        Col("notes",   "Notes",       220, sortable=False, stretch=True),
    ]

    def __init__(self, root):
        self.root = root
        self.devices = []
        self.selected = None
        self.selected_list = []
        self.running = True
        self.pulse_on = False
        self.pulse_after = None
        self.pulse_index = 0

        self.result_q = queue.Queue()
        self.inflight = set()
        self.inflight_lock = threading.Lock()
        self.last_probe = {}
        self.cooldown_until = 0

        self.geo_retry_at = {}
        self.geo_retry_handle = None

        self.ctx = None
        self.toast = None
        self.loc = GeoLookup()

        self.search_var = tk.StringVar()
        self.search_handle = None
        self.last_visible = None

        self.filter = "all"
        self.sort_key = None
        self.sort_desc = False

        self.record_visible = True
        self.record_width = 300

        self.task_total = 0
        self.task_done = 0

        self.store_dirty = False
        self.store_handle = None
        self.store_lock = threading.Lock()

        self.pool = ThreadPoolExecutor(max_workers=32,
                                       thread_name_prefix="probe")

        self.settings = self._read_settings()
        self._apply_geometry()

        root.title("0NET 2.2")
        root.minsize(1000, 600)
        root.configure(bg=self.BG)

        self._setup_style()
        self._build_menu()
        self._build_ui()
        root.protocol("WM_DELETE_WINDOW", self._close)

        # shortcuts
        root.bind("<Escape>", lambda e: self._close_ctx(), add="+")
        root.bind("<Delete>", self._del_key, add="+")
        root.bind("<F2>", lambda e: self.edit_selected(), add="+")
        root.bind("<Control-n>", lambda e: self.add_device(), add="+")
        root.bind("<Control-b>", lambda e: self.bulk_add(), add="+")
        root.bind("<Control-s>", lambda e: self.scan_now(), add="+")
        root.bind("<Control-p>", lambda e: self.toggle_pulse(), add="+")
        root.bind("<Control-m>", lambda e: self.open_map(), add="+")
        root.bind("<Control-t>", lambda e: self.open_terminal(), add="+")
        root.bind("<Control-Shift-S>", lambda e: self.open_share(), add="+")
        root.bind("<Control-Shift-I>", lambda e: self.open_import(), add="+")
        root.bind("<Control-f>", lambda e: self.search_entry.focus_set(),
                  add="+")

        # load first so geo results aren't dropped for migrated devices
        self._load_store_or_migrate()
        self._poll()
        self._geo_retry_tick()
        self.refresh_list()

    # -------------------------------------------------- settings

    def _read_settings(self):
        try:
            return json.loads(CONFIG_PATH.read_text())
        except (OSError, json.JSONDecodeError):
            return {}

    def _apply_geometry(self):
        geo = self.settings.get("geometry")
        if geo:
            try:
                self.root.geometry(geo)
                return
            except tk.TclError:
                pass
        self.root.geometry("1280x760")

    def _save_settings(self):
        try:
            CONFIG_PATH.write_text(json.dumps({
                "geometry": self.root.geometry(),
                "columns": {c.key: self.tree.column(c.key, "width")
                            for c in self.COLUMNS},
                "record_visible": self.record_visible,
                "record_width": self.record_width,
            }, indent=2))
        except OSError:
            log.debug("couldn't save settings", exc_info=True)

    # -------------------------------------------------- styling

    def _setup_style(self):
        s = ttk.Style(self.root)
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass
        s.configure("Treeview", background="#fff", fieldbackground="#fff",
                    foreground=self.TEXT, rowheight=28,
                    font=("TkDefaultFont", 9), borderwidth=0, relief="flat")
        s.map("Treeview", background=[("selected", self.SEL)],
              foreground=[("selected", self.TEXT)])
        s.configure("Treeview.Heading", background="#f3f4f6",
                    foreground=self.TEXT, font=("TkDefaultFont", 9, "bold"),
                    relief="flat", borderwidth=0, padding=(8, 6))
        s.map("Treeview.Heading", background=[("active", "#e5e7eb")])
        for o in ("Vertical", "Horizontal"):
            s.configure(f"{o}.TScrollbar", background="#e5e7eb",
                        troughcolor=self.BG, borderwidth=0, arrowsize=12,
                        width=10)
        s.configure("TProgressbar", background=self.ACCENT,
                    troughcolor="#e5e7eb", borderwidth=0, thickness=6)
        s.configure("TPanedwindow", background=self.BORDER)

    # -------------------------------------------------- menu

    def _build_menu(self):
        m = tk.Menu(self.root)

        fm = tk.Menu(m, tearoff=0)
        fm.add_command(label="Add Device…", accelerator="Ctrl+N",
                       command=self.add_device)
        fm.add_command(label="Bulk Add…", accelerator="Ctrl+B",
                       command=self.bulk_add)
        fm.add_separator()
        fm.add_command(label="Share Devices…", accelerator="Ctrl+Shift+S",
                       command=self.open_share)
        fm.add_command(label="Import Devices…", accelerator="Ctrl+Shift+I",
                       command=self.open_import)
        fm.add_separator()
        fm.add_command(label="Quit", command=self._close)
        m.add_cascade(label="File", menu=fm)

        em = tk.Menu(m, tearoff=0)
        em.add_command(label="Edit Selected…", accelerator="F2",
                       command=self.edit_selected)
        em.add_command(label="Delete Selected", accelerator="Del",
                       command=self.delete_selected)
        em.add_command(label="Clear Notes",
                       command=self.clear_notes_selected)
        em.add_separator()
        em.add_command(label="Select All", accelerator="Ctrl+A",
                       command=self._select_all)
        em.add_command(label="Find", accelerator="Ctrl+F",
                       command=lambda: self.search_entry.focus_set())
        m.add_cascade(label="Edit", menu=em)

        vm = tk.Menu(m, tearoff=0)
        vm.add_command(label="Toggle Record Panel",
                       command=self.toggle_record)
        vm.add_command(label="Clear Filters", command=self.clear_search)
        m.add_cascade(label="View", menu=vm)

        tm = tk.Menu(m, tearoff=0)
        tm.add_command(label="Scan Now", accelerator="Ctrl+S",
                       command=self.scan_now)
        tm.add_command(label="Pulse", accelerator="Ctrl+P",
                       command=self.toggle_pulse)
        tm.add_separator()
        tm.add_command(label="Map", accelerator="Ctrl+M",
                       command=self.open_map)
        tm.add_command(label="Terminal", accelerator="Ctrl+T",
                       command=self.open_terminal)
        m.add_cascade(label="Tools", menu=tm)

        hm = tk.Menu(m, tearoff=0)
        hm.add_command(label="Open Data Folder", command=self._open_data_dir)
        hm.add_command(label="About", command=self._about)
        m.add_cascade(label="Help", menu=hm)

        self.root.config(menu=m)

    def _about(self):
        messagebox.showinfo(
            "0NET 2.2",
            "0NET 2.2 — IoT device manager\n\n"
            f"Store:   {STORE_PATH}\n"
            f"Key:     {MASTER_KEY_PATH}\n"
            f"Config:  {CONFIG_PATH}\n"
            f"Log:     {LOG_PATH}\n\n"
            "Devices are encrypted at rest with AES-256-GCM. "
            "Sharing produces an encrypted file plus a one-time key.")

    def _open_data_dir(self):
        try:
            if sys.platform.startswith("win"):
                os.startfile(str(APP_DIR))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(APP_DIR)])
            else:
                subprocess.Popen(["xdg-open", str(APP_DIR)])
        except Exception as e:
            messagebox.showerror("Open folder", str(e))

    # -------------------------------------------------- UI

    def _build_ui(self):
        self._build_toolbar()
        self._build_searchbar()
        self._build_body()
        self._build_statusbar()

    def _build_toolbar(self):
        bar = tk.Frame(self.root, bg=self.BAR, height=52)
        bar.pack(side=tk.TOP, fill=tk.X)
        bar.pack_propagate(False)
        tk.Frame(bar, bg=self.BORDER, height=1).pack(side=tk.BOTTOM,
                                                     fill=tk.X)

        inner = tk.Frame(bar, bg=self.BAR)
        inner.pack(side=tk.LEFT, padx=10, pady=8)

        def btn(text, cmd, primary=False):
            b = tk.Button(inner, text=text, command=cmd,
                          relief=tk.FLAT, bd=0,
                          font=("TkDefaultFont", 9, "bold" if primary else
                                "normal"),
                          padx=14, pady=8, cursor="hand2")
            if primary:
                b.config(bg=self.ACCENT, fg="#fff",
                         activebackground=self.ACCENT2,
                         activeforeground="#fff")
            else:
                b.config(bg="#f3f4f6", fg=self.TEXT,
                         activebackground="#e5e7eb",
                         activeforeground=self.TEXT)
            return b

        btn("+  Add Device", self.add_device, True).pack(
            side=tk.LEFT, padx=(0, 6))
        btn("Bulk Add", self.bulk_add).pack(side=tk.LEFT, padx=(0, 6))
        self._sep(inner)
        btn("Scan Now", self.scan_now).pack(side=tk.LEFT, padx=(0, 6))
        btn("Pulse", self.toggle_pulse).pack(side=tk.LEFT, padx=(0, 6))
        self._sep(inner)
        btn("Map", self.open_map).pack(side=tk.LEFT, padx=(0, 6))
        btn("Terminal", self.open_terminal).pack(side=tk.LEFT, padx=(0, 6))
        self._sep(inner)
        btn("Share", self.open_share).pack(side=tk.LEFT, padx=(0, 6))
        btn("Import", self.open_import).pack(side=tk.LEFT, padx=(0, 6))
        self._sep(inner)
        self.record_btn = btn("◧  Record", self.toggle_record)
        self.record_btn.pack(side=tk.LEFT)

        right = tk.Frame(bar, bg=self.BAR)
        right.pack(side=tk.RIGHT, padx=14)
        self.pulse_dot = tk.Canvas(right, width=10, height=10, bg=self.BAR,
                                   highlightthickness=0)
        self.pulse_dot.pack(side=tk.LEFT, pady=20)
        self.pulse_dot.create_oval(1, 1, 9, 9, fill=self.MUTE, outline="")
        self.pulse_lbl = tk.Label(right, text="pulse off", bg=self.BAR,
                                  fg=self.DIM, font=("TkDefaultFont", 9))
        self.pulse_lbl.pack(side=tk.LEFT, padx=(8, 0))

    def _sep(self, parent):
        tk.Frame(parent, bg=self.BORDER, width=1).pack(
            side=tk.LEFT, fill=tk.Y, padx=8, pady=6)

    def _build_searchbar(self):
        sbar = tk.Frame(self.root, bg=self.BG, height=44)
        sbar.pack(side=tk.TOP, fill=tk.X)
        sbar.pack_propagate(False)
        wrap = tk.Frame(sbar, bg=self.BG)
        wrap.pack(fill=tk.X, padx=10, pady=(8, 4))

        box = tk.Frame(wrap, bg=self.BAR, highlightthickness=1,
                       highlightbackground=self.BORDER, bd=0)
        box.pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Label(box, text="⌕", bg=self.BAR, fg=self.MUTE,
                 font=("TkDefaultFont", 13)).pack(side=tk.LEFT,
                                                  padx=(10, 6))
        self.search_entry = tk.Entry(box, textvariable=self.search_var,
                                     bg=self.BAR, fg=self.TEXT, bd=0,
                                     insertbackground=self.TEXT,
                                     font=("TkDefaultFont", 10),
                                     highlightthickness=0)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True,
                               ipady=8, padx=(0, 8))
        self.search_entry.bind("<KeyRelease>", lambda e: self._schedule())
        self.search_entry.bind("<Escape>", lambda e: self.clear_search())

        self.chip_all = self._chip(wrap, "All", "all", True)
        self.chip_on = self._chip(wrap, "Online", "online")
        self.chip_off = self._chip(wrap, "Offline", "offline")

        tk.Button(wrap, text="Clear", command=self.clear_search,
                  bg="#f3f4f6", fg=self.TEXT, activebackground="#e5e7eb",
                  relief=tk.FLAT, bd=0, font=("TkDefaultFont", 9),
                  padx=12, pady=8, cursor="hand2"
                  ).pack(side=tk.LEFT, padx=(8, 0))

        self.search_info = tk.Label(wrap, text="", bg=self.BG, fg=self.DIM,
                                    font=("TkDefaultFont", 9))
        self.search_info.pack(side=tk.LEFT, padx=(12, 0))

    def _chip(self, parent, text, value, active=False):
        b = tk.Button(parent, text=text,
                      command=lambda v=value: self._set_filter(v),
                      bg=self.ACCENT if active else "#f3f4f6",
                      fg="#fff" if active else self.TEXT,
                      activebackground=self.ACCENT2 if active else "#e5e7eb",
                      activeforeground="#fff" if active else self.TEXT,
                      relief=tk.FLAT, bd=0, font=("TkDefaultFont", 9),
                      padx=10, pady=8, cursor="hand2")
        b.pack(side=tk.LEFT, padx=(6, 0))
        return b

    def _set_filter(self, value):
        self.filter = value
        for b, v in ((self.chip_all, "all"), (self.chip_on, "online"),
                     (self.chip_off, "offline")):
            on = (v == value)
            b.config(bg=self.ACCENT if on else "#f3f4f6",
                     fg="#fff" if on else self.TEXT,
                     activebackground=self.ACCENT2 if on else "#e5e7eb",
                     activeforeground="#fff" if on else self.TEXT)
        self.refresh_list()

    def _build_body(self):
        self.body = tk.PanedWindow(self.root, orient=tk.HORIZONTAL,
                                   sashwidth=1, sashrelief=tk.FLAT,
                                   bg=self.BORDER, bd=0)
        self.body.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        self.left_frame = tk.Frame(self.body, bg=self.BG)
        ids = [c.key for c in self.COLUMNS]
        self.tree = ttk.Treeview(self.left_frame, columns=ids,
                                 show="tree headings",
                                 selectmode="extended")
        self.tree.heading("#0", text="#")
        self.tree.column("#0", width=44, anchor="e", stretch=False,
                         minwidth=40)
        for c in self.COLUMNS:
            self.tree.heading(
                c.key, text=c.label,
                command=(lambda k=c.key: self._sort_by(k))
                        if c.sortable else "")
            saved = self.settings.get("columns", {}).get(c.key, c.width)
            self.tree.column(c.key, width=saved, minwidth=40, anchor="w",
                             stretch=c.stretch)

        ysb = ttk.Scrollbar(self.left_frame, orient="vertical",
                            command=self.tree.yview)
        xsb = ttk.Scrollbar(self.left_frame, orient="horizontal",
                            command=self.tree.xview)
        self.tree.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        xsb.grid(row=1, column=0, sticky="ew")
        self.left_frame.grid_rowconfigure(0, weight=1)
        self.left_frame.grid_columnconfigure(0, weight=1)
        self.left_frame.configure(padx=10, pady=8)

        # tag priority: higher number wins. Older Tk doesn't take the
        # priority kwarg, so fall back to configure order.
        try:
            self.tree.tag_configure("online", background="#f0fdf4",
                                    priority=10)
            self.tree.tag_configure("offline", background="#fef2f2",
                                    priority=10)
            self.tree.tag_configure("alt", background=self.ROW_ALT,
                                    priority=1)
        except tk.TclError:
            self.tree.tag_configure("alt", background=self.ROW_ALT)
            self.tree.tag_configure("online", background="#f0fdf4")
            self.tree.tag_configure("offline", background="#fef2f2")

        self.right_frame = tk.Frame(self.body, bg=self.BAR)
        hdr = tk.Frame(self.right_frame, bg=self.BAR)
        hdr.pack(fill=tk.X, padx=16, pady=(14, 8))
        self.rec_hdr = tk.Label(hdr, text="RECORD", bg=self.BAR, fg=self.MUTE,
                                font=("TkDefaultFont", 8, "bold"))
        self.rec_hdr.pack(anchor="w")

        self.rec_vars = {}
        for key, label in [
            ("ip", "Address"), ("status", "Status"), ("type", "Type"),
            ("port", "Port"), ("vendor", "Vendor"), ("model", "Model"),
            ("country", "Country"), ("city", "City"), ("isp", "ISP"),
            ("latency", "Latency"), ("serial", "Serial"),
            ("last", "Last check"), ("notes", "Notes"),
        ]:
            row = tk.Frame(self.right_frame, bg=self.BAR)
            row.pack(fill=tk.X, padx=16, pady=3)
            tk.Label(row, text=label, bg=self.BAR, fg=self.DIM,
                     font=("TkDefaultFont", 8), width=9, anchor="nw"
                     ).pack(side=tk.LEFT, anchor="n")
            v = tk.Label(row, text="—", bg=self.BAR, fg=self.TEXT,
                         font=("TkDefaultFont", 9), anchor="w",
                         wraplength=280, justify="left")
            v.pack(side=tk.LEFT, fill=tk.X, expand=True)
            self.rec_vars[key] = v

        self.body.add(self.left_frame, minsize=500, stretch="always")
        self.body.add(self.right_frame, minsize=220,
                      width=self.record_width, stretch="never")
        if not self.settings.get("record_visible", True):
            self.root.after(0, self.toggle_record)

        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Double-1>", lambda e: self._on_double())
        self.tree.bind("<Button-3>", self._right_click)
        self.tree.bind("<Control-a>", self._select_all)
        self.tree.bind("<Control-A>", self._select_all)

    def _build_statusbar(self):
        bar = tk.Frame(self.root, bg=self.BAR, height=26)
        bar.pack(side=tk.BOTTOM, fill=tk.X)
        bar.pack_propagate(False)
        tk.Frame(bar, bg=self.BORDER, height=1).pack(side=tk.TOP, fill=tk.X)
        self.status_lbl = tk.Label(bar, text="Ready", bg=self.BAR,
                                   fg=self.DIM, font=("TkDefaultFont", 9),
                                   anchor="w")
        self.status_lbl.pack(side=tk.LEFT, padx=14, pady=4)
        self.rows_lbl = tk.Label(bar, text="0 devices", bg=self.BAR,
                                 fg=self.DIM, font=("TkDefaultFont", 9))
        self.rows_lbl.pack(side=tk.RIGHT, padx=14, pady=4)

    def toggle_record(self):
        if self.record_visible:
            try:
                w = self.right_frame.winfo_width()
                if w > 200:
                    self.record_width = w
            except tk.TclError:
                pass
            try:
                self.body.forget(self.right_frame)
            except tk.TclError:
                pass
            self.record_visible = False
            try:
                self.record_btn.config(bg="#f3f4f6", fg=self.TEXT)
            except tk.TclError:
                pass
        else:
            try:
                self.body.add(self.right_frame, minsize=220,
                              width=self.record_width, stretch="never")
            except tk.TclError:
                pass
            self.record_visible = True
            try:
                self.record_btn.config(bg=self.ACCENT, fg="#fff")
            except tk.TclError:
                pass

    # -------------------------------------------------- sort / filter

    def _sort_by(self, key):
        if self.sort_key == key:
            if not self.sort_desc:
                self.sort_desc = True
            else:
                self.sort_key = None
                self.sort_desc = False
        else:
            self.sort_key = key
            self.sort_desc = False
        for c in self.COLUMNS:
            arrow = ""
            if c.key == self.sort_key:
                arrow = " ▼" if self.sort_desc else " ▲"
            self.tree.heading(c.key, text=c.label + arrow)
        self.refresh_list()

    def _sort_val(self, d, key):
        loc = d.get("location") or {}
        if key == "status":
            return 1 if d.get("online") else 0
        if key == "ip":
            try:
                return ipaddress.ip_address(d.get("ip", ""))
            except ValueError:
                return d.get("ip", "")
        if key == "port":
            return safe_int(d.get("port"))
        if key == "latency":
            v = d.get("latency_ms")
            return v if v is not None else float("inf")
        if key in ("country", "city", "isp"):
            return (loc.get(key) or "").lower()
        return str(d.get(key) or "").lower()

    def _schedule(self, ms=400):
        if self.search_handle:
            try:
                self.root.after_cancel(self.search_handle)
            except tk.TclError:
                pass
        self.search_handle = self.root.after(ms, self.refresh_list)

    def clear_search(self):
        self.search_var.set("")
        self._set_filter("all")

    def _matches(self, d, q):
        loc = d.get("location") or {}
        hay = " ".join([
            str(d.get("ip", "")), str(d.get("port", "")),
            str(d.get("type", "")), str(d.get("vendor", "")),
            str(d.get("model", "")), str(d.get("serial", "")),
            str(d.get("username", "")), str(d.get("notes", "")),
            str(loc.get("city", "")), str(loc.get("country", "")),
            str(loc.get("isp", "")),
            "online" if d.get("online") else "offline",
        ]).lower()
        return q in hay

    def _visible(self):
        q = self.search_var.get().strip().lower()
        out = self.devices
        if self.filter == "online":
            out = [d for d in out if d.get("online")]
        elif self.filter == "offline":
            out = [d for d in out if not d.get("online")]
        if q:
            out = [d for d in out if self._matches(d, q)]
        out = list(out)
        if self.sort_key:
            try:
                out.sort(key=lambda d: self._sort_val(d, self.sort_key),
                         reverse=self.sort_desc)
            except Exception:
                log.exception("sort failed")
        return out

    def _row(self, d):
        loc = d.get("location") or {}
        lat = d.get("latency_ms")
        return (
            "● online" if d.get("online") else "○ offline",
            d.get("ip", ""), d.get("port", 23),
            d.get("type", "") or "—",
            d.get("vendor", "") or "",
            d.get("model", "") or "",
            loc.get("country", "") or "",
            loc.get("city", "") or "",
            loc.get("isp", "") or "",
            f"{lat:.0f} ms" if lat is not None else "—",
            d.get("serial", "") or "",
            d.get("last_checked", "") or "",
            d.get("notes", "") or "",
        )

    def refresh_list(self):
        self.search_handle = None
        visible = self._visible()
        ids = [d["ip"] for d in visible]

        if ids == self.last_visible and \
                len(self.tree.get_children()) == len(ids):
            return
        self.last_visible = ids

        prev_sel = [d["ip"] for d in self.selected_list]
        for item in self.tree.get_children():
            self.tree.delete(item)
        for i, d in enumerate(visible, 1):
            tag = "online" if d.get("online") else "offline"
            self.tree.insert("", "end", iid=d["ip"], text=str(i),
                             values=self._row(d), tags=(tag,))

        keep = [ip for ip in prev_sel if self.tree.exists(ip)]
        if keep:
            self.tree.selection_set(keep)

        total, shown = len(self.devices), len(visible)
        self.rows_lbl.config(
            text=f"{shown} device{'s' if shown != 1 else ''}"
                 + (f" of {total}" if total != shown else ""))
        if (self.search_var.get().strip() or self.filter != "all") and total:
            self.search_info.config(text=f"{shown} of {total} match")
        else:
            self.search_info.config(text="")

    # -------------------------------------------------- selection

    def _on_select(self, _=None):
        by_ip = {d["ip"]: d for d in self.devices}
        devs = [by_ip[i] for i in self.tree.selection() if i in by_ip]
        self.selected_list = devs
        self.selected = devs[0] if devs else None

        if not devs:
            self.rec_hdr.config(text="RECORD", fg=self.MUTE)
            self._show_record(None)
        elif len(devs) == 1:
            self.rec_hdr.config(text="RECORD", fg=self.MUTE)
            self._show_record(devs[0])
        else:
            self.rec_hdr.config(text=f"{len(devs)} SELECTED", fg=self.ACCENT)
            self._show_record(devs[0])

    def _selected_devices(self):
        return list(self.selected_list)

    def _select_all(self, _=None):
        self.tree.selection_set(self.tree.get_children())
        return "break"

    def _on_double(self):
        if self.selected_list:
            self._open_terminal(self.selected_list[0])

    def _del_key(self, _=None):
        try:
            if self.root.focus_get() == self.tree:
                self.delete_selected()
        except tk.TclError:
            pass
        return "break"

    # -------------------------------------------------- context menu

    def _close_ctx(self):
        if self.ctx:
            try:
                self.ctx.unpost()
            except tk.TclError:
                pass

    def _right_click(self, event):
        row = self.tree.identify_row(event.y)
        if not row:
            return
        if row not in self.tree.selection():
            self.tree.selection_set(row)

        self._close_ctx()
        if self.ctx:
            try:
                self.ctx.destroy()
            except tk.TclError:
                pass
        self.ctx = tk.Menu(self.root, tearoff=0)

        n = len(self.tree.selection())
        if n > 1:
            self.ctx.add_command(label=f"Edit {n} Devices",
                                 command=self.edit_selected)
            self.ctx.add_command(label=f"Show Info (first of {n})",
                                 command=self.show_info_selected)
            self.ctx.add_command(label=f"Ping {n} Devices",
                                 command=self.ping_selected)
            self.ctx.add_separator()
            self.ctx.add_command(label="Open Terminal (first)",
                                 command=self.open_terminal)
            self.ctx.add_command(label=f"Copy {n} IPs",
                                 command=self.copy_ips)
            self.ctx.add_separator()
            self.ctx.add_command(label=f"Clear Notes ({n})",
                                 command=self.clear_notes_selected)
            self.ctx.add_separator()
            self.ctx.add_command(label=f"Delete {n} Devices",
                                 command=self.delete_selected)
        else:
            self.ctx.add_command(label="Edit Device",
                                 command=self.edit_selected)
            self.ctx.add_command(label="Show Info",
                                 command=self.show_info_selected)
            self.ctx.add_command(label="Ping Device",
                                 command=self.ping_selected)
            self.ctx.add_separator()
            self.ctx.add_command(label="Open Terminal",
                                 command=self.open_terminal)
            self.ctx.add_command(label="Copy IP", command=self.copy_ips)
            self.ctx.add_separator()
            self.ctx.add_command(label="Clear Notes",
                                 command=self.clear_notes_selected)
            self.ctx.add_separator()
            self.ctx.add_command(label="Delete Device",
                                 command=self.delete_selected)

        try:
            self.ctx.tk_popup(event.x_root, event.y_root)
        finally:
            try:
                self.ctx.grab_release()
            except tk.TclError:
                pass

    def _show_record(self, d):
        if not d:
            for v in self.rec_vars.values():
                v.config(text="—")
            return
        loc = d.get("location") or {}
        lat = d.get("latency_ms")
        vals = {
            "ip": f"{d['ip']}:{d.get('port', 23)}",
            "status": "online" if d.get("online") else "offline",
            "type": d.get("type", "") or "—",
            "port": str(d.get("port", 23)),
            "vendor": d.get("vendor", "") or "—",
            "model": d.get("model", "") or "—",
            "country": loc.get("country", "") or "—",
            "city": loc.get("city", "") or "—",
            "isp": loc.get("isp", "") or "—",
            "latency": f"{lat:.0f} ms" if lat is not None else "—",
            "serial": d.get("serial", "") or "—",
            "last": d.get("last_checked", "") or "—",
            "notes": d.get("notes", "") or "—",
        }
        for k, v in vals.items():
            if k in self.rec_vars:
                self.rec_vars[k].config(text=v)

    # -------------------------------------------------- actions

    def add_device(self):
        AddDeviceDialog(self.root, self._add_device)

    def _add_device(self, data):
        if any(d["ip"] == data["ip"] for d in self.devices):
            messagebox.showwarning("Duplicate",
                                   f"{data['ip']} is already in the list")
            return
        self.devices.append(data)
        self.loc.submit(data["ip"])
        self.geo_retry_at[data["ip"]] = time.time()
        self._queue_save()
        self.refresh_list()
        self.status_lbl.config(text=f"Added {data['ip']}")

    def edit_selected(self):
        devs = self._selected_devices()
        if not devs:
            return
        if len(devs) == 1:
            AddDeviceDialog(self.root, self._edit_device, device=devs[0])
        else:
            MultiEditDialog(self.root, self._multi_edit, devs)

    def _edit_device(self, data):
        for i, d in enumerate(self.devices):
            if d["ip"] == data["ip"]:
                self.devices[i] = data
                break
        else:
            self.devices.append(data)
        loc = data.get("location") or {}
        if (loc.get("country") or "").strip() in ("", "Unknown"):
            self.loc.submit(data["ip"])
            self.geo_retry_at[data["ip"]] = time.time()
        self._queue_save()
        self.refresh_list()
        for d in self.devices:
            if d["ip"] == data["ip"]:
                self.selected = d
                self._show_record(d)
                break

    def _multi_edit(self, devs, changes):
        for d in devs:
            for k, v in changes.items():
                if k == "port":
                    p = safe_int(v, d.get("port", 23))
                    d["port"] = p if valid_port(p) else d.get("port", 23)
                else:
                    d[k] = v
        self._queue_save()
        self.refresh_list()
        if self.selected:
            self._show_record(self.selected)
        self.status_lbl.config(text=f"Updated {len(devs)} device(s)")

    def clear_notes_selected(self):
        devs = self._selected_devices()
        if not devs:
            return
        n = len(devs)
        if not any((d.get("notes") or "").strip() for d in devs):
            self.status_lbl.config(text="Notes already empty")
            return
        msg = (f"Clear notes for {n} devices?" if n > 1
               else f"Clear notes for {devs[0]['ip']}?")
        if not messagebox.askyesno("Clear Notes", msg, parent=self.root):
            return
        for d in devs:
            d["notes"] = ""
        self._queue_save()
        self.refresh_list()
        if self.selected:
            self._show_record(self.selected)
        self.status_lbl.config(text=f"Cleared notes for {n} device(s)")

    def show_info_selected(self):
        d = self.selected
        if not d:
            return
        loc = d.get("location") or {}
        lat = d.get("latency_ms")
        n = len(self._selected_devices())
        title = (f"Device Info — {d['ip']}" if n <= 1
                 else f"Device Info — {d['ip']} (first of {n})")
        messagebox.showinfo(title, (
            f"IP Address:   {d['ip']}\n"
            f"Port:         {d.get('port', 23)}\n"
            f"Type:         {d.get('type') or '—'}\n"
            f"Vendor:       {d.get('vendor') or '—'}\n"
            f"Model:        {d.get('model') or '—'}\n"
            f"Serial:       {d.get('serial') or '—'}\n"
            f"\n"
            f"Status:       {'online' if d.get('online') else 'offline'}\n"
            f"Latency:      {f'{lat:.0f} ms' if lat is not None else '—'}\n"
            f"Last check:   {d.get('last_checked') or '—'}\n"
            f"Added:        {d.get('added') or '—'}\n"
            f"\n"
            f"Country:      {loc.get('country') or '—'}\n"
            f"City:         {loc.get('city') or '—'}\n"
            f"ISP:          {loc.get('isp') or '—'}\n"
            f"Latitude:     {loc.get('lat', 0)}\n"
            f"Longitude:    {loc.get('lon', 0)}\n"
            f"\n"
            f"Notes:\n{d.get('notes') or '—'}"), parent=self.root)

    def ping_selected(self):
        devs = self._selected_devices()
        if not devs:
            return
        for d in devs:
            with self.inflight_lock:
                self.inflight.discard(d["ip"])
            self._spawn_ping(d)
        self.status_lbl.config(
            text=(f"Pinging {len(devs)} device(s)…" if len(devs) > 1
                  else f"Pinging {devs[0]['ip']}…"))

    def copy_ips(self):
        devs = self._selected_devices()
        if not devs:
            return
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append("\n".join(d["ip"] for d in devs))
            self.status_lbl.config(
                text=(f"Copied {len(devs)} IPs" if len(devs) > 1
                      else f"Copied {devs[0]['ip']}"))
        except tk.TclError:
            pass

    def delete_selected(self):
        devs = self._selected_devices()
        if not devs:
            return
        ips = {d["ip"] for d in devs}
        removed = [d for d in self.devices if d["ip"] in ips]
        self.devices = [x for x in self.devices if x["ip"] not in ips]
        for ip in ips:
            self.geo_retry_at.pop(ip, None)
            self.last_probe.pop(ip, None)
        self.selected = None
        self.selected_list = []
        self._queue_save()
        self.refresh_list()
        self._show_record(None)
        self.rec_hdr.config(text="RECORD", fg=self.MUTE)
        self.status_lbl.config(text=f"Deleted {len(removed)} device(s)")

        def undo():
            have = {d["ip"] for d in self.devices}
            for d in removed:
                if d["ip"] not in have:
                    self.devices.append(d)
            self._queue_save()
            self.refresh_list()
            self.status_lbl.config(text=f"Restored {len(removed)} device(s)")

        self.toast = Toast(self.root,
                           f"Deleted {len(removed)} device"
                           f"{'s' if len(removed) != 1 else ''}",
                           "Undo", undo)

    def bulk_add(self):
        BulkAddDialog(self.root, self._bulk_add)

    def _bulk_add(self, data, done=False):
        if done:
            self.cooldown_until = time.time() + 5.0
            self._queue_save()
            self.refresh_list()
            self.status_lbl.config(
                text=f"Bulk add complete — {len(self.devices)} total")
            return True
        if data is None:
            return True
        if any(d["ip"] == data["ip"] for d in self.devices):
            return False
        self.devices.append(data)
        self.loc.submit(data["ip"])
        self.geo_retry_at[data["ip"]] = time.time()
        return True

    # -------------------------------------------------- scan / pulse

    def scan_now(self):
        now = time.time()
        if now < self.cooldown_until:
            self.status_lbl.config(
                text=f"Please wait {self.cooldown_until - now:.1f}s")
            return
        self.scan_id = getattr(self, "scan_id", 0) + 1
        self.scan_queue = list(self.devices)
        self.task_total = len(self.scan_queue)
        self.task_done = 0
        self.status_lbl.config(text=f"Scanning… 0/{self.task_total}")
        self._scan_next(self.scan_id)

    def _scan_next(self, tok):
        if tok != getattr(self, "scan_id", -1):
            return
        q = getattr(self, "scan_queue", None)
        if not q:
            self.status_lbl.config(
                text=f"Scan complete — {self.task_done} probed")
            return
        d = q.pop(0)
        if time.time() - self.last_probe.get(d["ip"], 0) >= PROBE_COOLDOWN:
            with self.inflight_lock:
                self.inflight.discard(d["ip"])
            self._spawn_ping(d)
        try:
            self.root.after(300, lambda: self._scan_next(tok))
        except tk.TclError:
            pass

    def toggle_pulse(self):
        if self.pulse_on:
            self.pulse_on = False
            if self.pulse_after:
                try:
                    self.root.after_cancel(self.pulse_after)
                except tk.TclError:
                    pass
                self.pulse_after = None
            self.pulse_lbl.config(text="pulse off", fg=self.DIM)
            self.pulse_dot.delete("all")
            self.pulse_dot.create_oval(1, 1, 9, 9, fill=self.MUTE,
                                       outline="")
        else:
            self.pulse_on = True
            self.pulse_lbl.config(text="pulse on", fg=self.OK)
            self.pulse_dot.delete("all")
            self.pulse_dot.create_oval(1, 1, 9, 9, fill=self.OK, outline="")
            self._pulse_tick()

    def _pulse_tick(self):
        if not self.pulse_on or not self.running:
            return
        now = time.time()
        if now < self.cooldown_until:
            self.pulse_lbl.config(
                text=f"cooling {self.cooldown_until - now:.0f}s")
            self._arm_pulse(1000)
            return

        n = len(self.devices)
        if n == 0:
            self._arm_pulse(int(PULSE_INTERVAL * 1000))
            return

        for _ in range(n):
            self.pulse_index = (self.pulse_index + 1) % n
            d = self.devices[self.pulse_index]
            if now - self.last_probe.get(d["ip"], 0) >= PROBE_COOLDOWN:
                with self.inflight_lock:
                    self.inflight.discard(d["ip"])
                self._spawn_ping(d)
                break

        self._arm_pulse(int(PULSE_INTERVAL * 1000))

    def _arm_pulse(self, ms):
        try:
            self.pulse_after = self.root.after(ms, self._pulse_tick)
        except tk.TclError:
            self.pulse_after = None

    # -------------------------------------------------- terminals

    def open_terminal(self):
        devs = self._selected_devices()
        if not devs:
            return
        if len(devs) == 1:
            self._open_terminal(devs[0])
        else:
            try:
                TerminalTabsWindow(self.root, devs)
            except Exception as e:
                messagebox.showerror("Terminal", str(e))

    def _open_terminal(self, d):
        try:
            TerminalWindow(self.root, d)
        except Exception as e:
            messagebox.showerror("Terminal", str(e))

    # -------------------------------------------------- share / import

    def open_share(self):
        if not self.devices:
            messagebox.showwarning("Share", "No devices to share")
            return
        snapshot = []
        for d in self.devices:
            c = dict(d)
            c["location"] = dict(d.get("location") or {})
            snapshot.append(c)
        try:
            ShareDialog(self.root, snapshot)
        except Exception as e:
            log.exception("share dialog failed")
            messagebox.showerror("Share", str(e))

    def open_import(self):
        try:
            ImportDialog(self.root, self)
        except Exception as e:
            log.exception("import dialog failed")
            messagebox.showerror("Import", str(e))

    def import_devices(self, incoming, overwrite):
        have = {d["ip"]: d for d in self.devices}
        added = updated = skipped = 0
        for d in incoming:
            ip = d.get("ip")
            if not ip:
                skipped += 1
                continue
            if ip in have:
                if overwrite:
                    for i, existing in enumerate(self.devices):
                        if existing["ip"] == ip:
                            self.devices[i] = d
                            break
                    have[ip] = d
                    updated += 1
                else:
                    skipped += 1
            else:
                self.devices.append(d)
                have[ip] = d
                added += 1
        for d in incoming:
            loc = d.get("location") or {}
            country = (loc.get("country") or "").strip()
            if not country or country == "Unknown":
                self.loc.forget(d["ip"])
                self.loc.submit(d["ip"])
                self.geo_retry_at[d["ip"]] = time.time()
        self._queue_save()
        self.refresh_list()
        return added, updated, skipped

    def open_map(self):
        if tkintermapview is None:
            messagebox.showinfo(
                "Map unavailable",
                "pip install --user tkintermapview Pillow")
            return
        try:
            MapWindow(self.root, self.devices)
        except Exception as e:
            messagebox.showerror("Map", str(e))

    # -------------------------------------------------- probing

    def _spawn_ping(self, d):
        ip = d["ip"]
        with self.inflight_lock:
            if ip in self.inflight:
                return
            self.inflight.add(ip)
        self.last_probe[ip] = time.time()
        port = safe_int(d.get("port"), 23)
        self.task_total = max(self.task_total, 1)

        def worker():
            online, lat, _ = probe(ip, port, timeout=1.5, send_newline=False)
            self.result_q.put(("ping", ip, online, lat))

        try:
            self.pool.submit(worker)
        except RuntimeError:
            with self.inflight_lock:
                self.inflight.discard(ip)

    def _poll(self):
        if not self.running:
            return
        try:
            while True:
                try:
                    item = self.result_q.get_nowait()
                except queue.Empty:
                    break
                _, ip, online, lat = item
                with self.inflight_lock:
                    self.inflight.discard(ip)
                d = next((x for x in self.devices if x["ip"] == ip), None)
                if not d:
                    continue
                d["online"] = online
                d["latency_ms"] = lat
                d["last_checked"] = datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S")
                if self.tree.exists(ip):
                    self.tree.item(ip, values=self._row(d))
                    self.tree.item(ip,
                                   tags=("online",) if online
                                   else ("offline",))
                if self.selected and self.selected["ip"] == ip:
                    self._show_record(d)
                self.task_done += 1
                if self.task_done <= self.task_total:
                    self.status_lbl.config(
                        text=f"Probing {self.task_done}/{self.task_total}…")

            while True:
                try:
                    ip, loc = self.loc.results.get_nowait()
                except queue.Empty:
                    break
                d = next((x for x in self.devices if x["ip"] == ip), None)
                if not d:
                    continue
                d["location"] = loc
                if self.tree.exists(ip):
                    self.tree.item(ip, values=self._row(d))
                if self.selected and self.selected["ip"] == ip:
                    self._show_record(d)
                country = (loc.get("country") or "").strip()
                if country and country != "Unknown":
                    self.geo_retry_at.pop(ip, None)
                self._queue_save()
        except Exception:
            log.exception("poll loop error")

        try:
            self.root.after(150, self._poll)
        except tk.TclError:
            pass

    # -------------------------------------------------- store

    def _load_store_or_migrate(self):
        if STORE_PATH.exists():
            try:
                items = load_store()
                if items is not None:
                    self._populate(items)
                    self.status_lbl.config(
                        text=f"Loaded {len(items)} device(s) from store")
                    return
            except Exception:
                log.exception("store unreadable")
                try:
                    go = messagebox.askyesno(
                        "Encrypted store unreadable",
                        f"{STORE_PATH}\n\n"
                        "The device store couldn't be opened — usually "
                        "this means the master key is missing or was "
                        "replaced.\n\n"
                        f"Key file:\n{MASTER_KEY_PATH}\n\n"
                        "Continue with an empty list?\n\n"
                        "(Nothing has been deleted. You can restore the "
                        "key manually to recover.)")
                except tk.TclError:
                    go = True
                if not go:
                    try:
                        self.root.destroy()
                    except tk.TclError:
                        pass
                    return

        for p in OLD_CSV_PATHS:
            if not p.exists():
                continue
            try:
                items = load_legacy_csv(p)
            except Exception:
                log.exception("couldn't read %s", p)
                continue
            if not items:
                continue
            log.info("migrating %d device(s) from %s", len(items), p)
            self._populate(items)
            self.store_dirty = True
            self._flush_store(sync=True)
            try:
                messagebox.showinfo(
                    "Migrated to encrypted store",
                    f"Imported {len(items)} device(s) from\n  {p}\n\n"
                    f"Now stored encrypted at\n  {STORE_PATH}\n\n"
                    f"The old plaintext file was left in place. Delete "
                    f"it once you've confirmed everything looks right.")
            except tk.TclError:
                pass
            return

    def _populate(self, items):
        for d in items:
            self.devices.append(d)
            loc = d.get("location") or {}
            country = (loc.get("country") or "").strip()
            if not country or country == "Unknown":
                self.loc.submit(d["ip"])
                self.geo_retry_at[d["ip"]] = time.time()

    def _queue_save(self):
        self.store_dirty = True
        if self.store_handle is None:
            try:
                self.store_handle = self.root.after(1500, self._flush_store)
            except tk.TclError:
                self.store_handle = None

    def _flush_store(self, sync=False):
        self.store_handle = None
        if not self.store_dirty:
            return
        self.store_dirty = False
        snapshot = []
        for d in self.devices:
            c = dict(d)
            c["location"] = dict(d.get("location") or {})
            snapshot.append(c)

        if sync:
            with self.store_lock:
                try:
                    save_store(snapshot)
                except Exception:
                    log.exception("store save failed")
            return

        def worker():
            with self.store_lock:
                try:
                    save_store(snapshot)
                except Exception:
                    log.exception("store save failed")
        threading.Thread(target=worker, daemon=True).start()

    # -------------------------------------------------- geo retry

    def _geo_retry_tick(self):
        if not self.running:
            return
        now = time.time()
        n = 0
        for d in list(self.devices):
            ip = d["ip"]
            country = ((d.get("location") or {}).get("country") or "").strip()
            if country and country != "Unknown":
                self.geo_retry_at.pop(ip, None)
                continue
            if now - self.geo_retry_at.get(ip, 0) >= GEO_RETRY_AFTER:
                self.geo_retry_at[ip] = now
                self.loc.forget(ip)
                self.loc.submit(ip)
                n += 1
        if n:
            log.info("retrying geo for %d device(s)", n)
        try:
            self.geo_retry_handle = self.root.after(
                GEO_RETRY_TICK * 1000, self._geo_retry_tick)
        except tk.TclError:
            self.geo_retry_handle = None

    # -------------------------------------------------- shutdown

    def _close(self):
        self.running = False
        self.pulse_on = False
        for h in (self.pulse_after, self.search_handle,
                  self.geo_retry_handle):
            if h:
                try:
                    self.root.after_cancel(h)
                except tk.TclError:
                    pass
        self._close_ctx()
        try:
            self._save_settings()
        except Exception:
            pass
        self.store_dirty = True
        self._flush_store(sync=True)
        try:
            self.pool.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass
        try:
            self.root.destroy()
        except tk.TclError:
            pass


# ---------------------------------------------------------------- share dialog

class ShareDialog:
    def __init__(self, parent, devices):
        self.devices = devices
        self.file_bytes = None
        self.key_str = ""

        self.win = tk.Toplevel(parent)
        self.win.title("Share Devices")
        self.win.geometry("640x620")
        self.win.minsize(600, 560)
        self.win.configure(bg="#f7f8fa")
        self.win.transient(parent)
        self.win.grab_set()

        tk.Label(self.win, text="Share Devices", bg="#f7f8fa", fg="#111827",
                 font=("TkDefaultFont", 15, "bold"), anchor="w"
                 ).pack(fill=tk.X, padx=20, pady=(18, 2))
        tk.Label(self.win,
                 text="The recipient needs BOTH the encrypted file and "
                      "the secret key. The file alone can't be opened.",
                 bg="#f7f8fa", fg="#6b7280", font=("TkDefaultFont", 9),
                 anchor="w", justify="left", wraplength=580
                 ).pack(fill=tk.X, padx=20, pady=(0, 14))

        footer = tk.Frame(self.win, bg="#f7f8fa")
        footer.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=14)
        tk.Button(footer, text="Close", command=self.win.destroy,
                  bg="#f3f4f6", fg="#111827", activebackground="#e5e7eb",
                  relief=tk.FLAT, bd=0, font=("TkDefaultFont", 10),
                  padx=20, pady=8, cursor="hand2"
                  ).pack(side=tk.RIGHT)

        self.body = tk.Frame(self.win, bg="#f7f8fa")
        self.body.pack(fill=tk.BOTH, expand=True, padx=20)
        self.include_creds = tk.BooleanVar(value=True)
        self._options()

    def _options(self):
        info = tk.Frame(self.body, bg="#fff", highlightthickness=1,
                        highlightbackground="#e5e7eb")
        info.pack(fill=tk.X)
        tk.Label(info,
                 text=f"{len(self.devices)} device"
                      f"{'s' if len(self.devices) != 1 else ''} "
                      f"will be included.",
                 bg="#fff", fg="#111827", font=("TkDefaultFont", 10, "bold"),
                 anchor="w").pack(fill=tk.X, padx=14, pady=(12, 6))
        tk.Checkbutton(info,
                       text="Include usernames and passwords",
                       variable=self.include_creds, bg="#fff", fg="#111827",
                       activebackground="#fff", activeforeground="#111827",
                       selectcolor="#fff", font=("TkDefaultFont", 9),
                       anchor="w", bd=0, highlightthickness=0
                       ).pack(fill=tk.X, padx=14, pady=(0, 12))
        tk.Button(self.body, text="Generate share", command=self._generate,
                  bg="#2563eb", fg="#fff", activebackground="#1d4ed8",
                  activeforeground="#fff", relief=tk.FLAT, bd=0,
                  font=("TkDefaultFont", 10, "bold"), padx=22, pady=10,
                  cursor="hand2").pack(fill=tk.X, pady=(14, 0))

    def _generate(self):
        try:
            key, blob = make_share(self.devices, self.include_creds.get())
        except Exception as e:
            log.exception("share failed")
            messagebox.showerror("Share", f"Couldn't create share:\n{e}",
                                 parent=self.win)
            return
        self.file_bytes = blob
        self.key_str = format_key(key)
        for w in self.body.winfo_children():
            w.destroy()
        self._result()

    def _result(self):
        warn = tk.Frame(self.body, bg="#fef3c7", highlightthickness=1,
                        highlightbackground="#fde68a")
        warn.pack(fill=tk.X, pady=(0, 12))
        tk.Label(warn,
                 text="⚠  Save BOTH the file and the key before closing. "
                      "Every click of Generate produces a new key — the "
                      "old one stops working.",
                 bg="#fef3c7", fg="#92400e", font=("TkDefaultFont", 9),
                 anchor="w", justify="left", wraplength=560
                 ).pack(fill=tk.X, padx=12, pady=10)

        tk.Label(self.body, text="1.  Encrypted clients file",
                 bg="#f7f8fa", fg="#111827",
                 font=("TkDefaultFont", 10, "bold"), anchor="w"
                 ).pack(fill=tk.X, pady=(6, 4))
        tk.Label(self.body,
                 text="Contains AES-256-GCM encrypted device data.",
                 bg="#f7f8fa", fg="#6b7280", font=("TkDefaultFont", 9),
                 anchor="w").pack(fill=tk.X)
        tk.Button(self.body, text="Save encrypted file…",
                  command=self._save_file, bg="#f3f4f6", fg="#111827",
                  activebackground="#e5e7eb", relief=tk.FLAT, bd=0,
                  font=("TkDefaultFont", 9), padx=16, pady=8, cursor="hand2"
                  ).pack(anchor="w", pady=(6, 14))

        tk.Label(self.body, text="2.  Secret key", bg="#f7f8fa", fg="#111827",
                 font=("TkDefaultFont", 10, "bold"), anchor="w"
                 ).pack(fill=tk.X, pady=(4, 4))
        tk.Label(self.body,
                 text="Send this through a different channel than the file.",
                 bg="#f7f8fa", fg="#6b7280", font=("TkDefaultFont", 9),
                 anchor="w", justify="left", wraplength=560
                 ).pack(fill=tk.X)

        keywrap = tk.Frame(self.body, bg="#fff", highlightthickness=1,
                           highlightbackground="#e5e7eb")
        keywrap.pack(fill=tk.X, pady=(6, 4))
        e = tk.Entry(keywrap, bg="#fff", fg="#111827", bd=0,
                     font=("Courier", 10), highlightthickness=0,
                     justify="center")
        e.insert(0, self.key_str)
        e.config(state="readonly", readonlybackground="#fff")
        e.pack(fill=tk.X, padx=10, pady=10)

        row = tk.Frame(self.body, bg="#f7f8fa")
        row.pack(fill=tk.X, pady=(2, 0))
        tk.Button(row, text="Copy key", command=self._copy_key,
                  bg="#f3f4f6", fg="#111827", activebackground="#e5e7eb",
                  relief=tk.FLAT, bd=0, font=("TkDefaultFont", 9),
                  padx=14, pady=8, cursor="hand2").pack(side=tk.LEFT)
        tk.Button(row, text="Save key to .txt…", command=self._save_key,
                  bg="#f3f4f6", fg="#111827", activebackground="#e5e7eb",
                  relief=tk.FLAT, bd=0, font=("TkDefaultFont", 9),
                  padx=14, pady=8, cursor="hand2"
                  ).pack(side=tk.LEFT, padx=(8, 0))

        self.status = tk.Label(self.body, text="", bg="#f7f8fa", fg="#059669",
                               font=("TkDefaultFont", 9), anchor="w")
        self.status.pack(fill=tk.X, pady=(10, 0))

    def _stamp(self):
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    def _save_file(self):
        fn = filedialog.asksaveasfilename(
            parent=self.win, defaultextension=".0share",
            filetypes=[("0NET share", "*.0share"), ("JSON", "*.json"),
                       ("All files", "*.*")],
            initialfile=f"0net_share_{self._stamp()}.0share")
        if not fn:
            return
        try:
            Path(fn).write_bytes(self.file_bytes)
            self.status.config(text=f"Saved file → {fn}", fg="#059669")
        except OSError as e:
            messagebox.showerror("Save", str(e), parent=self.win)

    def _copy_key(self):
        try:
            self.win.clipboard_clear()
            self.win.clipboard_append(self.key_str)
            self.status.config(text="Key copied to clipboard.",
                               fg="#059669")
        except tk.TclError as e:
            messagebox.showerror("Copy", str(e), parent=self.win)

    def _save_key(self):
        fn = filedialog.asksaveasfilename(
            parent=self.win, defaultextension=".txt",
            filetypes=[("Text file", "*.txt"), ("All files", "*.*")],
            initialfile=f"0net_share_{self._stamp()}.key.txt")
        if not fn:
            return
        try:
            Path(fn).write_text(self.key_str + "\n", encoding="utf-8")
            self.status.config(text=f"Saved key → {fn}", fg="#059669")
        except OSError as e:
            messagebox.showerror("Save", str(e), parent=self.win)


# ---------------------------------------------------------------- import dialog

class ImportDialog:
    def __init__(self, parent, app):
        self.app = app
        self.file_bytes = None
        self.parsed = None

        self.win = tk.Toplevel(parent)
        self.win.title("Import Devices")
        self.win.geometry("640x660")
        self.win.minsize(600, 600)
        self.win.configure(bg="#f7f8fa")
        self.win.transient(parent)
        self.win.grab_set()

        tk.Label(self.win, text="Import Devices", bg="#f7f8fa", fg="#111827",
                 font=("TkDefaultFont", 15, "bold"), anchor="w"
                 ).pack(fill=tk.X, padx=20, pady=(18, 2))
        tk.Label(self.win,
                 text="Provide the encrypted .0share file and the secret "
                      "key that was used to create it.",
                 bg="#f7f8fa", fg="#6b7280", font=("TkDefaultFont", 9),
                 anchor="w", justify="left", wraplength=580
                 ).pack(fill=tk.X, padx=20, pady=(0, 14))

        footer = tk.Frame(self.win, bg="#f7f8fa")
        footer.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=14)
        tk.Button(footer, text="Cancel", command=self.win.destroy,
                  bg="#f3f4f6", fg="#111827", activebackground="#e5e7eb",
                  relief=tk.FLAT, bd=0, font=("TkDefaultFont", 10),
                  padx=20, pady=8, cursor="hand2").pack(side=tk.RIGHT)
        self.import_btn = tk.Button(footer, text="Import",
                                    command=self._do_import,
                                    bg="#2563eb", fg="#fff",
                                    activebackground="#1d4ed8",
                                    activeforeground="#fff",
                                    relief=tk.FLAT, bd=0,
                                    font=("TkDefaultFont", 10, "bold"),
                                    padx=22, pady=8, cursor="hand2",
                                    state=tk.DISABLED)
        self.import_btn.pack(side=tk.RIGHT, padx=(0, 8))

        self.body = tk.Frame(self.win, bg="#f7f8fa")
        self.body.pack(fill=tk.BOTH, expand=True, padx=20)
        self.overwrite = tk.BooleanVar(value=False)
        self.status = tk.Label(self.body, text="", bg="#f7f8fa", fg="#6b7280",
                               font=("TkDefaultFont", 9), anchor="w",
                               justify="left", wraplength=580)
        self._form()

    def _form(self):
        tk.Label(self.body, text="1.  Encrypted share file (.0share)",
                 bg="#f7f8fa", fg="#111827",
                 font=("TkDefaultFont", 10, "bold"), anchor="w"
                 ).pack(fill=tk.X, pady=(6, 4))
        row = tk.Frame(self.body, bg="#f7f8fa")
        row.pack(fill=tk.X)
        self.file_var = tk.StringVar()
        tk.Entry(row, textvariable=self.file_var, bg="#fff", fg="#111827",
                 bd=0, insertbackground="#111827",
                 font=("TkDefaultFont", 10), highlightthickness=1,
                 highlightbackground="#e5e7eb", highlightcolor="#2563eb"
                 ).pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=7)
        tk.Button(row, text="Browse…", command=self._browse_file,
                  bg="#f3f4f6", fg="#111827", activebackground="#e5e7eb",
                  relief=tk.FLAT, bd=0, font=("TkDefaultFont", 9),
                  padx=14, pady=7, cursor="hand2"
                  ).pack(side=tk.LEFT, padx=(8, 0))

        tk.Label(self.body, text="2.  Secret key", bg="#f7f8fa", fg="#111827",
                 font=("TkDefaultFont", 10, "bold"), anchor="w"
                 ).pack(fill=tk.X, pady=(16, 4))
        self.key_var = tk.StringVar()
        tk.Entry(self.body, textvariable=self.key_var, bg="#fff",
                 fg="#111827", bd=0, insertbackground="#111827",
                 font=("Courier", 10), highlightthickness=1,
                 highlightbackground="#e5e7eb", highlightcolor="#2563eb"
                 ).pack(fill=tk.X, ipady=7)
        tk.Button(self.body, text="Load key from file…",
                  command=self._browse_key, bg="#f3f4f6", fg="#111827",
                  activebackground="#e5e7eb", relief=tk.FLAT, bd=0,
                  font=("TkDefaultFont", 9), padx=14, pady=6, cursor="hand2"
                  ).pack(anchor="w", pady=(6, 0))

        tk.Button(self.body, text="Verify", command=self._verify,
                  bg="#f3f4f6", fg="#111827", activebackground="#e5e7eb",
                  relief=tk.FLAT, bd=0, font=("TkDefaultFont", 10, "bold"),
                  padx=22, pady=8, cursor="hand2"
                  ).pack(anchor="w", pady=(16, 0))

        self.preview = tk.Frame(self.body, bg="#f7f8fa")
        self.preview.pack(fill=tk.BOTH, expand=True, pady=(14, 0))
        self.status.pack(fill=tk.X, pady=(10, 0))

    def _browse_file(self):
        fn = filedialog.askopenfilename(
            parent=self.win,
            filetypes=[("0NET share", "*.0share"), ("JSON", "*.json"),
                       ("All files", "*.*")])
        if not fn:
            return
        try:
            self.file_bytes = Path(fn).read_bytes()
        except OSError as e:
            messagebox.showerror("Read failed", str(e), parent=self.win)
            return
        self.file_var.set(fn)
        self.status.config(text="", fg="#6b7280")
        self._reset_preview()

    def _browse_key(self):
        fn = filedialog.askopenfilename(
            parent=self.win,
            filetypes=[("Text file", "*.txt"), ("All files", "*.*")])
        if not fn:
            return
        try:
            text = Path(fn).read_text(encoding="utf-8")
        except OSError as e:
            messagebox.showerror("Read failed", str(e), parent=self.win)
            return
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                self.key_var.set(line)
                return
        messagebox.showerror("Empty key file",
                             "That file had no key text in it.",
                             parent=self.win)

    def _verify(self):
        self._reset_preview()
        if not self.file_bytes:
            self.status.config(text="Choose the .0share file first.",
                               fg="#dc2626")
            return
        key = parse_key(self.key_var.get().strip())
        if not key:
            self.status.config(
                text="That doesn't look like a 0NET share key.",
                fg="#dc2626")
            return
        try:
            devices = open_share(self.file_bytes, key)
        except ShareError as e:
            self.status.config(text=str(e), fg="#dc2626")
            return
        except Exception as e:
            log.exception("import failed")
            self.status.config(text=f"Unexpected error: {e}", fg="#dc2626")
            return
        self.parsed = devices
        self._preview(devices)

    def _reset_preview(self):
        for w in self.preview.winfo_children():
            w.destroy()
        try:
            self.import_btn.config(state=tk.DISABLED, bg="#9ca3af")
        except tk.TclError:
            pass

    def _preview(self, devices):
        self._reset_preview()
        if not devices:
            self.status.config(
                text="The share is valid but has no devices in it.",
                fg="#dc2626")
            return

        have = {d["ip"] for d in self.app.devices}
        dupes = [d for d in devices if d["ip"] in have]

        header = tk.Frame(self.preview, bg="#fff", highlightthickness=1,
                          highlightbackground="#e5e7eb")
        header.pack(fill=tk.X)
        tk.Label(header,
                 text=f"Verified. {len(devices)} device"
                      f"{'s' if len(devices) != 1 else ''} found.",
                 bg="#fff", fg="#059669", font=("TkDefaultFont", 10, "bold"),
                 anchor="w").pack(fill=tk.X, padx=14, pady=(12, 4))
        tk.Label(header,
                 text=f"{len(dupes)} of these IPs are already in your list.",
                 bg="#fff", fg="#6b7280", font=("TkDefaultFont", 9),
                 anchor="w").pack(fill=tk.X, padx=14, pady=(0, 10))
        if dupes:
            tk.Checkbutton(
                header,
                text="Replace existing devices with the same IP "
                     "(overwrites local notes and credentials)",
                variable=self.overwrite, bg="#fff", fg="#111827",
                activebackground="#fff", activeforeground="#111827",
                selectcolor="#fff", font=("TkDefaultFont", 9), anchor="w",
                bd=0, highlightthickness=0, justify="left", wraplength=560
                ).pack(fill=tk.X, padx=14, pady=(0, 12))

        lw = tk.Frame(self.preview, bg="#fff", highlightthickness=1,
                      highlightbackground="#e5e7eb")
        lw.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        tk.Label(lw, text="Preview", bg="#fff", fg="#9ca3af",
                 font=("TkDefaultFont", 8, "bold"), anchor="w"
                 ).pack(fill=tk.X, padx=12, pady=(10, 4))
        lb = tk.Listbox(lw, bg="#fff", fg="#111827", bd=0,
                        highlightthickness=0, font=("Courier", 9),
                        activestyle="none")
        lb.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 12))
        for d in devices[:500]:
            marker = "•" if d["ip"] in have else " "
            lb.insert(tk.END, f"{marker}  {d['ip']:<39}  "
                              f"{d.get('type') or '—'}")
        if len(devices) > 500:
            lb.insert(tk.END, f"    … and {len(devices) - 500} more")

        self.status.config(text="Looks good. Click Import to merge.",
                           fg="#059669")
        try:
            self.import_btn.config(state=tk.NORMAL, bg="#2563eb")
        except tk.TclError:
            pass

    def _do_import(self):
        if not self.parsed:
            return
        try:
            added, updated, skipped = self.app.import_devices(
                self.parsed, self.overwrite.get())
        except Exception as e:
            log.exception("import failed")
            messagebox.showerror("Import", str(e), parent=self.win)
            return
        messagebox.showinfo("Import complete",
                            f"Added:   {added}\n"
                            f"Updated: {updated}\n"
                            f"Skipped: {skipped}",
                            parent=self.win)
        self.win.destroy()


# ---------------------------------------------------------------- add/edit

class AddDeviceDialog:
    def __init__(self, parent, callback, device=None):
        self.callback = callback
        self.device = device
        self.editing = device is not None

        self.win = tk.Toplevel(parent)
        self.win.title("Edit Device" if self.editing else "Add Device")
        self.win.geometry("460x660")
        self.win.minsize(420, 600)
        self.win.configure(bg="#f7f8fa")
        self.win.transient(parent)
        self.win.grab_set()

        tk.Label(self.win,
                 text="Edit Device" if self.editing else "Add Device",
                 bg="#f7f8fa", fg="#111827",
                 font=("TkDefaultFont", 15, "bold"), anchor="w"
                 ).pack(fill=tk.X, padx=20, pady=(18, 2))
        tk.Label(self.win, text="Fill in the details below",
                 bg="#f7f8fa", fg="#6b7280", font=("TkDefaultFont", 9),
                 anchor="w").pack(fill=tk.X, padx=20, pady=(0, 14))

        footer = tk.Frame(self.win, bg="#f7f8fa")
        footer.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=16)
        tk.Button(footer, text="Cancel", command=self.win.destroy,
                  bg="#f3f4f6", fg="#111827", activebackground="#e5e7eb",
                  activeforeground="#111827", relief=tk.FLAT, bd=0,
                  font=("TkDefaultFont", 10), padx=20, pady=8, cursor="hand2"
                  ).pack(side=tk.RIGHT)
        tk.Button(footer, text="Update" if self.editing else "Add",
                  command=self._save, bg="#2563eb", fg="#fff",
                  activebackground="#1d4ed8", activeforeground="#fff",
                  relief=tk.FLAT, bd=0,
                  font=("TkDefaultFont", 10, "bold"), padx=22, pady=8,
                  cursor="hand2").pack(side=tk.RIGHT, padx=(0, 8))

        wrap = tk.Frame(self.win, bg="#f7f8fa")
        wrap.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=20)
        canvas = tk.Canvas(wrap, bg="#f7f8fa", highlightthickness=0)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        inner = tk.Frame(canvas, bg="#f7f8fa")
        inner.bind("<Configure>",
                   lambda e: canvas.configure(
                       scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        self.v = {}
        defaults = {"ip": "", "port": "23", "vendor": "", "model": "",
                    "serial": "", "username": "", "password": "",
                    "notes": "", "type": ""}
        if device:
            for k in defaults:
                defaults[k] = str(device.get(k) or "")

        def field(label, key, show=None):
            tk.Label(inner, text=label, bg="#f7f8fa", fg="#374151",
                     font=("TkDefaultFont", 9, "bold"), anchor="w"
                     ).pack(fill=tk.X, pady=(10, 4))
            var = tk.StringVar(value=defaults[key])
            tk.Entry(inner, textvariable=var, bg="#fff", fg="#111827",
                     bd=0, insertbackground="#111827",
                     font=("TkDefaultFont", 10), highlightthickness=1,
                     highlightbackground="#e5e7eb",
                     highlightcolor="#2563eb", show=show or ""
                     ).pack(fill=tk.X, ipady=7)
            self.v[key] = var

        field("IP Address *", "ip")
        field("Port", "port")
        field("Device Type", "type")
        field("Vendor", "vendor")
        field("Model", "model")
        field("Serial", "serial")
        field("Username", "username")
        field("Password", "password", show="•")

        nh = tk.Frame(inner, bg="#f7f8fa")
        nh.pack(fill=tk.X, pady=(10, 4))
        tk.Label(nh, text="Notes", bg="#f7f8fa", fg="#374151",
                 font=("TkDefaultFont", 9, "bold"), anchor="w"
                 ).pack(side=tk.LEFT)
        tk.Button(nh, text="Clear",
                  command=lambda: self.notes.delete("1.0", tk.END),
                  bg="#f3f4f6", fg="#111827", activebackground="#e5e7eb",
                  relief=tk.FLAT, bd=0, font=("TkDefaultFont", 8),
                  padx=10, pady=2, cursor="hand2").pack(side=tk.RIGHT)

        self.notes = tk.Text(inner, height=4, bg="#fff", fg="#111827",
                             bd=0, insertbackground="#111827",
                             font=("TkDefaultFont", 10), wrap=tk.WORD,
                             highlightthickness=1,
                             highlightbackground="#e5e7eb",
                             highlightcolor="#2563eb", padx=6, pady=6)
        self.notes.pack(fill=tk.X, pady=(0, 8))
        self.notes.insert("1.0", defaults["notes"])

        self.win.bind("<Return>", lambda e: self._save())
        self.win.bind("<Escape>", lambda e: self.win.destroy())
        self.win.after(80, self.win.focus_force)

    def _save(self):
        ip = self.v["ip"].get().strip()
        if not valid_ip(ip):
            messagebox.showerror("Invalid IP",
                                 "Enter a valid IPv4 or IPv6 address.",
                                 parent=self.win)
            return
        try:
            port = int(self.v["port"].get().strip())
        except ValueError:
            messagebox.showerror("Invalid Port", "Port must be a number.",
                                 parent=self.win)
            return
        if not valid_port(port):
            messagebox.showerror("Invalid Port",
                                 "Port must be 1–65535.", parent=self.win)
            return

        if self.editing:
            old = self.device
            if old["ip"] == ip:
                loc = dict(old.get("location") or {})
                online = old.get("online", False)
                latency = old.get("latency_ms")
                last = old.get("last_checked", "")
                added = old.get("added", "")
            else:
                loc = {"city": "", "country": "", "lat": 0.0,
                       "lon": 0.0, "isp": ""}
                online, latency, last = False, None, ""
                added = old.get("added") or datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S")
        else:
            loc = {"city": "", "country": "", "lat": 0.0, "lon": 0.0,
                   "isp": ""}
            online, latency, last = False, None, ""
            added = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        data = {
            "ip": ip,
            "type": self.v["type"].get().strip(),
            "vendor": self.v["vendor"].get().strip(),
            "model": self.v["model"].get().strip(),
            "port": port,
            "username": self.v["username"].get().strip(),
            "password": self.v["password"].get().strip(),
            "serial": self.v["serial"].get().strip(),
            "notes": self.notes.get("1.0", tk.END).rstrip("\n"),
            "location": loc, "online": online, "latency_ms": latency,
            "last_checked": last, "added": added,
        }
        try:
            self.callback(data)
        except Exception as e:
            messagebox.showerror("Save failed", str(e), parent=self.win)
            return
        self.win.destroy()


class MultiEditDialog:
    FIELDS = [("type", "Device Type"), ("vendor", "Vendor"),
              ("model", "Model"), ("port", "Port"),
              ("username", "Username"), ("password", "Password"),
              ("serial", "Serial Number"), ("notes", "Notes")]

    def __init__(self, parent, callback, devices):
        self.callback = callback
        self.devices = devices
        n = len(devices)

        self.win = tk.Toplevel(parent)
        self.win.title(f"Edit {n} Devices")
        self.win.geometry("520x640")
        self.win.minsize(480, 580)
        self.win.configure(bg="#f7f8fa")
        self.win.transient(parent)
        self.win.grab_set()

        tk.Label(self.win, text=f"Edit {n} devices", bg="#f7f8fa",
                 fg="#111827", font=("TkDefaultFont", 15, "bold"), anchor="w"
                 ).pack(fill=tk.X, padx=20, pady=(18, 2))
        tk.Label(self.win,
                 text="Tick a checkbox to apply that field to every "
                      "selected device. Unticked fields are left alone.",
                 bg="#f7f8fa", fg="#6b7280", font=("TkDefaultFont", 9),
                 anchor="w", justify="left", wraplength=460
                 ).pack(fill=tk.X, padx=20, pady=(0, 14))

        footer = tk.Frame(self.win, bg="#f7f8fa")
        footer.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=16)
        tk.Button(footer, text="Cancel", command=self.win.destroy,
                  bg="#f3f4f6", fg="#111827", activebackground="#e5e7eb",
                  activeforeground="#111827", relief=tk.FLAT, bd=0,
                  font=("TkDefaultFont", 10), padx=20, pady=8, cursor="hand2"
                  ).pack(side=tk.RIGHT)
        tk.Button(footer, text=f"Apply to {n}", command=self._apply,
                  bg="#2563eb", fg="#fff", activebackground="#1d4ed8",
                  activeforeground="#fff", relief=tk.FLAT, bd=0,
                  font=("TkDefaultFont", 10, "bold"), padx=22, pady=8,
                  cursor="hand2").pack(side=tk.RIGHT, padx=(0, 8))

        body = tk.Frame(self.win, bg="#f7f8fa")
        body.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=20)

        self.vars = {}
        self.checks = {}
        for key, label in self.FIELDS:
            tk.Frame(body, bg="#f7f8fa", height=6).pack(fill=tk.X)
            apply_var = tk.BooleanVar(value=False)
            chk = tk.Checkbutton(body, text=label, variable=apply_var,
                                 bg="#f7f8fa", fg="#374151",
                                 activebackground="#f7f8fa",
                                 activeforeground="#374151",
                                 selectcolor="#f7f8fa",
                                 font=("TkDefaultFont", 9, "bold"),
                                 anchor="w", bd=0, highlightthickness=0)
            chk.pack(fill=tk.X)

            var = tk.StringVar()
            entry = tk.Entry(body, textvariable=var, bg="#e5e7eb",
                             fg="#9ca3af", disabledbackground="#e5e7eb",
                             disabledforeground="#9ca3af", bd=0,
                             insertbackground="#111827",
                             font=("TkDefaultFont", 10),
                             highlightthickness=1,
                             highlightbackground="#e5e7eb",
                             highlightcolor="#2563eb", state="disabled")
            entry.pack(fill=tk.X, ipady=6, pady=(2, 0))
            self.vars[key] = var
            self.checks[key] = apply_var

            def toggle(v=apply_var, e=entry):
                if v.get():
                    e.config(state="normal", bg="#fff", fg="#111827")
                    e.focus_set()
                else:
                    e.config(state="disabled", bg="#e5e7eb", fg="#9ca3af")
            chk.config(command=toggle)

        self.win.bind("<Escape>", lambda e: self.win.destroy())
        self.win.after(80, self.win.focus_force)

    def _apply(self):
        changes = {k: self.vars[k].get().strip()
                   for k, _ in self.FIELDS if self.checks[k].get()}
        if not changes:
            messagebox.showinfo("Nothing to do", "Tick at least one field.",
                                parent=self.win)
            return
        try:
            self.callback(self.devices, changes)
        except Exception as e:
            messagebox.showerror("Apply failed", str(e), parent=self.win)
            return
        self.win.destroy()


# ---------------------------------------------------------------- bulk add

class BulkAddDialog:
    MAX_BATCH = 1024

    def __init__(self, parent, callback):
        self.callback = callback
        self.probe_done = 0
        self.probe_added = 0
        self.probe_dupes = 0
        self.truncated = False
        self.cancelled = False

        self.win = tk.Toplevel(parent)
        self.win.title("Bulk Add")
        self.win.geometry("660x680")
        self.win.minsize(580, 620)
        self.win.configure(bg="#f7f8fa")
        self.win.transient(parent)
        self.win.grab_set()

        tk.Label(self.win, text="Bulk Add Devices", bg="#f7f8fa",
                 fg="#111827", font=("TkDefaultFont", 15, "bold"), anchor="w"
                 ).pack(fill=tk.X, padx=20, pady=(18, 2))
        tk.Label(self.win,
                 text="One IP per line, a range (192.168.1.1-192.168.1.20), "
                      "or CIDR (192.168.1.0/24)",
                 bg="#f7f8fa", fg="#6b7280", font=("TkDefaultFont", 9),
                 anchor="w").pack(fill=tk.X, padx=20, pady=(0, 12))

        footer = tk.Frame(self.win, bg="#f7f8fa")
        footer.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=14)
        tk.Button(footer, text="Cancel", command=self._cancel,
                  bg="#f3f4f6", fg="#111827", activebackground="#e5e7eb",
                  activeforeground="#111827", relief=tk.FLAT, bd=0,
                  font=("TkDefaultFont", 10), padx=20, pady=8, cursor="hand2"
                  ).pack(side=tk.RIGHT)
        self.add_btn = tk.Button(footer, text="Add All", command=self._add,
                                 bg="#2563eb", fg="#fff",
                                 activebackground="#1d4ed8",
                                 activeforeground="#fff", relief=tk.FLAT,
                                 bd=0, font=("TkDefaultFont", 10, "bold"),
                                 padx=22, pady=8, cursor="hand2")
        self.add_btn.pack(side=tk.RIGHT, padx=(0, 8))

        prog = tk.Frame(self.win, bg="#f7f8fa")
        prog.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=(4, 0))
        self.progress_lbl = tk.Label(prog, text="", bg="#f7f8fa",
                                     fg="#6b7280", font=("TkDefaultFont", 9),
                                     anchor="w")
        self.progress_lbl.pack(fill=tk.X)
        self.progress_bar = ttk.Progressbar(prog, mode="determinate",
                                            maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=4)

        body = tk.Frame(self.win, bg="#f7f8fa")
        body.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=20)

        ih = tk.Frame(body, bg="#f7f8fa")
        ih.pack(fill=tk.X, pady=(0, 4))
        tk.Label(ih, text="IP Addresses", bg="#f7f8fa", fg="#374151",
                 font=("TkDefaultFont", 9, "bold")).pack(side=tk.LEFT)
        tk.Button(ih, text="Clear All",
                  command=lambda: self.text.delete("1.0", tk.END),
                  bg="#fef2f2", fg="#dc2626", activebackground="#fee2e2",
                  activeforeground="#dc2626", relief=tk.FLAT, bd=0,
                  font=("TkDefaultFont", 8), padx=10, pady=2, cursor="hand2"
                  ).pack(side=tk.RIGHT)

        self.text = scrolledtext.ScrolledText(body, height=8, bg="#fff",
                                              fg="#111827", bd=0,
                                              insertbackground="#111827",
                                              font=("Courier", 10),
                                              highlightthickness=1,
                                              highlightbackground="#e5e7eb",
                                              padx=6, pady=6)
        self.text.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        self.text.insert("1.0", "192.168.1.1-192.168.1.10")

        opt = tk.Frame(body, bg="#fff", highlightthickness=1,
                       highlightbackground="#e5e7eb")
        opt.pack(fill=tk.X, pady=(0, 10))
        tk.Label(opt, text="OPTIONS", bg="#fff", fg="#9ca3af",
                 font=("TkDefaultFont", 8, "bold"), anchor="w"
                 ).pack(fill=tk.X, padx=12, pady=(10, 4))

        self.send_nl = tk.BooleanVar(value=True)
        self._cbox(opt,
                   "Send a newline to elicit a banner (recommended — "
                   "most devices wait for input)", self.send_nl)
        self.reject = tk.BooleanVar(value=True)
        self._cbox(opt,
                   "Reject error banners (timeout, login failed, etc.)",
                   self.reject)
        self.capture = tk.BooleanVar(value=True)
        self._cbox(opt, "Capture banner text into Notes", self.capture)
        self.autotype = tk.BooleanVar(value=True)
        self._cbox(opt, "Auto-detect device type from banner", self.autotype)
        self.slow = tk.BooleanVar(value=True)
        self._cbox(opt,
                   "Slow sweep — avoids locking single-session devices",
                   self.slow, last=True)

        row = tk.Frame(body, bg="#f7f8fa")
        row.pack(fill=tk.X, pady=(0, 6))
        tk.Label(row, text="Port:", bg="#f7f8fa", fg="#374151",
                 font=("TkDefaultFont", 9, "bold")).pack(side=tk.LEFT)
        self.port_var = tk.StringVar(value="23")
        tk.Entry(row, textvariable=self.port_var, bg="#fff", fg="#111827",
                 bd=0, insertbackground="#111827",
                 font=("TkDefaultFont", 10), highlightthickness=1,
                 highlightbackground="#e5e7eb", highlightcolor="#2563eb",
                 width=8).pack(side=tk.LEFT, padx=(8, 0), ipady=5)

        nrow = tk.Frame(body, bg="#f7f8fa")
        nrow.pack(fill=tk.X, pady=(6, 8))
        tk.Label(nrow, text="Notes:", bg="#f7f8fa", fg="#374151",
                 font=("TkDefaultFont", 9, "bold")).pack(side=tk.LEFT)
        self.notes_var = tk.StringVar(value="")
        tk.Entry(nrow, textvariable=self.notes_var, bg="#fff", fg="#111827",
                 bd=0, insertbackground="#111827",
                 font=("TkDefaultFont", 10), highlightthickness=1,
                 highlightbackground="#e5e7eb", highlightcolor="#2563eb"
                 ).pack(side=tk.LEFT, fill=tk.X, expand=True,
                        padx=(8, 6), ipady=5)
        tk.Button(nrow, text="Clear",
                  command=lambda: self.notes_var.set(""),
                  bg="#f3f4f6", fg="#111827", activebackground="#e5e7eb",
                  activeforeground="#111827", relief=tk.FLAT, bd=0,
                  font=("TkDefaultFont", 8), padx=10, pady=4, cursor="hand2"
                  ).pack(side=tk.LEFT)

        self.win.after(80, self.win.focus_force)

    def _cbox(self, parent, text, var, last=False):
        tk.Checkbutton(parent, text=text, variable=var, bg="#fff",
                       fg="#111827", activebackground="#fff",
                       activeforeground="#111827", selectcolor="#fff",
                       font=("TkDefaultFont", 9), anchor="w", padx=0, bd=0,
                       highlightthickness=0
                       ).pack(fill=tk.X, padx=12, pady=(2, 8 if last else 2))

    @staticmethod
    def _parse_one(spec):
        spec = spec.strip()
        if not spec:
            return []
        try:
            if "/" in spec:
                net = ipaddress.ip_network(spec, strict=False)
                if net.version == 4 or net.num_addresses <= 256:
                    return [str(ip) for ip in net.hosts()]
                return []
            if "-" in spec:
                a, b = [s.strip() for s in spec.split("-", 1)]
                start = int(ipaddress.ip_address(a))
                end = int(ipaddress.ip_address(b))
                if end < start:
                    start, end = end, start
                if end - start > BulkAddDialog.MAX_BATCH:
                    end = start + BulkAddDialog.MAX_BATCH
                return [str(ipaddress.ip_address(i))
                        for i in range(start, end + 1)]
            ipaddress.ip_address(spec)
            return [spec]
        except (ValueError, ipaddress.AddressValueError):
            return []

    def _collect(self):
        seen, out = set(), []
        for line in self.text.get("1.0", tk.END).strip().splitlines():
            for ip in self._parse_one(line):
                if ip not in seen:
                    seen.add(ip)
                    out.append(ip)
        return out

    def _cancel(self):
        self.cancelled = True
        self.win.destroy()

    def _add(self):
        ips = self._collect()
        if not ips:
            messagebox.showerror("No IPs", "No valid IP addresses found.",
                                 parent=self.win)
            return
        if len(ips) > self.MAX_BATCH:
            if not messagebox.askyesno(
                    "Large batch",
                    f"{len(ips)} addresses — only the first "
                    f"{self.MAX_BATCH} will run. Continue?",
                    parent=self.win):
                return
            ips = ips[:self.MAX_BATCH]
            self.truncated = True
        if not valid_port(self.port_var.get()):
            messagebox.showerror("Invalid Port", "Port must be 1–65535.",
                                 parent=self.win)
            return
        self._probe_and_add(ips, int(self.port_var.get()))

    def _probe_and_add(self, ips, port):
        try:
            self.add_btn.config(state=tk.DISABLED, bg="#9ca3af")
        except tk.TclError:
            pass

        self.probe_total = len(ips)
        self.probe_done = 0
        self.probe_added = 0
        self.probe_dupes = 0

        self.progress_bar["maximum"] = self.probe_total
        self.progress_bar["value"] = 0
        self.progress_lbl.config(
            text=f"Probing 0/{self.probe_total} on port {port}…")

        send_nl = self.send_nl.get()
        reject = self.reject.get()
        capture = self.capture.get()
        autotype = self.autotype.get()
        slow = self.slow.get()
        user_notes = self.notes_var.get().strip()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        workers = 8 if slow else 32
        gap = 0.25 if slow else 0.0
        result_q = queue.Queue()

        def do_probe(ip):
            ok, lat, banner = probe(ip, port, timeout=2.0,
                                    send_newline=send_nl,
                                    require_banner=True,
                                    reject_errors=reject)
            result_q.put((ip, ok, lat, banner))

        def runner():
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futs = []
                for ip in ips:
                    if self.cancelled:
                        break
                    futs.append(pool.submit(do_probe, ip))
                    if gap:
                        time.sleep(gap)
                for _ in as_completed(futs):
                    if self.cancelled:
                        break

        threading.Thread(target=runner, daemon=True).start()

        def poll():
            if self.cancelled or not self.win.winfo_exists():
                return
            try:
                while True:
                    ip, ok, lat, banner = result_q.get_nowait()
                    self.probe_done += 1
                    self.progress_bar["value"] = self.probe_done

                    if ok:
                        dtype = "Unknown"
                        if autotype and banner:
                            g = guess_type(banner)
                            if g:
                                dtype = g
                        parts = []
                        if user_notes:
                            parts.append(user_notes)
                        if capture and banner:
                            parts.append(f"[banner] {banner[:500]}")
                        data = {
                            "ip": ip, "type": dtype, "vendor": "",
                            "model": "", "port": port, "username": "",
                            "password": "", "serial": "",
                            "notes": "  |  ".join(parts),
                            "location": {"city": "", "country": "",
                                         "lat": 0.0, "lon": 0.0,
                                         "isp": ""},
                            "online": True, "latency_ms": lat,
                            "last_checked": now, "added": now,
                        }
                        try:
                            if self.callback(data):
                                self.probe_added += 1
                            else:
                                self.probe_dupes += 1
                        except Exception:
                            log.exception("bulk add callback failed")

                    self.progress_lbl.config(
                        text=f"Probing {self.probe_done}/{self.probe_total}"
                             f"…   added {self.probe_added}   "
                             f"dupes {self.probe_dupes}")
            except queue.Empty:
                pass

            if self.probe_done >= self.probe_total:
                try:
                    self.callback(None, done=True)
                except Exception:
                    pass
                extra = ""
                if self.probe_dupes:
                    extra += f"\nDuplicates skipped:     {self.probe_dupes}"
                if self.truncated:
                    extra += (f"\n\nNote: input was truncated to "
                              f"{self.MAX_BATCH} addresses.")
                messagebox.showinfo(
                    "Bulk probe complete",
                    f"Probed:                {self.probe_total}\n"
                    f"Added (positive):      {self.probe_added}\n"
                    f"Skipped (silent/error): "
                    f"{self.probe_total - self.probe_added - self.probe_dupes}"
                    f"{extra}", parent=self.win)
                self.win.destroy()
                return

            try:
                self.win.after(100, poll)
            except tk.TclError:
                pass

        self.win.after(100, poll)


# ---------------------------------------------------------------- terminal

class TerminalFrame(tk.Frame):
    def __init__(self, parent, device):
        super().__init__(parent, bg="#f7f8fa")
        self.ip = device["ip"]
        self.port = safe_int(device.get("port"), 23)
        self.sock = None
        self.alive = True
        self.connected = False
        self.got_any = False
        self.rx = queue.Queue()
        self._build()
        threading.Thread(target=self._reader, daemon=True).start()
        self.after(100, self._pump)

    def _build(self):
        head = tk.Frame(self, bg="#fff", height=44)
        head.pack(fill=tk.X)
        head.pack_propagate(False)
        tk.Frame(head, bg="#e5e7eb", height=1).pack(side=tk.BOTTOM, fill=tk.X)

        self.dot = tk.Canvas(head, width=10, height=10, bg="#fff",
                             highlightthickness=0)
        self.dot.pack(side=tk.LEFT, padx=(14, 8), pady=17)
        self.dot.create_oval(1, 1, 9, 9, fill="#f59e0b", outline="")
        self.status = tk.Label(head, text=f"{self.ip}:{self.port} — "
                                          f"connecting…",
                               bg="#fff", fg="#111827",
                               font=("TkDefaultFont", 10))
        self.status.pack(side=tk.LEFT, pady=14)
        tk.Label(head, text="⚠ plaintext — don't use real credentials",
                 bg="#fff", fg="#dc2626", font=("TkDefaultFont", 8)
                 ).pack(side=tk.RIGHT, padx=14, pady=17)

        wrap = tk.Frame(self, bg="#0f172a")
        wrap.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.text = scrolledtext.ScrolledText(wrap, bg="#0f172a",
                                              fg="#e2e8f0",
                                              font=("Courier", 10), bd=0,
                                              insertbackground="#fff",
                                              selectbackground="#1e40af")
        self.text.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)

        inp = tk.Frame(self, bg="#fff")
        inp.pack(fill=tk.X, padx=10, pady=(0, 10))
        tk.Label(inp, text="›", bg="#fff", fg="#2563eb",
                 font=("Courier", 14, "bold")).pack(side=tk.LEFT,
                                                    padx=(10, 6))
        self.entry_var = tk.StringVar()
        self.entry = tk.Entry(inp, textvariable=self.entry_var, bg="#fff",
                              fg="#111827", bd=0, insertbackground="#111827",
                              font=("Courier", 10), highlightthickness=0)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=8,
                        padx=(0, 8))
        self.entry.bind("<Return>", self._send)
        self.entry.focus_set()

        self.hide = tk.BooleanVar(value=False)
        tk.Checkbutton(inp, text="Hide input", variable=self.hide,
                       command=self._toggle_hide, bg="#fff", fg="#6b7280",
                       activebackground="#fff", activeforeground="#111827",
                       selectcolor="#fff", font=("TkDefaultFont", 8), bd=0,
                       highlightthickness=0
                       ).pack(side=tk.RIGHT, padx=(0, 6))
        tk.Button(inp, text="Send", command=self._send, bg="#2563eb",
                  fg="#fff", activebackground="#1d4ed8",
                  activeforeground="#fff", relief=tk.FLAT, bd=0,
                  font=("TkDefaultFont", 9, "bold"), padx=16, pady=6,
                  cursor="hand2").pack(side=tk.RIGHT, padx=8, pady=6)

    def _toggle_hide(self):
        self.entry.config(show="•" if self.hide.get() else "")

    def _reader(self):
        try:
            self.sock = make_socket(self.ip, self.port, 6)
            if not self.sock:
                self.rx.put("error: could not create socket\n")
                return
            self.sock.connect((self.ip, self.port))
            self.connected = True
            self.rx.put(f"connected to {self.ip}:{self.port}\n\n")
            self.sock.settimeout(0.3)
            while self.alive and self.connected:
                try:
                    data = self.sock.recv(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not data:
                    break
                self.got_any = True
                self.rx.put(telnet_strip(data))
        except OSError as e:
            self.rx.put(f"error: {e}\n")
        self.connected = False
        self.rx.put("\n--- disconnected ---\n" if self.got_any
                    else "\n--- peer closed without sending anything ---\n")
        close_socket(self.sock)
        self.sock = None

    def _send(self, _=None):
        txt = self.entry_var.get()
        if not txt:
            return
        self.entry_var.set("")
        shown = "•" * len(txt) if self.hide.get() else txt
        self.text.insert(tk.END, f"› {shown}\n")
        try:
            if self.sock and self.connected:
                self.sock.sendall((txt + "\r\n").encode())
        except OSError:
            pass

    def _pump(self):
        if not self.alive:
            return
        got = False
        try:
            while True:
                self.text.insert(tk.END, self.rx.get_nowait())
                got = True
        except queue.Empty:
            pass
        if got:
            try:
                self.text.see(tk.END)
            except tk.TclError:
                pass
        if self.connected:
            self.status.config(text=f"{self.ip}:{self.port} — connected",
                               fg="#059669")
            self.dot.delete("all")
            self.dot.create_oval(1, 1, 9, 9, fill="#059669", outline="")
        else:
            self.status.config(text=f"{self.ip}:{self.port} — disconnected",
                               fg="#dc2626")
            self.dot.delete("all")
            self.dot.create_oval(1, 1, 9, 9, fill="#dc2626", outline="")
        try:
            self.after(100, self._pump)
        except tk.TclError:
            pass

    def close(self):
        self.alive = False
        close_socket(self.sock)
        self.sock = None


class TerminalWindow:
    def __init__(self, parent, device):
        self.win = tk.Toplevel(parent)
        self.win.title(f"Terminal — {device['ip']}:{device.get('port', 23)}")
        self.win.geometry("820x580")
        self.win.configure(bg="#f7f8fa")
        self.frame = TerminalFrame(self.win, device)
        self.frame.pack(fill=tk.BOTH, expand=True)
        self.win.protocol("WM_DELETE_WINDOW", self._close)

    def _close(self):
        try:
            self.frame.close()
        except Exception:
            pass
        try:
            self.win.destroy()
        except tk.TclError:
            pass


class TerminalTabsWindow:
    def __init__(self, parent, devices):
        self.frames = []
        self.win = tk.Toplevel(parent)
        self.win.title(f"Terminals — {len(devices)} sessions")
        self.win.geometry("980x600")
        self.win.configure(bg="#f7f8fa")

        nb = ttk.Notebook(self.win)
        nb.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        for d in devices:
            fr = TerminalFrame(nb, d)
            nb.add(fr, text=f"{d['ip']}:{d.get('port', 23)}")
            self.frames.append(fr)
        self.win.protocol("WM_DELETE_WINDOW", self._close)

    def _close(self):
        for fr in self.frames:
            try:
                fr.close()
            except Exception:
                pass
        try:
            self.win.destroy()
        except tk.TclError:
            pass


# ---------------------------------------------------------------- map

class MapWindow:
    TILE = ("https://server.arcgisonline.com/ArcGIS/rest/services/"
            "Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}")

    def __init__(self, parent, devices):
        self.devices = devices
        self.markers = {}
        self.popup = None

        self.win = tk.Toplevel(parent)
        self.win.title("Device Map")
        self.win.geometry("1000x680")
        self.win.configure(bg="#f7f8fa")

        head = tk.Frame(self.win, bg="#fff", height=44)
        head.pack(fill=tk.X)
        head.pack_propagate(False)
        tk.Frame(head, bg="#e5e7eb", height=1).pack(side=tk.BOTTOM, fill=tk.X)
        self.info = tk.Label(head, text="", bg="#fff", fg="#6b7280",
                             font=("TkDefaultFont", 9))
        self.info.pack(side=tk.LEFT, padx=14, pady=14)
        tk.Button(head, text="Fit All", command=self.fit_all, bg="#f3f4f6",
                  fg="#111827", activebackground="#e5e7eb", relief=tk.FLAT,
                  bd=0, font=("TkDefaultFont", 9), padx=12, pady=6,
                  cursor="hand2").pack(side=tk.RIGHT, padx=(6, 14), pady=8)
        tk.Button(head, text="Refresh", command=self.refresh, bg="#f3f4f6",
                  fg="#111827", activebackground="#e5e7eb", relief=tk.FLAT,
                  bd=0, font=("TkDefaultFont", 9), padx=12, pady=6,
                  cursor="hand2").pack(side=tk.RIGHT, pady=8)

        wrap = tk.Frame(self.win, bg="#f7f8fa")
        wrap.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.map = tkintermapview.TkinterMapView(wrap, corner_radius=6)
        self.map.pack(fill=tk.BOTH, expand=True)
        try:
            self.map.set_tile_server(self.TILE, max_zoom=19)
        except Exception:
            pass

        try:
            self.map.add_left_click_map_command(self._map_click)
        except Exception:
            try:
                self.map.canvas.bind("<Button-1>", self._canvas_click,
                                     add="+")
            except Exception:
                pass

        self.refresh()
        self.win.after(500, self.fit_all)

    def refresh(self):
        try:
            self.map.delete_all_marker()
        except Exception:
            pass
        self.markers.clear()
        plotted = 0
        for d in self.devices:
            loc = d.get("location") or {}
            try:
                lat = float(loc.get("lat", 0) or 0)
                lon = float(loc.get("lon", 0) or 0)
            except (TypeError, ValueError):
                continue
            if not (lat or lon):
                continue
            try:
                fill = "#22c55e" if d.get("online") else "#ef4444"
                self.map.set_marker(lat, lon, marker_color_circle=fill,
                                    marker_color_outside="#111827")
                self.markers[d["ip"]] = (lat, lon, d)
                plotted += 1
            except Exception:
                continue
        self.info.config(text=f"{plotted} of {len(self.devices)} plotted"
                              f"  ·  click a marker for details")

    def _map_click(self, coords):
        try:
            lat, lon = coords
        except (TypeError, ValueError):
            return
        self._handle(lat, lon)

    def _canvas_click(self, event):
        try:
            lat, lon = self.map.convert_canvas_coords_to_decimal_coords(
                event.x, event.y)
        except Exception:
            return
        self._handle(lat, lon)

    def _handle(self, lat, lon):
        if not self.markers:
            return
        best_ip, best_d = None, float("inf")
        for ip, (mlat, mlon, _) in self.markers.items():
            d2 = (lat - mlat) ** 2 + (lon - mlon) ** 2
            if d2 < best_d:
                best_d, best_ip = d2, ip
        if best_ip is None:
            return
        try:
            zoom = self.map.zoom
        except Exception:
            zoom = 10
        if best_d ** 0.5 > 25 * (360.0 / (256.0 * (2 ** zoom))):
            return
        self._popup_for(self.markers[best_ip][2], best_ip)

    def _popup_for(self, device, ip):
        if self.popup:
            try:
                self.popup.destroy()
            except Exception:
                pass
        pop = tk.Toplevel(self.win)
        self.popup = pop
        pop.title(ip)
        pop.configure(bg="#fff")
        pop.resizable(False, False)
        pop.transient(self.win)

        w, h = 340, 360
        x = y = None
        try:
            loc = device.get("location") or {}
            mlat = float(loc.get("lat") or 0)
            mlon = float(loc.get("lon") or 0)
            if mlat or mlon:
                cx, cy = self.map.convert_decimal_coords_to_canvas_coords(
                    mlat, mlon)
                x = self.map.winfo_rootx() + int(cx) + 20
                y = self.map.winfo_rooty() + int(cy) + 20
        except Exception:
            x = y = None
        if x is None:
            try:
                x = self.win.winfo_rootx() + 60
                y = self.win.winfo_rooty() + 60
            except tk.TclError:
                x, y = 200, 200
        try:
            sw, sh = pop.winfo_screenwidth(), pop.winfo_screenheight()
            x = max(10, min(x, sw - w - 20))
            y = max(10, min(y, sh - h - 40))
        except tk.TclError:
            pass
        try:
            pop.geometry(f"{w}x{h}+{x}+{y}")
        except tk.TclError:
            pop.geometry(f"{w}x{h}")

        online = bool(device.get("online"))
        hdr = tk.Frame(pop, bg="#fff")
        hdr.pack(fill=tk.X, padx=16, pady=(14, 6))
        dot = tk.Canvas(hdr, width=10, height=10, bg="#fff",
                        highlightthickness=0)
        dot.pack(side=tk.LEFT, padx=(0, 8))
        dot.create_oval(1, 1, 9, 9, fill="#22c55e" if online else "#ef4444",
                        outline="")
        tk.Label(hdr, text=device.get("ip", "—"), bg="#fff", fg="#111827",
                 font=("TkDefaultFont", 12, "bold"), anchor="w"
                 ).pack(side=tk.LEFT)
        tk.Label(pop, text=device.get("type") or "Device", bg="#fff",
                 fg="#6b7280", font=("TkDefaultFont", 10), anchor="w"
                 ).pack(fill=tk.X, padx=16, pady=(0, 12))

        body = tk.Frame(pop, bg="#fff")
        body.pack(fill=tk.BOTH, expand=True, padx=16)
        loc = device.get("location") or {}
        lat_ms = device.get("latency_ms")
        rows = [
            ("Status", "online" if online else "offline"),
            ("Port", str(device.get("port", 23))),
            ("Latency", f"{lat_ms:.0f} ms" if lat_ms is not None else "—"),
            ("Vendor", device.get("vendor") or "—"),
            ("Model", device.get("model") or "—"),
            ("Serial", device.get("serial") or "—"),
            ("Country", loc.get("country") or "—"),
            ("City", loc.get("city") or "—"),
            ("ISP", loc.get("isp") or "—"),
        ]
        for label, value in rows:
            row = tk.Frame(body, bg="#fff")
            row.pack(fill=tk.X, pady=2)
            tk.Label(row, text=label, bg="#fff", fg="#9ca3af",
                     font=("TkDefaultFont", 8), width=8, anchor="w"
                     ).pack(side=tk.LEFT)
            tk.Label(row, text=value, bg="#fff", fg="#111827",
                     font=("TkDefaultFont", 9), anchor="w", justify="left",
                     wraplength=230
                     ).pack(side=tk.LEFT, fill=tk.X, expand=True)

        foot = tk.Frame(pop, bg="#fff")
        foot.pack(fill=tk.X, padx=16, pady=12)
        tk.Button(foot, text="Close", command=pop.destroy, bg="#f3f4f6",
                  fg="#111827", activebackground="#e5e7eb", relief=tk.FLAT,
                  bd=0, font=("TkDefaultFont", 9), padx=14, pady=6,
                  cursor="hand2").pack(side=tk.RIGHT)
        pop.bind("<Escape>", lambda e: pop.destroy())

    def fit_all(self):
        pts = []
        for d in self.devices:
            loc = d.get("location") or {}
            try:
                lat = float(loc.get("lat", 0) or 0)
                lon = float(loc.get("lon", 0) or 0)
            except (TypeError, ValueError):
                continue
            if lat or lon:
                pts.append((lat, lon))
        if not pts:
            self.map.set_position(20.0, 0.0)
            self.map.set_zoom(2)
            return
        max_lat = max(p[0] for p in pts)
        min_lat = min(p[0] for p in pts)
        max_lon = max(p[1] for p in pts)
        min_lon = min(p[1] for p in pts)
        if max_lat == min_lat and max_lon == min_lon:
            self.map.set_position(max_lat, max_lon)
            self.map.set_zoom(12)
            return
        try:
            self.map.fit_bounding_box((max_lat, min_lon), (min_lat, max_lon))
        except Exception:
            pass


# ---------------------------------------------------------------- entry

def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
