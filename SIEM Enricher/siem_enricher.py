#!/usr/bin/env python3
"""
siem_enricher.py - SIEM IP Enrichment & Containment Simulator
=============================================================

Reads a SIEM log feed, pulls the IP address(es) out of every event, enriches
each public IP with VirusTotal threat intelligence, and lets an analyst
CONTAIN an IP. Containing an IP writes it to a firewall blocklist file.

    SIEM feed (log file) -> parse -> VirusTotal enrichment -> analyst decision
                                                               |-> firewall blocklist (file)
                                                               |-> audit trail (CSV)

In production the input would be a SIEM alert stream, and containment would
push a block rule to the firewall (e.g. an External Dynamic List or the
firewall's API). Here plain text files stand in for both, so the whole
detect -> enrich -> respond loop runs anywhere.

Requirements: Python 3.8+ only. Standard library, nothing to pip install.

QUICK START
-----------
  python siem_enricher.py                          # interactive menu (works in any IDE: just press Run)
  python siem_enricher.py --make-sample siem.log   # create a realistic sample SIEM log
  python siem_enricher.py siem.log --mock          # try everything without an API key
  python siem_enricher.py siem.log                 # live VirusTotal lookups
  python siem_enricher.py siem.log --follow --simulate   # watch a live feed (tail -f style)
  python siem_enricher.py --contain 45.155.205.233 --reason "SSH brute force"
  python siem_enricher.py --release 45.155.205.233
  python siem_enricher.py --list                   # show the firewall blocklist + audit trail

API KEY: set the VT_API_KEY environment variable, put VT_API_KEY=... in a .env
file next to this script, or paste it when prompted. Free key:
https://www.virustotal.com/gui/my-apikey  (the free API allows 4 lookups/minute;
the script paces itself and caches results so repeat runs are instant).

LOG FORMAT (one event per line, pipe-separated key=value pairs):
  2026-11-18T21:04:11Z | sev=HIGH | device=fw-edge-01 | event=SSH brute force | src_ip=185.220.101.4 | dst_ip=10.0.20.15 | dst_port=22 | action=allowed | msg=37 failed logins for root

Other formats still work: space-separated key=value (src=1.2.3.4 dst=...) is
understood, and any IPv4/IPv6 address anywhere in a line is extracted. Use
--pattern to supply your own regex with named groups, e.g.
  --pattern "^(?P<timestamp>\\S+) (?P<event>.+?) from (?P<src_ip>[\\d.]+)"

OUTPUT FILES (in ./siem_output next to this script unless --out-dir is given):
  firewall_blocklist.txt   simulated firewall: one blocked IP per line
  firewall_allowlist.txt   IPs/CIDRs that must never be blocked (edit freely)
  containment_audit.csv    who contained/released what, when, and why
  enriched_events.jsonl    every log event with its VirusTotal context attached
  vt_cache.json            cached VirusTotal answers (saves your API quota)
"""

from __future__ import annotations

import argparse
import csv
import getpass
import hashlib
import ipaddress
import json
import math
import os
import random
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from dataclasses import fields as dc_fields
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, Iterator, List, Optional, Pattern, Set, Tuple

VERSION = "1.0.0"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
VT_API_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
VT_GUI_URL = "https://www.virustotal.com/gui/ip-address/"

# Never crash on odd characters when output is redirected (e.g. Windows cp1252).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass

if os.name == "nt":
    os.system("")  # turns on ANSI colour support in the classic Windows console


# =============================================================================
# Terminal styling
# =============================================================================

def _supports_color() -> bool:
    if os.getenv("NO_COLOR"):
        return False
    if os.getenv("FORCE_COLOR"):
        return True
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


class Style:
    enabled = _supports_color()


def _c(code: str, text: str) -> str:
    return "\033[{}m{}\033[0m".format(code, text) if Style.enabled else text


def bold(t: str) -> str: return _c("1", t)
def dim(t: str) -> str: return _c("2", t)
def red(t: str) -> str: return _c("91", t)
def yellow(t: str) -> str: return _c("93", t)
def green(t: str) -> str: return _c("92", t)
def cyan(t: str) -> str: return _c("96", t)
def magenta(t: str) -> str: return _c("95", t)


VERDICT_RANK = {"MALICIOUS": 5, "SUSPICIOUS": 4, "UNKNOWN": 3, "ERROR": 2, "CLEAN": 1, "INTERNAL": 0}
VERDICT_STYLE: Dict[str, Callable[[str], str]] = {
    "MALICIOUS": lambda t: _c("1;91", t),
    "SUSPICIOUS": yellow,
    "UNKNOWN": cyan,
    "ERROR": magenta,
    "CLEAN": green,
    "INTERNAL": dim,
}
# Verdicts an analyst is asked about during review. CLEAN/INTERNAL are skipped
# (they can still be contained manually).
REVIEW_VERDICTS = ("MALICIOUS", "SUSPICIOUS", "UNKNOWN", "ERROR")


def fmt_verdict(verdict: str, width: int = 10) -> str:
    return VERDICT_STYLE.get(verdict, str)(verdict.ljust(width))


def trunc(text: str, n: int) -> str:
    text = text or ""
    return text if len(text) <= n else text[: max(0, n - 3)] + "..."


ANSI_RE = re.compile(r"\033\[[\d;]*m")


def pad_ansi(text: str, width: int) -> str:
    """ljust that ignores colour codes when measuring width."""
    return text + " " * max(0, width - len(ANSI_RE.sub("", text)))


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def rule(title: str = "") -> None:
    line = "=" * 78
    if title:
        print("\n" + bold(cyan("== {} ".format(title) + "=" * max(0, 74 - len(title)))))
    else:
        print(dim(line))


def ask(prompt: str) -> Optional[str]:
    """input() that returns None instead of crashing when stdin is closed."""
    try:
        return input(prompt).strip()
    except EOFError:
        print()
        return None


def ask_yes_no(prompt: str, default: bool = False) -> bool:
    suffix = " [Y/n]: " if default else " [y/N]: "
    ans = ask(prompt + suffix)
    if ans is None or ans == "":
        return default
    return ans.lower().startswith("y")


def current_user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "analyst"


# =============================================================================
# IP helpers
# =============================================================================

IPV4_RE = re.compile(
    r"(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\w]|\.\d)"
)
IPV6_CANDIDATE_RE = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")


def normalize_ip(value: str) -> str:
    """Canonical form of an IP ('2001:DB8::0001' -> '2001:db8::1'). Raises ValueError."""
    return str(ipaddress.ip_address(value.strip().strip("[]")))


def is_valid_ip(value: str) -> bool:
    try:
        normalize_ip(value)
        return True
    except ValueError:
        return False


def is_public_ip(ip: str) -> bool:
    """True for internet-routable addresses (the only ones worth sending to VirusTotal)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version == 6 and addr.ipv4_mapped:  # type: ignore[union-attr]
        addr = addr.ipv4_mapped  # type: ignore[union-attr]
    return bool(addr.is_global) and not addr.is_multicast


def find_ips(text: str) -> List[str]:
    """Every valid IPv4/IPv6 address in a string, canonicalised, in order, de-duplicated."""
    found: List[str] = []
    for m in IPV4_RE.finditer(text):
        ip = normalize_ip(m.group(0))
        if ip not in found:
            found.append(ip)
    for m in IPV6_CANDIDATE_RE.finditer(text):
        try:
            ip = normalize_ip(m.group(0))
        except ValueError:
            continue
        if ip not in found:
            found.append(ip)
    return found


# =============================================================================
# Log parsing
# =============================================================================

SRC_KEYS = {"src_ip", "src", "srcip", "source_ip", "source", "sip", "client_ip", "clientip",
            "remote_ip", "remote_addr", "attacker_ip", "ip", "c_ip", "src_addr"}
DST_KEYS = {"dst_ip", "dst", "dstip", "dest_ip", "destination_ip", "dest", "dip",
            "server_ip", "target_ip", "dst_addr"}
SEVERITY_KEYS = ("sev", "severity", "level", "priority", "risk")
NAME_KEYS = ("event", "event_name", "signature", "alert", "rule", "rule_name", "category",
             "msg", "message")

SEVERITY_RANK = {"CRITICAL": 5, "CRIT": 5, "HIGH": 4, "MEDIUM": 3, "MED": 3, "WARNING": 3,
                 "WARN": 3, "LOW": 2, "INFO": 1, "INFORMATIONAL": 1, "NOTICE": 1, "DEBUG": 0}

KV_SPACE_RE = re.compile(r"""([A-Za-z_][\w.\-]*)=("([^"]*)"|'([^']*)'|\S+)""")
LEADING_TS_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
    r"|[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2})"
)


def severity_rank(sev: str) -> int:
    sev = (sev or "").strip().upper()
    if sev.isdigit():  # numeric levels, e.g. Wazuh 0-15
        n = int(sev)
        return 5 if n >= 12 else 4 if n >= 8 else 3 if n >= 5 else 2 if n >= 3 else 1
    return SEVERITY_RANK.get(sev, 0)


@dataclass
class IPRef:
    ip: str
    role: str      # "src", "dst", or the field name / "other" where it was found
    public: bool


@dataclass
class LogEvent:
    line_no: int
    raw: str
    timestamp: str = ""
    severity: str = ""
    name: str = ""
    fields: Dict[str, str] = field(default_factory=dict)
    ips: List[IPRef] = field(default_factory=list)
    known_format: bool = False

    @property
    def public_ips(self) -> List[str]:
        return [r.ip for r in self.ips if r.public]

    def role_of(self, ip: str) -> str:
        for r in self.ips:
            if r.ip == ip:
                return r.role
        return ""


def _parse_pipe(line: str) -> Tuple[str, Dict[str, str]]:
    ts, flds, extras = "", {}, []
    for i, part in enumerate(p.strip() for p in line.split("|")):
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            k = k.strip().lower()
            if k:
                flds[k] = v.strip().strip('"')
        elif i == 0:
            ts = part
        else:
            extras.append(part)
    if extras:
        flds.setdefault("text", " | ".join(extras))
    return ts, flds


def _parse_kv_space(line: str) -> Tuple[str, Dict[str, str]]:
    m = LEADING_TS_RE.match(line)
    ts = m.group(1) if m else ""
    flds = {}
    for km in KV_SPACE_RE.finditer(line):
        val = km.group(3) if km.group(3) is not None else km.group(4) if km.group(4) is not None else km.group(2)
        flds[km.group(1).lower()] = val
    return ts, flds


def parse_line(line: str, line_no: int, pattern: Optional[Pattern[str]] = None) -> Optional[LogEvent]:
    """Parse one log line. Returns None for blank lines and # comments."""
    raw = line.rstrip("\r\n")
    stripped = raw.strip()
    if not stripped or stripped.startswith("#"):
        return None

    ts, flds, known = "", {}, False
    if pattern is not None:
        m = pattern.search(raw)
        if m:
            flds = {k.lower(): v for k, v in m.groupdict().items() if v}
            ts = flds.get("timestamp", "")
            known = True
    if not known and "|" in raw:
        ts, flds = _parse_pipe(raw)
        known = bool(ts) and bool(flds)
    if not known and not flds:
        ts, flds = _parse_kv_space(raw)
        known = bool(flds)

    severity = next((flds[k] for k in SEVERITY_KEYS if flds.get(k)), "")
    name = next((flds[k] for k in NAME_KEYS if flds.get(k)), "")
    if not name:
        name = trunc(LEADING_TS_RE.sub("", stripped).strip(" :-|"), 60)

    # IPs from known fields first (so we know which one is the source),
    # then any other IP that appears anywhere in the line.
    refs: List[IPRef] = []
    seen: Set[str] = set()

    def add(ip: str, role: str) -> None:
        if ip not in seen:
            seen.add(ip)
            refs.append(IPRef(ip, role, is_public_ip(ip)))

    ordered = sorted(flds.items(), key=lambda kv: 0 if kv[0] in SRC_KEYS else 1 if kv[0] in DST_KEYS else 2)
    for k, v in ordered:
        for ip in find_ips(v):
            add(ip, "src" if k in SRC_KEYS else "dst" if k in DST_KEYS else k)
    for ip in find_ips(raw):
        add(ip, "other")

    return LogEvent(line_no, raw, ts, severity.upper(), name, flds, refs, known)


def detect_encoding(path: str) -> str:
    with open(path, "rb") as fh:
        head = fh.read(4)
    if head.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    if head.startswith(b"\xff\xfe") or head.startswith(b"\xfe\xff"):
        return "utf-16"
    return "utf-8"


def read_events(path: str, pattern: Optional[Pattern[str]] = None) -> Tuple[List[LogEvent], int]:
    """Parse a whole file. Returns (events, number_of_non_comment_lines)."""
    events: List[LogEvent] = []
    lines = 0
    with open(path, "r", encoding=detect_encoding(path), errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            ev = parse_line(line, n, pattern)
            if ev is not None:
                lines += 1
                events.append(ev)
    return events, lines


def tail_lines(path: str, from_start: bool = False, poll: float = 0.5,
               stop_event: Optional[threading.Event] = None) -> Iterator[Tuple[int, str]]:
    """Yield (line_no, line) as lines are appended to a file, like `tail -f`.

    Handles partial writes, truncation and log rotation (file replaced).
    """
    line_no = 0
    fh = open(path, "rb")
    try:
        if not from_start:
            for _ in fh:  # skip existing content but keep line numbers right
                line_no += 1
        inode = os.fstat(fh.fileno()).st_ino
        buf = b""
        while not (stop_event is not None and stop_event.is_set()):
            chunk = fh.readline()
            if chunk:
                buf += chunk
                if buf.endswith(b"\n"):
                    line_no += 1
                    yield line_no, buf.decode("utf-8", "replace").rstrip("\r\n")
                    buf = b""
                continue
            try:
                st = os.stat(path)
            except OSError:  # being rotated; wait for the new file
                time.sleep(poll)
                continue
            if st.st_size < fh.tell() or (st.st_ino and inode and st.st_ino != inode):
                print(dim("  (log file was truncated or rotated - reading the new file from the top)"))
                fh.close()
                fh = open(path, "rb")
                inode = os.fstat(fh.fileno()).st_ino
                line_no, buf = 0, b""
                continue
            time.sleep(poll)
    finally:
        fh.close()


# =============================================================================
# Threat intelligence (VirusTotal)
# =============================================================================

@dataclass
class IPIntel:
    ip: str
    verdict: str                       # MALICIOUS | SUSPICIOUS | CLEAN | UNKNOWN | INTERNAL | ERROR
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    total: int = 0
    reputation: Optional[int] = None
    country: str = ""
    as_owner: str = ""
    asn: Optional[int] = None
    network: str = ""
    tags: List[str] = field(default_factory=list)
    flagged_by: List[str] = field(default_factory=list)
    last_analysis: str = ""
    source: str = "live"               # live | cache | mock | n/a
    error: str = ""

    @property
    def detections(self) -> str:
        return "{}/{}".format(self.malicious, self.total) if self.total else "-"

    @property
    def link(self) -> str:
        return VT_GUI_URL + self.ip

    def rescore(self, threshold: int) -> "IPIntel":
        if self.total > 0:
            self.verdict = score_verdict(
                {"malicious": self.malicious, "suspicious": self.suspicious,
                 "harmless": self.harmless, "undetected": self.undetected}, threshold)
        return self

    def to_dict(self) -> dict:
        d = asdict(self)
        d["detections"] = self.detections
        d["vt_link"] = self.link
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "IPIntel":
        known = {f.name for f in dc_fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in known})


def score_verdict(stats: Dict[str, int], threshold: int = 3) -> str:
    """Verdict policy. `threshold` = engines that must say malicious for MALICIOUS.

    MALICIOUS  : >= threshold engines flag it malicious
    SUSPICIOUS : 1+ engine says malicious, or 2+ say suspicious
    CLEAN      : analysed, nothing flagged it
    UNKNOWN    : no analysis data
    """
    mal = int(stats.get("malicious", 0) or 0)
    sus = int(stats.get("suspicious", 0) or 0)
    if mal >= threshold:
        return "MALICIOUS"
    if mal >= 1 or sus >= 2:
        return "SUSPICIOUS"
    if sum(int(v or 0) for v in stats.values()) == 0:
        return "UNKNOWN"
    return "CLEAN"


def parse_vt_ip(ip: str, body: dict, threshold: int) -> IPIntel:
    attrs = (body.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    results = attrs.get("last_analysis_results") or {}
    flagged = sorted(
        "{}: {}".format(engine, (r or {}).get("result") or "malicious")
        for engine, r in results.items() if (r or {}).get("category") == "malicious"
    )
    last = attrs.get("last_analysis_date")
    total = sum(int(v or 0) for v in stats.values())
    return IPIntel(
        ip=ip,
        verdict=score_verdict(stats, threshold),
        malicious=int(stats.get("malicious", 0) or 0),
        suspicious=int(stats.get("suspicious", 0) or 0),
        harmless=int(stats.get("harmless", 0) or 0),
        undetected=int(stats.get("undetected", 0) or 0),
        total=total,
        reputation=attrs.get("reputation"),
        country=attrs.get("country") or "",
        as_owner=attrs.get("as_owner") or "",
        asn=attrs.get("asn"),
        network=attrs.get("network") or "",
        tags=list(attrs.get("tags") or [])[:8],
        flagged_by=flagged[:8],
        last_analysis=(datetime.fromtimestamp(last, tz=timezone.utc).strftime("%Y-%m-%d")
                       if isinstance(last, (int, float)) and last > 0 else ""),
        source="live",
    )


# Deterministic fake intel for --mock mode, so the whole workflow can be
# demonstrated without an API key. Clearly labelled "mock" everywhere it appears.
MOCK_PROFILES: Dict[str, Tuple[int, int, str, str, List[str]]] = {
    # ip: (malicious engines, suspicious engines, country, AS owner, tags)
    "185.220.101.4": (17, 2, "DE", "Tor exit relay network", ["tor", "brute-force"]),
    "45.155.205.233": (12, 1, "RU", "Bulletproof hosting LLC", ["brute-force", "scanner"]),
    "193.32.162.70": (9, 0, "NL", "VPS provider", ["ssh", "brute-force"]),
    "141.98.10.60": (14, 1, "LT", "Hosting provider", ["rdp", "brute-force"]),
    "89.248.165.52": (6, 2, "NL", "Scanning service", ["scanner"]),
    "194.26.29.113": (11, 0, "RU", "Hosting provider", ["ssh"]),
    "91.92.240.17": (21, 3, "BG", "Bulletproof hosting LLC", ["c2", "malware"]),
    "5.188.86.172": (8, 1, "RU", "Cloud provider", ["c2"]),
    "77.247.181.162": (15, 0, "NL", "Tor exit relay network", ["tor"]),
    "162.142.125.10": (1, 1, "US", "Internet census scanner", ["scanner", "research"]),
    "71.6.199.23": (2, 1, "US", "Internet census scanner", ["scanner", "research"]),
    "80.94.95.115": (0, 0, "RO", "Hosting provider", []),
    "8.8.8.8": (0, 0, "US", "GOOGLE", ["dns"]),
    "8.8.4.4": (0, 0, "US", "GOOGLE", ["dns"]),
    "1.1.1.1": (0, 0, "US", "CLOUDFLARENET", ["dns"]),
    "13.107.42.14": (0, 0, "US", "MICROSOFT-CORP", []),
    "140.82.112.3": (0, 0, "US", "GITHUB", []),
}
MOCK_ENGINES = ["Fortinet", "Kaspersky", "ESET", "Sophos", "BitDefender", "CRDF", "Webroot",
                "AlienVault", "abusix", "CyRadar", "Lionic", "G-Data", "SOCRadar", "Criminal IP"]
MOCK_RESULTS = ["malicious", "malware", "phishing", "suspicious", "spam"]


def mock_intel(ip: str, threshold: int) -> IPIntel:
    h = int(hashlib.sha256(ip.encode()).hexdigest(), 16)
    total = 94
    if ip in MOCK_PROFILES:
        mal, sus, country, owner, tags = MOCK_PROFILES[ip]
        if ip == "80.94.95.115":  # demo an IP VirusTotal has no analysis for
            total = 0
    else:
        bucket = h % 100
        mal = 4 + h % 14 if bucket < 35 else (1 + h % 2 if bucket < 55 else 0)
        sus = h % 3 if bucket < 55 else 0
        country, owner = [("US", "Cloud provider"), ("RU", "Hosting provider"), ("CN", "ISP backbone"),
                          ("BR", "Telecom ISP"), ("NL", "VPS provider"), ("DE", "Hosting provider")][h % 6]
        tags = []
        if bucket >= 92:
            total = 0
    if total == 0:
        return IPIntel(ip, "UNKNOWN", country=country, as_owner=owner, source="mock",
                       error="No analysis data (simulated)")
    engines = sorted(MOCK_ENGINES, key=lambda e: hashlib.md5((ip + e).encode()).hexdigest())
    flagged = ["{}: {}".format(e, MOCK_RESULTS[(h >> i) % len(MOCK_RESULTS)])
               for i, e in enumerate(engines[:min(mal, 8)])]
    harmless = int((total - mal - sus) * 0.66)
    return IPIntel(
        ip=ip, verdict="", malicious=mal, suspicious=sus, harmless=harmless,
        undetected=total - mal - sus - harmless, total=total,
        reputation=-(mal * 3) if mal else 5 + h % 20, country=country, as_owner=owner,
        tags=list(tags), flagged_by=flagged, last_analysis=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        source="mock",
    ).rescore(threshold)


class VTError(Exception):
    pass


class VTAuthError(VTError):
    pass


class VTQuotaError(VTError):
    pass


class VTNetworkError(VTError):
    pass


class RateLimiter:
    """Sliding window: at most `per_minute` calls in any 60 seconds."""

    def __init__(self, per_minute: int, clock: Callable[[], float] = time.monotonic,
                 sleeper: Callable[[float], None] = time.sleep) -> None:
        self.per_minute = per_minute
        self._clock = clock
        self._sleep = sleeper
        self._calls: List[float] = []
        self._lock = threading.Lock()

    def seconds_until_free(self) -> float:
        now = self._clock()
        self._calls = [t for t in self._calls if now - t < 60]
        if self.per_minute <= 0 or len(self._calls) < self.per_minute:
            return 0.0
        return 60 - (now - self._calls[0]) + 0.25

    def wait(self) -> None:
        if self.per_minute <= 0:
            return
        with self._lock:
            delay = self.seconds_until_free()
            if delay > 0:
                self._sleep(delay)
                self.seconds_until_free()
            self._calls.append(self._clock())

    def refund(self) -> None:
        """Give back the last slot (the request never reached the server)."""
        with self._lock:
            if self._calls:
                self._calls.pop()


def _paced_sleep(seconds: float) -> None:
    """Sleep with a visible countdown so a paused script doesn't look frozen."""
    end = time.monotonic() + seconds
    interactive = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
    if not interactive:
        print(dim("      (free API limit reached - waiting {:.0f}s)".format(seconds)))
        time.sleep(seconds)
        return
    while True:
        left = end - time.monotonic()
        if left <= 0:
            break
        sys.stdout.write("\r" + dim("      free API limit (4/min): next lookup in {:>3.0f}s ".format(left)))
        sys.stdout.flush()
        time.sleep(min(1.0, left))
    sys.stdout.write("\r" + " " * 60 + "\r")
    sys.stdout.flush()


CERT_HELP = ("TLS certificate verification failed when contacting VirusTotal.\n"
             "  - macOS (python.org installer): run 'Install Certificates.command' in your Python folder\n"
             "  - or run: pip install certifi   (the script uses it automatically if present)\n"
             "  - behind a corporate proxy: set SSL_CERT_FILE to your company's CA bundle")


class Enricher:
    """Looks up IPs on VirusTotal with pacing, retries, caching and mock mode."""

    NETWORK_PAUSE_S = 120

    def __init__(self, cfg: "Config", opener: Optional[Callable] = None,
                 sleeper: Callable[[float], None] = _paced_sleep,
                 backoff_sleeper: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.cfg = cfg
        self._opener = opener or urllib.request.urlopen
        self._sleep = backoff_sleeper
        self._clock = clock
        self.limiter = RateLimiter(cfg.rate_per_min, clock=clock, sleeper=sleeper)
        self.memory: Dict[str, IPIntel] = {}
        self.api_calls = 0
        self.cache_hits = 0
        self.disabled_reason = ""
        self._pause_until = 0.0
        self._pause_reason = ""
        self._ssl = ssl.create_default_context()
        self._tried_certifi = False
        self._cache: Dict[str, dict] = self._load_cache()
        self._lock = threading.Lock()

    # ---- cache -------------------------------------------------------------
    def _load_cache(self) -> Dict[str, dict]:
        try:
            with open(self.cfg.cache_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save_cache(self) -> None:
        try:
            os.makedirs(self.cfg.out_dir, exist_ok=True)
            tmp = self.cfg.cache_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self._cache, fh, indent=1)
            os.replace(tmp, self.cfg.cache_path)
        except OSError as exc:
            print(yellow("  warning: could not write cache: {}".format(exc)))

    def _cached(self, ip: str) -> Optional[IPIntel]:
        entry = self._cache.get(ip)
        if not entry or time.time() - float(entry.get("fetched", 0)) > self.cfg.cache_ttl_hours * 3600:
            return None
        intel = IPIntel.from_dict(entry.get("intel", {}))
        intel.source = "cache"
        return intel.rescore(self.cfg.threshold)

    def needs_api_call(self, ip: str) -> bool:
        return (is_public_ip(ip) and not self.cfg.mock and ip not in self.memory
                and self._cached(ip) is None)

    def clear_cache(self) -> None:
        self._cache = {}
        self.memory = {}
        self._save_cache()

    def reset_auth(self) -> None:
        self.disabled_reason = ""
        self._pause_until = 0.0

    # ---- lookup ------------------------------------------------------------
    def lookup(self, ip: str) -> IPIntel:
        try:
            ip = normalize_ip(ip)
        except ValueError:
            return IPIntel(ip, "ERROR", source="n/a", error="Not a valid IP address")
        if not is_public_ip(ip):
            return IPIntel(ip, "INTERNAL", source="n/a", error="Private/reserved address - not sent to VirusTotal")
        with self._lock:
            if ip in self.memory:
                return self.memory[ip].rescore(self.cfg.threshold)
            if self.cfg.mock:
                intel = mock_intel(ip, self.cfg.threshold)
                self.memory[ip] = intel
                return intel
            cached = self._cached(ip)
            if cached is not None:
                self.cache_hits += 1
                self.memory[ip] = cached
                return cached
            if not self.cfg.api_key:
                return IPIntel(ip, "UNKNOWN", source="n/a", error="No VirusTotal API key configured")
            if self.disabled_reason:
                return IPIntel(ip, "ERROR", source="n/a", error=self.disabled_reason)
            left = self._pause_until - self._clock()
            if left > 0:
                return IPIntel(ip, "ERROR", source="n/a", error="Lookups paused {:.0f}s more after a "
                               "connection failure: {}".format(left, self._pause_reason))
            try:
                status, body = self._fetch(ip)
            except (VTAuthError, VTQuotaError) as exc:
                self.disabled_reason = str(exc)
                print(red("\n  VirusTotal lookups stopped: {}".format(exc)))
                return IPIntel(ip, "ERROR", source="n/a", error=str(exc))
            except VTNetworkError as exc:
                # Don't hammer an unreachable service once per IP; try again later.
                self._pause_until = self._clock() + self.NETWORK_PAUSE_S
                self._pause_reason = str(exc)
                print(red("\n  Cannot reach VirusTotal ({}). Pausing lookups for {}s.".format(
                    exc, self.NETWORK_PAUSE_S)))
                return IPIntel(ip, "ERROR", source="n/a", error=str(exc))
            except VTError as exc:
                return IPIntel(ip, "ERROR", source="n/a", error=str(exc))
            if status == 404 or not body:
                intel = IPIntel(ip, "UNKNOWN", source="live", error="Not in VirusTotal dataset")
            else:
                intel = parse_vt_ip(ip, body, self.cfg.threshold)
            self.memory[ip] = intel
            self._cache[ip] = {"fetched": time.time(), "intel": intel.to_dict()}
            self._save_cache()
            return intel

    def _fetch(self, ip: str) -> Tuple[int, Optional[dict]]:
        req = urllib.request.Request(
            VT_API_URL + ip,
            headers={"x-apikey": self.cfg.api_key, "accept": "application/json",
                     "User-Agent": "siem-enricher/" + VERSION},
        )
        max_retries = 3
        attempt = 0
        while True:
            self.limiter.wait()
            self.api_calls += 1
            try:
                with self._opener(req, timeout=20, context=self._ssl) as resp:
                    return 200, json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                code = exc.code
                try:
                    err = json.loads(exc.read().decode("utf-8")).get("error", {})
                except Exception:
                    err = {}
                if code == 404:
                    return 404, None
                if code in (401, 403):
                    raise VTAuthError("VirusTotal rejected the API key (HTTP {}: {}). "
                                      "Check it in Settings.".format(code, err.get("code", "auth error")))
                if code == 429:
                    if attempt >= max_retries:
                        raise VTQuotaError("VirusTotal quota exceeded ({}). The free API allows "
                                           "a limited number of lookups per day.".format(err.get("code", "429")))
                    print(yellow("\n      VirusTotal says too many requests - waiting 60s before retrying"))
                    self._sleep(60)
                elif code >= 500 and attempt < max_retries:
                    self._sleep(2 ** attempt)
                else:
                    raise VTError("HTTP {} from VirusTotal: {}".format(code, err.get("message", exc.reason)))
            except urllib.error.URLError as exc:
                # The request never reached VirusTotal, so it doesn't count against the quota.
                self.limiter.refund()
                self.api_calls -= 1
                if isinstance(exc.reason, ssl.SSLCertVerificationError):
                    if not self._tried_certifi:
                        self._tried_certifi = True
                        try:
                            import certifi  # type: ignore
                            self._ssl = ssl.create_default_context(cafile=certifi.where())
                            continue
                        except ImportError:
                            pass
                    raise VTNetworkError(CERT_HELP)
                if attempt >= max_retries:
                    raise VTNetworkError("network error: {}".format(exc.reason))
                self._sleep(2 ** attempt)
            except ValueError as exc:  # VirusTotal answered with something that isn't JSON
                if attempt >= max_retries:
                    raise VTError("Unreadable response from VirusTotal: {}".format(exc))
                self._sleep(2 ** attempt)
            except OSError as exc:  # timeouts, connection resets
                self.limiter.refund()
                self.api_calls -= 1
                if attempt >= max_retries:
                    raise VTNetworkError("connection problem: {}".format(exc))
                self._sleep(2 ** attempt)
            attempt += 1


# =============================================================================
# Simulated firewall
# =============================================================================

class Firewall:
    """Text-file stand-in for a firewall. The blocklist is one IP per line,
    the same shape as an External Dynamic List a real firewall can consume."""

    BLOCK_HEADER = ("# SIMULATED FIREWALL BLOCKLIST - one IP per line (External Dynamic List style)\n"
                    "# Managed by siem_enricher.py. Every change is logged in containment_audit.csv.\n")
    ALLOW_HEADER = ("# FIREWALL ALLOWLIST - IPs or CIDR ranges that must NEVER be blocked.\n"
                    "# Protects critical services from a bad containment decision.\n"
                    "# Add your own public IP, DNS resolvers, partners, etc. One per line.\n"
                    "8.8.8.8\n8.8.4.4\n1.1.1.1\n1.0.0.1\n")
    AUDIT_COLS = ["timestamp_utc", "action", "ip", "verdict", "detections", "country", "as_owner",
                  "reason", "analyst", "intel_source", "log_file"]

    def __init__(self, cfg: "Config") -> None:
        self.cfg = cfg
        self._lock = threading.Lock()
        os.makedirs(cfg.out_dir, exist_ok=True)
        if not os.path.exists(cfg.blocklist_path):
            with open(cfg.blocklist_path, "w", encoding="utf-8") as fh:
                fh.write(self.BLOCK_HEADER)
        if not os.path.exists(cfg.allowlist_path):
            with open(cfg.allowlist_path, "w", encoding="utf-8") as fh:
                fh.write(self.ALLOW_HEADER)

    @staticmethod
    def _entries(path: str) -> List[str]:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                out = []
                for line in fh:
                    entry = line.split("#", 1)[0].strip()
                    if entry:
                        out.append(entry)
                return out
        except OSError:
            return []

    def blocked(self) -> List[str]:
        out = []
        for e in self._entries(self.cfg.blocklist_path):
            try:
                ip = normalize_ip(e)
            except ValueError:
                continue
            if ip not in out:
                out.append(ip)
        return out

    def is_blocked(self, ip: str) -> bool:
        try:
            return normalize_ip(ip) in self.blocked()
        except ValueError:
            return False

    def allowlisted(self, ip: str) -> Optional[str]:
        """Return the allowlist entry covering this IP, if any."""
        try:
            addr = ipaddress.ip_address(normalize_ip(ip))
        except ValueError:
            return None
        for entry in self._entries(self.cfg.allowlist_path):
            try:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return entry
            except ValueError:
                continue
        return None

    def contain(self, ip: str, intel: Optional[IPIntel] = None, reason: str = "",
                analyst: Optional[str] = None, force: bool = False, log_file: str = "") -> Tuple[bool, str]:
        """Write an IP to the firewall blocklist. Returns (success, message)."""
        try:
            ip = normalize_ip(ip)
        except ValueError:
            return False, "'{}' is not a valid IP address".format(ip)
        with self._lock:
            if ip in self.blocked():
                return False, "{} is already contained".format(ip)
            allowed = self.allowlisted(ip)
            if allowed:
                return False, ("{} is on the allowlist (entry '{}'), so it will not be blocked. "
                               "Edit {} if this is wrong.".format(ip, allowed, self.cfg.allowlist_path))
            if not is_public_ip(ip) and not (force or self.cfg.allow_private):
                return False, ("{} is a private/internal address. Blocking it on the perimeter firewall "
                               "would not stop external traffic and may break internal services. "
                               "Use force (or --allow-private) to block it anyway.".format(ip))
            self._append_line(self.cfg.blocklist_path, ip)
            self._audit("CONTAIN", ip, intel, reason, analyst, log_file)
        return True, "{} written to firewall blocklist".format(ip)

    def release(self, ip: str, reason: str = "", analyst: Optional[str] = None) -> Tuple[bool, str]:
        """Remove an IP from the firewall blocklist."""
        try:
            ip = normalize_ip(ip)
        except ValueError:
            return False, "'{}' is not a valid IP address".format(ip)
        with self._lock:
            if ip not in self.blocked():
                return False, "{} is not on the blocklist".format(ip)
            with open(self.cfg.blocklist_path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
            keep = []
            for line in lines:
                entry = line.split("#", 1)[0].strip()
                try:
                    if entry and normalize_ip(entry) == ip:
                        continue
                except ValueError:
                    pass
                keep.append(line)
            tmp = self.cfg.blocklist_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.writelines(keep)
            os.replace(tmp, self.cfg.blocklist_path)
            self._audit("RELEASE", ip, None, reason, analyst, "")
        return True, "{} removed from firewall blocklist".format(ip)

    @staticmethod
    def _append_line(path: str, text: str) -> None:
        needs_newline = False
        if os.path.exists(path) and os.path.getsize(path) > 0:
            with open(path, "rb") as fh:
                fh.seek(-1, os.SEEK_END)
                needs_newline = fh.read(1) != b"\n"
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(("\n" if needs_newline else "") + text + "\n")

    def _audit(self, action: str, ip: str, intel: Optional[IPIntel], reason: str,
               analyst: Optional[str], log_file: str) -> None:
        new = not os.path.exists(self.cfg.audit_path)
        with open(self.cfg.audit_path, "a", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            if new:
                w.writerow(self.AUDIT_COLS)
            w.writerow([utc_now(), action, ip,
                        intel.verdict if intel else "", intel.detections if intel else "",
                        intel.country if intel else "", intel.as_owner if intel else "",
                        reason, analyst or current_user(), intel.source if intel else "", log_file])

    def audit_rows(self) -> List[Dict[str, str]]:
        try:
            with open(self.cfg.audit_path, "r", newline="", encoding="utf-8") as fh:
                return list(csv.DictReader(fh))
        except OSError:
            return []


# =============================================================================
# Sample SIEM feed generator
# =============================================================================

SAMPLE_ATTACKERS = ["185.220.101.4", "45.155.205.233", "193.32.162.70", "141.98.10.60",
                    "194.26.29.113", "80.94.95.115"]
SAMPLE_SCANNERS = ["162.142.125.10", "71.6.199.23", "89.248.165.52"]
SAMPLE_C2 = ["91.92.240.17", "5.188.86.172"]
SAMPLE_BENIGN = ["8.8.8.8", "1.1.1.1", "13.107.42.14", "140.82.112.3"]
SAMPLE_INTERNAL = ["10.0.20.15", "10.0.20.21", "10.0.30.5", "10.0.40.10", "192.168.1.50", "172.16.4.12"]
SAMPLE_USERS = ["root", "admin", "administrator", "jsmith", "svc_backup", "test"]


def _fmt(ts: datetime, sev: str, device: str, event: str, src: str, dst: str, port: int,
         action: str, msg: str) -> str:
    return "{} | sev={} | device={} | event={} | src_ip={} | dst_ip={} | dst_port={} | action={} | msg={}".format(
        ts.strftime("%Y-%m-%dT%H:%M:%SZ"), sev, device, event, src, dst, port, action, msg)


def sample_event_line(rng: random.Random, ts: datetime) -> str:
    """One realistic random SIEM event in the expected format."""
    kind = rng.choices(
        ["ssh", "rdp", "scan", "web", "c2", "dns", "vpn", "internal", "noip"],
        weights=[22, 10, 14, 12, 7, 12, 8, 9, 6])[0]
    i = rng.choice(SAMPLE_INTERNAL)
    if kind == "ssh":
        return _fmt(ts, "HIGH", "fw-edge-01", "SSH brute force", rng.choice(SAMPLE_ATTACKERS), i, 22,
                    rng.choice(["allowed", "allowed", "dropped"]),
                    "{} failed logins for {}".format(rng.randint(8, 60), rng.choice(SAMPLE_USERS)))
    if kind == "rdp":
        return _fmt(ts, "HIGH", "fw-edge-01", "RDP brute force", rng.choice(SAMPLE_ATTACKERS[:4]), i, 3389,
                    "allowed", "{} failed NTLM logons".format(rng.randint(10, 90)))
    if kind == "scan":
        return _fmt(ts, "MEDIUM", "ids-01", "Port scan", rng.choice(SAMPLE_SCANNERS + SAMPLE_ATTACKERS[:2]), i,
                    0, "dropped", "SYN scan of {} ports".format(rng.randint(50, 2000)))
    if kind == "web":
        name, payload = rng.choice([("SQL injection attempt", "GET /login.php?id=1' OR '1'='1"),
                                    ("Path traversal attempt", "GET /static/../../etc/passwd"),
                                    ("XSS attempt", "GET /search?q=<script>alert(1)</script>")])
        return _fmt(ts, "HIGH", "waf-01", name, rng.choice(SAMPLE_ATTACKERS[:3] + ["77.247.181.162"]),
                    "10.0.40.10", 443, "blocked", payload)
    if kind == "c2":
        return _fmt(ts, "CRITICAL", "edr-ws-07", "Possible C2 beacon", i, rng.choice(SAMPLE_C2),
                    rng.choice([443, 8443, 4444]), "allowed", "Periodic beacon every 60s (jitter 10%)")
    if kind == "dns":
        return _fmt(ts, "INFO", "dns-01", "DNS query", i, rng.choice(SAMPLE_BENIGN[:2]), 53, "allowed",
                    "A record lookup")
    if kind == "vpn":
        return _fmt(ts, "LOW", "vpn-gw-01", "VPN login success",
                    rng.choice(SAMPLE_BENIGN[2:] + ["194.26.29.113"]), "10.0.0.1", 443, "allowed",
                    "user {} authenticated with MFA".format(rng.choice(SAMPLE_USERS[3:])))
    if kind == "internal":
        a, b = rng.sample(SAMPLE_INTERNAL, 2)
        return _fmt(ts, "LOW", "fw-core-01", "Internal SMB connection", a, b, 445, "allowed", "file share access")
    return "{} | sev=INFO | device=av-01 | event=Scheduled AV scan completed | msg=0 threats found".format(
        ts.strftime("%Y-%m-%dT%H:%M:%SZ"))


def make_sample_log(path: str, events: int = 40, seed: Optional[int] = 7) -> str:
    rng = random.Random(seed)
    start = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(hours=1)
    stamps = sorted(start + timedelta(seconds=rng.randint(0, 3500)) for _ in range(events))
    lines = [
        "# Simulated SIEM feed generated by siem_enricher.py on {}".format(utc_now()),
        "# Format: timestamp | sev=.. | device=.. | event=.. | src_ip=.. | dst_ip=.. | dst_port=.. | action=.. | msg=..",
    ]
    lines += [sample_event_line(rng, ts) for ts in stamps]
    # Off-format lines: the parser still extracts their IPs.
    lines.insert(12, "{} web01 sshd[2211]: Failed password for invalid user admin from 194.26.29.113 port 51122 ssh2"
                 .format(stamps[10].strftime("%b %d %H:%M:%S")))
    lines.insert(25, "<<< truncated syslog record >>> conn reset by peer 77.247.181.162:51515")
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return os.path.abspath(path)


class FeedSimulator(threading.Thread):
    """Background thread that appends random SIEM events to a log file, so live
    (follow) mode can be demonstrated without a real SIEM."""

    def __init__(self, path: str, min_s: float = 2.0, max_s: float = 5.0, seed: Optional[int] = None) -> None:
        super().__init__(daemon=True)
        self.path = path
        self.min_s, self.max_s = min_s, max_s
        self.rng = random.Random(seed)
        self._halt = threading.Event()

    def run(self) -> None:
        while not self._halt.wait(self.rng.uniform(self.min_s, self.max_s)):
            line = sample_event_line(self.rng, datetime.now(timezone.utc))
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    def halt(self) -> None:
        self._halt.set()


# =============================================================================
# Configuration
# =============================================================================

def _dotenv_save_path() -> str:
    """Where a pasted API key is saved. SIEM_DOTENV overrides it (Docker points it at the mounted folder)."""
    return os.getenv("SIEM_DOTENV") or os.path.join(SCRIPT_DIR, ".env")


def _env_files() -> List[str]:
    return [_dotenv_save_path(), os.path.join(os.getcwd(), ".env"), os.path.join(SCRIPT_DIR, ".env")]


def load_key_from_dotenv() -> str:
    for path in _env_files():
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line.startswith("export "):
                        line = line[7:]
                    if line.startswith("VT_API_KEY="):
                        return line.split("=", 1)[1].strip().strip("'\"")
        except OSError:
            continue
    return ""


def save_key_to_dotenv(key: str) -> str:
    path = _dotenv_save_path()
    lines: List[str] = []
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            lines = [l for l in fh.read().splitlines() if not l.strip().startswith(("VT_API_KEY=", "export VT_API_KEY="))]
    lines.append("VT_API_KEY=" + key)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def default_out_dir() -> str:
    d = os.getenv("SIEM_OUT_DIR") or os.path.join(SCRIPT_DIR, "siem_output")
    try:
        os.makedirs(d, exist_ok=True)
        probe = os.path.join(d, ".write_test")
        with open(probe, "w") as fh:
            fh.write("")
        os.remove(probe)
        return d
    except OSError:
        return os.path.join(os.getcwd(), "siem_output")


@dataclass
class Config:
    api_key: str = ""
    mock: bool = False
    threshold: int = 3
    rate_per_min: int = 4
    out_dir: str = ""
    cache_ttl_hours: float = 24.0
    auto_contain: str = ""          # "" (off) | "malicious" | "suspicious"
    prompt: bool = True
    allow_private: bool = False

    def __post_init__(self) -> None:
        if not self.out_dir:
            self.out_dir = default_out_dir()
        self.out_dir = os.path.abspath(os.path.expanduser(self.out_dir))

    def _p(self, name: str) -> str:
        return os.path.join(self.out_dir, name)

    @property
    def blocklist_path(self) -> str: return self._p("firewall_blocklist.txt")
    @property
    def allowlist_path(self) -> str: return self._p("firewall_allowlist.txt")
    @property
    def audit_path(self) -> str: return self._p("containment_audit.csv")
    @property
    def enriched_path(self) -> str: return self._p("enriched_events.jsonl")
    @property
    def cache_path(self) -> str: return self._p("vt_cache.json")

    @property
    def mode_label(self) -> str:
        if self.mock:
            return yellow("MOCK (simulated intel - nothing sent to VirusTotal)")
        if self.api_key:
            return green("LIVE VirusTotal") + dim(" (key ...{})".format(self.api_key[-4:]))
        return red("NO API KEY")


# =============================================================================
# The application
# =============================================================================

@dataclass
class IPSummary:
    ip: str
    public: bool
    hits: int = 0
    roles: Set[str] = field(default_factory=set)
    events: Dict[str, int] = field(default_factory=dict)
    max_sev: str = ""
    lines: List[int] = field(default_factory=list)

    def add(self, ev: LogEvent) -> None:
        self.hits += 1
        self.roles.add(ev.role_of(self.ip))
        self.events[ev.name] = self.events.get(ev.name, 0) + 1
        if severity_rank(ev.severity) > severity_rank(self.max_sev):
            self.max_sev = ev.severity
        self.lines.append(ev.line_no)

    def top_events(self, n: int = 3) -> str:
        top = sorted(self.events.items(), key=lambda kv: -kv[1])[:n]
        return ", ".join("{} ({})".format(name, c) for name, c in top)


class App:
    def __init__(self, cfg: Config, enricher: Optional[Enricher] = None) -> None:
        self.cfg = cfg
        self.enricher = enricher or Enricher(cfg)
        self.fw = Firewall(cfg)
        self.analyst = current_user()
        self.contained_this_session: List[str] = []
        self.last_log: Optional[str] = None
        self.pattern: Optional[Pattern[str]] = None
        self._live_prompt = cfg.prompt
        self._live_seen: Dict[str, str] = {}

    # ---- display helpers ---------------------------------------------------
    def intel_card(self, intel: IPIntel, summary: Optional[IPSummary] = None, prefix: str = "") -> None:
        loc = " / ".join(x for x in (intel.country, trunc(intel.as_owner, 40)) if x)
        print("{}{}  {}  {}  {}".format(
            prefix, bold(intel.ip), fmt_verdict(intel.verdict, 10),
            (intel.detections + " engines") if intel.total else dim("no detection data"),
            dim(loc)))
        pad = " " * (len(prefix) + 2)
        if summary is not None:
            print("{}Seen {}x as {} | {} | max severity {} | lines {}".format(
                pad, summary.hits, "/".join(sorted(r for r in summary.roles if r)) or "?",
                summary.top_events(), summary.max_sev or "-",
                ", ".join(str(n) for n in summary.lines[:8]) + (" ..." if len(summary.lines) > 8 else "")))
        if intel.flagged_by:
            print("{}Flagged by: {}".format(pad, ", ".join(intel.flagged_by[:5])))
        extras = []
        if intel.tags:
            extras.append("Tags: " + ", ".join(intel.tags))
        if intel.reputation is not None:
            extras.append("Reputation: {}".format(intel.reputation))
        if intel.network:
            extras.append("Network: " + intel.network)
        if intel.last_analysis:
            extras.append("Last analysed: " + intel.last_analysis)
        if extras:
            print(pad + dim(" | ".join(extras)))
        if intel.error:
            print(pad + magenta(intel.error))
        if intel.verdict not in ("INTERNAL",):
            print(pad + dim(intel.link + ("   [mock data]" if intel.source == "mock" else "")))

    def fw_status(self, ip: str, blocked: Set[str]) -> str:
        if ip in blocked:
            return red("BLOCKED")
        if self.fw.allowlisted(ip):
            return green("ALLOWLIST")
        return ""

    # ---- containment -------------------------------------------------------
    def contain(self, ip: str, intel: Optional[IPIntel], reason: str, log_file: str = "",
                force: bool = False, quiet: bool = False) -> bool:
        ok, msg = self.fw.contain(ip, intel, reason, self.analyst, force=force, log_file=log_file)
        if ok:
            self.contained_this_session.append(normalize_ip(ip))
            if not quiet:
                print("  " + red(bold("CONTAINED")) + " " + msg)
        elif not quiet:
            print("  " + yellow("Not contained: ") + msg)
        return ok

    def contain_with_override(self, ip: str, intel: Optional[IPIntel], reason: str, log_file: str = "") -> bool:
        """Contain; if refused only because the IP is internal, offer to force it."""
        ok, msg = self.fw.contain(ip, intel, reason, self.analyst, log_file=log_file)
        if ok:
            self.contained_this_session.append(normalize_ip(ip))
            print("  " + red(bold("CONTAINED")) + " " + msg)
            return True
        print("  " + yellow("Not contained: ") + msg)
        if "private/internal" in msg and ask_yes_no("  Block this internal address anyway?"):
            return self.contain(ip, intel, reason + " [forced: internal]", log_file, force=True)
        return False

    @staticmethod
    def default_reason(intel: IPIntel, summary: Optional[IPSummary]) -> str:
        r = "{} on VirusTotal ({})".format(intel.verdict, intel.detections)
        if summary is not None and summary.events:
            name, count = max(summary.events.items(), key=lambda kv: kv[1])
            r += "; {} x{}".format(name, count)
        return r

    # ---- batch analysis ----------------------------------------------------
    def analyze_file(self, path: str) -> dict:
        path = os.path.abspath(os.path.expanduser(path))
        self.last_log = path
        rule("1. PARSE  " + path)
        try:
            events, lines = read_events(path, self.pattern)
        except OSError as exc:
            print(red("Cannot read log file: {}".format(exc)))
            return {}
        summaries: Dict[str, IPSummary] = {}
        no_ip = off_format = 0
        for ev in events:
            if not ev.ips:
                no_ip += 1
            if not ev.known_format:
                off_format += 1
            for ref in ev.ips:
                summaries.setdefault(ref.ip, IPSummary(ref.ip, ref.public)).add(ev)
        public = [s for s in summaries.values() if s.public]
        internal = [s for s in summaries.values() if not s.public]
        print("  {} events | {} unique external IPs | {} internal IPs (not sent to VirusTotal) | "
              "{} events without an IP".format(len(events), len(public), len(internal), no_ip))
        if off_format:
            print(dim("  {} line(s) were not in the expected format; IPs were still extracted from them.".format(off_format)))
        if not public:
            print(yellow("  No external IP addresses found - nothing to enrich."))

        # ---- enrich: most important IPs first, in case of Ctrl+C or quota limits
        rule("2. ENRICH  mode: " + self.cfg.mode_label)
        public.sort(key=lambda s: (-severity_rank(s.max_sev), -s.hits))
        need = [s.ip for s in public if self.enricher.needs_api_call(s.ip)]
        if need and self.cfg.api_key and self.cfg.rate_per_min > 0:
            minutes = max(0, math.ceil(len(need) / self.cfg.rate_per_min) - 1)
            print(dim("  {} new lookup(s), {} cached. Estimated time: ~{} min at {}/min. "
                      "Press Ctrl+C to skip the rest.".format(len(need), len(public) - len(need), minutes,
                                                            self.cfg.rate_per_min)))
        if need and not self.cfg.api_key and not self.cfg.mock:
            print(red("  No API key: IPs will be marked UNKNOWN. Add a key in Settings or use mock mode."))
        intel: Dict[str, IPIntel] = {}
        try:
            for n, s in enumerate(public, 1):
                info = self.enricher.lookup(s.ip)
                intel[s.ip] = info
                print("  [{:>{w}}/{}] {:<15} {} {:>7}  {}".format(
                    n, len(public), s.ip, fmt_verdict(info.verdict), info.detections,
                    dim(" / ".join(x for x in (info.country, trunc(info.as_owner, 30), info.source) if x)),
                    w=len(str(len(public)))))
        except KeyboardInterrupt:
            print(yellow("\n  Enrichment interrupted - remaining IPs are marked UNKNOWN."))
        for s in public:
            intel.setdefault(s.ip, IPIntel(s.ip, "UNKNOWN", source="n/a", error="Not looked up (skipped)"))
        for s in internal:
            intel[s.ip] = IPIntel(s.ip, "INTERNAL", source="n/a")

        self._write_enriched(events, intel, path)

        # ---- triage table
        rule("3. TRIAGE")
        blocked = set(self.fw.blocked())
        ordered = sorted(public, key=lambda s: (-VERDICT_RANK[intel[s.ip].verdict],
                                                -severity_rank(s.max_sev), -s.hits))
        if ordered:
            w = max(15, max(len(s.ip) for s in ordered))
            print(bold("  {:<10} {:>7}  {:<{w}} {:>4}  {:<8} {:<4} {:<22} {:<9}  {}".format(
                "VERDICT", "DETECT", "IP", "HITS", "MAX SEV", "CC", "OWNER", "FIREWALL", "TOP EVENTS", w=w)))
            for s in ordered:
                i = intel[s.ip]
                print("  {} {:>7}  {:<{w}} {:>4}  {:<8} {:<4} {:<22} {:<9}  {}".format(
                    fmt_verdict(i.verdict), i.detections, s.ip, s.hits, s.max_sev or "-",
                    i.country or "-", trunc(i.as_owner or "-", 22),
                    pad_ansi(self.fw_status(s.ip, blocked), 9),
                    trunc(s.top_events(2), 60), w=w))
        counts: Dict[str, int] = {}
        for s in public:
            counts[intel[s.ip].verdict] = counts.get(intel[s.ip].verdict, 0) + 1
        if counts:
            print("\n  " + "  ".join(fmt_verdict(v, 0) + ": {}".format(c) for v, c in
                                       sorted(counts.items(), key=lambda kv: -VERDICT_RANK[kv[0]])))

        # ---- containment
        self.containment_review(ordered, intel, summaries, path)
        return self._summary(public, intel, path)

    def _write_enriched(self, events: List[LogEvent], intel: Dict[str, IPIntel], log_path: str) -> None:
        os.makedirs(self.cfg.out_dir, exist_ok=True)
        blocked = set(self.fw.blocked())
        now = utc_now()
        with open(self.cfg.enriched_path, "a", encoding="utf-8") as fh:
            for ev in events:
                fh.write(json.dumps(self._event_record(ev, intel, blocked, log_path, now)) + "\n")
        print(dim("\n  Enriched events appended to " + self.cfg.enriched_path))

    def _event_record(self, ev: LogEvent, intel: Dict[str, IPIntel], blocked: Set[str],
                      log_path: str, now: str) -> dict:
        worst = max((intel[r.ip].verdict for r in ev.ips if r.ip in intel),
                    key=lambda v: VERDICT_RANK[v], default="")
        return {
            "enriched_at": now, "log_file": log_path, "line_no": ev.line_no, "timestamp": ev.timestamp,
            "severity": ev.severity, "event": ev.name, "fields": ev.fields,
            "ips": [{"ip": r.ip, "role": r.role, "public": r.public,
                     "firewall": "blocked" if r.ip in blocked else ""} for r in ev.ips],
            "overall_verdict": worst,
            "enrichment": {r.ip: intel[r.ip].to_dict() for r in ev.ips if r.public and r.ip in intel},
            "raw": ev.raw,
        }

    def containment_review(self, ordered: List[IPSummary], intel: Dict[str, IPIntel],
                           summaries: Dict[str, IPSummary], log_path: str) -> None:
        rule("4. CONTAIN")
        blocked = set(self.fw.blocked())
        candidates = [s for s in ordered if s.ip not in blocked and not self.fw.allowlisted(s.ip)]
        already = [s.ip for s in ordered if s.ip in blocked]
        if already:
            print(dim("  Already contained on the firewall: " + ", ".join(already)))

        if self.cfg.auto_contain:
            floor = VERDICT_RANK[self.cfg.auto_contain.upper()]
            for s in candidates:
                i = intel[s.ip]
                if i.verdict in ("MALICIOUS", "SUSPICIOUS") and VERDICT_RANK[i.verdict] >= floor:
                    self.contain(s.ip, i, "AUTO: " + self.default_reason(i, s), log_path)
            candidates = [s for s in candidates if s.ip not in self.contained_this_session]

        review = [s for s in candidates if intel[s.ip].verdict in REVIEW_VERDICTS]
        if not self.cfg.prompt:
            if review:
                print(yellow("  {} IP(s) need an analyst decision (prompts disabled): {}".format(
                    len(review), ", ".join(s.ip for s in review))))
            return
        if not review:
            print(green("  No uncontained MALICIOUS/SUSPICIOUS/UNKNOWN external IPs need a decision."))
        else:
            print("  {} IP(s) need a decision. Default is NO; nothing is blocked unless you confirm.\n".format(len(review)))
        auto_mal = False
        for n, s in enumerate(review, 1):
            i = intel[s.ip]
            if auto_mal and i.verdict == "MALICIOUS":
                self.contain(s.ip, i, self.default_reason(i, s) + " (bulk: all malicious)", log_path)
                continue
            self.intel_card(i, s, prefix="  [{}/{}] ".format(n, len(review)))
            while True:
                ans = ask("  Contain {}? [y]es [n]o [d]etails [a]ll malicious [q]uit review: ".format(s.ip))
                if ans is None or ans.lower().startswith("q"):
                    print(dim("  Review stopped."))
                    return self._offer_manual(intel, summaries, log_path, allow=ans is not None)
                a = ans.lower()
                if a.startswith("d"):
                    self.show_log_lines(s, log_path)
                    continue
                if a.startswith("a"):
                    auto_mal = True
                    if i.verdict == "MALICIOUS":
                        self.contain(s.ip, i, self.default_reason(i, s) + " (bulk: all malicious)", log_path)
                    else:
                        print(dim("  Will contain the remaining MALICIOUS IPs automatically. This one is {}."
                                  .format(i.verdict)))
                        continue
                    break
                if a.startswith("y"):
                    default = self.default_reason(i, s)
                    reason = ask("  Reason [{}]: ".format(default))
                    self.contain(s.ip, i, reason or default, log_path)
                    break
                print(dim("  Skipped."))
                break
            print()
        self._offer_manual(intel, summaries, log_path)

    def _offer_manual(self, intel: Dict[str, IPIntel], summaries: Dict[str, IPSummary],
                      log_path: str, allow: bool = True) -> None:
        if not allow:
            return
        while True:
            ans = ask("  Contain any other IP from this log (e.g. one marked CLEAN)? Enter IP, or press Enter to finish: ")
            if not ans:
                return
            if not is_valid_ip(ans):
                print(yellow("  '{}' is not a valid IP address.".format(ans)))
                continue
            ip = normalize_ip(ans)
            if ip not in summaries and not ask_yes_no("  {} does not appear in this log. Contain it anyway?".format(ip)):
                continue
            i = intel.get(ip) or self.enricher.lookup(ip)
            s = summaries.get(ip)
            self.intel_card(i, s, prefix="  ")
            reason = ask("  Reason [{}]: ".format(self.default_reason(i, s))) or self.default_reason(i, s)
            self.contain_with_override(ip, i, reason, log_path)

    def show_log_lines(self, s: IPSummary, log_path: str, limit: int = 12) -> None:
        wanted = set(s.lines[:limit])
        try:
            with open(log_path, "r", encoding=detect_encoding(log_path), errors="replace") as fh:
                for n, line in enumerate(fh, 1):
                    if n in wanted:
                        print(dim("    {:>5}: ".format(n)) + trunc(line.rstrip(), 150))
        except OSError as exc:
            print(red("    cannot read log: {}".format(exc)))
        if len(s.lines) > limit:
            print(dim("    ... and {} more line(s)".format(len(s.lines) - limit)))

    def _summary(self, public: List[IPSummary], intel: Dict[str, IPIntel], log_path: str) -> dict:
        rule("5. SUMMARY")
        blocked = set(self.fw.blocked())
        mal_open = [s.ip for s in public if intel[s.ip].verdict == "MALICIOUS" and s.ip not in blocked
                    and not self.fw.allowlisted(s.ip)]
        print("  Contained this session : {}".format(
            red(", ".join(self.contained_this_session)) if self.contained_this_session else "none"))
        print("  Firewall blocklist     : {} IP(s)  -> {}".format(len(blocked), self.cfg.blocklist_path))
        print("  Audit trail            : {}".format(self.cfg.audit_path))
        print("  Enriched events        : {}".format(self.cfg.enriched_path))
        if not self.cfg.mock:
            print("  VirusTotal API calls   : {} (cache hits: {})".format(self.enricher.api_calls,
                                                                      self.enricher.cache_hits))
        if mal_open:
            print(yellow("  WARNING: {} MALICIOUS IP(s) are still NOT contained: {}".format(
                len(mal_open), ", ".join(mal_open))))
        return {"public_ips": [s.ip for s in public], "intel": intel,
                "contained": list(self.contained_this_session), "malicious_uncontained": mal_open}

    # ---- live (follow) mode -------------------------------------------------
    def follow_file(self, path: str, from_start: bool = False, simulate: bool = False,
                    stop_event: Optional[threading.Event] = None, max_events: Optional[int] = None,
                    poll: float = 0.5) -> dict:
        path = os.path.abspath(os.path.expanduser(path))
        self.last_log = path
        if not os.path.exists(path):
            open(path, "a").close()
        rule("LIVE SIEM FEED  " + path)
        print("  Mode: {} | Auto-contain: {} | Prompts: {}".format(
            self.cfg.mode_label, self.cfg.auto_contain or "off", "on" if self.cfg.prompt else "off"))
        print(dim("  Waiting for new events{}. Press Ctrl+C to stop.\n".format(
            " (simulated feed is writing to the file)" if simulate else "")))
        sim = FeedSimulator(path) if simulate else None
        if sim:
            sim.start()
        decided: Set[str] = set()
        stats = {"events": 0, "with_external_ip": 0, "dropped": 0}
        self._live_prompt = self.cfg.prompt
        try:
            for line_no, line in tail_lines(path, from_start, poll, stop_event):
                ev = parse_line(line, line_no, self.pattern)
                if ev is None:
                    continue
                stats["events"] += 1
                if ev.public_ips:
                    stats["with_external_ip"] += 1
                stats["dropped"] += self.handle_live_event(ev, decided, path)
                if max_events and stats["events"] >= max_events:
                    break
        except KeyboardInterrupt:
            print()
        finally:
            if sim:
                sim.halt()
        rule("LIVE SESSION SUMMARY")
        print("  Events processed: {} | with external IPs: {} | from contained IPs (dropped by FW): {}".format(
            stats["events"], stats["with_external_ip"], stats["dropped"]))
        print("  Contained this session: {}".format(
            red(", ".join(self.contained_this_session)) if self.contained_this_session else "none"))
        blocked = set(self.fw.blocked())
        open_mal = sorted(ip for ip, v in self._live_seen.items()
                          if v == "MALICIOUS" and ip not in blocked and not self.fw.allowlisted(ip))
        if open_mal:
            print(yellow("  WARNING: MALICIOUS IP(s) seen but NOT contained: " + ", ".join(open_mal)))
        print("  Blocklist: " + self.cfg.blocklist_path)
        stats["malicious_uncontained"] = open_mal
        return stats

    def handle_live_event(self, ev: LogEvent, decided: Set[str], log_path: str) -> int:
        """Enrich and display one live event; prompt/auto-contain new risky IPs.
        Returns 1 if the event came from an IP the firewall now blocks."""
        blocked = set(self.fw.blocked())
        sev = ev.severity or "-"
        sev_col = red if severity_rank(sev) >= 4 else yellow if severity_rank(sev) == 3 else dim
        ts = ev.timestamp[11:19] if len(ev.timestamp) >= 19 and ev.timestamp[10] in "T " else trunc(ev.timestamp, 15)
        head = "{} {} {}".format(dim(ts or "--:--:--"), sev_col(sev.ljust(8)), trunc(ev.name, 34).ljust(34))
        intel = {ip: self.enricher.lookup(ip) for ip in ev.public_ips}
        for ip, i in intel.items():
            self._live_seen[ip] = i.verdict
        dropped = 0
        if not ev.public_ips:
            internal = [r.ip for r in ev.ips]
            print(head + " " + dim("internal only: " + ", ".join(internal) if internal else "no IP"))
        else:
            parts = []
            for ip in ev.public_ips:
                i = intel[ip]
                tag = "{} {} {}".format(ip, fmt_verdict(i.verdict, 0), i.detections)
                if ip in blocked:
                    tag += " " + red("[FW DROP]")
                    dropped = 1
                parts.append(tag)
            print(head + " " + " | ".join(parts))
            self._write_enriched_quiet(ev, intel, blocked, log_path)

        for ip in ev.public_ips:
            i = intel[ip]
            if ip in decided or ip in blocked or self.fw.allowlisted(ip):
                continue
            if i.verdict not in REVIEW_VERDICTS:
                continue
            if self.cfg.auto_contain and i.verdict in ("MALICIOUS", "SUSPICIOUS") and \
                    VERDICT_RANK[i.verdict] >= VERDICT_RANK[self.cfg.auto_contain.upper()]:
                decided.add(ip)
                self.contain(ip, i, "AUTO (live): {} {} - {}".format(i.verdict, i.detections, ev.name), log_path)
                continue
            if not self._live_prompt:
                continue
            decided.add(ip)
            print()
            self.intel_card(i, None, prefix="    ")
            while True:
                ans = ask("    Contain {}? [y]es [n]o [d]etails [s]top asking: ".format(ip))
                if ans is None or ans.lower().startswith("s"):
                    self._live_prompt = False
                    print(dim("    Prompts off for this session; events keep streaming."))
                    break
                if ans.lower().startswith("d"):
                    print(dim("    Line {}: ".format(ev.line_no)) + trunc(ev.raw, 160))
                    continue
                if ans.lower().startswith("y"):
                    default = "{} on VirusTotal ({}); live event: {}".format(i.verdict, i.detections, ev.name)
                    reason = ask("    Reason [{}]: ".format(default))
                    self.contain(ip, i, reason or default, log_path)
                else:
                    print(dim("    Skipped. (Contain it later from the menu if it keeps showing up.)"))
                break
            print()
        return dropped

    def _write_enriched_quiet(self, ev: LogEvent, intel: Dict[str, IPIntel], blocked: Set[str],
                              log_path: str) -> None:
        full = dict(intel)
        for r in ev.ips:
            if not r.public:
                full[r.ip] = IPIntel(r.ip, "INTERNAL", source="n/a")
        try:
            os.makedirs(self.cfg.out_dir, exist_ok=True)
            with open(self.cfg.enriched_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(self._event_record(ev, full, blocked, log_path, utc_now())) + "\n")
        except OSError:
            pass

    # ---- blocklist view ----------------------------------------------------
    def show_blocklist(self) -> None:
        rule("FIREWALL BLOCKLIST")
        blocked = self.fw.blocked()
        rows = self.fw.audit_rows()
        last_contain: Dict[str, Dict[str, str]] = {}
        for r in rows:
            if r.get("action") == "CONTAIN":
                last_contain[r.get("ip", "")] = r
        if not blocked:
            print("  (empty) - no IPs are contained.")
        for ip in blocked:
            r = last_contain.get(ip, {})
            print("  {:<16} {} {:<8} {}  {}".format(
                red(ip.ljust(15)), dim(r.get("timestamp_utc", "manual edit".ljust(20))),
                r.get("verdict", ""), trunc(r.get("reason", ""), 50), dim(r.get("analyst", ""))))
        print(dim("  File: " + self.cfg.blocklist_path))
        allow = Firewall._entries(self.cfg.allowlist_path)
        print(dim("  Allowlist ({}): {}".format(len(allow), ", ".join(allow)) if allow else "  Allowlist: empty"))
        if rows:
            rule("RECENT AUDIT TRAIL")
            for r in rows[-10:]:
                act = r.get("action", "")
                print("  {} {:<8} {:<16} {}  {}".format(
                    dim(r.get("timestamp_utc", "")), red(act.ljust(8)) if act == "CONTAIN" else green(act.ljust(8)),
                    r.get("ip", ""), trunc(r.get("reason", ""), 55), dim(r.get("analyst", ""))))
            print(dim("  File: " + self.cfg.audit_path))


# =============================================================================
# Interactive menu
# =============================================================================

def browse_for_file(title: str = "Choose a SIEM log file") -> Optional[str]:
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        try:
            root.attributes("-topmost", True)
        except Exception:
            pass
        path = filedialog.askopenfilename(
            title=title, filetypes=[("Log files", "*.log *.txt *.json *.csv"), ("All files", "*.*")])
        root.destroy()
        return path or None
    except Exception as exc:
        print(yellow("  File browser unavailable here ({}). Type the path instead.".format(
            type(exc).__name__)))
        return None


def sample_dir() -> str:
    """Where menu-created sample logs go: next to the script, or the working folder if that's read-only."""
    return SCRIPT_DIR if os.access(SCRIPT_DIR, os.W_OK) else os.getcwd()


def clean_path(text: str) -> str:
    return os.path.expanduser(text.strip().strip('"').strip("'"))


class Menu:
    def __init__(self, app: App) -> None:
        self.app = app
        self.cfg = app.cfg

    def ensure_intel_source(self) -> bool:
        if self.cfg.mock or self.cfg.api_key:
            return True
        print(yellow("\nNo VirusTotal API key found (checked VT_API_KEY and .env)."))
        print("  1) Enter an API key now (free: https://www.virustotal.com/gui/my-apikey)")
        print("  2) Use MOCK mode - simulated threat intel, nothing sent to VirusTotal")
        print("  3) Continue without enrichment (IPs will show UNKNOWN)")
        choice = ask("Choose [1-3]: ")
        if choice == "1":
            return self.set_key()
        if choice == "2":
            self.cfg.mock = True
            return True
        return choice == "3"

    def set_key(self) -> bool:
        try:
            key = getpass.getpass("Paste your VirusTotal API key (input hidden): ").strip()
        except Exception:
            key = (ask("Paste your VirusTotal API key: ") or "").strip()
        if not key:
            print(yellow("No key entered."))
            return False
        if len(key) != 64 or not re.fullmatch(r"[0-9a-fA-F]+", key):
            print(yellow("Note: VirusTotal keys are usually 64 hex characters - double-check it."))
        self.cfg.api_key = key
        self.cfg.mock = False
        self.app.enricher.reset_auth()
        if ask_yes_no("Save it to {} so you are not asked again?".format(_dotenv_save_path())):
            print(dim("Saved to " + save_key_to_dotenv(key) + "  (never commit this file to Git)"))
        return True

    def pick_log(self, for_follow: bool = False) -> Optional[str]:
        last = self.app.last_log
        gui = not os.getenv("SIEM_NO_GUI")
        hint = ("Enter=file browser, " if gui else "") + "s=create a sample log" + (
            ", l=last ({})".format(os.path.basename(last)) if last else "")
        ans = ask("Log file path ({}): ".format(hint))
        if ans is None:
            return None
        if ans.lower() == "l" and last:
            return last
        if ans.lower() == "s":
            default = os.path.join(sample_dir(), "sample_siem.log")
            p = make_sample_log(default)
            print(green("Created sample log: " + p))
            return p
        if ans == "":
            if not gui:
                print(yellow("  Type the path to a log file (current folder: {}).".format(os.getcwd())))
                return None
            p = browse_for_file()
            if not p:
                return None
            return p
        p = clean_path(ans)
        if not os.path.isfile(p):
            if for_follow and ask_yes_no("{} does not exist. Create it and watch it?".format(p)):
                return p
            print(red("File not found: " + os.path.abspath(p)))
            return None
        return p

    def run(self) -> None:
        print(bold(cyan("\nSIEM IP Enricher & Containment Simulator v" + VERSION)))
        self.ensure_intel_source()
        while True:
            rule("MENU")
            print("  Intel: {}   Threshold: {} engines   Auto-contain: {}".format(
                self.cfg.mode_label, self.cfg.threshold, self.cfg.auto_contain or "off"))
            print(dim("  Output folder: " + self.cfg.out_dir))
            print("""
  1) Analyze a log file          (parse, enrich every IP, review & contain)
  2) Watch a log file live       (SIEM feed: enrich new events as they arrive)
  3) Contain an IP manually
  4) Release (unblock) an IP
  5) Show firewall blocklist & audit trail
  6) Look up a single IP
  7) Create a sample SIEM log
  8) Settings
  0) Exit""")
            choice = ask("\nChoose: ")
            if choice is None or choice in ("0", "q", "exit", "quit"):
                print("Bye.")
                return
            try:
                self.dispatch(choice)
            except KeyboardInterrupt:
                print(yellow("\n  Cancelled."))

    def dispatch(self, choice: str) -> None:
        app = self.app
        if choice == "1":
            p = self.pick_log()
            if p:
                app.analyze_file(p)
        elif choice == "2":
            p = self.pick_log(for_follow=True)
            if not p:
                return
            from_start = ask_yes_no("Process the lines already in the file first?", default=False)
            simulate = ask_yes_no("Start the simulated SIEM feed (writes new random events into this file)?",
                                  default=False)
            app.follow_file(p, from_start=from_start, simulate=simulate)
        elif choice == "3":
            ip = ask("IP to contain: ")
            if not ip:
                return
            if not is_valid_ip(ip):
                print(red("Not a valid IP address."))
                return
            intel = app.enricher.lookup(ip)
            app.intel_card(intel, prefix="  ")
            default = "Manual containment" + (" - {} ({})".format(intel.verdict, intel.detections)
                                              if intel.total else "")
            reason = ask("Reason [{}]: ".format(default)) or default
            app.contain_with_override(ip, intel, reason)
        elif choice == "4":
            blocked = app.fw.blocked()
            if not blocked:
                print("  Blocklist is empty.")
                return
            print("  Contained: " + ", ".join(blocked))
            ip = ask("IP to release: ")
            if not ip:
                return
            reason = ask("Reason [false positive]: ") or "false positive"
            ok, msg = app.fw.release(ip, reason, app.analyst)
            print("  " + (green("RELEASED ") if ok else yellow("Not released: ")) + msg)
        elif choice == "5":
            app.show_blocklist()
        elif choice == "6":
            ip = ask("IP to look up: ")
            if not ip:
                return
            intel = app.enricher.lookup(ip)
            app.intel_card(intel, prefix="  ")
            if app.fw.is_blocked(intel.ip):
                print(red("  This IP is currently contained."))
            elif intel.verdict != "ERROR" and ask_yes_no("  Contain it?"):
                reason = ask("Reason [Manual lookup]: ") or "Manual lookup - {} ({})".format(
                    intel.verdict, intel.detections)
                app.contain_with_override(intel.ip, intel, reason)
        elif choice == "7":
            default = os.path.join(sample_dir(), "sample_siem.log")
            ans = ask("Save sample log as [{}]: ".format(default))
            p = make_sample_log(clean_path(ans) if ans else default, seed=None)
            print(green("Created " + p))
            app.last_log = p
        elif choice == "8":
            self.settings()
        else:
            print(yellow("  Unknown option."))

    def settings(self) -> None:
        while True:
            rule("SETTINGS")
            key = "...{}".format(self.cfg.api_key[-4:]) if self.cfg.api_key else "not set"
            print("""  1) VirusTotal API key          [{}]
  2) Intel mode                   [{}]
  3) Malicious threshold          [{} engines]
  4) Auto-contain                 [{}]
  5) Lookup rate                  [{}/min  (free API = 4)]
  6) Output folder                [{}]
  7) Allow blocking internal IPs  [{}]
  8) Clear VirusTotal cache
  0) Back""".format(key, "MOCK" if self.cfg.mock else "LIVE", self.cfg.threshold,
                    self.cfg.auto_contain or "off", self.cfg.rate_per_min, self.cfg.out_dir,
                    "yes" if self.cfg.allow_private else "no"))
            c = ask("Choose: ")
            if c is None or c in ("0", ""):
                return
            if c == "1":
                self.set_key()
            elif c == "2":
                if not self.cfg.mock or self.cfg.api_key:
                    self.cfg.mock = not self.cfg.mock
                    self.app.enricher.memory.clear()
                else:
                    print(yellow("Set an API key first to use LIVE mode."))
            elif c == "3":
                v = ask("Engines that must flag an IP as malicious [{}]: ".format(self.cfg.threshold))
                if v and v.isdigit() and int(v) > 0:
                    self.cfg.threshold = int(v)
            elif c == "4":
                v = ask("Auto-contain: [o]ff, [m]alicious only, [s]uspicious and above: ")
                if v:
                    self.cfg.auto_contain = {"o": "", "m": "malicious", "s": "suspicious"}.get(v[0].lower(),
                                                                                               self.cfg.auto_contain)
            elif c == "5":
                v = ask("Requests per minute (0 = no limit, premium keys only) [{}]: ".format(self.cfg.rate_per_min))
                if v and v.isdigit():
                    self.cfg.rate_per_min = int(v)
                    self.app.enricher.limiter.per_minute = int(v)
            elif c == "6":
                v = ask("Output folder [{}]: ".format(self.cfg.out_dir))
                if v:
                    self.cfg.out_dir = os.path.abspath(clean_path(v))
                    self.app.fw = Firewall(self.cfg)
                    self.app.enricher._cache = self.app.enricher._load_cache()
            elif c == "7":
                self.cfg.allow_private = not self.cfg.allow_private
            elif c == "8":
                self.app.enricher.clear_cache()
                print(green("Cache cleared."))


# =============================================================================
# CLI
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="siem_enricher.py",
        description="Enrich SIEM log IPs with VirusTotal and contain them on a (simulated) firewall. "
                    "Run with no arguments for the interactive menu.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s                                   interactive menu
  %(prog)s --make-sample siem.log            create a sample SIEM log
  %(prog)s siem.log --mock                   analyze with simulated intel (no key needed)
  %(prog)s siem.log                          analyze with live VirusTotal lookups
  %(prog)s siem.log --auto-contain malicious --no-prompt   hands-free SOAR-style run
  %(prog)s siem.log --follow --simulate      watch a live feed with a built-in event generator
  %(prog)s --contain 45.155.205.233 --reason "SSH brute force"
  %(prog)s --release 45.155.205.233 --reason "false positive"
  %(prog)s --list                            show blocklist and audit trail""")
    p.add_argument("logfile", nargs="?", help="SIEM log file to analyze or watch")
    g = p.add_argument_group("analysis")
    g.add_argument("--follow", "-f", action="store_true", help="watch the file for new events (like tail -f)")
    g.add_argument("--from-start", action="store_true", help="with --follow: process existing lines first")
    g.add_argument("--simulate", action="store_true", help="with --follow: append random events to the file")
    g.add_argument("--pattern", help="custom regex with named groups, e.g. (?P<src_ip>...) (?P<event>...)")
    g.add_argument("--auto-contain", choices=["malicious", "suspicious"],
                   help="contain IPs at or above this verdict without asking")
    g.add_argument("--no-prompt", action="store_true", help="never ask questions (report only / auto mode)")
    g.add_argument("--max-events", type=int, help=argparse.SUPPRESS)
    i = p.add_argument_group("threat intel")
    i.add_argument("--api-key", help="VirusTotal API key (default: $VT_API_KEY or .env)")
    i.add_argument("--mock", action="store_true", help="simulated intel; nothing is sent to VirusTotal")
    i.add_argument("--threshold", type=int, default=3, help="engines needed for MALICIOUS (default 3)")
    i.add_argument("--rate", type=int, default=4, help="max lookups per minute (free API: 4)")
    i.add_argument("--cache-ttl", type=float, default=24, help="hours to reuse cached answers (default 24)")
    f = p.add_argument_group("firewall")
    f.add_argument("--contain", metavar="IP", nargs="+", help="contain IP(s) and exit")
    f.add_argument("--release", metavar="IP", nargs="+", help="release IP(s) and exit")
    f.add_argument("--reason", default="", help="reason recorded in the audit trail")
    f.add_argument("--force", action="store_true", help="with --contain: allow internal IPs")
    f.add_argument("--allow-private", action="store_true", help="allow containing private/internal IPs")
    f.add_argument("--list", action="store_true", help="show the blocklist and audit trail")
    o = p.add_argument_group("other")
    o.add_argument("--lookup", metavar="IP", nargs="+", help="look up IP(s) on VirusTotal and exit")
    o.add_argument("--make-sample", metavar="PATH", help="write a sample SIEM log to PATH")
    o.add_argument("--out-dir", help="folder for blocklist/audit/enriched output")
    o.add_argument("--no-color", action="store_true", help="disable coloured output")
    o.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    return p


def _graceful_sigterm() -> None:
    """Treat SIGTERM (e.g. `docker stop`) like Ctrl+C so sessions end cleanly with a summary."""
    import signal

    def handler(signum, frame):  # type: ignore[no-untyped-def]
        raise KeyboardInterrupt

    try:
        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGTERM, handler)
    except (ValueError, OSError, AttributeError):
        pass


def main(argv: Optional[List[str]] = None) -> int:
    _graceful_sigterm()
    args = build_parser().parse_args(argv)
    if args.no_color:
        Style.enabled = False
    cfg = Config(
        api_key=(args.api_key or os.getenv("VT_API_KEY") or load_key_from_dotenv()).strip(),
        mock=args.mock, threshold=max(1, args.threshold), rate_per_min=max(0, args.rate),
        out_dir=args.out_dir or "", cache_ttl_hours=args.cache_ttl,
        auto_contain=args.auto_contain or "", prompt=not args.no_prompt, allow_private=args.allow_private,
    )
    app = App(cfg)
    if args.pattern:
        try:
            app.pattern = re.compile(args.pattern)
        except re.error as exc:
            print(red("Invalid --pattern regex: {}".format(exc)))
            return 1

    did_something = False
    if args.make_sample:
        print(green("Sample SIEM log written to " + make_sample_log(args.make_sample)))
        did_something = True
    if args.contain:
        for ip in args.contain:
            intel = app.enricher.lookup(ip) if (cfg.mock or cfg.api_key) and is_valid_ip(ip) else None
            if intel is not None:
                app.intel_card(intel, prefix="  ")
            app.contain(ip, intel, args.reason or "Manual containment (CLI)", force=args.force)
        did_something = True
    if args.release:
        for ip in args.release:
            ok, msg = app.fw.release(ip, args.reason or "Manual release (CLI)", app.analyst)
            print("  " + (green("RELEASED ") if ok else yellow("Not released: ")) + msg)
        did_something = True
    if args.lookup:
        for ip in args.lookup:
            app.intel_card(app.enricher.lookup(ip), prefix="  ")
        did_something = True
    if args.list:
        app.show_blocklist()
        did_something = True

    if args.logfile:
        if not (cfg.mock or cfg.api_key):
            if args.no_prompt:
                print(red("No VirusTotal API key. Set VT_API_KEY, use --api-key, or add --mock."))
                return 1
            if not Menu(app).ensure_intel_source():
                return 1
        try:
            if args.follow:
                app.follow_file(args.logfile, from_start=args.from_start, simulate=args.simulate,
                                max_events=args.max_events)
            else:
                if not os.path.isfile(args.logfile):
                    print(red("File not found: " + args.logfile))
                    return 1
                result = app.analyze_file(args.logfile)
                return 2 if result.get("malicious_uncontained") else 0
        except KeyboardInterrupt:
            print(yellow("\nInterrupted."))
            return 130
        return 0

    if did_something:
        return 0
    try:
        Menu(app).run()
    except KeyboardInterrupt:
        print("\nBye.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
