#!/usr/bin/env python3
"""
oscp_toolkit_lib.py  —  Shared library for OSCP Toolkit v6

Provides:
  - TriageResult   dataclass (shared between launcher and exploit_runner)
  - CredStore      session credential accumulation
  - HandoffFile    JSON serialisation / deserialisation for launcher → runner handoff
  - Shared helpers (have_bin, best_wordlist, run_cmd, yes_no, etc.)
  - Wordlist priority cascades
  - Common constants

All heavyweight imports (yaml, xml) stay in the scripts that need them.
This file must import cleanly with stdlib only.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# ─────────────────────────────────────────────────────────────────────────────
# Version tag
# ─────────────────────────────────────────────────────────────────────────────

TOOLKIT_VERSION = "6.0"

# ─────────────────────────────────────────────────────────────────────────────
# Handoff file name  (written by launcher, read by exploit_runner)
# ─────────────────────────────────────────────────────────────────────────────

HANDOFF_FILENAME = "triage_handoff.json"


# ─────────────────────────────────────────────────────────────────────────────
# TriageResult — single ranked finding
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TriageResult:
    ip:           str
    port:         str
    service:      str
    product:      str
    version:      str
    pattern_id:   str
    pattern_name: str
    score:        int
    likely_next:  List[str] = field(default_factory=list)
    enum_cmds:    List[str] = field(default_factory=list)
    confirmed:    bool      = False   # set by exploit_runner after PoC check
    exploited:    bool      = False   # set by exploit_runner after successful exploit


def triage_to_dict(t: TriageResult) -> Dict:
    return asdict(t)


def triage_from_dict(d: Dict) -> TriageResult:
    return TriageResult(
        ip           = d.get("ip", ""),
        port         = d.get("port", ""),
        service      = d.get("service", ""),
        product      = d.get("product", ""),
        version      = d.get("version", ""),
        pattern_id   = d.get("pattern_id", ""),
        pattern_name = d.get("pattern_name", ""),
        score        = d.get("score", 0),
        likely_next  = d.get("likely_next", []),
        enum_cmds    = d.get("enum_cmds", []),
        confirmed    = d.get("confirmed", False),
        exploited    = d.get("exploited", False),
    )


# ─────────────────────────────────────────────────────────────────────────────
# HandoffFile — persists triage results + creds + workspace path between scripts
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class HandoffFile:
    workspace:   str
    target:      str
    stamp:       str
    scan_type:   str
    ranked:      List[Dict]   = field(default_factory=list)   # TriageResult dicts
    cred_store:  List[Dict]   = field(default_factory=list)   # CredEntry dicts
    parsed_hosts: List[Dict]  = field(default_factory=list)   # raw host dicts for spray


def save_handoff(hf: HandoffFile, workspace: Path) -> Path:
    path = workspace / HANDOFF_FILENAME
    with path.open("w", encoding="utf-8") as f:
        json.dump(asdict(hf), f, indent=2)
    return path


def load_handoff(path: Path) -> HandoffFile:
    with path.open("r", encoding="utf-8") as f:
        d = json.load(f)
    return HandoffFile(
        workspace    = d.get("workspace", ""),
        target       = d.get("target", ""),
        stamp        = d.get("stamp", ""),
        scan_type    = d.get("scan_type", ""),
        ranked       = d.get("ranked", []),
        cred_store   = d.get("cred_store", []),
        parsed_hosts = d.get("parsed_hosts", []),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Credential store
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CredEntry:
    username:  str
    secret:    str
    source:    str
    cred_type: str = "password"   # password | hash | no-auth | anonymous | key


CRED_STORE: List[CredEntry] = []


def store_credential(
    username:  str,
    secret:    str,
    source:    str,
    cred_type: str = "password",
) -> None:
    entry = CredEntry(username=username, secret=secret,
                      source=source, cred_type=cred_type)
    # de-duplicate
    for existing in CRED_STORE:
        if (existing.username == username and existing.secret == secret
                and existing.cred_type == cred_type):
            return
    CRED_STORE.append(entry)
    print(f"[CRED] Stored: {username or '(none)'} / {secret} ({cred_type}) from {source}")


def print_cred_store() -> None:
    if not CRED_STORE:
        print("[+] No credentials accumulated this session.")
        return
    print("\n" + "=" * 60)
    print("  SESSION CREDENTIAL STORE")
    print("=" * 60)
    for i, c in enumerate(CRED_STORE, 1):
        print(f"  #{i}  [{c.cred_type}]  {c.username or '(none)'} : {c.secret}")
        print(f"       Source: {c.source}")
    print("=" * 60)


def cred_store_as_dicts() -> List[Dict]:
    return [asdict(c) for c in CRED_STORE]


def load_cred_store_from_dicts(lst: List[Dict]) -> None:
    global CRED_STORE
    CRED_STORE = []
    for d in lst:
        CRED_STORE.append(CredEntry(
            username  = d.get("username", ""),
            secret    = d.get("secret", ""),
            source    = d.get("source", ""),
            cred_type = d.get("cred_type", "password"),
        ))


# ─────────────────────────────────────────────────────────────────────────────
# Wordlist priority cascades
# ─────────────────────────────────────────────────────────────────────────────

WORDLIST_PRIORITY = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
]

WORDLIST_VHOST = [
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
    "/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt",
]

USER_WORDLIST_PRIORITY = [
    "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
    "/usr/share/seclists/Usernames/Names/names.txt",
    "/usr/share/wordlists/metasploit/unix_users.txt",
]

LFI_WORDLIST_PRIORITY = [
    "/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt",
    "/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
]

PASSWORD_WORDLIST_PRIORITY = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
]

VHOST_WORDLIST_PRIORITY = [
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
]


def best_wordlist(candidates: List[str]) -> Optional[str]:
    for w in candidates:
        if Path(w).exists():
            return w
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Binary / tool helpers
# ─────────────────────────────────────────────────────────────────────────────

def have_bin(name: str) -> bool:
    """Check system PATH and common pip/gem local install paths."""
    if shutil.which(name) is not None:
        return True
    for extra in [
        "/usr/local/bin",
        "/root/.local/bin",
        os.path.expanduser("~/.local/bin"),
        "/usr/local/share/gem/ruby/3.0.0/bin",
        "/usr/bin",
    ]:
        if Path(extra, name).exists():
            return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Timestamp / path helpers
# ─────────────────────────────────────────────────────────────────────────────

def now_stamp() -> str:
    return datetime.now().strftime("%d%m%y-%H%M")


def sanitize_target(target: str) -> str:
    return target.replace("/", "_").replace(":", "_").strip()


def workspace_root() -> Path:
    root = Path.cwd() / "scan_runs"
    root.mkdir(exist_ok=True)
    return root


def make_workspace(scan_type: str, target: str, stamp: str) -> Path:
    ws = workspace_root() / f"{scan_type}_{sanitize_target(target)}_{stamp}"
    ws.mkdir(parents=True, exist_ok=True)
    return ws


def append_log(log: Optional[Path], text: str) -> None:
    if log is None:
        return
    with log.open("a", encoding="utf-8") as f:
        f.write(text)


# ─────────────────────────────────────────────────────────────────────────────
# Command execution
# ─────────────────────────────────────────────────────────────────────────────

def run_streaming_command(
    cmd: List[str],
    label:           str            = "",
    cwd:             Optional[Path] = None,
    combined_log:    Optional[Path] = None,
    timeout_seconds: Optional[int]  = None,
) -> int:
    if label:
        print(f"\n=== {label} ===")
    print("[+] Running:", " ".join(cmd))
    append_log(combined_log, f"\n=== {label or 'Command'} ===\n{' '.join(cmd)}\n\n")

    with subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=str(cwd) if cwd else None,
        bufsize=1,
        universal_newlines=True,
    ) as proc:
        timed_out = False

        def _kill_after(secs: int) -> None:
            nonlocal timed_out
            import time
            time.sleep(secs)
            if proc.poll() is None:
                timed_out = True
                print(f"\n[!] Timeout ({secs}s) for: {label or cmd[0]}. Terminating.")
                try:
                    proc.terminate()
                except Exception:
                    pass

        if timeout_seconds:
            t = threading.Thread(target=_kill_after,
                                 args=(timeout_seconds,), daemon=True)
            t.start()

        assert proc.stdout is not None
        for line in proc.stdout:
            print(line, end="")
            append_log(combined_log, line)

        rc = proc.wait()
        return -1 if timed_out else rc


# ─────────────────────────────────────────────────────────────────────────────
# User interaction helpers
# ─────────────────────────────────────────────────────────────────────────────

def yes_no(prompt: str, default: bool = False) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    try:
        ans = input(f"{prompt} {suffix}: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return default
    if not ans:
        return default
    return ans == "y"


def prompt_until_valid(prompt: str, validator) -> str:
    while True:
        try:
            value = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            sys.exit(0)
        try:
            return validator(value)
        except ValueError as e:
            print(f"[!] {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Hash detection helpers
# ─────────────────────────────────────────────────────────────────────────────

def detect_hash_type(h: str) -> str:
    """Naive hash-length classifier. Returns hashcat -m value as string."""
    h = h.strip()
    if h.startswith("$2y$") or h.startswith("$2b$") or h.startswith("$2a$"):
        return "3200"   # bcrypt
    if h.startswith("$6$"):
        return "1800"   # sha512crypt
    if h.startswith("$5$"):
        return "500"    # md5crypt
    if h.startswith("$apr1$"):
        return "1600"   # apr1
    if ":" in h and len(h.split(":")[0]) == 32:
        return "5600"   # NTLMv2 (contains ':')
    length = len(h)
    if length == 32:
        return "0"      # MD5
    if length == 40:
        return "100"    # SHA1
    if length == 64:
        return "1400"   # SHA256
    if length == 128:
        return "1700"   # SHA512
    if length == 65:    # NT:LM style
        return "1000"   # NTLM
    return "0"          # fallback


# ─────────────────────────────────────────────────────────────────────────────
# OS detection helper
# ─────────────────────────────────────────────────────────────────────────────

def guess_os_from_services(open_ports: List[Dict]) -> str:
    """Return 'windows', 'linux', or 'unknown' based on service fingerprints."""
    ports   = {p["port"] for p in open_ports}
    svcs    = {(p["service"] or "").lower() for p in open_ports}
    products = " ".join((p.get("product") or "").lower() for p in open_ports)

    windows_signals = {"microsoft-ds", "netbios-ssn", "msrpc", "wsman"}
    linux_signals   = {"ssh", "nfs", "mountd", "rpcbind"}

    if "445" in ports or windows_signals & svcs or "windows" in products:
        return "windows"
    if "22" in ports or linux_signals & svcs or "linux" in products or "ubuntu" in products:
        return "linux"
    return "unknown"
