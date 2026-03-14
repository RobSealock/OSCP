# OSCP Toolkit v6

Authorized reconnaissance, triage, and exploit-execution toolkit for HTB / CTF / OSCP exam-prep environments.

> **Authorized use only.** Run against systems you own or have explicit written permission to test.

---

## File Layout

```
/opt/oscp-toolkit/
├── interactive_nmap_launcher_v6.py   # Scanner and triage engine
├── exploit_runner.py                 # Interactive exploit execution module
├── oscp_toolkit_lib.py               # Shared library (types, helpers, cred store)
├── OSCP_playbook_enhanced_yaml.txt   # 43 foothold patterns, 31 fingerprint entries
├── setup_oscp_toolkit.sh             # One-shot installer
└── scan_runs/                        # All scan output (auto-created)
    └── <TYPE>_<TARGET>_<STAMP>/
        ├── *.xml / *.nmap / *.gnmap  # Nmap output files
        ├── *_combined.md             # Markdown triage summary
        ├── *_combined.html           # HTML report
        ├── triage_handoff.json       # Launcher → runner handoff
        ├── exploit_runner.log        # Runner session log
        ├── obsidian_notes/           # Per-host Obsidian-compatible notes
        └── follow_up/               # Service enumeration output

/opt/privesc/
├── linpeas.sh                        # Linux privilege escalation
├── winPEASx64.exe                    # Windows privilege escalation
├── GodPotato-NET4.exe                # Token abuse (SeImpersonate)
├── PrintSpoofer64.exe                # Token abuse alternative
└── JuicyPotatoNG.exe                 # Token abuse (older Windows)
```

---

## Quick Start

```bash
# 1. Install everything
sudo bash setup_oscp_toolkit.sh

# 2. Run the scanner
cd /opt/oscp-toolkit
sudo python3 interactive_nmap_launcher_v6.py
# or via symlink:
sudo oscp-scan

# 3. After scanning, run the exploit runner
sudo python3 exploit_runner.py scan_runs/<workspace>/
# or auto-find latest scan:
sudo oscp-exploit
```

---

## Script Reference

### `interactive_nmap_launcher_v6.py` — Scanner and Triage Engine

The primary entry point. Runs Nmap scans, scores findings against the playbook, performs follow-up enumeration, and writes a handoff file for the exploit runner.

**Scan modes:**

| Key | Mode | Description |
|-----|------|-------------|
| A | Fast Subnet | Top-100 TCP ports across the whole subnet. Good for initial host discovery. |
| B | Detailed IP | Two-phase scan: top-1000 TCP with NSE, then full `-p-` with adaptive scripts. Includes optional UDP sweep. |
| C | Detailed Subnet | Host discovery followed by full two-phase scan on each live host. Supports parallel workers. |
| D | AD Scan | Active Directory-focused: services, LDAP, SMB info + signing, SMB enum, Kerberos. Prints AD attack surface hints. |
| E | Custom | User-specified ports and NSE scripts. Good for deep-dive on a specific service. |

**What the launcher does after scanning:**

1. Parses Nmap XML and extracts service banners, HTTP titles, and NSE script output
2. Scores each (IP, port, pattern) triple against the playbook to produce a ranked triage list
3. Runs `searchsploit` against all discovered product/version banners
4. Optionally runs service-specific follow-up enumeration (see Follow-up Modules below)
5. Builds a CeWL custom wordlist from web targets if requested
6. Prints post-exploit one-liners if any finding scores ≥ 8
7. Optionally serves linpeas/winpeas via a background HTTP server
8. Sprays any accumulated credentials across discovered services
9. Writes `triage_handoff.json` for the exploit runner

**Follow-up enumeration modules** (called automatically per service):

| Service | Tools used |
|---------|-----------|
| HTTP/HTTPS | whatweb, nikto, ffuf (dir + ext), wpscan, droopescan, joomscan, LFI wordlist fuzz, PHP wrapper probes, log poisoning hints |
| HTTP vhosts | ffuf Host-header fuzzing against discovered hostnames |
| .git exposure | curl probe, git-dumper, trufflehog |
| SMB | smbclient, enum4linux, netexec/crackmapexec (null + guest session) |
| SMTP | NSE smtp-commands/enum-users/open-relay, smtp-user-enum (VRFY/EXPN/RCPT) |
| DNS | NSE zone-transfer/recursion, dnsrecon (axfr + std), dig axfr |
| NFS | showmount, NSE nfs-ls/nfs-showmount/nfs-statfs |
| SNMP | snmpwalk (public/private/manager) |
| FTP | NSE ftp-anon/ftp-syst/ftp-bounce |
| LDAP | NSE ldap* |
| Redis | redis-cli INFO, CONFIG GET, KEYS |
| MySQL | NSE mysql-info/empty-password/databases/users |
| MSSQL | NSE ms-sql-info/empty-password/config, netexec |
| WinRM | NSE, netexec winrm |

---

### `exploit_runner.py` — Interactive Exploit Execution Module

Reads `triage_handoff.json`, displays ranked findings, and drives exploit selection interactively. Every destructive action requires explicit `y` confirmation.

**Interactive menu:**

| Key | Action |
|-----|--------|
| 1–N | Select a ranked finding for exploit |
| c | Run confirmation PoC checks (non-destructive) on all high-confidence findings |
| s | Run searchsploit against all discovered banners |
| h | Hash cracking helper (hashid → hashcat mode → rockyou) |
| p | Print post-exploit one-liners (file transfer, shell stabilization, privesc) |
| w | Spray accumulated credentials across SMB/WinRM/SSH |
| v | Vhost / subdomain fuzzing |
| j | Joomscan against a specified port |
| d | Droopescan (Drupal) against a specified port |
| q | Quit and save updated handoff |

**Exploit modules available:**

| Pattern ID | Module |
|-----------|--------|
| FTP-ANON-UPLOAD | Anonymous FTP listing via curl |
| REDIS-UNAUTH-PIVOT | Redis INFO/CONFIG dump + webshell path |
| MS17-010-PATTERN | AutoBlue and Metasploit one-liners |
| SMB-ANON-SHARE-CREDS | Null session share listing and mounting |
| NFS-EXPORTED-SECRETS | showmount + mount one-liners + SSH key plant |
| TOMCAT-MANAGER | msfvenom WAR generation + curl deploy |
| SSTI | Jinja2/Twig/FreeMarker payload list |
| WORDPRESS-CREDS | Theme editor and malicious plugin upload |
| SMB-SIGNING-RELAY | responder + ntlmrelayx setup |
| KERBEROAST | impacket-GetUserSPNs + hashcat -m 13100 |
| ASREPROAST | impacket-GetNPUsers + hashcat -m 18200 |
| WINRM-WITH-RECOVERED-CREDS | evil-winrm (password or hash) |
| ACL-ABUSE | bloodyAD + PowerView one-liners |
| LFI (generic) | PHP wrappers, log poisoning, RFI, LFI fuzz |
| SQLi (generic) | sqlmap full pipeline |
| Vhost (generic) | ffuf Host-header fuzz |
| AlwaysInstallElevated | Registry check + msfvenom MSI |
| Potato family | GodPotato, PrintSpoofer, JuicyPotatoNG transfer + run |
| DPAPI | donpapi + netexec --dpapi |

**Confirmation PoC checks** (non-destructive, run before active exploits):

| Pattern | PoC method |
|---------|-----------|
| FTP-ANON | NSE ftp-anon |
| Redis | redis-cli PING |
| MS17-010 | NSE smb-vuln-ms17-010 |
| SMB anon | smbclient -N |
| NFS | showmount -e |
| Tomcat | curl HEAD /manager/html |
| SNMP | snmpwalk public community |
| MySQL empty pwd | NSE mysql-empty-password |
| SMB signing | NSE smb2-security-mode (always run if SMB present) |

---

### `oscp_toolkit_lib.py` — Shared Library

Imported by both launcher and exploit runner. Never run directly.

Provides:
- `TriageResult` dataclass and JSON serialisation
- `HandoffFile` — launcher-to-runner state transfer
- `CredEntry` / `CRED_STORE` — session-wide credential accumulation
- `run_streaming_command()` — subprocess wrapper with live output and timeout
- `best_wordlist()` — cascading wordlist path resolution
- `detect_hash_type()` — naive hash-length classifier → hashcat `-m` mode
- `guess_os_from_services()` — windows/linux/unknown from service fingerprints
- Wordlist priority lists (web content, vhost, LFI, users, passwords)
- `have_bin()`, `yes_no()`, `prompt_until_valid()`, `now_stamp()`, `sanitize_target()`

---

### `OSCP_playbook_enhanced_yaml.txt` — Triage Playbook

YAML file consumed by both scripts. Contains:

- **43 foothold patterns** — each with ID, name, estimated exam frequency, likely next steps, and enumeration commands
- **31 service fingerprint map entries** — match rules against Nmap `service`, `product`, `port_in`, and `title_contains` fields
- **Simple scoring model** — base priority + frequency score + signal bonuses (version exposed, default banner)

Patterns include: WEB-CONTENT-DISCOVERY, LFI, SQLI, SSTI, FILE-UPLOAD-BYPASS, WORDPRESS-CREDS, WORDPRESS-PLUGIN-EXPOSURE, TOMCAT-MANAGER, JENKINS-CONSOLE-OR-BUILD-ABUSE, FTP-ANON-UPLOAD, SMB-ANON-SHARE-CREDS, SMB-SIGNING-RELAY, MS17-010-PATTERN, NFS-EXPORTED-SECRETS, NFS-MISCONFIG-PRIVESC, REDIS-UNAUTH-PIVOT, SNMP-USER-DISCOVERY, DB-CREDENTIAL-DISCOVERY, ASREPROAST, KERBEROAST, VNC-NO-AUTH, MSSQL-XPCMD, ELASTICSEARCH-UNAUTH, GHOSTCAT-AJP, JAVA-RMI-EXPLOIT, DEFAULT-CREDS, DNS-ENUM, SMTP-ENUM, AD-SURFACE, WINRM-WITH-RECOVERED-CREDS, CREDENTIAL-REUSE, EXPOSED-BACKUP, and more.

Triage scores ≥ 6 are treated as high-confidence. Scores ≥ 8 trigger the post-exploit helper automatically.

---

### `setup_oscp_toolkit.sh` — Installer

Installs and configures the full toolkit in one pass.

**Steps:**
1. System apt packages (nmap, ffuf, nikto, smbclient, enum4linux, joomscan, hashcat, hashid, exploitdb, cewl, exiftool, rlwrap, and others)
2. Python packages (pyyaml, impacket, droopescan, git-dumper, trufflehog, donpapi, bloodyAD, certipy-ad, pywhisker)
3. External binaries (ffuf from GitHub, netexec via pip, wpscan/evil-winrm via gem, ligolo-ng, chisel, vulners NSE script)
4. Privesc script downloads (linpeas, winPEAS, GodPotato, PrintSpoofer, JuicyPotatoNG) to `/opt/privesc/`
5. Wordlists (rockyou, SecLists)
6. Toolkit file installation to `/opt/oscp-toolkit/`
7. Symlinks: `oscp-scan`, `oscp-scan-v6`, `oscp-exploit` in `/usr/local/bin/`
8. Syntax validation of all Python files and YAML playbook
9. Working directory creation
10. PATH fixup for pip-installed tools
11. Final tool availability report

---

## Workflow

```
┌──────────────────────────────────────────┐
│  interactive_nmap_launcher_v6.py         │
│                                          │
│  Scan → Parse → Score → Triage List      │
│  ↓                                       │
│  Follow-up enumeration (per service)     │
│  ↓                                       │
│  searchsploit all banners                │
│  ↓                                       │
│  CeWL wordlist / hash crack / cred spray │
│  ↓                                       │
│  Write triage_handoff.json               │
└──────────────┬───────────────────────────┘
               │  triage_handoff.json
               ▼
┌──────────────────────────────────────────┐
│  exploit_runner.py                       │
│                                          │
│  Load ranked findings + cred store       │
│  ↓                                       │
│  Confirmation PoC checks (non-destruct.) │
│  ↓                                       │
│  Interactive exploit selection           │
│  (user confirms each action)             │
│  ↓                                       │
│  Post-exploit helper on success          │
│  ↓                                       │
│  Save updated handoff                    │
└──────────────────────────────────────────┘
```

---

## Key Design Decisions

**Why two scripts?**
The launcher is a non-destructive reconnaissance and triage tool. The exploit runner is an interactive attack orchestrator. Separating them keeps each script's threat model clean and makes the launcher safe to run repeatedly without risk of unintended impact.

**Handoff file**
`triage_handoff.json` contains the full ranked triage list, accumulated credentials, and raw host data. The exploit runner picks it up automatically from the latest scan workspace. Credentials discovered during recon (anonymous FTP, Redis no-auth) are propagated into the credential spray at no extra cost.

**Confirmation before execution**
Every active exploit module requires an explicit `y` before firing. Non-destructive PoC checks (NSE scripts, banner grabs, showmount) can be run in bulk first to validate exploitability without causing impact.

**Wordlist cascade**
All wordlist paths use a priority cascade — the toolkit tries four or more paths in order and uses the first that exists. If none are found, the module prints a warning and skips gracefully rather than crashing.

**Graceful degradation**
Every tool dependency is checked at runtime via `have_bin()`. Missing tools cause the relevant module to print a manual one-liner and skip, never crash.

---

## Tool Dependencies

**Required:**
- `nmap`, `python3`, `python3-pip`

**Strongly recommended (most modules depend on these):**
- `ffuf` — content discovery and vhost fuzzing
- `seclists` — wordlists
- `netexec` or `crackmapexec` — SMB/WinRM enumeration and credential spray
- `impacket` — Kerberos attacks (ASREPRoast, Kerberoast, PtH)
- `evil-winrm` — WinRM shell with credentials or hash

**Situational (loaded as available):**
- `wpscan`, `droopescan`, `joomscan` — CMS scanning
- `git-dumper`, `trufflehog` — .git exposure
- `sqlmap` — SQL injection
- `hashcat`, `hashid`, `john` — hash cracking
- `cewl` — custom wordlists
- `exiftool` — file metadata
- `redis-cli` — Redis
- `snmpwalk` — SNMP
- `dnsrecon`, `dig` — DNS
- `showmount` — NFS
- `smtp-user-enum` — SMTP
- `searchsploit` — exploit lookup
- `msfvenom` — payload generation (WAR, MSI)
- `chisel`, `ligolo-proxy` — tunneling
- `certipy`, `bloodyad`, `donpapi`, `pywhisker` — AD/ADCS attacks

---

## Credential Store

Credentials are accumulated automatically during scanning:
- Anonymous FTP login detected via NSE → stored as `anonymous:anonymous`
- Redis with no authentication detected → stored as `no-auth`
- Manually added via `store_credential()` calls in follow-up modules

At end of scan, the store is printed and optionally used for:
1. Credential spray via netexec across SMB/WinRM/SSH
2. Passed to exploit runner via handoff file for WinRM shell, PtH, etc.

---

## AD Attack Checklist

Printed automatically at the end of an AD scan:

- ASREPRoast → hashcat -m 18200
- Kerberoast → hashcat -m 13100
- Pass-the-Hash (psexec, wmiexec, evil-winrm)
- ACL/ACE abuse (PowerView, bloodyAD)
- Shadow credentials (certipy, pywhisker)
- GPO abuse (SharpGPOAbuse)
- Token abuse — SeImpersonatePrivilege (GodPotato, PrintSpoofer, JuicyPotatoNG)
- AlwaysInstallElevated (registry check → msfvenom MSI)
- DPAPI (donpapi, netexec --dpapi)

---

## Version History

| Version | Key changes |
|---------|-------------|
| v4 | Base launcher — two-phase scan, service follow-up |
| v5 | Bug fixes (NFS dispatch, title_contains, wordlist cascade, UDP ports, PATH) + new services (SMTP, DNS, NFS, MySQL, MSSQL, WinRM) + exploit confirmation layer + credential store + scan mode E |
| v6 | Split into launcher + exploit_runner + shared lib. Added: vhost fuzzing, .git exposure, PHP wrappers + log poisoning, droopescan/joomscan, searchsploit auto-lookup, post-exploit helper, linpeas/winpeas serve, hash crack helper, CeWL, Potato family, ACL/ACE/PtH/shadow creds/GPO abuse in AD scan, tunneling tools (chisel, ligolo-ng), DPAPI |
