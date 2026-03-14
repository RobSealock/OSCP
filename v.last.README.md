# OSCP Toolkit v6.1

Authorized reconnaissance, triage, and exploit-execution toolkit for HTB / CTF / OSCP exam-prep.
Integrated with the **SpellBook** (rusted-silver.github.io/spellbook) — 172 pages of penetration
testing techniques covering recon through lateral movement.

> **Authorized use only.** Run against systems you own or have explicit written permission to test.

---

## File Layout

```
/opt/oscp-toolkit/
├── interactive_nmap_launcher_v6.py   # Scanner, triage, and recon engine
├── exploit_runner.py                 # Interactive exploit execution
├── oscp_toolkit_lib.py               # Shared types, helpers, credential store
├── OSCP_playbook_enhanced_yaml.txt   # 66 foothold patterns, 46 fingerprint entries
├── setup_oscp_toolkit.sh             # One-shot installer
├── README.md                         # This file
└── scan_runs/                        # All scan output (auto-created)
    └── <TYPE>_<TARGET>_<STAMP>/
        ├── *.xml / *.nmap / *.gnmap
        ├── *_combined.md             # Triage summary + attack path
        ├── *_combined.html           # HTML report
        ├── triage_handoff.json       # Launcher → runner handoff
        ├── bloodhound/               # BloodHound zip output
        ├── obsidian_notes/
        └── follow_up/

/opt/privesc/                         # Served to target via HTTP
├── linpeas.sh / winPEASx64.exe
├── GodPotato-NET4.exe / PrintSpoofer64.exe / JuicyPotatoNG.exe
├── SharpHound.exe / Rubeus.exe / SharpUp.exe / Seatbelt.exe
├── nc.exe / mimikatz.zip
/opt/noPac/                           # CVE-2021-42278/42287
/opt/targetedKerberoast/              # GenericWrite Kerberoasting
/opt/PrintNightmare/                  # CVE-2021-34527 PS module
/opt/ligolo-ng/                       # Tunneling proxy
```

---

## Quick Start

```bash
chmod +x setup_oscp_toolkit.sh && sudo bash setup_oscp_toolkit.sh
cd /opt/oscp-toolkit && sudo python3 interactive_nmap_launcher_v6.py
# After scan:
sudo python3 exploit_runner.py scan_runs/<workspace>/
# Or via symlinks:
sudo oscp-scan
sudo oscp-exploit
```

---

## Workflow

```
interactive_nmap_launcher_v6.py
  Scan (A/B/C/D/E) → Parse XML → Score against playbook
  → Ranked triage list → searchsploit all banners
  → 25 service follow-up modules (auto-dispatched)
  → CeWL / hash crack / cred spray / post-exploit hints
  → Write triage_handoff.json
        ↓
exploit_runner.py
  Load handoff → Confirmation PoCs → Interactive exploit selection
  → Post-exploit helper → Save updated handoff
```

---

## Scan Modes

| Key | Mode |
|-----|------|
| A | Fast Subnet — top-100 TCP across subnet |
| B | Detailed IP — phase 1 + phase 2 (-p-) + UDP |
| C | Detailed Subnet — parallel per-host full scan |
| D | AD Scan — LDAP, SMB, Kerberos + Timeroasting + BloodHound |
| E | Custom — user-specified ports and scripts |

---

## Follow-Up Modules (25)

HTTP, Vhost, .git, SMB, SMTP, DNS, NFS, SNMP, FTP, LDAP, Redis, MySQL, MSSQL, WinRM, **IPMI**, **Rsync**, **MongoDB**, **NATS**, **IMAP**, **Kubernetes**, **Docker API**, CeWL, exiftool, **BloodHound**, **Timeroasting**

---

## Exploit Modules (35)

FTP anon, Redis unauth, MS17-010, SMB null, NFS export, Tomcat WAR, Drupal, Joomla, LFI chain (wrappers+log poison), SQLi, Vhost, searchsploit, SMB relay, Potato family, AlwaysInstallElevated, WinRM shell, ACL abuse, ASREPRoast, Kerberoast, **Timeroasting**, **NoPAC**, **IPMI hash**, **Rsync anon**, **MongoDB noauth**, **DNS Admins DLL**, **PrintNightmare**, **UAC bypass**, **Docker escape**, **LXC escape**, **ADCS ESC1/ESC4**, **LAPS read**, **DACL abuse**, **Wildcard injection**, **DirtyPipe/kernel CVE**, **Kubernetes token**

---

## Playbook v2.2

| Metric | Count |
|--------|-------|
| Fingerprint entries | 46 (+15) |
| Foothold patterns | 66 (+23) |
| Linux privesc steps | 15 (+7) |
| Windows privesc steps | 8 (+1) |

New patterns: IPMI-HASH-CAPTURE, RSYNC-ANON-READ, MONGODB-NOAUTH, NATS-ENUM, TIMEROASTING, GRAPHQL-ENUM, WEBSOCKET-ATTACK, NOPAC-ESCALATION, ADCS-ESC1, ADCS-ESC4, DACL-GENERICWRITE, BLOODHOUND-COLLECTION, NTLM-RELAY-CAPTURE, RELAY-POTATO, DNS-ADMINS-DLL, PRINTNIGHTMARE, UAC-BYPASS, DOCKER-SOCKET-ESCAPE, LXC-PRIVESC, KUBERNETES-HOSTPATH, LAPS-READ, WILDCARD-INJECTION, KERNEL-CVE-DIRTYPIPE

---

## Setup Script

60 tools installed and checked. Key additions in v6.1:

**Python:** bloodhound, defaultcreds-cheat-sheet
**Binaries:** mongosh, kubeletctl, rustscan, bloodhound-python
**Git clones:** noPac, targetedKerberoast, PrintNightmare PS module
**Privesc depot:** SharpHound, Rubeus, SharpUp, Seatbelt, nc.exe, mimikatz

---

## AD Attack Checklist (D scan auto-prints)

Timeroasting (unauthenticated) → ASREPRoast → Kerberoast → NoPAC →
Pass-the-Hash → BloodHound → LAPS → ADCS ESC1/ESC4 → DACL abuse →
Shadow creds → GPO abuse → Token abuse (GodPotato/PrintSpoofer) →
AlwaysInstallElevated → DNSAdmins DLL → PrintNightmare → DPAPI

---

## SpellBook Integration (v6.1)

172 pages from rusted-silver.github.io/spellbook integrated covering:
Passive recon, active recon, 26 HTTP vulnerability types, 16 service ports,
initial access (RDP/SMB/Timeroast/WinRM), defense evasion, Linux and Windows
privilege escalation, credential looting, discovery, pivoting, lateral movement,
and file transfer.

---

## Version History

| Version | Summary |
|---------|---------|
| v4 | Base launcher |
| v5 | Bug fixes + 6 new service follow-ups + exploit confirmation + cred store |
| v6 | Architecture split: launcher + exploit_runner + shared lib. Vhost, .git, PHP wrappers, CeWL, linpeas serve, hash crack, post-exploit helper, tunneling |
| v6.1 | SpellBook integration: +15 fingerprint entries, +23 patterns, +9 follow-up functions, +16 exploit modules, +5 menu options, +12 setup tool installs |
