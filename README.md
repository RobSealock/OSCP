# OSCP Toolkit v6.2

Authorized reconnaissance, triage, and exploit-execution toolkit for HTB / CTF / OSCP exam-prep.

Integrated content from:
- **SpellBook** (rusted-silver.github.io/spellbook) — 172 pages
- **0xsyr0/OSCP** — most actively maintained OSCP+ cheatsheet (~5k stars)
- **saisathvik1/OSCP-Cheatsheet** — exam-proven May 2024
- **crtvrffnrt/OSCP-Checklist-Cheatsheet2024** — process checklists + Library-ms
- **n0xturne/OSCP-Cheat-Sheet-2024** — DCC2, phar/zip LFI, password mutation
- **BlessedRebuS/OSCP-Pentesting-Cheatsheet** — NTLM relay chains, PowerUp
- **swisskyrepo/PayloadsAllTheThings** — payload reference (~65k stars)

> **Authorized use only.** Run against systems you own or have explicit written permission to test.

---

## Files

| File | Description | Lines |
|------|-------------|-------|
| `interactive_nmap_launcher_v6.py` | Scanner, triage, recon engine | 2,076 |
| `exploit_runner.py` | Interactive exploit execution | 2,274 |
| `oscp_toolkit_lib.py` | Shared types, helpers, credential store | 406 |
| `OSCP_playbook_enhanced_yaml.txt` | 78 foothold patterns, 55 fingerprint entries | 2,704 |
| `setup_oscp_toolkit_v6.sh` | One-shot installer, 76 tools checked | 702 |
| `README.md` | This file | — |

---

## Quick Start

```bash
# 1. Install everything
chmod +x setup_oscp_toolkit_v6.sh
sudo bash setup_oscp_toolkit_v6.sh

# 2. Run the scanner (from toolkit dir so playbook is found)
cd /opt/oscp-toolkit
sudo python3 interactive_nmap_launcher_v6.py
# or via symlink:
sudo oscp-scan

# 3. After scanning, launch the exploit runner
sudo python3 exploit_runner.py scan_runs/<workspace>/
# or auto-find latest scan:
sudo oscp-exploit
```

---

## Installed Tool Locations

```
/opt/oscp-toolkit/          Main toolkit
/opt/privesc/               Served to targets via HTTP (linpeas, winPEAS, Rubeus, etc.)
/opt/noPac/                 CVE-2021-42278/42287 DA escalation
/opt/targetedKerberoast/    GenericWrite Kerberoasting
/opt/PrintNightmare/        CVE-2021-34527 PowerShell module
/opt/php_filter_chain_generator/  LFI→RCE without writable files
/opt/SharpEfsPotato/        SeImpersonate via EFS (Server 2019/2022)
/opt/BadSuccessor/          dMSA privilege escalation (2025)
/opt/ligolo-ng/             Tunneling proxy binary
```

---

## Workflow

```
interactive_nmap_launcher_v6.py
  ├── Scan modes A/B/C/D/E
  ├── Parse Nmap XML → score against playbook → ranked triage list
  ├── searchsploit all product/version banners
  ├── 31 service follow-up modules (auto-dispatched)
  ├── KeePass hunt, CeWL wordlist, hash crack, cred spray
  ├── Password mutation tips (best64, OneRuleToRuleThemAll, cupp, crunch)
  ├── Post-exploit one-liners (auto-shown if score ≥ 8)
  └── Write triage_handoff.json
              ↓
exploit_runner.py
  ├── Load ranked findings + credential store
  ├── [c] Confirmation PoC layer (non-destructive)
  ├── [1-N] Select finding → exploit module (confirm each action)
  ├── [17 menu keys for quick access]
  └── Save updated handoff
```

---

## Scan Modes

| Key | Mode | Description |
|-----|------|-------------|
| A | Fast Subnet | Top-100 TCP across full subnet |
| B | Detailed IP | Phase 1 (top-1000 + NSE) → Phase 2 (full -p-) → UDP |
| C | Detailed Subnet | Host discovery + parallel full scan per live host |
| D | AD Scan | LDAP, SMB, Kerberos + Timeroasting + BloodHound + GPP |
| E | Custom | User-specified ports and NSE scripts |

---

## Service Follow-Up Modules (31)

| Service | Port(s) | Key Tools |
|---------|---------|-----------|
| HTTP/HTTPS | 80,443,8080,8443 | whatweb, nikto, ffuf, wpscan, droopescan, joomscan, LFI fuzz, PHP wrappers, log poison, WebDAV probe, NoSQL hints, phar/zip wrappers, SQL truncation, PHP filter chain hint |
| Vhost | any HTTP | ffuf Host-header fuzz against discovered/default hostnames |
| .git exposure | any HTTP | curl probe, git-dumper, trufflehog |
| SMB | 139,445 | smbclient, enum4linux, netexec null+guest+GPP check |
| SMTP | 25,465,587 | NSE smtp-*, smtp-user-enum VRFY/EXPN/RCPT |
| DNS | 53 | NSE zone-transfer, dnsrecon, dig axfr |
| NFS | 2049 | showmount, NSE nfs-ls/statfs |
| SNMP | 161,162 | snmpwalk public/private/manager |
| FTP | 21 | NSE ftp-anon/syst/bounce |
| LDAP | 389,636,3268 | NSE ldap* |
| Redis | 6379 | redis-cli PING/INFO/CONFIG/KEYS |
| MySQL | 3306 | NSE mysql-info/empty-password/databases |
| MSSQL | 1433 | NSE ms-sql-*, netexec mssql |
| WinRM | 5985,5986 | NSE, netexec winrm |
| **IPMI** | 623 UDP | NSE ipmi-version, MSF dumphashes hint |
| **Rsync** | 873 | nc probe, module listing, anon download |
| **MongoDB** | 27017-27019 | NSE mongodb-info, mongosh databases |
| **NATS** | 4222,8222 | curl varz/subsz, natscli hints |
| **IMAP** | 143,993 | NSE imap-capabilities, openssl/curl hints |
| **Kubernetes** | 10250,10255,6443 | kubeletctl pods/rce, curl kubelet API |
| **Docker API** | 2375,2376 | Docker remote API, container escape hint |
| **PostgreSQL** | 5432 | NSE pgsql-brute, psql connect, COPY FROM PROGRAM hint |
| **Memcached** | 11211 | NSE memcached-info, telnet dump |
| **WebDAV** | any HTTP | davtest, cadaver, curl PUT |
| **SVN** | 3690 | NSE svn-brute, svn checkout |
| CeWL | any HTTP | spider for domain-specific wordlist |
| exiftool | workspace | metadata from discovered files |
| **BloodHound** | AD scan | bloodhound-python ALL collection |
| **Timeroasting** | AD scan | nxc timeroast → hashcat -m 31300 |
| **GPP** | AD scan + SMB | netexec gpp_password module, SYSVOL search |
| KeePass hunt | workspace | find .kdbx → keepass2john → hashcat -m 13400 |

---

## Exploit Modules (47)

### Web / Initial Access
| Module | Pattern | Description |
|--------|---------|-------------|
| `_exploit_ftp_anon` | FTP-ANON-UPLOAD | Anonymous curl listing |
| `_exploit_tomcat_war` | TOMCAT-MANAGER | msfvenom WAR + curl deploy |
| `_exploit_drupal` | — | droopescan + CVE hints |
| `_exploit_joomla` | — | joomscan + CVE hints |
| `_exploit_lfi_chain` | LFI | PHP wrappers, log poisoning, proc/self/environ |
| `_exploit_php_filter_chain` | **PHP-FILTER-CHAIN-RCE** | LFI→RCE without log/session file |
| `_exploit_sqli` | SQLI | sqlmap full pipeline + os-shell |
| `_exploit_nosql_injection` | **NOSQL-INJECTION** | MongoDB $ne/$regex/$where auth bypass |
| `_exploit_webdav_shell` | **WEBDAV-UPLOAD** | davtest + cadaver upload + MOVE rename |
| `_exploit_vhost` | — | ffuf Host-header fuzz |
| `_exploit_smb_anon` | SMB-ANON-SHARE-CREDS | null session listing + mount hints |
| `_exploit_nfs_export` | NFS-EXPORTED-SECRETS | showmount + mount + SSH key plant |
| `_exploit_redis_unauth` | REDIS-UNAUTH-PIVOT | INFO/CONFIG dump + webshell path |
| `_exploit_rsync_anon` | RSYNC-ANON-READ | module list + download + writable plant |
| `_exploit_mongodb_noauth` | MONGODB-NOAUTH | mongosh DB/collection dump |
| `_exploit_postgres_rce` | **POSTGRES-COPY-RCE** | superuser COPY FROM PROGRAM RCE |
| `_exploit_memcached_interactive` | MEMCACHED-ENUM | stats + cachedump + get all keys |
| `_exploit_library_ms_phish` | **LIBRARY-MS-PHISH** | generate Library-ms → swaks → Responder NTLMv2 |
| `_exploit_ms17010` | MS17-010-PATTERN | AutoBlue / MSF one-liners |
| `_exploit_searchsploit` | generic | banner → searchsploit |

### Windows Privilege Escalation
| Module | Pattern | Description |
|--------|---------|-------------|
| `_exploit_potato` | RELAY-POTATO | GodPotato / PrintSpoofer / JuicyPotatoNG |
| `_exploit_alwaysinstallelevated` | — | registry check + msfvenom MSI |
| `_exploit_uac_bypass` | UAC-BYPASS | UACMe / eventvwr / fodhelper |
| `_exploit_printnightmare` | PRINTNIGHTMARE | local PS module or remote DLL |
| `_exploit_dns_admins_dll` | DNS-ADMINS-DLL | msfvenom DLL + dnscmd + SMB server |
| `_exploit_lxc_escape` | LXC-PRIVESC | Alpine image + hostPath mount |
| `_exploit_docker_escape` | DOCKER-SOCKET-ESCAPE | privileged container + chroot to host |
| `_exploit_kubernetes_interactive` | KUBERNETES-HOSTPATH | kubeletctl + token extract + kubectl |
| `_exploit_wildcard_injection` | WILDCARD-INJECTION | tar checkpoint filename injection |
| `_exploit_kernel_dirtypipe` | KERNEL-CVE-DIRTYPIPE | DirtyPipe / Netfilter / sudo Baron Samedit |
| `_exploit_keepass` | **KEEPASS-KDBX** | keepass2john + hashcat -m 13400 |
| `_exploit_gpp_cpassword` | **GPP-CPASSWORD** | SYSVOL search + gpp-decrypt |
| `_exploit_dcc2_crack` | **DCC2-HASH-CRACK** | secretsdump + hashcat -m 2100 |

### Active Directory
| Module | Pattern | Description |
|--------|---------|-------------|
| `_exploit_asreproast` | ASREPROAST | impacket-GetNPUsers + hashcat -m 18200 |
| `_exploit_kerberoast` | KERBEROAST | impacket-GetUserSPNs + hashcat -m 13100 |
| `_exploit_timeroasting` | TIMEROASTING | nxc timeroast + hashcat -m 31300 |
| `_exploit_silver_ticket` | **SILVER-TICKET** | impacket-ticketer forge + export KRB5CCNAME |
| `_exploit_silver_rubeus` | — | Rubeus asreproast/kerberoast/golden/silver/PtT guide |
| `_exploit_nopac` | NOPAC-ESCALATION | scanner.py + noPac.py SYSTEM shell |
| `_exploit_ipmi_hash` | IPMI-HASH-CAPTURE | MSF ipmi_dumphashes + hashcat -m 7300 |
| `_exploit_adcs_esc1` | ADCS-ESC1/ESC4 | certipy find + req + auth → NTLM hash |
| `_exploit_laps_read` | LAPS-READ | netexec ldap --module laps + PtH hint |
| `_exploit_dacl_genericwrite` | DACL-GENERICWRITE | bloodyAD GenericAll/WriteDACL/ForceChange |
| `_exploit_winrm_shell` | WINRM-WITH-RECOVERED-CREDS | evil-winrm password or hash |
| `_exploit_smb_relay` | SMB-SIGNING-RELAY | responder + ntlmrelayx |
| `_exploit_acl_abuse` | ACL-ABUSE | bloodyAD + PowerView (legacy) |
| `_exploit_account_operators` | — | create user + add to group via netexec |
| `_bloodhound_interactive` | BLOODHOUND-COLLECTION | bloodhound-python ALL + import hints |

---

## Exploit Runner Menu (17 options)

| Key | Action |
|-----|--------|
| 1–N | Select ranked finding |
| c | Confirmation PoC layer (non-destructive) |
| s | searchsploit all banners |
| h | Hash crack (interactive) |
| p | Post-exploit helper |
| w | Credential spray |
| v | Vhost/subdomain fuzz |
| b | BloodHound collection |
| t | Timeroasting |
| n | NoPAC scan + exploit |
| a | ADCS certipy ESC1/ESC4 |
| l | LAPS password read |
| g | **GPP/cpassword SYSVOL** |
| k | **KeePass .kdbx cracking** |
| i | **Silver Ticket forge** |
| r | **Rubeus Kerberos guide** |
| j/d | Joomscan / Droopescan |
| q | Quit and save handoff |

---

## Playbook v2.2

| Metric | Count |
|--------|-------|
| Fingerprint map entries | **55** |
| Foothold patterns | **78** |
| Linux privesc decision steps | **15** |
| Windows privesc decision steps | **8** |

### All 78 Pattern IDs

**Original 43:** WEB-CONTENT-DISCOVERY, FILE-UPLOAD-BYPASS, SQLI, LFI, SSTI, WORDPRESS-PLUGIN-EXPOSURE, WORDPRESS-CREDS, TOMCAT-MANAGER, JENKINS-CONSOLE-OR-BUILD-ABUSE, SMB-ANON-SHARE-CREDS, SMB-SIGNING-RELAY, MS17-010-PATTERN, FTP-ANON-UPLOAD, NFS-EXPORTED-SECRETS, NFS-MISCONFIG-PRIVESC, SNMP-USER-DISCOVERY, REDIS-UNAUTH-PIVOT, EXPOSED-BACKUP, CREDENTIAL-REUSE, KEY-REUSE, SSH-KEY-BRUTEFORCE, DNS-ENUM, SMTP-ENUM, MAIL-ENUM, DIRECTORY-ENUM, AD-SURFACE, ASREPROAST, KERBEROAST, RPC-ENUM, WINRM-WITH-RECOVERED-CREDS, RDP-WITH-RECOVERED-CREDS, VNC-NO-AUTH, REMOTE-DESKTOP-WITH-RECOVERED-CREDS, DB-CREDENTIAL-DISCOVERY, MSSQL-XPCMD, ELASTICSEARCH-UNAUTH, GHOSTCAT-AJP, JAVA-RMI-EXPLOIT, MIDDLEWARE-ENUM, WEB-STACK-SECONDARY, TARGETED-CREDENTIAL-ATTACK, DEFAULT-CREDS, SERVICE-CORRELATION

**SpellBook (+23):** IPMI-HASH-CAPTURE, RSYNC-ANON-READ, MONGODB-NOAUTH, NATS-ENUM, TIMEROASTING, GRAPHQL-ENUM, WEBSOCKET-ATTACK, NOPAC-ESCALATION, ADCS-ESC1, ADCS-ESC4, DACL-GENERICWRITE, BLOODHOUND-COLLECTION, NTLM-RELAY-CAPTURE, RELAY-POTATO, DNS-ADMINS-DLL, PRINTNIGHTMARE, UAC-BYPASS, DOCKER-SOCKET-ESCAPE, LXC-PRIVESC, KUBERNETES-HOSTPATH, LAPS-READ, WILDCARD-INJECTION, KERNEL-CVE-DIRTYPIPE

**GitHub repos (+12):** GPP-CPASSWORD, DCC2-HASH-CRACK, POSTGRES-COPY-RCE, SILVER-TICKET, KEEPASS-KDBX, LIBRARY-MS-PHISH, NOSQL-INJECTION, BADSUCCESSOR-DMSA, SHARPEFSPOTATO, PHP-FILTER-CHAIN-RCE, WEBDAV-UPLOAD, MEMCACHED-ENUM

---

## Setup Script

**76 tools checked.** Installs in ~5 minutes on Kali.

### New from GitHub Repo Research

**APT packages added:** `cupp`, `crunch`, `swaks`, `cadaver`, `davtest`, `wfuzz`, `postgresql-client`, `gpp-decrypt`, `responder`

**Python packages added:** `keepass2john`, `nosqlmap`

**Git clones added:**
- `/opt/php_filter_chain_generator` — LFI→RCE without any log/session file
- `/opt/SharpEfsPotato` — SeImpersonate via EFS for Server 2019/2022
- `/opt/BadSuccessor` — dMSA privilege escalation (2025, fully patched environments)

**Privesc depot additions:** `SharpEfsPotato.exe`, `Certify.exe`, `SharpView.exe`, `PowerUp.ps1`, `PowerView.ps1`, `accesschk.exe`

### Symlinks Created

```bash
oscp-scan    → interactive_nmap_launcher_v6.py
oscp-scan-v6 → interactive_nmap_launcher_v6.py
oscp-exploit → exploit_runner.py
```

---

## AD Scan Auto-Checklist

Printed and run automatically during AD scan (mode D):

| Step | Tool | Notes |
|------|------|-------|
| Timeroasting | `nxc smb -M timeroast` | Unauthenticated, runs first |
| GPP/SYSVOL | `nxc smb -M gpp_password` | Unauthenticated null session |
| Null session enum | netexec `--shares --users` | No creds required |
| ASREPRoast | `impacket-GetNPUsers` | No pre-auth accounts |
| Kerberoast | `impacket-GetUserSPNs` | Needs domain user |
| BloodHound | `bloodhound-python -c ALL` | Needs domain user, optional |
| NoPAC | `scanner.py + noPac.py` | Exploit runner menu [n] |
| Pass-the-Hash | `psexec/wmiexec/evil-winrm -H` | After hash recovery |
| LAPS | `nxc ldap --module laps` | Exploit runner menu [l] |
| ADCS ESC1/ESC4 | `certipy find -vulnerable` | Exploit runner menu [a] |
| DACL abuse | `bloodyAD + targetedKerberoast` | Exploit runner menu, pattern DACL-GENERICWRITE |
| Shadow creds | `certipy / pywhisker` | When GenericWrite on account |
| GPO abuse | `SharpGPOAbuse` | When GPO write permission |
| Token abuse | GodPotato / PrintSpoofer / SharpEfsPotato | SeImpersonatePrivilege |
| AlwaysInstallElevated | registry + msfvenom MSI | Exploit runner menu |
| DNS Admins DLL | `dnscmd + msfvenom` | Exploit runner pattern DNS-ADMINS-DLL |
| PrintNightmare | `rpcdump + CVE-2021-1675.ps1` | Exploit runner pattern PRINTNIGHTMARE |
| DPAPI | `donpapi + netexec --dpapi` | Post-compromise cred harvest |
| Silver Ticket | `impacket-ticketer` | Exploit runner menu [i] |
| DCSync | `secretsdump -just-dc-ntds` | DA or DCSync rights required |

---

## Credential Store

Accumulated automatically:
- Anonymous FTP → `anonymous:anonymous`
- Redis no-auth → `(no-auth)`
- GPP cpassword decrypted → stored as `password`
- Cracked hashes → stored with source file reference

Used for: credential spray (netexec), BloodHound collection, PtH, WinRM shell.

---

## Source Integration Summary

| Source | Stars | Content Integrated |
|--------|-------|-------------------|
| rusted-silver SpellBook | — | 172 pages, 23 new patterns, 9 follow-up fns, 16 exploit modules |
| 0xsyr0/OSCP | ~5k | BadSuccessor, SharpEfsPotato, DCC2, PHP filter chain, NoSQL, SQL truncation, wfuzz |
| saisathvik1/OSCP-Cheatsheet | ~1k | GPP/cpassword full chain, KeePass hunting, Rubeus guide, Silver tickets |
| crtvrffnrt/OSCP-Checklist | ~500 | Library-ms phishing (swaks + Responder), KeePass, DCShadow |
| n0xturne/OSCP-Cheat-Sheet-2024 | ~400 | DCC2 cracking (mode 2100), phar/zip LFI, password mutation rules |
| BlessedRebuS/OSCP-Cheatsheet | ~300 | NTLM relay chain, PowerUp service binary, scheduled task hijack |
| swisskyrepo/PayloadsAllTheThings | ~65k | WebDAV upload chain, NoSQL operators, PHP filter chain reference |

---

## Version History

| Version | Key Changes |
|---------|-------------|
| v4 | Base launcher — two-phase scan, service follow-up |
| v5 | Bug fixes + 6 new services + exploit confirmation + credential store |
| v6 | Architecture split (launcher + exploit_runner + lib). Vhost, .git, PHP wrappers, CeWL, linpeas serve, hash crack, tunneling |
| v6.1 | SpellBook 172-page integration — +23 patterns, +9 follow-up fns, +16 exploit modules, +12 setup tools |
| v6.2 | GitHub repo research (top 10) — +12 patterns, +6 follow-up fns, +12 exploit modules, +9 apt tools, +3 git clones, +6 privesc downloads. New: GPP, DCC2, PostgreSQL RCE, Silver Ticket, KeePass, Library-ms phishing, NoSQL, PHP filter chain, WebDAV, Memcached, Rubeus guide, Account Operators |
