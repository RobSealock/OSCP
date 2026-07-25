# AD Enumeration Parity Modules

Add-on tools that bring the OSCP kit's **AD/Windows enumeration** in line with the
`ad-recon-toolkit` (blue-team) coverage. Each closes a specific enumeration gap
the base kit lacked. All four are **offline-installable** (vendored here as
portable `py3-none-any` wheels + one standalone script).

| Tool | ad-recon gap it closes | Command | Vendored as |
|------|------------------------|---------|-------------|
| **ldeep** | Broad LDAP enum: trusts, delegation, gMSA, sIDHistory, PKI/ADCS, silos → structured JSON (closest analogue to AD-Core) | `ldeep` | `wheels/ldeep-2.0.3-py3-none-any.whl` |
| **adidnsdump** | ADIDNS: who can write DNS records, wildcard/WPAD presence | `adidnsdump` | `wheels/adidnsdump-1.4.0-py3-none-any.whl` |
| **pre2k** | Pre-created / `PASSWD_NOTREQD` computer accounts | `pre2k` | `wheels/pre2k-3.0-py3-none-any.whl` |
| **gMSADumper** | gMSA readable managed passwords | `python3 gMSADumper.py` | `gMSADumper/gMSADumper.py` |

> Two more gaps are closed with tools **already on Kali** — no module needed:
> **sIDHistory / AdminSDHolder / object ACLs** via `bloodyAD ... get ...`, and
> **explicit delegation lists** via `impacket-findDelegation`. `netexec` modules
> (`--gmsa`, `-M maq`, `-M user-desc`, `-M laps`, `-M adcs`) cover several as well.

---

## Online install (internet-connected Kali)

```bash
pipx install adidnsdump
pipx install ldeep
pipx install git+https://github.com/garrettfoster13/pre2k     # pre2k is git-only
# gMSADumper is a standalone script:
sudo install -m0755 gMSADumper/gMSADumper.py /opt/oscp-toolkit/modules/gMSADumper/gMSADumper.py
```

## Offline install (airgapped Kali) — primary path

Uses only the vendored wheels here. Works when the standard Kali runtime deps
(`impacket`, `ldap3`, `dnspython`, `pycryptodomex`) are present — which they are
on a stock Kali.

```bash
sudo ./install-offline.sh              # installs wheels --no-index, stages gMSADumper
# verify:
adidnsdump -h ; ldeep -h ; pre2k -h ; python3 gMSADumper/gMSADumper.py -h
```

## Offline install — hardened/minimal airgap (full dependency closure)

If the target Kali is missing runtime deps, the `--no-deps` path above will fail
at runtime. Some deps (e.g. `pycryptodomex`, `cryptography`) are **compiled**, so
they must be built/downloaded on a Kali whose `python3` version matches the target
— they cannot be pre-vendored generically. Build the complete bundle on a
connected, matching-Python Kali:

```bash
./build-offline-bundle.sh              # creates ./wheelhouse with tools + all deps
# carry ./wheelhouse into the airgap, then:
pip install --no-index --find-links wheelhouse adidnsdump ldeep pre2k --break-system-packages
```

> **Isolation option:** to avoid `--break-system-packages`, install into a venv:
> `python3 -m venv /opt/oscp-toolkit/adenv && /opt/oscp-toolkit/adenv/bin/pip install --no-index --no-deps wheels/*.whl`
> and call the tools via that venv's `bin/`.

---

## Usage (authenticated as a normal domain user)

```bash
# ldeep — dump everything to JSON (trusts, delegation, gMSA, sIDHistory, PKI, silos...)
ldeep ldap -u USER -p 'PASS' -d DOMAIN.LOCAL -s ldap://DC_IP all /tmp/ldeep_out
# targeted examples:
ldeep ldap -u USER -p 'PASS' -d DOMAIN.LOCAL -s ldap://DC_IP trusts
ldeep ldap -u USER -p 'PASS' -d DOMAIN.LOCAL -s ldap://DC_IP delegation
ldeep ldap -u USER -p 'PASS' -d DOMAIN.LOCAL -s ldap://DC_IP sid_history

# adidnsdump — enumerate ADIDNS records / zones (spot wildcard, wpad, isatap)
adidnsdump -u 'DOMAIN\USER' -p 'PASS' DC_IP --print-zones

# pre2k — find/validate pre-created (PASSWD_NOTREQD) computer accounts
pre2k auth -u USER -p 'PASS' -d DOMAIN.LOCAL -dc-ip DC_IP
pre2k unauth -d DOMAIN.LOCAL -dc-ip DC_IP          # no creds, from a computer list

# gMSADumper — retrieve gMSA managed passwords you're allowed to read
python3 gMSADumper/gMSADumper.py -u USER -p 'PASS' -d DOMAIN.LOCAL

# already-on-Kali gap closers:
impacket-findDelegation -dc-ip DC_IP DOMAIN.LOCAL/USER:'PASS'
bloodyAD -u USER -p 'PASS' -d DOMAIN.LOCAL --host DC_IP get search --filter '(sIDHistory=*)' --attr sAMAccountName,sIDHistory
netexec ldap DC_IP -u USER -p 'PASS' --gmsa -M maq -M user-desc
```

## Offline-vendorability summary (asked: is it possible?)

| Tool | On PyPI? | Vendored form | Fully offline? |
|------|----------|---------------|----------------|
| adidnsdump | yes | portable wheel | ✅ yes |
| ldeep | yes (sdist) | wheel built here | ✅ yes |
| pre2k | **no — git only** | wheel built from source here | ✅ yes |
| gMSADumper | no | standalone script | ✅ yes |

The tools themselves are 100% offline-vendorable. The **only** caveat is their
shared runtime dependencies on a *minimal* airgap — handled by
`build-offline-bundle.sh`. On a standard Kali, `install-offline.sh` is sufficient.

## Attribution

adidnsdump & bloodyAD (dirkjanm), ldeep (franc-pentest), pre2k (garrettfoster13),
gMSADumper (micahvandeusen), impacket/netexec (Fortra / community). All third-party;
see each project for licensing. Vendored here for airgapped range use only.
