#!/usr/bin/env bash
# install-offline.sh — offline install of the AD-enum parity modules on Kali.
# Uses ONLY the vendored wheels in ./wheels (no internet). Relies on Kali's
# system Python deps (impacket, ldap3, dnspython, pycryptodomex), which ship on
# a standard Kali. gMSADumper is staged as a standalone script.
#
# If a tool later fails at runtime on a missing dependency, your target is a
# minimal/hardened box — build a full closure with build-offline-bundle.sh on a
# connected Kali of the SAME python3 version, then use the full-install one-liner
# in README.md.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAGE="${1:-/opt/oscp-toolkit/modules}"

echo "[*] Installing vendored wheels (offline, --no-index --no-deps)..."
# --break-system-packages: Kali's system Python is PEP-668 externally-managed.
# These are pure-python tools; installing them system-wide on a pentest box is fine.
# Prefer a venv/pipx if you want isolation (see README).
python3 -m pip install --no-index --no-deps --break-system-packages "$HERE"/wheels/*.whl

echo "[*] Staging gMSADumper.py -> $STAGE/gMSADumper/"
mkdir -p "$STAGE/gMSADumper"
install -m 0755 "$HERE/gMSADumper/gMSADumper.py" "$STAGE/gMSADumper/gMSADumper.py"

echo "[*] Verifying entry-point commands..."
for c in adidnsdump ldeep pre2k; do
  if command -v "$c" >/dev/null 2>&1; then
    echo "    [+] $c -> $(command -v "$c")"
  else
    echo "    [!] $c not on PATH — check ~/.local/bin or /usr/local/bin"
  fi
done
echo "    [i] gMSADumper: python3 $STAGE/gMSADumper/gMSADumper.py -h"
echo "[*] Done."
