#!/usr/bin/env bash
# build-offline-bundle.sh — run on an INTERNET-CONNECTED Kali whose python3
# MAJOR.MINOR matches the airgapped target. Produces ./wheelhouse containing the
# tools AND their FULL dependency closure (some deps are compiled and must match
# the target's Python/arch — this is why the closure is built on Kali, not vendored).
#
# Then carry ./wheelhouse into the airgap and run the full-install one-liner:
#   pip install --no-index --find-links wheelhouse adidnsdump ldeep pre2k --break-system-packages
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/wheelhouse"
mkdir -p "$OUT"

echo "[*] Downloading adidnsdump + ldeep with full dependency closure..."
python3 -m pip download adidnsdump ldeep -d "$OUT"

echo "[*] Building pre2k wheel from git (git-only, not on PyPI)..."
python3 -m pip wheel "git+https://github.com/garrettfoster13/pre2k" --no-deps -w "$OUT"

echo "[*] Copying vendored gMSADumper into the bundle..."
mkdir -p "$OUT/gMSADumper"; cp "$HERE/gMSADumper/gMSADumper.py" "$OUT/gMSADumper/"

echo "[*] Wheelhouse ready: $OUT ($(ls "$OUT" | wc -l) files)."
echo "    Airgap install: pip install --no-index --find-links '$OUT' adidnsdump ldeep pre2k --break-system-packages"
