#!/usr/bin/env bash
# =============================================================================
#  setup_oscp_toolkit.sh  —  v6
#  One-shot setup for OSCP Toolkit v6
#  (launcher + exploit_runner + shared library + playbook)
#
#  Authorized lab / CTF / exam-prep use only
#
#  Usage:
#    chmod +x setup_oscp_toolkit.sh
#    sudo bash setup_oscp_toolkit.sh
#
#  Then run:
#    cd /opt/oscp-toolkit && sudo python3 interactive_nmap_launcher_v6.py
#  Or via symlink:
#    sudo oscp-scan
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[x]${RESET} $*"; }
header()  { echo -e "\n${BOLD}${CYAN}==============================${RESET}";
            echo -e "${BOLD}${CYAN}  $*${RESET}";
            echo -e "${BOLD}${CYAN}==============================${RESET}"; }

if [[ $EUID -ne 0 ]]; then
    error "Run with sudo: sudo bash setup_oscp_toolkit.sh"
    exit 1
fi

REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6 2>/dev/null || echo "/root")
INSTALL_DIR="/opt/oscp-toolkit"
PRIVESC_DIR="/opt/privesc"

clear
echo -e "${BOLD}${RED}"
cat << 'EOF'
  OSCP Toolkit v6 -- Setup
  launcher + exploit_runner + shared lib + playbook
  Authorized lab / CTF / exam-prep use only
EOF
echo -e "${RESET}"

# ─────────────────────────────────────────────
# STEP 1 — System packages
# ─────────────────────────────────────────────
header "STEP 1 -- System Packages"

APT_PACKAGES=(
    nmap python3 python3-pip python3-venv curl wget git
    xsltproc
    nikto whatweb
    smbclient enum4linux
    snmp snmp-mibs-downloader
    redis-tools
    dnsutils dnsrecon
    nfs-common rpcbind
    smtp-user-enum
    sqlmap
    joomscan
    libimage-exiftool-perl
    cewl
    hashid
    exploitdb
    hashcat john
    gobuster
    # NEW: From GitHub repo research
    cupp               # target-specific wordlist generator
    crunch             # pattern-based wordlist generation
    swaks              # SMTP test tool / Library-ms phishing
    cadaver            # WebDAV interactive client
    davtest            # WebDAV extension testing
    wfuzz              # Web fuzzer alternative to ffuf
    postgresql-client  # psql CLI for PostgreSQL enumeration
    gpp-decrypt        # decrypt GPP cpassword values
    responder          # NTLM hash capture via multiple protocols
    jq netcat-openbsd pipx ruby ruby-dev build-essential
    ncat rlwrap
)

info "Updating apt cache..."
apt-get update -qq

MISSING_APT=()
for pkg in "${APT_PACKAGES[@]}"; do
    dpkg -s "$pkg" &>/dev/null 2>&1 || MISSING_APT+=("$pkg")
done

if [[ ${#MISSING_APT[@]} -gt 0 ]]; then
    info "Installing: ${MISSING_APT[*]}"
    apt-get install -y -qq "${MISSING_APT[@]}" 2>/dev/null \
        || warn "Some packages failed -- continuing."
else
    success "All apt packages already installed."
fi

# ─────────────────────────────────────────────
# STEP 2 — Python packages
# ─────────────────────────────────────────────
header "STEP 2 -- Python Packages"

PYTHON_PACKAGES=(
    pyyaml
    requests
    lxml
    impacket
    droopescan          # Drupal/Silverstripe scanner
    git-dumper          # .git directory extraction
    trufflehog          # Secret scanning in repos
    donpapi             # DPAPI credential extraction
    bloodyAD            # ACL/ACE manipulation
    certipy-ad          # ADCS / shadow credentials
    pywhisker           # Shadow credentials via msDS-KeyCredentialLink
    bloodhound          # bloodhound-python AD collector
    defaultcreds-cheat-sheet  # creds search <service> CLI
    # NEW: From GitHub repo research
    keepass2john        # extract hash from KeePass .kdbx files
    nosqlmap            # NoSQL injection automation
    impacket-Get-GPPPassword  # GPP cpassword extraction
)

for pkg in "${PYTHON_PACKAGES[@]}"; do
    info "  Installing ${pkg}..."
    pip3 install --quiet --break-system-packages "$pkg" 2>/dev/null \
        || pip3 install --quiet "$pkg" 2>/dev/null \
        || warn "  Failed: ${pkg} -- install manually: pip3 install ${pkg}"
done
success "Python packages done."

# ─────────────────────────────────────────────
# STEP 3 — External tools
# ─────────────────────────────────────────────
header "STEP 3 -- External Tools"

# ffuf
if command -v ffuf &>/dev/null; then
    success "ffuf already installed"
else
    info "Installing ffuf..."
    FFUF_VER=$(curl -s https://api.github.com/repos/ffuf/ffuf/releases/latest \
               | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'])" 2>/dev/null \
               || echo "v2.1.0")
    FFUF_URL="https://github.com/ffuf/ffuf/releases/download/${FFUF_VER}/ffuf_${FFUF_VER#v}_linux_amd64.tar.gz"
    TMP=$(mktemp -d)
    curl -sL "$FFUF_URL" -o "${TMP}/ffuf.tar.gz" 2>/dev/null \
        && tar -xzf "${TMP}/ffuf.tar.gz" -C "$TMP" 2>/dev/null \
        && mv "${TMP}/ffuf" /usr/local/bin/ffuf \
        && chmod +x /usr/local/bin/ffuf \
        && success "ffuf installed" \
        || warn "ffuf download failed -- get from https://github.com/ffuf/ffuf/releases"
    rm -rf "$TMP"
fi

# netexec / crackmapexec
_install_netexec() {
    pip3 install --quiet --break-system-packages netexec 2>/dev/null \
        || pip3 install --quiet netexec 2>/dev/null \
        || return 1
    for DIR in /usr/local/bin /root/.local/bin "${REAL_HOME}/.local/bin" /usr/bin; do
        if [[ -x "${DIR}/netexec" && "${DIR}" != "/usr/local/bin" ]]; then
            ln -sf "${DIR}/netexec" /usr/local/bin/netexec 2>/dev/null || true
        fi
    done
    return 0
}

if command -v netexec &>/dev/null || [[ -x /usr/local/bin/netexec ]]; then
    success "netexec already installed"
elif command -v crackmapexec &>/dev/null; then
    success "crackmapexec already installed"
else
    _install_netexec && success "netexec installed" \
        || warn "netexec install failed -- try: pip3 install netexec"
fi

# wpscan
command -v wpscan &>/dev/null \
    && success "wpscan already installed" \
    || { gem install wpscan --quiet 2>/dev/null && success "wpscan installed" \
         || warn "wpscan install failed"; }

# evil-winrm
command -v evil-winrm &>/dev/null \
    && success "evil-winrm already installed" \
    || { gem install evil-winrm --quiet 2>/dev/null && success "evil-winrm installed" \
         || warn "evil-winrm install failed"; }

# impacket
if command -v impacket-GetNPUsers &>/dev/null || [[ -f /usr/local/bin/impacket-GetNPUsers ]]; then
    success "impacket already installed"
else
    pip3 install --quiet --break-system-packages impacket 2>/dev/null \
        || warn "impacket install failed."
fi

# Symlink impacket tools
for IMPTOOL in impacket-GetNPUsers impacket-GetUserSPNs impacket-psexec \
               impacket-wmiexec impacket-smbexec impacket-ntlmrelayx impacket-secretsdump; do
    for DIR in /root/.local/bin "${REAL_HOME}/.local/bin" /usr/local/lib/python3*/dist-packages/impacket; do
        if [[ -x "${DIR}/${IMPTOOL}" ]]; then
            ln -sf "${DIR}/${IMPTOOL}" "/usr/local/bin/${IMPTOOL}" 2>/dev/null || true
            break
        fi
    done
done

# Ligolo-ng (tunneling)
LIGOLO_DIR="/opt/ligolo-ng"
if [[ -f "${LIGOLO_DIR}/proxy" ]]; then
    success "ligolo-ng already installed"
else
    info "Downloading ligolo-ng..."
    LIGOLO_VER=$(curl -s https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest \
                 | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'])" 2>/dev/null \
                 || echo "v0.6.2")
    mkdir -p "$LIGOLO_DIR"
    TMP=$(mktemp -d)
    curl -sL "https://github.com/nicocha30/ligolo-ng/releases/download/${LIGOLO_VER}/ligolo-ng_proxy_${LIGOLO_VER#v}_linux_amd64.tar.gz" \
         -o "${TMP}/ligolo.tar.gz" 2>/dev/null \
        && tar -xzf "${TMP}/ligolo.tar.gz" -C "$LIGOLO_DIR" 2>/dev/null \
        && chmod +x "${LIGOLO_DIR}/proxy" \
        && ln -sf "${LIGOLO_DIR}/proxy" /usr/local/bin/ligolo-proxy \
        && success "ligolo-ng installed" \
        || warn "ligolo-ng download failed -- https://github.com/nicocha30/ligolo-ng/releases"
    rm -rf "$TMP"
fi

# Chisel (tunneling)
if command -v chisel &>/dev/null || [[ -f /usr/local/bin/chisel ]]; then
    success "chisel already installed"
else
    info "Downloading chisel..."
    CHISEL_VER=$(curl -s https://api.github.com/repos/jpillora/chisel/releases/latest \
                 | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'])" 2>/dev/null \
                 || echo "v1.9.1")
    TMP=$(mktemp -d)
    curl -sL "https://github.com/jpillora/chisel/releases/download/${CHISEL_VER}/chisel_${CHISEL_VER#v}_linux_amd64.gz" \
         -o "${TMP}/chisel.gz" 2>/dev/null \
        && gunzip "${TMP}/chisel.gz" \
        && mv "${TMP}/chisel" /usr/local/bin/chisel \
        && chmod +x /usr/local/bin/chisel \
        && success "chisel installed" \
        || warn "chisel download failed"
    rm -rf "$TMP"
fi

# ── mongosh (MongoDB shell) ───────────────────────────────────────────────────
if command -v mongosh &>/dev/null; then
    success "mongosh already installed"
else
    info "Installing mongosh..."
    TMP=$(mktemp -d)
    MONGOSH_VER="2.5.10"
    MONGOSH_DEB="mongodb-mongosh_${MONGOSH_VER}_amd64.deb"
    MONGOSH_URL="https://downloads.mongodb.com/compass/${MONGOSH_DEB}"
    if curl -sL "$MONGOSH_URL" -o "${TMP}/${MONGOSH_DEB}" 2>/dev/null; then
        dpkg -i "${TMP}/${MONGOSH_DEB}" 2>/dev/null \
            && success "mongosh installed" \
            || warn "mongosh dpkg install failed — manual: dpkg -i ${MONGOSH_DEB}"
    else
        warn "mongosh download failed. Get from: https://www.mongodb.com/try/download/shell"
    fi
    rm -rf "$TMP"
fi

# ── kubeletctl (Kubernetes kubelet client) ────────────────────────────────────
if command -v kubeletctl &>/dev/null || [[ -f /usr/local/bin/kubeletctl ]]; then
    success "kubeletctl already installed"
else
    info "Installing kubeletctl..."
    KUBELETCTL_URL="https://github.com/cyberark/kubeletctl/releases/latest/download/kubeletctl_linux_amd64"
    curl -sL "$KUBELETCTL_URL" -o /usr/local/bin/kubeletctl 2>/dev/null \
        && chmod +x /usr/local/bin/kubeletctl \
        && success "kubeletctl installed" \
        || warn "kubeletctl download failed — https://github.com/cyberark/kubeletctl/releases"
fi

# ── RustScan (fast port scanner) ─────────────────────────────────────────────
if command -v rustscan &>/dev/null || [[ -f /usr/local/bin/rustscan ]]; then
    success "rustscan already installed"
else
    info "Installing rustscan..."
    RUSTSCAN_VER="2.4.1"
    RUSTSCAN_URL="https://github.com/bee-san/RustScan/releases/download/${RUSTSCAN_VER}/x86_64-linux-rustscan.tar.gz.zip"
    TMP=$(mktemp -d)
    if curl -sL "$RUSTSCAN_URL" -o "${TMP}/rustscan.tar.gz.zip" 2>/dev/null; then
        cd "$TMP" && unzip -q rustscan.tar.gz.zip 2>/dev/null \
            && tar -xzf x86_64-linux-rustscan.tar.gz 2>/dev/null \
            && mv rustscan /usr/local/bin/rustscan \
            && chmod +x /usr/local/bin/rustscan \
            && success "rustscan installed" \
            || warn "rustscan extract failed"
        cd - >/dev/null
    else
        warn "rustscan download failed — https://github.com/bee-san/RustScan/releases"
    fi
    rm -rf "$TMP"
fi

# ── bloodhound-python (AD collector) ─────────────────────────────────────────
if command -v bloodhound-python &>/dev/null || python3 -c "import bloodhound" &>/dev/null 2>&1; then
    success "bloodhound-python already installed"
else
    info "Installing bloodhound-python..."
    pip3 install --quiet --break-system-packages bloodhound 2>/dev/null \
        || pip3 install --quiet bloodhound 2>/dev/null \
        || warn "bloodhound-python install failed — pip3 install bloodhound"
fi

# ── noPac (CVE-2021-42278/42287) ─────────────────────────────────────────────
NOPAC_DIR="/opt/noPac"
if [[ -f "${NOPAC_DIR}/noPac.py" ]]; then
    success "noPac already cloned at ${NOPAC_DIR}"
else
    info "Cloning noPac..."
    git clone --quiet https://github.com/Ridter/noPac.git "$NOPAC_DIR" 2>/dev/null \
        && success "noPac cloned to ${NOPAC_DIR}" \
        || warn "noPac clone failed — git clone https://github.com/Ridter/noPac.git"
fi

# ── targetedKerberoast ────────────────────────────────────────────────────────
TKRB_DIR="/opt/targetedKerberoast"
if [[ -f "${TKRB_DIR}/targetedKerberoast.py" ]]; then
    success "targetedKerberoast already cloned"
else
    info "Cloning targetedKerberoast..."
    git clone --quiet https://github.com/ShutdownRepo/targetedKerberoast.git "$TKRB_DIR" 2>/dev/null \
        && pip3 install --quiet --break-system-packages -r "${TKRB_DIR}/requirement.txt" 2>/dev/null \
        && success "targetedKerberoast cloned to ${TKRB_DIR}" \
        || warn "targetedKerberoast clone failed"
fi

# ── CVE-2021-1675 PrintNightmare PS module ────────────────────────────────────
PNIGHTMARE_DIR="/opt/PrintNightmare"
if [[ -f "${PNIGHTMARE_DIR}/CVE-2021-1675.ps1" ]]; then
    success "PrintNightmare PS module already present"
else
    info "Downloading PrintNightmare PS module..."
    mkdir -p "$PNIGHTMARE_DIR"
    curl -sL "https://github.com/calebstewart/CVE-2021-1675/raw/main/CVE-2021-1675.ps1" \
         -o "${PNIGHTMARE_DIR}/CVE-2021-1675.ps1" 2>/dev/null \
        && success "PrintNightmare PS module downloaded" \
        || warn "PrintNightmare download failed"
fi

# ── php_filter_chain_generator (LFI→RCE without writable files) ──────────────
PHPCHAIN_DIR="/opt/php_filter_chain_generator"
if [[ -f "${PHPCHAIN_DIR}/php_filter_chain_generator.py" ]]; then
    success "php_filter_chain_generator already cloned"
else
    info "Cloning php_filter_chain_generator..."
    git clone --quiet https://github.com/synacktiv/php_filter_chain_generator.git \
        "$PHPCHAIN_DIR" 2>/dev/null \
        && success "php_filter_chain_generator cloned to ${PHPCHAIN_DIR}" \
        || warn "php_filter_chain_generator clone failed"
fi

# ── SharpEfsPotato (SeImpersonate via EFS) ───────────────────────────────────
SHARPEFS_DIR="/opt/SharpEfsPotato"
if [[ -f "${SHARPEFS_DIR}/SharpEfsPotato.exe" ]]; then
    success "SharpEfsPotato already present"
else
    info "Downloading SharpEfsPotato..."
    mkdir -p "$SHARPEFS_DIR"
    curl -sL "https://github.com/bugch3ck/SharpEfsPotato/releases/latest/download/SharpEfsPotato.exe" \
         -o "${SHARPEFS_DIR}/SharpEfsPotato.exe" 2>/dev/null \
        && cp "${SHARPEFS_DIR}/SharpEfsPotato.exe" "${PRIVESC_DIR}/SharpEfsPotato.exe" 2>/dev/null \
        && success "SharpEfsPotato downloaded" \
        || warn "SharpEfsPotato download failed — https://github.com/bugch3ck/SharpEfsPotato"
fi

# ── BadSuccessor (dMSA privilege escalation — 2025) ──────────────────────────
BADSUCC_DIR="/opt/BadSuccessor"
if [[ -d "$BADSUCC_DIR" ]]; then
    success "BadSuccessor already cloned"
else
    info "Cloning BadSuccessor..."
    git clone --quiet https://github.com/akamai/BadSuccessor.git \
        "$BADSUCC_DIR" 2>/dev/null \
        && success "BadSuccessor cloned to ${BADSUCC_DIR}" \
        || warn "BadSuccessor clone failed — https://github.com/akamai/BadSuccessor"
fi

# ── PowerUp.ps1 (Windows privilege escalation checks) ────────────────────────
if [[ -f "${PRIVESC_DIR}/PowerUp.ps1" ]]; then
    success "PowerUp.ps1 already in ${PRIVESC_DIR}"
else
    info "Downloading PowerUp.ps1..."
    curl -sL "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1" \
         -o "${PRIVESC_DIR}/PowerUp.ps1" 2>/dev/null \
        && success "PowerUp.ps1 downloaded" \
        || warn "PowerUp.ps1 download failed"
fi

# ── PowerView.ps1 (AD enumeration) ───────────────────────────────────────────
if [[ -f "${PRIVESC_DIR}/PowerView.ps1" ]]; then
    success "PowerView.ps1 already in ${PRIVESC_DIR}"
else
    info "Downloading PowerView.ps1..."
    curl -sL "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1" \
         -o "${PRIVESC_DIR}/PowerView.ps1" 2>/dev/null \
        && success "PowerView.ps1 downloaded" \
        || warn "PowerView.ps1 download failed"
fi

# ── accesschk.exe (Sysinternals — service/file permission checks) ────────────
if [[ -f "${PRIVESC_DIR}/accesschk.exe" ]]; then
    success "accesschk.exe already in ${PRIVESC_DIR}"
else
    info "Downloading accesschk.exe (Sysinternals)..."
    curl -sL "https://live.sysinternals.com/accesschk.exe" \
         -o "${PRIVESC_DIR}/accesschk.exe" 2>/dev/null \
        && success "accesschk.exe downloaded" \
        || warn "accesschk.exe download failed — get from https://live.sysinternals.com/accesschk64.exe"
fi

# vulners NSE script
VULNERS_PATH="/usr/share/nmap/scripts/vulners.nse"
[[ -f "$VULNERS_PATH" ]] && success "vulners.nse present" || {
    curl -sL "https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse" \
         -o "$VULNERS_PATH" 2>/dev/null \
        && nmap --script-updatedb -q 2>/dev/null \
        && success "vulners.nse installed" \
        || warn "vulners.nse download failed"
}

# ── Privesc scripts (served to targets via HTTP) ──
mkdir -p "$PRIVESC_DIR"

declare -A PRIVESC_URLS=(
    ["GodPotato-NET4.exe"]="https://github.com/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET4.exe"
    ["PrintSpoofer64.exe"]="https://github.com/itm4n/PrintSpoofer/releases/latest/download/PrintSpoofer64.exe"
    ["JuicyPotatoNG.exe"]="https://github.com/antonioCoco/JuicyPotatoNG/releases/latest/download/JuicyPotatoNG.exe"
    ["linpeas.sh"]="https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh"
    ["winPEASx64.exe"]="https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe"
    ["nc.exe"]="https://github.com/int0x33/nc.exe/raw/master/nc.exe"
    ["SharpHound.exe"]="https://github.com/BloodHoundAD/SharpHound/releases/latest/download/SharpHound.exe"
    ["Rubeus.exe"]="https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe"
    ["SharpUp.exe"]="https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/SharpUp.exe"
    ["Seatbelt.exe"]="https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Seatbelt.exe"
    ["mimikatz.exe"]="https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip"
    # NEW: From GitHub repo research
    ["SharpEfsPotato.exe"]="https://github.com/bugch3ck/SharpEfsPotato/releases/latest/download/SharpEfsPotato.exe"
    ["Certify.exe"]="https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Certify.exe"
    ["SharpView.exe"]="https://github.com/tevora-threat/SharpView/releases/latest/download/SharpView.exe"
)

for FNAME in "${!PRIVESC_URLS[@]}"; do
    FPATH="${PRIVESC_DIR}/${FNAME}"
    if [[ -f "$FPATH" ]]; then
        success "  ${FNAME} already in ${PRIVESC_DIR}"
    else
        info "  Downloading ${FNAME}..."
        curl -sL "${PRIVESC_URLS[$FNAME]}" -o "$FPATH" 2>/dev/null \
            && chmod +x "$FPATH" \
            && success "  ${FNAME} downloaded" \
            || warn "  ${FNAME} download failed"
    fi
done

# ─────────────────────────────────────────────
# STEP 3b — Wordlists
# ─────────────────────────────────────────────
header "STEP 3b -- Wordlists"

if [[ -f /usr/share/wordlists/rockyou.txt ]]; then
    success "rockyou.txt present."
elif [[ -f /usr/share/wordlists/rockyou.txt.gz ]]; then
    gunzip /usr/share/wordlists/rockyou.txt.gz && success "rockyou.txt decompressed."
else
    apt-get install -y -qq wordlists 2>/dev/null || warn "wordlists package not found."
fi

if [[ -d /usr/share/seclists ]]; then
    success "SecLists present."
else
    apt-get install -y -qq seclists 2>/dev/null || {
        info "Cloning SecLists (large download)..."
        git clone --quiet --depth 1 https://github.com/danielmiessler/SecLists.git \
            /usr/share/seclists 2>/dev/null \
            && success "SecLists cloned." \
            || warn "SecLists clone failed."
    }
fi

EXPECTED_WORDLISTS=(
    "/usr/share/seclists/Discovery/Web-Content/common.txt"
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
    "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
    "/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt"
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    "/usr/share/wordlists/rockyou.txt"
)
for wl in "${EXPECTED_WORDLISTS[@]}"; do
    [[ -f "$wl" ]] && success "  Found: ${wl##*/}" || warn "  Missing: $wl"
done

# ─────────────────────────────────────────────
# STEP 4 — Install toolkit files
# ─────────────────────────────────────────────
header "STEP 4 -- Toolkit Files"

mkdir -p "$INSTALL_DIR"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

FILES_TO_INSTALL=(
    "interactive_nmap_launcher_v6.py"
    "exploit_runner.py"
    "oscp_toolkit_lib.py"
    "OSCP_playbook_enhanced_yaml.txt"
)

for FILE in "${FILES_TO_INSTALL[@]}"; do
    SRC="${SCRIPT_DIR}/${FILE}"
    DEST="${INSTALL_DIR}/${FILE}"
    if [[ -f "$SRC" ]]; then
        cp "$SRC" "$DEST"
        success "Copied: ${FILE}"
    elif [[ -f "$DEST" ]]; then
        info "${FILE} already present (not overwriting)"
    else
        warn "${FILE} not found -- place it in ${INSTALL_DIR}/ manually."
    fi
done

chmod +x "${INSTALL_DIR}/interactive_nmap_launcher_v6.py" 2>/dev/null || true
chmod +x "${INSTALL_DIR}/exploit_runner.py"               2>/dev/null || true

for SYMNAME in oscp-scan oscp-scan-v6; do
    ln -sf "${INSTALL_DIR}/interactive_nmap_launcher_v6.py" "/usr/local/bin/${SYMNAME}" 2>/dev/null \
        && success "Symlink: ${SYMNAME}" || warn "Could not create symlink ${SYMNAME}"
done
ln -sf "${INSTALL_DIR}/exploit_runner.py" /usr/local/bin/oscp-exploit 2>/dev/null \
    && success "Symlink: oscp-exploit" || warn "Could not create symlink oscp-exploit"

# ─────────────────────────────────────────────
# STEP 5 — Syntax checks
# ─────────────────────────────────────────────
header "STEP 5 -- Syntax Checks"

for F in "${INSTALL_DIR}/interactive_nmap_launcher_v6.py" \
         "${INSTALL_DIR}/exploit_runner.py" \
         "${INSTALL_DIR}/oscp_toolkit_lib.py"; do
    if [[ -f "$F" ]]; then
        python3 -m py_compile "$F" 2>/dev/null \
            && success "Syntax OK: $(basename "$F")" \
            || error  "Syntax error: $F"
    fi
done

if [[ -f "${INSTALL_DIR}/OSCP_playbook_enhanced_yaml.txt" ]]; then
    python3 -c "import yaml; yaml.safe_load(open('${INSTALL_DIR}/OSCP_playbook_enhanced_yaml.txt'))" 2>/dev/null \
        && success "YAML OK: OSCP_playbook_enhanced_yaml.txt" \
        || error "YAML parse error in playbook"
fi

# ─────────────────────────────────────────────
# STEP 6 — Directories
# ─────────────────────────────────────────────
header "STEP 6 -- Working Directories"

mkdir -p "${INSTALL_DIR}/scan_runs"
mkdir -p "$PRIVESC_DIR"
success "Scan output:   ${INSTALL_DIR}/scan_runs/"
success "Privesc depot: ${PRIVESC_DIR}/"

# ─────────────────────────────────────────────
# STEP 7 — PATH fixup
# ─────────────────────────────────────────────
header "STEP 7 -- PATH Configuration"

PROFILE_LINE='export PATH="$PATH:/usr/local/bin:/root/.local/bin"'
for PROFILE in /root/.bashrc /root/.profile; do
    [[ -f "$PROFILE" ]] && ! grep -q "usr/local/bin" "$PROFILE" 2>/dev/null \
        && echo "$PROFILE_LINE" >> "$PROFILE" \
        && info "Added PATH to ${PROFILE}"
done

for BIN in netexec bloodyad certipy donpapi pywhisker \
           impacket-GetNPUsers impacket-GetUserSPNs impacket-psexec \
           impacket-wmiexec impacket-ntlmrelayx impacket-secretsdump \
           bloodhound-python defaultcreds-cheat-sheet keepass2john; do
    for DIR in /root/.local/bin "${REAL_HOME}/.local/bin"; do
        if [[ -x "${DIR}/${BIN}" ]]; then
            ln -sf "${DIR}/${BIN}" "/usr/local/bin/${BIN}" 2>/dev/null || true
        fi
    done
done

# ─────────────────────────────────────────────
# STEP 8 — Final tool check
# ─────────────────────────────────────────────
header "STEP 8 -- Final Tool Check"

declare -A TOOL_DESC=(
    ["nmap"]="Port scanning (required)"
    ["python3"]="Script runtime (required)"
    ["xsltproc"]="XML-to-HTML report"
    ["whatweb"]="Web fingerprinting"
    ["nikto"]="Web baseline scanner"
    ["ffuf"]="Content and vhost fuzzing"
    ["gobuster"]="Content discovery alt"
    ["sqlmap"]="SQL injection"
    ["smbclient"]="SMB share listing"
    ["enum4linux"]="SMB full enumeration"
    ["netexec"]="SMB/WinRM/LDAP enum nxc"
    ["crackmapexec"]="SMB/WinRM enum legacy"
    ["snmpwalk"]="SNMP community walk"
    ["wpscan"]="WordPress enumeration"
    ["redis-cli"]="Redis unauth check"
    ["showmount"]="NFS export listing"
    ["smtp-user-enum"]="SMTP user enumeration"
    ["dnsrecon"]="DNS zone transfer recon"
    ["dig"]="DNS queries AXFR"
    ["evil-winrm"]="WinRM shell"
    ["impacket-GetNPUsers"]="Kerberos ASREPRoast"
    ["impacket-GetUserSPNs"]="Kerberoast"
    ["impacket-psexec"]="PsExec style exec"
    ["impacket-wmiexec"]="WMI exec"
    ["impacket-ntlmrelayx"]="NTLM relay"
    ["impacket-secretsdump"]="Dump hashes"
    ["searchsploit"]="Exploit DB lookup"
    ["git-dumper"]="Git directory extraction"
    ["exiftool"]="File metadata extraction"
    ["cewl"]="Custom wordlist spider"
    ["droopescan"]="Drupal Moodle scanner"
    ["joomscan"]="Joomla scanner"
    ["hashid"]="Hash identification"
    ["hashcat"]="Hash cracking GPU"
    ["john"]="Hash cracking alt"
    ["msfvenom"]="Payload generation"
    ["chisel"]="Tunneling SOCKS port-fwd"
    ["ligolo-proxy"]="Tunneling ligolo-ng"
    ["certipy"]="ADCS shadow credentials"
    ["bloodyad"]="ACL ACE manipulation"
    ["donpapi"]="DPAPI credential dump"
    ["curl"]="HTTP utility"
    ["wget"]="Download utility"
    ["rlwrap"]="Readline wrapper for shells"
    ["mongosh"]="MongoDB shell enum"
    ["kubeletctl"]="Kubernetes kubelet client"
    ["rustscan"]="Fast port scanner"
    ["bloodhound-python"]="BloodHound AD collector"
    ["defaultcreds-cheat-sheet"]="Default credentials lookup"
    # NEW: From GitHub repo research
    ["cupp"]="Target-specific wordlist generator"
    ["crunch"]="Pattern wordlist generator"
    ["swaks"]="SMTP testing and Library-ms phishing"
    ["cadaver"]="WebDAV interactive client"
    ["davtest"]="WebDAV extension testing"
    ["wfuzz"]="Web fuzzer alternative"
    ["psql"]="PostgreSQL client"
    ["gpp-decrypt"]="Decrypt GPP cpassword values"
    ["responder"]="NTLM/NTLMv2 hash capture"
    ["keepass2john"]="Extract KeePass database hash"
    ["svn"]="Subversion repository client"
    ["hydra"]="Credential bruteforce tool"
    ["medusa"]="Parallel login bruteforcer"
)

ALL_OK=true
for tool in "${!TOOL_DESC[@]}"; do
    if command -v "$tool" &>/dev/null || [[ -x "/usr/local/bin/$tool" ]]; then
        printf "  ${GREEN}+${RESET}  %-30s %s\n" "${tool}" "${TOOL_DESC[$tool]}"
    else
        printf "  ${YELLOW}x${RESET}  %-30s %s  ${YELLOW}(missing)${RESET}\n" "${tool}" "${TOOL_DESC[$tool]}"
        ALL_OK=false
    fi
done

echo ""
echo -e "${BOLD}${GREEN}============================================================${RESET}"
echo -e "${BOLD}${GREEN}  Setup complete!${RESET}"
echo -e "${BOLD}${GREEN}============================================================${RESET}"
echo ""
echo -e "  ${BOLD}Run scanner:${RESET}"
echo -e "  ${CYAN}  sudo oscp-scan${RESET}"
echo -e "  ${CYAN}  sudo python3 ${INSTALL_DIR}/interactive_nmap_launcher_v6.py${RESET}"
echo ""
echo -e "  ${BOLD}Run exploit runner (after scanner):${RESET}"
echo -e "  ${CYAN}  sudo oscp-exploit${RESET}          # auto-finds latest handoff"
echo -e "  ${CYAN}  sudo python3 ${INSTALL_DIR}/exploit_runner.py <workspace>${RESET}"
echo ""
echo -e "  ${BOLD}Privesc scripts:${RESET}    ${PRIVESC_DIR}/"
echo -e "  ${BOLD}noPac:${RESET}              /opt/noPac/"
echo -e "  ${BOLD}targetedKerberoast:${RESET} /opt/targetedKerberoast/"
echo -e "  ${BOLD}PrintNightmare:${RESET}     /opt/PrintNightmare/"
echo -e "  ${BOLD}PHP filter chain:${RESET}   /opt/php_filter_chain_generator/"
echo -e "  ${BOLD}SharpEfsPotato:${RESET}     /opt/SharpEfsPotato/"
echo -e "  ${BOLD}BadSuccessor:${RESET}       /opt/BadSuccessor/"
echo ""
[[ "$ALL_OK" == false ]] \
    && warn "Some tools missing -- affected modules skip at runtime automatically."
echo -e "${YELLOW}  Warning: Authorized use only.${RESET}"
echo ""
