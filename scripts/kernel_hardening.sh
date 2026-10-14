#!/usr/bin/env bash
# =============================================================================
#  AegisKube-SecOps — Linux Kernel Hardening Script
# =============================================================================
#
#  Applies best-practice sysctl & firewall (nftables/iptables) hardening
#  settings for high-performance production Linux servers.
#
#  USAGE:
#    sudo bash kernel_hardening.sh [--dry-run] [--firewall] [--rollback]
#
#  FLAGS:
#    --dry-run    Print what would be applied without making changes
#    --firewall   Also apply iptables hardening rules
#    --rollback   Restore backed-up sysctl settings
#
#  Author : Nawaz Sharif <contact@nawazsharif.in>
#  Role   : Senior Linux Developer | Kubernetes | Cybersecurity &
#           Blockchain Architect | AI/ML & Python | DevOps & Cloud
#  License: Apache-2.0
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------

readonly SCRIPT_VERSION="1.0.0"
readonly BACKUP_FILE="/etc/sysctl.d/aegiskube-backup.conf"
readonly HARDENING_FILE="/etc/sysctl.d/99-aegiskube-hardening.conf"
readonly LOG_FILE="/var/log/aegiskube-hardening.log"

DRY_RUN=false
APPLY_FIREWALL=false
ROLLBACK=false
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# ANSI colours
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log() {
    local level="$1"; shift
    local msg="$*"
    local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${ts} [${level}] ${msg}" | tee -a "${LOG_FILE}" 2>/dev/null || true
}

info()    { log "INFO " "${GREEN}${*}${RESET}"; }
warn()    { log "WARN " "${YELLOW}${*}${RESET}"; }
error()   { log "ERROR" "${RED}${*}${RESET}"; }
section() { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════${RESET}"; \
            echo -e "${BOLD}${CYAN}  ${*}${RESET}"; \
            echo -e "${BOLD}${CYAN}══════════════════════════════════════${RESET}"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root. Use: sudo bash $0"
        exit 1
    fi
}

apply_sysctl() {
    local param="$1"
    local value="$2"
    if [[ "${DRY_RUN}" == "true" ]]; then
        echo "  [DRY-RUN] Would set: ${param} = ${value}"
    else
        sysctl -w "${param}=${value}" >> "${LOG_FILE}" 2>&1 || \
            warn "Could not set ${param} (kernel may not support it)"
    fi
}

# ---------------------------------------------------------------------------
# Argument Parsing
# ---------------------------------------------------------------------------

parse_args() {
    for arg in "$@"; do
        case "${arg}" in
            --dry-run)   DRY_RUN=true ;;
            --firewall)  APPLY_FIREWALL=true ;;
            --rollback)  ROLLBACK=true ;;
            --help|-h)
                echo "Usage: sudo bash $0 [--dry-run] [--firewall] [--rollback]"
                exit 0
                ;;
            *)
                error "Unknown argument: ${arg}"
                exit 1
                ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Backup current sysctl settings
# ---------------------------------------------------------------------------

backup_current_settings() {
    section "Backing Up Current Kernel Parameters"
    if [[ "${DRY_RUN}" == "false" ]]; then
        sysctl -a 2>/dev/null | grep -v "^sysctl" > "${BACKUP_FILE}" || true
        info "Backup written to ${BACKUP_FILE}"
    else
        info "[DRY-RUN] Would backup sysctl settings to ${BACKUP_FILE}"
    fi
}

# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------

rollback() {
    section "Rolling Back Kernel Hardening Settings"
    if [[ ! -f "${BACKUP_FILE}" ]]; then
        error "No backup file found at ${BACKUP_FILE}. Cannot rollback."
        exit 1
    fi
    sysctl -p "${BACKUP_FILE}"
    rm -f "${HARDENING_FILE}"
    info "Rollback complete."
    exit 0
}

# ---------------------------------------------------------------------------
# Kernel Network Hardening
# ---------------------------------------------------------------------------

harden_network() {
    section "Applying Network Hardening Parameters"

    declare -A NET_PARAMS=(
        # Disable IP forwarding (not a router)
        ["net.ipv4.ip_forward"]="0"
        ["net.ipv6.conf.all.forwarding"]="0"
        # Reverse path filtering — prevent IP spoofing
        ["net.ipv4.conf.all.rp_filter"]="1"
        ["net.ipv4.conf.default.rp_filter"]="1"
        # Reject ICMP redirects (MITM prevention)
        ["net.ipv4.conf.all.accept_redirects"]="0"
        ["net.ipv6.conf.all.accept_redirects"]="0"
        ["net.ipv4.conf.default.accept_redirects"]="0"
        ["net.ipv4.conf.all.send_redirects"]="0"
        ["net.ipv4.conf.default.send_redirects"]="0"
        # Ignore source-routed packets
        ["net.ipv4.conf.all.accept_source_route"]="0"
        ["net.ipv6.conf.all.accept_source_route"]="0"
        # Log martian packets (those with impossible source addresses)
        ["net.ipv4.conf.all.log_martians"]="1"
        # SYN flood protection
        ["net.ipv4.tcp_syncookies"]="1"
        ["net.ipv4.tcp_syn_retries"]="2"
        ["net.ipv4.tcp_synack_retries"]="2"
        # Smurf attack mitigation
        ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
        # Ignore bogus ICMP error responses
        ["net.ipv4.icmp_ignore_bogus_error_responses"]="1"
        # TCP time-wait assassination hazards fix
        ["net.ipv4.tcp_rfc1337"]="1"
        # Disable TCP timestamps to reduce fingerprinting
        ["net.ipv4.tcp_timestamps"]="0"
        # IPv6 — disable router advertisements
        ["net.ipv6.conf.all.accept_ra"]="0"
        ["net.ipv6.conf.default.accept_ra"]="0"
    )

    for param in "${!NET_PARAMS[@]}"; do
        apply_sysctl "${param}" "${NET_PARAMS[${param}]}"
    done
    info "Network hardening parameters applied."
}

# ---------------------------------------------------------------------------
# Kernel Core Hardening
# ---------------------------------------------------------------------------

harden_kernel() {
    section "Applying Kernel Core Hardening Parameters"

    declare -A KERNEL_PARAMS=(
        # Full ASLR
        ["kernel.randomize_va_space"]="2"
        # Restrict dmesg to root
        ["kernel.dmesg_restrict"]="1"
        # Hide kernel pointers from unprivileged users
        ["kernel.kptr_restrict"]="2"
        # Restrict ptrace to parent processes only
        ["kernel.yama.ptrace_scope"]="1"
        # Disable magic SysRq key
        ["kernel.sysrq"]="0"
        # Disable core dumps for SUID processes
        ["fs.suid_dumpable"]="0"
        # Prevent hard-link attacks
        ["fs.protected_hardlinks"]="1"
        # Prevent symlink-following attacks
        ["fs.protected_symlinks"]="1"
        # Restrict FIFO files in sticky directories
        ["fs.protected_fifos"]="2"
        # Restrict regular file creation in sticky directories
        ["fs.protected_regular"]="2"
        # Increase system file descriptor limit
        ["fs.file-max"]="2097152"
        # Performance: max connection backlog
        ["net.core.somaxconn"]="65535"
        ["net.core.netdev_max_backlog"]="65535"
        # BPF hardening (restrict JIT)
        ["net.core.bpf_jit_harden"]="2"
        # Disable unprivileged user namespaces (reduces attack surface)
        ["kernel.unprivileged_userns_clone"]="0"
    )

    for param in "${!KERNEL_PARAMS[@]}"; do
        apply_sysctl "${param}" "${KERNEL_PARAMS[${param}]}"
    done
    info "Kernel core hardening parameters applied."
}

# ---------------------------------------------------------------------------
# Persist Settings
# ---------------------------------------------------------------------------

persist_settings() {
    section "Persisting Settings to ${HARDENING_FILE}"
    if [[ "${DRY_RUN}" == "true" ]]; then
        info "[DRY-RUN] Would write hardening config to ${HARDENING_FILE}"
        return
    fi

    cat > "${HARDENING_FILE}" << 'EOF'
# =============================================================================
# AegisKube-SecOps — Kernel Hardening Configuration
# Generated by kernel_hardening.sh
# Author: Nawaz Sharif <contact@nawazsharif.in>
# =============================================================================

# --- Network Security ---
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_timestamps = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# --- Kernel Core ---
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
kernel.sysrq = 0
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.file-max = 2097152
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.core.bpf_jit_harden = 2
EOF

    sysctl -p "${HARDENING_FILE}" >> "${LOG_FILE}" 2>&1
    info "Settings persisted and activated."
}

# ---------------------------------------------------------------------------
# Optional Firewall Hardening (iptables)
# ---------------------------------------------------------------------------

harden_firewall() {
    section "Applying iptables Firewall Hardening Rules"

    if ! command -v iptables &>/dev/null; then
        warn "iptables not found — skipping firewall hardening"
        return
    fi

    if [[ "${DRY_RUN}" == "true" ]]; then
        info "[DRY-RUN] Would apply iptables rules"
        return
    fi

    # Flush existing rules
    iptables -F
    iptables -X
    iptables -Z

    # Default policies: DROP everything, then allow what we need
    iptables -P INPUT   DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT  ACCEPT

    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    # Allow established/related connections
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Allow SSH (rate-limited to 3 new connections per minute per IP)
    iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW \
        -m recent --set --name SSH --rsource
    iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW \
        -m recent --update --seconds 60 --hitcount 4 --name SSH --rsource -j DROP
    iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT

    # Allow HTTPS
    iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT

    # Allow ICMP ping (rate-limited)
    iptables -A INPUT -p icmp --icmp-type echo-request \
        -m limit --limit 1/s --limit-burst 5 -j ACCEPT

    # Drop invalid packets
    iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

    # Drop Christmas tree packets
    iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

    # Drop null packets
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

    # Log and drop everything else
    iptables -A INPUT -j LOG --log-prefix "[AEGIS-DROP] " --log-level 4
    iptables -A INPUT -j DROP

    info "iptables rules applied."

    # Save rules
    if command -v iptables-save &>/dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi
}

# ---------------------------------------------------------------------------
# Disable Unused & Risky Kernel Modules
# ---------------------------------------------------------------------------

disable_modules() {
    section "Disabling Unused Risky Kernel Modules"
    local dangerous_modules=(
        "dccp"          # Uncommon — frequently exploited
        "sctp"          # SCTP — rarely needed, large attack surface
        "rds"           # RDS — remote exploit history
        "tipc"          # TIPC — rarely used, CVE history
        "cramfs"        # Legacy filesystem
        "freevxfs"      # Legacy filesystem
        "jffs2"         # Embedded only
        "hfs"           # Mac HFS — rarely needed on servers
        "hfsplus"       # Mac HFS+ — rarely needed on servers
        "udf"           # DVD filesystem
        "usb-storage"   # Block USB storage if not needed
    )

    local blacklist_file="/etc/modprobe.d/aegiskube-blacklist.conf"
    if [[ "${DRY_RUN}" == "true" ]]; then
        info "[DRY-RUN] Would blacklist: ${dangerous_modules[*]}"
        return
    fi

    {
        echo "# AegisKube-SecOps — Dangerous Module Blacklist"
        echo "# Generated: ${TIMESTAMP}"
        for mod in "${dangerous_modules[@]}"; do
            echo "blacklist ${mod}"
            echo "install ${mod} /bin/true"
        done
    } > "${blacklist_file}"

    info "Module blacklist written to ${blacklist_file}"
    info "Rebuild initramfs to take effect: update-initramfs -u (Debian/Ubuntu) or dracut -f (RHEL)"
}

# ---------------------------------------------------------------------------
# Summary Report
# ---------------------------------------------------------------------------

print_summary() {
    section "Hardening Complete — Summary"
    echo -e "  ${GREEN}✔${RESET}  Kernel network parameters hardened"
    echo -e "  ${GREEN}✔${RESET}  Kernel core security parameters applied"
    echo -e "  ${GREEN}✔${RESET}  Settings persisted to ${HARDENING_FILE}"
    echo -e "  ${GREEN}✔${RESET}  Dangerous kernel modules blacklisted"
    if [[ "${APPLY_FIREWALL}" == "true" ]]; then
        echo -e "  ${GREEN}✔${RESET}  iptables firewall rules applied"
    fi
    if [[ "${DRY_RUN}" == "true" ]]; then
        echo -e "\n  ${YELLOW}⚠  DRY-RUN mode — no changes were made to the system${RESET}"
    fi
    echo ""
    info "Log: ${LOG_FILE}"
    echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    parse_args "$@"
    check_root

    section "AegisKube-SecOps Kernel Hardening Script v${SCRIPT_VERSION}"
    info "Mode: $([ "${DRY_RUN}" = "true" ] && echo "DRY-RUN" || echo "LIVE")"
    info "Timestamp: ${TIMESTAMP}"

    if [[ "${ROLLBACK}" == "true" ]]; then
        rollback
    fi

    backup_current_settings
    harden_network
    harden_kernel
    persist_settings
    disable_modules

    if [[ "${APPLY_FIREWALL}" == "true" ]]; then
        harden_firewall
    fi

    print_summary
}

main "$@"
