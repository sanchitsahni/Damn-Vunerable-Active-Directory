#!/usr/bin/env bash
# ==============================================================================
# DVAD QEMU Provider - Network Setup
#
# Creates 3 isolated lab bridges + 1 NAT bridge for Windows activation, then
# starts a per-project dnsmasq under /tmp/dvad-dnsmasq/ with static leases
# keyed on the VM MAC addresses.
#
# Cross-bridge routing is enabled so the attacker host at 10.10.0.1 can reach
# the finance (10.20.0.x) and root (10.30.0.x) domains for trust-attack chains.
#
# Subcommands:
#   setup    — bring up bridges, NAT, dnsmasq
#   destroy  — tear everything down
# ==============================================================================
set -euo pipefail
IFS=$'\n\t'

# ==============================================================================
# Logging helpers
# ==============================================================================
log()  { echo -e "\033[0;32m[+]\033[0m $*" >&2; }
warn() { echo -e "\033[1;33m[!]\033[0m $*" >&2; }
info() { echo -e "\033[0;34m[*]\033[0m $*" >&2; }
err()  { echo -e "\033[0;31m[ERROR]\033[0m $*" >&2; }

# ==============================================================================
# Constants
# ==============================================================================
BRIDGE_CTF="dvad-ctf"         # corp.local + eu.corp.local  10.10.0.0/24
BRIDGE_FINANCE="dvad-finance"  # finance.local               10.20.0.0/24
BRIDGE_ROOT="dvad-root"        # root.corp                   10.30.0.0/24
BRIDGE_NAT="dvad-nat"          # outbound NAT                10.0.2.0/24

GW_CTF="10.10.0.1"
GW_FINANCE="10.20.0.1"
GW_ROOT="10.30.0.1"
GW_NAT="10.0.2.1"

DNSMASQ_DIR="/tmp/dvad-dnsmasq"
DNSMASQ_CONF="${DNSMASQ_DIR}/dvad-dnsmasq.conf"
DNSMASQ_STATIC="${DNSMASQ_DIR}/dvad-static.conf"
DNSMASQ_PID="${DNSMASQ_DIR}/dvad-dnsmasq.pid"
DNSMASQ_LOG="${DNSMASQ_DIR}/dvad-dnsmasq.log"

# ==============================================================================
# Detect outbound interface reliably (never hardcoded eth0/wlan0)
# ==============================================================================
outbound_iface() {
    ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") { print $(i+1); exit }}'
}

# ==============================================================================
# create_bridge <name> <gateway_cidr>
# Creates a Linux bridge, assigns the gateway address, brings it up, and
# registers it with qemu-bridge-helper.
# ==============================================================================
create_bridge() {
    local name="$1"
    local gw_cidr="$2"   # e.g. 10.10.0.1/24

    if ip link show "${name}" &>/dev/null 2>&1; then
        info "Bridge ${name} already exists."
    else
        log "Creating bridge ${name} (${gw_cidr})..."
        sudo -n ip link add name "${name}" type bridge
        sudo -n ip addr add "${gw_cidr}" dev "${name}"
        sudo -n ip link set "${name}" up
        log "Bridge ${name} up."
    fi

    # Register with qemu-bridge-helper so unprivileged QEMU can attach tap ifaces
    sudo -n mkdir -p /etc/qemu
    if ! sudo -n grep -qx "allow ${name}" /etc/qemu/bridge.conf 2>/dev/null; then
        echo "allow ${name}" | sudo -n tee -a /etc/qemu/bridge.conf >/dev/null
        info "Registered ${name} in /etc/qemu/bridge.conf"
    fi
}

# ==============================================================================
# setup_ip_forwarding
# Enables kernel IP forwarding (idempotent).
# ==============================================================================
setup_ip_forwarding() {
    local current
    current="$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)"
    if [[ "${current}" != "1" ]]; then
        log "Enabling IPv4 forwarding..."
        sudo -n sysctl -w net.ipv4.ip_forward=1 >/dev/null
    else
        info "IPv4 forwarding already enabled."
    fi
}

# ==============================================================================
# setup_nat
# Adds MASQUERADE rules so VMs can reach the internet through the host's
# outbound interface (needed for Windows activation).
# Detects the outbound interface dynamically — never hardcodes eth0/wlan0.
# ==============================================================================
setup_nat() {
    local out_iface
    out_iface="$(outbound_iface)"

    if [[ -z "${out_iface}" ]]; then
        warn "Could not detect outbound interface — NAT masquerade skipped."
        warn "VMs will not have internet access for Windows activation."
        return 0
    fi

    log "Setting up NAT masquerade via interface: ${out_iface}"

    if command -v nft &>/dev/null; then
        # nftables path
        # Create the dvad table + chains only once
        if ! sudo -n nft list table inet dvad &>/dev/null 2>&1; then
            sudo -n nft add table inet dvad
            sudo -n nft add chain inet dvad postrouting \
                '{ type nat hook postrouting priority srcnat; policy accept; }'
            sudo -n nft add chain inet dvad forward \
                '{ type filter hook forward priority 0; policy accept; }'
        fi

        # Masquerade from each lab subnet to the internet
        for subnet in "10.10.0.0/24" "10.20.0.0/24" "10.30.0.0/24" "10.0.2.0/24"; do
            local rule="ip saddr ${subnet} oifname \"${out_iface}\" masquerade"
            if ! sudo -n nft list chain inet dvad postrouting 2>/dev/null | grep -qF "ip saddr ${subnet}"; then
                sudo -n nft add rule inet dvad postrouting ${rule}
                info "Added nft masquerade rule: ${subnet} → ${out_iface}"
            fi
        done
    else
        # iptables fallback
        for subnet in "10.10.0.0/24" "10.20.0.0/24" "10.30.0.0/24" "10.0.2.0/24"; do
            if ! sudo -n iptables -t nat -C POSTROUTING \
                    -s "${subnet}" -o "${out_iface}" -j MASQUERADE 2>/dev/null; then
                sudo -n iptables -t nat -A POSTROUTING \
                    -s "${subnet}" -o "${out_iface}" -j MASQUERADE
                info "Added iptables masquerade rule: ${subnet} → ${out_iface}"
            fi
        done
        for br in "${BRIDGE_CTF}" "${BRIDGE_FINANCE}" "${BRIDGE_ROOT}" "${BRIDGE_NAT}"; do
            sudo -n iptables -C FORWARD -i "${br}" -j ACCEPT 2>/dev/null || \
                sudo -n iptables -A FORWARD -i "${br}" -j ACCEPT
            sudo -n iptables -C FORWARD -o "${br}" -j ACCEPT 2>/dev/null || \
                sudo -n iptables -A FORWARD -o "${br}" -j ACCEPT
        done
    fi
}

# ==============================================================================
# setup_cross_bridge_routes
# Adds host routes so traffic from dvad-ctf (10.10.0.1) can reach
# dvad-finance (10.20.0.x) and dvad-root (10.30.0.x).
# This is necessary for trust-chain attack scenarios.
# ==============================================================================
setup_cross_bridge_routes() {
    log "Setting up cross-bridge routes for trust-attack paths..."

    # Route 10.20.0.0/24 via dvad-finance bridge gateway (already on-link)
    if ! ip route show dev "${BRIDGE_FINANCE}" | grep -q "10.20.0.0/24" 2>/dev/null; then
        sudo -n ip route add 10.20.0.0/24 dev "${BRIDGE_FINANCE}" src "${GW_FINANCE}" 2>/dev/null || true
        info "Route 10.20.0.0/24 → ${BRIDGE_FINANCE}"
    fi

    # Route 10.30.0.0/24 via dvad-root bridge gateway
    if ! ip route show dev "${BRIDGE_ROOT}" | grep -q "10.30.0.0/24" 2>/dev/null; then
        sudo -n ip route add 10.30.0.0/24 dev "${BRIDGE_ROOT}" src "${GW_ROOT}" 2>/dev/null || true
        info "Route 10.30.0.0/24 → ${BRIDGE_ROOT}"
    fi

    # Allow forwarding between the bridges (kernel may drop inter-bridge traffic)
    if command -v nft &>/dev/null; then
        if ! sudo -n nft list table inet dvad &>/dev/null 2>&1; then
            sudo -n nft add table inet dvad
            sudo -n nft add chain inet dvad forward \
                '{ type filter hook forward priority 0; policy accept; }'
        fi
        # Accept forwarding from ctf → finance and ctf → root (trust-attack paths)
        for pair in \
            "${BRIDGE_CTF}:${BRIDGE_FINANCE}" \
            "${BRIDGE_CTF}:${BRIDGE_ROOT}" \
            "${BRIDGE_FINANCE}:${BRIDGE_CTF}" \
            "${BRIDGE_ROOT}:${BRIDGE_CTF}"; do
            local in_br="${pair%%:*}"
            local out_br="${pair##*:}"
            local rule="iifname \"${in_br}\" oifname \"${out_br}\" accept"
            if ! sudo -n nft list chain inet dvad forward 2>/dev/null | grep -qF "iifname \"${in_br}\" oifname \"${out_br}\""; then
                sudo -n nft add rule inet dvad forward ${rule}
            fi
        done
    else
        # iptables fallback
        for pair in \
            "${BRIDGE_CTF}:${BRIDGE_FINANCE}" \
            "${BRIDGE_CTF}:${BRIDGE_ROOT}" \
            "${BRIDGE_FINANCE}:${BRIDGE_CTF}" \
            "${BRIDGE_ROOT}:${BRIDGE_CTF}"; do
            local in_br="${pair%%:*}"
            local out_br="${pair##*:}"
            sudo -n iptables -C FORWARD -i "${in_br}" -o "${out_br}" -j ACCEPT 2>/dev/null || \
                sudo -n iptables -A FORWARD -i "${in_br}" -o "${out_br}" -j ACCEPT
        done
    fi

    log "Cross-bridge routes configured."
}

# ==============================================================================
# write_dnsmasq_config
# Writes the main dnsmasq.conf and static lease file.
# ==============================================================================
write_dnsmasq_config() {
    mkdir -p "${DNSMASQ_DIR}"

    # Static lease file — MACs from the VM topology table
    cat > "${DNSMASQ_STATIC}" <<'STATIC_EOF'
# DVAD static DHCP leases — keyed on VM MAC addresses
# corp.local / eu.corp.local
dhcp-host=52:54:00:01:01:01,dc01.corp.local,10.10.0.10,infinite
dhcp-host=52:54:00:01:01:02,dc01.eu.corp.local,10.10.0.11,infinite
dhcp-host=52:54:00:01:01:03,ca01.corp.local,10.10.0.12,infinite
dhcp-host=52:54:00:01:01:04,file01.corp.local,10.10.0.13,infinite
dhcp-host=52:54:00:01:01:05,sql01.corp.local,10.10.0.14,infinite
dhcp-host=52:54:00:01:01:06,ws01.corp.local,10.10.0.100,infinite
# finance.local
dhcp-host=52:54:00:02:01:01,dc01.finance.local,10.20.0.10,infinite
# root.corp
dhcp-host=52:54:00:03:01:01,dc01.root.corp,10.30.0.10,infinite
STATIC_EOF

    # Main dnsmasq configuration
    cat > "${DNSMASQ_CONF}" <<DNSMASQ_EOF
# DVAD Lab dnsmasq configuration
# Managed by providers/qemu/network-setup.sh — do not edit by hand.

bind-interfaces
no-resolv
domain-needed
bogus-priv
log-dhcp

# Include static leases
conf-file=${DNSMASQ_STATIC}

# ── corp.local / eu.corp.local (dvad-ctf, 10.10.0.0/24) ─────────────────────
interface=${BRIDGE_CTF}
dhcp-range=${BRIDGE_CTF},10.10.0.150,10.10.0.200,255.255.255.0,12h
dhcp-option=${BRIDGE_CTF},3,${GW_CTF}
dhcp-option=${BRIDGE_CTF},6,10.10.0.10
dhcp-option=${BRIDGE_CTF},15,corp.local

# ── finance.local (dvad-finance, 10.20.0.0/24) ───────────────────────────────
interface=${BRIDGE_FINANCE}
dhcp-range=${BRIDGE_FINANCE},10.20.0.100,10.20.0.200,255.255.255.0,12h
dhcp-option=${BRIDGE_FINANCE},3,${GW_FINANCE}
dhcp-option=${BRIDGE_FINANCE},6,10.20.0.10
dhcp-option=${BRIDGE_FINANCE},15,finance.local

# ── root.corp (dvad-root, 10.30.0.0/24) ──────────────────────────────────────
interface=${BRIDGE_ROOT}
dhcp-range=${BRIDGE_ROOT},10.30.0.100,10.30.0.200,255.255.255.0,12h
dhcp-option=${BRIDGE_ROOT},3,${GW_ROOT}
dhcp-option=${BRIDGE_ROOT},6,10.30.0.10
dhcp-option=${BRIDGE_ROOT},15,root.corp

# ── NAT bridge (dvad-nat, 10.0.2.0/24) ───────────────────────────────────────
interface=${BRIDGE_NAT}
dhcp-range=${BRIDGE_NAT},10.0.2.100,10.0.2.200,255.255.255.0,12h
dhcp-option=${BRIDGE_NAT},3,${GW_NAT}
DNSMASQ_EOF

    log "dnsmasq configuration written to ${DNSMASQ_CONF}"
}

# ==============================================================================
# start_dnsmasq
# ==============================================================================
start_dnsmasq() {
    # Kill any existing dvad dnsmasq instance (optional cleanup — not critical)
    if [[ -f "${DNSMASQ_PID}" ]]; then
        local old_pid
        old_pid="$(cat "${DNSMASQ_PID}")"
        if kill -0 "${old_pid}" 2>/dev/null; then
            warn "Stopping existing dnsmasq (PID: ${old_pid})..."
            sudo -n kill "${old_pid}" 2>/dev/null || true
            sleep 1
        fi
        rm -f "${DNSMASQ_PID}"
    fi

    log "Starting dnsmasq..."
    sudo -n dnsmasq \
        --conf-file="${DNSMASQ_CONF}" \
        --pid-file="${DNSMASQ_PID}" \
        --log-facility="${DNSMASQ_LOG}"

    # Wait up to 5 s for PID file
    local waited=0
    while [[ "${waited}" -lt 5 ]]; do
        [[ -f "${DNSMASQ_PID}" ]] && break
        sleep 1
        waited=$(( waited + 1 ))
    done

    if [[ -f "${DNSMASQ_PID}" ]]; then
        log "dnsmasq started (PID: $(cat "${DNSMASQ_PID}"))"
    else
        err "dnsmasq failed to start. Check log: ${DNSMASQ_LOG}"
        return 1
    fi
}

# ==============================================================================
# setup  — main entry point to bring up the full network stack
# ==============================================================================
setup() {
    log "=== DVAD Network Setup ==="

    # 1. Lab bridges
    create_bridge "${BRIDGE_CTF}"     "${GW_CTF}/24"
    create_bridge "${BRIDGE_FINANCE}" "${GW_FINANCE}/24"
    create_bridge "${BRIDGE_ROOT}"    "${GW_ROOT}/24"

    # 2. NAT bridge for Windows activation (outbound internet only)
    create_bridge "${BRIDGE_NAT}" "${GW_NAT}/24"

    # 3. IP forwarding
    setup_ip_forwarding

    # 4. NAT masquerade
    setup_nat

    # 5. Cross-bridge routes (trust-attack paths)
    setup_cross_bridge_routes

    # 6. dnsmasq
    write_dnsmasq_config
    start_dnsmasq

    # 7. Summary
    echo ""
    log "Network setup complete. Bridges:"
    ip -br link show | grep "^dvad" || true
    echo ""
    log "Bridge IPs:"
    ip -br addr show | grep "^dvad" || true
    echo ""
    log "dnsmasq config: ${DNSMASQ_CONF}"
    log "dnsmasq log:    ${DNSMASQ_LOG}"
    local out_iface
    out_iface="$(outbound_iface)"
    log "Outbound NAT interface: ${out_iface:-<not detected>}"
}

# ==============================================================================
# destroy  — tear down everything created by setup
# ==============================================================================
destroy() {
    warn "=== DVAD Network Teardown ==="

    # Stop dnsmasq
    if [[ -f "${DNSMASQ_PID}" ]]; then
        local pid
        pid="$(cat "${DNSMASQ_PID}")"
        if kill -0 "${pid}" 2>/dev/null; then
            log "Stopping dnsmasq (PID: ${pid})..."
            sudo -n kill "${pid}" 2>/dev/null || true
        fi
    fi
    # Belt-and-suspenders: kill any stray dvad dnsmasq processes
    sudo -n pkill -f "dnsmasq.*dvad" 2>/dev/null || true
    rm -rf "${DNSMASQ_DIR}"

    # Remove bridges
    for br in "${BRIDGE_CTF}" "${BRIDGE_FINANCE}" "${BRIDGE_ROOT}" "${BRIDGE_NAT}"; do
        if ip link show "${br}" &>/dev/null 2>&1; then
            log "Removing bridge ${br}..."
            sudo -n ip link set "${br}" down 2>/dev/null || true
            sudo -n ip link delete "${br}" 2>/dev/null || true
        fi
    done

    # Remove firewall rules
    if command -v nft &>/dev/null; then
        if sudo -n nft list table inet dvad &>/dev/null 2>&1; then
            log "Removing nftables dvad table..."
            sudo -n nft delete table inet dvad
        fi
    else
        # Best-effort iptables cleanup
        local out_iface
        out_iface="$(outbound_iface || true)"
        if [[ -n "${out_iface}" ]]; then
            for subnet in "10.10.0.0/24" "10.20.0.0/24" "10.30.0.0/24" "10.0.2.0/24"; do
                sudo -n iptables -t nat -D POSTROUTING \
                    -s "${subnet}" -o "${out_iface}" -j MASQUERADE 2>/dev/null || true
            done
        fi
    fi

    # Remove qemu-bridge-helper entries
    for br in "${BRIDGE_CTF}" "${BRIDGE_FINANCE}" "${BRIDGE_ROOT}" "${BRIDGE_NAT}"; do
        if [[ -f /etc/qemu/bridge.conf ]]; then
            sudo -n sed -i "/^allow ${br}$/d" /etc/qemu/bridge.conf 2>/dev/null || true
        fi
    done

    log "Network teardown complete."
}

# ==============================================================================
# usage
# ==============================================================================
usage() {
    cat >&2 <<EOF
Usage: $(basename "$0") COMMAND

Commands:
  setup    — create bridges, enable NAT, start dnsmasq
  destroy  — remove bridges, stop dnsmasq, clean firewall rules

Bridges created:
  ${BRIDGE_CTF}      ${GW_CTF}/24  — corp.local / eu.corp.local
  ${BRIDGE_FINANCE}  ${GW_FINANCE}/24  — finance.local
  ${BRIDGE_ROOT}     ${GW_ROOT}/24  — root.corp
  ${BRIDGE_NAT}      ${GW_NAT}/24   — outbound NAT (Windows activation)
EOF
    exit 1
}

# ==============================================================================
# Entrypoint
# ==============================================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    COMMAND="${1:-}"
    case "${COMMAND}" in
        setup)   setup   ;;
        destroy) destroy ;;
        ""|--help|-h) usage ;;
        *)
            err "Unknown command: ${COMMAND}"
            usage
            ;;
    esac
fi
