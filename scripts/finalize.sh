#!/usr/bin/env bash
# ==============================================================================
# EMPIRE - Lab Finalization and Verification
# Post-Ansible sanity checks and handout generation
# ==============================================================================
set -euo pipefail

EMPIRE_HOME="${EMPIRE_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
VM_DIR="${CFG_DISK_PATH:-${EMPIRE_HOME}/vms}"

log()  { echo -e "\033[0;32m[+]\033[0m $*"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*"; }
info() { echo -e "\033[0;34m[*]\033[0m $*"; }

run_verification() {
    info "Running post-deployment verification..."

    # Check VM processes are running
    local running_vms=0
    for pidfile in "${VM_DIR}"/*.pid; do
        [ -f "$pidfile" ] || continue
        local vm_name pid
        vm_name=$(basename "$pidfile" .pid)
        pid=$(cat "$pidfile")
        if kill -0 "$pid" 2>/dev/null; then
            running_vms=$((running_vms + 1))
        else
            warn "$vm_name: PID $pid not running."
        fi
    done

    if [ "$running_vms" -eq 0 ]; then
        warn "No VMs currently running."
    else
        log "$running_vms VMs are running."
    fi

    # Verify network bridges exist
    for br in empire-ctf empire-finance empire-root; do
        if ip link show "$br" &>/dev/null; then
            log "Bridge $br is up."
        else
            warn "Bridge $br is MISSING."
        fi
    done

    # Verify dnsmasq is responsive
    if pgrep -f "dnsmasq.*empire" &>/dev/null; then
        log "dnsmasq is running."
    else
        warn "dnsmasq is NOT running. DHCP may be unavailable."
    fi

    # Check disk usage
    info "VM disk usage:"
    df -h "$VM_DIR" 2>/dev/null || df -h "$(dirname "$VM_DIR")"

    # Print connection info
    echo ""
    echo "========================================"
    echo "  EMPIRE LAB CONNECTION INFORMATION       "
    echo "========================================"
    echo ""
    echo "  VNC Console Access:"
    for vm_def in coruscant-corp coruscant-eu endor scarif kamino tatooine coruscant-fin coruscant-root; do
        local vnc_port=""
        case "$vm_def" in
            coruscant-corp)  vnc_port=5901 ;;
            coruscant-eu)    vnc_port=5902 ;;
            endor)       vnc_port=5903 ;;
            scarif)     vnc_port=5904 ;;
            kamino)      vnc_port=5905 ;;
            tatooine)       vnc_port=5906 ;;
            coruscant-fin)   vnc_port=5907 ;;
            coruscant-root)  vnc_port=5908 ;;
        esac
        if [ -n "$vnc_port" ]; then
            echo "    $vm_def -> vnc://localhost:$vnc_port"
        fi
    done
    echo ""
    echo "  Primary Domain Controller:  coruscant.empire.local (10.10.0.10)"
    echo "  Victim Workstation:         tatooine.empire.local (10.10.0.100)"
    echo ""
    echo "  SSH to tatooine:  ssh loki@10.10.0.100"
    echo ""
    echo "========================================"
    echo ""

    # Generate local handout
    local handout_dir="${EMPIRE_HOME}/handout"
    mkdir -p "$handout_dir"
    cat > "${handout_dir}/README.txt" << 'EOF'
================================================================================
   EMPIRE - Game of AD v2.0 - Handout
================================================================================

Getting Started:
  1. Connect to victim workstation via VNC on port 5906
  2. Login: corp\loki / SithLord123!
  3. Open PowerShell, navigate to C:\EMPIRE\tools
  4. Read the handout: C:\EMPIRE\handout\CTF-Handout.txt

Key Targets:
  coruscant.empire.local      10.10.0.10
  endor.empire.local      10.10.0.12
  scarif.empire.local    10.10.0.13
  kamino.empire.local     10.10.0.14

Flags are located in: C:\Flags\ on each Windows host.
EOF

    log "Local handout written to: ${handout_dir}/README.txt"
}

# If executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_verification
fi
