#!/usr/bin/env bash
# ==============================================================================
# DVAD VirtualBox Provider - VM Create / Start / Stop / Destroy / Status
# ==============================================================================
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DUNDER_HOME="${DUNDER_HOME:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"

# Default packer output dir (can be overridden via --packer-output)
PACKER_OUTPUT="${DUNDER_HOME}/packer-output"

# ==============================================================================
# Logging helpers
# ==============================================================================
log()  { echo -e "\033[0;32m[+]\033[0m $*" >&2; }
warn() { echo -e "\033[1;33m[!]\033[0m $*" >&2; }
info() { echo -e "\033[0;34m[*]\033[0m $*" >&2; }
err()  { echo -e "\033[0;31m[ERROR]\033[0m $*" >&2; }

# ==============================================================================
# Guard: require VBoxManage
# ==============================================================================
if ! command -v VBoxManage &>/dev/null; then
    err "VBoxManage not found. Install VirtualBox first."
    exit 1
fi

# ==============================================================================
# VM Definitions
# Format: name|mac|ram_mb|disk_gb|cpu|hostonly_iface|base_ova
#
# base_ova values: server2022 | server2019 | win10
# hostonly_iface: the VirtualBox host-only network name for this VM's segment.
#   Single network for all forests (matches the QEMU single-bridge plan):
#   vboxnet0 = corp/eu/finance/root on 10.10.0.0/16
#     corp/eu = 10.10.0.x, finance = 10.10.20.x, root = 10.10.30.x
# ==============================================================================
declare -A VM_DEFS

VM_DEFS=(
    # corp.local / eu.corp.local segment — vboxnet0
    ["dc01"]="52:54:00:01:01:01|2048|40|2|vboxnet0|server2022"
    ["dc01eu"]="52:54:00:01:01:02|1536|25|2|vboxnet0|server2022"
    ["ca01"]="52:54:00:01:01:03|1536|25|2|vboxnet0|server2022"
    ["file01"]="52:54:00:01:01:04|1536|20|2|vboxnet0|server2019"
    ["sql01"]="52:54:00:01:01:05|2048|25|2|vboxnet0|server2022"
    ["ws01"]="52:54:00:01:01:06|2048|30|2|vboxnet0|win10"
    # finance.local segment — vboxnet0 (10.10.20.x)
    ["dc01fin"]="52:54:00:02:01:01|1536|25|2|vboxnet0|server2022"
    # root.corp segment — vboxnet0 (10.10.30.x)
    ["dc01root"]="52:54:00:03:01:01|1536|25|2|vboxnet0|server2022"
)

# VM name → FQDN
declare -A VM_FQDN=(
    ["dc01"]="dc01.corp.local"
    ["dc01eu"]="dc01.eu.corp.local"
    ["ca01"]="ca01.corp.local"
    ["file01"]="file01.corp.local"
    ["sql01"]="sql01.corp.local"
    ["ws01"]="ws01.corp.local"
    ["dc01fin"]="dc01.finance.local"
    ["dc01root"]="dc01.root.corp"
)

# VM name → static IP
declare -A VM_IP=(
    ["dc01"]="10.10.0.10"
    ["dc01eu"]="10.10.0.11"
    ["ca01"]="10.10.0.12"
    ["file01"]="10.10.0.13"
    ["sql01"]="10.10.0.14"
    ["ws01"]="10.10.0.100"
    ["dc01fin"]="10.10.20.10"
    ["dc01root"]="10.10.30.10"
)

# Profile → VM list (ordered)
PROFILE_FULL=("dc01" "dc01eu" "ca01" "file01" "sql01" "ws01" "dc01fin" "dc01root")
PROFILE_MINIMAL=("dc01" "dc01eu" "ca01" "file01" "sql01" "ws01")
PROFILE_SINGLE_DC=("dc01")

# ==============================================================================
# Helpers
# ==============================================================================

# resolve_base_ova <key> → absolute path to .ova
resolve_base_ova() {
    local key="$1"
    local path
    case "$key" in
        server2022) path="${PACKER_OUTPUT}/server2022-virtualbox/windows-server-2022-base.ova" ;;
        server2019) path="${PACKER_OUTPUT}/server2019-virtualbox/windows-server-2019-base.ova" ;;
        win10)      path="${PACKER_OUTPUT}/win10-virtualbox/windows-10-base.ova" ;;
        *)
            err "Unknown base OVA key: ${key}"
            return 1
            ;;
    esac
    echo "$path"
}

# parse_vm_def <vm_name>
# Sets: vm_mac vm_ram vm_disk vm_cpu vm_iface vm_base_ova
parse_vm_def() {
    local name="$1"
    if [[ -z "${VM_DEFS[$name]+_}" ]]; then
        err "Unknown VM: ${name}"
        return 1
    fi
    local def="${VM_DEFS[$name]}"
    IFS='|' read -r vm_mac vm_ram vm_disk vm_cpu vm_iface vm_base_ova <<< "$def"
}

# profile_vms <profile> → space-separated VM names
profile_vms() {
    local profile="$1"
    case "$profile" in
        full)      echo "${PROFILE_FULL[@]}" ;;
        minimal)   echo "${PROFILE_MINIMAL[@]}" ;;
        single-dc) echo "${PROFILE_SINGLE_DC[@]}" ;;
        *)
            err "Unknown profile: ${profile}. Valid: full, minimal, single-dc"
            return 1
            ;;
    esac
}

# vm_exists <vm_name> → returns 0 if registered in VirtualBox
vm_exists() {
    local name="$1"
    VBoxManage list vms 2>/dev/null | grep -q "\"dvad-${name}\""
}

# ==============================================================================
# setup_host_only_networks
# Creates vboxnet0/1/2 if they don't exist and assigns the gateway IPs.
# ==============================================================================
setup_host_only_networks() {
    log "Configuring VirtualBox host-only network..."

    # Single host-only network for all forests on 10.10.0.0/16
    # (matches the QEMU single-bridge plan). gateway 10.10.0.1.
    local gw="10.10.0.1"

    local existing_nets
    existing_nets="$(VBoxManage list hostonlyifs 2>/dev/null | grep '^Name:' | awk '{print $2}' || true)"

    local iface="vboxnet0"
    if echo "${existing_nets}" | grep -qx "${iface}"; then
        info "Host-only interface ${iface} already exists."
    else
        log "Creating host-only interface ${iface}..."
        local created_iface
        created_iface="$(VBoxManage hostonlyif create 2>&1 | grep "^Interface" | awk -F"'" '{print $2}')"
        if [[ -z "${created_iface}" ]]; then
            # VBoxManage may or may not report — list again
            created_iface="$(VBoxManage list hostonlyifs 2>/dev/null | grep '^Name:' | awk '{print $2}' | tail -1 || true)"
        fi
        info "Created host-only interface: ${created_iface:-${iface}}"
    fi

    # Configure IP address on the interface (/16 to cover finance/root ranges)
    log "Setting ${iface} IP to ${gw}/16..."
    VBoxManage hostonlyif ipconfig "${iface}" \
        --ip "${gw}" \
        --netmask "255.255.0.0"

    log "Host-only network configured."
}

# ==============================================================================
# import_ova <vm_name>
# Imports the .ova into VirtualBox under the name dvad-<vm_name>.
# ==============================================================================
import_ova() {
    local vm_name="$1"
    parse_vm_def "${vm_name}"

    local vbox_name="dvad-${vm_name}"

    if vm_exists "${vm_name}"; then
        info "VM ${vbox_name} already registered in VirtualBox."
        return 0
    fi

    local ova_path
    ova_path="$(resolve_base_ova "${vm_base_ova}")"

    if [[ ! -f "${ova_path}" ]]; then
        err "Base OVA not found: ${ova_path}"
        err "Run packer build first, or set --packer-output to the correct directory."
        return 1
    fi

    log "Importing OVA for ${vbox_name}: ${ova_path}"
    VBoxManage import "${ova_path}" \
        --vsys 0 \
        --vmname "${vbox_name}" \
        --memory "${vm_ram}" \
        --cpus   "${vm_cpu}"

    log "OVA imported as ${vbox_name}."
}

# ==============================================================================
# create_vm <vm_name>
# Imports (if needed), clones, and configures one VM.
# ==============================================================================
create_vm() {
    local vm_name="$1"
    parse_vm_def "${vm_name}"

    local vbox_name="dvad-${vm_name}"
    local fqdn="${VM_FQDN[$vm_name]:-$vm_name}"
    local ip="${VM_IP[$vm_name]}"

    # Ensure the base OVA is imported (used as the source for clonevm)
    local base_reg_name="dvad-${vm_name}-base"
    local ova_path
    ova_path="$(resolve_base_ova "${vm_base_ova}")"

    if [[ ! -f "${ova_path}" ]]; then
        err "Base OVA not found: ${ova_path}"
        err "Run packer build first, or set --packer-output to the correct directory."
        return 1
    fi

    # Import the base OVA under a temporary name if the final clone doesn't exist
    if vm_exists "${vm_name}"; then
        info "${vbox_name} is already registered — skipping create."
    else
        # Import OVA directly as the working VM (VirtualBox clonevm from OVA is
        # most reliably done by importing then renaming).
        log "Importing ${ova_path} as ${vbox_name}..."
        VBoxManage import "${ova_path}" \
            --vsys 0 \
            --vmname "${vbox_name}"

        log "Configuring ${vbox_name}: RAM=${vm_ram}MB, CPUs=${vm_cpu}"
        VBoxManage modifyvm "${vbox_name}" \
            --memory  "${vm_ram}" \
            --cpus    "${vm_cpu}" \
            --nic1    hostonly \
            --hostonlyadapter1 "${vm_iface}" \
            --macaddress1      "$(echo "${vm_mac}" | tr -d ':')" \
            --nictype1         "82574L" \
            --vrde             off \
            --graphicscontroller vmsvga

        log "${vbox_name} configured."
    fi
}

# ==============================================================================
# start_vm <vm_name>
# Starts a VM headlessly.
# ==============================================================================
start_vm() {
    local vm_name="$1"
    local vbox_name="dvad-${vm_name}"

    if ! vm_exists "${vm_name}"; then
        err "VM ${vbox_name} is not registered. Run create first."
        return 1
    fi

    # Check if already running
    if VBoxManage list runningvms 2>/dev/null | grep -q "\"${vbox_name}\""; then
        info "${vbox_name} is already running."
        return 0
    fi

    log "Starting ${vbox_name} (headless)..."
    VBoxManage startvm "${vbox_name}" --type headless
    log "${vbox_name} started."
}

# ==============================================================================
# stop_vm <vm_name>
# Saves VM state (non-destructive).
# ==============================================================================
stop_vm() {
    local vm_name="$1"
    local vbox_name="dvad-${vm_name}"

    if ! VBoxManage list runningvms 2>/dev/null | grep -q "\"${vbox_name}\""; then
        info "${vbox_name} is not running."
        return 0
    fi

    log "Saving state of ${vbox_name}..."
    VBoxManage controlvm "${vbox_name}" savestate
    log "${vbox_name} state saved."
}

# ==============================================================================
# destroy_vm <vm_name>
# Stops (if running) then unregisters and deletes all files.
# ==============================================================================
destroy_vm() {
    local vm_name="$1"
    local vbox_name="dvad-${vm_name}"

    if ! vm_exists "${vm_name}"; then
        info "${vbox_name} is not registered — nothing to destroy."
        return 0
    fi

    # Power off if running
    if VBoxManage list runningvms 2>/dev/null | grep -q "\"${vbox_name}\""; then
        log "Powering off ${vbox_name}..."
        VBoxManage controlvm "${vbox_name}" poweroff
        sleep 2
    fi

    log "Unregistering and deleting ${vbox_name}..."
    VBoxManage unregistervm "${vbox_name}" --delete
    log "${vbox_name} destroyed."
}

# ==============================================================================
# destroy_all [profile]
# ==============================================================================
destroy_all() {
    local profile="${1:-full}"
    warn "Destroying all VMs in profile '${profile}'..."

    local vm_list
    read -ra vm_list <<< "$(profile_vms "${profile}")"

    for vm_name in "${vm_list[@]}"; do
        destroy_vm "${vm_name}"
    done

    log "All VMs in profile '${profile}' destroyed."
}

# ==============================================================================
# status
# ==============================================================================
status() {
    echo "=== DVAD VirtualBox VM Status ==="

    local running_vms
    running_vms="$(VBoxManage list runningvms 2>/dev/null || true)"

    printf "%-12s %-26s %-12s\n" "NAME" "FQDN" "STATE"
    printf "%-12s %-26s %-12s\n" "----" "----" "-----"

    for vm_name in "${PROFILE_FULL[@]}"; do
        local vbox_name="dvad-${vm_name}"
        local fqdn="${VM_FQDN[$vm_name]:-$vm_name}"
        local state

        if echo "${running_vms}" | grep -q "\"${vbox_name}\""; then
            state="RUNNING"
        elif vm_exists "${vm_name}"; then
            # Get saved/powered-off state
            local vm_state
            vm_state="$(VBoxManage showvminfo "${vbox_name}" --machinereadable 2>/dev/null \
                | grep '^VMState=' | cut -d= -f2 | tr -d '"' || echo "unknown")"
            state="${vm_state^^}"
        else
            state="NOT REGISTERED"
        fi

        printf "%-12s %-26s %-12s\n" "${vm_name}" "${fqdn}" "${state}"
    done
}

# ==============================================================================
# wait_for_winrm <vm_name> [timeout_seconds]
# Polls TCP 5985 until open.  Default timeout: 600 s (10 min).
# ==============================================================================
wait_for_winrm() {
    local vm_name="$1"
    local timeout="${2:-600}"

    if [[ -z "${VM_IP[$vm_name]+_}" ]]; then
        err "No IP mapping for VM: ${vm_name}"
        return 1
    fi

    local ip="${VM_IP[$vm_name]}"
    log "Waiting for WinRM on ${vm_name} (${ip}:5985) — timeout ${timeout}s..."

    local elapsed=0
    while [[ "${elapsed}" -lt "${timeout}" ]]; do
        if bash -c ">/dev/tcp/${ip}/5985" 2>/dev/null; then
            log "${vm_name} WinRM is UP (${ip}:5985) after ${elapsed}s."
            return 0
        fi
        sleep 5
        elapsed=$(( elapsed + 5 ))
    done

    err "Timed out waiting for WinRM on ${vm_name} (${ip}:5985) after ${timeout}s."
    return 1
}

# ==============================================================================
# wait_for_winrm_all [profile] [timeout_seconds]
# ==============================================================================
wait_for_winrm_all() {
    local profile="${1:-full}"
    local timeout="${2:-600}"

    local vm_list
    read -ra vm_list <<< "$(profile_vms "${profile}")"

    for vm_name in "${vm_list[@]}"; do
        wait_for_winrm "${vm_name}" "${timeout}" &
    done
    wait
    log "All WinRM checks complete for profile '${profile}'."
}

# ==============================================================================
# create_all [profile]
# Sets up host-only networks, then imports and configures each VM.
# ==============================================================================
create_all() {
    local profile="${1:-full}"

    local vm_list
    read -ra vm_list <<< "$(profile_vms "${profile}")"

    log "Setting up host-only networks..."
    setup_host_only_networks

    log "Creating VMs — profile: ${profile} (${#vm_list[@]} VMs)"

    for vm_name in "${vm_list[@]}"; do
        create_vm "${vm_name}"
    done

    log "All VMs created. Starting them..."
    for vm_name in "${vm_list[@]}"; do
        start_vm "${vm_name}"
    done

    log "All VMs started."
    status
}

# ==============================================================================
# usage
# ==============================================================================
usage() {
    cat >&2 <<EOF
Usage: $(basename "$0") [OPTIONS] COMMAND [ARGS]

Options:
  --packer-output <dir>   Directory containing packer-output/ subdirs
                          (default: ${DUNDER_HOME}/packer-output)
  --profile <profile>     VM profile: full | minimal | single-dc (default: full)

Commands:
  create [profile]        Import OVAs and configure all VMs in profile
  start <vm>              Start a single VM headlessly
  stop <vm>               Save state of a single VM
  destroy <vm>            Unregister + delete a single VM
  destroy-all [profile]   Unregister + delete all VMs in profile
  status                  Show state of all VMs
  wait-winrm <vm>         Poll WinRM (TCP 5985) until ready
  wait-winrm-all [profile]  Poll WinRM for all VMs in profile
  setup-networks          Create/configure host-only interfaces only

VM names: ${PROFILE_FULL[*]}
Profiles:
  full       — all 8 VMs
  minimal    — corp.local only (dc01 dc01eu ca01 file01 sql01 ws01)
  single-dc  — dc01 only
EOF
    exit 1
}

# ==============================================================================
# Entrypoint
# ==============================================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Parse global options before the subcommand
    while [[ "${1:-}" == --* ]]; do
        case "$1" in
            --packer-output)
                PACKER_OUTPUT="${2:?--packer-output requires a directory argument}"
                shift 2
                ;;
            --profile)
                DEFAULT_PROFILE="${2:?--profile requires a value}"
                shift 2
                ;;
            --help|-h)
                usage
                ;;
            *)
                err "Unknown option: $1"
                usage
                ;;
        esac
    done

    DEFAULT_PROFILE="${DEFAULT_PROFILE:-full}"
    COMMAND="${1:-}"
    shift || true

    case "${COMMAND}" in
        create)
            create_all "${1:-${DEFAULT_PROFILE}}"
            ;;
        start)
            vm="${1:?start requires a VM name}"
            start_vm "${vm}"
            ;;
        stop)
            vm="${1:?stop requires a VM name}"
            stop_vm "${vm}"
            ;;
        destroy)
            vm="${1:?destroy requires a VM name}"
            destroy_vm "${vm}"
            ;;
        destroy-all)
            destroy_all "${1:-${DEFAULT_PROFILE}}"
            ;;
        status)
            status
            ;;
        wait-winrm)
            vm="${1:?wait-winrm requires a VM name}"
            wait_for_winrm "${vm}" "${2:-600}"
            ;;
        wait-winrm-all)
            wait_for_winrm_all "${1:-${DEFAULT_PROFILE}}" "${2:-600}"
            ;;
        setup-networks)
            setup_host_only_networks
            ;;
        ""|--help|-h)
            usage
            ;;
        *)
            err "Unknown command: ${COMMAND}"
            usage
            ;;
    esac
fi
