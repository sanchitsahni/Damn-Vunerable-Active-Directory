#!/usr/bin/env bash
# ==============================================================================
# DVAD QEMU Provider - VM Create / Launch / Destroy / Status
# ==============================================================================
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DUNDER_HOME="${DUNDER_HOME:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"

# Default packer output dir (can be overridden via --packer-output)
PACKER_OUTPUT="${DUNDER_HOME}/packer-output"

# Per-VM runtime state lives here
VM_STATE_DIR="${DUNDER_HOME}/vms"

VNC_BIND="127.0.0.1"

# ==============================================================================
# Logging helpers
# ==============================================================================
log()  { echo -e "\033[0;32m[+]\033[0m $*" >&2; }
warn() { echo -e "\033[1;33m[!]\033[0m $*" >&2; }
info() { echo -e "\033[0;34m[*]\033[0m $*" >&2; }
err()  { echo -e "\033[0;31m[ERROR]\033[0m $*" >&2; }

# ==============================================================================
# KVM detection
# ==============================================================================
if [[ -e /dev/kvm ]]; then
    KVM_OPT="-enable-kvm"
    ACCEL="kvm"
else
    warn "No KVM available — running in software emulation (very slow)."
    KVM_OPT=""
    ACCEL="tcg"
fi

# ==============================================================================
# VM Definitions
# Format: name|mac|ram_mb|disk_gb|cpu|vnc_port|bridge|base_image
#
# base_image values: server2022 | server2019 | win10
# vnc_port is the absolute TCP port (5901-5908), bound to VNC_BIND only.
# ==============================================================================
declare -A VM_DEFS

VM_DEFS=(
    # corp.local / eu.corp.local segment — bridge dvad-ctf
    ["dc01"]="52:54:00:01:01:01|2048|40|2|5901|dvad-ctf|server2022"
    ["dc01eu"]="52:54:00:01:01:02|1536|25|2|5902|dvad-ctf|server2022"
    ["ca01"]="52:54:00:01:01:03|1536|25|2|5903|dvad-ctf|server2022"
    ["file01"]="52:54:00:01:01:04|1536|20|2|5904|dvad-ctf|server2019"
    ["sql01"]="52:54:00:01:01:05|2048|25|2|5905|dvad-ctf|server2022"
    # ws01 — Server Core member acting as the victim "workstation" (headless,
    # no GUI). Was Win10 Desktop; converted to reuse the server2022 base so the
    # whole lab is GUI-less and lower-RAM. All AD/network/coercion attacks still
    # apply via vuln_victim_exec + vuln_traffic_sim. GUI-only CVEs were removed.
    ["ws01"]="52:54:00:01:01:06|1536|30|2|5906|dvad-ctf|server2022"
    # finance.local segment — single bridge dvad-ctf (10.10.20.x)
    ["dc01fin"]="52:54:00:02:01:01|1536|25|2|5907|dvad-ctf|server2022"
    # root.corp segment — single bridge dvad-ctf (10.10.30.x)
    ["dc01root"]="52:54:00:03:01:01|1536|25|2|5908|dvad-ctf|server2022"
    # linux01 — Ubuntu 22.04 cloud member (Linux-in-AD). NOT a packer build:
    # base_image "ubuntu" resolves to media/ubuntu-22.04-cloud.img and the
    # launch branch boots it COW + a cloud-init NoCloud seed ISO (no install).
    ["linux01"]="52:54:00:01:01:07|2048|20|2|5909|dvad-ctf|ubuntu"
)

# Ordered name → FQDN mapping (associative arrays are unordered in Bash)
declare -A VM_FQDN=(
    ["dc01"]="dc01.corp.local"
    ["dc01eu"]="dc01.eu.corp.local"
    ["ca01"]="ca01.corp.local"
    ["file01"]="file01.corp.local"
    ["sql01"]="sql01.corp.local"
    ["ws01"]="ws01.corp.local"
    ["dc01fin"]="dc01.finance.local"
    ["dc01root"]="dc01.root.corp"
    ["linux01"]="linux01.corp.local"
)

# Profile → VM list (ordered)
PROFILE_FULL=("dc01" "dc01eu" "ca01" "file01" "sql01" "ws01" "dc01fin" "dc01root" "linux01")
PROFILE_MINIMAL=("dc01" "dc01eu" "ca01" "file01" "sql01" "ws01" "linux01")
PROFILE_SINGLE_DC=("dc01")

# ==============================================================================
# Helpers
# ==============================================================================

# resolve_base_image <base_image_key> → absolute path to .qcow2
resolve_base_image() {
    local key="$1"
    local path
    case "$key" in
        server2022) path="${PACKER_OUTPUT}/server2022-qemu/windows-server-2022-base.qcow2" ;;
        server2019) path="${PACKER_OUTPUT}/server2019-qemu/windows-server-2019-base.qcow2" ;;
        win10)      path="${PACKER_OUTPUT}/win10-qemu/windows-10-base.qcow2" ;;
        # ubuntu — prebuilt cloud image fetched by deploy.py phase 0 (no packer).
        ubuntu)     path="${DUNDER_HOME}/media/ubuntu-22.04-cloud.img" ;;
        *)
            err "Unknown base image key: ${key}"
            return 1
            ;;
    esac
    echo "$path"
}

# parse_vm_def <vm_name>
# Exports: vm_mac vm_ram vm_disk vm_cpu vm_vnc_port vm_bridge vm_base_image
parse_vm_def() {
    local name="$1"
    if [[ -z "${VM_DEFS[$name]+_}" ]]; then
        err "Unknown VM: ${name}"
        return 1
    fi
    local def="${VM_DEFS[$name]}"
    IFS='|' read -r vm_mac vm_ram vm_disk vm_cpu vm_vnc_port vm_bridge vm_base_image <<< "$def"
}

# profile_vms <profile> → array of VM names
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

# ensure_tap <vm_name> <bridge>
# Creates tap interface dvad-<vmname> attached to <bridge> if it doesn't exist.
ensure_tap() {
    local vm_name="$1"
    local bridge="$2"
    local tap="dvad-${vm_name}"

    if ip link show "${tap}" &>/dev/null 2>&1; then
        info "TAP ${tap} already exists."
        return 0
    fi

    log "Creating TAP interface ${tap} on bridge ${bridge}..."
    sudo -n ip tuntap add dev "${tap}" mode tap
    sudo -n ip link set "${tap}" master "${bridge}"
    sudo -n ip link set "${tap}" up
}

# destroy_tap <vm_name>
destroy_tap() {
    local vm_name="$1"
    local tap="dvad-${vm_name}"
    if ip link show "${tap}" &>/dev/null 2>&1; then
        sudo -n ip link set "${tap}" down 2>/dev/null || true
        sudo -n ip link delete "${tap}" 2>/dev/null || true
    fi
}

# ==============================================================================
# create_vm <vm_name>
# Clones the base QCOW2 with a backing file (copy-on-write) then launches.
# ==============================================================================
create_vm() {
    local vm_name="$1"

    parse_vm_def "${vm_name}"

    local base_img
    base_img="$(resolve_base_image "${vm_base_image}")"

    if [[ ! -f "${base_img}" ]]; then
        err "Base image not found: ${base_img}"
        err "Run packer build first, or set --packer-output to the correct directory."
        return 1
    fi

    local disk_path="${VM_STATE_DIR}/${vm_name}.qcow2"
    mkdir -p "${VM_STATE_DIR}"

    if [[ -f "${disk_path}" ]]; then
        local sz
        sz="$(stat -c%s "${disk_path}" 2>/dev/null || echo 0)"
        if [[ "${sz}" -gt 1048576 ]]; then
            info "Disk for ${vm_name} already exists ($(du -h "${disk_path}" | cut -f1)). Skipping clone."
        else
            warn "Existing disk for ${vm_name} is too small (${sz} B) — removing and re-cloning."
            rm -f "${disk_path}"
            qemu-img create -f qcow2 -b "${base_img}" -F qcow2 "${disk_path}"
            log "Cloned ${base_img} → ${disk_path}"
        fi
    else
        log "Cloning base image for ${vm_name}: ${base_img} → ${disk_path}"
        qemu-img create -f qcow2 -b "${base_img}" -F qcow2 "${disk_path}"
        log "Clone complete for ${vm_name}."
    fi

    launch_vm "${vm_name}"
}

# ==============================================================================
# SSH key + cloud-init NoCloud seed ISO for Linux members
# ==============================================================================

# Path to the lab SSH private key ansible uses to reach Linux members.
LINUX_SSH_KEY="${DUNDER_HOME}/vms/linux01_id"

# ensure_linux_ssh_key — generate vms/linux01_id{,.pub} if absent (idempotent).
ensure_linux_ssh_key() {
    mkdir -p "${VM_STATE_DIR}"
    if [[ -f "${LINUX_SSH_KEY}" && -f "${LINUX_SSH_KEY}.pub" ]]; then
        return 0
    fi
    log "Generating lab SSH keypair for Linux members → ${LINUX_SSH_KEY}"
    ssh-keygen -t ed25519 -N "" -C "labadmin@dunder" -f "${LINUX_SSH_KEY}" >/dev/null
}

# detect_iso_tool — echo the first available ISO-builder, or empty if none.
detect_iso_tool() {
    if command -v cloud-localds &>/dev/null;  then echo "cloud-localds"; return 0; fi
    if command -v genisoimage &>/dev/null;    then echo "genisoimage";   return 0; fi
    if command -v mkisofs &>/dev/null;        then echo "mkisofs";       return 0; fi
    if command -v xorriso &>/dev/null;        then echo "xorriso";       return 0; fi
    echo ""
}

# build_seed_iso <vm_name> <fqdn>
# Writes user-data + meta-data and packs a NoCloud seed ISO at
# vms/<vm>-seed.iso. Idempotent: rebuilt each launch so key/IP edits apply.
build_seed_iso() {
    local vm_name="$1"
    local fqdn="$2"
    local short="${fqdn%%.*}"

    ensure_linux_ssh_key
    local pubkey
    pubkey="$(cat "${LINUX_SSH_KEY}.pub")"

    local seed_dir="${VM_STATE_DIR}/${vm_name}-seed"
    local seed_iso="${VM_STATE_DIR}/${vm_name}-seed.iso"
    mkdir -p "${seed_dir}"

    # meta-data — instance id + hostname
    cat > "${seed_dir}/meta-data" <<META_EOF
instance-id: ${vm_name}-001
local-hostname: ${short}
META_EOF

    # user-data — labadmin (sudo), known SSH pubkey + password, password SSH on,
    # python3 for ansible. The dnsmasq static lease supplies the IP (DHCP).
    cat > "${seed_dir}/user-data" <<USERDATA_EOF
#cloud-config
hostname: ${short}
fqdn: ${fqdn}
manage_etc_hosts: true
ssh_pwauth: true
disable_root: false
users:
  - name: labadmin
    gecos: DUNDER Lab Admin
    groups: [sudo]
    shell: /bin/bash
    lock_passwd: false
    # password: DVADlab2024!  (intentionally weak — vulnerable lab)
    passwd: \$6\$dunderlab\$Hl0gnUuJ4Yx0a8pYxN0aQ7rGq0i1m3oVrTn9wQ2bFv6sJxN0kS8eR5wT3uY1iO6pA9dG7hL4jK2mN0bV8cX1z.
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - ${pubkey}
package_update: false
packages:
  - python3
runcmd:
  - [ systemctl, enable, --now, ssh ]
USERDATA_EOF

    log "Building cloud-init NoCloud seed ISO → ${seed_iso}"
    local tool
    tool="$(detect_iso_tool)"
    case "${tool}" in
        cloud-localds)
            cloud-localds "${seed_iso}" "${seed_dir}/user-data" "${seed_dir}/meta-data"
            ;;
        genisoimage|mkisofs)
            "${tool}" -output "${seed_iso}" -volid cidata -joliet -rock \
                "${seed_dir}/user-data" "${seed_dir}/meta-data" >/dev/null 2>&1
            ;;
        xorriso)
            xorriso -as mkisofs -output "${seed_iso}" -volid cidata -joliet -rock \
                "${seed_dir}/user-data" "${seed_dir}/meta-data" >/dev/null 2>&1
            ;;
        *)
            err "No ISO builder found (need cloud-localds, genisoimage, mkisofs, or xorriso)."
            err "Install one (e.g. apt install genisoimage) and re-run."
            return 1
            ;;
    esac
    [[ -f "${seed_iso}" ]] || { err "Seed ISO not produced at ${seed_iso}"; return 1; }
}

# ==============================================================================
# launch_linux_vm <vm_name>
# Boots an Ubuntu cloud image (virtio disk) + cloud-init NoCloud seed ISO.
# No install media, no WinRM — straight to multi-user + SSH.
# ==============================================================================
launch_linux_vm() {
    local vm_name="$1"

    parse_vm_def "${vm_name}"

    local fqdn="${VM_FQDN[$vm_name]:-$vm_name}"
    local disk_path="${VM_STATE_DIR}/${vm_name}.qcow2"
    local pid_file="${VM_STATE_DIR}/${vm_name}.pid"
    local mon_file="${VM_STATE_DIR}/${vm_name}.mon"
    local log_file="${VM_STATE_DIR}/${vm_name}.log"
    local seed_iso="${VM_STATE_DIR}/${vm_name}-seed.iso"

    if [[ ! -f "${disk_path}" ]]; then
        err "No disk found for ${vm_name} at ${disk_path}. Run create_vm first."
        return 1
    fi

    if [[ -f "${pid_file}" ]] && kill -0 "$(cat "${pid_file}")" 2>/dev/null; then
        info "${vm_name} is already running (PID: $(cat "${pid_file}"))."
        return 0
    fi
    rm -f "${pid_file}"

    build_seed_iso "${vm_name}" "${fqdn}" || return 1

    ensure_tap "${vm_name}" "${vm_bridge}"

    local tap="dvad-${vm_name}"
    local vnc_display="${VNC_BIND}:$((vm_vnc_port - 5900))"

    log "Launching Linux ${vm_name} (${fqdn}) — VNC ${vnc_display} (port ${vm_vnc_port})"

    qemu-system-x86_64 \
        -name          "${vm_name}" \
        -machine       "q35,accel=${ACCEL}" \
        ${KVM_OPT} \
        -cpu           host \
        -smp           "cpus=${vm_cpu}" \
        -m             "${vm_ram}M" \
        -drive         "file=${disk_path},if=virtio,format=qcow2,cache=writeback" \
        -drive         "file=${seed_iso},if=virtio,format=raw,media=cdrom" \
        -netdev        "tap,id=net0,ifname=${tap},script=no,downscript=no" \
        -device        "virtio-net-pci,netdev=net0,mac=${vm_mac}" \
        -display       none \
        -vnc           "${vnc_display}" \
        -vga           std \
        -rtc           "base=utc" \
        -boot          "order=c" \
        -daemonize \
        -pidfile       "${pid_file}" \
        -monitor       "unix:${mon_file},server,nowait" \
        2>"${log_file}" || {
            err "${vm_name} failed to launch. Last log:"
            tail -10 "${log_file}" | sed 's/^/    /' >&2 || true
            return 1
        }

    local waited=0
    while [[ "${waited}" -lt 10 ]]; do
        [[ -f "${pid_file}" ]] && break
        sleep 1
        waited=$(( waited + 1 ))
    done

    if [[ -f "${pid_file}" ]]; then
        log "${vm_name} started (PID: $(cat "${pid_file}"), VNC ${VNC_BIND}:${vm_vnc_port})"
    else
        err "${vm_name} failed to start — no PID file after ${waited}s."
        [[ -f "${log_file}" ]] && tail -5 "${log_file}" | sed 's/^/    /' >&2 || true
        return 1
    fi
}

# ==============================================================================
# launch_vm <vm_name>
# Starts a VM that already has a cloned disk.  No ISO — boots from disk only.
# Linux members (base_image=ubuntu) are delegated to launch_linux_vm.
# ==============================================================================
launch_vm() {
    local vm_name="$1"

    parse_vm_def "${vm_name}"

    # Linux member → cloud-image + seed-ISO boot path.
    if [[ "${vm_base_image}" == "ubuntu" ]]; then
        launch_linux_vm "${vm_name}"
        return $?
    fi

    local fqdn="${VM_FQDN[$vm_name]:-$vm_name}"
    local disk_path="${VM_STATE_DIR}/${vm_name}.qcow2"
    local pid_file="${VM_STATE_DIR}/${vm_name}.pid"
    local mon_file="${VM_STATE_DIR}/${vm_name}.mon"
    local log_file="${VM_STATE_DIR}/${vm_name}.log"

    if [[ ! -f "${disk_path}" ]]; then
        err "No disk found for ${vm_name} at ${disk_path}. Run create_vm first."
        return 1
    fi

    # Already running?
    if [[ -f "${pid_file}" ]] && kill -0 "$(cat "${pid_file}")" 2>/dev/null; then
        info "${vm_name} is already running (PID: $(cat "${pid_file}"))."
        return 0
    fi

    # Remove stale PID file
    rm -f "${pid_file}"

    ensure_tap "${vm_name}" "${vm_bridge}"

    local tap="dvad-${vm_name}"
    local vnc_display="${VNC_BIND}:$((vm_vnc_port - 5900))"

    log "Launching ${vm_name} (${fqdn}) — VNC ${vnc_display} (port ${vm_vnc_port})"

    qemu-system-x86_64 \
        -name          "${vm_name}" \
        -machine       "q35,accel=${ACCEL}" \
        ${KVM_OPT} \
        -cpu           host \
        -smp           "cpus=${vm_cpu}" \
        -m             "${vm_ram}M" \
        -drive         "file=${disk_path},if=none,id=drive0,format=qcow2,cache=writeback" \
        -device        "ahci,id=ahci0" \
        -device        "ide-hd,drive=drive0,bus=ahci0.0,bootindex=1" \
        -netdev        "tap,id=net0,ifname=${tap},script=no,downscript=no" \
        -device        "e1000e,netdev=net0,mac=${vm_mac}" \
        -display       none \
        -vnc           "${vnc_display}" \
        -vga           std \
        -rtc           "base=localtime" \
        -boot          "order=c" \
        -daemonize \
        -pidfile       "${pid_file}" \
        -monitor       "unix:${mon_file},server,nowait" \
        2>"${log_file}" || {
            err "${vm_name} failed to launch. Last log:"
            tail -10 "${log_file}" | sed 's/^/    /' >&2 || true
            return 1
        }

    # Wait up to 10 s for daemonize to write PID file
    local waited=0
    while [[ "${waited}" -lt 10 ]]; do
        [[ -f "${pid_file}" ]] && break
        sleep 1
        waited=$(( waited + 1 ))
    done

    if [[ -f "${pid_file}" ]]; then
        log "${vm_name} started (PID: $(cat "${pid_file}"), VNC ${VNC_BIND}:${vm_vnc_port})"
    else
        err "${vm_name} failed to start — no PID file after ${waited}s."
        [[ -f "${log_file}" ]] && tail -5 "${log_file}" | sed 's/^/    /' >&2 || true
        return 1
    fi
}

# ==============================================================================
# destroy_vm <vm_name>
# Kills QEMU process + removes disk and state files.
# ==============================================================================
destroy_vm() {
    local vm_name="$1"
    local pid_file="${VM_STATE_DIR}/${vm_name}.pid"
    local disk_path="${VM_STATE_DIR}/${vm_name}.qcow2"

    if [[ -f "${pid_file}" ]]; then
        local pid
        pid="$(cat "${pid_file}")"
        log "Killing ${vm_name} (PID: ${pid})..."
        kill "${pid}" 2>/dev/null || true
        # Grace period then hard kill
        local waited=0
        while kill -0 "${pid}" 2>/dev/null && [[ "${waited}" -lt 5 ]]; do
            sleep 1
            waited=$(( waited + 1 ))
        done
        kill -9 "${pid}" 2>/dev/null || true
        rm -f "${pid_file}"
    else
        info "No PID file for ${vm_name} — VM may already be stopped."
    fi

    destroy_tap "${vm_name}"

    if [[ -f "${disk_path}" ]]; then
        log "Removing disk ${disk_path}..."
        rm -f "${disk_path}"
    fi

    rm -f \
        "${VM_STATE_DIR}/${vm_name}.mon" \
        "${VM_STATE_DIR}/${vm_name}.log"

    # Linux members carry a cloud-init seed ISO + scratch dir — clean those too.
    rm -f  "${VM_STATE_DIR}/${vm_name}-seed.iso"
    rm -rf "${VM_STATE_DIR}/${vm_name}-seed"

    log "${vm_name} destroyed."
}

# ==============================================================================
# destroy_all [profile]
# Destroys every VM in the given profile (default: full).
# ==============================================================================
destroy_all() {
    local profile="${1:-full}"
    warn "Destroying all VMs in profile '${profile}'..."

    local vm_list
    IFS=' ' read -ra vm_list <<< "$(profile_vms "${profile}")"

    for vm_name in "${vm_list[@]}"; do
        destroy_vm "${vm_name}"
    done

    log "All VMs in profile '${profile}' destroyed."
}

# ==============================================================================
# status
# Prints running/stopped state for every defined VM.
# ==============================================================================
status() {
    echo "=== DVAD QEMU VM Status ==="
    printf "%-12s %-26s %-8s %s\n" "NAME" "FQDN" "STATE" "DETAIL"
    printf "%-12s %-26s %-8s %s\n" "----" "----" "-----" "------"

    for vm_name in "${PROFILE_FULL[@]}"; do
        local fqdn="${VM_FQDN[$vm_name]:-$vm_name}"
        local pid_file="${VM_STATE_DIR}/${vm_name}.pid"
        local state detail

        if [[ -f "${pid_file}" ]] && kill -0 "$(cat "${pid_file}")" 2>/dev/null; then
            state="RUNNING"
            parse_vm_def "${vm_name}"
            detail="PID=$(cat "${pid_file}") VNC=${VNC_BIND}:${vm_vnc_port}"
        elif [[ -f "${pid_file}" ]]; then
            state="DEAD"
            detail="stale PID file: ${pid_file}"
        else
            state="STOPPED"
            detail=""
        fi

        printf "%-12s %-26s %-8s %s\n" "${vm_name}" "${fqdn}" "${state}" "${detail}"
    done
}

# ==============================================================================
# wait_for_winrm <vm_name> [timeout_seconds]
# Polls TCP 5985 until open, signalling VM is ready for Ansible.
# Default timeout: 600 s (10 min).
# ==============================================================================
wait_for_winrm() {
    local vm_name="$1"
    local timeout="${2:-600}"

    parse_vm_def "${vm_name}"

    # Resolve IP from dnsmasq static lease mapping (keyed by MAC)
    # The static IPs are assigned by the bridge DHCP — we infer from FQDN/MAC table.
    local ip
    ip="$(get_vm_ip "${vm_name}")"

    # Linux members have no WinRM — wait for SSH (TCP 22) readiness instead.
    local port="5985" svc="WinRM"
    if [[ "${vm_base_image}" == "ubuntu" ]]; then
        port="22"; svc="SSH"
    fi

    log "Waiting for ${svc} on ${vm_name} (${ip}:${port}) — timeout ${timeout}s..."

    local elapsed=0
    while [[ "${elapsed}" -lt "${timeout}" ]]; do
        if bash -c ">/dev/tcp/${ip}/${port}" 2>/dev/null; then
            log "${vm_name} ${svc} is UP (${ip}:${port}) after ${elapsed}s."
            return 0
        fi
        sleep 5
        elapsed=$(( elapsed + 5 ))
    done

    err "Timed out waiting for ${svc} on ${vm_name} (${ip}:${port}) after ${timeout}s."
    return 1
}

# get_vm_ip <vm_name> — maps VM name to its static IP
get_vm_ip() {
    local vm_name="$1"
    case "${vm_name}" in
        dc01)     echo "10.10.0.10"  ;;
        dc01eu)   echo "10.10.0.11"  ;;
        ca01)     echo "10.10.0.12"  ;;
        file01)   echo "10.10.0.13"  ;;
        sql01)    echo "10.10.0.14"  ;;
        ws01)     echo "10.10.0.100" ;;
        dc01fin)  echo "10.10.20.10" ;;
        dc01root) echo "10.10.30.10" ;;
        linux01)  echo "10.10.0.15"  ;;
        *)
            err "No IP mapping for VM: ${vm_name}"
            return 1
            ;;
    esac
}

# ==============================================================================
# wait_for_winrm_all [profile] [timeout_seconds]
# ==============================================================================
wait_for_winrm_all() {
    local profile="${1:-full}"
    local timeout="${2:-600}"

    local vm_list
    IFS=' ' read -ra vm_list <<< "$(profile_vms "${profile}")" || true
    if [[ "${#vm_list[@]}" -eq 0 ]]; then
        err "No VMs for profile '${profile}' (valid: full|minimal|single-dc)."
        return 1
    fi

    for vm_name in "${vm_list[@]}"; do
        wait_for_winrm "${vm_name}" "${timeout}" &
    done
    wait
    log "All WinRM checks complete for profile '${profile}'."
}

# ==============================================================================
# create_all [profile]
# ==============================================================================
create_all() {
    local profile="${1:-full}"

    local vm_list
    IFS=' ' read -ra vm_list <<< "$(profile_vms "${profile}")" || true
    if [[ "${#vm_list[@]}" -eq 0 ]]; then
        err "No VMs for profile '${profile}' (valid: full|minimal|single-dc)."
        return 1
    fi

    log "Creating VMs — profile: ${profile} (${#vm_list[@]} VMs)"
    mkdir -p "${VM_STATE_DIR}"

    for vm_name in "${vm_list[@]}"; do
        create_vm "${vm_name}" &
    done
    wait

    log "All VMs launched. VNC endpoints:"
    for vm_name in "${vm_list[@]}"; do
        parse_vm_def "${vm_name}"
        local fqdn="${VM_FQDN[$vm_name]:-$vm_name}"
        echo "  ${vm_name} (${fqdn}) -> ${VNC_BIND}:${vm_vnc_port}"
    done
}

# ==============================================================================
# start_all [profile] — (re)launch every VM in the profile that has a cloned disk
# ==============================================================================
start_all() {
    local profile="${1:-full}"
    local vm_list
    IFS=' ' read -ra vm_list <<< "$(profile_vms "${profile}")" || true
    if [[ "${#vm_list[@]}" -eq 0 ]]; then
        err "No VMs for profile '${profile}'."
        return 1
    fi
    for vm_name in "${vm_list[@]}"; do
        local disk="${VM_STATE_DIR}/${vm_name}.qcow2"
        local pid_file="${VM_STATE_DIR}/${vm_name}.pid"
        if [[ -f "${pid_file}" ]] && kill -0 "$(cat "${pid_file}" 2>/dev/null)" 2>/dev/null; then
            info "${vm_name} already running."
            continue
        fi
        if [[ -f "${disk}" ]]; then
            launch_vm "${vm_name}" &
        else
            warn "${vm_name} has no disk — run 'create' first."
        fi
    done
    wait
    log "Start complete for profile '${profile}'."
}

# ==============================================================================
# stop_all [profile] — gracefully stop every running VM in the profile
# ==============================================================================
stop_all() {
    local profile="${1:-full}"
    local vm_list
    IFS=' ' read -ra vm_list <<< "$(profile_vms "${profile}")" || true
    for vm_name in "${vm_list[@]}"; do
        local pid_file="${VM_STATE_DIR}/${vm_name}.pid"
        if [[ -f "${pid_file}" ]]; then
            local pid; pid="$(cat "${pid_file}" 2>/dev/null || true)"
            if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
                log "Stopping ${vm_name} (pid ${pid})..."
                kill "${pid}" 2>/dev/null || true
            fi
            rm -f "${pid_file}"
        fi
    done
    log "Stop complete for profile '${profile}'."
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
  create [profile]        Clone base images and launch all VMs in profile
  launch <vm>             Launch a single already-cloned VM
  destroy <vm>            Kill + delete a single VM
  destroy-all [profile]   Kill + delete all VMs in profile
  status                  Show running/stopped state for all VMs
  wait-winrm <vm>         Poll WinRM (TCP 5985) until ready
  wait-winrm-all [profile]  Poll WinRM for all VMs in profile

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
    # Parse flags ANYWHERE (before or after the subcommand) and collect the rest
    # as positional args. deploy.py passes e.g. `create --profile full`, so a
    # before-command-only parser silently dropped --profile -> 0 VMs created.
    POSITIONAL=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --packer-output)
                PACKER_OUTPUT="${2:?--packer-output requires a directory argument}"
                shift 2 ;;
            --profile)
                DEFAULT_PROFILE="${2:?--profile requires a value}"
                shift 2 ;;
            --help|-h)
                usage ;;
            --*)
                err "Unknown option: $1"; usage ;;
            *)
                POSITIONAL+=("$1"); shift ;;
        esac
    done
    set -- ${POSITIONAL[@]+"${POSITIONAL[@]}"}

    DEFAULT_PROFILE="${DEFAULT_PROFILE:-full}"
    COMMAND="${1:-}"
    shift || true

    case "${COMMAND}" in
        create)
            create_all "${1:-${DEFAULT_PROFILE}}"
            ;;
        start)
            start_all "${1:-${DEFAULT_PROFILE}}"
            ;;
        stop)
            stop_all "${1:-${DEFAULT_PROFILE}}"
            ;;
        launch)
            vm="${1:?launch requires a VM name}"
            launch_vm "${vm}"
            ;;
        destroy)
            # bare `destroy` (no VM name) tears down the whole profile
            if [[ -n "${1:-}" ]]; then destroy_vm "${1}"; else destroy_all "${DEFAULT_PROFILE}"; fi
            ;;
        destroy-all)
            destroy_all "${1:-${DEFAULT_PROFILE}}"
            ;;
        status)
            status
            ;;
        wait-winrm)
            # with a VM name -> single; without -> whole profile
            if [[ -n "${1:-}" ]]; then wait_for_winrm "${1}" "${2:-600}"; else wait_for_winrm_all "${DEFAULT_PROFILE}" "600"; fi
            ;;
        wait-winrm-all)
            wait_for_winrm_all "${1:-${DEFAULT_PROFILE}}" "${2:-600}"
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
