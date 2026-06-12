#!/usr/bin/env bash
# ==============================================================================
# EMPIRE QEMU Provider - VM Create / Launch / Destroy / Status
# ==============================================================================
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EMPIRE_HOME="${EMPIRE_HOME:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"

# Default packer output dir (can be overridden via --packer-output)
PACKER_OUTPUT="${EMPIRE_HOME}/packer-output"

# Per-VM runtime state lives here
VM_STATE_DIR="${EMPIRE_HOME}/vms"

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

# RAM right-sized BY LOAD to keep the full 9-VM lab under ~16 GB real usage.
# Sum = 12.25 GB alloc -> ~15 GB real with qemu overhead. The workhorses get
# more; the near-idle lone trust DCs (yavin4/neimoidia) and the child DC get
# the floor. All guests have Windows pagefile on, so transient spikes swap
# rather than OOM. If a low-RAM DC's promotion still struggles, bump it +256.
#   coruscant    1792  forest root: AD+DNS+both trusts + bulk of vuln injection
#   kamino   1792  MSSQL engine (memory-hungry)
#   endor    1536  ADCS / CA role
#   deathstar  1280  child DC (light)
#   scarif  1280  2019 file/IIS/SMB/services
#   yavin4 1280  lone DC — only holds the finance trust (near-idle)
#   dc01root1280  lone DC — only holds the root trust (near-idle)
#   mandalore 1280  Ubuntu + lightweight services
#   tatooine    1024  Server Core victim member (no roles, just sim tasks)
VM_DEFS=(
    # empire.local / eu.empire.local segment — bridge empire-ctf
    ["coruscant"]="52:54:00:01:01:01|1792|40|2|5901|empire-ctf|server2022"
    ["deathstar"]="52:54:00:01:01:02|1280|25|2|5902|empire-ctf|server2022"
    ["endor"]="52:54:00:01:01:03|1536|25|2|5903|empire-ctf|server2022"
    ["scarif"]="52:54:00:01:01:04|1280|20|2|5904|empire-ctf|server2019"
    ["kamino"]="52:54:00:01:01:05|1792|25|2|5905|empire-ctf|server2022"
    # tatooine — Server Core member acting as the victim "workstation" (headless,
    # no GUI). Was Win10 Desktop; converted to reuse the server2022 base so the
    # whole lab is GUI-less and lower-RAM. All AD/network/coercion attacks still
    # apply via vuln_victim_exec + vuln_traffic_sim. GUI-only CVEs were removed.
    ["tatooine"]="52:54:00:01:01:06|1024|30|2|5906|empire-ctf|server2022"
    # rebel.local segment — single bridge empire-ctf (10.10.20.x)
    ["yavin4"]="52:54:00:02:01:01|1280|25|2|5907|empire-ctf|server2022"
    # trade.corp segment — single bridge empire-ctf (10.10.30.x)
    ["neimoidia"]="52:54:00:03:01:01|1280|25|2|5908|empire-ctf|server2022"
    # mandalore — Ubuntu 22.04 cloud member (Linux-in-AD). NOT a packer build:
    # base_image "ubuntu" resolves to media/ubuntu-22.04-cloud.img and the
    # launch branch boots it COW + a cloud-init NoCloud seed ISO (no install).
    ["mandalore"]="52:54:00:01:01:07|1280|20|2|5909|empire-ctf|ubuntu"
)

# Ordered name → FQDN mapping (associative arrays are unordered in Bash)
declare -A VM_FQDN=(
    ["coruscant"]="coruscant.empire.local"
    ["deathstar"]="deathstar.eu.empire.local"
    ["endor"]="endor.empire.local"
    ["scarif"]="scarif.empire.local"
    ["kamino"]="kamino.empire.local"
    ["tatooine"]="tatooine.empire.local"
    ["yavin4"]="yavin4.rebel.local"
    ["neimoidia"]="neimoidia.trade.corp"
    ["mandalore"]="mandalore.empire.local"
)

# Profile → VM list (ordered)
PROFILE_FULL=("coruscant" "deathstar" "endor" "scarif" "kamino" "tatooine" "yavin4" "neimoidia" "mandalore")
PROFILE_MINIMAL=("coruscant" "deathstar" "endor" "scarif" "kamino" "tatooine" "mandalore")
PROFILE_SINGLE_DC=("coruscant")

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
        ubuntu)     path="${EMPIRE_HOME}/media/ubuntu-22.04-cloud.img" ;;
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
# Creates tap interface empire-<vmname> attached to <bridge> if it doesn't exist.
ensure_tap() {
    local vm_name="$1"
    local bridge="$2"
    local tap="emp-${vm_name}"   # short prefix: Linux IFNAMSIZ caps iface names at 15 chars

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
    local tap="emp-${vm_name}"   # short prefix: Linux IFNAMSIZ caps iface names at 15 chars
    if ip link show "${tap}" &>/dev/null 2>&1; then
        sudo -n ip link set "${tap}" down 2>/dev/null || true
        sudo -n ip link delete "${tap}" 2>/dev/null || true
    fi
}

# ==============================================================================
# ALL-FRESH Windows install (no CoW cloning -> every VM gets a UNIQUE machine
# SID, which is what a child DC needs to join an existing forest). Each Windows
# VM installs from the ISO via an unattended answer file; the Linux member still
# boots the Ubuntu cloud image CoW (machine identity handled by cloud-init).
# ==============================================================================

# resolve_win_iso <base_image_key> -> path to the Windows install ISO
resolve_win_iso() {
    case "$1" in
        server2022) echo "${EMPIRE_HOME}/media/windows-server-2022.iso" ;;
        server2019) echo "${EMPIRE_HOME}/media/windows-server-2019.iso" ;;
        win10)      echo "${EMPIRE_HOME}/media/windows-10.iso" ;;
        *) err "No Windows ISO mapping for base image: $1"; return 1 ;;
    esac
}

# build_unattend_iso <vm_name> <os_key>
# Packs Autounattend.xml (per-OS) + setup-winrm.ps1 onto a small ISO labelled
# UNATTEND. Windows Setup auto-detects Autounattend.xml at the CD root; the
# FirstLogonCommand finds setup-winrm.ps1 by scanning drive letters.
build_unattend_iso() {
    local vm_name="$1" os="$2"
    local ua_src="${SCRIPT_DIR}/unattend/autounattend-${os}.xml"
    local winrm_src="${EMPIRE_HOME}/packer/scripts/setup-winrm.ps1"
    [[ -f "${ua_src}" ]]    || { err "No autounattend for ${os}: ${ua_src}"; return 1; }
    [[ -f "${winrm_src}" ]] || { err "setup-winrm.ps1 missing: ${winrm_src}"; return 1; }

    local stage="${VM_STATE_DIR}/${vm_name}-unattend"
    local iso="${VM_STATE_DIR}/${vm_name}-unattend.iso"
    rm -rf "${stage}"; mkdir -p "${stage}"
    cp "${ua_src}"    "${stage}/Autounattend.xml"
    cp "${winrm_src}" "${stage}/setup-winrm.ps1"

    if command -v genisoimage &>/dev/null; then
        genisoimage -quiet -output "${iso}" -volid UNATTEND -joliet -rock "${stage}"
    elif command -v mkisofs &>/dev/null; then
        mkisofs -quiet -output "${iso}" -volid UNATTEND -joliet -rock "${stage}"
    elif command -v xorriso &>/dev/null; then
        xorriso -as mkisofs -output "${iso}" -volid UNATTEND -joliet -rock "${stage}" >/dev/null 2>&1
    else
        err "Need genisoimage, mkisofs, or xorriso to build the unattend ISO."
        return 1
    fi
    [[ -f "${iso}" ]] || { err "Unattend ISO not produced: ${iso}"; return 1; }
}

# _send_boot_keys <monitor_socket>
# Background: nudges 'Enter' into the QEMU HMP monitor so the "Press any key to
# boot from CD or DVD" prompt starts Windows Setup. Under 9 PARALLEL installs the
# prompt can appear well after boot (CPU contention), so send for ~5 min and
# RECONNECT each time (the server,nowait monitor takes one client at a time).
# Stop early once the disk grows past 600 MB (Setup is applying the image), so we
# don't keep hammering Enter into a live WinPE session.
_send_boot_keys() {
    local mon="$1"
    local disk="$2"
    ( python3 - "${mon}" "${disk}" <<'PY' 2>/dev/null || true
import socket, sys, time, os
sock, disk = sys.argv[1], sys.argv[2]
for _ in range(150):
    try:
        if os.path.exists(disk) and os.path.getsize(disk) > 600_000_000:
            break
        s = socket.socket(socket.AF_UNIX); s.settimeout(2); s.connect(sock)
        try: s.recv(4096)
        except Exception: pass
        s.sendall(b"sendkey ret\n"); s.close()
    except Exception:
        pass
    time.sleep(2)
PY
    ) &
}

# install_windows_vm <vm_name> — blank disk + unattended install from ISO.
install_windows_vm() {
    local vm_name="$1"
    parse_vm_def "${vm_name}"

    local fqdn="${VM_FQDN[$vm_name]:-$vm_name}"
    local disk_path="${VM_STATE_DIR}/${vm_name}.qcow2"
    local pid_file="${VM_STATE_DIR}/${vm_name}.pid"
    local mon_file="${VM_STATE_DIR}/${vm_name}.mon"
    local log_file="${VM_STATE_DIR}/${vm_name}.log"

    local win_iso; win_iso="$(resolve_win_iso "${vm_base_image}")" || return 1
    [[ -f "${win_iso}" ]] || { err "Windows ISO not found: ${win_iso} (run deploy.py phase 0)"; return 1; }

    mkdir -p "${VM_STATE_DIR}"
    rm -f "${disk_path}" "${pid_file}"
    log "Creating blank ${vm_disk}G disk for ${vm_name}"
    qemu-img create -f qcow2 "${disk_path}" "${vm_disk}G" >/dev/null

    build_unattend_iso "${vm_name}" "${vm_base_image}" || return 1
    local ua_iso="${VM_STATE_DIR}/${vm_name}-unattend.iso"

    ensure_tap "${vm_name}" "${vm_bridge}"
    local tap="emp-${vm_name}"   # short prefix: Linux IFNAMSIZ caps iface names at 15 chars
    local vnc_display="${VNC_BIND}:$((vm_vnc_port - 5900))"

    log "Installing ${vm_name} (${fqdn}) FRESH from ${win_iso##*/} — VNC ${vnc_display}"

    # Disk bootindex=1 (empty -> falls through), Windows ISO bootindex=2 (the
    # installer). Post-install the disk is bootable and boots first directly.
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
        -drive         "file=${win_iso},if=none,id=wincd,media=cdrom,readonly=on" \
        -device        "ide-cd,drive=wincd,bus=ahci0.1,bootindex=2" \
        -drive         "file=${ua_iso},if=none,id=uacd,media=cdrom,readonly=on" \
        -device        "ide-cd,drive=uacd,bus=ahci0.2" \
        -netdev        "tap,id=net0,ifname=${tap},script=no,downscript=no" \
        -device        "e1000e,netdev=net0,mac=${vm_mac}" \
        -display       none \
        -vnc           "${vnc_display}" \
        -vga           std \
        -rtc           "base=localtime" \
        -daemonize \
        -pidfile       "${pid_file}" \
        -monitor       "unix:${mon_file},server,nowait" \
        2>"${log_file}" || {
            err "${vm_name} install launch failed. Last log:"
            tail -10 "${log_file}" | sed 's/^/    /' >&2 || true
            return 1
        }

    # Wait for the monitor socket, then nudge past "Press any key to boot from CD".
    local w=0
    while [[ ! -S "${mon_file}" && "${w}" -lt 10 ]]; do sleep 1; w=$(( w + 1 )); done
    _send_boot_keys "${mon_file}" "${disk_path}"

    if [[ -f "${pid_file}" ]]; then
        log "${vm_name} installing (unattended). WinRM expected up in ~15-20 min; phase 4 waits for it."
    else
        err "${vm_name} failed to start install — no PID file."
        [[ -f "${log_file}" ]] && tail -5 "${log_file}" | sed 's/^/    /' >&2 || true
        return 1
    fi
}

# ==============================================================================
# create_vm <vm_name>
# Windows: fresh unattended install from ISO (unique SID). Linux: CoW clone of
# the Ubuntu cloud image + cloud-init seed. Idempotent: a VM that already has a
# '.installed' marker (written by scripts/wait-vms.sh once WinRM answered) just
# boots from its disk.
# ==============================================================================
create_vm() {
    local vm_name="$1"
    parse_vm_def "${vm_name}"
    mkdir -p "${VM_STATE_DIR}"

    local disk_path="${VM_STATE_DIR}/${vm_name}.qcow2"
    local marker="${VM_STATE_DIR}/${vm_name}.installed"

    # Linux member — CoW clone the cloud image, then boot (cloud-init handles id).
    if [[ "${vm_base_image}" == "ubuntu" ]]; then
        local base_img
        base_img="$(resolve_base_image "${vm_base_image}")"
        if [[ ! -f "${base_img}" ]]; then
            err "Cloud image not found: ${base_img} (run deploy.py phase 0)"; return 1
        fi
        if [[ ! -f "${disk_path}" ]]; then
            log "Cloning cloud image for ${vm_name}: ${base_img} → ${disk_path}"
            qemu-img create -f qcow2 -b "${base_img}" -F qcow2 "${disk_path}"
            # Ubuntu cloud images ship a ~2 GB rootfs — too small for apt + AD
            # packages (realmd/sssd/krb5) -> "No space left on device". Grow the
            # overlay to the VM's disk size; cloud-init growpart expands rootfs on boot.
            log "Resizing ${vm_name} disk to ${vm_disk}G (cloud-init grows rootfs)"
            qemu-img resize "${disk_path}" "${vm_disk}G"
        fi
        launch_vm "${vm_name}"
        return $?
    fi

    # Windows — already installed and reachable once -> just boot from disk.
    if [[ -f "${marker}" && -f "${disk_path}" ]]; then
        info "${vm_name} already installed — booting from disk."
        launch_vm "${vm_name}"
        return $?
    fi

    # Windows — fresh unattended install from ISO.
    install_windows_vm "${vm_name}"
}

# ==============================================================================
# SSH key + cloud-init NoCloud seed ISO for Linux members
# ==============================================================================

# Path to the lab SSH private key ansible uses to reach Linux members.
LINUX_SSH_KEY="${EMPIRE_HOME}/vms/linux01_id"

# ensure_linux_ssh_key — generate vms/linux01_id{,.pub} if absent (idempotent).
ensure_linux_ssh_key() {
    mkdir -p "${VM_STATE_DIR}"
    if [[ -f "${LINUX_SSH_KEY}" && -f "${LINUX_SSH_KEY}.pub" ]]; then
        return 0
    fi
    log "Generating lab SSH keypair for Linux members → ${LINUX_SSH_KEY}"
    ssh-keygen -t ed25519 -N "" -C "labadmin@empire" -f "${LINUX_SSH_KEY}" >/dev/null
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
    gecos: EMPIRE Lab Admin
    groups: [sudo]
    shell: /bin/bash
    lock_passwd: false
    # password: SithLord123!  (intentionally weak — vulnerable lab)
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

    local tap="emp-${vm_name}"   # short prefix: Linux IFNAMSIZ caps iface names at 15 chars
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

    local tap="emp-${vm_name}"   # short prefix: Linux IFNAMSIZ caps iface names at 15 chars
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

    # ── Name-independent sweep ────────────────────────────────────────────────
    # A profile rename (e.g. dc01 -> coruscant) orphans the OLD VMs/taps because
    # the loop above only knows the CURRENT names. Sweep everything that belongs
    # to this project regardless of name so a rename can't leave zombies.

    # 1) Kill any QEMU whose command line references our VM_STATE_DIR (any disk,
    #    monitor, or pidfile under vms/), old or new name.
    local pids
    pids="$(pgrep -af qemu-system 2>/dev/null | grep -F "${VM_STATE_DIR}" | awk '{print $1}')"
    for pid in ${pids}; do
        warn "Killing orphaned QEMU PID ${pid}"
        kill "${pid}" 2>/dev/null || true
        sleep 1
        kill -9 "${pid}" 2>/dev/null || true
    done

    # 2) Remove every project TAP (empire-* AND legacy dvad-* orphans from the
    #    pre-rename naming) — but never the empire-ctf/empire-nat bridges.
    local iface
    for iface in $(ip -o link show 2>/dev/null | grep -oE '(emp|empire|dvad)-[a-z0-9]+' | sort -u); do
        case "${iface}" in
            empire-ctf|empire-nat|dvad-ctf|dvad-nat) continue ;;   # bridges
        esac
        sudo -n ip link set "${iface}" down 2>/dev/null || true
        sudo -n ip link delete "${iface}" 2>/dev/null || true
    done
    # Tear down the legacy dvad-ctf/dvad-nat bridges if they linger from before.
    for br in dvad-ctf dvad-nat; do
        ip link show "${br}" &>/dev/null && { sudo -n ip link set "${br}" down 2>/dev/null || true; sudo -n ip link delete "${br}" 2>/dev/null || true; }
    done

    # 3) Clean stray per-VM state files (disks/pids/mons/logs/ISOs/markers).
    rm -f "${VM_STATE_DIR}"/*.pid "${VM_STATE_DIR}"/*.mon "${VM_STATE_DIR}"/*.log \
          "${VM_STATE_DIR}"/*.installed "${VM_STATE_DIR}"/*-unattend.iso 2>/dev/null || true

    log "All VMs in profile '${profile}' destroyed (incl. orphaned taps/qemu)."
}

# ==============================================================================
# status
# Prints running/stopped state for every defined VM.
# ==============================================================================
status() {
    echo "=== EMPIRE QEMU VM Status ==="
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
        coruscant)     echo "10.10.0.10"  ;;
        deathstar)   echo "10.10.0.11"  ;;
        endor)     echo "10.10.0.12"  ;;
        scarif)   echo "10.10.0.13"  ;;
        kamino)    echo "10.10.0.14"  ;;
        tatooine)     echo "10.10.0.100" ;;
        yavin4)  echo "10.10.20.10" ;;
        neimoidia) echo "10.10.30.10" ;;
        mandalore)  echo "10.10.0.15"  ;;
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

    # Stagger launches: firing all create_vm in the same instant makes 9 parallel
    # 'sudo ip tuntap add' + qemu-img + xorriso + qemu-launch race on netlink/sudo,
    # and under 'set -e' a raced ensure_tap silently aborts that VM's subshell ->
    # dead VM with a blank disk. A few seconds apart keeps installs overlapping
    # without the stampede.
    for vm_name in "${vm_list[@]}"; do
        create_vm "${vm_name}" &
        sleep 5
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
# snapshot_all [profile] [name] — internal qcow2 snapshot of every VM disk.
# Run AFTER a successful provision. VMs are stopped first (qemu-img can't safely
# snapshot a running image). Internal snapshots are instant + space-efficient.
# ==============================================================================
SNAP_NAME_DEFAULT="empire-provisioned"
snapshot_all() {
    local profile="${1:-full}"
    local snap="${2:-${SNAP_NAME_DEFAULT}}"
    local vm_list
    IFS=' ' read -ra vm_list <<< "$(profile_vms "${profile}")" || true
    if [[ "${#vm_list[@]}" -eq 0 ]]; then err "No VMs for profile '${profile}'."; return 1; fi

    log "Stopping VMs before snapshot..."
    stop_all "${profile}"
    sleep 2
    for vm_name in "${vm_list[@]}"; do
        local disk="${VM_STATE_DIR}/${vm_name}.qcow2"
        [[ -f "${disk}" ]] || { warn "${vm_name}: no disk, skipping."; continue; }
        # replace an existing snapshot of the same name, then create fresh
        qemu-img snapshot -d "${snap}" "${disk}" 2>/dev/null || true
        if qemu-img snapshot -c "${snap}" "${disk}"; then
            log "${vm_name}: snapshot '${snap}' created."
        else
            err "${vm_name}: snapshot failed."
        fi
    done
    log "Snapshot '${snap}' complete. Use 'reset' to restore in seconds."
}

# ==============================================================================
# reset_all [profile] [name] — restore every VM to a snapshot, then start.
# Turns a fresh-lab reset from ~40 min (re-provision) into seconds.
# ==============================================================================
reset_all() {
    local profile="${1:-full}"
    local snap="${2:-${SNAP_NAME_DEFAULT}}"
    local vm_list
    IFS=' ' read -ra vm_list <<< "$(profile_vms "${profile}")" || true
    if [[ "${#vm_list[@]}" -eq 0 ]]; then err "No VMs for profile '${profile}'."; return 1; fi

    log "Stopping VMs before reset..."
    stop_all "${profile}"
    sleep 2
    local missing=0
    for vm_name in "${vm_list[@]}"; do
        local disk="${VM_STATE_DIR}/${vm_name}.qcow2"
        [[ -f "${disk}" ]] || { warn "${vm_name}: no disk, skipping."; continue; }
        if qemu-img snapshot -a "${snap}" "${disk}" 2>/dev/null; then
            log "${vm_name}: restored to '${snap}'."
        else
            warn "${vm_name}: no snapshot '${snap}' — run 'snapshot' after a good provision first."
            missing=1
        fi
    done
    [[ "${missing}" -eq 1 ]] && warn "Some VMs had no snapshot; they keep their current disk."
    log "Restarting VMs..."
    start_all "${profile}"
}

# ==============================================================================
# usage
# ==============================================================================
usage() {
    cat >&2 <<EOF
Usage: $(basename "$0") [OPTIONS] COMMAND [ARGS]

Options:
  --packer-output <dir>   Directory containing packer-output/ subdirs
                          (default: ${EMPIRE_HOME}/packer-output)
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
  minimal    — empire.local only (coruscant deathstar endor scarif kamino tatooine)
  single-dc  — coruscant only
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
        snapshot)
            snapshot_all "${1:-${DEFAULT_PROFILE}}" "${2:-${SNAP_NAME_DEFAULT}}"
            ;;
        reset)
            reset_all "${1:-${DEFAULT_PROFILE}}" "${2:-${SNAP_NAME_DEFAULT}}"
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
