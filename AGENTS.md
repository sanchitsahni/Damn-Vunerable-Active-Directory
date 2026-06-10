# AGENTS.md

DVAD = **Deployable Vulnerable Active Directory** lab. A multi-forest Windows AD CTF environment provisioned with QEMU/KVM + Ansible on a Linux host. There is no app/codebase — this repo is **infrastructure automation that builds Windows VMs and intentionally misconfigures them**.

## Repo shape

- `deploy.py` (root) — **the entry point**. Interactive wizard + 7-phase pipeline: media download → packer build → networks → VM create → WinRM wait → Ansible → verify. Run with `python3 deploy.py` or `python3 deploy.py --help`.
- `providers/qemu/` — `vm-create.sh` (VM definitions, clone, launch) + `network-setup.sh` (bridge + dnsmasq). VM_DEFS contains RAM, CPU, MAC, VNC port, and bridge assignments.
- `providers/virtualbox/` — `vm-create.sh` for VirtualBox provider (import OVAs, configure host-only networking).
- `packer/` — three HCL templates (`windows-server-2022`, `windows-server-2019`, `windows-10`). `phase_download_media()` in `deploy.py` downloads `media/virtio-win.iso` before packer runs.
- `ansible/` — single canonical Ansible directory. `playbooks/site.yml` is the master playbook; roles in `roles/` inject vulnerabilities. Control node talks WinRM/NTLM on 5985.
- `PLAN.md` — authoritative attack-vector matrix and topology design. `ad-architechture.html` is the visual companion.
- `scripts/` — utility helpers: `wait-vms.sh`, `activate-windows.sh`, `verify_vulns.py`, `vps-wg-gateway.sh`, etc.

## Topology that must stay consistent across files

Three forests, hardcoded everywhere:

| Host | IP | Bridge | MAC suffix |
|---|---|---|---|
| dc01.corp.local | 10.10.0.10 | dvad-ctf | 01:01 |
| dc01.eu.corp.local | 10.10.0.11 | dvad-ctf | 01:02 |
| ca01.corp.local | 10.10.0.12 | dvad-ctf | 01:03 |
| file01.corp.local | 10.10.0.13 | dvad-ctf | 01:04 |
| sql01.corp.local | 10.10.0.14 | dvad-ctf | 01:05 |
| ws01.corp.local | 10.10.0.100 | dvad-ctf | 01:06 |
| dc01.finance.local | 10.20.0.10 | dvad-finance | 02:01 |
| dc01.root.corp | 10.30.0.10 | dvad-root | 03:01 |

If you add/rename a VM, update **all four** sources: `providers/qemu/vm-create.sh` `VM_DEFS`, `providers/qemu/network-setup.sh` `add_static_leases`, `ansible/inventory.yml`, and any role/task that references the hostname.

Lab-wide password (Administrator, safe-mode, etc.): `DVADlab2024!`. Lives in `ansible/inventory.yml` and `qemu/vm-create.sh`. Not a secret — this is an intentionally vulnerable lab.

## Commands

```bash
python3 deploy.py                                          # interactive wizard (full lab)
python3 deploy.py --profile minimal --provider qemu --yes  # corp.local only, no prompts
python3 deploy.py --profile single-dc --provider qemu --yes
python3 deploy.py --ram 24 --disk-path /mnt/vms --yes
python3 deploy.py --phase 5                                # restart from Ansible only
python3 deploy.py --destroy                                # tear down all VMs + networks

# Re-run only Ansible after VMs are up:
cd ansible && ansible-playbook -i inventory.yml playbooks/site.yml -v

# Syntax / dry-run checks:
ansible-playbook -i ansible/inventory.yml ansible/playbooks/site.yml --syntax-check
ansible-playbook -i ansible/inventory.yml ansible/playbooks/site.yml --check
```

There is **no test suite, no linter, no formatter, no CI**. Validation is "run it and watch it boot". For Ansible changes, the closest thing to a check is `ansible-playbook --syntax-check` and `--check` mode.

## Host requirements (non-obvious)

- KVM + libvirt + `swtpm` + OVMF required. `scripts/setup-deps.sh` installs them per distro (apt/dnf/pacman/zypper); `deploy.py` calls it if needed.
- User must be in `kvm` and `libvirt` groups — setup adds them but a **logout/login is required** before the same shell can launch VMs without sudo on `/dev/kvm`.
- Bridge creation, dnsmasq, and nftables/iptables rules **require sudo**; the script calls `sudo` directly rather than running as root.
- Windows ISO and virtio-win ISO are downloaded into `media/` (~5GB). Re-runs are idempotent — existing ISOs are skipped.
- Per-VM state lives in `vms/<name>.{pid,mon,log,installed}`. The `.installed` marker switches `launch_vm` from install-mode (with ISOs attached) to boot-mode.
- Default VM disk path is `./vms` unless `--disk-path` is passed to `deploy.py`.

## Ansible quirks

- Connection is **WinRM/NTLM on 5985 (HTTP, cert validation off)**. Targets must have finished `post-install.ps1` (which enables WinRM and disables the firewall) before any play will succeed — that is what `scripts/wait-vms.sh` waits for via the `.installed` marker.
- `site.yml` mixes `import_tasks: tasks/<name>.yml` and `import_role: <name>`. Both styles are intentional; the `tasks/` files do imperative AD setup, the roles inject vulnerabilities.
- Groups referenced by `site.yml` (`corp_servers`, `corp_workstation`, `all_dcs`, `member_servers`) are defined in `inventory.yml`. Adding a new host means adding it to the right child group, not just listing it under `all`.
- Phases 6–9 are the **vulnerability injection** phases. They are the whole point of the lab — do not "fix" things like `DoNotRequirePreAuth`, weak service-account passwords, overly permissive ACLs, ESC-vulnerable cert templates, SMB1, disabled Defender, etc. They are the spec, cross-referenced in `PLAN.md`.

## Editing rules of thumb

- Bash scripts use `set -euo pipefail` and `IFS=$'\n\t'`; preserve that. Logging helpers `log/warn/info/err` are redefined per script — keep them.
- The repo intentionally disables Defender, the firewall, UAC, LAPS-style protections, etc. in `post-install.ps1` and the Ansible vuln roles. Security "improvements" are out of scope unless the user explicitly asks.
- When PLAN.md and code disagree, PLAN.md is the design intent but code is what runs. Reconcile by updating whichever the user is asking about, and flag the drift.
- Do not commit anything under `media/`, `vms/`, `autounattend/<vm>/` (generated), or `/tmp/dvad-*` paths.
