# AGENTS.md

EMPIRE = **empire Mifflin Active Directory** lab. A multi-forest Windows AD CTF environment provisioned with QEMU/KVM + Ansible on a Linux host. There is no app/codebase — this repo is **infrastructure automation that builds Windows VMs and intentionally misconfigures them**.

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
| coruscant.empire.local | 10.10.0.10 | empire-ctf | 01:01 |
| deathstar.eu.empire.local | 10.10.0.11 | empire-ctf | 01:02 |
| endor.empire.local | 10.10.0.12 | empire-ctf | 01:03 |
| scarif.empire.local | 10.10.0.13 | empire-ctf | 01:04 |
| kamino.empire.local | 10.10.0.14 | empire-ctf | 01:05 |
| tatooine.empire.local | 10.10.0.100 | empire-ctf | 01:06 |
| yavin4.rebel.local | 10.20.0.10 | empire-rebel | 02:01 |
| neimoidia.trade.corp | 10.30.0.10 | empire-tradefed | 03:01 |

If you add/rename a VM, update **all four** sources: `providers/qemu/vm-create.sh` `VM_DEFS`, `providers/qemu/network-setup.sh` `add_static_leases`, `ansible/inventory.yml`, and any role/task that references the hostname.

Lab-wide password (Administrator, safe-mode, etc.): `EmpireLab2024!`. Lives in `ansible/inventory.yml` and `qemu/vm-create.sh`. Not a secret — this is an intentionally vulnerable lab.

## Commands

```bash
python3 deploy.py                                          # interactive wizard (full lab)
python3 deploy.py --profile minimal --provider qemu --yes  # empire.local only, no prompts
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
- Do not commit anything under `media/`, `vms/`, `autounattend/<vm>/` (generated), or `/tmp/empire-*` paths.

---

# The EMPIRE AD Lab: Star Wars Lore & Thematic Mapping

Welcome to the **EMPIRE AD Lab**, where the intricacies of Active Directory align with the galactic struggle between the Galactic Empire, the Rebel Alliance, and the shadow syndicates. This section provides a conceptual thematic mapping between the AD concepts you are attacking and the Star Wars universe.

## The Galactic Topology

The lab topology represents the political structure of the galaxy. Just as trust relationships govern AD, diplomatic and military alliances govern the galaxy.

```mermaid
graph TD
    classDef empire fill:#000000,stroke:#ff0000,stroke-width:2px,color:#fff;
    classDef rebel fill:#2b5c8f,stroke:#ff9900,stroke-width:2px,color:#fff;
    classDef trade fill:#4a4a4a,stroke:#aaaaaa,stroke-width:2px,color:#fff;
    classDef highlight fill:#440000,stroke:#ff0000,stroke-width:3px,color:#fff;

    subgraph The Galactic Empire (empire.local)
        Coruscant["Coruscant (Root DC)<br/>coruscant.empire.local"]:::empire
        DeathStar["The Death Star (Child DC)<br/>deathstar.eu.empire.local"]:::highlight
        Scarif["Scarif Citadel (File Server)<br/>scarif.empire.local"]:::empire
        Kamino["Kamino Cloning Facility (SQL)<br/>kamino.empire.local"]:::empire
        Endor["Endor Shield Generator (CA)<br/>endor.empire.local"]:::empire
        Mandalore["Mandalore Mercenary Base (Linux)<br/>mandalore.empire.local"]:::empire
        Coruscant -- "Imperial Command" --> DeathStar
        Coruscant --- Scarif
        Coruscant --- Kamino
        Coruscant --- Endor
        Coruscant --- Mandalore
    end

    subgraph The Rebel Alliance (rebel.local)
        Yavin4["Yavin 4 Base<br/>yavin4.rebel.local"]:::rebel
    end

    subgraph The Trade Federation (trade.corp)
        Neimoidia["Cato Neimoidia<br/>neimoidia.trade.corp"]:::trade
    end

    Coruscant <-->|Espionage / External Trust| Yavin4
    Coruscant <-->|Treaty / Forest Trust| Neimoidia
```

## Infrastructure Mapping

Understanding the infrastructure is key to successfully executing your attack paths. Here is how the technical components of the EMPIRE AD lab map to the Star Wars universe:

### 1. The Core Domains
* **`empire.local` (The Galactic Empire):** The central root domain. This is the seat of the Emperor and the Imperial Senate. Taking over this domain is equivalent to taking over Coruscant. It controls all the core infrastructure.
* **`eu.empire.local` (The Death Star):** A child domain of `empire.local`. While it reports to the root domain, it holds immense power. Escaping the child domain to compromise the root domain is the equivalent of using the Death Star plans to destroy the Empire.
* **`rebel.local` (The Rebel Alliance):** An external forest. It has an external trust with the Empire (perhaps through espionage or captured spies). Moving laterally across this trust requires finding a weak link in the Rebel defenses.
* **`trade.corp` (The Trade Federation):** A separate forest with a bidirectional forest trust. The Empire uses them for resources, but you can forge trust tickets (Inter-Realm TGTs) to cross this boundary.

### 2. High-Value Targets (Servers)
* **`coruscant.empire.local` (Coruscant Root DC):** The ultimate prize. Achieving Domain Admin here gives you the keys to the galaxy.
* **`endor.empire.local` (Endor Shield Generator / ADCS):** Active Directory Certificate Services. If you can compromise the CA (via ESC1, ESC8, etc.), you can forge certificates for any user in the Empire, effectively bringing down the deflector shields.
* **`scarif.empire.local` (Scarif Citadel):** This file server hosts critical SMB shares. It is the repository of the Death Star plans. Look for exposed passwords in scripts or configuration files left by careless Imperial engineers.
* **`kamino.empire.local` (Kamino Facility):** The SQL Server. SQL injection or xp_cmdshell here can lead to a foothold. It represents the cloning facilities—a hidden source of power.
* **`mandalore.empire.local` (Mandalore Base):** The Linux-in-AD member. Contains local privilege escalations and cross-OS pivot opportunities. Represents the mercenary faction employed by the Empire.

### 3. Attack Paths and Tactics
* **Initial Access (The Smuggler's Route):** Finding an exposed SMB share or exploiting an LLMNR poisoning vulnerability (Responder) is like slipping past the Imperial blockade.
* **Kerberoasting (Bounty Hunting):** Requesting TGS tickets for service accounts and cracking them offline is like putting a bounty on a high-value target and cracking their encryption.
* **DCSync (The Force):** Using `secretsdump` to pull the `krbtgt` hash directly from the Domain Controller. It's an invisible, powerful attack that bypasses normal defenses.
* **Golden Ticket (Order 66):** Once you have the `krbtgt` hash, you can forge a TGT for any user, granting you infinite access. It is the ultimate executive order, overriding all security protocols.
* **Trust Abuse (Diplomatic Immunity):** Forging a trust ticket to cross from the Child Domain to the Root Domain.

## The Hacker's Code (Sith vs Jedi)
As you navigate the lab, remember that the tools you use define your path. Will you use noisy, aggressive tools (The Dark Side) that trigger every alarm, or will you use stealthy, precise tradecraft (The Light Side) to move undetected?

* **The Dark Side (Noisy):** Running `BloodHound` with all collection methods, spraying passwords across the entire domain, and dropping standard Mimikatz binaries to disk. It is powerful and fast, but leaves a massive trail.
* **The Light Side (Stealthy):** Targeted LDAP queries, memory-only execution via Covenant or Cobalt Strike, and careful evasion of logging (AMSI bypasses, ETW patching).

## Flag Locations (Holocrons)
Hidden throughout the EMPIRE AD lab are flags (Holocrons) that prove your mastery over the environment. Look for `FLAG-*.txt` files on desktops, hidden SMB shares, and within the SQL databases. 

**Remember:** 
* "Your focus determines your reality." - Qui-Gon Jinn. Focus on the attack paths mapped out in `PLAN.md`.
* "I find your lack of faith disturbing." - Darth Vader. If an exploit fails, check your syntax, your targeting, and the underlying misconfiguration. The lab is intentionally vulnerable.

May the Force be with you as you conquer the EMPIRE AD!
