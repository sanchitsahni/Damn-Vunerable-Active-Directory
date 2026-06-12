# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

`AGENTS.md` in the repo root is the authoritative orientation doc for any agent working here — read it first. The notes below highlight the points most often missed and the few CLAUDE-specific things AGENTS.md does not cover.

## What this repo is

EMPIRE (empire Mifflin Active Directory) is a lab for CTF/red-team practice. Not application code — infrastructure automation (Bash + Ansible + QEMU/KVM) that builds a multi-forest Windows AD environment and **intentionally misconfigures it**. The "bugs" (disabled Defender, weak service accounts, ESC-vulnerable cert templates, DoNotRequirePreAuth, permissive ACLs, SMB1, etc.) are the spec, not regressions. Do not "fix" them unless explicitly asked. `PLAN.md` is the attack-vector spec; `ad-architechture.html` is the visual companion.

## Entry point

- **Entry point:** `python3 deploy.py` at repo root. Interactive wizard + 7-phase pipeline: media download → packer build → networks → VM create → WinRM wait → Ansible → verify.
- Provider scripts live in `providers/qemu/` (vm-create.sh + network-setup.sh) and `providers/virtualbox/` — not the old `qemu/` directory.
- `.nanocoder/` was leftover tool state — it has been removed. If it reappears, delete it.

## Topology consistency (four-way invariant)

Hostnames, IPs, and MACs are hardcoded across **four** files that must stay in sync. All VMs share the single `empire-ctf` bridge on `10.10.0.0/16` (corp=10.10.0.x, finance=10.10.20.x, root=10.10.30.x). When adding/renaming a VM, update all four:

1. `providers/qemu/vm-create.sh` — `VM_DEFS` associative array
2. `providers/qemu/network-setup.sh` — `add_static_leases` (dnsmasq static leases)
3. `ansible/inventory.yml` — host entry **and** the right child group (`corp_servers`, `corp_workstation`, `all_dcs`, `member_servers` — `site.yml` references these by name)
4. Any role/task referencing the hostname

Lab-wide password is `EmpireLab2024!` (in `ansible/inventory.yml` and `providers/qemu/vm-create.sh`). Not a secret — intentionally vulnerable lab.

## Common commands

```bash
python3 deploy.py                                            # interactive menu
python3 deploy.py --profile minimal --provider qemu --yes   # empire.local only, no prompts
python3 deploy.py --profile single-dc --provider qemu --yes # 1 VM smoke test
python3 deploy.py --ram 24 --disk-path /mnt/vms --yes
python3 deploy.py --phase 5 --yes                           # restart from Ansible
python3 deploy.py --destroy --yes                           # tear down everything

# Re-run only Ansible after VMs are up:
cd ansible && ansible-playbook -i inventory.yml playbooks/site.yml -v

# Syntax / dry-run checks (closest thing to a "test"):
ansible-playbook -i ansible/inventory.yml ansible/playbooks/site.yml --syntax-check
ansible-playbook -i ansible/inventory.yml ansible/playbooks/site.yml --check
```

**No test suite, no linter, no formatter, no CI exists.** Validation is "run it and watch it boot." Don't claim a change is verified unless it has actually been booted, or syntax-checked for Ansible.

## Architecture in one screen

- `providers/qemu/vm-create.sh` defines each VM (RAM, CPU, MAC, VNC port, bridge), generates a per-VM `autounattend.xml` + `post-install.ps1`, and packs them into a small ISO injected alongside the Windows install media. Per-VM state lives in `vms/<name>.{pid,mon,log,installed}`. The `.installed` marker switches `launch_vm` from install-mode (with ISOs attached) to boot-mode.
- `providers/qemu/network-setup.sh` creates Linux bridges + a project-local dnsmasq under `/tmp/empire-dnsmasq/` with static leases keyed off the MACs in `vm-create.sh`.
- `ansible/playbooks/site.yml` is the master playbook. It deliberately mixes `import_tasks: tasks/<name>.yml` (imperative AD setup) and `import_role: <name>` (vulnerability injection). Both styles are intentional. **Roles in `roles/vuln_*` are the vulnerability injection phases — they are the whole point of the lab.**
- Ansible connection is **WinRM/NTLM on 5985 (HTTP, cert validation off)**. Targets must have finished `post-install.ps1` (which enables WinRM and disables the firewall) before any play succeeds; `scripts/wait-vms.sh` waits on the `.installed` marker.

## Host setup gotchas

- KVM + libvirt + `swtpm` + OVMF required. `scripts/setup-deps.sh` installs these per distro (apt/dnf/pacman/zypper).
- User is added to `kvm` and `libvirt` groups by the script — but a **logout/login is required** before the same shell can launch VMs without sudo on `/dev/kvm`.
- Bridge creation, dnsmasq, nftables/iptables rules **require sudo**; the script calls `sudo` directly rather than running as root.
- Windows ISO + virtio-win ISO land in `media/` (~5GB). Re-runs are idempotent; existing ISOs are skipped.
- Default VM disk path is `./vms` unless `--disk-path` is passed to `deploy.py`.

## Editing conventions

- All Bash scripts use `set -euo pipefail` and `IFS=$'\n\t'` — preserve that.
- `log` / `warn` / `info` / `err` helpers are redefined per script — keep them as-is rather than refactoring into a shared lib.
- Never commit anything under `media/`, `vms/`, `autounattend/<vm>/` (generated), or `/tmp/empire-*`.
- When `PLAN.md` and code disagree, `PLAN.md` is design intent but the code is what runs. Reconcile by updating whichever the user is asking about and flag the drift.

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
