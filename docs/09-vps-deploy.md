# 09 — Running EMPIRE on a VPS (WireGuard gateway)

EMPIRE on a VPS is the same lab as EMPIRE on your desk — eight intentionally
vulnerable Windows VMs sitting on three private bridges. The VPS-specific
problem is **reachability**: your attacker box (Kali / BlackArch) is no longer
on the same Ethernet as the lab. The solution this repo ships with is a
WireGuard gateway running on the VPS that pulls your laptop into the lab
subnets over a single UDP port.

```
                              ┌─────────────────────────────────────────────────┐
                              │                     VPS                          │
                              │                                                  │
   Internet                   │   wg-empire (51820/udp)  ─┐                        │
   ─────────►  UDP/51820 ────►│   10.99.0.1/24          │ MASQUERADE             │
                              │                         ▼                        │
   Your laptop                │   ┌──────────────────────────────────────────┐  │
   ┌───────────────┐          │   │ Linux bridges (empire-ctf / empire-rebel / │  │
   │  Kali / Black │          │   │ empire-tradefed) + dnsmasq                     │  │
   │  10.99.0.2    │ ◄────────┤   └────┬──────────────┬───────────────┬──────┘  │
   │               │   WG     │        ▼              ▼               ▼         │
   │  routes:      │  tunnel  │   empire.local      rebel.local   trade.corp     │
   │   10.10/21    │          │   10.10.0.0/21   10.20.0.0/24    10.30.0.0/24   │
   │   10.20/24    │          │   (8 vulnerable Windows VMs)                     │
   │   10.30/24    │          │                                                  │
   └───────────────┘          └─────────────────────────────────────────────────┘
```

Only **one** inbound port reaches the VPS from the internet (the WG port).
Everything else — SMB, LDAP, Kerberos, WinRM, RPC — is reachable **only**
after the attacker peer has authenticated and brought the tunnel up.

---

## Why a tunnel, not port forwarding

You will be tempted to `iptables -t nat -A PREROUTING -p tcp --dport 445 -j DNAT ...`
and call it a day. Don't. EMPIRE is **intentionally vulnerable**. Exposing
SMB 445 / LDAP 389 / Kerberos 88 / WinRM 5985 / RDP 3389 / MSSQL 1433 / WebDAV
/ NFS / Telnet / FTP / etc. directly to the internet means:

1. Anyone in the world can hit the lab and use it as a relay / phishing pad
   (lab service accounts have known weak passwords).
2. Your VPS provider's abuse desk will receive complaints inside 24h.
3. Many of the exploits used inside the lab (PetitPotam, NTLM relay, mitm6,
   coercion chains) work just as well against the public internet if relayed
   outbound through the VPS — your VPS becomes the attacker.

WireGuard fixes all three: only your peer key can reach the tunnel, and only
attacker → lab traffic crosses it.

---

## Resource budget on the VPS

| Profile | Min RAM | Min vCPU | Disk | Typical VPS plan |
|---|---|---|---|---|
| `./deploy.py --vps --single-dc` | 4 GB | 2 | 30 GB | Hetzner CX22, DO 4 GB |
| `./deploy.py --vps --minimal`   | 16 GB | 6 | 80 GB | Hetzner CX52, Vultr 16 GB |
| `./deploy.py --vps` (full 8 VM) | 24 GB | 8 | 120 GB | Hetzner CCX33, dedicated |

The `--vps` flag forces VNC to bind on `127.0.0.1` (so you can SSH-tunnel
to a console without exposing VNC to the world) and pre-flights host capacity.

---

## Deploy

### 1. Build the lab on the VPS

```bash
ssh root@your-vps
git clone <this-repo> EMPIRE
cd EMPIRE
./deploy.py --vps                    # 45–90 min — Windows install dominates
```

### 2. Bring up the WireGuard gateway

```bash
sudo bash scripts/vps-wg-gateway.sh up
```

This script:

1. Installs `wireguard-tools` (apt/dnf/pacman/zypper auto-detected).
2. Generates server + client keypairs in `/etc/wireguard/`.
3. Writes `/etc/wireguard/wg-empire.conf` (server, listens on `51820/udp`).
4. Enables IPv4 forwarding + adds NAT rules so the attacker peer
   (`10.99.0.2`) masquerades into the lab bridges.
5. Brings the interface up with `wg-quick` and enables it on boot.
6. Writes `./empire-attacker.conf` and **prints it to stdout** — that's your
   client config.

```bash
sudo bash scripts/vps-wg-gateway.sh status   # see connected peers
sudo bash scripts/vps-wg-gateway.sh down     # stop the tunnel
```

### 3. Attacker side (your laptop)

```bash
# Grab the printed conf (or scp it):
scp root@your-vps:EMPIRE/empire-attacker.conf .

# Bring it up:
sudo wg-quick up ./empire-attacker.conf

# Verify reachability:
ping -c1 10.10.0.10                                  # coruscant.empire.local
nxc smb 10.10.0.10 -u peter.parker -p 'EmpireLab2024!'        # full lab is yours
```

The client conf only routes the three lab subnets (`10.10.0.0/21`,
`10.20.0.0/24`, `10.30.0.0/24`) — your laptop keeps its normal default
route for the rest of the internet.

### 4. Make lab hostnames resolve

Add to your laptop's `/etc/hosts` (or the entries from `docs/01-setup.md`):

```
10.10.0.10  coruscant.empire.local empire.local
10.10.0.11  deathstar.eu.empire.local eu.empire.local
10.10.0.12  endor.empire.local
10.10.0.13  scarif.empire.local
10.10.0.14  kamino.empire.local
10.10.0.100 tatooine.empire.local
10.20.0.10  yavin4.rebel.local rebel.local
10.30.0.10  neimoidia.trade.corp trade.corp
```

You can also dump these via `nslookup` once you're inside the tunnel — the
lab DNS on `coruscant.empire.local` is reachable as a normal nameserver.

---

## Firewall hardening on the VPS

The gateway script only opens the WG port. Belt-and-braces — block everything
else inbound on the WAN interface:

```bash
# UFW example (Debian/Ubuntu)
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp                # your SSH — restrict to your /32 if you can
ufw allow 51820/udp             # WireGuard
ufw enable

# nftables equivalent (RHEL/Fedora/Arch)
nft add table inet empire
nft add chain inet empire input '{ type filter hook input priority 0 ; policy drop ; }'
nft add rule inet empire input ct state established,related accept
nft add rule inet empire input iif lo accept
nft add rule inet empire input tcp dport 22 accept
nft add rule inet empire input udp dport 51820 accept
```

Critical: **do not** open 445 / 389 / 88 / 5985 / 3389 / 1433 / 80 / 443
on the WAN interface. If you accidentally do, the lab will be ingested by
opportunistic scanners within hours.

---

## VNC over SSH (for console access when something is wedged)

```bash
# On your laptop, tunnel VNC port 5901 from the VPS to localhost:
ssh -L 5901:127.0.0.1:5901 root@your-vps
# In another terminal:
vncviewer 127.0.0.1:5901
```

VNC ports per VM are in `qemu/vm-create.sh` (`VM_DEFS` table).

---

## Routing failure checklist

| Symptom | Cause | Fix |
|---|---|---|
| `wg-quick up` succeeds on laptop but no ping to `10.10.0.10` | IP forwarding off on VPS | `sysctl -w net.ipv4.ip_forward=1` (the script does this; check `/proc/sys/net/ipv4/ip_forward` = 1) |
| Ping works, but SMB / WinRM time out | Windows firewall — but post-install.ps1 disables it. Re-run Ansible. | `cd ansible && ansible-playbook -i inventory.yml playbooks/site.yml --tags windows_base` |
| Asymmetric routing: TCP SYN reaches lab, SYN-ACK lost | NAT MASQUERADE missing for that subnet | `iptables -t nat -L POSTROUTING -n` should show one MASQUERADE per lab subnet |
| Tunnel works for `empire.local` (10.10/21) but not `rebel.local` (10.20/24) | Attacker peer's `AllowedIPs` doesn't list 10.20.0.0/24 | Re-generate client conf with `vps-wg-gateway.sh up` — it includes all three subnets |
| Latency feels awful | Path-MTU between VPS and laptop | Add `MTU = 1380` under `[Interface]` on the laptop conf |

---

## Cleanup

```bash
sudo bash scripts/vps-wg-gateway.sh down     # stop tunnel
bash qemu/vm-create.sh destroy               # delete VMs
bash qemu/network/setup-network.sh destroy   # tear down bridges + dnsmasq
```

The WG server config at `/etc/wireguard/wg-empire.conf` and the keypairs in
`/etc/wireguard/*.key` are intentionally left in place after `down` — delete
them by hand if you want a clean slate.

---

## See also

- `scripts/vps-wg-gateway.sh` — the script itself; read it before running
- [`01-setup.md`](01-setup.md) — attacker-box prep (Kali tools, /etc/hosts, krb5.conf)
- [`02a-initial-access.md`](02a-initial-access.md) — IA-001..050 — once you're in the tunnel, this is where you start
- `README.md` — quick-start

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
