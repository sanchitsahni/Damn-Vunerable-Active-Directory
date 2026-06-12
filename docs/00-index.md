# EMPIRE Walkthrough — Index

Welcome to the empire Mifflin Active Directory (EMPIRE) walkthrough. This `docs/` tree is the operator companion to `PLAN.md` (spec) and `ad-architechture.html` (visual map). It explains how to install the lab, every attack we intentionally injected, how to perform each one with real tooling, what each attack actually *means*, how to detect it, and how to prevent it in a real environment.

> **Scope reminder:** every "vulnerability" in EMPIRE is intentional. The lab password `EmpireLab2024!`, the disabled Defender, the weakened ACLs, the rogue cert templates — they're the spec, not a bug.
> **Authorization:** only run this on a network you own. Treat the VMs as hostile.

---

## How to read this

| If you want to... | Read |
|---|---|
| Get the lab booted | [`01-setup.md`](01-setup.md) |
| Deploy on a VPS + reach over WireGuard | [`09-vps-deploy.md`](09-vps-deploy.md) |
| Land your first foothold from outside (no creds) | [`02a-initial-access.md`](02a-initial-access.md) (IA-001..050) |
| Enumerate the environment | [`02-recon.md`](02-recon.md) (REC-001..015) |
| Exhaustive enum catalog (every technique) | [`02b-enumeration.md`](02b-enumeration.md) (ENUM-001..080) |
| Look up one host (ports, RPC pipes, vulns) | [`hosts/`](hosts/) (8 per-host crib sheets) |
| Harvest credentials / hashes / tickets | [`03-credential-access.md`](03-credential-access.md) (CRED-001..065) |
| Move between hosts and forests | [`04-lateral-movement.md`](04-lateral-movement.md) (LAT-001..035) |
| Escalate privilege locally | [`05-privilege-escalation.md`](05-privilege-escalation.md) (PE-001..060) |
| Maintain access | [`06-persistence.md`](06-persistence.md) (PER-001..037) |
| Take the whole forest | [`07-forest-compromise.md`](07-forest-compromise.md) (DF-001..040) |
| See the canonical solve and wireframe diagrams | [`08-solve-path.md`](08-solve-path.md) |

Every per-ID writeup follows the same template:

```
### <ID> — <Technique>
**What it is:** plain-English description of the attack.
**Why it works here:** the specific misconfiguration we injected in EMPIRE.
**Tools:** the canonical attacker tools.
**Steps:** copy/paste-ready commands.
**Detection:** Event IDs, logs, Sigma rule families.
**Prevention:** the real-world fix.
```

---

## High-level attack-flow wireframe

This is the macro pattern that 80% of EMPIRE solves collapse into. Detail per pattern lives in `08-solve-path.md`.

```
                     ┌──────────────────────────────────┐
                     │  EXTERNAL ATTACKER (your own     │
                     │  Kali / BlackArch) on host bridge│
                     │  10.10.0.1 — zero credentials    │
                     └────────────────┬─────────────────┘
                                      │  Phase 0 — Initial Access (IA-001..050)
                                      │    nmap, anon SMB/LDAP/DNS, Kerbrute,
                                      │    AS-REP roast (no creds), Responder,
                                      │    mitm6, MSSQL public, PetitPotam,
                                      │    ZeroLogon, PrintNightmare, ProxyShell,
                                      │    EternalBlue, Log4Shell, phishing
                                      │    (macro/LNK/ISO/HTA/library-ms),
                                      │    VPN CVE, web RCE, RDP brute, USB drop,
                                      │    SCCM PXE, VLAN hop, OAuth phish
                                      ▼
                     ┌──────────────────────────────────┐
                     │  First foothold                  │
                     │  cleartext / NT hash on a user,  │
                     │  beacon on tatooine (phish/RCE/LPE), │
                     │  or DC$ hash (ZeroLogon),        │
                     │  or coerced+relayed cert         │
                     └────────────────┬─────────────────┘
                                      │
                                      ▼
                     ┌──────────────────────────────────┐
                     │  Domain User                     │
                     │  (cracked hash or sprayed pwd)   │
                     └────────────────┬─────────────────┘
                                      │
        ┌─────────────────────────────┼──────────────────────────────┐
        ▼                             ▼                              ▼
  ┌──────────────┐            ┌────────────────┐             ┌────────────────┐
  │ Kerberoast   │            │ ADCS ESC1/4/8  │             │ Coerce + Relay │
  │ -> service   │            │ -> client-auth │             │ PetitPotam /   │
  │   acct hash  │            │   cert as DA   │             │ DFSCoerce ->   │
  │ -> crack ->  │            │ -> PKINIT ->   │             │ ntlmrelayx ->  │
  │   PtH / TGS  │            │   TGT as DA    │             │ ADCS ESC8 / LDAP│
  └──────┬───────┘            └────────┬───────┘             └────────┬───────┘
         │                             │                              │
         └─────────────────────────────┼──────────────────────────────┘
                                       ▼
                     ┌──────────────────────────────────┐
                     │  Domain Admin on empire.local      │
                     │  (DCSync krbtgt + all hashes)    │
                     └────────────────┬─────────────────┘
                                      │
                ┌─────────────────────┼─────────────────────┐
                ▼                     ▼                     ▼
        ┌─────────────┐       ┌──────────────┐      ┌────────────────┐
        │ Golden TGT  │       │ ExtraSID via │      │ Cross-forest   │
        │ -> any user │       │ child->parent│      │ SID History    │
        │ persistent  │       │ trust (519)  │      │ -> finance/root│
        └─────────────┘       └──────────────┘      └────────────────┘
                                      │
                                      ▼
                     ┌──────────────────────────────────┐
                     │  Enterprise Admin on trade.corp   │
                     └──────────────────────────────────┘
```

---

## Forest / host crib sheet

```
empire.local (10.10.0.0/21)               rebel.local (10.20.0/24)     trade.corp (10.30.0/24)
─────────────────────────               ──────────────────────────     ────────────────────────
coruscant.empire.local      10.10.0.10  DC     yavin4.rebel.local 10.20.0.10  neimoidia.trade.corp 10.30.0.10
deathstar.eu.empire.local   10.10.0.11  ChildDC
endor.empire.local      10.10.0.12  ADCS
scarif.empire.local    10.10.0.13  SMB/SSH
kamino.empire.local     10.10.0.14  MSSQL
tatooine.empire.local      10.10.0.100 VICTIM Workstation
```

Lab-wide password: `EmpireLab2024!`. krbtgt is reset to `KrbtgtEmpire2024!`. Cross-forest trust keys reset to `TrustKey2024!`. `MachineAccountQuota=10`.

---

## Tool inventory (run from your Kali / BlackArch on the host bridge)

> `tatooine.empire.local` is a **victim** workstation, not an attacker box. Tools live on your own Kali (`10.10.0.1` from inside the lab). Zero-credential initial-access vectors are in [`02a-initial-access.md`](02a-initial-access.md).

| Purpose | Tool |
|---|---|
| AD enum + BloodHound ingest | `bloodhound-python`, `SharpHound.exe`, `BloodHound CE` |
| Kerberos | `Rubeus`, `impacket-GetUserSPNs`, `impacket-GetNPUsers`, `impacket-getTGT` |
| Credential dump | `mimikatz`, `secretsdump.py`, `lsassy`, `nanodump` |
| Relay / coercion | `ntlmrelayx.py`, `Responder`, `mitm6`, `PetitPotam.py`, `Coercer`, `dfscoerce.py`, `printerbug.py` |
| ADCS | `Certify.exe`, `Certipy`, `certutil`, `PKINITtools` |
| Lateral exec | `psexec.py`, `wmiexec.py`, `smbexec.py`, `evil-winrm`, `dcomexec.py` |
| PrivEsc local | `winPEAS`, `PrintSpoofer`, `GodPotato`, `SweetPotato`, `SharpUp`, `Watson` |
| Coerce/relay frameworks | `KrbRelayUp`, `krbrelayx`, `Coercer` |
| Cross-platform swiss army | `netexec` (formerly `crackmapexec`) |
| SCCM | `sccmhunter`, `SharpSCCM` |
| Password cracking | `hashcat`, `john` |

---

## Defensive lens

For every attack we list **Detection** (logs/Event IDs/Sigma rule families) and **Prevention** (Microsoft-recommended hardening). Use these to build your blue-team playbooks. The point of EMPIRE is that you can train both colors against the same lab.

---

Next: [`01-setup.md`](01-setup.md).

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
