# deathstar.eu.empire.local — 10.10.0.11

Child DC of `empire.local`. Parent-child trust has **no SID filtering** (modern AD design choice) → child DA = parent EA via ExtraSID injection.

## Listening ports

Same as a domain-joined DC: 53, 88, 135, 137-139, 389, 445, 464, 636, 3268-3269, 3389, 5985, 9389. No extra services wired beyond stock AD-DS + DNS + GPMC.

## What's special

- `eu.empire.local` krbtgt reset deterministically (`KrbtgtEU2024!`) — Golden Ticket from any leaked secret here
- Trust account `eu.empire.local$` between parent and child — password set to `TrustKey2024!` from corp side
- Cross-realm TGS requests from `empire.local` users land here (and vice versa)

## Minimum enum sweep

```bash
EU=10.10.0.11
nxc smb $EU -u peter.parker@empire.local -p 'EmpireLab2024!'        # cross-realm SMB
ldapsearch -x -H ldap://$EU -D 'corp\peter.parker' -w 'EmpireLab2024!' \
    -b "DC=eu,DC=empire,DC=local" "(objectClass=user)" sAMAccountName
nxc ldap $EU -u peter.parker@empire.local -p 'EmpireLab2024!' --kerberoasting eu_kerb.txt
# As corp DA, dump child krbtgt:
impacket-secretsdump empire.local/Administrator@$EU -hashes :<NTHASH> -just-dc
# Then forge with parent SIDs (519/512) — Pattern G / DF-007
```

## Forward to

DF-007 ExtraSID (child→parent EA), DF-027 sAMAccountName spoof across trust.

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
