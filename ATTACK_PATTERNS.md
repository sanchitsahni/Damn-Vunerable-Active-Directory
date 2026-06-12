# EMPIRE Attack Patterns

All attack chains validated by `scripts/exploit_graph.py` (41 exploit primitive edges, 155+ chains to DA/EA).  
Lab network: `10.10.0.0/16` — all 8 VMs on single bridge `empire-ctf`.

```
Run: python3 scripts/exploit_graph.py --test --dot chains.dot
```

---

## Network Topology

| Host | IP | Role |
|------|----|------|
| coruscant.empire.local | 10.10.0.10 | empire.local Domain Controller |
| deathstar.eu.empire.local | 10.10.0.11 | eu.empire.local Child DC |
| endor.empire.local | 10.10.0.12 | ADCS Certificate Authority |
| scarif.empire.local | 10.10.0.13 | File/Web server |
| kamino.empire.local | 10.10.0.14 | SQL Server 2022 |
| tatooine.empire.local | 10.10.0.100 | Windows Server 2022 Core workstation |
| mandalore.empire.local | 10.10.0.15 | Ubuntu 22.04 Cloud Member (Linux-in-AD) |
| yavin4.rebel.local | 10.10.20.10 | rebel.local Forest DC |
| neimoidia.trade.corp | 10.10.30.10 | trade.corp Forest DC |

---

## Initial Access Vectors

| ID | Vector | Entry Point | Prereq |
|----|--------|-------------|--------|
| IA-001 | LLMNR/NBNS poisoning | empire.local broadcast | Responder on segment |
| IA-052 | LNK UNC coercion | tatooine Desktop | User opens file |
| IA-056 | HTA in Downloads | tatooine | User opens HTA |
| IA-076 | IIS HTTP | scarif:80 | No auth |
| IA-078 | WebDAV PUT | scarif:80/uploads | No auth |
| IA-084 | RDP no NLA | tatooine:3389 | Credentials |
| IA-085 | SSH password auth | scarif:22 | Credentials |
| IA-113 | Password spray | coruscant:88/389 | Weak policy (no lockout, min len 1) |
| IA-114 | Weak PSO | coruscant | Targeted account in Weak-PSO |
| IA-119 | GPO registry credential | Any domain member | Read HKLM\Software\EMPIRELab |

---

## Kill Chains — Initial Access → Domain Admin

### Chain A — Web → SQLi → xp_cmdshell → DA
```
[Attacker] → (IA-076: IIS/HTTP) → scarif:user
           → (WEB-021: SQLi login.aspx) → kamino:user
           → (SRV-003: xp_cmdshell) → kamino:system
           → (SRV-007: svc_sql domain token) → domain:user
           → (CRED-013: DCSync svc_bobafett) → DA
```
**Tools:** curl/burp → impacket-mssqlclient → impacket-secretsdump  
**Creds obtained:** sa/DeathStar2025! (via SQLi) → krbtgt hash

---

### Chain B — LLMNR → NTLM Relay → LDAP → DA
```
[Attacker] → (IA-001: LLMNR/Responder) → coruscant:creds (NTLMv2 hash)
           → (LAT-011: NTLM relay, SMB signing off) → coruscant:creds
           → (LAT-relay: LDAP relay → RBCD/ACL) → DA
```
**Tools:** Responder → ntlmrelayx.py → impacket-secretsdump  
**Prereqs:** SMB signing disabled on scarif, LDAP signing not required

---

### Chain C — Password Spray → ADCS ESC1 → DA
```
[Attacker] → (IA-113: spray jdoe/SithLord123!) → domain:user
           → (ESC1: UserTemplate SAN forgery) → DA cert
           → (certipy auth) → DA TGT
```
**Tools:** crackmapexec → certipy req → certipy auth  
**Creds:** jdoe:SithLord123! → forge admin@empire.local UPN in cert

---

### Chain D — Password Spray → DCSync → Golden Ticket
```
[Attacker] → (IA-113: spray) → domain:user
           → (CRED-013: DCSync via svc_bobafett:Droid2024!) → krbtgt hash
           → (CRED-099: Golden Ticket) → DA (any time, no expiry)
```
**Tools:** impacket-secretsdump → mimikatz/Rubeus  
**Creds:** svc_bobafett:Droid2024! has GetChangesAll on domain NC

---

### Chain E — PrinterBug → Unconstrained Delegation → DA
```
[Attacker] → (DF-011: Spooler coerce coruscant → scarif) → scarif captures coruscant$ TGT
           → (DF-042: Unconstrained delegation on scarif$)
           → (DCSync with coruscant$ TGT) → DA
```
**Tools:** SpoolSample/printerbug.py → Rubeus monitor → secretsdump  
**Prereqs:** Spooler on coruscant (DF-011), scarif$ TrustedForDelegation=True (DF-042)

---

### Chain F — RDP → WDigest → PtH → DA
```
[Attacker] → (IA-084: RDP tatooine, NLA disabled) → tatooine:user
           → (WDigest enabled: CRED-043/LAT-043) → plaintext creds in LSASS
           → (LAT-045: PtH to coruscant) → coruscant:admin
           → (PE-128: local admin on DC = DA) → DA
```
**Tools:** mstsc/rdesktop → mimikatz sekurlsa::logonpasswords → psexec/wmiexec

---

### Chain G — SSH → GPP Password → DA
```
[Attacker] → (IA-085: SSH scarif:22) → scarif:user
           → (CRED-030: GPP cpassword in SYSVOL) → svc_bobafett hash
           → (CRED-013: DCSync) → krbtgt hash
           → (CRED-099: Golden Ticket) → DA
```
**Tools:** ssh → smbclient → gpp-decrypt → secretsdump  
**Creds:** GPP groups.xml cpassword decrypts to Droid2024!

---

### Chain H — Kerberoasting → Service Account → Relay → DA
```
[Attacker] → (IA-113: spray low-priv) → domain:user
           → (CRED-017: Kerberoast svc_sql/svc_c3po) → TGS hash
           → (hashcat crack) → svc_sql:SqlSvc2024!
           → (SRV-001: MSSQL sa access with svc_sql) → kamino:system
           → (xp_cmdshell net group DA add) → DA
```
**Tools:** GetUserSPNs → hashcat -m 13100 → mssqlclient

---

### Chain I — RBCD via MAQ → S4U2Self → DA
```
[Attacker with domain user] → (DF-041: MAQ=100 create evil$) → evil$:machine
           → (CRED-014: jdoe GenericWrite on scarif/tatooine) → set RBCD evil$ → target
           → (S4U2Self+Proxy impacket-getST) → admin ticket for target
           → (lateral to DC) → DA
```
**Tools:** addcomputer.py → rbcd.py → getST → smbclient/psexec

---

### Chain J — Shadow Credentials → PKINIT → DA
```
[domain:user with HelpDesk] → (LAT-036: write KeyCredentialLink on tatooine$)
           → (LAT-048: Whisker/pyWhisker) → tatooine$ PKINIT cert
           → (S4U2Self with tatooine$ TGT) → admin on tatooine
           → (sekurlsa dump) → DA cached creds
```
**Tools:** Whisker.exe → Rubeus asktgt → Rubeus s4u

---

## Kill Chains — DA → Enterprise Admin (Cross-Forest)

### Chain K — Golden Ticket + ExtraSID → rebel.local EA
```
[empire.local DA] → (CRED-099: krbtgt hash) → Golden Ticket
               → (DF-081: ExtraSID = rebel.local EA SID, filtering off)
               → rebel.local Enterprise Admin
               → (DF-100: access trade.corp via finance trust) → trade.corp EA
```
**Tools:** mimikatz kerberos::golden /sids:S-1-5-21-REBEL-519 → pass-the-ticket

---

### Chain L — Entra Connect Abuse → Cloud DA
```
[empire.local DA] → (CLO-001: MSOL_sync account DCSync rights)
               → (CLO-002: DCSync empire.local → NTLM hashes)
               → (CLO-008: Entra Connect credentials) → cloud admin
               → Global Administrator in Entra ID
```
**Tools:** AADInternals, secretsdump, Entra Connect DB extraction

---

## Kill Chains — Web App → OS → Domain

### Chain M — File Upload RCE → SYSTEM → Domain
```
[Attacker] → (IA-076: HTTP scarif:80)
           → (WEB-012: upload.aspx — no extension check) → upload webshell
           → (upload.aspx?cmd=whoami) → IIS app pool OS command
           → (WEB-010: app pool runs as SYSTEM/svc_iis) → SYSTEM
           → (svc_iis domain token) → domain:user
           → (CRED-013: DCSync) → DA
```
**Tools:** curl -F "file=@shell.aspx" http://scarif/upload.aspx → browse shell

---

### Chain N — Path Traversal → web.config → SA creds → DA
```
[Attacker] → (WEB-024: path_traversal.aspx?file=web.config) → SQL SA password
           → (SRV-001: MSSQL sa login) → kamino:system
           → (SRV-003: xp_cmdshell) → OS exec
           → (net user /domain) → domain enumeration → DA chain
```
**Exposed:** web.config contains `SqlSaPassword=DeathStar2025!` (WEB-009)

---

## Persistence Chains

### PER-Chain 1 — Golden Ticket (infinite validity)
```
[DA] → DCSync krbtgt → Golden Ticket (10yr validity)
     → Access any service in empire.local without further authentication
```

### PER-Chain 2 — WMI Event Subscription
```
[DA/Admin] → (PER-006: WMI __EventFilter + CommandLineEventConsumer)
           → Triggered on boot/login → persistent backdoor
```
**Cleanup detection:** `Get-WMIObject -NS 'root\subscription' -Class __FilterToConsumerBinding`

### PER-Chain 3 — AdminSDHolder WriteDACL
```
[DA] → (DF-017: svc_bobafett WriteDACL on AdminSDHolder)
     → SDProp propagates every 60min → svc_bobafett gains DA-equivalent rights
```

### PER-Chain 4 — Skeleton Key / DSRM backdoor
```
[DA on DC] → mimikatz misc::skeleton → all accounts accept master password
           → (or) lsadump::setntlm /user:Administrator → persistent DSRM hash
```

---

## Credential Extraction Paths

| Source | Tool | Credentials |
|--------|------|-------------|
| LSASS memory | mimikatz sekurlsa | Plaintext (WDigest) + NTLM hashes |
| SAM hive | secretsdump/HiveNightmare | Local admin hashes |
| NTDS.dit (DCSync) | secretsdump -just-dc | All domain hashes |
| SYSVOL GPP | gpp-decrypt | svc_bobafett:Droid2024! |
| Windows Credential Manager | cmdkey /list + SharpDPAPI | coruscant Admin, sa creds |
| web.config | path_traversal.aspx | sa:DeathStar2025! |
| DunderMifflin DB | sqlcmd/sqli.aspx | All service account passwords |
| .rdp file | DPAPI decode | coruscant Admin |
| AWS credentials | file read | AKIA... key |
| Terraform tfstate | file read | EmpireLab2024! + DeathStar2025! |

---

## Privilege Escalation Paths

| ID | Vuln | From | To |
|----|------|------|----|
| PE-010 | AlwaysInstallElevated | user | SYSTEM |
| PE-015 | Weak service DACL (svc_empire_weak) | user | SYSTEM |
| PE-016 | Unquoted service path (svc_pathsvc) | user | SYSTEM |
| PE-017 | MSSQL Binn world-writable DLL hijack | sql user | SYSTEM |
| PE-020 | World-writable scheduled task script | user | SYSTEM |
| PE-028 | SeImpersonatePrivilege | service | SYSTEM (Potato) |
| PE-061 | PATH hijack (C:\Tools world-writable) | user | SYSTEM |
| CVE-2021-36934 | HiveNightmare (SAM ACL) | user | Local Admin hash |
| CVE-2021-34527 | PrintNightmare | domain user | SYSTEM on DC |

---

## Graph-Based Validation

```bash
# Topology only — enumerate all 155+ chains
python3 scripts/exploit_graph.py

# Live test against running lab
python3 scripts/exploit_graph.py --test

# Export attack graph as PNG
python3 scripts/exploit_graph.py --dot chains.dot
dot -Tpng chains.dot -o chains.png

# Show only fully-working chains
python3 scripts/exploit_graph.py --test --ready

# JSON output for automation
python3 scripts/exploit_graph.py --test --json > chains.json
```

Graph nodes: `attacker:anon` → `domain:user` → `{host}:{priv}` → `domain_admin:da` → `enterprise_admin:ea`

---

## Layer 2 Exploit Verification

```bash
# Run all checks
./scripts/verify_exploits.sh

# Per-category
./scripts/verify_exploits.sh --category cred_access
./scripts/verify_exploits.sh --category adcs
./scripts/verify_exploits.sh --category lateral_movement
./scripts/verify_exploits.sh --category web

# Layer 1 passive check (Ansible config verification)
python3 scripts/verify_vulns.py
```

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
