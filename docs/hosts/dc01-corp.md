# coruscant.empire.local — 10.10.0.10

Forest root DC for `empire.local`. **Every** classic AD attack lands here first: it holds krbtgt, runs Spooler + EFSRPC + WebClient + DFSNM (all coercion primitives), exposes null-session pipes, allows zone transfer, ADIDNS is writable, LDAP signing is off, and the password policy is the lab default.

## Listening ports

| Port | Proto | Service | Notes |
|---|---|---|---|
| 53 | TCP/UDP | DNS | AXFR open, dynamic updates accepted from auth users |
| 88 | TCP/UDP | Kerberos KDC | RC4 enabled (`msDS-SupportedEncryptionTypes=0x7`) |
| 123 | UDP | W32Time | NTP, also used by ZeroLogon path indirectly |
| 135 | TCP | RPC endpoint mapper | enumerate all dyn-port RPC interfaces |
| 137-139 | TCP/UDP | NetBIOS | NBT-NS active |
| 389 | TCP | LDAP | signing not required → unauthenticated bind tolerated |
| 445 | TCP | SMB | signing required (DC default) — *server-side*; client signing off |
| 464 | TCP/UDP | kpasswd | password change |
| 593 | TCP | RPC over HTTP | rarely used but reachable |
| 636 | TCP | LDAPS | cert issued by endor |
| 3268-3269 | TCP | Global Catalog (LDAP/LDAPS) | forest-wide search |
| 3389 | TCP | RDP | NLA default; firewall rule on |
| 5985 | TCP | WinRM HTTP | `AllowUnencrypted=true`, Basic + CredSSP |
| 9389 | TCP | ADWS | SOAP wrapper around DC data |

## Reachable RPC pipes (after null session, then authed)

| Pipe | Null? | Authed? | What you get |
|---|---|---|---|
| `\PIPE\lsarpc` | Y | Y | SIDs, domain policy, trust list |
| `\PIPE\samr` | Y | Y | users, groups, password policy |
| `\PIPE\netlogon` | Y | Y | NRPC — **ZeroLogon target** |
| `\PIPE\srvsvc` | Y | Y | shares, sessions (NetSessionEnum) |
| `\PIPE\browser` | Y | Y | legacy browse list |
| `\PIPE\wkssvc` | N | Y | logged-on users, transports |
| `\PIPE\svcctl` | N | Y (admin) | service control |
| `\PIPE\winreg` | N | Y | remote registry |
| `\PIPE\atsvc` | N | Y | scheduled tasks |
| `\PIPE\eventlog` | N | Y | event log read |
| `\PIPE\spoolss` | N | Y | **PrinterBug / PrintNightmare** |
| `\PIPE\drsuapi` | N | Y (DCSync rights) | replication / DCSync |
| `\PIPE\efsrpc` | N | Y | **PetitPotam** |
| `\PIPE\dfsnm` | N | Y | **DFSCoerce** |
| `\PIPE\dnsserver` | N | Y (DnsAdmins) | server-level plugin DLL load → RCE |
| `\PIPE\fssagentrpc` | N | Y | **ShadowCoerce** (VSS) |

## Shares

| Share | Path | ACL highlights | Bait |
|---|---|---|---|
| `SYSVOL` | `C:\Windows\SYSVOL\sysvol` | Auth Users R, scripts folder M | `Groups.xml` (cpassword), `login.bat`, `map_backup.bat` |
| `NETLOGON` | `C:\Windows\SYSVOL\sysvol\empire.local\SCRIPTS` | Auth Users R | logon scripts with cleartext |
| (default admin) `C$`, `ADMIN$`, `IPC$` | — | admin-only | use after PtH |

## Users / groups / SPNs to grep for

```
svc_vision        SPN: HTTP/web.empire.local                RC4 only, ConstrainedDelegation→tatooine
svc_jarvis        SPN: MSSQLSvc/kamino.empire.local:1433
svc_thanos                                          DONT_REQ_PREAUTH    (AS-REP)
no_preauth_svc                                          DONT_REQ_PREAUTH    (AS-REP)
heimdall                                             Backup Operators + reversible
nick.fury                                                Account Operators, Print Operators, Schema Admins
doctor.strange                                               DCSync (Replicating Changes + ChangesAll)
developer1                                              DnsAdmins, Server Operators, many privs
gmsa01                                                  Attacker can retrieve managed pwd
former_admin                                            Disabled DA, attacker has GenericAll
svc_legacy                                              TRUSTED_FOR_DELEGATION (Unconstrained)
PRE2K01$                                                PASSWD_NOTREQD; pwd = pre2k01
```

## ADIDNS

Authenticated Users have `CreateChild` on the AD-integrated zone → register `wpad.empire.local`, `new-fileserver.empire.local`, etc. → MITM.

## Hardening that is OFF

- LLMNR re-enabled
- IPv6 enabled (mitm6 viable)
- `RestrictAnonymous=0`, `RestrictNullSessAccess=0`, `EveryoneIncludesAnonymous=1`
- `LmCompatibilityLevel=2` (NTLMv1 accepted)
- WDigest UseLogonCredential=1 (cleartext in LSASS)
- `LSAProtection (RunAsPPL)=0`
- LDAP signing not required, channel binding off
- Defender disabled
- `FullSecureChannelProtection=0` → **ZeroLogon viable**
- Print Spooler auto-started

## Minimum enum sweep (paste these)

```bash
DC=10.10.0.10
# Anonymous
enum4linux-ng -A $DC
nxc smb $DC -u '' -p ''
impacket-rpcdump $DC
impacket-lookupsid 'empire.local/'@$DC 10000
ldapsearch -x -H ldap://$DC -s base -b "" "(objectclass=*)"
dig @$DC empire.local AXFR
kerbrute userenum -d empire.local --dc $DC users.txt
impacket-GetNPUsers empire.local/ -dc-ip $DC -no-pass -usersfile users.txt -format hashcat
# Coercion gates
nxc smb $DC -M petitpotam,dfscoerce,printerbug,spooler,webdav,ms17-010
# ZeroLogon
python3 zerologon_tester.py coruscant $DC
# After first credential
bloodhound-python -u peter.parker -p 'EmpireLab2024!' -d empire.local -ns $DC -c all
nxc smb,ldap $DC -u peter.parker -p 'EmpireLab2024!' \
    --users --groups --pass-pol --kerberoasting kerb.txt --asreproast asrep.txt \
    --trusted-for-delegation --password-not-required --admin-count --gmsa
certipy find -u peter.parker@empire.local -p 'EmpireLab2024!' -dc-ip $DC -vulnerable -stdout
```

## What this host enables (forward links)

REC-001..015, CRED-001/002/013/014/018/020/021/022/023, LAT-001..035, PE-018/057, PER-018, DF-001..040 (every domain compromise eventually touches coruscant).

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
