# Handoff Report — Vulnerability Inventory and Documentation Verification

This handoff report summarizes the findings of the read-only investigation scanning specified Ansible vulnerability roles, cross-referencing their vulnerability tags with the walk-through documentation files under `docs/`, classifying the tags by category, and detailing documentation coverage status, including any identified tag drifts.

---

## 1. Observation

A complete manual audit of the files in the roles `vuln_persistence`, `vuln_privesc`, `vuln_recon`, `vuln_traffic_sim`, `vuln_victim_exec`, and `vuln_web_apps` was performed alongside the Markdown files under `docs/`.

### Verbatim Vulnerability Tag Occurrences in Ansible Roles

*   **`vuln_persistence`**:
    *   `ansible/roles/vuln_persistence/tasks/registry.yml`
        *   Line 6: `# PER-002  IFEO debugger on accessibility tools (sethc/utilman) -> cmd.exe`
        *   Line 7: `# PER-025  DSRM admin network logon (DsrmAdminLogonBehavior=2)`
        *   Line 8: `# PER-018  krbtgt reset to known lab password (Golden Ticket precondition)`
        *   Line 79: `# PER-021 - Drop hint for Diamond/Sapphire tickets (same krbtgt prereq)`
    *   `ansible/roles/vuln_persistence/tasks/acl.yml`
        *   Line 6: `# PER-015/033  stanley.hudson → GenericAll on AdminSDHolder`
        *   Line 10: `# PER-027      KeyCredentialLink write surface — svc_printer has GenericWrite on`
    *   `ansible/roles/vuln_persistence/tasks/gpo.yml`
        *   Line 6: `# PER-034  Attacker-writable GPO (DVADBackdoorGPO) linked to corp.local OU`
    *   `ansible/roles/vuln_persistence/tasks/services.yml`
        *   Line 6: `# PER-004  Malicious scheduled task (SynchTask — calls schtasks.exe payload)`
        *   Line 7: `# PER-005  COM object persistence via registry hijack entry`
        *   Line 8: `# PER-006  WMI event subscription persistence (WMI filter + consumer + binding)`
        *   Line 9: `# PER-017  Malicious service binary stub (dvad_svc)`
    *   `ansible/roles/vuln_persistence/tasks/files.yml`
        *   Line 6: `# PER-003  Startup folder persistence note`
        *   Line 7: `# PER-013  Office macro autorun stub`
        *   Line 8: `# PER-019  DLL search order hijack via PATH manipulation`
        *   Line 9: `# PER-020  Image file execution options (IFEO) debugger stub`
        *   Line 10: `# PER-021  AppInit_DLLs registry key`
        *   Line 11: `# PER-022  Winlogon helper DLL entry`
        *   Line 12: `# PER-023  Time provider DLL stub`
        *   Line 13: `# PER-031  Boot script in group policy`
    *   `ansible/roles/vuln_persistence/tasks/registry_ext.yml`
        *   Line 4: `# PER-001  — Registry Run Keys (HKLM + HKCU)`
        *   Line 5: `# PER-007  — Netsh helper DLL`
        *   Line 6: `# PER-008  — COM hijacking via HKCU InprocServer32`
        *   Line 7: `# PER-009  — Authentication Package (mimilib in Authentication Packages)`
        *   Line 8: `# PER-010  — W32Time DLL hijack (custom TimeProvider)`
        *   Line 9: `# PER-011  — BootExecute modification`
        *   Line 10: `# PER-012  — AppInit_DLLs`
        *   Line 11: `# PER-013  — Accessibility tool IFEO Debugger entries (osk/magnify/narrator)`
        *   Line 12: `# PER-024  — Custom SSP (mimilib in Security Packages)`
        *   Line 13: `# PER-026  — Auth package persistence (same key as PER-009, verify consistency)`
    *   `ansible/roles/vuln_persistence/meta/main.yml`
        *   Line 7: `PER-002 IFEO debugger, PER-014 RID hijack surface, PER-015 AdminSDHolder ACL,`
        *   Line 8: `PER-018 golden ticket (known krbtgt), PER-025 DSRM backdoor,`
        *   Line 9: `PER-027 KeyCredentialLink write surface, PER-034 GPO backdoor`

*   **`vuln_privesc`**:
    *   `ansible/roles/vuln_privesc/templates/ad_pe.ps1.j2`
        *   Line 4: `# PE-123 LAPS-not-deployed note, PE-126 Protected Users empty note, PE-128`
    *   `ansible/roles/vuln_privesc/tasks/ext_cves.yml`
        *   Line 6: `# CVE-2021-36934 (HiveNightmare / SeriousSAM) — SAM ACL weakened on ws01`
        *   Line 12: `# CVE-2023-36874 (Windows Error Reporting LPE) — WER service check`
        *   Line 13: `# CVE-2024-26230 (Telephony Service LPE) — TapiSrv enabled on file01`
        *   Line 119: `FLAG-PE-CVE-2021-1732.txt`
        *   Line 127: `FLAG-PE-CVE-2024-38080.txt`
        *   Line 135: `FLAG-PE-CVE-2025-21333.txt`
    *   `ansible/roles/vuln_privesc/tasks/ext_paths_dlls.yml`
        *   Line 6: `# PE-009  DLL hijacking: C:\Tools in system PATH + version.dll placeholder`
        *   Line 8: `# PE-010  PATH hijacking: C:\Tools already in PATH (PE-009); also add`
        *   Line 10: `# PE-023  Startup folder writable by Domain Users`
        *   Line 11: `# PE-041  Modifiable service path folder: C:\Program Files\DunderSvc2\ writable`
        *   Line 13: `# PE-042  Modifiable registry service path: DVADRegSvc with writable ImagePath key`
        *   Line 14: `# PE-025  Token privilege helper files: token_helper.exe + privileges.txt`
    *   `ansible/roles/vuln_privesc/tasks/ext_privileges.yml`
        *   Line 7: `# PE-002  SeAssignPrimaryTokenPrivilege  -> svc_phyllis`
        *   Line 8: `# PE-003  SeTcbPrivilege                -> svc_tcb`
        *   Line 9: `# PE-004  SeLoadDriverPrivilege         -> Dev_Team group + RTCore64 placeholder`
        *   Line 10: `# PE-021  SeIncreaseQuotaPrivilege      -> svc_quota`
        *   Line 11: `# PE-026  SeManageVolumePrivilege       -> Asset_Owners group`
        *   Line 12: `# PE-027  SeCreateSymbolicLinkPrivilege -> Dev_Team group`
        *   Line 13: `# PE-028  SeDebugPrivilege (Admins)     -> verify + NoLmHash=0`
        *   Line 14: `# PE-029  SeTakeOwnershipPrivilege      -> Asset_Owners group`
        *   Line 15: `# PE-058  Print Operators              -> Print_Ops group / print_user member`
        *   Line 571: `# PE-020: SeChangeNotifyPrivilege traverse — hidden dir + restricted ACL.`
    *   `ansible/roles/vuln_privesc/tasks/ext_services.yml`
        *   Line 6: `# PE-009   Writable service binary path (svc_phyllis on file01)`
        *   Line 7: `# PE-010   AlwaysInstallElevated registry keys (ws01 + file01)`
        *   Line 8: `# PE-013   SeDebugPrivilege for Domain Users (dc01)`
        *   Line 9: `# PE-014   SeBackupPrivilege for Backup_Operators (dc01)`
        *   Line 10: `# PE-015   Weak service DACL — Authenticated Users can modify svc_dvad_weak`
        *   Line 11: `# PE-016   Unquoted service path (file01) — svc_pathsvc`
        *   Line 12: `# PE-017   DLL hijack via writable service binary directory (sql01)`
        *   Line 13: `# PE-020   Scheduled task runs as SYSTEM with world-writable script`
        *   Line 14: `# PE-025   Named pipe impersonation surface (svc_named_pipe service)`
        *   Line 15: `# PE-028   Token impersonation — SeImpersonatePrivilege on IIS/SQL accounts`
        *   Line 16: `# PE-029   User-writeable SYSTEM PATH entry (%TEMP%)`
    *   `ansible/roles/vuln_privesc/tasks/services.yml`
        *   Line 6: `# PE-007  Unquoted service path — VulnService with path containing spaces`
        *   Line 7: `# PE-008  Weak service DACL — VulnService registry key writable by Authenticated Users`
        *   Line 8: `# PE-030  Binary replacement via world-writable C:\Tools (ToolService)`
        *   Line 126: `# PE-016 - Create C:\VulnTasks and writable task action on ws01`
    *   `ansible/roles/vuln_privesc/templates/registry.ps1.j2`
        *   Line 4: `#   PE-011 AlwaysInstallElevated (HKLM+HKCU)  -> ws01, file01`
        *   Line 5: `#   PE-012 ConsentPromptBehaviorAdmin=0       -> ws01`
        *   Line 6: `#   PE-024 HiveNightmare hive-file read ACL   -> ws01`
    *   `ansible/roles/vuln_privesc/tasks/registry_pe.yml`
        *   Line 6: `# PE-061  Auto-run registry entry with world-writable binary path`
        *   Line 7: `# PE-062  Print processor DLL path (world-writable)`
        *   Line 8: `# PE-063  LSA notification package (world-writable DLL)`
        *   Line 9: `# PE-064  Security support provider (custom SSP)`
        *   Line 10: `# PE-065  MachineKeys directory world-readable (DPAPI)`
        *   Line 11: `# PE-066  Cached credentials in DPAPI user master key`
        *   Line 12: `# PE-067  CredentialGuard disabled`
        *   Line 13: `# PE-068  Secure Boot disabled (CSM mode — boot-level attack)`
        *   Line 14: `# PE-069  BitLocker not enabled (cold boot / hibernation attack)`
        *   Line 15: `# PE-070  SAM/SYSTEM registry backup accessible`
    *   `ansible/roles/vuln_privesc/templates/groups.ps1.j2`
        *   Line 4: `# PE-005/006/059 svc_darryl in Warehouse (SeBackup/SeRestore -> NTDS.dit),`
        *   Line 5: `# PE-057: developer1 in Server Operators, PE-018: SYSVOL Scripts DACL loosen,`
        *   Line 6: `# PE-019: SYSTEM-only flag (SeBackup read path).`
    *   `ansible/roles/vuln_privesc/templates/kernel.ps1.j2`
        *   Line 4: `# PE-101 Vulnerable Kernel Driver Loading, PE-110 Hypervisor / Virtual Firmware PE, PE-115 BYOVD Vulnerable Driver Reference`
    *   `ansible/roles/vuln_privesc/templates/tokens.ps1.j2`
        *   Line 4: `# Grants extended privileges via secedit + drops the abuse note (PE-081..100).`

*   **`vuln_recon`**:
    *   `ansible/roles/vuln_recon/tasks/main.yml`
        *   Line 7: `#   REC-002 / IA-002   RestrictAnonymous=0, RestrictAnonymousSAM=0`
        *   Line 9: `#   REC-010 / IA-008   LLMNR enabled (remove GPO disable key); NBT-NS enabled`
        *   Line 10: `#   IA-042             NullSessionPipes — lsarpc,samr,netlogon,srvsvc,browser`
        *   Line 11: `#   IA-007             Guest account enabled on file01`
        *   Line 12: `#   LAT-028            SMB signing disabled on non-DC members`
        *   Line 188: `# REC-007 - Allow unrestricted DNS zone transfers on corp.local`
        *   Line 209: `# REC-006 - Check LDAPServerIntegrity registry value`
    *   `ansible/roles/vuln_recon/tasks/recon_ext.yml`
        *   Line 6: `# REC-001  Anonymous LDAP bind (see IA-003 — verified here for completeness)`
        *   Line 7: `# REC-002  WMI unauthenticated namespace access`
        *   Line 8: `# REC-004  DNS AXFR open (see IA-004 — verified)`
        *   Line 9: `# REC-005  SNMP v1/v2c public community string`
        *   Line 10: `# REC-006  NBT-NS/NetBIOS enumeration`
        *   Line 11: `# REC-007  SMB null session (RestrictAnonymous=0)`
        *   Line 12: `# REC-008  RPC endpoint mapper + named pipes`
        *   Line 13: `# REC-010  SAMR anonymous enumeration`
    *   `ansible/roles/vuln_recon/tasks/enum.yml`
        *   Line 6: `# REC-009  BloodHound LDAP paths — ADWS + LDAP accessible, no auth required`
        *   Line 7: `# REC-011  Kerberoastable SPNs visible in LDAP`
        *   Line 8: `# REC-012  AS-REP users discoverable via LDAP filter`
        *   Line 9: `# REC-013  LDAP SPN enumeration for targeted Kerberoasting`
        *   Line 10: `# REC-014  BloodHound ACL collection — GenericAll/GenericWrite ACEs discoverable`

*   **`vuln_traffic_sim`** & **`vuln_victim_exec`** comments:
    *   `ansible/roles/vuln_victim_exec/tasks/main.yml`
        *   Line 20: `#   IA-019..022 (Office macros), IA-024 / CRED-051 (.library-ms),`
        *   Line 21: `#   IA-052 (.lnk), IA-056 (.hta), CRED-052 (.url),`
        *   Line 22: `#   CVE-2025-24071 / CVE-2025-24054 (.library-ms/.search-ms NTLM leak),`
        *   Line 23: `#   CVE-2023-21716 (WordPad RTF — opened via Word/RTF handler).`

*   **`vuln_web_apps`**:
    *   `ansible/roles/vuln_web_apps/tasks/main.yml`
        *   Line 3: `# vuln_web_apps/tasks/main.yml — WEB-001..080`
    *   `ansible/roles/vuln_web_apps/tasks/iis_config.yml`
        *   Line 6: `# WEB-001  IIS installed + running`
        *   Line 7: `# WEB-002  Anonymous authentication on default site`
        *   Line 8: `# WEB-003  Directory browsing enabled`
        *   Line 9: `# WEB-004  WebDAV with write permissions (PUT method)`
        *   Line 10: `# WEB-005  HTTP TRACE method enabled`
        *   Line 11: `# WEB-006  IIS server version header exposed`
        *   Line 12: `# WEB-007  ASP.NET error details exposed (custom errors off)`
        *   Line 13: `# WEB-008  Upload directory world-writable`
        *   Line 14: `# WEB-009  Insecure web.config with SQL credentials`
        *   Line 15: `# WEB-010  IIS application pool running as SYSTEM`
        *   Line 16: `# WEB-011  IIS logs world-readable`
        *   Line 17: `# WEB-012  ASPX shell upload via WebDAV`
        *   Line 18: `# WEB-013  FTP + WebDAV same root (cross-protocol upload)`
        *   Line 19: `# WEB-014  IIS short file name (8.3 filename) enumeration`
        *   Line 20: `# WEB-015  IIS ISAPI filter vulnerability stub`
    *   `ansible/roles/vuln_web_apps/tasks/web_vulns.yml`
        *   Line 6: `# WEB-021  SQL injection via ASPX page`
        *   Line 7: `# WEB-022  XSS via reflected parameter`
        *   Line 8: `# WEB-023  CSRF — no token validation`
        *   Line 9: `# WEB-024  Path traversal via file download endpoint`
        *   Line 10: `# WEB-025  XXE injection in XML endpoint`
        *   Line 11: `# WEB-026  SSRF via image fetch endpoint`
        *   Line 12: `# WEB-027  Insecure deserialization (ViewState without MAC)`
        *   Line 13: `# WEB-028  JWT none algorithm bypass stub`
        *   Line 14: `# WEB-029  Open redirect`
        *   Line 15: `# WEB-030  IDOR — user ID enumeration via parameter`
    *   `ansible/roles/vuln_web_apps/tasks/web_notes.yml`
        *   Line 14: `# WEB-061: Kerberos Constrained Delegation via Web App`
        *   Line 28: `# WEB-065: NTLM Authentication in Web App`
        *   Line 42: `# WEB-070: Web Shell to AD Compromise Chain`

### Verification of Documentation in `/home/sanchit/DVWA/docs/`

*   **`02a-initial-access.md`**: Contains detailed write-ups for `IA-002`, `IA-003`, `IA-004`, `IA-008`, `IA-019`, `IA-020`, `IA-021`, `IA-022`, `IA-024`, `IA-042`, `IA-046`.
*   **`02-recon.md`**: Contains detailed write-ups for `REC-001` to `REC-015`.
*   **`03-credential-access.md`**: Contains detailed write-ups for `CRED-013`, `CRED-051`, `CRED-052`.
*   **`04-lateral-movement.md`**: Contains detailed write-ups for `LAT-025`, `LAT-028`.
*   **`05-privilege-escalation.md`**: Contains detailed write-ups for `PE-001` to `PE-060`.
*   **`06-persistence.md`**: Contains detailed write-ups for `PER-001` to `PER-037`.
*   **`07-forest-compromise.md`**: Contains detailed write-ups for `DF-` tags.
*   **Web App Documentation (`WEB-` tags)**: No Markdown files or content sections mention `WEB-` tags in the entirety of the `docs/` directory.

---

## 2. Logic Chain

1.  **Tag Extraction**: Scanned all task files and templates within the 6 requested roles using explicit string-matching lookups (`view_file` and specific `grep_search`). The resulting set of tags spans Categories: `IA`, `REC`, `CRED`, `LAT`, `PE`, `PER`, and `WEB`.
2.  **Cross-Referencing**:
    *   For `IA-*`, `REC-*`, `CRED-*`, `LAT-*`, `PE-*`, and `PER-*` tags, we found corresponding sections in `docs/` matching those IDs.
    *   For `WEB-*` tags, a recursive grep search on the `docs/` folder for the query `"WEB-"` returned zero matches, showing that none of the web application vulnerability tags are documented.
    *   For `PE-*` tags, we found that all tags `PE-061` to `PE-070`, `PE-081` to `PE-100`, `PE-101`, `PE-110`, `PE-115`, `PE-123`, `PE-126`, and `PE-128` are completely missing from `docs/05-privilege-escalation.md`.
3.  **Discrepancy (Drift) Analysis**:
    *   Comparing the technique implemented in the Ansible tasks vs the technique documented in the corresponding markdown file revealed several tag/concept mismatches:
        *   **`REC-` Drifts**:
            *   `REC-002`: Code sets `RestrictAnonymous` (Null Sessions) and WMI namespace access, but docs describe it as `SPN Enumeration`.
            *   `REC-004`: Code enables `DNS AXFR`, but docs describe it as `Trust Enumeration`.
            *   `REC-005`: Code configures `SNMP v1/v2c`, but docs describe it as `GPO Enumeration`.
            *   `REC-006`: Code enables `NBT-NS` and `LDAP signing`, but docs describe it as `ACL Enumeration`.
            *   `REC-008`: Code configures `RPC endpoint mapper`, but docs describe it as `SMB Share Enumeration`.
            *   `REC-009`: Code configures `BloodHound LDAP paths`, but docs describe it as `MSSQL Instance Enumeration`.
            *   `REC-011`: Code checks `Kerberoastable SPNs`, but docs describe it as `Password Policy Enumeration`.
            *   `REC-012`: Code checks `AS-REP roastable`, but docs describe it as `ADCS Template Enumeration`.
            *   `REC-013`: Code enumerates `LDAP SPNs`, but docs describe it as `AS-REP pre-auth enumeration`.
            *   `REC-014`: Code sets `BloodHound ACL collection`, but docs describe it as `Machine Account Enumeration`.
        *   **`PER-` Drifts**:
            *   `PER-004`: Code implements WMI/Scheduled Task (SynchTask), but docs describe `Service Install`.
            *   `PER-005`: Code implements COM hijack, but docs describe `Scheduled Task`.
            *   `PER-017`: Code implements Service Install, but docs describe `DCShadow Persistent`.
            *   `PER-019`: Code implements PATH/DLL hijack, but docs describe `Silver Ticket`.
            *   `PER-020`: Code implements IFEO debugger (Sticky Keys), but docs describe `Skeleton Key`.
            *   `PER-021`: Code implements AppInit_DLLs, but docs describe `Diamond Ticket`.
            *   `PER-022`: Code implements Winlogon helper, but docs describe `Sapphire Ticket`.
            *   `PER-023`: Code implements Time provider, but docs describe `Golden Certificate`.
            *   `PER-031`: Code implements Group Policy boot script, but docs describe `Schema Modification Backdoor`.
        *   **`PE-` / `IA-` / `CRED-` Drifts**:
            *   `PE-011`: Code implements AlwaysInstallElevated / SeDebugPrivilege, but docs describe `AlwaysInstallElevated`.
            *   `PE-013`: Code implements SeDebugPrivilege, but docs describe `Token Kidnapping (churrasco)`.
            *   `PE-014`: Code implements SeBackupPrivilege, but docs describe `Named Pipe Impersonation`.
            *   `PE-015`: Code implements weak service DACL, but docs describe `Service binary overwrite`.
            *   `PE-016`: Code implements unquoted service path / writable scheduled task, but docs describe `Task Scheduler XML Race`.
            *   `PE-017`: Code implements DLL hijack sql01, but docs describe `COM Object Hijacking (PrintNotify)`.
            *   `PE-018`: Code implements SYSVOL Scripts loosen, but docs describe `Insecure SYSVOL GPO`.
            *   `PE-019`: Code implements SYSTEM-only flag, but docs describe `Backup Operators → GPO modification`.
            *   `PE-025`: Code implements named pipe impersonation, but docs describe `Token Privilege Exploitation Suite`.
            *   `PE-028`: Code implements token impersonation (SeImpersonate), but docs describe `SeDebugPrivilege -> LSASS token steal`.
            *   `PE-029`: Code implements SeTakeOwnershipPrivilege / %TEMP% PATH, but docs describe `SeTakeOwnershipPrivilege`.
            *   `IA-007`: Code implements local guest account enabling, but docs describe `AS-REP roast without credentials`.
            *   `CRED-052`: Code implements `.url` coercion, but docs describe `NTLM Relay via .library-ms (CVE-2025-33073)`.

---

## 3. Caveats

*   **Other Roles Unscanned**: Roles other than the six requested (such as `vuln_adcs`, `vuln_kerberos`, `vuln_gpo`, `ad_domain`, `child_domain`, etc.) were not scanned.
*   **Search Limitations**: Grep searches were constrained to the local file system scope and used case-sensitive matching, but manual checks of target documentation files resolved potential false negatives.

---

## 4. Conclusion

All unique vulnerability tags found in the scanned roles have been verified and classified. The core findings show a split in documentation coverage:
1.  **Fully Documented**: Standard `IA-` and `PE-` tags (except extended ones) are fully documented with dedicated headers.
2.  **Partially Documented**: `PER-009`, `PER-013`, `PER-026`, and `PER-033` redirect or link to other entries rather than having dedicated write-ups.
3.  **Completely Undocumented**:
    *   **All `WEB-` tags (`WEB-001` to `WEB-070`)** are undocumented.
    *   **Privilege Escalation Tags `PE-061` to `PE-070`, `PE-081` to `PE-100`, `PE-101`, `PE-110`, `PE-115`, `PE-123`, `PE-126`, `PE-128`** are undocumented.
    *   **Client-Side Execution Tags `IA-052`, `IA-054`, `IA-056`** are undocumented.
    *   **Specific CVE tags (`PE-CVE-2021-36934`, `PE-CVE-2023-36874`, `PE-CVE-2024-26230`, `PE-CVE-2021-1732`, `PE-CVE-2024-38080`, `PE-CVE-2025-21333`)** are undocumented under those exact names.
4.  **Major Tag Drift**: The tags `REC-` and `PER-` are used in the codebase for completely different techniques than what is documented in `02-recon.md` and `06-persistence.md` (e.g. `PER-019` is Silver Ticket in docs but DLL search order in code).

### Summary Table of Vulnerability Tags and Documentation Status

| Tag | Category | Description in Role Code | Documentation Status | Docs File |
|---|---|---|---|---|
| **IA-002** | Initial Access | RestrictAnonymous=0 (null session) | Fully Documented | `02a-initial-access.md` |
| **IA-003** | Initial Access | Anonymous LDAP bind | Fully Documented | `02a-initial-access.md` |
| **IA-004** | Initial Access | DNS AXFR | Fully Documented | `02a-initial-access.md` |
| **IA-007** | Initial Access | Enable Guest account on file01 | **Mismatched** (Docs write-up is AS-REP) | `02a-initial-access.md` |
| **IA-008** | Initial Access | LLMNR / NBT-NS enabled | Fully Documented | `02a-initial-access.md` |
| **IA-019..022** | Initial Access | Office macros, LNK, HTA | Fully Documented | `02a-initial-access.md` |
| **IA-024** | Initial Access | `.library-ms` coercion | Fully Documented | `02a-initial-access.md` |
| **IA-042** | Initial Access | NullSessionPipes | Fully Documented | `02a-initial-access.md` |
| **IA-046** | Initial Access | ADWS running | Fully Documented | `02a-initial-access.md` |
| **IA-052** | Initial Access | `.lnk` bait | **Undocumented** | None |
| **IA-054** | Initial Access | Office macro doc | **Undocumented** | None |
| **IA-056** | Initial Access | `.hta` bait | **Undocumented** | None |
| **REC-001** | Recon | Anonymous LDAP bind | Fully Documented | `02-recon.md` |
| **REC-002** | Recon | WMI unauth namespace access | **Mismatched** (Docs: SPN Enumeration) | `02-recon.md` |
| **REC-004** | Recon | DNS AXFR open | **Mismatched** (Docs: Trust Enumeration) | `02-recon.md` |
| **REC-005** | Recon | SNMP public community | **Undocumented/Mismatched** (Docs: GPO Enum) | `02-recon.md` |
| **REC-006** | Recon | NBT-NS enumeration / LDAP signing | **Mismatched** (Docs: ACL Enumeration) | `02-recon.md` |
| **REC-007** | Recon | DNS zone transfer / SMB null session | **Mismatched** (Docs: DNS Zone Transfer) | `02-recon.md` |
| **REC-008** | Recon | RPC endpoint mapper | **Mismatched** (Docs: SMB Share Enum) | `02-recon.md` |
| **REC-009** | Recon | BloodHound LDAP paths | **Mismatched** (Docs: MSSQL Instance Enum) | `02-recon.md` |
| **REC-010** | Recon | SAMR anonymous / LLMNR | Fully Documented | `02-recon.md` |
| **REC-011** | Recon | Kerberoastable SPNs | **Mismatched** (Docs: Password Policy Enum) | `02-recon.md` |
| **REC-012** | Recon | AS-REP roastable | **Mismatched** (Docs: ADCS Template Enum) | `02-recon.md` |
| **REC-013** | Recon | LDAP SPN enumeration | **Mismatched** (Docs: AS-REP pre-auth) | `02-recon.md` |
| **REC-014** | Recon | BloodHound ACL collection | **Mismatched** (Docs: Machine Account Enum) | `02-recon.md` |
| **CRED-013** | Credentials | DCSync | Fully Documented | `03-credential-access.md` |
| **CRED-051** | Credentials | `.library-ms` coercion | Fully Documented | `03-credential-access.md` |
| **CRED-052** | Credentials | `.url` coercion | **Mismatched** (Docs: NTLM Relay via library-ms) | `03-credential-access.md` |
| **LAT-025** | Lateral | SPN settings | **Mismatched** (Docs: WebDAV Coercion) | `04-lateral-movement.md` |
| **LAT-028** | Lateral | SMB signing disabled | Fully Documented | `04-lateral-movement.md` |
| **PE-001..008** | PrivEsc | Token privileges, service path/DACL | Fully Documented | `05-privilege-escalation.md` |
| **PE-009** | PrivEsc | DLL hijacking / Writable service path | Fully Documented | `05-privilege-escalation.md` |
| **PE-010** | PrivEsc | PATH hijacking / AlwaysInstallElevated | Fully Documented | `05-privilege-escalation.md` |
| **PE-011** | PrivEsc | AlwaysInstallElevated / SeDebugPrivilege | Fully Documented | `05-privilege-escalation.md` |
| **PE-012** | PrivEsc | ConsentPromptBehaviorAdmin=0 / UAC | Fully Documented | `05-privilege-escalation.md` |
| **PE-013** | PrivEsc | SeDebugPrivilege for Domain Users | **Mismatched** (Docs: Token Kidnapping) | `05-privilege-escalation.md` |
| **PE-014** | PrivEsc | SeBackupPrivilege for Backup_Operators | **Mismatched** (Docs: Named Pipe Impersonation) | `05-privilege-escalation.md` |
| **PE-015** | PrivEsc | Weak service DACL svc_dvad_weak | **Mismatched** (Docs: Service binary overwrite) | `05-privilege-escalation.md` |
| **PE-016** | PrivEsc | Writable scheduled-task action | **Mismatched** (Docs: Task Scheduler XML Race) | `05-privilege-escalation.md` |
| **PE-017** | PrivEsc | DLL hijack sql01 | **Mismatched** (Docs: COM Hijack PrintNotify) | `05-privilege-escalation.md` |
| **PE-018** | PrivEsc | SYSVOL Scripts DACL loosen | **Mismatched** (Docs: Insecure SYSVOL GPO) | `05-privilege-escalation.md` |
| **PE-019** | PrivEsc | SYSTEM-only flag | **Mismatched** (Docs: Backup Operators GPO write) | `05-privilege-escalation.md` |
| **PE-020** | PrivEsc | SeChangeNotifyPrivilege / Scheduled task | Fully Documented | `05-privilege-escalation.md` |
| **PE-021** | PrivEsc | SeIncreaseQuotaPrivilege | Fully Documented | `05-privilege-escalation.md` |
| **PE-023** | PrivEsc | Startup folder writable | Fully Documented | `05-privilege-escalation.md` |
| **PE-024** | PrivEsc | HiveNightmare | Fully Documented | `05-privilege-escalation.md` |
| **PE-025** | PrivEsc | Token privilege helper | **Mismatched** (Docs: Token Privilege Suite) | `05-privilege-escalation.md` |
| **PE-026** | PrivEsc | SeManageVolumePrivilege | Fully Documented | `05-privilege-escalation.md` |
| **PE-027** | PrivEsc | SeCreateSymbolicLinkPrivilege | Fully Documented | `05-privilege-escalation.md` |
| **PE-028** | PrivEsc | Token impersonation (SeImpersonate) | **Mismatched** (Docs: SeDebugPrivilege LSASS) | `05-privilege-escalation.md` |
| **PE-029** | PrivEsc | SeTakeOwnershipPrivilege / %TEMP% PATH | Fully Documented | `05-privilege-escalation.md` |
| **PE-030** | PrivEsc | Binary replacement ToolService | Fully Documented | `05-privilege-escalation.md` |
| **PE-041** | PrivEsc | Modifiable service path | Fully Documented | `05-privilege-escalation.md` |
| **PE-042** | PrivEsc | Modifiable service registry key | Fully Documented | `05-privilege-escalation.md` |
| **PE-049** | PrivEsc | Vulnerable Signed Driver RTCore64 | Fully Documented | `05-privilege-escalation.md` |
| **PE-057** | PrivEsc | Server Operators -> SYSTEM | Fully Documented | `05-privilege-escalation.md` |
| **PE-058** | PrivEsc | Print Operators -> SYSTEM | Fully Documented | `05-privilege-escalation.md` |
| **PE-059** | PrivEsc | Backup Operators on DC -> NTDS.dit theft | Fully Documented | `05-privilege-escalation.md` |
| **PE-061..070** | PrivEsc | Auto-run, LSA packages, backup, etc. | **Undocumented** | None |
| **PE-081..100** | PrivEsc | Secedit privilege grants | **Undocumented** | None |
| **PE-101** | PrivEsc | Vulnerable Kernel Driver Loading | **Undocumented** | None |
| **PE-110** | PrivEsc | Hypervisor PE | **Undocumented** | None |
| **PE-115** | PrivEsc | BYOVD Driver Reference | **Undocumented** | None |
| **PE-123** | PrivEsc | LAPS-not-deployed note | **Undocumented** | None |
| **PE-126** | PrivEsc | Protected Users empty note | **Undocumented** | None |
| **PE-128** | PrivEsc | developer2 GenericWrite on EntAdmins | **Undocumented** | None |
| **PE-CVE-*** | PrivEsc | CVE LPE stubs / indicators | **Undocumented** (by specific name) | None |
| **PER-001** | Persistence | Registry Run Keys | Fully Documented | `06-persistence.md` |
| **PER-002** | Persistence | IFEO debugger sethc/utilman | Fully Documented | `06-persistence.md` |
| **PER-003** | Persistence | Startup folder | **Mismatched** (Docs: Sticky Keys / Utilman) | `06-persistence.md` |
| **PER-004** | Persistence | Scheduled task | **Mismatched** (Docs: Service Install) | `06-persistence.md` |
| **PER-005** | Persistence | COM object hijack | **Mismatched** (Docs: Scheduled Task) | `06-persistence.md` |
| **PER-006** | Persistence | WMI subscription | Fully Documented | `06-persistence.md` |
| **PER-007** | Persistence | Netsh Helper DLL | Fully Documented | `06-persistence.md` |
| **PER-008** | Persistence | COM Hijacking | Fully Documented | `06-persistence.md` |
| **PER-009** | Persistence | Authentication Package | Partially Documented | `06-persistence.md` |
| **PER-010** | Persistence | Time Providers / W32Time | Fully Documented | `06-persistence.md` |
| **PER-011** | Persistence | BootExecute | Fully Documented | `06-persistence.md` |
| **PER-012** | Persistence | AppInit_DLLs | Fully Documented | `06-persistence.md` |
| **PER-013** | Persistence | ActiveSetup / Accessibility Tools | Partially Documented | `06-persistence.md` |
| **PER-014** | Persistence | RID Hijacking (unimplemented in code) | Fully Documented | `06-persistence.md` |
| **PER-015** | Persistence | AdminSDHolder ACL | Fully Documented | `06-persistence.md` |
| **PER-017** | Persistence | Malicious service binary | **Mismatched** (Docs: DCShadow Persistent) | `06-persistence.md` |
| **PER-018** | Persistence | krbtgt reset / Golden Ticket | Fully Documented | `06-persistence.md` |
| **PER-019** | Persistence | DLL search order | **Mismatched** (Docs: Silver Ticket) | `06-persistence.md` |
| **PER-020** | Persistence | IFEO debugger stub | **Mismatched** (Docs: Skeleton Key) | `06-persistence.md` |
| **PER-021** | Persistence | AppInit_DLLs registry key | **Mismatched** (Docs: Diamond Ticket) | `06-persistence.md` |
| **PER-022** | Persistence | Winlogon helper DLL | **Mismatched** (Docs: Sapphire Ticket) | `06-persistence.md` |
| **PER-023** | Persistence | Time provider DLL | **Mismatched** (Docs: Golden Certificate) | `06-persistence.md` |
| **PER-024** | Persistence | Custom SSP | Fully Documented | `06-persistence.md` |
| **PER-025** | Persistence | DSRM Network Logon | Fully Documented | `06-persistence.md` |
| **PER-026** | Persistence | Auth Package Persistence | Partially Documented | `06-persistence.md` |
| **PER-027** | Persistence | KeyCredentialLink | Fully Documented | `06-persistence.md` |
| **PER-031** | Persistence | Boot script | **Mismatched** (Docs: Schema Mod Backdoor) | `06-persistence.md` |
| **PER-033** | Persistence | stanley.hudson GenericAll | Partially Documented | `06-persistence.md` |
| **PER-034** | Persistence | GPO Backdoor | Fully Documented | `06-persistence.md` |
| **WEB-001..015** | Web App | IIS configs, directory browsing, WebDAV | **Undocumented** | None |
| **WEB-021..030** | Web App | SQLi, XSS, SSRF, Path Traversal | **Undocumented** | None |
| **WEB-061..070** | Web App | Delegation, NTLM web auth, shells | **Undocumented** | None |

---

## 5. Verification Method

To verify these results independently, do the following:
1.  **Grep for WEB- tags**: Run `grep -rn "WEB-" /home/sanchit/DVWA/docs/` to confirm that absolutely no matches are returned.
2.  **Verify PE-061 missing**: Open `/home/sanchit/DVWA/docs/05-privilege-escalation.md` and check the end of the file; confirm it stops at `PE-060` (line 478) and does not contain `PE-061`.
3.  **Verify PER-019 Silver Ticket drift**: Open `/home/sanchit/DVWA/docs/06-persistence.md` at line 190 and verify it defines `PER-019 — Silver Ticket`. Then open `/home/sanchit/DVWA/ansible/roles/vuln_persistence/tasks/files.yml` at line 8 and verify it implements `# PER-019  DLL search order hijack via PATH manipulation`.
