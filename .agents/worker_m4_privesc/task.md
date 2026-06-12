# Task: Documentation Update - Privilege Escalation (M4)

## Objective
Update `/home/sanchit/DVWA/docs/05-privilege-escalation.md` to document all missing `PE-` vulnerability tags and resolve naming mismatches.

## Target File
`/home/sanchit/DVWA/docs/05-privilege-escalation.md`

## Vulnerabilities to Add/Correct
- `PE-013` (SeDebugPrivilege for Domain Users)
- `PE-014` (SeBackupPrivilege for Backup Operators)
- `PE-015` (Weak service DACL svc_dvad_weak)
- `PE-016` (Writable scheduled-task action)
- `PE-017` (DLL hijack sql01)
- `PE-018` (SYSVOL Scripts DACL loosen)
- `PE-019` (SYSTEM-only flag)
- `PE-025` (Token privilege helper)
- `PE-028` (Token impersonation SeImpersonate)
- `PE-029` (SeTakeOwnershipPrivilege / %TEMP% PATH)
- `PE-061`..`PE-070` (Auto-run, print processor, LSA packages, cached creds in DPAPI, Credential Guard disabled, secure boot, bitlocker, SAM/SYSTEM backup)
- `PE-081`..`PE-100` (Secedit privilege grants)
- `PE-101` (Vulnerable Kernel Driver Loading)
- `PE-110` (Hypervisor PE)
- `PE-115` (BYOVD)
- `PE-123` (LAPS-not-deployed note)
- `PE-126` (Protected Users empty note)
- `PE-128` (developer2 GenericWrite on EntAdmins)
- `PE-CVE-*` tags (CVE-2021-36934 HiveNightmare, CVE-2023-36874 WER, CVE-2024-26230 TapiSrv, CVE-2021-1732, CVE-2024-38080, CVE-2025-21333)

## Requirements
For each tag, provide:
1. Standard header (e.g. `### PE-061 — Auto-run registry entry`)
2. Explanation of the vulnerability and how it works.
3. Execution commands (PowerShell/CMD).
4. Detection and prevention.
