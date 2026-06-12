# Task: Documentation Update - Persistence and Forest Compromise (M4)

## Objective
Update `/home/sanchit/DVWA/docs/06-persistence.md` and `/home/sanchit/DVWA/docs/07-forest-compromise.md` to document all missing `PER-` and `DF-` vulnerability tags and resolve naming mismatches.

## Target Files
- `/home/sanchit/DVWA/docs/06-persistence.md`
- `/home/sanchit/DVWA/docs/07-forest-compromise.md`

## Vulnerabilities to Add/Correct
- In `06-persistence.md`:
  - `PER-003` (Startup folder persistence)
  - `PER-004` (Scheduled task SynchTask)
  - `PER-005` (COM object hijack)
  - `PER-017` (Malicious service binary)
  - `PER-019` (DLL search order PATH)
  - `PER-020` (IFEO debugger)
  - `PER-021` (AppInit_DLLs registry key)
  - `PER-022` (Winlogon helper DLL)
  - `PER-023` (Time provider DLL)
  - `PER-031` (Group Policy boot script)
- In `07-forest-compromise.md`:
  - `DF-011`..`DF-022` (Reconcile ADCS ESC1..11 vs code names: Spooler, SID filtering, Exchange permissions, AdminSDHolder, Constrained delegation, krbtgt ACL, Schema Admin, Cross-forest relay)
  - `DF-041`..`DF-050` (MAQ, Delegation, DNSAdmins, Account Operators)
  - `DF-055` (PrintNightmare)
  - `DF-060` (noPac)
  - `DF-070`..`DF-080` (ADCS ESC)
  - `DF-081`..`DF-085` (ExtraSID, Trust transitivity, GPO Creator Owners, GPO Default policy link, Read LAPS)
  - `DF-087` (LAPS extraction)
  - `DF-090` (DCShadow)
  - `DF-095`..`DF-100` (PKI/Entra)

## Requirements
For each tag, provide:
1. Standard header.
2. Explanation of the vulnerability and how it works.
3. Execution commands.
4. Detection and prevention.
