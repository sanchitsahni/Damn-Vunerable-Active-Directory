# Task: Documentation Update - Initial Access (M4)

## Objective
Update `/home/sanchit/DVWA/docs/02a-initial-access.md` to document all missing `IA-` vulnerability tags and resolve any naming/mapping mismatches.

## Target File
`/home/sanchit/DVWA/docs/02a-initial-access.md`

## Vulnerabilities to Add/Correct
- `IA-007` (Guest account enabled on file01) - ensure correctly documented (fix mismatch with AS-REP).
- `IA-052` (LNK file bait)
- `IA-053` (AutoPlay enabled)
- `IA-054` (Office macro doc)
- `IA-056` (HTA bait)
- `IA-063` (CHM bait)
- `IA-076` (IIS default pages exposed)
- `IA-078` (WebDAV write enabled)
- `IA-084` (RDP NLA disabled)
- `IA-085` (OpenSSH unauth access)
- `IA-113` (Domain password policy)
- `IA-114` (Weak PSO)
- `IA-115` (AdminCount=1)
- `IA-117` (MachineAccountQuota=100)
- `IA-119` (Plaintext cred in GPO)

## Requirements
For each tag, provide:
1. Standard header (e.g. `### IA-052 — LNK file bait`)
2. Explanation of the vulnerability and how it works.
3. Execution commands (Terminal, bash, or PowerShell commands to exploit/reproduce).
4. Detection and prevention sections.
5. Ensure formatting matches the existing file structure.
