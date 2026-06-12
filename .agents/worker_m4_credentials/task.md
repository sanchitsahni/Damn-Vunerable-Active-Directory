# Task: Documentation Update - Credentials (M4)

## Objective
Update `/home/sanchit/DVWA/docs/03-credential-access.md` to document all missing `CRED-` vulnerability tags, resolve naming mismatches, and add cloud identity tags.

## Target File
`/home/sanchit/DVWA/docs/03-credential-access.md`

## Vulnerabilities to Add/Correct
- `CRED-014` (GenericAll on DC01 computer object - correct code-doc mismatch).
- `CRED-022`, `CRED-025`, `CRED-027`, `CRED-031`, `CRED-040`, `CRED-050`, `CRED-058` (fill in missing command details/remedy partial status).
- `CRED-052` (.url coercion NTLM relay - correct mismatch).
- `CRED-066` (DPAPI backup keys extraction via LSARPC)
- `CRED-067` (CredentialGuard disabled)
- `CRED-068` (LSA Notification Packages registry)
- `CRED-100` (extra-range cred stubs)
- `CRED-121` to `CRED-130` (browser logs, Edge/Chrome/Firefox saved passwords, KeePass database, RDP saved passwords, AWS, Azure, Terraform cred files, SSH keys).
- Cloud Identity tags (`CLO-001` to `CLO-095`) - e.g., Entra hybrid join sync, sync accounts, password hash sync settings.

## Requirements
For each tag, provide:
1. Standard header (e.g. `### CRED-121 — Chrome saved passwords`)
2. Explanation of the vulnerability and how it works.
3. Execution commands (e.g. impacket, Mimikatz, Rubeus, local scripts).
4. Detection and prevention.
