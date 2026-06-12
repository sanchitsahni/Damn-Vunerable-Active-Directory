# Task: Documentation Update - Linux AD Pivot (M4)

## Objective
Create `/home/sanchit/DVWA/docs/hosts/linux01-corp.md` to document all local Linux LPEs and services vulnerabilities on the Mandalore Base member server.

## Target File
`/home/sanchit/DVWA/docs/hosts/linux01-corp.md`

## Vulnerabilities to Add
- Linux LPE and AD integration tags `B1` to `B8`:
  - `B1` (krb5.keytab file readable)
  - `B2` (CORP\Domain Users passwordless sudo)
  - `B3` (SSSD cache readable)
  - `B4` (Cron job LPE)
  - `B5` (SUID find binary)
  - `B6` (Leaked domain credentials in history/files)
  - `B7` (NFS export no_root_squash)
  - `B8` (Weak SSH user configuration)
- Local service vulnerabilities:
  - `Redis` (unauthenticated bind)
  - `Memcached` (exposed unauthenticated)
  - `MongoDB` (no authentication)
  - `MySQL` (weak root remote password)
  - `NFS` export misconfigurations
  - `WebApp` (dunder app Python RCE)

## Requirements
For each tag/vulnerability, provide:
1. Standard header.
2. Explanation of the vulnerability and how it works.
3. Execution commands (Bash/Terminal shell).
4. Detection and prevention.
5. Correct formatting matching other host docs in `/home/sanchit/DVWA/docs/hosts/`.
