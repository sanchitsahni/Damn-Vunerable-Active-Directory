# Task: Documentation Update - Lateral Movement (M4)

## Objective
Update `/home/sanchit/DVWA/docs/04-lateral-movement.md` to document all missing `LAT-` vulnerability tags and resolve naming mismatches.

## Target File
`/home/sanchit/DVWA/docs/04-lateral-movement.md`

## Vulnerabilities to Add/Correct
- `LAT-001`..`LAT-015`, `LAT-017`..`LAT-020`, `LAT-023`..`LAT-025`, `LAT-029`..`LAT-032`, `LAT-035` (reconcile naming mismatches with coercion and relay tasks in code).
- `LAT-036` (Shadow credentials)
- `LAT-041`..`LAT-048` (EPA relay, WDigest caching, Credential Guard disabled, Pass-the-Hash, Pass-the-Ticket, Overpass-the-Hash, Pass-the-Certificate)
- `LAT-061` (DPAPI key theft)
- `LAT-070` to `LAT-076` (OpenSSH, DCOM, WMI, WinRM, PSRemoting, RDP, RDP Hijacking)
- `LAT-080` (SCMExec)
- `LAT-090` (Scheduled Task)
- `LAT-095` (Named Pipe)

## Requirements
For each tag, provide:
1. Standard header (e.g. `### LAT-036 — Shadow credentials`)
2. Explanation of the vulnerability and how it works.
3. Execution commands (e.g. impacket-secretsdump, Rubeus, certipy, WinRM commands).
4. Detection and prevention.
