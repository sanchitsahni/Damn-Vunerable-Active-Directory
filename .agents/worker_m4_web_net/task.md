# Task: Documentation Update - Web Apps and Network Protocols (M4)

## Objective
Create `/home/sanchit/DVWA/docs/10-web-vulnerabilities.md` and `/home/sanchit/DVWA/docs/11-network-vulnerabilities.md` to document all `WEB-` and `NET-`/`SRV-` tags.

## Target Files
- `/home/sanchit/DVWA/docs/10-web-vulnerabilities.md`
- `/home/sanchit/DVWA/docs/11-network-vulnerabilities.md`

## Vulnerabilities to Add
- In `10-web-vulnerabilities.md`:
  - `WEB-001` to `WEB-015` (IIS install, anonymous auth, directory browsing, WebDAV write PUT, HTTP TRACE, version headers, ASP.NET errors, world-writable upload directory, web.config creds, app pool as SYSTEM, logs world-readable, ASPX shell upload, FTP+WebDAV root, 8.3 filename, ISAPI filters).
  - `WEB-021` to `WEB-030` (SQL injection, XSS reflected, CSRF, Path traversal, XXE injection, SSRF, ViewState without MAC, JWT none algorithm, open redirect, IDOR).
  - `WEB-061` to `WEB-070` (Constrained delegation, NTLM auth in WebApp, Web Shell to AD Compromise Chain).
  - Include the Mermaid diagram "Web Shell to AD Domain Admin Chain" from `doc_design.md`.
- In `11-network-vulnerabilities.md`:
  - `NET-001` to `NET-012` (WPAD DNS, mDNS, insecure DNS update, TFTP UDP 69, NetBIOS B-node, IPv6 segment-wide, NTP, SMTP open relay, POP3 plaintext, DHCP starvation, scanning exposure).
  - `SRV-001` to `SRV-065` (SQL, SCCM, WSUS, Exchange stubs/notes).

## Requirements
For each tag, provide:
1. Standard header.
2. Explanation of the vulnerability and how it works.
3. Execution commands.
4. Detection and prevention.
5. Correct Mermaid block syntax.
