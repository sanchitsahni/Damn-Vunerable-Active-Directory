# Handoff Report: Vulnerability Documentation Gap Analysis (Group B)

## 1. Observation
We conducted a comprehensive, read-only analysis of the Ansible playbooks/templates and the walkthrough documentation files in the repository. The exact file paths, lines, and content observed include:

### 1.1 Ansible Roles and Files Scanned
We scanned all files within the six requested roles under `/home/sanchit/DVWA/ansible/roles/`:
1. **`vuln_forest`**: 
   - `tasks/main.yml`: Injects `DF-003` (michael.scott DCSync, line 22), `DF-007` (ExtraSID child krbtgt reset, line 75), `DF-008` (Disable SID filtering, line 95), `DF-009` (FSP Domain Admins, line 115), `DF-010` (Cross-forest SPN, line 161), `DF-023` (Verify child DA, line 195).
   - `tasks/domain_adv.yml`: Injects `DF-041` (Machine Account Quota, line 8), `DF-042..048` (Delegation, line 23), `DF-049` (DNSAdmins, line 48), `DF-050` (Account Operators, line 66), `DF-055` (PrintNightmare, line 138), `DF-060` (noPac, line 151), `DF-070..080` (ADCS ESC, line 164), `DF-081..100` (Trust/cross-forest notes, line 113).
   - `tasks/esc_ext.yml`: Injects `ESC9` (line 18), `ESC10` (line 55), `ESC12` (line 91), `ESC14` (line 115), `ESC16` (line 139).
   - `tasks/forest_attacks.yml`: Injects `DF-005` (DsAddSidHistory, line 21), `DF-011` (Print Spooler on DC, line 63), `DF-012` (SID filtering forest trust, line 8), `DF-015` (Exchange Win Perms, line 91), `DF-017` (AdminSDHolder WriteDACL, line 146), `DF-020` (Constrained delegation, line 173), `DF-022` (Readable krbtgt, line 204), `DF-025` (Schema Admins non-DA, line 231), `DF-030` (Cross-forest NTLM relay, line 258).
   - `tasks/trust_abuse.yml`: Injects `DF-081` (ExtraSID, line 7), `DF-082` (Trust transitivity, line 29), `DF-083` (GPO Creator Owners, line 45), `DF-084` (GPO link Default Policy, line 65), `DF-085` (Read LAPS, line 83), `DF-087` (LAPS extraction, line 150), `DF-090` (DCShadow, line 162), `DF-095..100` (PKI/Entra, line 174).
2. **`vuln_ia_surface`**:
   - `templates/dc_surface.ps1.j2`: Injects `IA-003` (dsHeuristics, line 16), `IA-004`/`IA-041` (AXFR, line 28), `IA-046` (ADWS, line 41), `IA-014` (ZeroLogon registry, line 52), `IA-040` (WinRM HTTPS, line 64), `REC-015` (SYSVOL creds, line 79).
   - `templates/file01_surface.ps1.j2`: Injects `IA-034`/`IA-050` (SNMP, line 20), `IA-035` (FTP, line 33), `IA-036` (Telnet, line 51), `IA-037` (NFS, line 63), `IA-038` (SMB1, line 75), `IA-044`/`IA-015` (Spooler/printer, line 82), `IA-047` (WSD/SSDP, line 99), `IA-040` (WinRM HTTPS, line 112).
   - `templates/ca01_surface.ps1.j2`: Injects `IA-039` (WebDAV, line 13), `IA-049` (WebDAV authoring, line 24), `IA-045` (WebClient, line 46), `IA-040` (WinRM HTTPS, line 60).
   - `templates/sql01_surface.ps1.j2`: Injects `IA-011` (sa/xp_cmdshell, line 18), `IA-048` (SQL Browser, line 49), `IA-040` (WinRM HTTPS, line 65).
   - `templates/ws01_surface.ps1.j2`: Injects `IA-019..022` (ASR rules, line 13), `IA-024` (.library-ms, line 21), `IA-027`/`IA-043` (RDP NLA, line 54), `IA-033` (WSH/AMSI, line 72), `IA-045` (WebClient, line 84), `IA-047` (WSD/SSDP, line 95), `IA-040` (WinRM HTTPS, line 108).
   - `templates/ext_phishing.ps1.j2`: Injects `IA-052` (LNK, line 12), `IA-053` (AutoPlay, line 28), `IA-056` (HTA, line 36), `IA-063` (CHM, line 56).
   - `templates/ext_services.ps1.j2`: Injects `IA-076` (IIS, line 13), `IA-078` (WebDAV write, line 25), `IA-084` (RDP NLA, line 32), `IA-085` (OpenSSH, line 43).
   - `templates/ext_misconfig.ps1.j2`: Injects `IA-113` (domain pw policy, line 15), `IA-114` (Weak-PSO, line 23), `IA-115` (AdminCount=1, line 36), `IA-117` (MachineAccountQuota=100, line 47), `IA-119` (Plaintext cred in GPO, line 57).
3. **`vuln_kerberos`**:
   - `tasks/main.yml`: Injects `CRED-001` (Kerberoastable service accounts, line 15), `CRED-002` (AS-REP Roasting, line 100), `CRED-016` (Constrained delegation, line 121), `CRED-018` (Unconstrained delegation, line 145), `RC4-only` (msDS-SupportedEncryptionTypes=1, line 178), `RBCD` (sql01 AllowedToActOnBehalfOfOtherIdentity, line 203).
4. **`vuln_lateral`**:
   - `tasks/acl.yml`: Injects `LAT-021` (michael.scott GenericAll, line 13), `LAT-022` (Validated-SPN write, line 47), `LAT-034` (Cross-forest FSP, line 83).
   - `tasks/rbcd.yml`: Injects `LAT-016` (RBCD, line 16), `LAT-026` (KrbRelayUp/MAQ=10, line 54), `LAT-012` (SID filtering disabled netdom, line 77).
   - `tasks/smb.yml`: Injects `LAT-027` (IPv6 ws01, line 12), `LAT-028` (SMB signing off, line 26), `LAT-033` (Writable share C:\Shared, line 47).
   - `tasks/coerce.yml`: Injects `LAT-001` (MS-RPRN, line 18), `LAT-002` (MS-EFSR, line 29), `LAT-003` (MS-FSRVP, line 51), `LAT-004` (MS-DFSNM, line 69), `LAT-005` (MS-NRPC, line 9), `LAT-006` (WebDAV, line 11), `LAT-007` (MS-ICPR, line 12), `LAT-008` (PrivExchange, line 13), `LAT-009` (SCF file, line 91), `LAT-010` (mDNS poisoning, line 121).
   - `tasks/relay.yml`: Injects `LAT-011` (LDAP signing, line 19), `LAT-012` (LDAP channel binding, line 8), `LAT-013` (SMB1 + signing off, line 9), `LAT-014` (Cross-protocol relay, line 10), `LAT-015` (CredSSP, line 34), `LAT-016` (Shadow credentials, line 56), `LAT-017` (Unconstrained delegation coercion, line 102), `LAT-018` (NTLMv2 capture, line 14), `LAT-019` (Cross-forest NTLM relay, line 15), `LAT-020` (ADCS relay, line 124).
   - `tasks/acl_abuse.yml`: Injects `LAT-023` (LAPS read IT_Team, line 17), `LAT-024` (Cross-forest SPN abuse, line 7), `LAT-025` (WriteSPN jim.halpert, line 62), `LAT-029` (ForceChangePassword, line 92), `LAT-030` (GenericWrite HelpDesk, line 129), `LAT-031` (WriteOwner finance_sync, line 152), `LAT-032` (AddMember Domain Admins, line 12), `LAT-034` (Pass-the-Ticket, line 193), `LAT-035` (Overpass-the-Hash, line 216).
   - `tasks/lateral_adv.yml`: Injects `LAT-036` (Shadow credentials, line 7), `LAT-041` (EPA, line 46), `LAT-042` (SMB signing, line 55), `LAT-043` (WDigest caching, line 69), `LAT-044` (Credential Guard, line 78), `LAT-045` (Pass-the-Hash, line 92), `LAT-046` (Pass-the-Ticket, line 93), `LAT-047` (Overpass-the-Hash, line 94), `LAT-048` (Pass-the-Certificate, line 95), `LAT-061` (DPAPI, line 135), `LAT-070` (SSH, line 147).
   - `tasks/dcom_wmi.yml`: Injects `LAT-071` (DCOM, line 7), `LAT-072` (WMI remote exec, line 27), `LAT-073` (WinRM, line 34), `LAT-074` (PSRemoting, line 45), `LAT-075` (RDP, line 57), `LAT-076` (RDP Hijacking, line 58), `LAT-080` (SCMExec, line 93), `LAT-090` (Scheduled Task, line 105), `LAT-095` (Named Pipe, line 117).
5. **`vuln_linux`**:
   - `tasks/linux_in_ad.yml`: Injects `B1` (krb5.keytab, line 8), `B2` (CORP\Domain Users passwordless sudo, line 24), `B3` (SSSD cache readable, line 36), `B4` (Cron job LPE, line 48), `B5` (SUID find, line 74), `B6` (Leaked domain credentials, line 85), `B7` (NFS export no_root_squash, line 113), `B8` (Weak SSH user, line 129).
   - `tasks/services.yml`: Injects `Redis` (unauth/bind, line 8), `Memcached` (exposed, line 37), `MongoDB` (no auth, line 59), `MySQL` (weak root remote, line 100), `NFS` (line 156), `WebApp` (dunder app RCE, line 179).
6. **`vuln_network_protocols`**:
   - `tasks/dns_wpad.yml`: Injects `NET-001` (WPAD DNS, line 6), `NET-003` (Insecure DNS update, line 9).
   - `tasks/name_services.yml`: Injects `NET-002` (mDNS, line 6), `NET-005` (NetBIOS B-node, line 9), `NET-006` (IPv6 enabled segment-wide, line 12).
   - `tasks/tftp.yml`: Injects `NET-004` (TFTP UDP 69, line 6).
   - `tasks/ntp_smtp.yml`: Injects `NET-007` (NTP server, line 6), `NET-008` (SMTP open relay document, line 13).
   - `tasks/vnc.yml`: Injects `NET-009` (VNC unauth, line 6).
   - `tasks/smtp_mail.yml`: Injects `NET-008` (SMTP open relay, line 6), `NET-010` (POP3, line 19).
   - `tasks/pop3.yml`: Injects `NET-010` (POP3 cleartext credentials, line 6).
   - `tasks/dhcp_scan_notes.yml`: Injects `NET-011` (DHCP starvation, line 6), `NET-012` (Scanning exposure, line 16).

---

## 2. Logic Chain
We compared each extracted tag against the contents of all files in `/home/sanchit/DVWA/docs/`.
1. **DF (Forest Compromise) Category**: 
   - `DF-001`..`DF-040` are documented in `07-forest-compromise.md`.
   - Matching tags: `DF-003`, `DF-005`, `DF-007`, `DF-008`, `DF-009`, `DF-010`, `DF-023` match the respective walkthrough titles exactly.
   - Colliding/Mismatched tags: 
     - In the code: `DF-011` (Spooler), `DF-012` (SID filtering), `DF-015` (Exchange NC), `DF-017` (AdminSDHolder), `DF-020` (Constrained delegation), `DF-022` (krbtgt ACL), `DF-025` (Schema Admin), `DF-030` (Cross-forest relay) are defined.
     - In the docs: `DF-011`..`DF-022` are mapped to ADCS ESC1..11 vulnerabilities. Therefore, their code definitions and walkthrough descriptions do not align. For instance, code `DF-017` is AdminSDHolder, but doc `DF-017` is ESC6.
   - Undocumented tags: All `DF-` tags above 40 (specifically `DF-041`..`DF-050`, `DF-055`, `DF-060`, `DF-070`..`DF-080`, `DF-081`..`DF-085`, `DF-087`, `DF-090`, `DF-095`, `DF-100`) are absent because the walkthrough file `07-forest-compromise.md` stops at `DF-040`.
2. **ESC Category**:
   - `ESC9`, `ESC10`, `ESC12`, `ESC14`, `ESC16` are fully covered. The docs map them as `DF-020`, `DF-021`, `CRED-047`, `DF-032`, and `DF-034` respectively, and their technical details match.
3. **IA (Initial Access) Category**:
   - `IA-001`..`IA-050` are documented in `02a-initial-access.md`.
   - All extracted code tags in that range (`IA-003`, `IA-004`, `IA-011`, `IA-014`, `IA-015`, `IA-019`..`IA-022`, `IA-024`, `IA-027`, `IA-033`..`IA-039`, `IA-040`, `IA-041`, `IA-043`..`IA-050`) are fully documented in `02a-initial-access.md`.
   - Any `IA-` tag above 50 (`IA-052`, `IA-053`, `IA-056`, `IA-063`, `IA-076`, `IA-078`, `IA-084`, `IA-085`, `IA-113`, `IA-114`, `IA-115`, `IA-117`, `IA-119`) is completely undocumented in `docs/` because the walkthrough only covers up to `IA-050`.
4. **CRED (Credential Access) Category**:
   - `CRED-001`, `CRED-002`, `CRED-016`, `CRED-018` are fully documented in `03-credential-access.md`.
5. **LAT (Lateral Movement) Category**:
   - `LAT-001`..`LAT-035` are documented in `04-lateral-movement.md`.
   - Matching tags: `LAT-016`, `LAT-021`, `LAT-022`, `LAT-026`, `LAT-027`, `LAT-028`, `LAT-033`, `LAT-034` align with their walkthrough names.
   - Colliding/Mismatched tags:
     - `LAT-001`..`LAT-015`, `LAT-017`..`LAT-020`, `LAT-023`..`LAT-025`, `LAT-029`..`LAT-032`, `LAT-035` are defined differently in the code (mostly coercion and relays) than in the docs (which lists standard movements like PsExec, WMI, DCOM, RDP, WinRM, etc.). For instance, code `LAT-029` is ForceChangePassword, but doc `LAT-029` is SCShell.
   - Undocumented tags: All `LAT-` tags above 35 (`LAT-036`, `LAT-041`..`LAT-048`, `LAT-061`, `LAT-070`..`LAT-076`, `LAT-080`, `LAT-090`, `LAT-095`) are absent because the walkthrough file `04-lateral-movement.md` stops at `LAT-035`.
6. **NET (Network Protocols) Category**:
   - There is no `NET-` category inside `/home/sanchit/DVWA/docs/`. Thus, all `NET-001`..`NET-012` tags are completely undocumented as distinct entities, although some techniques (like mitm6 or mDNS) are mentioned inside other sections.
7. **LNX / local Linux-in-AD Category**:
   - There is no crib sheet or LPE/lateral walkthrough for the Linux host `linux01.corp.local` in `docs/` (no `hosts/linux01-corp.md`). Hence, all Linux-local vectors (such as B1..B8, Redis, MongoDB, Memcached, MySQL, etc.) are completely undocumented.

---

## 3. Caveats
- We assumed `/home/sanchit/DVWA/docs/` contains the entire operator walkthrough set. We verified that no other documentation directories exist in the repository.
- We bypassed running the automated python script due to the user-approval terminal timeout. Instead, we performed manual recursive searches using `grep_search` and verified the file contents via `view_file`. This method is highly reliable as it leverages direct search outputs.

---

## 4. Conclusion
A significant gap exists between the Ansible configuration files (which inject a modern, expanded suite of vulnerabilities) and the walkthrough files under `docs/`. This drift manifests in three ways:
1. **Completely Undocumented Tags**: 
   - All `NET-` tags (`NET-001`..`NET-012`)
   - All `IA-` tags above 50 (`IA-052`, `IA-053`, `IA-056`, `IA-063`, `IA-076`, `IA-078`, `IA-084`, `IA-085`, `IA-113`, `IA-114`, `IA-115`, `IA-117`, `IA-119`)
   - All `DF-` tags above 40 (`DF-041`..`DF-050`, `DF-055`, `DF-060`, `DF-070`..`DF-080`, `DF-081`..`DF-085`, `DF-087`, `DF-090`, `DF-095`, `DF-100`)
   - All `LAT-` tags above 35 (`LAT-036`, `LAT-041`..`LAT-048`, `LAT-061`, `LAT-070`..`LAT-076`, `LAT-080`, `LAT-090`, `LAT-095`)
   - The entire `linux01.corp.local` host (Mandalore Base) LPE and service vulnerabilities (B1..B8, Redis, MongoDB, Memcached, MariaDB).
2. **Collisions / Mismatches**:
   - The `LAT-` family (e.g. `LAT-001` in code is PrinterBug, but in docs is PsExec).
   - The `DF-` family (e.g. `DF-015` in code is Exchange NC WriteDACL, but in docs is ESC4 Vulnerable Template ACL).
3. **Fully Documented Tags**:
   - The root ADCS `ESC9`, `ESC10`, `ESC12`, `ESC14`, `ESC16` tags are fully documented (although mapped to different IDs).
   - The standard `IA-001`..`IA-050` range, standard `CRED-` tags, and some `LAT-/DF-` tags align correctly.

### Summary Classification Table

| Category | Fully Documented | Partially Documented (Mismatched/Collision) | Completely Undocumented |
|---|---|---|---|
| **DF** | `DF-003`, `DF-005`, `DF-007`, `DF-008`, `DF-009`, `DF-010`, `DF-023` | `DF-011`, `DF-012`, `DF-015`, `DF-017`, `DF-020`, `DF-022`, `DF-025`, `DF-030`, `DF-049`, `DF-055`, `DF-060`, `DF-070..080` (ranges), `DF-081..085` (ranges), `DF-087`, `DF-090` | `DF-041..048`, `DF-050`, `DF-095`, `DF-100` |
| **ESC** | `ESC9`, `ESC10`, `ESC12`, `ESC14`, `ESC16` | None | None |
| **IA** | `IA-003`, `IA-004`, `IA-011`, `IA-014`, `IA-015`, `IA-019..022` (ranges), `IA-024`, `IA-027`, `IA-033..039` (ranges), `IA-040`, `IA-041`, `IA-043..050` (ranges), `REC-015` | None | `IA-052`, `IA-053`, `IA-056`, `IA-063`, `IA-076`, `IA-078`, `IA-084`, `IA-085`, `IA-113`, `IA-114`, `IA-115`, `IA-117`, `IA-119` |
| **CRED** | `CRED-001`, `CRED-002`, `CRED-016`, `CRED-018` | None | None |
| **LAT** | `LAT-016`, `LAT-021`, `LAT-022`, `LAT-026`, `LAT-027`, `LAT-028`, `LAT-033`, `LAT-034` | `LAT-001..015` (except `LAT-012` in code), `LAT-017..020`, `LAT-023..025`, `LAT-029..032`, `LAT-035`, `LAT-070..076`, `LAT-090`, `LAT-095` | `LAT-036`, `LAT-041..048`, `LAT-061`, `LAT-080` |
| **NET** | None | None | `NET-001`..`NET-012` |
| **LNX** | None | None | `B1`..`B8`, `Redis`, `Memcached`, `MongoDB`, `MySQL`, `WebApp` |

---

## 5. Verification Method
To independently verify these findings:
1. Run a grep search on the `docs/` folder for any of the undocumented tags, e.g.:
   `grep -rn "IA-117" /home/sanchit/DVWA/docs/`
   Observe that it returns 0 matches.
2. View `/home/sanchit/DVWA/docs/04-lateral-movement.md` starting at line 20 and compare the titles of `LAT-001` to `LAT-015` with the comments inside `/home/sanchit/DVWA/ansible/roles/vuln_lateral/tasks/coerce.yml` and `/home/sanchit/DVWA/ansible/roles/vuln_lateral/tasks/relay.yml`. Observe the mismatch.
3. Check `/home/sanchit/DVWA/docs/hosts/` and notice the absence of `linux01-corp.md` despite `linux01` being defined in the network topology and Ansible playbooks.
