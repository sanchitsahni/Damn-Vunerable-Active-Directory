# Handoff Report — Lateral Movement Documentation (M4)

## 1. Observation
I observed that the lateral movement documentation (`docs/04-lateral-movement.md`) originally mapped `LAT-001` through `LAT-015` to standard remote execution and tunneling techniques (e.g. PsExec, WMI, Scheduled Tasks, WinRM, RDP, SSH, etc.), which did not match the corresponding tasks in the Ansible roles.

Specifically, inside `/home/sanchit/DVWA/ansible/roles/vuln_lateral/tasks/`:
* `coerce.yml` (lines 6-15) defines:
  ```yaml
  # LAT-001  MS-RPRN PrinterBug — Print Spooler on all DCs (see DF-011 too)
  # LAT-002  MS-EFSR PetitPotam — EFS service enabled
  # LAT-003  MS-FSRVP ShadowCopyAgent — shadow copy coercion
  # LAT-004  MS-DFSNM DFS coercion — DFS namespace service
  # LAT-005  MS-NRPC Netlogon coercion — always-on service
  # LAT-006  WebDAV coercion — WebClient on tatooine (set in packer)
  # LAT-007  MS-ICPR ADCS HTTP enrollment endpoint (endor)
  # LAT-008  PrivExchange — Exchange coercion (note + placeholder)
  # LAT-009  HTTP coercion via SCF file in share
  # LAT-010  Multicast DNS poisoning surface (LLMNR/NBT-NS still active)
  ```
* `relay.yml` (lines 7-17) defines:
  ```yaml
  # LAT-011  LDAP signing not required on DCs (no enforce)
  # LAT-012  LDAP channel binding disabled
  # LAT-013  SMB1 + signing off on scarif (relay target)
  # LAT-014  Cross-protocol relay: LDAP signing off, SMB signing off
  # LAT-015  CredSSP AllowEncryptionOracle=2 on scarif (CVE-2018-0886 surface)
  # ...
  # LAT-017  Unconstrained delegation coercion + relay chain note
  # LAT-018  NTLMv2 capture via Responder + relay to LDAPS
  # LAT-019  Cross-forest NTLM relay (SID filtering off — see ad_trust)
  # LAT-020  NTLM relay to ADCS HTTP enrollment (endor ESC8)
  ```
* `acl_abuse.yml` (lines 6-15) defines:
  ```yaml
  # LAT-023  LAPS read ACL for IT_Team (ms-Mcs-AdmPwd read on Computers OU)
  # LAT-024  Cross-forest SPN abuse (svc_trooper with SPN on rebel.local)
  # LAT-025  WriteSPN on HelpDesk users (targeted Kerberoast-able accounts)
  # ...
  # LAT-029  ForceChangePassword on IT_Team members
  # LAT-030  GenericWrite on service accounts for SPN add (Kerberoasting)
  # LAT-031  WriteOwner on finance_sync group
  # LAT-032  AddMember on Domain Admins for HelpDesk (indirect)
  # ...
  # LAT-035  Overpass-the-hash: AES key extraction surface
  ```
* `lateral_adv.yml` (lines 7-95) defines:
  ```yaml
  # LAT-036: Shadow Credentials (PKINIT + msDS-KeyCredentialLink write)
  # LAT-041: NTLM relay target — disable Extended Protection for Authentication
  # LAT-042: SMB signing verification
  # LAT-043: WDigest credential caching
  # LAT-044: Credential Guard disabled
  # LAT-045: Pass-the-Hash via SMB
  # LAT-046: Pass-the-Ticket via Rubeus/Mimikatz
  # LAT-047: Overpass-the-Hash (RC4 TGT from NT hash)
  # LAT-048: Pass-the-Certificate (PKINIT with shadow credential cert)
  # ...
  # LAT-061: DPAPI-Based Lateral Movement
  # ...
  # LAT-070: SSH Lateral Movement
  ```
* `dcom_wmi.yml` (lines 7-119) defines:
  ```yaml
  # LAT-071: DCOM ShellBrowserWindow / MMC20 / ShellWindows exec
  # LAT-072: WMI remote exec surface
  # LAT-073: WinRM lateral
  # LAT-074: PSRemoting with domain credentials
  # LAT-075: RDP as lateral movement channel
  # LAT-076: RDP hijacking via tscon
  # ...
  # LAT-080: Service Control Manager Remote Execution
  # ...
  # LAT-090: Remote Scheduled Task Lateral Movement
  # ...
  # LAT-095: Named Pipe Lateral Movement
  ```

## 2. Logic Chain
1. There was a discrepancy where documentation defined `LAT-001..015` as basic remote execution techniques, but the Ansible playbooks implement them as coercions and relays.
2. The standard remote execution techniques are actually mapped to the `LAT-070` to `LAT-095` ranges in `dcom_wmi.yml`.
3. To reconcile the documentation with the code implementation, `04-lateral-movement.md` had to be updated to:
   - Remap `LAT-001..015` to their coercion and relay equivalents from `coerce.yml` and `relay.yml`.
   - Remap `LAT-017..020` to delegation and relay techniques from `relay.yml`.
   - Remap `LAT-023..025` to the LAPS, Cross-Forest SPN, and WriteSPN ACL abuses from `acl_abuse.yml`.
   - Remap `LAT-029..032` to the ForceChangePassword, GenericWrite, WriteOwner, and AddMember ACL abuses from `acl_abuse.yml`.
   - Remap `LAT-035` to Overpass-the-Hash (AES Key Extraction).
   - Append new sections for `LAT-036` (Shadow Credentials), `LAT-041..048` (EPA relay, WDigest caching, Credential Guard disabled, Pass-the-Hash, Pass-the-Ticket, Overpass-the-Hash, Pass-the-Certificate), `LAT-061` (DPAPI key theft), `LAT-070..076` (OpenSSH, DCOM, WMI, WinRM, PSRemoting, RDP, RDP Hijacking), `LAT-080` (SCMExec), `LAT-090` (Scheduled Task), and `LAT-095` (Named Pipe).

## 3. Caveats
- Since this is documentation, there is no runnable code test suite or compiler validation to run.
- The standard user/password for the lab (`EmpireLab2024!`) was used to replace instances of `SithLord123!` to maintain consistency with `AGENTS.md` guidelines.

## 4. Conclusion
The file `/home/sanchit/DVWA/docs/04-lateral-movement.md` has been successfully updated. All `LAT-` vulnerability tags (`LAT-001..015`, `LAT-017..020`, `LAT-023..025`, `LAT-029..032`, `LAT-035`, `LAT-036`, `LAT-041..048`, `LAT-061`, `LAT-070..076`, `LAT-080`, `LAT-090`, `LAT-095`) are fully documented with headings, explanations, execution commands, and detection/prevention mechanisms, fully aligning with the codebase tasks.

## 5. Verification Method
To verify:
1. View the contents of `/home/sanchit/DVWA/docs/04-lateral-movement.md`.
2. Inspect the headings and details for `LAT-001`, `LAT-015`, `LAT-036`, `LAT-045`, `LAT-071`, `LAT-095` to ensure they match the remapped coercion/relay/advanced movement definitions.
3. Validate that the layout and syntax format matches the rest of the documentation.
