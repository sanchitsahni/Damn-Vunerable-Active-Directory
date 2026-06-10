# DVAD Attack Patterns

All attack chains validated by `scripts/exploit_graph.py` (41 exploit primitive edges, 155+ chains to DA/EA).  
Lab network: `10.10.0.0/16` — all 8 VMs on single bridge `dvad-ctf`.

```
Run: python3 scripts/exploit_graph.py --test --dot chains.dot
```

---

## Network Topology

| Host | IP | Role |
|------|----|------|
| dc01.corp.local | 10.10.0.10 | corp.local Domain Controller |
| dc01.eu.corp.local | 10.10.0.11 | eu.corp.local Child DC |
| ca01.corp.local | 10.10.0.12 | ADCS Certificate Authority |
| file01.corp.local | 10.10.0.13 | File/Web server |
| sql01.corp.local | 10.10.0.14 | SQL Server 2022 |
| ws01.corp.local | 10.10.0.100 | Windows 10 workstation |
| dc01.finance.local | 10.10.20.10 | finance.local Forest DC |
| dc01.root.corp | 10.10.30.10 | root.corp Forest DC |

---

## Initial Access Vectors

| ID | Vector | Entry Point | Prereq |
|----|--------|-------------|--------|
| IA-001 | LLMNR/NBNS poisoning | corp.local broadcast | Responder on segment |
| IA-052 | LNK UNC coercion | ws01 Desktop | User opens file |
| IA-056 | HTA in Downloads | ws01 | User opens HTA |
| IA-076 | IIS HTTP | file01:80 | No auth |
| IA-078 | WebDAV PUT | file01:80/uploads | No auth |
| IA-084 | RDP no NLA | ws01:3389 | Credentials |
| IA-085 | SSH password auth | file01:22 | Credentials |
| IA-113 | Password spray | dc01:88/389 | Weak policy (no lockout, min len 1) |
| IA-114 | Weak PSO | dc01 | Targeted account in Weak-PSO |
| IA-119 | GPO registry credential | Any domain member | Read HKLM\Software\DVADLab |

---

## Kill Chains — Initial Access → Domain Admin

### Chain A — Web → SQLi → xp_cmdshell → DA
```
[Attacker] → (IA-076: IIS/HTTP) → file01:user
           → (WEB-021: SQLi login.aspx) → sql01:user
           → (SRV-003: xp_cmdshell) → sql01:system
           → (SRV-007: svc_sql domain token) → domain:user
           → (CRED-013: DCSync svc_darryl) → DA
```
**Tools:** curl/burp → impacket-mssqlclient → impacket-secretsdump  
**Creds obtained:** sa/SqlServer2025! (via SQLi) → krbtgt hash

---

### Chain B — LLMNR → NTLM Relay → LDAP → DA
```
[Attacker] → (IA-001: LLMNR/Responder) → dc01:creds (NTLMv2 hash)
           → (LAT-011: NTLM relay, SMB signing off) → dc01:creds
           → (LAT-relay: LDAP relay → RBCD/ACL) → DA
```
**Tools:** Responder → ntlmrelayx.py → impacket-secretsdump  
**Prereqs:** SMB signing disabled on file01, LDAP signing not required

---

### Chain C — Password Spray → ADCS ESC1 → DA
```
[Attacker] → (IA-113: spray jdoe/Password123!) → domain:user
           → (ESC1: UserTemplate SAN forgery) → DA cert
           → (certipy auth) → DA TGT
```
**Tools:** crackmapexec → certipy req → certipy auth  
**Creds:** jdoe:Password123! → forge admin@corp.local UPN in cert

---

### Chain D — Password Spray → DCSync → Golden Ticket
```
[Attacker] → (IA-113: spray) → domain:user
           → (CRED-013: DCSync via svc_darryl:Backup2024!) → krbtgt hash
           → (CRED-099: Golden Ticket) → DA (any time, no expiry)
```
**Tools:** impacket-secretsdump → mimikatz/Rubeus  
**Creds:** svc_darryl:Backup2024! has GetChangesAll on domain NC

---

### Chain E — PrinterBug → Unconstrained Delegation → DA
```
[Attacker] → (DF-011: Spooler coerce dc01 → file01) → file01 captures dc01$ TGT
           → (DF-042: Unconstrained delegation on file01$)
           → (DCSync with dc01$ TGT) → DA
```
**Tools:** SpoolSample/printerbug.py → Rubeus monitor → secretsdump  
**Prereqs:** Spooler on dc01 (DF-011), file01$ TrustedForDelegation=True (DF-042)

---

### Chain F — RDP → WDigest → PtH → DA
```
[Attacker] → (IA-084: RDP ws01, NLA disabled) → ws01:user
           → (WDigest enabled: CRED-043/LAT-043) → plaintext creds in LSASS
           → (LAT-045: PtH to dc01) → dc01:admin
           → (PE-128: local admin on DC = DA) → DA
```
**Tools:** mstsc/rdesktop → mimikatz sekurlsa::logonpasswords → psexec/wmiexec

---

### Chain G — SSH → GPP Password → DA
```
[Attacker] → (IA-085: SSH file01:22) → file01:user
           → (CRED-030: GPP cpassword in SYSVOL) → svc_darryl hash
           → (CRED-013: DCSync) → krbtgt hash
           → (CRED-099: Golden Ticket) → DA
```
**Tools:** ssh → smbclient → gpp-decrypt → secretsdump  
**Creds:** GPP groups.xml cpassword decrypts to Backup2024!

---

### Chain H — Kerberoasting → Service Account → Relay → DA
```
[Attacker] → (IA-113: spray low-priv) → domain:user
           → (CRED-017: Kerberoast svc_sql/svc_web) → TGS hash
           → (hashcat crack) → svc_sql:SqlSvc2024!
           → (SRV-001: MSSQL sa access with svc_sql) → sql01:system
           → (xp_cmdshell net group DA add) → DA
```
**Tools:** GetUserSPNs → hashcat -m 13100 → mssqlclient

---

### Chain I — RBCD via MAQ → S4U2Self → DA
```
[Attacker with domain user] → (DF-041: MAQ=100 create evil$) → evil$:machine
           → (CRED-014: jdoe GenericWrite on file01/ws01) → set RBCD evil$ → target
           → (S4U2Self+Proxy impacket-getST) → admin ticket for target
           → (lateral to DC) → DA
```
**Tools:** addcomputer.py → rbcd.py → getST → smbclient/psexec

---

### Chain J — Shadow Credentials → PKINIT → DA
```
[domain:user with HelpDesk] → (LAT-036: write KeyCredentialLink on ws01$)
           → (LAT-048: Whisker/pyWhisker) → ws01$ PKINIT cert
           → (S4U2Self with ws01$ TGT) → admin on ws01
           → (sekurlsa dump) → DA cached creds
```
**Tools:** Whisker.exe → Rubeus asktgt → Rubeus s4u

---

## Kill Chains — DA → Enterprise Admin (Cross-Forest)

### Chain K — Golden Ticket + ExtraSID → finance.local EA
```
[corp.local DA] → (CRED-099: krbtgt hash) → Golden Ticket
               → (DF-081: ExtraSID = finance.local EA SID, filtering off)
               → finance.local Enterprise Admin
               → (DF-100: access root.corp via finance trust) → root.corp EA
```
**Tools:** mimikatz kerberos::golden /sids:S-1-5-21-FINANCE-519 → pass-the-ticket

---

### Chain L — Entra Connect Abuse → Cloud DA
```
[corp.local DA] → (CLO-001: MSOL_sync account DCSync rights)
               → (CLO-002: DCSync corp.local → NTLM hashes)
               → (CLO-008: Entra Connect credentials) → cloud admin
               → Global Administrator in Entra ID
```
**Tools:** AADInternals, secretsdump, Entra Connect DB extraction

---

## Kill Chains — Web App → OS → Domain

### Chain M — File Upload RCE → SYSTEM → Domain
```
[Attacker] → (IA-076: HTTP file01:80)
           → (WEB-012: upload.aspx — no extension check) → upload webshell
           → (upload.aspx?cmd=whoami) → IIS app pool OS command
           → (WEB-010: app pool runs as SYSTEM/svc_iis) → SYSTEM
           → (svc_iis domain token) → domain:user
           → (CRED-013: DCSync) → DA
```
**Tools:** curl -F "file=@shell.aspx" http://file01/upload.aspx → browse shell

---

### Chain N — Path Traversal → web.config → SA creds → DA
```
[Attacker] → (WEB-024: path_traversal.aspx?file=web.config) → SQL SA password
           → (SRV-001: MSSQL sa login) → sql01:system
           → (SRV-003: xp_cmdshell) → OS exec
           → (net user /domain) → domain enumeration → DA chain
```
**Exposed:** web.config contains `SqlSaPassword=SqlServer2025!` (WEB-009)

---

## Persistence Chains

### PER-Chain 1 — Golden Ticket (infinite validity)
```
[DA] → DCSync krbtgt → Golden Ticket (10yr validity)
     → Access any service in corp.local without further authentication
```

### PER-Chain 2 — WMI Event Subscription
```
[DA/Admin] → (PER-006: WMI __EventFilter + CommandLineEventConsumer)
           → Triggered on boot/login → persistent backdoor
```
**Cleanup detection:** `Get-WMIObject -NS 'root\subscription' -Class __FilterToConsumerBinding`

### PER-Chain 3 — AdminSDHolder WriteDACL
```
[DA] → (DF-017: svc_darryl WriteDACL on AdminSDHolder)
     → SDProp propagates every 60min → svc_darryl gains DA-equivalent rights
```

### PER-Chain 4 — Skeleton Key / DSRM backdoor
```
[DA on DC] → mimikatz misc::skeleton → all accounts accept master password
           → (or) lsadump::setntlm /user:Administrator → persistent DSRM hash
```

---

## Credential Extraction Paths

| Source | Tool | Credentials |
|--------|------|-------------|
| LSASS memory | mimikatz sekurlsa | Plaintext (WDigest) + NTLM hashes |
| SAM hive | secretsdump/HiveNightmare | Local admin hashes |
| NTDS.dit (DCSync) | secretsdump -just-dc | All domain hashes |
| SYSVOL GPP | gpp-decrypt | svc_darryl:Backup2024! |
| Windows Credential Manager | cmdkey /list + SharpDPAPI | dc01 Admin, sa creds |
| web.config | path_traversal.aspx | sa:SqlServer2025! |
| DunderMifflin DB | sqlcmd/sqli.aspx | All service account passwords |
| .rdp file | DPAPI decode | dc01 Admin |
| AWS credentials | file read | AKIA... key |
| Terraform tfstate | file read | DVADlab2024! + SqlServer2025! |

---

## Privilege Escalation Paths

| ID | Vuln | From | To |
|----|------|------|----|
| PE-010 | AlwaysInstallElevated | user | SYSTEM |
| PE-015 | Weak service DACL (svc_dvad_weak) | user | SYSTEM |
| PE-016 | Unquoted service path (svc_pathsvc) | user | SYSTEM |
| PE-017 | MSSQL Binn world-writable DLL hijack | sql user | SYSTEM |
| PE-020 | World-writable scheduled task script | user | SYSTEM |
| PE-028 | SeImpersonatePrivilege | service | SYSTEM (Potato) |
| PE-061 | PATH hijack (C:\Tools world-writable) | user | SYSTEM |
| CVE-2021-36934 | HiveNightmare (SAM ACL) | user | Local Admin hash |
| CVE-2021-34527 | PrintNightmare | domain user | SYSTEM on DC |

---

## Graph-Based Validation

```bash
# Topology only — enumerate all 155+ chains
python3 scripts/exploit_graph.py

# Live test against running lab
python3 scripts/exploit_graph.py --test

# Export attack graph as PNG
python3 scripts/exploit_graph.py --dot chains.dot
dot -Tpng chains.dot -o chains.png

# Show only fully-working chains
python3 scripts/exploit_graph.py --test --ready

# JSON output for automation
python3 scripts/exploit_graph.py --test --json > chains.json
```

Graph nodes: `attacker:anon` → `domain:user` → `{host}:{priv}` → `domain_admin:da` → `enterprise_admin:ea`

---

## Layer 2 Exploit Verification

```bash
# Run all checks
./scripts/verify_exploits.sh

# Per-category
./scripts/verify_exploits.sh --category cred_access
./scripts/verify_exploits.sh --category adcs
./scripts/verify_exploits.sh --category lateral_movement
./scripts/verify_exploits.sh --category web

# Layer 1 passive check (Ansible config verification)
python3 scripts/verify_vulns.py
```
