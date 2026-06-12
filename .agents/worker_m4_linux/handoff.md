# Handoff Report

## 1. Observation
I observed and analyzed the following files in the workspace to construct the documentation:
* `/home/sanchit/DVWA/ansible/roles/vuln_linux/tasks/linux_in_ad.yml` - Contains task definitions for B1 to B8 vulnerabilities:
  - B1: `/etc/krb5.keytab` configured with mode `0644`.
  - B2: `/etc/sudoers.d/empire-ad` configured with `%domain\ users` having `NOPASSWD:ALL`.
  - B3: `/var/lib/sss/db/` configured with `chmod -R a+r /var/lib/sss/db`.
  - B4: `/opt/empire/backup.sh` configured with mode `0777` and executed by root cron.
  - B5: `/usr/local/bin/find-suid` configured with mode `4755`.
  - B6: `/home/labadmin/.creds.txt` containing `svc_r2d2`/`Droid2024!` and `/home/labadmin/.bash_history` leaking commands.
  - B7: NFS export `/srv/nfs/empire` with `no_root_squash`.
  - B8: Weak SSH configuration, local user `michael`/`Scranton2024!`, and world-writable `/home/michael/.ssh/authorized_keys`.
* `/home/sanchit/DVWA/ansible/roles/vuln_linux/tasks/services.yml` - Configures the target services:
  - Redis (6379, bind 0.0.0.0, protected-mode off, no auth).
  - Memcached (11211, bind 0.0.0.0).
  - MongoDB (27017, bind 0.0.0.0, no auth).
  - MySQL/MariaDB (3306, bind 0.0.0.0, root/root remote login, empty secure_file_priv).
  - WebApp (5000, python3).
* `/home/sanchit/DVWA/ansible/roles/vuln_linux/files/dunder_app.py` - Standard library Python script for the "Schrute Logistics" portal listening on port 5000 with OS command injection and unrestricted upload vulnerabilities.
* `/home/sanchit/DVWA/ansible/roles/vuln_linux/tasks/flags.yml` - Lists the exact flag locations and flag text files.
* `/home/sanchit/DVWA/docs/hosts/file01-corp.md` and `/home/sanchit/DVWA/docs/hosts/ca01-corp.md` - Used as templates for identical document layout, structure, and Star Wars mapping.

I have created `/home/sanchit/DVWA/docs/hosts/linux01-corp.md` containing all the requested documentation.

## 2. Logic Chain
1. Using grep and find tools, I located the specific configuration files (`linux_in_ad.yml`, `services.yml`, `dunder_app.py`, `flags.yml`) defining how the Mandalore member server (`mandalore.empire.local` at `10.10.0.15`) is built.
2. I extracted the exact parameters (ports, files, permissions, credentials, execution behaviors) for vulnerabilities B1 to B8 and the five network services.
3. I structured each vulnerability/service with:
   - Heading (tag/service name)
   - Detailed explanation of the vulnerability
   - Concrete execution/exploit commands (bash code blocks)
   - Specific detection and prevention steps.
4. I retrieved formatting standards from `/home/sanchit/DVWA/docs/hosts/file01-corp.md` and `/home/sanchit/DVWA/docs/hosts/ca01-corp.md` (e.g. Title header with hostname and IP, Listening ports markdown table, Local LPE table, Minimum enum sweep, Forward to references, and the thematic Star Wars mapping).
5. I generated the final markdown file `/home/sanchit/DVWA/docs/hosts/linux01-corp.md` with layout and content matching these verified details.

## 3. Caveats
No caveats.

## 4. Conclusion
The documentation file `/home/sanchit/DVWA/docs/hosts/linux01-corp.md` has been successfully created. It covers all requested Linux local LPEs (B1-B8) and service vulnerabilities (Redis, MongoDB, Memcached, MySQL, WebApp Python RCE) on Mandalore Base, including precise commands, and adheres strictly to the existing documentation's layout, style, and thematic lore.

## 5. Verification Method
Verify that the file exists and check its content and formatting:
```bash
cat /home/sanchit/DVWA/docs/hosts/linux01-corp.md
```
Ensure it contains all sections and identical formatting to `/home/sanchit/DVWA/docs/hosts/file01-corp.md`.
