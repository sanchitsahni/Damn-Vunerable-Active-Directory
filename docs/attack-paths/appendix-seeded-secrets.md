---
tags: [lab/empire, reference, seeded-secrets]
---
# 📋 Appendix — All Seeded Secrets

> [!info] Source
> Pulled from the ansible roles `vuln_kerberos`, `vuln_cred_access`, `vuln_adcs`, `vuln_lateral`, `ad_domain`. These are the planted attack targets — not invented.

## Credentials (cleartext / crackable)

| Principal | Domain | Password | Use |
|---|---|---|---|
| `Administrator` | all 4 | `SithLord123!` | uniform forest/local admin |
| spray cohort ×7 | empire | `SithLord123!` | [[02-kerberoast-to-da]] step 1 |
| `svc_trooper` | empire | `Summer2024` | Kerberoast + delegation |
| `svc_maul` | empire | `DeathStar1!` | Kerberoast (MSSQL) |
| `svc_sidious` | empire | `Tarkin123` | Kerberoast |
| `svc_palpatine` | empire | — (AS-REP crack) | [[03-asrep-roast]] |
| `rebel_svc` | rebel | `RebelSvc2025!` | Kerberoast |
| `han.solo` | rebel | `Rebel1234!` | foothold |
| `padme.amidala` | rebel | `Rebel1234!` | foothold |

Spray cohort: `biggs.darklighter, mon.mothma, greedo.tets, mace.windu, jabba.hutt, wilhuff.tarkin, jyn.erso`

## Stored-credential surfaces (`vuln_cred_access`)

| Surface | Detail |
|---|---|
| GPP cpassword | in SYSVOL → `gpp-decrypt` (public MS key) |
| DBeaver config | `sa : DeathStar2025!` (kamino:1433) |
| SCCM NAA blob | `svc_sccm` (DPAPI-style) |
| LM compat = 1 | members/WS → NTLMv1 capture via Responder |

## Kerberos misconfig (`vuln_kerberos`) — [[07-delegation]]

| Type | Principal | Target |
|---|---|---|
| Constrained deleg | `svc_trooper` | `HTTP/tatooine.empire.local` |
| Unconstrained deleg | `scarif`, `tatooine` | (computer accounts) |
| RC4-only enctype | roastable accounts | faster cracking |
| SPN `svc_trooper` | `HTTP/print.empire.local` | |
| SPN `svc_maul` | `MSSQLSvc/kamino.empire.local:1433` | |

## ADCS (`vuln_adcs`) — [[05-adcs-esc1-esc8]]

CA = `corp-CA` on `endor.empire.local`.

| ESC | Template / flag |
|---|---|
| ESC1 | `EMPIREUserESC1` |
| ESC2 | `EMPIREMachineESC2` |
| ESC3 | `EMPIREAgentESC3` |
| ESC4 | `EMPIREWriteESC4` |
| ESC13 | `EMPIREIssuanceESC13` |
| ESC15 | `EMPIRENoSecExtESC15` |
| ESC6 | `EDITF_ATTRIBUTESUBJECTALTNAME2` on corp-CA |
| ESC7 | `svc_bobafett` = Certificate Manager |
| ESC8 | CertSrv HTTP + NTLM, no EPA |
| ESC11 | CertSrv RPC, no HTTPS |

## ACL edges (`vuln_lateral`) — [[04-acl-sheev-palpatine-dcsync]] · [[11-laps-helpdesk-chain]]

| ID | Principal | Right | Target |
|---|---|---|---|
| LAT-021 | `sheev.palpatine` | **GenericAll** | **domain object** |
| LAT-022 | `darth.maul` | Validated-SPN write | `svc_trooper` |
| LAT-025 | (WriteSPN) | add SPN | `luke.skywalker` |
| LAT-029 | `HelpDesk` | ForceChangePassword | `IT_Team` members |
| LAT-030 | `HelpDesk` | GenericWrite | `svc_bobafett2` |
| LAT-031 | `svc_bobafett` | WriteOwner | `finance_sync` |
| LAT-023 | `IT_Team` | read `ms-Mcs-AdmPwd` | Computers OU (LAPS) |
| LAT-034 | rebel `Administrator` | FSP member | empire `Corporate Admins` |

## Coerce / relay (`vuln_cred_access`) — [[06-coerce-relay]]

| Surface | Detail |
|---|---|
| Spooler + EFS on DCs | PrinterBug / PetitPotam |
| WSUS SPN | `HTTP/wsus.empire.local` (SRV-046) |
