---
tags: [lab/empire, study, notes]
---
# 📚 Study — EMPIRE Lab Notes

Personal working notes for the EMPIRE multi-forest AD lab. Scratch space for
findings, query results, and per-run observations.

> [!tip] Where things live
> - **Attack playbook** (foothold → DA, all paths): [[00-overview]] in `docs/attack-paths/`
> - **All seeded secrets**: [[appendix-seeded-secrets]]
> - **BloodHound collector**: `scripts/bh-dump-all.sh`

## Suggested layout

```
study/
├── README.md           ← this file
├── bloodhound/         ← Cypher queries, graph exports, findings
├── runs/               ← per-engagement notes (dated)
└── loot/               ← cracked hashes, tickets (gitignored if sensitive)
```

## Open questions / TODO

- [ ] Verify cross-forest trust state — see [[09-rebel-forest]] / [[10-trade-forest]]
- [ ] Confirm which ESC templates `certipy find -vulnerable` actually flags per forest
- [ ] Map `Corporate Admins` FSP bridge (LAT-034) both directions
