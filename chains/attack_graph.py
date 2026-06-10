#!/usr/bin/env python3
# ==============================================================================
# attack_graph.py — GROUND-TRUTH attack graph for the DUNDER / DVAD lab.
#
# This module is *data*, not logic. Every node and edge below is derived from
# what the ansible/roles/vuln_* roles ACTUALLY deploy (verified by reading the
# task files), cross-referenced against PLAN.md. The validator (validator.py)
# consumes this data and runs reachability analysis over it.
#
# Provenance convention:  each edge carries `source` = the role/task file (and
# attack id) that injects the transition. If `source` is None the edge is a
# logical/offline step (e.g. "crack a captured hash") that needs no injection.
#
# Nodes are PRIVILEGE/ACCESS STATES. Edges are TECHNIQUES that move between
# them, each labelled with its catalog id, prerequisite state, and what it
# yields.
#
# IMPORTANT — discrepancies discovered while deriving this graph are recorded
# in DANGLING (techniques PLAN/roles reference but that nothing makes
# practically usable). The validator surfaces them.
# ==============================================================================

# ─── Lab topology (matches CLAUDE.md four-way invariant) ───────────────────────
HOSTS = {
    "dc01":    "10.10.0.10",     # corp.local PDC, forest root
    "dc01eu":  "10.10.0.11",     # eu.corp.local child DC
    "ca01":    "10.10.0.12",     # ADCS
    "file01":  "10.10.0.13",     # file server (unconstrained deleg, SMB1)
    "sql01":   "10.10.0.14",     # MSSQL
    "ws01":    "10.10.0.100",    # victim workstation
    "findc01": "10.10.20.10",    # finance.local DC (external trust)
    "rootdc01":"10.10.30.10",    # root.corp DC (forest/tree-root trust)
}

DOMAIN = "corp.local"

# ─── Access-state nodes ────────────────────────────────────────────────────────
# Naming: "<scope>:<state>". A player "holds" a node once reached.
ANON          = "anonymous"                      # attacker on the bridge, no creds

# foothold identities a player can actually OBTAIN unauthenticated:
USER_SPRAY    = "user:spray-cohort@corp"         # any of 7 Password123! users
USER_ANY      = "user:any-domain-user@corp"      # generalised authenticated user
WS01_USER     = "shell:ws01"                     # code-exec on ws01 (phishing/RDP)
FILE01_USER   = "shell:file01"                   # code-exec on file01 (IIS/SSH/FTP)
SQL01_SVC     = "shell:sql01-service"            # xp_cmdshell service context

# captured-credential intermediate states:
CREDS_KERBEROAST = "creds:kerberoast-svc"        # svc_printer/dwight/creed hashes
CREDS_ASREP      = "creds:asrep-svc_michael"     # svc_michael AS-REP hash
CREDS_DARRYL     = "creds:svc_darryl"            # DCSync-capable account creds
CREDS_MICHAEL    = "creds:michael.scott"         # GenericAll-on-domain / Schema Admins
CREDS_DEVELOPER2 = "creds:developer2"            # ->Enterprise Admins GenericWrite
CREDS_SCCM       = "creds:svc_sccm"              # member of Domain Admins
KRBTGT           = "creds:krbtgt-hash"           # full domain key material

# local-admin milestones:
ADMIN_FILE01  = "local-admin:file01"
ADMIN_SQL01   = "local-admin:sql01"
ADMIN_WS01    = "local-admin:ws01"
ADMIN_CA01    = "local-admin:ca01"

# domain/forest milestones:
DA_CORP       = "domain-admin:corp"
EA            = "enterprise-admin:corp-forest"
DA_FINANCE    = "da:finance"
DA_ROOT       = "da:root"

# ─── Footholds the lab actually provides (Phase 0 / IA-xxx, verified) ──────────
# Each is an edge from ANON. These are the entry points reachability starts from.
FOOTHOLDS = [
    # id, dst, label, source(role/task)
    ("IA-007/IA-113", USER_SPRAY,  "Password spray (min-len 1 policy, Password123! cohort)",
        "vuln_cred_access/users_creds.yml + vuln_ia_surface/ext_misconfig.yml"),
    ("IA-006/IA-111", CREDS_ASREP, "Unauth AS-REP roast of svc_michael (DoNotRequirePreAuth)",
        "vuln_kerberos/main.yml + vuln_ia_surface/ext_misconfig.yml"),
    ("IA-019..024",   WS01_USER,   "Phishing landing on ws01 (macros/LNK/HTA/.library-ms)",
        "vuln_ia_surface/ws01_surface.yml"),
    ("IA-027/IA-043/IA-084", WS01_USER, "RDP NLA-disabled on ws01 (BlueKeep gate)",
        "vuln_ia_surface/ws01_surface.yml"),
    ("IA-035/IA-085/IA-076", FILE01_USER, "Anonymous IIS/FTP or SSH password-auth on file01",
        "vuln_ia_surface/file01_surface.yml + ext_services.yml"),
    ("IA-011/IA-086", SQL01_SVC,  "Unauth MSSQL sa + xp_cmdshell on sql01",
        "vuln_ia_surface/sql01_surface.yml"),
    ("IA-038", FILE01_USER, "SMB1/EternalBlue surface on file01",
        "vuln_ia_surface/file01_surface.yml"),
]

# ─── Technique edges (state -> state), all derived from roles ──────────────────
# (id, src, dst, label, source)
EDGES = [
    # ── shell on a box implies a usable domain identity (machine/cached) ───────
    ("post-foothold", WS01_USER,   USER_ANY, "Domain-joined ws01 shell -> authenticated domain context",
        "domain_join (ws01 is domain member)"),
    ("post-foothold", FILE01_USER, USER_ANY, "Domain-joined file01 shell -> authenticated domain context",
        "domain_join"),
    ("post-foothold", SQL01_SVC,   USER_ANY, "SQL service token / svc_dwight context -> domain identity",
        "vuln_exchange/vuln_ia_surface (sql01 domain member)"),
    ("spray=user",    USER_SPRAY,  USER_ANY, "Spray-cohort creds are valid domain users",
        "vuln_cred_access/users_creds.yml"),

    # ── credential access reachable from any authenticated domain user ─────────
    ("CRED-001", USER_ANY, CREDS_KERBEROAST, "Kerberoast svc_printer/svc_dwight/svc_creed (weak pw + SPN)",
        "vuln_kerberos/main.yml"),
    ("CRED-002", USER_ANY, CREDS_ASREP, "AS-REP roast svc_michael",
        "vuln_kerberos/main.yml"),
    # AS-REP foothold is itself a crackable hash -> the svc_michael identity
    ("crack", CREDS_ASREP, USER_ANY, "Crack svc_michael AS-REP hash (offline) -> domain user",
        None),
    ("crack", CREDS_KERBEROAST, USER_ANY, "Crack kerberoast hashes (Summer2024/BeetFarm1!/Creed123)",
        None),

    # ── local admin on each box ────────────────────────────────────────────────
    ("IA-011/SRV-003", SQL01_SVC, ADMIN_SQL01, "xp_cmdshell service -> SeImpersonate potato -> SYSTEM/local admin",
        "vuln_ia_surface/sql01_surface.yml + vuln_privesc/tokens.yml (PE-081)"),
    ("PE-007/PE-008", FILE01_USER, ADMIN_FILE01, "Unquoted service path / weak service DACL on file01",
        "vuln_privesc/services.yml"),
    ("LAT-013/LAT-045", USER_ANY, ADMIN_FILE01, "PtH to file01 (SMB signing off, flat NTLM)",
        "vuln_lateral/relay.yml + smb.yml"),
    ("PE-016/PE-030", WS01_USER, ADMIN_WS01, "Writable scheduled task / world-writable C:\\Tools on ws01",
        "vuln_privesc/services.yml"),
    ("LAT-023/PE-123", USER_ANY, ADMIN_WS01, "LAPS read (IT_Team) / golden-image local-admin reuse -> ws01 admin",
        "vuln_lateral/acl_abuse.yml + vuln_privesc/ad_pe.yml"),
    ("IA-039/IA-049", FILE01_USER, ADMIN_CA01, "WebDAV PUT aspx webshell on ca01 then SeImpersonate",
        "vuln_ia_surface/ca01_surface.yml + vuln_privesc/tokens.yml"),
    ("ESC7+SeImp", USER_ANY, ADMIN_CA01, "svc_darryl CA Manager (ESC7) / DCOM ESC12 -> code-exec on ca01",
        "vuln_adcs/ca-flags.yml + vuln_forest/esc_ext.yml"),

    # ── paths to Domain Admin in corp.local ────────────────────────────────────
    # ESC1: ANY domain user can enroll DVADUserESC1 (Domain Users enroll right)
    ("DF-012/ESC1", USER_ANY, DA_CORP, "ADCS ESC1: enroll DVADUserESC1 w/ arbitrary SAN -> DA cert -> TGT",
        "vuln_adcs/templates.yml (Domain Users enroll)"),
    ("DF-019/ESC8", USER_ANY, DA_CORP, "ADCS ESC8: coerce DC auth -> NTLM relay to CA web enrollment -> DC cert",
        "vuln_adcs/ca-flags.yml + vuln_lateral/coerce.yml"),
    # SCCM service account is a literal Domain Admins member; its NAA/DPAPI
    # secrets are recoverable with local admin on the SCCM-managed file01.
    ("SRV-030/SRV-031", ADMIN_FILE01, CREDS_SCCM, "Recover svc_sccm NAA/DPAPI secret on SCCM client file01",
        "vuln_exchange/sccm.yml"),
    ("SRV-030", CREDS_SCCM, DA_CORP, "svc_sccm is a member of Domain Admins",
        "vuln_exchange/sccm.yml"),
    # svc_darryl creds are recoverable: plaintext net-use line in the world-readable
    # SYSVOL bootstrap script (REC-015), password matches the real account.
    ("REC-015", USER_ANY, CREDS_DARRYL, "Read svc_darryl plaintext creds from SYSVOL setup.bat",
        "vuln_ia_surface/defaults (ia_sysvol_script_content)"),
    # DCSync: svc_darryl holds Replicate-Directory-Changes(-All) on the domain NC.
    ("CRED-013", CREDS_DARRYL, KRBTGT, "DCSync as svc_darryl -> dump krbtgt + all hashes",
        "vuln_cred_access/acl_rights.yml"),
    # michael.scott: Kerberoastable (SPN HTTP/mgmt.corp.local), pw WorldsBestBoss1!
    # is in the wordlist -> any sprayed domain user can roast + crack it.
    ("CRED-001b", USER_ANY, CREDS_MICHAEL, "Kerberoast michael.scott (SPN) -> crack WorldsBestBoss1!",
        "ad_domain/users.yml ($spns michael.scott) + wordlists"),
    # michael.scott holds GenericAll on the domain NC (LAT-021) -> grant self
    # DCSync / DA, run DCShadow (CRED-015), or ExtraSID inject (DF-007).
    ("LAT-021/CRED-015/DF-007", CREDS_MICHAEL, DA_CORP,
        "michael.scott GenericAll on domain NC -> DCSync/DCShadow/ExtraSID -> DA",
        "vuln_lateral/acl.yml + vuln_cred_access/services.yml + vuln_forest/main.yml"),
    # developer2 password (DVADlab2024!) is in the wordlist -> reachable by full
    # credential spray; then GenericWrite on Enterprise Admins.
    ("spray-wide", USER_ANY, CREDS_DEVELOPER2, "Spray full wordlist -> developer2 (DVADlab2024!)",
        "vuln_forest/forest_attacks.yml + wordlists"),
    ("DF-001", KRBTGT, DA_CORP, "Golden Ticket with krbtgt hash -> DA",
        "vuln_forest/* (krbtgt material)"),
    # developer2 -> Enterprise Admins (also implies DA since EA>=DA in root domain)
    ("PE-128", CREDS_DEVELOPER2, EA, "developer2 GenericWrite on Enterprise Admins -> add self -> EA",
        "vuln_privesc/ad_pe.yml"),

    # ── Enterprise Admin (corp.local IS the forest root) ───────────────────────
    ("forest-root", DA_CORP, EA, "corp.local is its own forest root: DA in root domain == Enterprise Admin",
        "ad_domain (corp.local = forest root)"),

    # ── cross-forest: SID filtering disabled on bidirectional trusts ───────────
    ("DF-008/DF-081", EA, DA_FINANCE, "SID-history injection across corp<->finance (SID filtering off)",
        "ad_trust/main.yml (SIDFilteringQuarantined=false) + vuln_forest/trust_abuse.yml"),
    ("DF-008/DF-081", EA, DA_ROOT, "SID-history / inter-realm TGT across corp<->root (forest trust, filtering off)",
        "ad_trust/main.yml + vuln_forest/trust_abuse.yml"),
    # also reachable directly from corp DA via golden inter-realm ticket
    ("DF-006/DF-100", KRBTGT, DA_FINANCE, "Forged inter-realm TGT (trust key) corp->finance",
        "ad_trust/main.yml + vuln_forest/forest_attacks.yml"),
]

# ─── Milestones the checker must prove reachable ───────────────────────────────
MILESTONES = [
    (ADMIN_FILE01, "Local admin on file01"),
    (ADMIN_SQL01,  "Local admin on sql01"),
    (ADMIN_WS01,   "Local admin on ws01"),
    (ADMIN_CA01,   "Local admin on ca01 (ADCS)"),
    (DA_CORP,      "Domain Admin in corp.local"),
    (EA,           "Enterprise Admin (corp forest root)"),
    (DA_FINANCE,   "Domain Admin in finance.local (via trust)"),
    (DA_ROOT,      "Domain Admin in root.corp (via trust)"),
]

# ─── Known discrepancies discovered while deriving the graph ───────────────────
# Each entry: (id, kind, detail). kind in {dangling, undocumented, weak-prereq}.
#   dangling     = PLAN/role references it but nothing makes it practically usable
#   weak-prereq  = the prereq credential exists but is not reachable from a foothold
#   undocumented = role injects surface PLAN.md never catalogs
DANGLING = [
    # NOTE: michael.scott IS created (ad_domain/users.yml loop). The earlier
    # "never created" finding was a false positive. Acquisition was the real gap
    # and is now fixed: michael.scott has an SPN (Kerberoastable) and its password
    # WorldsBestBoss1! is in the wordlist -> LAT-021/CRED-015/DF-007 reachable.
    # svc_darryl (CRED-013) reachable via the SYSVOL plaintext creds (REC-015,
    # password now matches). developer2 (PE-128) reachable via full-wordlist spray.
    ("SRV-*/IA-051..065/PE-081..130/LAT-036..095/CRED-066..130/WEB-*",
     "undocumented",
     "Roles inject large extended ranges (SRV-001..066 SCCM/MSSQL, WEB-000..070 "
     "web apps, and extended IA/PE/LAT/CRED/DF blocks) that PLAN.md's matrix "
     "does not individually catalog. PLAN tops out around IA-050/PE-060/DF-040; "
     "roles go well beyond. Surface exists but is undocumented for players."),
]
