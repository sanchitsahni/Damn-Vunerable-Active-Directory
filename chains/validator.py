#!/usr/bin/env python3
# ==============================================================================
# validator.py — EMPIRE / DVAD attack-combination checker.
#
# Validates that EVERY intended milestone in the lab is PRACTICALLY reachable
# end-to-end from the initial-access footholds the lab actually provides — not
# just theoretically catalogued in PLAN.md.
#
# The attack graph it analyses lives in chains/attack_graph.py and is derived
# directly from the ansible vuln_* roles (ground truth), cross-checked against
# PLAN.md. This file is pure graph logic + reporting; the data is separate.
#
# Two modes:
#   STATIC (default) — offline. Reads the graph, runs reachability, reports.
#                      Needs no live hosts; runs anywhere.
#   LIVE   (--live)  — stub only. Structured hook that would probe real hosts
#                      to confirm each edge's prereq service is up. No network
#                      calls are implemented; it falls back to static + warns.
#
# Usage:
#   python3 chains/validator.py                 # static reachability report
#   python3 chains/validator.py --json          # machine-readable output
#   python3 chains/validator.py --list-edges    # dump the derived graph
#   python3 chains/validator.py --live          # (stub) live-probe scaffold
#   python3 chains/validator.py --no-color      # plain text
#
# Stdlib only. Graph traversal implemented by hand. py_compile clean.
# ==============================================================================

import sys
assert sys.version_info >= (3, 6), "Python 3.6+ required"

import argparse
import json
import os
from collections import defaultdict

# attack_graph.py sits next to this file.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import attack_graph as G  # noqa: E402


# ─── Colour helpers ────────────────────────────────────────────────────────────
class C:
    def __init__(self, enabled):
        if enabled:
            self.RED = "\033[31m"; self.GRN = "\033[32m"; self.YLW = "\033[33m"
            self.BLU = "\033[34m"; self.CYN = "\033[36m"
            self.BLD = "\033[1m"; self.DIM = "\033[2m"; self.RST = "\033[0m"
        else:
            self.RED = self.GRN = self.YLW = self.BLU = self.CYN = ""
            self.BLD = self.DIM = self.RST = ""


# ─── Graph model ───────────────────────────────────────────────────────────────
class AttackGraph:
    """Directed multigraph of access states. Built from attack_graph.py data."""

    def __init__(self):
        # adjacency: src -> list of edge dicts
        self.adj = defaultdict(list)
        self.all_edges = []
        self.nodes = set()

        # Foothold edges originate from the ANON node.
        for eid, dst, label, src in G.FOOTHOLDS:
            self._add(G.ANON, dst, eid, label, src, foothold=True)
        for eid, s, d, label, src in G.EDGES:
            self._add(s, d, eid, label, src, foothold=False)

    def _add(self, s, d, eid, label, src, foothold):
        edge = {"id": eid, "src": s, "dst": d, "label": label,
                "source": src, "foothold": foothold}
        self.adj[s].append(edge)
        self.all_edges.append(edge)
        self.nodes.add(s)
        self.nodes.add(d)

    def reachable(self, start):
        """Worklist forward reachability. Returns set of reachable nodes."""
        seen = {start}
        work = [start]
        while work:
            n = work.pop()
            for e in self.adj.get(n, []):
                if e["dst"] not in seen:
                    seen.add(e["dst"])
                    work.append(e["dst"])
        return seen

    def shortest_path(self, start, goal):
        """BFS shortest edge-path start->goal. Returns list of edges or None."""
        if start == goal:
            return []
        from collections import deque
        q = deque([(start, [])])
        seen = {start}
        while q:
            node, path = q.popleft()
            for e in self.adj.get(node, []):
                if e["dst"] in seen:
                    continue
                npath = path + [e]
                if e["dst"] == goal:
                    return npath
                seen.add(e["dst"])
                q.append((e["dst"], npath))
        return None

    def edges_into(self, goal):
        return [e for e in self.all_edges if e["dst"] == goal]


# ─── Live-probe stub (intentionally inert) ─────────────────────────────────────
def live_probe(edge):
    """
    LIVE-mode hook. In a future implementation this would test whether the
    service backing `edge` is actually answering on the real host (e.g. tcp
    connect to the CA's 80/443 for ESC8, 1433 for the MSSQL foothold, 88 for
    Kerberoast). Structured here so the traversal can call it per-edge.

    Returns (probed: bool, ok: bool, detail: str). Currently always
    (False, True, "stub") so live mode degrades to static without ever
    touching the network.
    """
    return (False, True, "live probe not implemented — static result used")


# ─── Reporting ─────────────────────────────────────────────────────────────────
def fmt_path(c, edges):
    """Render foothold -> t1 -> ... -> goal."""
    if not edges:
        return "(already held)"
    parts = [edges[0]["src"]]
    for e in edges:
        parts.append(f"--[{e['id']}]-->")
        parts.append(e["dst"])
    return " ".join(parts)


def run(args):
    c = C(enabled=not args.no_color and sys.stdout.isatty() and not args.json)
    graph = AttackGraph()

    if args.list_edges:
        list_edges(graph, c)
        return 0

    reachable = graph.reachable(G.ANON)

    results = []
    for node, desc in G.MILESTONES:
        path = graph.shortest_path(G.ANON, node)
        ok = node in reachable and path is not None
        missing = None
        if not ok:
            missing = diagnose_unreachable(graph, node, reachable)
        results.append({
            "milestone": desc, "node": node, "reachable": ok,
            "path": path, "missing": missing,
        })

    if args.json:
        emit_json(graph, results)
        return 0 if all(r["reachable"] for r in results) else 1

    return emit_text(c, graph, results, args)


def diagnose_unreachable(graph, node, reachable):
    """Find which prerequisite is missing: list edges into `node` and report
    the source states that are themselves unreachable."""
    feeders = graph.edges_into(node)
    if not feeders:
        return "no technique edge targets this state at all (orphaned objective)"
    blocked = []
    for e in feeders:
        if e["src"] not in reachable:
            blocked.append(f"needs '{e['src']}' (via {e['id']}) — itself unreachable")
        else:
            blocked.append(f"edge {e['id']} from reachable '{e['src']}' exists but goal still unreached")
    return "; ".join(blocked)


def list_edges(graph, c):
    print(f"{c.BLD}Derived attack graph — {len(graph.all_edges)} edges, "
          f"{len(graph.nodes)} states{c.RST}\n")
    print(f"{c.CYN}Footholds (from {G.ANON}):{c.RST}")
    for e in graph.all_edges:
        if e["foothold"]:
            print(f"  [{e['id']:<18}] {e['dst']:<28} {e['label']}")
    print(f"\n{c.CYN}Transitions:{c.RST}")
    for e in graph.all_edges:
        if not e["foothold"]:
            print(f"  [{e['id']:<18}] {e['src']:<26} -> {e['dst']:<26} {e['label']}")


def emit_text(c, graph, results, args):
    print(f"\n{c.BLD}{'='*74}{c.RST}")
    print(f"{c.BLD} EMPIRE / DVAD — Attack-Combination Reachability Checker (STATIC){c.RST}")
    print(f"{c.BLD}{'='*74}{c.RST}")
    print(f"  Graph:     {len(graph.all_edges)} edges / {len(graph.nodes)} access-states "
          f"(derived from ansible vuln_* roles)")
    foothold_dsts = sorted({e['dst'] for e in graph.all_edges if e['foothold']})
    print(f"  Footholds: {len(foothold_dsts)} entry states from '{G.ANON}'")
    if args.live:
        print(f"  {c.YLW}LIVE mode requested — probe stub is inert; "
              f"showing STATIC results.{c.RST}")

    n_ok = sum(1 for r in results if r["reachable"])
    print(f"\n{c.BLD}Milestones ({n_ok}/{len(results)} reachable):{c.RST}\n")

    for r in results:
        if r["reachable"]:
            tag = f"{c.GRN}REACHABLE  {c.RST}"
        else:
            tag = f"{c.RED}UNREACHABLE{c.RST}"
        print(f"  [{tag}] {c.BLD}{r['milestone']}{c.RST}  ({r['node']})")
        if r["reachable"]:
            print(f"      {c.DIM}path:{c.RST} {fmt_path(c, r['path'])}")
            # show the human-readable technique chain
            for e in r["path"]:
                probed, pok, detail = (live_probe(e) if args.live else (False, True, ""))
                mark = ""
                if args.live and probed:
                    mark = f" {c.GRN}[live OK]{c.RST}" if pok else f" {c.RED}[live FAIL]{c.RST}"
                src = f"  {c.DIM}<{e['source']}>{c.RST}" if e["source"] else ""
                print(f"         - [{e['id']}] {e['label']}{mark}{src}")
        else:
            print(f"      {c.RED}missing prereq:{c.RST} {r['missing']}")
        print()

    # ── Discrepancy report (the key finding) ───────────────────────────────────
    print(f"{c.BLD}{'-'*74}{c.RST}")
    print(f"{c.BLD} Dangling / unreachable techniques & doc drift "
          f"(role-vs-PLAN cross-check){c.RST}")
    print(f"{c.BLD}{'-'*74}{c.RST}")
    kinds = {
        "dangling":     (c.RED, "DANGLING   "),
        "weak-prereq":  (c.YLW, "WEAK-PREREQ"),
        "undocumented": (c.BLU, "UNDOCUMENTED"),
    }
    for eid, kind, detail in G.DANGLING:
        col, lab = kinds.get(kind, (c.RST, kind.upper()))
        print(f"\n  [{col}{lab}{c.RST}] {c.BLD}{eid}{c.RST}")
        # wrap detail
        for line in _wrap(detail, 66):
            print(f"      {line}")

    # ── Summary ────────────────────────────────────────────────────────────────
    n_dangling = sum(1 for _, k, _ in G.DANGLING if k == "dangling")
    n_weak = sum(1 for _, k, _ in G.DANGLING if k == "weak-prereq")
    n_undoc = sum(1 for _, k, _ in G.DANGLING if k == "undocumented")
    print(f"\n{c.BLD}{'='*74}{c.RST}")
    print(f"{c.BLD} Summary{c.RST}")
    print(f"{c.BLD}{'='*74}{c.RST}")
    print(f"  Milestones reachable:        {c.GRN}{n_ok}{c.RST}/{len(results)}")
    unreached = [r['milestone'] for r in results if not r['reachable']]
    if unreached:
        print(f"  {c.RED}UNREACHABLE milestones:{c.RST}      {', '.join(unreached)}")
    print(f"  Dangling techniques:         {c.RED}{n_dangling}{c.RST}  "
          f"(prereq nothing provides / principal never created)")
    print(f"  Weak-prereq (orphaned edges):{c.YLW}{n_weak}{c.RST}  "
          f"(creds exist but not reachable from a foothold)")
    print(f"  Undocumented surface groups: {c.BLU}{n_undoc}{c.RST}")
    print()

    # Exit non-zero if any milestone is unreachable OR any dangling vuln exists.
    return 0 if (not unreached and n_dangling == 0) else 1


def _wrap(text, width):
    words = text.split()
    lines, cur = [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur)
            cur = w
        else:
            cur = (cur + " " + w).strip()
    if cur:
        lines.append(cur)
    return lines


def emit_json(graph, results):
    out = {
        "graph": {
            "nodes": sorted(graph.nodes),
            "edges": [
                {"id": e["id"], "src": e["src"], "dst": e["dst"],
                 "label": e["label"], "source": e["source"],
                 "foothold": e["foothold"]}
                for e in graph.all_edges
            ],
        },
        "milestones": [
            {
                "milestone": r["milestone"],
                "node": r["node"],
                "reachable": r["reachable"],
                "path": [
                    {"id": e["id"], "from": e["src"], "to": e["dst"],
                     "technique": e["label"]}
                    for e in (r["path"] or [])
                ],
                "missing_prereq": r["missing"],
            }
            for r in results
        ],
        "discrepancies": [
            {"id": eid, "kind": kind, "detail": detail}
            for eid, kind, detail in G.DANGLING
        ],
        "summary": {
            "milestones_total": len(results),
            "milestones_reachable": sum(1 for r in results if r["reachable"]),
            "unreachable": [r["node"] for r in results if not r["reachable"]],
            "dangling": sum(1 for _, k, _ in G.DANGLING if k == "dangling"),
            "weak_prereq": sum(1 for _, k, _ in G.DANGLING if k == "weak-prereq"),
        },
    }
    print(json.dumps(out, indent=2))


def main():
    p = argparse.ArgumentParser(
        description="EMPIRE/DVAD attack-combination reachability checker "
                    "(static graph analysis of the vuln_* roles).")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--live", action="store_true",
                   help="request live-probe mode (stub — degrades to static)")
    p.add_argument("--list-edges", action="store_true",
                   help="print the derived attack graph and exit")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    args = p.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
