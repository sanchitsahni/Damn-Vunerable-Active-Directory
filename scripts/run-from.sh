#!/usr/bin/env bash
# ==============================================================================
# run-from.sh — run the Ansible site.yml FROM a given phase to the end.
# Skips every already-done phase, so debug iterations are fast.
#
#   scripts/run-from.sh 8b                         # phases 8b -> 20
#   scripts/run-from.sh 9  --limit endor.empire.local
#   scripts/run-from.sh 10 -v
#   scripts/run-from.sh only 8b --limit scarif...  # 'only' = just that one phase
#
# Any extra args (--limit, -v, --check, ...) are passed straight to ansible.
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")/../ansible"

# Ordered phases (as they run in site.yml) -> their tag.
phases=(1   2      5         6      7    8         8b        9       10           11       13       14       16       17             18                      19               20)
tags=(phase1 phase2 phase5 phase6 phase7 phase8 vuln_adcs phase9 phase10 phase11 phase13 phase14 phase16 phase17 phase18 phase19 phase20)

usage() { echo "usage: $0 [only] <phase>  (valid: ${phases[*]})  [extra ansible args]"; exit 1; }
[ $# -ge 1 ] || usage

mode="range"
if [ "$1" = "only" ]; then mode="only"; shift; fi
[ $# -ge 1 ] || usage
start="$1"; shift || true

idx=-1
for i in "${!phases[@]}"; do [ "${phases[$i]}" = "$start" ] && idx=$i && break; done
[ "$idx" -ge 0 ] || { echo "unknown phase: $start"; usage; }

if [ "$mode" = "only" ]; then
    sel="${tags[$idx]}"
    echo "[*] Running ONLY phase ${start} (tag: ${sel})"
else
    sel="$(IFS=,; echo "${tags[*]:$idx}")"
    echo "[*] Running phases ${start} -> end (tags: ${sel})"
fi

exec ansible-playbook -i inventory.yml playbooks/site.yml --tags "${sel}" "$@"
