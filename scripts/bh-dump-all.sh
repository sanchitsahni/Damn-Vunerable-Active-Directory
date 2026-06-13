#!/usr/bin/env bash
# Dump all EMPIRE lab domains into BloodHound CE zips.
# Usage: ./bh-dump-all.sh   (zips land in ./bh-empire/)
set -euo pipefail

USER="Administrator"
PASS="SithLord123!"
OUT="bh-empire"

# domain : DC-IP (nameserver = that forest's DC)
DOMAINS=(
  "empire.local:10.10.0.10"
  "eu.empire.local:10.10.0.11"
  "rebel.local:10.10.20.10"
  "trade.corp:10.10.30.10"
)

mkdir -p "$OUT" && cd "$OUT"

for entry in "${DOMAINS[@]}"; do
  dom="${entry%%:*}"; ip="${entry##*:}"
  echo "=== collecting $dom via $ip ==="
  uvx --from bloodhound-ce bloodhound-ce-python \
    -u "$USER" -p "$PASS" \
    -d "$dom" -dc "$dom" -ns "$ip" \
    -c All --zip -op "$dom" || echo "!! $dom failed — continuing"
done

echo
echo "done. zips:"
ls -1 *.zip
