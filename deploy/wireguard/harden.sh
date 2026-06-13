#!/usr/bin/env bash
# ==============================================================================
# harden.sh — minimal firewalling for exposing the EMPIRE lab over WireGuard.
# Run on the VPS AFTER `docker compose up -d`. Idempotent-ish (ufw add is safe;
# iptables rules are appended once-ish — re-running duplicates, harmless).
#
#   sudo ADMIN_IP=1.2.3.4 ./harden.sh
#
# Addresses the 3 real risks (host takeover via 10.10.0.1, egress abuse that
# gets the VPS terminated, cross-player traffic). See README.md.
# ==============================================================================
set -euo pipefail

: "${ADMIN_IP:?set ADMIN_IP=<your.admin.ip> — the IP allowed to reach SSH + wg-easy UI}"
LAB_NET="10.10.0.0/16"
LAB_GW="10.10.0.1"
WG_PORT="51820"
UI_PORT="51821"

echo "[*] Admin IP: ${ADMIN_IP}"

# --- 1. Firewall: WG port open to world; SSH + UI only to admin --------------
if command -v ufw >/dev/null; then
  ufw allow "${WG_PORT}/udp"
  ufw allow from "${ADMIN_IP}" to any port 22 proto tcp
  ufw allow from "${ADMIN_IP}" to any port "${UI_PORT}" proto tcp
  echo "[+] ufw: ${WG_PORT}/udp open; 22 + ${UI_PORT} restricted to ${ADMIN_IP}"
else
  echo "[!] ufw not found — restrict 22 and ${UI_PORT} to ${ADMIN_IP} manually."
fi

# --- 2. Block lab VMs from attacking the host itself (10.10.0.1) -------------
#     Lab is RCE-by-design; stop a popped box reaching host SSH / wg UI / Docker.
iptables -C INPUT -i empire-ctf -d "${LAB_GW}" -p tcp -m multiport --dports 22,2375,2376,"${UI_PORT}" -j DROP 2>/dev/null \
  || iptables -A INPUT -i empire-ctf -d "${LAB_GW}" -p tcp -m multiport --dports 22,2375,2376,"${UI_PORT}" -j DROP
echo "[+] Lab → host services (22/2375/2376/${UI_PORT}) dropped"

# --- 3. Peer isolation: players cannot attack each other's tunnel IPs --------
iptables -C FORWARD -i wg0 -o wg0 -j DROP 2>/dev/null \
  || iptables -A FORWARD -i wg0 -o wg0 -j DROP
echo "[+] wg0↔wg0 peer isolation enabled"

# --- 4. Egress lockdown: lab may resolve DNS but NOT use VPS as attack origin -
#     network-setup.sh masquerades 10.10.0.0/16 to the internet. Drop forwarded
#     lab→internet traffic except DNS so a popped box can't launch attacks /
#     get the VPS terminated by the provider. Comment out if you want updates.
out_iface="$(ip route show default | awk '/default/ {print $5; exit}')"
if [[ -n "${out_iface}" ]]; then
  # allow DNS out
  iptables -C FORWARD -s "${LAB_NET}" -o "${out_iface}" -p udp --dport 53 -j ACCEPT 2>/dev/null \
    || iptables -I FORWARD -s "${LAB_NET}" -o "${out_iface}" -p udp --dport 53 -j ACCEPT
  iptables -C FORWARD -s "${LAB_NET}" -o "${out_iface}" -p tcp --dport 53 -j ACCEPT 2>/dev/null \
    || iptables -I FORWARD -s "${LAB_NET}" -o "${out_iface}" -p tcp --dport 53 -j ACCEPT
  # drop everything else lab→internet
  iptables -C FORWARD -s "${LAB_NET}" -o "${out_iface}" -j DROP 2>/dev/null \
    || iptables -A FORWARD -s "${LAB_NET}" -o "${out_iface}" -j DROP
  echo "[+] Lab→internet egress dropped (DNS allowed) via ${out_iface}"
else
  echo "[!] Could not detect default iface — egress lockdown skipped."
fi

echo "[*] Done. Verify: sudo iptables -L FORWARD -n --line-numbers"
