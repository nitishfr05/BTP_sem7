#!/bin/bash
# ==============================================================================
# Helper to package Zeek and Suricata logs into a single archive for export
# ==============================================================================

EXPORT_DIR=~/btp_exported_logs_$(date +%Y%m%d_%H%M%S)
mkdir -p "$EXPORT_DIR"

echo "[*] Collecting Zeek JSON logs..."
cp /opt/zeek/logs/current/*.log "$EXPORT_DIR/" 2>/dev/null || true

echo "[*] Collecting Suricata EVE logs..."
cp /var/log/suricata/eve.json "$EXPORT_DIR/" 2>/dev/null || true

tar -czvf "${EXPORT_DIR}.tar.gz" -C "$EXPORT_DIR" .
echo "[+] Logs exported to: ${EXPORT_DIR}.tar.gz"
echo "You can transfer this file to your Windows host via scp or shared folder."
