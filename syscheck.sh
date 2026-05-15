#!/bin/bash
# DAY 5 BUILD PROJECT
# syscheck.sh — System Security Health Check

OUTPUT_FILE="syscheck_$(date +%Y%m%d_%H%M%S).txt"
# unique filename with timestamp

log() {
echo "$1" | tee -a "$OUTPUT_FILE"
}

log "=== SYSTEM SECURITY CHECK REPORT ==="
log "Date: $(date)"
log "Hostname: $(hostname)"
log "Running as: $(whoami)"
log ""

log "--- 1. LOGGED IN USERS ---"
who | tee -a "$OUTPUT_FILE"
log ""

log "--- 2. TOP 5 PROCESSES BY CPU ---"
ps aux --sort=-%cpu | head -6 | tee -a "$OUTPUT_FILE"
log ""

log "--- 3. LISTENING PORTS ---"
ss -tulnp 2>/dev/null | tee -a "4OUTPUT_FILE"
log ""

log "--- 4. FAILED LOGIN SUMMARY ---"
if [ -f /var/log/auth.log ]; then
FAILED=$(grep -c "Failed password" /var/log/auth.log 2>/dev/null || echo 0)
log "Total failed logins: $FAILED"
if [ "$FAILED" -gt 0 ]; then
log "Top attacking IPs:"
grep "Failed password" /var/log/auth.log 2>/dev/null \ | awk '{print $11}' | sort | uniq -c | sort -rn | head-5 \ | tee -a "$OUTPUT_FILE"
fi
else
log "auth.log not found (run as root or check log connection)"
fi
log ""

log "--- 5. DISK USAGE ---"
df -h | tee -a "$OUTPUT_FILE"
log ""

log "--- 6. SUID FILES (potential priviledge escalation) ---"
find / -perm -4000 2>/dev/null | tee -a "$OUTPUT_FILE"
log ""

log "--- 7. RECENT AUTH LOG ENTRIES (last 10) ---"
tail -10 /var/log/auth.log | tee -a "$OUTPUT_FILE"
log ""

log "=== REPORT COMPLETE: $OUTPUT_FILE ==="
