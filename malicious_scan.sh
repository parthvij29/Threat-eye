#!/bin/bash
# Lightweight malicious activity scanner (heuristic)

echo "=== Malicious Activity Scan (heuristic) ==="

echo "[1] World-writable files (top 10):"
find / -xdev -type f -perm -0002 2>/dev/null | head -n 10 || echo "No results or permission denied"

echo "\n[2] SUID/SGID files (top 10):"
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -n 10 || echo "No results or permission denied"

echo "\n[3] Executables in /tmp (top 10):"
find /tmp -type f -executable 2>/dev/null | head -n 10 || echo "No results"

echo "\n[4] Recent suspicious writable files in /etc (modified in last 7 days):"
find /etc -type f -mtime -7 2>/dev/null | head -n 20 || echo "No recent modifications or permission denied"

echo "\n[5] Suspicious cron entries (system & user):"
grep -R "wget\|curl\|nc\|bash -i\|/dev/tcp" /etc/cron* 2>/dev/null || echo "None found or permission denied"

echo "\n[6] Suspicious network listeners on uncommon ports (1337,4444,5555,6666):"
ss -tulwn | egrep '(:1337|:4444|:5555|:6666)' || echo "None detected"

echo "\nScan complete. This is heuristic; investigate any positives manually."
