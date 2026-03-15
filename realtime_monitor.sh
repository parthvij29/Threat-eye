#!/bin/bash
# Real-Time Monitoring Script

echo "=== Real-Time Monitoring Started ==="
echo "Press Ctrl+C to stop."

while true; do
    echo "---- $(date) ----"

    # Check suspicious world-writable files
    echo "[*] World-writable files (possible risk):"
    find / -type f -perm -0002 2>/dev/null | head -n 5

    # Check open suspicious ports
    echo "[*] Suspicious open ports:"
    ss -tulwn | egrep '(:1337|:4444|:5555|:6666)' || echo "None detected"

    # Check processes with high CPU usage
    echo "[*] High CPU processes:"
    ps -eo pid,ppid,cmd,%cpu --sort=-%cpu | head -n 6

    # Check executable files in /tmp (common malware trick)
    echo "[*] Executables in /tmp:"
    find /tmp -type f -executable 2>/dev/null | head -n 5

    echo "--------------------------"
    sleep 5
done
