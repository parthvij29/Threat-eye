#!/bin/bash
# System Monitoring Script

echo "=== System Monitor ==="
echo "1) Running Processes"
echo "2) CPU and Memory Usage"
echo "3) Top 5 Processes by CPU"
echo "4) Startup Services"

# Accept an option as first CLI argument for non-interactive use
if [ -n "$1" ]; then
    choice=$1
else
    echo "Choose an option: "
    read choice
fi

case $choice in
    1)
        echo "[*] Running Processes"
        ps aux --sort=-%mem | head -20
        ;;
    2)
        echo "[*] CPU and Memory Usage"
        top -bn1 | head -n 10
        ;;
    3)
        echo "[*] Top 5 Processes by CPU"
        # Print header then top 5 lines (PID, %CPU, CMD)
        printf "%s\n" "PID %CPU CMD"
        ps -eo pid,%cpu,cmd --sort=-%cpu | head -n 6
        ;;
    4)
        echo "[*] Startup Services"
        systemctl list-unit-files --type=service | grep enabled
        ;;
    *)
        echo "Invalid option!"
        ;;
esac
