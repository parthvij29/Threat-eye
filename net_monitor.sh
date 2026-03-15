#!/bin/bash
# Network Monitoring Script

echo "=== Network Monitor ==="
echo "1) Active Connections"
echo "2) Open Ports"
echo "3) Capture 10 packets (requires sudo)"

# Accept an option as first CLI argument for non-interactive use
if [ -n "$1" ]; then
    choice=$1
else
    echo "Choose an option: "
    read choice
fi

case $choice in
    1)
        echo "[*] Active Network Connections"
        ss -tulwn
        ;;
    2)
        echo "[*] Open Ports"
        lsof -i -P -n | grep LISTEN
        ;;
    3)
        if command -v tcpdump &> /dev/null; then
            echo "[*] Capturing 10 packets..."
            sudo tcpdump -c 10 -i any
        else
            echo "[-] tcpdump not installed. Install with: sudo apt install tcpdump"
        fi
        ;;
    *)
        echo "Invalid option!"
        ;;
esac
