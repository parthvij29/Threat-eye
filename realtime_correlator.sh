#!/bin/bash
# Real-time correlator: watches filesystem events (inotifywait) and correlates with network/process activity
# Requires: inotifywait (inotify-tools), lsof, ss

WATCH_PATHS=(/tmp /var/tmp /etc "$HOME")
LOGFILE="/tmp/deep_inspector_correlator.log"

echo "Starting Real-Time Correlator... (logging to $LOGFILE)"
echo "Watching: ${WATCH_PATHS[*]}"

trap 'echo "Correlator shutting down (SIGTERM)" | tee -a "$LOGFILE"; exit 0' TERM INT

if ! command -v inotifywait >/dev/null 2>&1; then
    echo "inotifywait not found. Install inotify-tools (e.g., sudo apt install inotify-tools)" | tee -a "$LOGFILE"
    exit 1
fi

# Run inotifywait in monitor mode, pipe events into loop. When this script receives SIGTERM,
# trap will run and the script will exit; inotifywait will also be terminated when this process exits.
inotifywait -m -r -e create,modify,delete --format '%w%f %e' "${WATCH_PATHS[@]}" 2>/dev/null |
while read -r filepath ev; do
    ts=$(date -Iseconds)
    # Write human-friendly header to logfile
    echo "[$ts] Event: $ev -> $filepath" | tee -a "$LOGFILE";

    # Which processes currently have the file open?
    pids=""
    if command -v lsof >/dev/null 2>&1; then
        lsof_out=$(lsof "$filepath" 2>/dev/null)
        if [ -n "$lsof_out" ]; then
            echo "  [i] lsof entries:" | tee -a "$LOGFILE"
            echo "$lsof_out" | tee -a "$LOGFILE"
            # extract PIDs from lsof output lines (second column is PID)
            pids=$(echo "$lsof_out" | awk 'NR>1{print $2}' | sort -u | paste -sd "," -)
        fi
    fi

    # Snapshot network connections with process info and extract PIDs seen in ss
    net_pids=""
    if command -v ss >/dev/null 2>&1; then
        ss_out=$(ss -tupn 2>/dev/null)
        echo "  [i] ss snapshot:" | tee -a "$LOGFILE"
        echo "$ss_out" | sed -n '1,20p' | tee -a "$LOGFILE"
        # extract pid numbers from patterns like pid=1234,
        net_pids=$(echo "$ss_out" | grep -oP 'pid=\K[0-9]+' | sort -u | paste -sd "," -)
    fi

    # Determine intersection between pids and net_pids
    alert=0
    if [ -n "$pids" ] && [ -n "$net_pids" ]; then
        IFS=',' read -ra APIDS <<< "$pids"
        IFS=',' read -ra NPIDS <<< "$net_pids"
        for a in "${APIDS[@]}"; do
            for n in "${NPIDS[@]}"; do
                if [ "$a" = "$n" ]; then
                    alert=1
                fi
            done
        done
    fi

    # Log alert if any
    if [ "$alert" -eq 1 ]; then
        echo "  [ALERT] File event + network activity detected for PIDs: $pids" | tee -a "$LOGFILE"
    fi

    # Also log a compact CPU snapshot (to logfile only)
    echo "  [i] Top CPU snapshot:" | tee -a "$LOGFILE"
    ps -eo pid,ppid,cmd,%cpu --sort=-%cpu | head -n 6 | tee -a "$LOGFILE"
    echo "---" | tee -a "$LOGFILE"

    # Emit a structured single-line event for UI consumption (tab-separated)
    # Format: CORRELATOR_EVENT	<timestamp>	<event>	<filepath>	<pids>	<net_pids>	<alert>	<summary>
    summary=""
    if [ "$alert" -eq 1 ]; then
        summary="ALERT: process modified file and has network activity"
    elif [ -n "$pids" ]; then
        summary="Process touched file"
    else
        summary="No process hold; file event observed"
    fi

    echo -e "CORRELATOR_EVENT\t$ts\t$ev\t$filepath\t${pids}\t${net_pids}\t${alert}\t${summary}"
done
