#!/bin/bash

echo "=== File Inspection Tool ==="

# Accept file path as first arg for non-interactive use
if [ -n "$1" ]; then
    filepath=$1
else
    echo "Enter file path:"
    read filepath
fi

if [ -f "$filepath" ]; then
    echo "File: $filepath"
    echo "Type: $(file "$filepath")"
    echo "Size: $(du -h "$filepath" | cut -f1)"
    echo "Permissions: $(ls -l "$filepath" | awk '{print $1}')"
    echo "Owner: $(stat -c %U "$filepath")"
    echo "SHA256: $(sha256sum "$filepath" | awk '{print $1}')"

    # Quick heuristic checks for suspicious/malicious indicators
    echo "\n[+] Heuristic checks:" 

    # Is the file executable?
    if [ -x "$filepath" ]; then
        echo "- Executable: Yes"
    else
        echo "- Executable: No"
    fi

    # Check for suspicious strings in the file (e.g., reverse shells, downloads)
    suspicious_patterns=("/bin/bash -i" "bash -i" "nc -e" "/dev/tcp" "curl " "wget " "python -c" "perl -e" "bash -c")
    found=0
    for p in "${suspicious_patterns[@]}"; do
        if strings "$filepath" 2>/dev/null | grep -i -q -- "$p"; then
            echo "- Suspicious pattern found: $p"
            found=1
        fi
    done
    if [ $found -eq 0 ]; then
        echo "- Suspicious pattern found: None"
    fi

    # Location-based heuristics
    if [[ "$filepath" == /tmp/* || "$filepath" == /var/tmp/* ]]; then
        echo "- Location: Temporary folder (higher risk)"
    fi

    # Check if ELF binary and extract symbols (basic)
    if file "$filepath" | grep -i -q elf; then
        echo "- ELF binary: Yes"
        echo "- LDD (shared libs) preview:" 
        ldd "$filepath" 2>/dev/null | sed -n '1,10p'
    fi

else
    echo "File not found!"
fi
