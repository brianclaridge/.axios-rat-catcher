#!/bin/bash
# Demo: replay scanner output line-by-line with pauses at key moments.

OUTPUT=$(axios-rat-scan --no-process /projects 2>&1)

SECTION="pre"
IFS=$'\n'
for line in $OUTPUT; do
    echo "$line"

    if echo "$line" | grep -q "npm/node project tree"; then
        SECTION="tree"
    fi

    # Pause after tree, before IOC scan
    if [ "$SECTION" = "tree" ] && echo "$line" | grep -q "IOC scan"; then
        sleep 2
        SECTION="scan"
        continue
    fi

    # Pause before first finding
    if [ "$SECTION" = "scan" ] && echo "$line" | grep -q "CRITICAL"; then
        sleep 1
        SECTION="findings"
    fi

    # Pause before summary
    if echo "$line" | grep -q "^===="; then
        sleep 2
    fi

    sleep 0.02
done

sleep 4
