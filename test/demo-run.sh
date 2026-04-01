#!/bin/bash
# Slow-feed scanner output so VHS captures each line as a visible frame
# Pauses after tree section so viewer can see discovered projects
OUTPUT=$(axios-rat-scan --no-process /projects 2>&1)

IN_TREE=false
TREE_DONE=false

IFS=$'\n'
for line in $OUTPUT; do
    echo "$line"

    # Detect tree section
    if echo "$line" | grep -q "npm/node project tree"; then
        IN_TREE=true
    fi

    # Detect end of tree (IOC scan header or separator line)
    if $IN_TREE && echo "$line" | grep -q "IOC scan"; then
        IN_TREE=false
        TREE_DONE=true
        sleep 3
    fi

    sleep 0.04
done
