#!/bin/bash
set -euo pipefail

SCANNER="axios-rat-scan"
PASS=0
FAIL=0
TOTAL=0

check() {
    local desc="$1" pattern="$2" json="$3"
    TOTAL=$((TOTAL + 1))
    if echo "$json" | grep -q "$pattern"; then
        printf "  \033[32m\u2713\033[0m %s\n" "$desc"
        PASS=$((PASS + 1))
    else
        printf "  \033[31m\u2717\033[0m %s\n" "$desc"
        FAIL=$((FAIL + 1))
    fi
}

check_absent() {
    local desc="$1" pattern="$2" json="$3"
    TOTAL=$((TOTAL + 1))
    if echo "$json" | grep -q "$pattern"; then
        printf "  \033[31m\u2717\033[0m %s (unexpected match)\n" "$desc"
        FAIL=$((FAIL + 1))
    else
        printf "  \033[32m\u2713\033[0m %s\n" "$desc"
        PASS=$((PASS + 1))
    fi
}

count_matches() {
    echo "$1" | grep -o "$2" | wc -l
}

echo ""
echo -e "\033[1m\033[36m"
echo "  ============================================="
echo "  axios-rat-scan integration tests"
echo "  realistic environment: ~100 projects, 4 infected"
echo "  ============================================="
echo -e "\033[0m"

# ── Full scan with tree + progress (visual) ─────────────────
echo -e "\033[1m  Visual scan output\033[0m"
echo "  ────────────────────────────────────────"
echo ""
"$SCANNER" --no-process /projects 2>&1 || true
echo ""

# ── JSON scan for assertions ────────────────────────────────
RESULT=$("$SCANNER" --json --no-process /projects 2>/dev/null || true)

echo ""
echo -e "\033[1m  Host artifact detection (Linux)\033[0m"
echo "  ────────────────────────────────────────"
check "Detects /tmp/ld.py RAT payload" "rat-artifact" "$RESULT"
check "Detects /tmp/6202033 dropper artifact" "dropper-artifact" "$RESULT"

echo ""
echo -e "\033[1m  Infected project #1: acme-corp/notification-service\033[0m"
echo "  ────────────────────────────────────────"
check "axios@1.14.1 in deps" "compromised-axios" "$RESULT"
check "plain-crypto-js in deps" "malicious-dep" "$RESULT"
check "postinstall hook (setup.js)" "malicious-hook" "$RESULT"
check "axios@1.14.1 pinned in lockfile" "locked-compromised-axios" "$RESULT"
check "plain-crypto-js in lockfile" "locked-malicious-dep" "$RESULT"
check "installed plain-crypto-js" "installed-malicious-pkg" "$RESULT"
check "setup.js dropper on disk" "active-dropper" "$RESULT"
check "compromised axios installed" "installed-compromised-axios" "$RESULT"
check "injected dep in axios" "axios-injected-dep" "$RESULT"

echo ""
echo -e "\033[1m  Infected project #2: electron-apps/internal-dashboard (legacy 0.30.4)\033[0m"
echo "  ────────────────────────────────────────"
check "axios@0.30.4 detected" "0.30.4" "$RESULT"
check "@shadanai/openclaw detected" "installed-secondary-vector" "$RESULT"

echo ""
echo -e "\033[1m  Infected project #3: clients/kilo (secondary vector)\033[0m"
echo "  ────────────────────────────────────────"
check "@qqbrowser/openclaw-qbot detected" "openclaw-qbot" "$RESULT"
check "axios@1.14.1 in kilo lockfile" "locked-compromised-axios" "$RESULT"

echo ""
echo -e "\033[1m  Infected project #4: infra/ci-runner-cache\033[0m"
echo "  ────────────────────────────────────────"
check "Stale compromised axios in CI cache" "ci-runner-cache" "$RESULT"

echo ""
echo -e "\033[1m  False positive checks\033[0m"
echo "  ────────────────────────────────────────"
# Remove host artifacts, scan only clean projects
rm -f /tmp/ld.py /tmp/6202033
CLEAN_RESULT=$("$SCANNER" --json --no-process /projects/acme-corp/packages/shared-lib-1 2>/dev/null || true)
check_absent "Clean shared-lib produces no findings" "CRITICAL" "$CLEAN_RESULT"

CLEAN_RESULT2=$("$SCANNER" --json --no-process /projects/oss/react-hooks 2>/dev/null || true)
check_absent "Clean OSS project produces no findings" "CRITICAL" "$CLEAN_RESULT2"

CLEAN_RESULT3=$("$SCANNER" --json --no-process /projects/tools/data-pipeline 2>/dev/null || true)
check_absent "Clean tool produces no findings" "CRITICAL" "$CLEAN_RESULT3"

echo ""
echo -e "\033[1m  Exit codes\033[0m"
echo "  ────────────────────────────────────────"
TOTAL=$((TOTAL + 1))
"$SCANNER" --json --no-process /projects/oss/react-hooks > /dev/null 2>&1
if [ $? -eq 0 ]; then
    printf "  \033[32m\u2713\033[0m Clean scan exits 0\n"
    PASS=$((PASS + 1))
else
    printf "  \033[31m\u2717\033[0m Clean scan should exit 0\n"
    FAIL=$((FAIL + 1))
fi

TOTAL=$((TOTAL + 1))
set +e
"$SCANNER" --json --no-process /projects/acme-corp/apps/notification-service > /dev/null 2>&1
INFECTED_EXIT=$?
set -e
if [ "$INFECTED_EXIT" -eq 1 ]; then
    printf "  \033[32m\u2713\033[0m Infected scan exits 1\n"
    PASS=$((PASS + 1))
else
    printf "  \033[31m\u2717\033[0m Infected scan exited %d (expected 1)\n" "$INFECTED_EXIT"
    FAIL=$((FAIL + 1))
fi

# ── Counting ────────────────────────────────────────────────
echo ""
echo -e "\033[1m  Scale validation\033[0m"
echo "  ────────────────────────────────────────"
TOTAL_PROJECTS=$(echo "$RESULT" | python3 -c "
import sys, json
data = json.load(sys.stdin)
# Handle both flat array and metadata-wrapped output
findings = data.get('findings', data) if isinstance(data, dict) else data
print(len(findings))
" 2>/dev/null || echo "0")
TOTAL=$((TOTAL + 1))
if [ "$TOTAL_PROJECTS" -gt 15 ]; then
    printf "  \033[32m\u2713\033[0m Generated %s findings across infected projects\n" "$TOTAL_PROJECTS"
    PASS=$((PASS + 1))
else
    printf "  \033[31m\u2717\033[0m Only %s findings (expected >15 across 4 infected projects)\n" "$TOTAL_PROJECTS"
    FAIL=$((FAIL + 1))
fi

# ── Summary ─────────────────────────────────────────────────
echo ""
echo -e "\033[1m\033[36m"
echo "  ============================================="
if [ "$FAIL" -eq 0 ]; then
    printf "  \033[32mALL %d TESTS PASSED\033[36m\n" "$TOTAL"
else
    printf "  \033[31m%d/%d TESTS FAILED\033[36m\n" "$FAIL" "$TOTAL"
fi
echo "  ============================================="
echo -e "\033[0m"

# ── GIF recording (if /output is mounted) ──────────────────
if [ -d /output ] && command -v vhs &> /dev/null; then
    echo -e "\033[1m  Recording demo GIF...\033[0m"
    # Re-plant artifacts for the recording
    echo '#!/usr/bin/env python3' > /tmp/ld.py
    echo 'dropper-payload' > /tmp/6202033
    vhs /demo.tape 2>&1 || true
    if [ -f /output/test.gif ]; then
        # Optimize GIF size
        if command -v gifsicle &> /dev/null; then
            gifsicle -O3 --lossy=80 /output/test.gif -o /output/test.gif 2>/dev/null || true
        fi
        SIZE=$(ls -lh /output/test.gif | awk '{print $5}')
        echo -e "  \033[32m\u2713\033[0m Saved to /output/test.gif ($SIZE)\n"
    else
        echo -e "  \033[33m! GIF recording skipped (VHS needs chromium in container)\033[0m\n"
    fi
fi

exit "$FAIL"
