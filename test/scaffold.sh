#!/bin/bash
# Scaffold ~100 realistic npm/node/electron projects with 4 infected among them.
# Mirrors what a dev machine looks like: various workspaces, electron apps,
# libraries, internal tools — and a few that pulled axios during the bad window.

set -e

BASE="/projects"

# Helper: create a clean npm project with optional axios
make_clean() {
    local dir="$1" name="$2" axios_ver="${3:-}" extra_deps="${4:-}"
    mkdir -p "$dir/node_modules/axios" 2>/dev/null || true
    mkdir -p "$dir"

    local deps="{}"
    if [ -n "$axios_ver" ]; then
        mkdir -p "$dir/node_modules/axios"
        echo "{\"name\":\"axios\",\"version\":\"$axios_ver\",\"dependencies\":{\"follow-redirects\":\"^1.15.0\"}}" \
            > "$dir/node_modules/axios/package.json"
        deps="{\"axios\":\"^$axios_ver\"$extra_deps}"
    else
        deps="{\"express\":\"^4.18.0\"$extra_deps}"
    fi

    echo "{\"name\":\"$name\",\"version\":\"1.0.0\",\"dependencies\":$deps}" \
        > "$dir/package.json"

    if [ -n "$axios_ver" ]; then
        echo "{\"name\":\"$name\",\"lockfileVersion\":3,\"packages\":{\"node_modules/axios\":{\"version\":\"$axios_ver\"}}}" \
            > "$dir/package-lock.json"
    fi
}

# ── Org 1: "acme-corp" workspace (30 packages, 1 infected) ─────
for i in $(seq 1 8); do
    make_clean "$BASE/acme-corp/packages/shared-lib-$i" "@acme/shared-lib-$i" "1.14.0"
done
make_clean "$BASE/acme-corp/packages/auth" "@acme/auth" "1.14.0"
make_clean "$BASE/acme-corp/packages/db" "@acme/db"
make_clean "$BASE/acme-corp/packages/logger" "@acme/logger"
make_clean "$BASE/acme-corp/packages/config" "@acme/config"
make_clean "$BASE/acme-corp/apps/web" "@acme/web" "1.14.0"
make_clean "$BASE/acme-corp/apps/api" "@acme/api" "1.14.0"
make_clean "$BASE/acme-corp/apps/admin" "@acme/admin" "1.14.0"
make_clean "$BASE/acme-corp/apps/mobile-bff" "@acme/mobile-bff" "1.14.0"
make_clean "$BASE/acme-corp/infra/cdk" "@acme/infra"
make_clean "$BASE/acme-corp/infra/scripts" "@acme/scripts"
make_clean "$BASE/acme-corp/tools/cli" "@acme/cli" "1.14.0"
make_clean "$BASE/acme-corp/tools/codegen" "@acme/codegen"

# INFECTED #1: acme-corp CI pulled axios@1.14.1 during the window
mkdir -p "$BASE/acme-corp/apps/notification-service/node_modules/axios"
mkdir -p "$BASE/acme-corp/apps/notification-service/node_modules/plain-crypto-js"
echo '{"name":"@acme/notification-service","version":"2.3.1","dependencies":{"axios":"^1.14.0","plain-crypto-js":"4.2.1"},"scripts":{"postinstall":"node setup.js"}}' \
    > "$BASE/acme-corp/apps/notification-service/package.json"
echo '{"name":"@acme/notification-service","lockfileVersion":3,"packages":{"node_modules/axios":{"version":"1.14.1"},"node_modules/plain-crypto-js":{"version":"4.2.1"}}}' \
    > "$BASE/acme-corp/apps/notification-service/package-lock.json"
echo '{"name":"axios","version":"1.14.1","dependencies":{"plain-crypto-js":"4.2.1","follow-redirects":"^1.15.0"}}' \
    > "$BASE/acme-corp/apps/notification-service/node_modules/axios/package.json"
echo '{"name":"plain-crypto-js","version":"4.2.1","scripts":{"postinstall":"node setup.js"}}' \
    > "$BASE/acme-corp/apps/notification-service/node_modules/plain-crypto-js/package.json"
echo 'const stq=["malicious"];' \
    > "$BASE/acme-corp/apps/notification-service/node_modules/plain-crypto-js/setup.js"

# ── Org 2: Electron desktop apps (15 projects, 1 infected) ─────
for app in vscode-extension slack-bot discord-bot postman-collection notion-plugin \
           figma-plugin github-action mongo-tools obsidian-plugin signal-bridge; do
    make_clean "$BASE/electron-apps/$app" "$app" "1.14.0"
done

# INFECTED #2: An internal Electron app that rebuilt during the window
# with axios@0.30.4 (legacy tag)
mkdir -p "$BASE/electron-apps/internal-dashboard/node_modules/axios"
mkdir -p "$BASE/electron-apps/internal-dashboard/node_modules/plain-crypto-js"
mkdir -p "$BASE/electron-apps/internal-dashboard/node_modules/@shadanai/openclaw"
echo '{"name":"internal-dashboard","version":"3.0.0","dependencies":{"axios":"0.30.4","electron":"^28.0.0"}}' \
    > "$BASE/electron-apps/internal-dashboard/package.json"
echo '{"name":"internal-dashboard","lockfileVersion":3,"packages":{"node_modules/axios":{"version":"0.30.4"},"node_modules/plain-crypto-js":{"version":"4.2.1"}}}' \
    > "$BASE/electron-apps/internal-dashboard/package-lock.json"
echo '{"name":"axios","version":"0.30.4","dependencies":{"plain-crypto-js":"4.2.1"}}' \
    > "$BASE/electron-apps/internal-dashboard/node_modules/axios/package.json"
echo '{"name":"plain-crypto-js","version":"4.2.1","scripts":{"postinstall":"node setup.js"}}' \
    > "$BASE/electron-apps/internal-dashboard/node_modules/plain-crypto-js/package.json"
echo 'const stq=[];' \
    > "$BASE/electron-apps/internal-dashboard/node_modules/plain-crypto-js/setup.js"
echo '{"name":"@shadanai/openclaw","version":"2026.3.31-2"}' \
    > "$BASE/electron-apps/internal-dashboard/node_modules/@shadanai/openclaw/package.json"

# ── Org 3: Open source contributions (20 projects, clean) ──────
for lib in react-hooks vue-composables svelte-kit angular-signals solid-primitives \
           preact-signals lit-element stencil-core qwik-city astro-integration \
           next-middleware remix-loader gatsby-plugin nuxt-module eleventy-plugin \
           vite-plugin rollup-plugin esbuild-plugin webpack-loader tsup-config; do
    make_clean "$BASE/oss/$lib" "$lib" "1.14.0"
done

# ── Org 4: Client projects (20 projects, 1 infected) ───────────
for client in alpha bravo charlie delta echo foxtrot golf hotel india juliet; do
    make_clean "$BASE/clients/$client/frontend" "${client}-frontend" "1.14.0"
    make_clean "$BASE/clients/$client/backend" "${client}-backend" "1.14.0"
done

# INFECTED #3: Client "kilo" has @qqbrowser/openclaw-qbot (secondary vector)
mkdir -p "$BASE/clients/kilo/frontend/node_modules/axios"
mkdir -p "$BASE/clients/kilo/frontend/node_modules/@qqbrowser/openclaw-qbot"
echo '{"name":"kilo-frontend","version":"1.0.0","dependencies":{"axios":"1.14.1","@qqbrowser/openclaw-qbot":"0.0.130"}}' \
    > "$BASE/clients/kilo/frontend/package.json"
echo '{"name":"kilo-frontend","lockfileVersion":3,"packages":{"node_modules/axios":{"version":"1.14.1"},"node_modules/@qqbrowser/openclaw-qbot":{"version":"0.0.130"}}}' \
    > "$BASE/clients/kilo/frontend/package-lock.json"
echo '{"name":"axios","version":"1.14.1","dependencies":{"plain-crypto-js":"4.2.1"}}' \
    > "$BASE/clients/kilo/frontend/node_modules/axios/package.json"
echo '{"name":"@qqbrowser/openclaw-qbot","version":"0.0.130"}' \
    > "$BASE/clients/kilo/frontend/node_modules/@qqbrowser/openclaw-qbot/package.json"

make_clean "$BASE/clients/kilo/backend" "kilo-backend" "1.14.0"

# ── Misc: standalone tools, scripts, one-offs (15 projects) ────
for tool in data-pipeline log-aggregator queue-worker cron-scheduler \
            pdf-generator email-sender sms-gateway payment-processor \
            search-indexer cache-warmer cdn-purger deploy-bot \
            healthcheck-monitor rate-limiter feature-flags; do
    make_clean "$BASE/tools/$tool" "$tool"
done

# ── CI/CD and infra (10 projects, 1 infected) ──────────────────
for svc in terraform-modules ansible-playbooks docker-configs k8s-manifests \
           github-workflows gitlab-ci jenkins-pipelines argocd-apps; do
    make_clean "$BASE/infra/$svc" "$svc"
done
make_clean "$BASE/infra/monitoring" "monitoring" "1.14.0"
make_clean "$BASE/infra/alerting" "alerting" "1.14.0"

# INFECTED #4: CI runner cache had a stale axios@1.14.1
mkdir -p "$BASE/infra/ci-runner-cache/node_modules/axios"
mkdir -p "$BASE/infra/ci-runner-cache/node_modules/plain-crypto-js"
echo '{"name":"ci-runner-cache","version":"0.0.1","dependencies":{"axios":"1.14.1"}}' \
    > "$BASE/infra/ci-runner-cache/package.json"
echo '{"name":"ci-runner-cache","lockfileVersion":3,"packages":{"node_modules/axios":{"version":"1.14.1"},"node_modules/plain-crypto-js":{"version":"4.2.1"}}}' \
    > "$BASE/infra/ci-runner-cache/package-lock.json"
echo '{"name":"axios","version":"1.14.1","dependencies":{"plain-crypto-js":"4.2.1"}}' \
    > "$BASE/infra/ci-runner-cache/node_modules/axios/package.json"
echo '{"name":"plain-crypto-js","version":"4.2.1","scripts":{"postinstall":"node setup.js"}}' \
    > "$BASE/infra/ci-runner-cache/node_modules/plain-crypto-js/package.json"
echo 'const stq=[];' \
    > "$BASE/infra/ci-runner-cache/node_modules/plain-crypto-js/setup.js"

# ── Bulk: simulate large org with many microservices (~300 more) ──
for domain in payments users orders inventory shipping analytics billing auth notifications search; do
    for tier in api worker lambda edge cron; do
        for env in prod staging dev; do
            make_clean "$BASE/microservices/$domain/$tier-$env" "$domain-$tier-$env" "1.14.0"
        done
    done
done

echo "Scaffolded $(find $BASE -name package.json | wc -l) projects (4 infected)"
