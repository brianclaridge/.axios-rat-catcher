## Stage 1: Build the Linux binary inside Docker
FROM rust:1-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release
RUN strip target/release/axios-rat-scan

## Stage 2: Test environment — ~100 realistic projects, 4 infected
FROM ghcr.io/charmbracelet/vhs

USER root

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 procps net-tools iproute2 bash gifsicle \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/axios-rat-scan /usr/local/bin/axios-rat-scan

# ── Scaffold realistic project tree ─────────────────────────────
COPY test/scaffold.sh /scaffold.sh
RUN chmod +x /scaffold.sh && /scaffold.sh

# ── Plant host-level RAT artifacts ──────────────────────────────
RUN echo '#!/usr/bin/env python3\nimport time\nwhile True: time.sleep(60)' > /tmp/ld.py
RUN echo 'dropper-payload' > /tmp/6202033

# ── Test + demo scripts ────────────────────────────────────────
COPY test/verify.sh /verify.sh
COPY test/demo.tape /demo.tape
COPY test/demo-run.sh /demo-run.sh
RUN chmod +x /verify.sh /demo-run.sh

WORKDIR /projects
ENTRYPOINT ["/verify.sh"]
