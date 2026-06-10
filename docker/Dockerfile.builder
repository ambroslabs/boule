# boule build environment — published to GHCR as ghcr.io/ambroslabs/boule-builder.
#
# This image is NOT a build stage of the app image. It's a standalone toolchain
# container: CI and local dev run the actual `cargo` build INSIDE it with the
# source + target + cargo home + sccache config bind-mounted from the host, so
# compiled artifacts land back on the host filesystem. The runtime app image
# then just COPYs the host's built binary. That keeps caching to plain host
# directories (no BuildKit cache-mount gymnastics) and keeps secrets out of any
# image layer (they're just env on `docker run`).
#
# Rebuilt only when the toolchain / system deps below change (the builder-image
# workflow keys its tag on a hash of this file + rust-toolchain.toml).

# Pin the toolchain. Bundle MSRV is 1.93 (edition 2024); stable is past it.
FROM rust:1-bookworm

# reth's mdbx-sys runs bindgen via libclang; solc compiles the predeploy genesis
# (boule-reth build.rs); git for any git deps; the rest are build hygiene.
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang \
        libclang-dev \
        pkg-config \
        curl \
        ca-certificates \
        git \
    && rm -rf /var/lib/apt/lists/*

# Pinned solc 0.8.24, from two independent CDNs (GitHub's release CDN 504s).
RUN set -eux; \
    for url in \
        "https://github.com/ethereum/solidity/releases/download/v0.8.24/solc-static-linux" \
        "https://binaries.soliditylang.org/linux-amd64/solc-linux-amd64-v0.8.24+commit.e11b9ed9"; do \
        curl -fsSL --retry 5 --retry-all-errors --retry-delay 3 -o /usr/local/bin/solc "$url" && break; \
    done; \
    chmod +x /usr/local/bin/solc; solc --version

# sccache (compiler cache) — the build container sets RUSTC_WRAPPER=sccache and
# points it at the shared DO Spaces bucket via env at run time.
RUN set -eux; \
    curl -fsSL "https://github.com/mozilla/sccache/releases/download/v0.15.0/sccache-v0.15.0-x86_64-unknown-linux-musl.tar.gz" \
      | tar -xz -C /tmp; \
    cp /tmp/sccache-v0.15.0-x86_64-unknown-linux-musl/sccache /usr/local/bin/sccache; \
    chmod +x /usr/local/bin/sccache; rm -rf /tmp/sccache-*; sccache --version

# cargo-nextest (the test job runs via nextest) — prebuilt binary, no compile.
RUN curl -fsSL https://get.nexte.st/latest/linux | tar -xz -C /usr/local/bin && cargo-nextest --version

# rustfmt + clippy components for the lint/format jobs.
RUN rustup component add rustfmt clippy

# bindgen needs the C compiler's resource-dir headers; bookworm ships gcc 12.
ENV BINDGEN_EXTRA_CLANG_ARGS=-I/usr/lib/gcc/x86_64-linux-gnu/12/include

# Clean CI checkouts gain nothing from incremental compilation, and it's the
# recommended setting alongside sccache.
ENV CARGO_INCREMENTAL=0

# Runs as an arbitrary `--user $(id -u):$(id -g)` so bind-mounted host files stay
# host-owned. Such a UID has no home; callers pass `-e HOME=...` and a writable
# `-e CARGO_HOME=...` (both bind-mounted). The rustup toolchain in /usr/local is
# world-readable, so a non-root UID can still run rustc/cargo.
