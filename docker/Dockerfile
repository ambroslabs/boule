# ──────────────────────────────────────────────────────────────────────────────
# Minimal single-binary `boule` image (milestone #7, #892).
#
# Multi-stage: the builder compiles the ONE `boule` binary from the EXCLUDED
# `crates/boule-bundle` workspace (reth linked in-process); the runtime is a slim
# base with just that binary. NO entrypoint.sh, NO bootstrap.sh, NO wait-loop —
# reth runs in-process, so `boule node --dev` is a complete, zero-glue dev chain.
#
# Build from the REPO ROOT (the bundle path-depends on its sibling crates):
#   docker build -f docker/Dockerfile -t boule .
# Run a zero-config dev chain that commits blocks:
#   docker run --rm -p 8545:8545 boule node --dev
# See docker/README.md for the custom-chain recipe.
# ──────────────────────────────────────────────────────────────────────────────

# ── Builder ──────────────────────────────────────────────────────────────────
# Pinned to the bundle's edition-2024 MSRV (rust-version = "1.93"); `stable` is
# well past that. bookworm matches the runtime base's glibc.
FROM rust:1.93-bookworm AS builder

# Build prerequisites for the reth-linked bundle, mirroring the CI lane
# (.github/workflows/ci.yml "Unified boule binary"):
#  - solc 0.8.24: boule-reth's build.rs compiles the EVM predeploy genesis from
#    source at build time (the bytecode is never committed — see AGENTS.md).
#    Fetched from the same pinned URL as .github/actions/install-solc.
#  - clang + libclang-dev: reth's mdbx-sys runs bindgen via libclang.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        clang \
        libclang-dev \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Pinned solc 0.8.24 (same binary as .github/actions/install-solc), with a CDN
# fallback so a sustained outage on one mirror doesn't break the build.
RUN set -eux; \
    for url in \
        "https://github.com/ethereum/solidity/releases/download/v0.8.24/solc-static-linux" \
        "https://binaries.soliditylang.org/linux-amd64/solc-linux-amd64-v0.8.24+commit.e11b9ed9"; do \
        if curl -fsSL --retry 5 --retry-all-errors --retry-delay 3 -o /usr/local/bin/solc "$url"; then \
            break; \
        fi; \
        echo "solc download failed from $url; trying next mirror" >&2; \
    done; \
    chmod +x /usr/local/bin/solc; \
    solc --version

# bindgen (mdbx-sys) needs the C compiler's resource-dir headers (e.g. stdarg.h).
# Point it at the installed gcc's include dir; the gcc major is derived at build
# time so this isn't pinned to a specific base image's gcc.
RUN gcc_inc="$(ls -d /usr/lib/gcc/x86_64-linux-gnu/*/include | sort -V | tail -1)" \
    && echo "BINDGEN_EXTRA_CLANG_ARGS=-I${gcc_inc}" > /etc/environment.bindgen

WORKDIR /src
# The bundle path-depends on its sibling crates, so the build context is the repo
# root. (.dockerignore keeps target/ and other heavy artifacts out.)
COPY . .

# Build the single `boule` binary in release mode from the bundle workspace, then
# strip it. The reth dep tree is enormous (~6 min + hundreds of crates); under
# BuildKit, `docker build` callers can add `--mount=type=cache` for the cargo
# registry/target, but this builds with the plain layer cache so it works on the
# legacy builder too.
RUN set -eux; \
    export $(cat /etc/environment.bindgen); \
    cargo build --release --locked --manifest-path crates/boule-bundle/Cargo.toml --bin boule; \
    cp crates/boule-bundle/target/release/boule /usr/local/bin/boule; \
    strip /usr/local/bin/boule

# ── Runtime ──────────────────────────────────────────────────────────────────
# Slim base with just glibc + CA certs (the reth-linked binary is dynamically
# linked against the builder's glibc; bookworm-slim matches it).
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Run as a non-root user; reth/consensus state lives under its home.
RUN useradd --create-home --uid 10001 boule
USER boule
WORKDIR /home/boule

COPY --from=builder /usr/local/bin/boule /usr/local/bin/boule

# The public eth_* JSON-RPC port (boule node / node --dev default).
EXPOSE 8545

# Just the binary — every subcommand is reachable (node/init/genesis/...).
# `docker run <img> node --dev` is a complete zero-config dev chain.
ENTRYPOINT ["boule"]
