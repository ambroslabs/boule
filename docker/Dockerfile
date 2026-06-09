# A boule + reth node in one image: the custom reth execution layer
# (boule-reth-node) and the boule consensus node, run side by side. boule orders
# blocks; reth executes the EVM payloads.
#
# The image ships the binaries + orchestration only — the chain (genesis, JWT,
# keys, node.toml) is supplied at runtime under CHAIN_DIR (default /chain), so the
# same image runs any node: a validator, a full node, or one-of-N in a cluster.
# With an empty CHAIN_DIR it bootstraps a single-validator dev chain. See README.
#
# Build (context = repo root):
#     docker build -f docker/Dockerfile -t boule-node .

# ─────────────────────────── builder ───────────────────────────
# boule-reth-node pins reth v2.2.0 and requires Rust >= 1.93 (edition 2024).
FROM rust:1-bookworm AS builder

# reth's mdbx-sys runs bindgen via libclang; solc compiles the predeploy
# contracts in boule-reth's build.rs.
RUN apt-get update && apt-get install -y --no-install-recommends \
      clang libclang-dev pkg-config curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Pinned solc 0.8.24, from two independent CDNs (GitHub's release CDN 504s).
RUN set -eux; \
    for u in \
      "https://github.com/ethereum/solidity/releases/download/v0.8.24/solc-static-linux" \
      "https://binaries.soliditylang.org/linux-amd64/solc-linux-amd64-v0.8.24+commit.e11b9ed9" ; do \
      curl -fsSL --retry 5 --retry-all-errors --retry-delay 3 -o /usr/local/bin/solc "$u" && break; \
    done; \
    chmod +x /usr/local/bin/solc; solc --version

WORKDIR /src
COPY . .

# boule (reth backend) + the genesis/BLS helpers, from the main workspace.
RUN cargo build --release -p boule-cli --features reth --bin boule \
 && cargo build --release -p boule-reth --bin gen-genesis --bin gen-bls-genesis \
 && cp target/release/boule target/release/gen-genesis target/release/gen-bls-genesis /usr/local/bin/

# The custom EL — its own standalone workspace (excluded from boule's root).
# Give bindgen gcc's standard headers in case libclang lacks the resource dir.
RUN export BINDGEN_EXTRA_CLANG_ARGS="-I$(ls -d /usr/lib/gcc/x86_64-linux-gnu/*/include | head -1)" \
 && cargo build --release --manifest-path crates/boule-reth-node/Cargo.toml \
 && cp crates/boule-reth-node/target/release/boule-reth-node /usr/local/bin/

# ─────────────────────────── runtime ───────────────────────────
FROM debian:bookworm-slim AS runtime

# ca-certificates: rustls native roots. curl/jq/openssl: the entrypoint's
# EL-readiness probe and the (optional) single-validator bootstrap.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl jq openssl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/boule            /usr/local/bin/boule
COPY --from=builder /usr/local/bin/boule-reth-node  /usr/local/bin/boule-reth-node
COPY --from=builder /usr/local/bin/gen-genesis      /usr/local/bin/gen-genesis
COPY --from=builder /usr/local/bin/gen-bls-genesis  /usr/local/bin/gen-bls-genesis
COPY docker/entrypoint.sh                  /usr/local/bin/entrypoint.sh
COPY docker/bootstrap-single-validator.sh  /usr/local/bin/bootstrap-single-validator.sh

# Runtime knobs (all overridable with `docker run -e`). Chain artifacts live in
# CHAIN_DIR; mutable state (reth datadir, consensus storage) in DATA_DIR.
ENV CHAIN_DIR=/chain \
    DATA_DIR=/data \
    EL_HTTP_ADDR=0.0.0.0 \
    EL_HTTP_PORT=8545 \
    EL_AUTHRPC_PORT=8551 \
    EL_P2P_PORT=30303 \
    BOOTSTRAP=auto

# 8545 eth RPC · 8000 boule API · 7000 boule p2p · 30303 reth p2p
EXPOSE 8545 8000 7000 30303

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
