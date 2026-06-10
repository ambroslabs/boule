# Runtime image for the single `boule` binary. It does NO compilation: the
# binary is built on the host (cargo, run inside the boule-builder image — see
# .github/actions/cargo-build for CI and `make build` for local) and copied in.
#
# Build context is the repo root; the binary must already exist at BOULE_BIN.
#   make build                        # produces crates/boule-bundle/target/release/boule
#   docker build -f docker/Dockerfile -t boule .
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 10001 boule
USER boule
WORKDIR /home/boule

# Path (relative to the build context) to the host-built, stripped binary.
ARG BOULE_BIN=crates/boule-bundle/target/release/boule
COPY ${BOULE_BIN} /usr/local/bin/boule

# 8545 eth RPC (boule node / node --dev default).
EXPOSE 8545

# The single binary — every subcommand is reachable. `docker run <img> node --dev`
# is a complete zero-config dev chain.
ENTRYPOINT ["boule"]
