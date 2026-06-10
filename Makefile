# Local build helpers.
#
# `make build` is the reproducible path: it runs cargo INSIDE the boule-builder
# image (the same image CI uses), with the source/target/cargo-home bind-mounted
# from the host, so the compiled binary lands back on the host.
#
# The escape hatch is a plain `cargo build` (no container) if you have the
# toolchain + clang + solc locally — fine for fast iteration.
#
# For the shared DO Spaces compiler cache, export the Spaces creds first
# (e.g. `source ~/.config/boule-cache/sccache.env`); otherwise sccache falls
# back to a local-disk cache.

BUILDER_IMAGE ?= ghcr.io/ambroslabs/boule-builder:latest
ROOT := $(shell git rev-parse --show-toplevel)
UIDGID := $(shell id -u):$(shell id -g)

.PHONY: build image

## build: compile the unified `boule` binary inside the builder image
build:
	@mkdir -p "$(ROOT)/.cache/cargo-home"
	docker run --rm \
	  --user "$(UIDGID)" \
	  -e HOME=/tmp -e CARGO_HOME=/cache/cargo -e CARGO_INCREMENTAL=0 \
	  -e RUSTC_WRAPPER=sccache \
	  -e SCCACHE_BUCKET=$${SCCACHE_BUCKET:-boule-sccache} \
	  -e SCCACHE_ENDPOINT=$${SCCACHE_ENDPOINT:-https://nyc3.digitaloceanspaces.com} \
	  -e SCCACHE_REGION=$${SCCACHE_REGION:-auto} \
	  -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY \
	  -v "$(ROOT)":/work -w /work/crates/boule-bundle \
	  -v "$(ROOT)/.cache/cargo-home":/cache/cargo \
	  "$(BUILDER_IMAGE)" \
	  bash -c 'cargo build --release --locked --bin boule && strip target/release/boule && (sccache --show-stats || true)'
	@echo "built: crates/boule-bundle/target/release/boule"

## image: build the runtime image from the host-built binary (run `make build` first)
image:
	docker build -f docker/Dockerfile -t boule "$(ROOT)"
