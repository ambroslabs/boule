# `ambros-p2p-fuzz`

[`cargo-fuzz`](https://rust-fuzz.github.io/book/cargo-fuzz.html) targets for
the consensus layer.

This crate is intentionally **not** part of the parent workspace. It is
nightly-only (libFuzzer needs `-Z sanitizer`), and its `libfuzzer-sys`
dependency would be a runtime cost on every `cargo test` / `cargo clippy`
run otherwise. CI does not build or run anything in this directory; the
targets are intended for manual / scheduled invocations.

## Targets

### `dispatch_ingress_skip`

Decodes arbitrary bytes as
[`WireMessage`](../src/consensus/node.rs) and feeds them into
[`ingress_wire`](../src/consensus/dispatch/ingress.rs) under
`QcVerification::Skip` against a fixed 4-validator history.

[`src/consensus/wire_fuzz.rs`](../src/consensus/wire_fuzz.rs) already covers
the decode-side panic surface with a proptest harness. This target trades
proptest's per-iteration signing cost for raw libFuzzer bytes plus
coverage-guided mutation, so it can run for hours rather than seconds and
catches:

- panics in QC well-formedness paths under malformed bitmaps,
- stray-bit conditions on `SignerBitmap` past `len`,
- signer-bitmap overflow / signature-count-vs-signers divergence,
- any decode-time invariant the wire types' constructors enforce that
  postcard's positional decode bypasses.

If audit finding 14-3 (issue #9, gate `QcVerification::Skip` to
`cfg(test)`) lands, this target becomes the watchdog ensuring even the
test-only `Skip` path can't crash on weird-but-decodable inputs.

## Setup

```sh
cargo install --locked cargo-fuzz
rustup toolchain install nightly
```

## Run

```sh
# From the repo root:
cd fuzz
cargo +nightly fuzz run dispatch_ingress_skip
```

The first run rebuilds with libFuzzer instrumentation; subsequent runs
reuse the cached artifact.

## Recommended runtime budgets

| When                       | Budget         | Flag                                  |
| -------------------------- | -------------- | ------------------------------------- |
| Local smoke (does it run?) | 60 s           | `-- -max_total_time=60`               |
| Per-PR opt-in              | 10 min         | `-- -max_total_time=600`              |
| Nightly soak               | 6 h            | `-- -max_total_time=21600`            |
| Triage after a crash       | until quiesced | `-- -runs=0` against the artifact dir |

CI does **not** run this target on every PR. The proptest harness in
[`src/consensus/wire_fuzz.rs`](../src/consensus/wire_fuzz.rs) gives the
day-to-day shape coverage; this target is the long-tail watchdog.

## Initial corpus

`fuzz/corpus/dispatch_ingress_skip/` ships with a small seed corpus
covering one decodable sample per `WireMessage` variant. To regenerate:

```sh
cd fuzz
cargo run --release --bin seed_corpus
```

The seeder is deterministic: rerunning produces byte-identical files,
so a clean `git diff` after running it means the wire format hasn't
shifted under us. Adjust the seeder when adding new `WireMessage`
variants — drop the variant in once, re-run, commit.

## Triaging a crash

When libFuzzer finds a crash, it writes the input to
`fuzz/artifacts/dispatch_ingress_skip/crash-*`. To reproduce:

```sh
cd fuzz
cargo +nightly fuzz run dispatch_ingress_skip artifacts/dispatch_ingress_skip/crash-<id>
```

Useful follow-ups after a fix lands:

- Add the artifact to the seed corpus so the regression is caught on
  every future run.
- Or, if it's a wire-shape concern, encode the same shape into the
  proptest generator in `src/consensus/wire_fuzz.rs` so CI catches it
  without nightly.
