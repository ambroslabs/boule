# Upgrading reth in `boule-reth-node`

This crate embeds **reth as a library (the SDK)** — it does **not** fork reth's
source. That is the whole point of Option A (#777): we own only the node
*assembly* (a `NodeBuilder` with a custom block executor + payload builder), so a
reth bump is a dependency-version change plus a recompile, not a diff-rebase.
This file is the playbook for that bump and the record of what's pinned today.

## What's pinned now

| Thing | Value |
| --- | --- |
| reth crates (`reth-ethereum`, `reth-payload-builder`, `reth-basic-payload-builder`, `reth-ethereum-payload-builder`) | git tag **`v2.2.0`**, commit **`88505c7`** (`paradigmxyz/reth`) |
| `alloy-evm` | `0.34.0` (the version reth `v2.2.0` resolves; carries `EthBlockExecutionCtx` + the block-executor traits) |
| `alloy-sol-types` / `alloy-primitives` | `1.5.6` / `1` |
| Local `reth` binary this matches | `v2.2.0`, commit `88505c7` |
| MSRV | `1.93` (edition 2024) — see `clippy.toml` |

The pin lives in `Cargo.toml` (the four `git = ".../reth.git", tag = "v2.2.0"`
deps) and is locked in this crate's own `Cargo.lock`. The crate is a **standalone
workspace** (excluded from the repo-root workspace) so the reth tree never enters
boule's main build/lockfile; CI builds it via `.github/workflows/reth-node.yml`.

## Build prerequisites

A reth-SDK build is ~6 min + a huge dep tree (~16 GB working set); use `--jobs`
to throttle. On a fresh box:

```sh
sudo apt-get install -y clang libclang-dev   # mdbx-sys runs bindgen via libclang
# bindgen needs the C compiler's resource-dir headers (e.g. stdarg.h):
export BINDGEN_EXTRA_CLANG_ARGS="-I$(ls -d /usr/lib/gcc/x86_64-linux-gnu/*/include | sort -V | tail -1)"
cargo build --jobs 3        # from crates/boule-reth-node/
```

`solc` is **not** needed by this crate (it has no `build.rs`; genesis-from-source
lives in the `boule-reth` crate).

## The SDK seam we depend on

We extend reth at exactly two intended extension points (the same place reth
applies EIP-4788/2935/7002/7251 system calls), composed via `NodeBuilder`:

- **`ExecutorBuilder` / `ConfigureEvm` + `ConfigureEngineEvm` + `BlockExecutor`**
  (`src/executor.rs`) — `CustomBlockExecutor` reads the registry writes from the
  block's `extra_data` and applies them as system calls on **both** the build
  path and the `newPayloadV4` verify path (implementing only `ConfigureEvm` is
  the classic trap — see the module docs).
- **`PayloadBuilderBuilder` / `PayloadBuilder`** (`src/payload.rs`) —
  `BoulePayloadBuilder` transcribes the registry payload into header `extra_data`
  by calling `default_ethereum_payload`.

These are the surfaces most likely to move between reth releases. The risk of a
bump is concentrated here, not in business logic.

## Bump procedure

1. **Pick the target.** Choose the new reth git tag and read its release notes /
   `CHANGELOG` for changes to `ConfigureEvm`, `BlockExecutor`, `ExecutorBuilder`,
   `PayloadBuilder`, the engine validator, and `EthBlockExecutionCtx`.
2. **Repin.** Update the `tag = "vX.Y.Z"` on all four reth git deps in
   `Cargo.toml` (keep them on the *same* tag). Bump `alloy-evm`/`alloy-*` to the
   versions the new reth resolves (check reth's lockfile or `cargo tree`); keep
   using reth's **re-exports** for `alloy-rpc-types-engine` etc. — never add a
   second direct copy (causes "multiple versions of crate" trait mismatches; see
   the note in `Cargo.toml`).
3. **Relock.** `cargo update --workspace` (or delete + regenerate `Cargo.lock`).
4. **Build + test** with the prerequisites above:
   `cargo build --jobs 3 && cargo test --locked`.
5. **Refit the seam** if it broke — adjust `src/executor.rs` / `src/payload.rs`
   to the new trait shapes. This is the only place real work is expected.
6. **Re-run the gates** (mirrors CI):
   ```sh
   cargo fmt --all --check
   cargo clippy --locked --all-targets -- -D warnings
   cargo test --locked --all-targets
   cargo deny --all-features check
   ```
7. **Reconcile `deny.toml`.** A reth bump shifts the dep tree, so revisit:
   - the **advisory ignores** — drop any that the new lock no longer triggers
     (especially `RUSTSEC-2026-0118/0119` for hickory, fixed in hickory 0.26.x
     which a later reth pulls in; and `RUSTSEC-2025-0141` bincode);
   - the **license allow-list** additions (`0BSD`, `CDLA-Permissive-2.0`,
     `MPL-2.0`, `Unlicense`) — add any newly surfaced license here, not in the
     root `deny.toml`;
   - the **git-source allow-org** list (`paradigmxyz`, `sigp`) — a new reth may
     move a git pin (e.g. `discv5`).
8. **Sync the version table** at the top of this file, and update the pinned
   `v2.2.0` references in `Cargo.toml` comments and the matching local `reth`
   binary if it's used for interop.

## Why the cost is low

Because we compose reth, the diff for a bump is normally just steps 2–3 (repin +
relock) and step 7 (deny reconcile). Step 5 (seam refit) only triggers when reth
changes the executor/payload trait shapes — and when it does, the change is
localized to two files, not spread across a forked tree we'd have to rebase.
