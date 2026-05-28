# Workspace crate split — design notes

Splitting the monolithic `boule-rs` library into layered crates. Tracks the
target layering, the cycles that forced specific moves, and **what is left
behind in `boule-rs`**.

## Target crates (depend strictly downward)

```
boule-rs            clock, crypto (incl. NodeId/NodeIdentity via identity, SignerBitmap),
                    storage, config (structs + loaders), paths, cli, identity
   ▲
boule-transport     transport interface: Broadcaster/Discovery traits, MessageKind,
                    RateLimiter + limits config, PeerCommand, Protocol{Handle,Outbound,Event}
   ▲                         ▲
boule-transport-tcp          boule-consensus  (consensus core + replication)
(today's p2p impl)           — depends on boule-rs only; NO edge to boule-transport-tcp
   ▲                         ▲
boule-node          node.rs runtime + consensus/node driver + testnet + sim
   ▲
boule-cli           binaries (boule, testnet)
```

## Cycles found and how each was broken

- `consensus ↔ replication` — bundled together into `boule-consensus`.
- `crypto → consensus` (`SignerBitmap`) — `SignerBitmap` moved down into `crypto`.
- `crypto → p2p` (`NodeId`/`NodeIdentity`) — identity moved to `boule-rs::identity`
  (bottom); transport crates reach *down* for it.
- `consensus → node` (`derive_chain_id`) — moved into `consensus` (needs validator
  histories + genesis Block, so it belongs in consensus, not down in config).
- `config ↔ {consensus, p2p}` — config split: raw structs + TOML loading + identity
  providers stay in `boule-rs`; the conversion methods move to consumers
  (`to_cache_limits` → `consensus::limits::CacheLimits::from_config`,
  `rate_limits`/`connection_limits` → `p2p::limits::{RateLimitsConfig,ConnectionLimitsConfig}::from_config`);
  the `DEFAULT_*` limit constants and `MAX_FRAME_BYTES` move down into `config`
  (`consensus::node::wire` re-exports `MAX_FRAME_BYTES` from there).

## What is LEFT BEHIND in boule-rs (bottom primitives)

- `clock` — Clock trait, BoxFuture, TokioClock/SimClock. Leaf.
- `crypto` — signing schemes, Signed envelopes, ChainId; now also owns `SignerBitmap`.
- `identity` — NodeId (`[u8;32]`), NodeIdentity, base58 helpers, key-provider backends
  (file/env/exec/encrypted/keyring). Moved out of `p2p`.
- `storage` — Storage + Wal traits, in-memory + redb backends.
- `config` — Config structs, TOML load, identity-provider construction, DEFAULT_* limit
  constants. Conversions to consensus/transport limit types removed (moved to consumers).
- `paths` — default file locations. Leaf.
- `cli` — OutputFormat + structured-output rendering helpers (used by boule-cli).

## Progress

- **Step 1 (committed):** identity → `boule-rs::identity`; `SignerBitmap` → `crypto`;
  genesis/`derive_chain_id` → `consensus::genesis`. boule-rs compiles + lib tests pass.
- **Step 2 (committed):** config detangle — `DEFAULT_*` + `MAX_FRAME_BYTES` → `config`;
  `to_cache_limits` → `consensus::limits::CacheLimits::from_config`;
  `connection_limits`/`rate_limits` → `p2p::limits::*::from_config`. config production
  code now has zero upward refs. boule-rs compiles + lib tests pass.
- **Step 3 (committed):** monolithic file-move carve — created boule-transport,
  boule-transport-tcp, boule-consensus, boule-node; moved every module to its target
  crate and rewrote all `crate::` paths. `cargo check --workspace` green.
- **Step 4:** test layer + gate — relocated orphaned integration tests, re-added the
  cross-layer wire-tag test in boule-node, and exposed test-only items across the new
  crate boundaries via feature flags (see below). fmt + clippy(`-D warnings`) + the full
  `cargo test --locked` suite (~1196 tests) all pass.

## Cross-crate test/seam features

Splitting the driver out of consensus turned several in-crate `#[cfg(test)]` /
`pub(crate)` items into cross-crate accesses. Rather than widen the production API, they
are gated behind opt-in features enabled only by downstream dev-dependencies:

- `boule-rs/testing` — `ChainId::TEST` (the all-zero sentinel stays out of production).
- `boule-consensus/testing` — test ingress entry points (`dispatch::ingress`/`ingress_wire`),
  `QcVerification::Skip`, `SnapshotManifest::build_for_test_genesis_histories`,
  `HotStuffCore::install_block_sync_inflight_for_test`, `QuorumCertificate::from_raw_parts`.
- `boule-consensus/crashpoints` — the `crashpoint!` firing path + `CrashSlot` API
  (no-op in production; the macro compiles to an empty inlined `fire`).

`boule-node`'s dev-dependencies enable `boule-rs/testing`,
`boule-consensus/{testing,crashpoints}`; feature unification turns them on for the whole
`cargo test --locked` build.

## Remaining carve — execution spec (historical; completed in Step 3)

File-move map (`git mv` into each new crate's `src/`):

- **boule-transport** ← `p2p/limits.rs` (as `limits.rs`) + `p2p/overlay/traits.rs`
  (as `overlay.rs`; holds Broadcaster/Discovery/DiscoveryEvent). Deps: boule-rs, bytes,
  tokio. The `#[cfg(test)]` block in limits.rs that references `consensus::node::WireMessage`
  moves to boule-node (or is deleted).
- **boule-transport-tcp** ← the rest of `p2p/*` (tls, manager, rpc, listener, dialer,
  connection, api, tls_protocol, overlay/{gossip,mesh,sink}, mod.rs's ConnectionProtocol/
  PeerCommand/Protocol*). Deps: boule-transport, boule-rs.
- **boule-consensus** ← `consensus/*` minus `consensus/node/`, `sim.rs`, `sim_byzantine.rs`,
  `sim_crashpoint.rs`, `wire_fuzz.rs`; plus all of `replication/*`. Deps: boule-rs only
  (verify: no boule-transport/-tcp edge). `crate::consensus::` → `crate::`,
  `crate::replication::` stays `crate::replication::`.
- **boule-node** ← `node.rs` (becomes lib root) + `consensus/node/*` + the four
  `#[cfg(test)]` sim/fuzz modules + `testnet/*`. Deps: all of the above.
- **boule-cli** (exists) ← repoint `boule` dep to `boule-node` + siblings; fix
  `main.rs`, `cli/*`, `bin/testnet.rs` import paths.

Path-rewrite rules (per moved crate, via perl):
- `crate::crypto::` → `boule_rs::crypto::`; same for `clock`, `storage`, `config`,
  `paths`, `identity`, `cli`.
- in transport-tcp & node: `crate::p2p::limits::` → `boule_transport::limits::`;
  `crate::p2p::overlay::{Broadcaster,Discovery,DiscoveryEvent}` → `boule_transport::overlay::…`.
- in transport-tcp: `crate::p2p::` (remaining) → `crate::`.
- in node: `crate::p2p::` → `boule_transport_tcp::`; `crate::consensus::` →
  `boule_consensus::`; `crate::replication::` → `boule_consensus::replication::`;
  `crate::node::` → `crate::`.
- in consensus: `crate::consensus::` → `crate::`.

Compile order: boule-rs → boule-transport → {boule-transport-tcp, boule-consensus} →
boule-node → boule-cli. Then `cargo fmt --all`, `clippy --all-targets -D warnings`,
`test --locked`, `deny check`.

## Notable consumer-side changes
- `CacheLimits::from_config(&CacheLimitsConfig)` now lives in `consensus::limits`
  (was `config::to_cache_limits`).
- `RateLimitsConfig`/`ConnectionLimitsConfig` `from_config` conversions live with the
  limits types in `boule-transport` (was `config::rate_limits`/`connection_limits`).
- `derive_chain_id` / `derive_chain_id_from_parts` now in `consensus` (was `node`).
- The `#[cfg(test)]` sim/byzantine/crashpoint/wire_fuzz harnesses move to `boule-node`
  (they drive the full node + concrete transport).
