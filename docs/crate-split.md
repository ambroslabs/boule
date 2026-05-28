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
  (`to_cache_limits` → consensus, `rate_limits`/`connection_limits` → transport);
  the `DEFAULT_*` limit constants move down from `consensus::limits` into `config`.

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

## Notable consumer-side changes
- `CacheLimits::from_config(&CacheLimitsConfig)` now lives in `consensus::limits`
  (was `config::to_cache_limits`).
- `RateLimitsConfig`/`ConnectionLimitsConfig` `from_config` conversions live with the
  limits types in `boule-transport` (was `config::rate_limits`/`connection_limits`).
- `derive_chain_id` / `derive_chain_id_from_parts` now in `consensus` (was `node`).
- The `#[cfg(test)]` sim/byzantine/crashpoint/wire_fuzz harnesses move to `boule-node`
  (they drive the full node + concrete transport).
