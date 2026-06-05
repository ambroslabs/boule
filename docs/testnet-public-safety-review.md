# Public testnet safety review (#809)

Final adversarial safety review of the assembled boule MVP public testnet,
before it is exposed to the open internet. This is an **assessment of the new
public surface and its integration seams**, not a from-scratch re-audit.

- **Model:** trusted validator set (permissionless discovery / Sybil /
  reputation / gossipsub are explicitly out of scope), but **public
  non-validating full nodes connect, and a public eth JSON-RPC + faucet are
  exposed to the open internet**.
- **Already reviewed elsewhere (referenced, not redone):** EL write-path /
  slashing / weighted-quorum threat model (#768); consensus-core adversarial
  review ("2026-04-29 AI Security Audit", #420–#428); live Byzantine-injection
  slashing harness (#685); continuous-reconfig leader-integrity machinery
  (#797–#799, residual tracked in #800/#801).

## Go / no-go

**NO-GO as currently generated** — two MUST-FIX items expose the open internet
to validator-set griefing and to reth's unguarded operator RPC. Both are in the
*deployment/contract* layer, not the consensus core; the consensus core, the
handshake/connection DoS caps, the admin/public listener split, and the
faucet/proxy *policy* code are sound. With the two MUST-FIX items resolved (each
is a small, localized change), the testnet is **GO** under the trusted-set
assumptions listed at the end.

## Findings (severity-sorted)

| # | Severity | Area | File:function | Attack | Fix |
|---|----------|------|---------------|--------|-----|
| 1 | **MUST-FIX** | Staking griefing | `crates/boule-reth/contracts/Staking.sol:withdraw` | `withdraw(bytes32 nodeId, uint256 amount)` is **fully unauthenticated**: any internet user (gas from the faucet) can call it for **any** validator's `nodeId`. boule reads the `Withdraw` log via `eth_getLogs` and applies it as an unbond against that validator's `BondedStakeLedger`, saturating weight at zero — removing validators from the active set and attacking liveness/safety from the open internet. | Gate `withdraw` (system-account/`onlyWriter`, or bind to a `msg.sender`→`nodeId` authorization), **or** drop the `Staking` predeploy from the public-testnet genesis entirely (genesis-seeded weights need no user `withdraw` for the MVP). The issue (#809) flags this exact vector. |
| 2 | **MUST-FIX** | reth RPC exposure | `crates/boule-reth/render-run-tooling.sh` (docker-compose branch, lines 48–56) | The generated `docker-compose.yml` launches reth with `--http.addr 0.0.0.0 --http.api eth,net,web3,txpool,admin` **and publishes `httpport:httpport` to the host**, with **no `eth-rpc-proxy` in front**. So reth's raw RPC — including the `admin_*` and `txpool_*` namespaces — is reachable on the host's public interface, defeating the entire `rpc_proxy.rs` allow-list design. (`admin_addPeer`, `txpool_content`, etc. are open.) | In the compose path: bind reth to `127.0.0.1`, drop `admin,txpool` from `--http.api` (leave `eth,net,web3`), do not publish `httpport` to the host, and front reth with the `eth-rpc-proxy` service (publish only the proxy's port). The systemd / `run-local.sh` paths already bind `127.0.0.1` — but they too should drop `admin,txpool` from `--http.api`. |
| 3 | should-fix | Public info exposure | `crates/boule-node/src/lib.rs` public listener (merges `p2p::api::router` + `boule_consensus::api::router`) | The **public** API listener serves `GET /consensus/status` (the full `ConsensusStatus`: node id, peer node-ids, validator set + keys, high-QC, internal vote/timeout buckets, delinquent validators) and `GET /peers` (peer node-ids) to anonymous internet users. No private keys or IPs leak (node-ids/validator-keys are public in a trusted-set genesis), so this is not a key/IP disclosure — but it hands attackers detailed live internal consensus state and a peer-enumeration oracle. | Move `/consensus/status` and `/peers` to the **admin** listener; keep only `/metrics /health /ready` on the public listener (those already emit counts, not identities). Alternatively gate them behind the admin bearer token. |
| 4 | should-fix | Faucet correctness / drain | `crates/boule-reth/src/faucet.rs:FaucetService::drip` (+ `eth_public.rs:faucet_handler`) | The per-address cooldown lock is released before `drip()` runs (by design, "submit outside the lock"), and `drip()` itself has **no nonce serialization**: two concurrent requests for two different recipients both read the same `pending` nonce N, both build a tx with nonce N, and one is dropped/replaced by reth (nonce-too-low / replacement-underpriced). Under load the faucet silently under-delivers or returns `BAD_GATEWAY`; a stuck nonce can wedge it. Not a fund-drain (per-address cooldown + fixed drip bound the amount), but a reliability/availability hole on a public faucet. | Serialize submission: hold a `tokio::Mutex` (or an in-process monotonically-incrementing nonce counter seeded from `pending` once) across `pending_nonce()` + `eth_sendRawTransaction` so concurrent drips get distinct nonces. |
| 5 | should-fix | Body-cap ordering | `crates/boule-node/src/eth_public.rs:rpc_proxy_handler` / `faucet_handler` | The proxy's `max_body_bytes` (256 KiB) is checked only **after** axum buffers the whole `Bytes` body, and the routers set no `DefaultBodyLimit`, so axum's 2 MiB default bounds the transient. An attacker can force a 2 MiB buffer per request before the 256 KiB rejection. Bounded by the per-IP rate limiter, so it is a minor amplification, not a DoS. | Add `axum::extract::DefaultBodyLimit::max(cfg.max_body_bytes)` as a router layer so oversized bodies are rejected at the framing layer before buffering. |
| 6 | should-fix | Handshake→admit gap | `crates/boule-transport-tcp/src/listener.rs:handshake_inbound` vs `ConnectionLimiter` (in the manager) | The `HandshakePermit` is released when `handshake_inbound` returns (right after `manager_tx.send(NewConnection)`), but `ConnectionLimiter::try_admit` runs later in the manager. There is a brief window where a completed-TLS connection is neither charged to the handshake limiter nor yet to the connection limiter. It is bounded by `max_inflight` (256) + the manager channel's backpressure, so it is not exploitable into an unbounded backlog, but the seam exists. | Acceptable for MVP given the bounds; if tightened later, hold the permit until the manager confirms `try_admit`, or have the manager reject-and-close on cap overflow (it already does — confirm the close path frees the socket promptly). |
| 7 | acceptable-MVP | Public RPC allow-list | `crates/boule-reth/src/rpc_proxy.rs:ALLOWED_METHODS` / `is_allowed` | Deny-by-default allow-list; `admin_*`/`debug_*`/`txpool_*`/`engine_*`/`personal_*`/`eth_sendTransaction` are all rejected (unit-tested). Batch size, method check, and per-IP rate limit are all enforced **before** the upstream call; the limiter `gc`s on every request so the map stays bounded; XFF is deliberately **not** trusted. Sound — *provided the proxy is actually the single public ingress* (see MUST-FIX #2). | None. The policy layer is correct; the gap is purely that the deployment tooling bypasses it. |
| 8 | acceptable-MVP | Faucet key + drain | `crates/boule-node/src/bin/faucet.rs`, `faucet.rs:RateLimiter` | Signing key is read from `FAUCET_PRIVATE_KEY` env, parsed, and **only the address is ever logged** (never the key). Per-address cooldown (24h) is the primary anti-drain (fixed drip ⇒ bounded per address), per-IP cap (5/hr) blunts address-rotation; `gc` bounds both maps. A dry faucet account returns `BAD_GATEWAY` (drip reverts), which is a graceful, non-crashing failure. | None for MVP. Address-rotation behind many IPs can still slowly drain a public faucet — inherent to faucets; the genesis prefund + drip size bound the blast radius. |
| 9 | acceptable-MVP | Admin isolation | `crates/boule-node/src/admin_api.rs`, `observability.rs` | Two-listener split is correct: privileged routes (`/admin/rotate-key`, `/mempool/submit`) live **only** on the admin listener (test: public router 404s them); bearer auth uses a length-aware **constant-time** compare and wraps **every** admin route via middleware. `gen-testnet.sh` binds the admin listener to `127.0.0.1` regardless of `HOST` (default-safe) and documents `auth_token_env` + firewall. Triggering a rotation without auth is at worst a self-inflicted liveness fault (needs *this* node's current key to forge the tx), not key theft. | None. Operators MUST still set `auth_token_env` if they ever bind the admin listener off-loopback. |
| 10 | acceptable-MVP | Handshake/connection DoS caps | `crates/boule-core/src/transport/limits.rs` | Pre-handshake `HandshakeLimiter` (global 256, per-IP 4, 10s timeout) bounds half-open/slowloris floods *before* TLS work; RAII permit frees the slot on every exit path (success/error/timeout) — listener test confirms a stalled handshake times out and frees its slot. Post-handshake `ConnectionLimiter` (inbound 512, per-IP 8, plus `max_total`) layers on top. Public-sized defaults are sane for a public edge. | None. |
| 11 | acceptable-MVP | Genesis / totalWeight=0 | `crates/boule-reth/src/genesis.rs`, `bin/gen-testnet-genesis.rs`, `gen-testnet.sh` | Seeding fails **closed** if the Registry predeploy is absent (`NoRegistryAlloc`). The operator-facing CLI guards `weight > 0` per validator **and** `!validators.is_empty()`, so `totalWeight=0` cannot ship through the supported path. chain-id is required (`--chain-id`); prefund/faucet account is a plain `--prefund` entry. | None (operator path is safe). Defense-in-depth follow-up: have the library `build_deployment_genesis` itself reject an empty validator set / zero total weight, so a future non-CLI caller can't ship an inert chain. |
| 12 | acceptable-MVP | Halt-aware readiness (#649) / restart-after-reconfig (#815) | `crates/boule-node/src/observability.rs:HealthView`, consensus history-rebuild (#815/#816 on this base) | `/ready` flips to 503 once `current_view` runs `> HEALTHY_VIEW_LAG (8)` ahead of `last_committed_view` (halt detected) and requires `committed_progress`; cold start is "healthy view, not ready" (no false-ready). A follower that is merely behind also drains (intended). No false-healthy signal found. The #815 weighted-genesis history-rebuild fix is on this base and its tests pass. | None. |
| 13 | acceptable-MVP (residual, tracked) | Continuous-reconfig integrity (#800/#801) | weight-proof / vote-time-validation machinery | The #797–#799 leader-integrity machinery (vote-time validation + receipt-inclusion proofs) exists because of continuous per-block reconfig; its residual risk surface is the same on a public testnet as on a private one and is **already covered** by #768 / #797 / #420–#428. Under the trusted validator set, a public RPC user cannot forge a BLS quorum, so they cannot make a full node serve non-canonical state (see #802 note below). | Out of scope here; tracked in #800/#801. Do not redo the #797 design review. |

## Non-validating full-node trust (#802)

A full node verifies each block's QC against the **trusted** validator set + BLS
keys and applies the same QC-certified, deterministically-executed (reth) blocks
the validators do. A malicious *peer* cannot feed it non-canonical state without
forging a ⅔-weight BLS quorum from the trusted set, which the trusted-set
assumption rules out. So the state a full node serves over public RPC is the
canonical chain state. The deferred-execution app-hash divergence check is the
validators' responsibility (surfaced as `state_divergence_detected`); a full
node trusts the committed ordering. **Acceptable for the trusted-set MVP** and
consistent with #768 / the "no validate/execute before vote" design.

The one caveat that turns this from theory into an attack is **MUST-FIX #1**:
the unauthenticated `Staking.withdraw` lets a public user *legitimately commit*
a validator-set delta (an unbond) — the full node correctly serves it, but the
delta itself is adversary-controlled. The fix belongs at the contract, not the
full-node trust model.

## Trusted-set assumptions this review relies on

- The genesis validator set + their BLS keys are honest and ≥ ⅔ weight is
  non-Byzantine (the consensus safety guarantee; reviewed in #420–#428).
- Operators keep the **admin listener** and the **reth Engine API (`:8551`)**
  off the public internet (loopback or firewalled). The generated systemd /
  `run-local.sh` tooling honors this; MUST-FIX #2 is where the compose path
  violates it for the *eth* RPC.
- Operators set `auth_token_env` on any admin listener not bound to loopback.
- The faucet's funding key is supplied via env and its genesis prefund is sized
  for expected drip volume.

## Inline hardening applied in this PR

None beyond this document. The two MUST-FIX items and the should-fix items are
each more than a one-line constant change and touch deployment tooling / a
genesis contract, so per the review scope they are **deferred to follow-up
issues** rather than bundled into this docs-only review PR:

- **#809-F1 (MUST-FIX):** authenticate or remove `Staking.withdraw` on the
  public testnet genesis.
- **#809-F2 (MUST-FIX):** stop the generated docker-compose from publishing
  reth's raw `admin,txpool`-enabled RPC; bind reth loopback + front it with the
  `eth-rpc-proxy`; drop `admin,txpool` from `--http.api` everywhere.
- **#809-F3 (should-fix):** move `/consensus/status` + `/peers` off the public
  listener.
- **#809-F4 (should-fix):** serialize faucet nonce allocation.
- **#809-F5 (should-fix):** add an explicit `DefaultBodyLimit` to the proxy +
  faucet routers.
- **#809-F6 (defense-in-depth):** reject empty/zero-weight validator sets in
  `build_deployment_genesis` itself.
