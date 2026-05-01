# Back-pressure policy

System-wide reference for every queue, channel, and buffer in
`ambros-p2p`. Each entry records what the path carries, the chosen
overflow policy, and *why* — so a future contributor can adjust a
capacity or convert a `try_send` to a `send().await` (or the other way
round) without rediscovering the trade-offs.

This document is the design output of issue #163 (Phase 1 + 2). The
implementation work — wiring overflow counters into status, fixing the
sim's unbounded commit channel, adding a slow-peer disconnect heuristic,
adding the four named back-pressure tests — is tracked separately and
linked at the bottom of this doc.

## The load-bearing principle

> **Must-deliver-or-disconnect** for consensus messages. **Block** when
> back-pressure is the right answer for the data plane. **Drop with
> a counter** for best-effort overlays where multiple delivery paths
> exist. **Never block consensus on observability.**

Silently dropping a vote or QC re-creates exactly the f=1 liveness
regression that PR #129 fixed: progress halts and the failing peer
isn't even logged as the culprit. Blocking *forever* on a slow peer
wedges the cluster — one bad peer ⇒ no progress. The middle ground
is a bounded queue that, once full, surfaces the problem (counter +
warn) and uses disconnect as the escape valve.

Three policies cover every path in the system today:

| Policy             | When to use                                                    | Mechanism                                |
|--------------------|----------------------------------------------------------------|------------------------------------------|
| **Block**          | Receiver loss ⇒ correctness violation (persist, single-task pipelines) | `mpsc::Sender::send().await` on a bounded channel |
| **Block+disconnect** *(target)* | Per-peer outbound for must-deliver consensus messages | Bounded queue → block briefly → disconnect peer if a stall threshold is exceeded |
| **Drop + counter** | Best-effort overlays with multiple delivery paths (gossip, peer-list) | `try_send`; on `Full` increment a counter and `warn` |

The "block+disconnect" target landed in #486 + #490: the per-peer
outbound `write_tx` (`p2p::manager`) drops on `Full`, increments a
shared overflow counter, and tracks per-peer overflow timestamps in a
sliding window; once a peer accumulates one full channel-worth of
overflows inside the window the manager kicks it via the same cleanup
path `PeerCommand::Disconnect` performs.

## Per-path table

Every flow-control mechanism in production code, grouped by
component. Capacities are quoted from the production allocation site;
test fixtures with smaller channels do not appear here.

### P2P transport

| Path | File:line | Type | Capacity | Send-side on full | Policy | Rationale |
|------|-----------|------|----------|-------------------|--------|-----------|
| Per-peer outbound bytes (`write_tx`) | `p2p/manager.rs:326,351` | `mpsc<Bytes>` | 64 | `try_send` → drop + counter + warn; per-peer slow-peer tracker → disconnect after `SLOW_PEER_OVERFLOW_THRESHOLD` (=64) overflows in `SLOW_PEER_OVERFLOW_WINDOW` (=10s) | **Drop + counter + slow-peer disconnect** | Carries every consensus and overlay message destined for one peer. Drops on `Full` increment a single shared counter (`ConsensusStatus.backpressure.peer_outbound_overflow_total`) and a per-peer sliding-window tracker. A peer that accumulates one full channel-worth of consecutive drops within the window is kicked via the same cleanup `PeerCommand::Disconnect` performs — the must-deliver-or-disconnect contract's escape valve. Closed-channel failures are not counted. (#486 + #490.) |
| Per-peer inbound (`internal_tx`) | `p2p/manager.rs:472` | `mpsc<ManagerMsg>` | 64 | `send().await` (`p2p/connection.rs:64`) | **Block** | Connection task back-pressures the read loop; a slow manager naturally throttles all peers. The manager is single-threaded so this is safe — it cannot starve one peer for another. |
| Manager command channel (`cmd_tx`) | `p2p/manager.rs:471` | `mpsc<PeerCommand>` | 16 | `send().await` | **Block** | Used for `RegisterProtocol`/`Disconnect`/`ListPeers`. Not on the data plane. |
| `peer_gone` broadcast | `p2p/manager.rs:473` | `broadcast<NodeId>` | 16 | broadcast::send (lagging receivers see `Lagged`) | **Drop on lag (best-effort)** | Subscribers re-poll `known_peers()` to recover from a `Lagged` error. |
| `discovery` broadcast | `p2p/manager.rs:474` | `broadcast<DiscoveryEvent>` | 16 | broadcast::send | **Drop on lag (best-effort)** | Same recovery pattern as `peer_gone`. |

### P2P protocol multiplex

| Path | File:line | Type | Capacity | Send-side on full | Policy | Rationale |
|------|-----------|------|----------|-------------------|--------|-----------|
| `ProtocolHandle::event_rx` (manager → consensus inbound) | `p2p/manager.rs:214` | `mpsc<ProtocolEvent>` | 256 | `send().await` (`p2p/manager.rs:180`) | **Block** | Carries decoded consensus messages from the manager into the consensus run loop. The manager blocks here, which fans back through the per-peer inbound and ultimately stalls the read loop on each peer — full back-pressure. |
| `ProtocolHandle::send_tx` (consensus → manager outbound) | `p2p/manager.rs:215` | `mpsc<ProtocolOutbound>` | 256 | `send().await` (consensus side) | **Block** | Used by the safety-action loop to enqueue Broadcast / SendTo. The forwarding loop on the manager side then awaits `internal_tx.send` so back-pressure flows all the way to consensus. |
| Per-peer disconnect notifications | `p2p/manager.rs:169,257,370` | (uses the protocol's `event_tx`) | (256, shared) | `try_send` → drop silently | **Drop (intentional)** | Control-plane events; if the protocol's event channel is full of in-flight messages, the next data-plane message and ensuing reconnect attempt will surface the disconnect anyway. |

### P2P overlay (gossip)

| Path | File:line | Type | Capacity | Send-side on full | Policy | Rationale |
|------|-----------|------|----------|-------------------|--------|-----------|
| Overlay sink to peer | `p2p/overlay/gossip/sink.rs:64` | wraps `ProtocolHandle::send_tx` | 256 | `try_send` → drop + counter + warn | **Drop + counter** | Used by the peer-list maintenance loop and gossip forwards. Multiple delivery paths exist (peer-list pushes repeat at the next interval; mesh forwards have N>1 hops), so one drop is recoverable. Counter (#486) is wired through `node.rs` into `ConsensusStatus.backpressure.gossip_sink_overflow_total`; the closed-channel path is intentionally not counted (manager-shutdown noise would mask real back-pressure). |
| Gossip dedup ring | `p2p/overlay/gossip/dedup.rs` | `IndexMap` (FIFO) | configurable | FIFO eviction at capacity, lazy TTL purge | **Bounded with eviction** | Content store rather than flow-control queue; cap is sized for expected gossip diameter × fan-out. |
| Discovery events | `p2p/overlay/gossip/discovery.rs:94` | `broadcast<DiscoveryEvent>` | configurable | broadcast::send | **Drop on lag** | Subscribers re-poll on `Lagged`. |
| Overlay command queue | `p2p/overlay/gossip/overlay.rs:288` | `mpsc<OverlayCmd>` | configurable | `send().await` | **Block** | Internal coordination; not data-plane. |

### Consensus

| Path | File:line | Type | Capacity | Send-side on full | Policy | Rationale |
|------|-----------|------|----------|-------------------|--------|-----------|
| View-timer events | `consensus/node/mod.rs:820` | `mpsc<View>` | 4 | `send().await` | **Block** | Single-producer (`ViewTimer`); the run loop drains promptly. A backlog ⇒ pacemaker is starved, which is itself a bug we want to surface, not paper over. |
| Safety-action persist | `consensus/node/action_interpreter.rs:395,598` | direct call to `persist_updates` | n/a (synchronous) | propagates `?` error | **Block (synchronous)** | Persist-before-send is the durability invariant for HotStuff safety. There is *no* queue between the safety core and storage; the run loop awaits the storage write inline. A storage error currently returns up the stack and aborts the run loop, which is correct — see `docs/storage-durability.md`. |
| Safety-action outbound | via `Broadcaster` trait → `ProtocolHandle::send_tx` | `mpsc<ProtocolOutbound>` | 256 | `send().await` | **Block** | Outbound consensus messages back-pressure the action loop, which back-pressures the safety core, which is exactly the right behavior. |
| `ConsensusStatus` watch | `consensus/api.rs:185` | `watch<Arc<ConsensusStatus>>` | 1 | replace-and-publish | **Latest-wins** | Status is a snapshot, not an event log. Receivers always observe the most recent value; intermediate states are intentionally collapsible. |

### Mempool

| Path | File:line | Type | Capacity | Send-side on full | Policy | Rationale |
|------|-----------|------|----------|-------------------|--------|-----------|
| In-memory mempool | `replication/impls/mem_mempool.rs:34` | `VecDeque` behind a `Mutex` | configurable (`max_size`) | returns `Err` to caller on full (line 59-65) | **Reject + counter** | Caller (the application driving `submit`) chooses whether to retry or surface the rejection up. Consensus continues regardless. |

### Storage

The on-disk WAL (`storage/disk.rs`) and the in-memory backend
(`storage/memory.rs`) both expose synchronous `put` / `get` /
`commit_batch` calls. There is **no internal queue** — every write
serializes on the storage trait's lock. This is intentional: persist
ordering is a HotStuff safety invariant, and a queue would either
have to preserve ordering (then it's just a serialization point with
extra latency) or it would be unsafe.

### Sim

| Path | File:line | Type | Capacity | Send-side on full | Policy | Rationale |
|------|-----------|------|----------|-------------------|--------|-----------|
| Per-node event mailbox (data plane) | `consensus/sim.rs:713,1328` | `mpsc<ProtocolEvent>` | 1024 | `send().await` (`consensus/sim.rs:1817,1843`) | **Block** | Mirrors the production `event_rx` policy: a slow consumer back-pressures the route task. Capacity is sized far above any realistic per-tick burst. |
| Per-node mailbox (PeerConnected / PeerDisconnected) | `consensus/sim.rs:1013,2177,2449` | shares the data-plane mailbox | 1024 | `try_send` → drop silently | **Drop (intentional)** | Control-plane events on the kill / wire-up path. Fire-and-forget by design — we don't want a wedged survivor's mailbox to gate the death of another node. |
| Commit notifier | `consensus/api.rs::MpscCommitNotifier`, allocated in `consensus/sim.rs` | `mpsc::Sender<Block>` | `SIM_COMMIT_CHANNEL_CAP` (4096) | `try_send` → drop + counter increment + warn | **Drop + counter** | Pre-#485 was unbounded — tests that didn't drain `commit_rxs` accumulated committed blocks indefinitely in RAM. Now the cap is large enough that any healthy test stays at zero overflows; if a test wedges its receiver the harness can poll `SimCluster::total_commit_overflows()` to surface the cause instead of OOMing. |

### Rate-limiter / connection-limiter state

These aren't flow-control queues but they accumulate per-peer or per-IP
state, so they're worth recording.

| Structure | File:line | Eviction | Worry? |
|-----------|-----------|----------|--------|
| Per-peer rate-limit state | `p2p/limits.rs:482` | Lazy purge of stale entries on every check | Theoretically unbounded under sustained connect-spam from new IPs; #134 covers the rate-limit policy and the per-IP cap is the practical bound. |
| Per-IP rate-limit state | `p2p/limits.rs:671` | Lazy purge | Same caveat as above. |
| Protocol cap registry | `p2p/manager.rs:91` | None (one entry per registered protocol) | Bounded by protocol count (~3 today); fine. |

## Known gaps

The audit identified three gaps that are tracked as sub-issues of #163:

- ~~**#485** — Sim commit channel is unbounded.~~ Landed: bounded
  at [`SIM_COMMIT_CHANNEL_CAP`](../src/consensus/sim.rs); the
  notifier increments a per-node overflow counter on drop, surfaced
  in `SimCluster::total_commit_overflows()`.
- **#486** (closed) — counters wired for both the gossip sink
  (`backpressure.gossip_sink_overflow_total`) and the per-peer outbound
  `write_tx` (`backpressure.peer_outbound_overflow_total`) via a
  single shared counter on every `ProtocolHandle`. The production
  consensus event channel uses `send().await` (block-on-full), so it
  doesn't need a counter.
- ~~**#490** — Slow-peer disconnect heuristic for per-peer outbound.~~
  Landed: `p2p/manager` tracks a per-peer sliding window of overflow
  timestamps; once a peer hits `SLOW_PEER_OVERFLOW_THRESHOLD` overflows
  inside `SLOW_PEER_OVERFLOW_WINDOW`, the manager kicks it with the
  same cleanup path `PeerCommand::Disconnect` performs.
- **Phase 4 sim primitives** — slow-node and slow-disk primitives for
  `SimCluster` so the four named tests in #163 (slow peer, slow disk,
  sync flood, tracing burst) can be expressed deterministically.
  Filed as a follow-up after the metrics land.

## Cross-references

- **#129** — vote broadcast fix. The bug it patched was effectively a
  silent drop of votes via routing-to-dead-peer; this policy makes
  that class of bug detectable via overflow metrics (#486).
- **#134** — per-peer rate limiting + connection caps. Caps inbound
  *rate*; this doc covers the *backlog* policy. They compose: rate
  limit shapes the inflow; back-pressure handles whatever fits
  through.
- **#135** — bounded caches with eviction. Orthogonal: those are
  content stores (block cache, vote pool), not flow-control queues.
- **#137** — gossip overlay. Once richer fanout lands, gossip should
  respect per-peer back-pressure (skip slow peers in fanout) rather
  than blocking the broadcast — the overlay sink's `try_send` policy
  is already aligned with that direction.
- **`docs/storage-durability.md`** — the persist-before-send
  invariant referenced in the consensus table.
