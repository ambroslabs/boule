# Operations

Operational guidance for running an `ambros-p2p` validator. The
[testnet walkthrough](testnet-local.md) covers the local-cluster
driver; this document focuses on production-deployment concerns.

## Running behind NAT (issue #138)

Some operators can dial out but cannot accept new inbound TCP
connections — typically because they sit behind a corporate NAT, an
asymmetric firewall, or a cloud network with a single public load
balancer. `ambros-p2p` supports those operators through **outbound-only
mode**.

### When to use it

Set `[p2p] inbound_disabled = true` if:

- Your validator host's external IP/port is **not** reachable from the
  rest of the cluster.
- You have at least one bootstrap peer (`[overlay] bootstrap_addrs` or
  a `[[peers]]` entry) that **is** reachable. Without that, a node in
  outbound-only mode has nowhere to dial and stays orphaned.

You do **not** need this flag when:

- You run on a public IP / forwarded port — even if behind a firewall,
  if the rest of the cluster can dial you, the default
  (`inbound_disabled = false`) is correct.
- Your operator is behind NAT but can configure a stable inbound port
  via UPnP, VPN, or a tunnel — those are equivalent to inbound-capable
  hosts as far as the overlay is concerned.

### What it does

1. **Skips the TCP listener bind.** The `[node] listen_addr` field is
   still required by the parser, but no socket is opened. Other peers
   that try to dial the host get `ECONNREFUSED` (or `ETIMEDOUT` if a
   firewall silently drops the SYN).
2. **Self-advertises `reachable = false`.** The gossip overlay's
   peer-list publisher injects a self-entry with this flag, so the
   rest of the cluster learns through normal peer-list propagation
   that this node is outbound-only.
3. **Causes other nodes to skip dialing this host.** The partial-mesh
   maintenance loop on every reachable node filters its candidate pool
   to `reachable = true` peers only. Outbound-only validators are not
   counted as candidates for the maintenance-loop's "fill the deficit"
   step, so reachable nodes never waste TCP-connect attempts on hosts
   that would refuse the SYN.

The connection itself is direction-agnostic: once a TLS session is
up, both ends use it for ingress and egress. The frame multiplexer
(see `src/p2p/connection.rs`) forwards application frames to the
manager regardless of which side initiated the TCP connection. So a
node in outbound-only mode dials its bootstrap peer once, and from
that point on the connection carries consensus traffic in both
directions.

### Required configuration

Minimal example for an outbound-only validator that joins via a single
public bootstrap peer:

```toml
[node]
listen_addr = "127.0.0.1:0"   # required by the parser; no listener is bound

[node.identity]
backend = "file"
path    = "/var/lib/ambros-p2p/node.key"

[api]
listen_addr = "127.0.0.1:8000"

[p2p]
inbound_disabled = true        # outbound-only mode

[overlay]
mode             = "gossip"
bootstrap_addrs  = ["public-validator.example.org:7000"]

[consensus]
validators       = [
    "<bootstrap-validator-id>",
    "<this-validator-id>",
    "<peer-2-id>",
    "<peer-3-id>",
]
storage_dir      = "/var/lib/ambros-p2p/consensus"
```

`bootstrap_addrs` may list any reachable validator(s); the gossip
overlay uses that connection as the seed for peer-list discovery. As
soon as the bootstrap peer's peer-list gossip arrives, the
outbound-only node learns about the remaining reachable validators and
opens additional outbound connections to them, up to
`[overlay] target_degree`.

### Two-or-more outbound-only validators

If two validators are both behind NAT and both have
`inbound_disabled = true`, they cannot connect directly — neither has a
listener for the other to dial. The gossip overlay routes consensus
traffic between them through any common reachable neighbour: a unicast
`SendTo` is fanned out over the partial mesh and surfaces upstream at
every receiver, so as long as there is at least one reachable
validator that holds direct connections to both unreachable peers,
they remain in lock-step with the cluster.

This works well when ≤ ~25% of validators are outbound-only. If a
larger fraction needs NAT traversal, add hole-punching (out of scope
for this release).

### Tracking reachability across restarts

`reachable` is a sender-side claim: each node injects its own bit into
the peer-list it publishes, and the table's last-seen-wins merge
ensures that the most recent self-advertisement wins. A node that
flips between reachable and unreachable (e.g. you toggle
`inbound_disabled` and restart) propagates the new value at the next
peer-list-gossip tick (default 5 s). No coordinated config rollout is
needed.

### Verifying the deployment

The integration test
`tests/integration_test.rs::test_inbound_disabled_node_participates_via_outbound_only`
exercises this path locally without docker: it spins up a 4-node
cluster where one node has `inbound_disabled = true`, and asserts
every node — including the unreachable one — commits at steady
state. Skipping the listener bind is in fact a stronger blocker than
an iptables INPUT rule, since there is no socket to connect to at
all, and the test works identically on Linux and macOS.
