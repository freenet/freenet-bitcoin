# Deployment and operations

The live prototype runs on `nova`. Everything below reflects what is actually
deployed, not what would ideally be deployed.

## What is running

| Unit | Purpose |
|---|---|
| `bitcoind-signet` | Pruned signet node. Fully synced; the working demo. |
| `bitcoind-mainnet` | Pruned mainnet node. Long initial block download. |
| `bitcoin-freenet-bridge` | Observes Bitcoin, publishes into Freenet, serves requests on `127.0.0.1:8431`. |

```bash
systemctl status bitcoind-signet bitcoind-mainnet bitcoin-freenet-bridge
journalctl -u bitcoin-freenet-bridge -f
```

## Bitcoin Core

Version 31.1, installed from the official tarball with its SHA256 verified
against the published `SHA256SUMS`, at `/opt/bitcoin-31.1` with symlinks in
`/usr/local/bin`.

Configuration lives in `/etc/bitcoind/{mainnet,signet}.conf`. Two things there
are not obvious and will bite anyone editing them:

- **Network-scoped options must sit inside a `[main]` / `[signet]` section**
  once `chain=` is set. At top level they are a hard startup error, not a
  warning. `rpcbind` is the one that fails first.
- **The RPC cookie is relocated** to `/run/bitcoind-<net>/rpc.cookie`. Bitcoin
  Core creates its network datadir mode 0700 regardless of the service umask,
  so the bridge cannot read a cookie left in the default location. Moving the
  cookie into the unit's runtime directory (`RuntimeDirectoryMode=0750`, group
  `bitcoin`) lets the bridge read it *without* loosening the datadir, which
  also holds wallets.

Low-resource profile, as required:

- `prune=10000` on mainnet, `prune=2000` on signet — bounded block storage.
- **No `txindex`.** Nothing looks up arbitrary historical transactions, and it
  is incompatible with pruning. Adding it would cost tens of gigabytes.
- `dbcache=450`, `par=2`, `maxconnections=24`.
- RPC bound to loopback only; cookie auth, no password in any file.
- `shrinkdebugfile=1`; systemd captures the rest.

### Not disrupting the Freenet gateways on the same box

```ini
Nice=10
IOSchedulingClass=idle
CPUWeight=40
IOWeight=40
MemoryMax=3G
MemoryHigh=2G
CPUQuota=200%
```

Priority alone was not considered sufficient — the memory and CPU ceilings
bound the worst case rather than merely deprioritising it.

Two systemd details worth recording because both cost time:

- **`Type=forking` with `-daemonwait`, not `Type=notify`.** The official release
  binaries are not linked against libsystemd, so `Type=notify` never receives a
  readiness ping and the unit sits in `activating` forever while bitcoind is
  perfectly healthy. `-daemonwait` returns only once init has finished, which
  gives `Type=forking` genuine readiness semantics.
- **`RestrictAddressFamilies` must include `AF_NETLINK`.** libzmq calls
  `getifaddrs()`, which opens a netlink socket; without it bitcoind aborts at
  startup with `Address family not supported by protocol (ip_resolver.cpp:542)`.

## The bridge

Configuration: `/etc/bitcoin-freenet-bridge.toml`. State:
`/var/lib/btcbridge/` (SQLite database, signing key, contract WASM).

```bash
# The id applications must trust to accept this bridge's observations.
bitcoin-freenet-bridge --config /etc/... --print-bridge-id

# Validate config without connecting to anything.
bitcoin-freenet-bridge --config /etc/... --check

# Read an address's observations back OUT of Freenet and re-verify them.
bitcoin-freenet-bridge --config /etc/... --verify <address> --network signet

# Public status: bridge id, tip height, and the tip contract's id.
curl -s http://127.0.0.1:8431/v1/status
```

`--verify` is the honest end-to-end check and worth preferring over reading the
logs. "The PUT returned Ok" only says the local node accepted a write; `--verify`
fetches the contract back from the network, re-verifies every claim against its
own Bitcoin evidence, and prints what a third party could independently
establish.

### Recovery

The database is **operational state, not authoritative**. Delete it and the
bridge rescans and converges to the same contract state, because claims are
keyed by digest and re-publishing one the network already holds is a no-op. The
cost of losing it is bandwidth, never correctness.

Restart safety comes from the chain checkpoint plus recorded block hashes. On
start the bridge compares its recorded hash at the checkpoint height with what
the node reports there now; a mismatch means a reorg happened while it was
down, and it walks back to the fork point and retracts the orphaned outputs.

### Backfilling history on a pruned node

A watch request may carry `scan_from_height`, which rewinds the chain cursor so
a newly-watched script is backfilled rather than only watched going forward.
Rescanning is idempotent, so this costs bandwidth only.

The window is bounded, deliberately. A pruned node has not kept the early chain,
so an unbounded backfill would fail; and on a busy address it would fill the
contract's byte budget with ancient history instead of recent activity.

For an address's *current* balance on a pruned node, `scantxoutset` works
because it scans the UTXO set rather than block history. It finds unspent
outputs only — exactly right for "has this invoice been paid", and wrong for
"show me full history". That limit is accepted rather than worked around by
enabling `txindex`.

## Current deployment status

- **Signet: fully working.** Real third-party payments are being observed,
  published, retrieved and independently verified.
- **Mainnet: syncing.** Initial block download takes many hours. The bridge
  refuses to publish scan watermarks while a node is in IBD, because during IBD
  an absence of payments means nothing and the claim would be misleading.
- **The bridge listens on loopback only, with `auth = open`.**

That last point matters. Making the bridge internet-facing is a deliberate step
that has **not** been taken, and it needs three things first:

1. `auth = { mode = "ghost_key" }`, so the service is not an open invitation to
   make nova scan arbitrary scripts;
2. rate limiting per credential and per source;
3. a reverse-proxy route with TLS (nova already runs caddy).

Leaving an open-auth service exposed would let anyone consume the operator's
disk and CPU. It is a decision for the operator, not a default.
