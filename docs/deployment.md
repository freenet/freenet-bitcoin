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

### The temporary IBD profile (applied 2026-09-04, REVERTED the same day)

Mainnet's initial block download is running under a deliberately looser
profile, because the conservative numbers above were throttling it hard: the
unit sat pinned at its 2 GB `MemoryHigh` with `dbcache=450`, while the host had
82 GB free and 16 cores at 18% load. `dbcache` dominates IBD — it is the
in-memory UTXO cache, and at 450 MB the node flushes to disk constantly.

Applied to **mainnet only**, and **already reverted** — this section is kept as
the record of what the numbers bought, not as a live instruction:

```ini
dbcache=4000          # was 450
par=6                 # was 2
MemoryHigh=6G         # was 2G
MemoryMax=8G          # was 3G
CPUQuota=600%         # was 200%
IOSchedulingClass=best-effort   # was idle
IOSchedulingPriority=6
```

`idle` was the worst of these: it means the process gets disk only when nothing
else wants any, which on a shared box is close to starvation. `best-effort` at
priority 6 still yields to the gateways without being starved. `Nice=10` is
unchanged, so it stays deprioritised for CPU.

**Revert once `initialblockdownload` is false.** Steady-state observation needs
none of this, and the conservative numbers are the right ones for a box shared
with the Freenet gateways:

```bash
sudo sed -i 's/^dbcache=4000$/dbcache=450/;s/^par=6$/par=2/' /etc/bitcoind/mainnet.conf
sudo sed -i 's/^MemoryHigh=6G$/MemoryHigh=2G/;s/^MemoryMax=8G$/MemoryMax=3G/;\
s/^CPUQuota=600%$/CPUQuota=200%/;s/^IOSchedulingClass=best-effort$/IOSchedulingClass=idle/;\
/^IOSchedulingPriority=6$/d' /etc/systemd/system/bitcoind-mainnet.service
sudo systemctl daemon-reload && sudo systemctl restart bitcoind-mainnet
```

Check it is safe to revert with:

```bash
sudo -u bitcoin bitcoin-cli -conf=/etc/bitcoind/mainnet.conf \
  -datadir=/var/lib/bitcoind/mainnet getblockchaininfo | grep initialblockdownload
```

Two systemd details worth recording because both cost time:

- **`Type=forking` with `-daemonwait`, not `Type=notify`.** The official release
  binaries are not linked against libsystemd, so `Type=notify` never receives a
  readiness ping and the unit sits in `activating` forever while bitcoind is
  perfectly healthy. `-daemonwait` returns only once init has finished, which
  gives `Type=forking` genuine readiness semantics.
- **`RestrictAddressFamilies` must include `AF_NETLINK`.** libzmq calls
  `getifaddrs()`, which opens a netlink socket; without it bitcoind aborts at
  startup with `Address family not supported by protocol (ip_resolver.cpp:542)`.

## Deploying: one command, because two is the bug

```bash
cargo make deploy            # scripts/deploy.sh
cargo make deploy --dry-run  # build and check, change nothing
```

A contract's address is `BLAKE3(BLAKE3(wasm) || params)`, so the code is part
of the address. The bridge writes observations to an address derived from the
WASM under `/var/lib/btcbridge/contracts`; the webapp derives one from the WASM
it was built with. Deploy those on different days, from different trees, or
from a `target/` that has drifted, and they derive different addresses — and
**nothing errors**. The webapp reads a contract nobody writes to and renders
what it renders for an address that has never been paid.

So the script builds the contracts once, into a throwaway target directory, and
installs those exact bytes into both places. It refuses to publish if the two
disagree where they finally sit, and refuses to replace a generation that
`legacy/` does not record as outgoing.

The throwaway target directory is required rather than careful: a long-lived
`target/` changes a contract's identity, because `cargo clean -p` of the
workspace crates still reuses dependency artifacts and under fat LTO those
yield a different module. Two fresh clones of one commit agreed with each other
and disagreed with a working tree, which is how that was found.

## Generation pointers: how a reader survives a re-key

The bridge signs a **pointer record** naming the code hash it publishes to, at
an address derived from its own signing key plus `freenet-migrate`'s frozen
pointer contract. The bridge key is the only thing here that survives a
rebuild — everything derived from WASM moves — so it is the only usable anchor,
and it is one applications already name explicitly and already trust for every
fact they display.

A reader knowing only the bridge id computes the pointer's address offline,
reads the code hash, and derives the real contract from that instead of from
whatever WASM it shipped. When the two differ the webapp follows the bridge and
says so; when the pointer cannot be read it falls back to its own generation
and says *that*, naming what it is reading. The one thing it never does is show
an empty page with no explanation.

```bash
# What is installed, where its pointers live, and what they currently say.
sudo -u btcbridge /usr/local/bin/bitcoin-freenet-bridge \
  --config /etc/bitcoin-freenet-bridge.toml --print-generation
```

Run it after installing new contract WASM. A mismatch is a line of output
rather than an application rendering a blank page.

## What is deployed

| Thing | Where |
|---|---|
| Webapp | contract `6s9q7nSCmPrHY85RfPjQpdHo7WTFabDCTtsJAzHXfuLN`, signing key `freenet-bitcoin` (`fdev website list`) |
| Bridge id | `4MZnDAQWccEWXBUb1wt4iTEkDi6Z2MCcZ9WQN1umRsVL` |
| Address-contract pointer | `C1cTJXmyZ9EMDMKwTEMTSq2PNwoMNhrKWrnzWK2XbcKV` |
| Tip-contract pointer | `G9brbHSKXEdFZW8jKtfMHYT2GcrvJH6jhebkykN35mo9` |

The webapp is republished **in place** with `fdev website update --key
freenet-bitcoin`, never `publish`: the contract id is the app's URL, and
`publish` would mint a new one and orphan every link to this one. The pointer
addresses are fixed for the life of the bridge key; the contract ids they name
move on every re-key and are deliberately not written down here.

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
own Bitcoin evidence, and prints what a third party reading that contract would
conclude. It confirms the round trip and the evidence's self-consistency; it
does not confirm the blocks are on Bitcoin, which stays this bridge's assertion
(see [trust-boundaries.md](trust-boundaries.md)).

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
  published, retrieved and re-checked against their own evidence.
- **Mainnet: synced and observing.** Initial block download finished
  2026-09-04. The bridge publishes mainnet's chain tip and recent blocks and
  watches **no mainnet address**, deliberately: observations about a specific
  address are somebody's real money published to a permanent, replicated
  network, so which addresses to watch is an operator decision rather than a
  default. Mainnet therefore shows a live tip and no payments, and the webapp
  says why rather than leaving that to look like a fault. The bridge still
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

#### What it bought, measured

Worth recording because the first diagnosis was wrong. The unit was pinned at
its `MemoryHigh` with `dbcache=4000` — the two settings were mutually
incompatible, and the kernel was throttling the process into continuous direct
reclaim: **27.8 million `memory.events high` and 4.19 billion `pgscan_direct`**,
against 1,178 scans for ordinary background reclaim. It was spending its time
fighting a ceiling rather than verifying blocks.

Raising the ceiling to match the cache took sync from **0.0145 to 0.044
progress/hour** (about 3x), and the run finished the same evening rather than
the following day. Anon memory settled at 5.2 GB with the file cache elastic
above it — so the working set genuinely needed the room, and the earlier 6 GB
limit was cutting into it rather than into cache.

**The lesson worth keeping:** `dbcache` and `MemoryHigh` have to be set as a
pair. Raising one without the other is worse than leaving both alone, because a
cache the process is not allowed to hold turns into reclaim pressure instead of
throughput.

Reverted 2026-09-04 once `initialblockdownload` went false. Steady-state
observation sits at about 1.4 GB, well inside the 2 GB `MemoryHigh`, so the
conservative numbers are the right ones for a box shared with the gateways.
