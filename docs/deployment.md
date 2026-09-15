# Deployment and operations

The live prototype runs on `nova`. Everything below reflects what is actually
deployed, not what would ideally be deployed.

## What is running

| Unit | Purpose |
|---|---|
| `bitcoind-signet` | Pruned signet node. Fully synced; the working demo. |
| `bitcoind-mainnet` | Pruned mainnet node. Long initial block download. |
| `bitcoin-freenet-bridge` | Observes Bitcoin, publishes into Freenet, reads its request inbox. No network listener. |

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

### Never `cargo build` a contract directly

Use `scripts/build-contracts.sh` (which `cargo make build-contracts`, CI and
the deploy script all call). It passes `--remap-path-prefix` for `CARGO_HOME`,
`RUSTUP_HOME` and the repository root, and then refuses if any build-machine
path survived into the bytes.

That is not tidiness. Release binaries embed panic locations as `file:line`,
and for dependencies those are absolute, so before 2026-09-04 every contract
this project shipped had `/home/ian/.cargo/registry/...` compiled into it — and
a build on any other machine was a **different contract**. Nobody could verify
what was deployed. The flags are therefore part of a contract's identity, and a
build that skips them silently produces a different one.

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

`fdev website list` also shows a key named **`btc-drift-proof`**, contract
`2L6y7hoEXnMbPXaiTpa3ZbdUoArcoHNYBjmRrLscakAK`. It is not a deployment. It is a
one-off copy of the app built against deliberately-wrong contract WASM,
published on 2026-09-04 to demonstrate in a real browser that the divergence
notice fires and that the page still shows live data by following the bridge's
pointer. Do not update it and do not link to it.

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

**One row is not like the others: `pointer_versions`.** A generation pointer is
accepted only if it supersedes the record already published, so its version
counter must be monotonic across restarts. Deleted along with everything else,
that counter restarts at 1, every write is refused as stale, and the pointer
silently freezes at whatever generation it last named — pointing every reader
at contracts the bridge no longer writes to. That is the failure the pointer
exists to prevent, reintroduced by following the paragraph above.

The bridge handles this itself and needs no special procedure: before writing,
it reads the standing record back off the network and adopts its version
whenever that record verifies under the bridge's own key. So deleting the
database is still safe. It is called out because the reasoning is not obvious
from the sentence above it, and because anyone tempted to "simplify" that
read-back would be removing the only thing that makes this paragraph true.

Restart safety comes from the chain checkpoint plus recorded block hashes. On
start the bridge compares its recorded hash at the checkpoint height with what
the node reports there now; a mismatch means a reorg happened while it was
down, and it walks back to the fork point and retracts the orphaned outputs.

### The request inbox

The bridge has no network listener. A client asks it to watch a script by
appending a Ghost Key signed request, sealed to the bridge, to its inbox
contract. The bridge reads the inbox over its own connection to the local node,
acts on each request, and removes it with a signed removal batch. On first start it
opens the inbox itself, by PUTting it with its first floor, and logs the
contract id as `serving the request inbox`.

- **Mainnet must be configured.** Requests are dated by Bitcoin mainnet block
  height whichever network they are for, and the inbox floor follows the
  mainnet tip, 2 blocks behind. With no `Bitcoin` network in the config the
  inbox stays closed, and the bridge says so at startup.
- **The floor waits two minutes after the bridge connects to its node**
  (`FLOOR_HOLD_MS`), so a node that was down has time to catch up with the
  inbox before the floor moves past requests other peers were holding. An
  inbox the node has lost is opened again at the highest floor the bridge
  has signed, not the tip's.
- **`bitcoin_inbox_contract.wasm` must be in the contract directory**, beside
  the other two. `scripts/deploy.sh` installs it.
- **`listen` and `auth` are ignored.** They configured the HTTP service the
  inbox replaced, and a config that still sets them loads unchanged.
- **Unwatch is per requester.** The database records which Ghost Key asked for
  each script (`script_interests`), and a script stops being scanned only when
  the last requester withdraws. A watch registered before the inbox existed has
  no requester on record, so no unwatch ends it.
- **A watch lasts about a day, counted in blocks**: 144 blocks scanned after
  the Watch that last asked for it (`WATCH_LIFETIME_BLOCKS`), and then until
  the last of them is `deep_confirmations` deep (six by default), when it
  ends as if its requester had withdrawn it. Watching costs an update to the
  script's address contract every block, and a client typically watches an
  address for one payment. A client that still wants the script sends the
  Watch again, with a newer timestamp, well before then. The count starts at the present as
  the bridge knows it when it reads the Watch, the highest of Bitcoin Core's
  tip, the headers it holds and the observer's scan, so a Watch read while
  either is catching up after downtime does not start in the past, and a
  renewal never moves a watch's start back. The count is of
  blocks the observer has scanned, so no clock enters: however long the
  bridge or Bitcoin Core was down, or cut off from its peers, a watch ends
  only once every block of its life has been scanned for it (#11 is the known
  exception, a reorg round that fails part-way, and a reorg deeper than
  `deep_confirmations` can still bring in a payment after a watch has ended).
  Nor does a watch end while a payment to it is less than
  `deep_confirmations` deep, while the floor is held, or while a request from
  its own requester waits on the removal budget, since that may be its
  renewal (only while that request is still in the inbox: one the caps push
  out or the floor passes no longer counts). Every scan also covers the scripts of
  payments a reorg moved out of their block and that have not been seen
  again, watched or not, so such a payment is found where it was re-mined
  rather than left retracted. Where a
  payment to the script has been seen and is not yet `deep_confirmations`
  deep, the watch lasts until it is, erring towards watching while a reorg
  could still move the payment; a moved payment is found again by the scan
  of scripts in doubt either way. Watches registered before the inbox
  existed never end this way.
- **Acted-on entries are recorded** (`inbox_handled`) until the floor passes
  them, so an entry whose removal failed to land is removed again rather than
  acted on again, and each removal batch is built from this record. Each
  requester's latest request per script is kept with its sender's timestamp,
  so requests take effect in the order they were made whatever order they
  arrive in. Deleting the database loses both records; the cost is that
  requests still in the inbox, about half an hour's worth, are acted on a
  second time.
- **Reading stops at the removal budget** (`REMOVAL_BUDGET`, 4096 entries).
  Every entry read is removed, and removals last until the floor passes them,
  about half an hour for a request dated as senders date them and at most
  five blocks for any. Past the budget, new requests wait in the inbox for the
  floor, and the bridge logs that they do. Each Ghost Key gets a 64th of the
  budget (`REMOVAL_SHARE_PER_GHOSTKEY`), so one sender cannot spend it for
  everyone; a sender past its share waits the same way while others are read.

### Backfilling history on a pruned node

A watch request may carry `scan_from_height`, a hint that nothing before that
height needs scanning. **The bridge does not act on it**
(freenet/freenet-bitcoin#7). The HTTP service the inbox replaced did, by
rewinding the scan cursor with no bound. The inbox's first PR tried several
bounded versions, and each raced the observer, which is the only thing that
should move the cursor, so none shipped. Harvest does not send watches yet
(freenet/harvest#59), so nothing in use relies on the hint.

So a new script is watched from the observer's next round. A payment to it
mined earlier is missed, and the bridge then publishes a `ScannedTo` height
past that payment, so the webapp reports that a bridge looked and found no
payments when the truth is that nobody looked. On a healthy bridge the gap is
seconds, so a client should send its watch before it shows the address to
whoever will pay it, and leave the hint unset. The gap is wide in two cases:

- **The bridge's Freenet node is down, or the inbox worker is reconnecting,
  while Bitcoin Core is up.** The observer keeps scanning, the watch waits in
  the inbox, and nothing rewinds when it is read.
- **The bridge restarts after downtime.** At startup, if the tip can be read,
  the cursor is rewound to `demo_backfill_blocks` below it so the tip contract
  refills. A payment in those blocks is still found if the inbox worker
  registers its watch before the observer scans past it. Blocks older than
  that window are not rescanned, so after longer downtime every payment mined
  during it can be missed.

#7 has the design a backfill needs, including publishing no `ScannedTo` below
where a script's watch began.

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
- **Requests come only through the inbox.** There is no service to expose and
  no reverse proxy to run. The inbox admits only Ghost Key signed entries,
  verified by every peer, and holds at most 2 waiting requests per Ghost Key
  and 128 in all; a request gives its place back as soon as the bridge has
  read it. The bridge adds its own limit: 1000 watched scripts per Ghost Key.
  A request cannot move the scan cursor (see "Backfilling history" above).
- **A removal means read, not done.** The bridge removes every entry it
  reads, including ones it cannot open, ones for a network it does not
  observe, and a Watch beyond its sender's limit, whose extra scripts it
  drops with a warning in the log. A sender learns what a Watch did from the
  address contract, not from the inbox.
- **What the inbox does not stop.** 64 Ghost Keys can hold every place in it.
  A request gives its place back once read, and each Ghost Key is read only up
  to its share of the removal budget, so the cost is 64 Ghost Keys each
  sending about 66 requests every five blocks, about 50 minutes (dated at the
  top of the window, which also outranks honest requests by height). That is
  the same act as spending
  the removal budget, after which new requests wait for the floor. See
  `MAX_ENTRIES` and `REMOVAL_BUDGET` in `inbox/src/lib.rs` for why neither is
  raised freely: more entries mean more certificates for every peer to check,
  and more removals mean a larger state.

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
