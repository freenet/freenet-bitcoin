# Architecture

How Bitcoin blockchain state is exposed to Freenet applications, and why the
pieces are divided the way they are.

## The shape

```text
                          FREENET
        ┌─────────────────────────────────────────┐
        │   Harvest store contract                │
        │   offers / orders / fulfilment          │
        │              │                          │
        │              │ RequestRelated           │
        │              ▼                          │
        │   BitcoinAddressContract(network, spk)  │
        │                                         │
        │   BitcoinTipContract(network)           │
        └──────────────▲──────────────────────────┘
                       │ signed observations (public, generic)
              Bitcoin/Freenet bridge
                       │
                  Bitcoin Core (pruned, no txindex)
                       │
                  Bitcoin network
```

Four kinds of information are kept strictly apart, and most of the design
follows from refusing to let them blur:

| | Where it lives | Who can see it |
|---|---|---|
| Shared application state | Harvest store contract | everyone |
| Public Bitcoin facts | Bitcoin address / tip contracts | everyone |
| Private user interests | Harvest delegate, on the user's device | only the user |
| Service authorization | the bridge's own database | only the operator |

## The reorg model

This is the load-bearing design decision, so it is worth stating precisely.

Freenet requires contract state to converge under a merge that is associative,
commutative and idempotent. Bitcoin's canonical chain is not monotonic: blocks
get reorganized, and a transaction that was confirmed can stop being confirmed.
A naive `confirmed: bool` that flips to `false` is not expressible — two peers
that applied updates in different orders would disagree forever.

The resolution is that **nothing is ever edited**. State is a grow-only set of
signed assertions, each stamped with the asserting bridge's own chain height:

> bridge *B*, whose best chain tipped at height *H*, asserts *X*

A reorg does not retract an older assertion. It produces a **newer** one at a
greater `as_of` height. Current status is then *derived* by folding the set and
letting the highest `as_of` win per outpoint.

```text
  as_of 100:  ConfirmedOutput(tx, 50_000 sats, block 99)
  as_of 105:  Retracted(tx)                                 <- reorg
  as_of 107:  ConfirmedOutput(tx, 50_000 sats, block 106)   <- re-mined
  ------------------------------------------------------------------
  derived  :  Confirmed at block 106
```

Set union is trivially associative, commutative and idempotent, and the fold is
a pure function of the set, so every replica computes the same answer from the
same bytes. Ties at equal height are broken on the anchor hash so the result
never depends on which peer merged first.

One collection is *not* grow-only: the per-bridge `ScannedTo` watermark, which
merges as a **monotonic maximum**. If it grew it would gain an entry per block
forever. A maximum is also associative, commutative and idempotent, and it can
never oscillate.

The watermark exists because a grow-only set of payments cannot express *"this
address has received nothing"* — an empty set is indistinguishable from *"nobody
has looked yet"*. A payment UI needs that distinction badly, so bridges publish
how far they have scanned. The bridge deliberately refuses to publish a
watermark while Bitcoin Core is still in initial block download: during IBD an
absence of payments means nothing, so the claim would be actively misleading.

## Checking a payment against its own evidence

**The bridge is trusted for chain state.** It asserts which blocks are on
Bitcoin, what height each one is at, and where the tip is, and nothing in this
system checks any of that independently. A holder of a trusted bridge key can
assert a payment that never happened. Start from that, because the SPV
machinery below is defence in depth against a lying bridge and is easy to
mistake for a replacement for trusting one.

A bridge signature proves only that a bridge *said* something, so
confirmed-payment claims additionally carry **SPV evidence**, and it is
required rather than optional.

Any reader checks, from the bytes alone:

1. the txid is `SHA256d` of the transaction — so the amount and destination
   cannot be chosen independently of the txid;
2. output *N* really pays this script this many sats;
3. a Merkle branch folds to the block header's merkle root;
4. the header hashes below the difficulty target it names, and below the
   configured `PowFloor`;
5. each following header chains by `prev_hash` and carries its own work.

The claim is separately bound to this contract instance's script and network,
so it cannot be replayed onto a different destination or a different network.

**What that buys.** A bridge cannot misreport what a real transaction paid, or
to whom: the amount and destination are read out of the bytes the txid commits
to, not taken from the bridge's word. It is a genuine and useful narrowing —
the bridge cannot invent an amount, redirect a payment, or point at somebody
else's transaction.

**What it does not buy, stated plainly:**

- **That the block is on Bitcoin.** Nothing anchors the containing header to
  the real chain: no checkpoint, no path to genesis, no comparison of
  accumulated work against anything. Every check above is self-referential — a
  header is judged only against the difficulty it itself claims. Which blocks
  are on Bitcoin is the bridge's assertion, and it is the load-bearing one.
- **Confirmation depth.** The evidence can carry a run of chained headers, but
  nothing places that run on the real chain. In practice an application derives
  depth arithmetically from two further bridge assertions: the claim's
  `anchor.height` and a bridge-signed chain tip. A header does not carry its
  own height, so `anchor.height` is unverifiable in principle here.
- **The `PowFloor` is a sanity check, not an economic boundary.** It rejects
  trivially-fabricated headers, which is worth doing, and that is all. It is
  chosen so it never rejects a genuine block, which puts it well below
  mainnet's real difficulty — around four orders of magnitude below — and it is
  `NONE` on the test networks. It does not bound what forgery costs.
- **Completeness.** A bridge can *omit* a payment or a reorg. Omission is a
  liveness failure, not a forgery, and it is why an application should be able
  to name more than one bridge.
- **Signet is not mainnet.** Signet's difficulty is trivial and its blocks are
  authorized by the signet challenge key, not by work. A green signet
  demonstration shows the mechanism working; it says nothing about mainnet-grade
  security. Do not read one as the other.

## Why a payment is published twice

When a payment is first seen, its evidence can only exhibit a one-block header
run — no following blocks exist yet. So the bridge publishes a payment
**twice**: once when it appears, and again once the chain has actually buried
it, the second claim carrying the headers that show the depth.

Without the second claim, the evidence itself could only ever exhibit a
one-block run. The fold takes the higher `as_of`, so the deeper claim wins, and
the set semantics make a duplicate harmless anyway.

This does not make depth trustless. The header run is self-consistent but
unanchored, and the confirmation count an application acts on is computed from
the claim's block height and a bridge-signed tip rather than from the run —
both bridge assertions. What the second claim buys is that the evidence and the
asserted depth agree, so an inflated depth is at least accompanied by headers
somebody had to produce.

## Contract state and summaries

Both contracts follow the platform's cost rules deliberately, because summaries
are broadcast on every anti-entropy heartbeat whether or not anything changed.

- **The address summary is constant-size.** Claims are hashed into 16 fixed
  buckets, each publishing one 8-byte digest: 128 bytes whether the script has
  one payment or ten thousand. `delta()` then resends *whole buckets*, which is
  a superset of the true difference. That is sound only because applying a claim
  the receiver already holds is a no-op on a digest-keyed set.
- **Encodings are asserted, never derived.** A `[u8; 32]` under a derive encodes
  as a CBOR array of 32 integers costing up to 65 bytes, and — worse — its size
  depends on the byte *values*, so a test built from small numbers reports a
  flatteringly cheap figure. Every fixed-width value here hand-writes
  `serialize_bytes`, pinned by golden-vector tests. This was a real bug caught by
  those tests, not a theoretical concern.
- **The tip contract publishes a retention horizon.** It keeps the highest 64
  blocks and prunes the rest. Pruning plus a set-difference delta is a classic
  non-terminating loop — the receiver prunes what it was just sent, its summary
  does not change, and the pair re-sends forever. The summary therefore carries
  both the lowest height held *and* the count, and the horizon only applies to a
  peer that is genuinely at capacity. An earlier version applied it to any peer,
  which silently starved a peer that had simply started late.
- **Maps are `BTreeMap`, never `HashMap`.** Peers compare state bytes to decide
  they have converged, so nondeterministic iteration order would make two peers
  holding identical logical state disagree forever.

## Related contracts, and their real limits

Harvest reaches a paid order's `BitcoinAddressContract` through Freenet's actual
related-contract mechanism: `validate_state` returns
`ValidateResult::RequestRelated(ids)` and the host re-invokes with
`RelatedContracts` populated.

Verified limits, checked against the **published** 0.6.1 and 0.8.5 crates and
against freenet-core `origin/main` (not a local worktree — the local `main`
checkout was 71 commits stale, and reading it produced a wrong answer once
already):

- **`ValidateResult` is byte-identical in 0.6.1 and 0.8.5**, and carries no
  `#[non_exhaustive]`. Harvest's 0.6 pin does not constrain this API at all.
- **One round only.** A `RequestRelated` is fetched and retried exactly once; a
  second is a hard error on every path (PUT/UPDATE, network/local). Declare
  every related contract you need in the first call.
- **At most 10 contract ids** per request
  (`MAX_RELATED_CONTRACTS_PER_REQUEST`, `runtime.rs:19`), with a 10-second
  fetch budget. Empty lists and self-references are rejected before the fetch.
- Honored on both the PUT and UPDATE paths, network and local
  (`fetch_related_for_validation` / `fetch_related_for_validation_network`).
- **All six `UpdateData` variants are legal** on a client-originated
  `ContractRequest::Update`, including the `Related*` ones; only a variant from
  a stdlib newer than the host build is rejected.
- A related fetch that times out could once wedge an UPDATE merge
  (freenet-core#4077); the parallel-fetch fix (#4080) is merged, though the
  issue is still open.
- Conformance capture of validation-resolved related state (freenet-core#5376)
  **is fixed on `origin/main`** — the capture hook is present in both fetch
  paths (`contract_ops.rs:846`). It was genuinely absent before #5393/#5402
  merged on 2026-08-23, which would have made a contract like this one
  unjudgeable, and an unjudgeable contract reads exactly like a clean one. The
  field re-verification on the live capture peer is still pending, so treat the
  fix as merged-but-unconfirmed rather than proven.

**The important part is not whether it works, but what may be read.** Harvest's
cross-check against related state is **strictly additive**: no path through it
can turn otherwise-valid state invalid. The authority is the *embedded*
`OrderPaymentProof`.

The reason is not stylistic. A contract's verdict has to be a pure function of
its own inputs, or replicas evaluating it at different moments reach different
answers and never converge. Related state is a separate contract replicated on
its own schedule, so a peer whose copy has not caught up would judge a perfectly
good order invalid. Embedding the signed claims makes validity self-contained
and monotonic: once a proof verifies, it verifies forever, on every peer.

Consequently a reorg is **not** modelled as invalidation. It is a further
forward transition, `PaymentReversed`, carried by its own evidence. Status only
ever moves forward, which is what keeps the merge monotonic.

## Two payment rails

`OrderPaymentProof` is an enum over on-chain and Lightning from the outset,
because contract state format is frozen at publish: adding a rail afterwards
would orphan existing orders rather than merely change code.

The rails verify very differently:

- **On-chain** payments are publicly observable, so proof is bridge-signed
  observations plus SPV evidence, and a bridge is needed to watch for them.
- **Lightning** payments are, by design, *not* publicly observable. No bridge
  can watch one and the SPV machinery has nothing to look at. Proof is instead
  the **preimage** `r` where `SHA256(r) == payment_hash`: the order publishes the
  payment hash exactly where an on-chain order publishes its scriptPubKey, and
  verification is a single hash with no bridge involved at all.

The Lightning path is therefore *simpler* to verify, and it sidesteps the
watch-list privacy problem entirely because there is nothing to watch. Its real
difficulty is operational — a seller needs an always-on node with inbound
liquidity — and none of that lives in the contract layer. The preimage arm is
implemented and tested; the node integration is not built.
