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

## Verifying a payment without trusting the bridge

A bridge signature proves only that a bridge *said* something. That would make
every reader a client of the bridge's honesty, so confirmed-payment claims
additionally carry **SPV evidence**, and it is required rather than optional.

Any reader checks, from the bytes alone:

1. the txid is `SHA256d` of the transaction — so the amount and destination
   cannot be chosen independently of the txid;
2. output *N* really pays this script this many sats;
3. a Merkle branch folds to the block header's merkle root;
4. the header hashes below its own difficulty target;
5. each following header chains by `prev_hash` and carries its own work.

This collapses what a bridge is trusted for: from *"trusted to report payments
truthfully"* down to *"trusted for availability, and for which fork is the best
chain"* — and the second is bounded by proof-of-work rather than by a signature.

**What is still trusted, stated plainly:**

- **Completeness.** A bridge can *omit* a payment or a reorg. Omission is a
  liveness failure, not a forgery, and it is why an application should be able
  to name more than one bridge.
- **Chain selection.** Bounded by work: fabricating six valid mainnet headers is
  not economically reachable. A `PowFloor` parameter rejects headers claiming
  implausibly easy work, which is otherwise unbounded because a standalone
  header does not say what the difficulty at its height should have been.
- **Signet is not mainnet.** Signet's difficulty is trivial and its blocks are
  authorized by the signet challenge key, not by work. A green signet
  demonstration shows the mechanism working; it says nothing about mainnet-grade
  security. Do not read one as the other.

## Why a payment is published twice

At first sight, a payment can only be proven to depth 1 — no following blocks
exist yet. So the bridge publishes a payment **twice**: once when it appears, and
again once the chain has actually buried it, the second claim carrying the
headers that prove the depth.

Without the second claim, a reader could only ever see depth 1 from the evidence
and would have to take the bridge's word for how deep the payment is, which is
exactly the trust being removed. The fold takes the higher `as_of`, so the deeper
claim wins, and the set semantics make a duplicate harmless anyway.

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
