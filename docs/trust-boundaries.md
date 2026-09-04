# Trust and security boundaries

What each component may hold, what it must never hold, and what it is trusted
for. Stated as boundaries rather than as prose, because these are the claims
that a reviewer should be able to check against the code.

## The headline, so nothing below can be misread

**The bridge is trusted for chain state.** It asserts which blocks are on
Bitcoin, what height each one is at, and where the tip is. Nothing in this
system checks any of that independently — there is no checkpoint, no path to
genesis, and no accumulated-work comparison anywhere — so a holder of a trusted
bridge key can assert a payment that never happened.

**The SPV evidence is still load-bearing.** It binds a claim to a
self-consistent transaction and block: the txid is `SHA256d` of the supplied
bytes so it is not a free parameter, the named output genuinely pays that
script that amount, the transaction is committed to by that header's Merkle
root, and each header meets the target it names. With the claim bound to a
particular script and network, a bridge therefore **cannot misreport what a
real transaction paid, or to whom**. That is defence in depth against a lying
bridge, not a substitute for trusting it.

## Harvest store contract

**Holds (public):** marketplace state, orders, payment requirements, payment
destinations where decentralized validation needs them, fulfilment state.

**Never holds:** any user's arbitrary watch list, Ghost Key credentials, wallet
private keys.

**Trusted for:** nothing of its own — but it inherits the bridge's trust for
chain state. Order terms carry the seller's ghostkey signature, and the `Paid`
transition carries bridge-signed Bitcoin evidence that any peer re-verifies for
itself. That re-verification checks the evidence is self-consistent and pays
this order's script; it does not establish that the block is on Bitcoin, and
the confirmation count is arithmetic over the claim's block height and a
bridge-signed tip.

**Cannot do:** invalidate previously-valid state. A reorg produces a forward
`PaymentReversed` transition, never a retroactive rejection, because state
flipping from valid to invalid is what stops replicas converging.

## BitcoinAddressContract

**Holds (public):** authenticated Bitcoin facts for exactly one output script.

**Does not know:** who watches the script, who owns it, which Ghost Key caused
it to be synchronized, or why anyone cares. There is no field for any of it.

**Trusted for:** nothing of its own; its contents are only as good as the
bridges its parameters name, which are trusted for chain state. A claim's SPV
proof is checked against the transaction, the Merkle branch, and the target
each header names, which fixes the amount and the destination; the bridge
signature establishes *who asserted it*; and nothing establishes that the
block is on Bitcoin.

## Harvest delegate — the local trust zone

**Holds (private, on the user's device):** watched scripts, private labels,
order associations, bridge authorization credentials, future wallet config.

**Never exposes:** Ghost Key credentials to a Harvest contract, or to the UI in
a form the UI could replay against another service.

**Platform limits worth knowing:** a delegate has no scheduled wakeup
(freenet-core#3972); its contract GET reads only the local store and its
subscribe registers no network demand (freenet-core#4669); and under
`freenet local` a delegate's contract operations silently do nothing
(freenet-core#5273). Nothing here is designed to depend on a delegate waking
itself.

## The bridge

**Holds (private operational state):** its Bitcoin Core connection, the set of
scripts it is synchronizing, chain checkpoints, its signing key, and service
authorization decisions including Ghost Key fingerprints.

**Never holds:** any user's Bitcoin private keys. It cannot sign a Bitcoin
transaction, and the broadcast path relays bytes it did not create.

**Trusted for:** availability, and for chain state — which blocks are on
Bitcoin, what height each is at, and where the tip is. Those assertions are not
checked against anything, and a payment's confirmation depth is derived from
two of them.

**Not trusted for:** what a real transaction paid, or to whom. The SPV evidence
fixes the amount and destination out of the bytes the txid commits to, and the
claim is bound to this instance's script and network, so a payment cannot be
invented against a genuine transaction, nor redirected here from elsewhere.

**Can still:** omit a payment or a reorg. Omission is a liveness failure, not a
forgery. An application that cares should name more than one bridge in its
contract parameters.

**Its signing key:** authenticates observations. It is not a Bitcoin key and
holds no funds. Compromising it yields the bridge's trust for chain state, so
it is a serious compromise. The SPV evidence constrains what can be done with
it rather than neutralising it: two tests in `common/src/signing.rs` assert
that a *trusted* bridge with a *valid* signature still cannot inflate what a
real transaction paid, nor repoint someone else's payment here. Neither test
shows — and nothing does — that such a bridge cannot assert a payment against a
block it made up.

## Ghost Keys

**Used only** to prove eligibility for one operator's service.

**Must never** become part of Bitcoin contract identity or payment semantics.
Bitcoin contracts are parameterized by `(network, script_pubkey)` and nothing
else. A Ghost Key is not required to own, send or receive Bitcoin, to create an
address, to build a Bitcoin-enabled Freenet application, to implement this
contract format, or to run a compatible bridge.

The two authorizations that are constantly confused:

```text
  service authorization    "May this caller ask THIS bridge to do work?"
                           -> operator policy. Never on the Freenet wire.

  observation authenticity "Did THIS bridge sign this Bitcoin fact?"
                           -> protocol-level. Always on the wire.
```

## The user's wallet

**Owns:** Bitcoin private keys and all signing.

An ordinary payer needs to know nothing about Freenet, Freenet.org, or Ghost
Keys. They receive an address and an amount and pay it with any wallet.

## Attacks considered, and what stops them

| Attack | What stops it |
|---|---|
| Bridge inflates what a real transaction paid | SPV evidence: the txid commits to the amount, which is read out of the transaction |
| Bridge repoints someone else's payment to this address | Claim binds `script_id`; SPV checks the output's actual script |
| Replay a signet observation as mainnet | Network folded into `ScriptId` and checked against parameters |
| Replay a captured service authorization for another request | Signature covers a single-use challenge **and** the request body |
| Use the bridge as a signature-verification oracle | Challenge consumed atomically *before* certificate verification |
| Probe which certificates exist via error messages | Every denial returns an identical generic message |
| Headers carrying trivially little work | `PowFloor` rejects them — a sanity check only; see below |
| Withhold a retraction to keep an order looking paid | Partially: the verifier re-runs the same fold, but only over the claims the submitter supplied. Open gap, written up on Harvest's `OnChainPaymentProof` |
| Seller marks their own order paid without payment | Requires bridge-signed evidence any peer re-verifies; a bare seller signature is not accepted |
| Flood one address contract to exhaust state | `MAX_CLAIMS` cap, pruned deterministically, keeping the most recent evidence |
| Enumerate who watches what | No registry exists to enumerate |

**Not in the table, because nothing stops it:** a trusted bridge asserting
chain state that is not Bitcoin's. No check anchors a header to the real chain,
so the value of `PowFloor` is not a forgery cost — it is chosen so it never
rejects a genuine block, which puts it well below mainnet's difficulty and
makes it `NONE` on the test networks. Confirmation depth rests on the same
trust: it is arithmetic over the claim's asserted block height and a
bridge-signed tip. Choosing `trusted_bridges` is the control that matters, and
naming more than one is how an application reduces its exposure.
