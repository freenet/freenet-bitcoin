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

**A submitter is a third party, trusted for nothing.** A payment proof is
verified as a pure function of its own bytes, so the claims it contains are
whichever ones the submitter chose to include, and no such function can tell a
complete set from a curated one. That is why confirmation depth is taken from
inside the winning claim's signature — `as_of.height - anchor.height + 1`, via
`OutpointStatus::confirmations_at` — rather than from a tip supplied alongside
it. See "Withholding a retraction" below.

## Harvest store contract

**Holds (public):** marketplace state, orders, payment requirements, payment
destinations where decentralized validation needs them, fulfilment state.

**Never holds:** any user's arbitrary watch list, Ghost Key credentials, wallet
private keys.

**Trusted for:** nothing of its own — but it inherits the bridge's trust for
chain state. Order terms carry the seller's ghostkey signature, and the `Paid`
transition carries bridge-signed Bitcoin evidence that any peer re-verifies for
itself. That re-verification checks the evidence is self-consistent and pays
this order's script; it does not establish that the block is on Bitcoin. The
confirmation count is bounded by what the signing bridge asserted inside the
claim, so it cannot be inflated by the party who assembled the proof — but it
is still a bridge assertion, not an independent measurement.

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
checked against anything, and a payment's confirmation depth is one of them:
the depth a verifier will act on is the one the bridge stamped into the claim
via `as_of`, capped by the reader's own tip view.

**Consequence for operators:** `deep_confirmations` is the deepest confirmation
any application using this bridge can prove. The bridge re-asserts a confirmed
payment on a doubling ladder up to that ceiling; an application asking for more
confirmations than the ceiling will never see its order settle.

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
| Withhold a retraction to keep an order looking paid | Depth is capped by the claim's own `as_of`, so a withheld retraction leaves a confirmation worth only the depth the bridge had actually seen. Succeeds only against a reorg at least as deep as the required confirmations — see "Withholding a retraction" |
| Seller marks their own order paid without payment | Requires bridge-signed evidence any peer re-verifies; a bare seller signature is not accepted |
| Flood one address contract to exhaust state | `MAX_CLAIMS` cap, pruned deterministically, keeping the most recent evidence |
| Enumerate who watches what | No registry exists to enumerate |

**Not in the table, because nothing stops it:** a trusted bridge asserting
chain state that is not Bitcoin's. No check anchors a header to the real chain,
so the value of `PowFloor` is not a forgery cost — it is chosen so it never
rejects a genuine block, which puts it well below mainnet's difficulty and
makes it `NONE` on the test networks. Confirmation depth rests on the same
trust: it is the difference between two heights the bridge itself asserted.
Choosing `trusted_bridges` is the control that matters, and naming more than
one is how an application reduces its exposure.

## Withholding a retraction

A verifier is handed a set of claims and must decide from those bytes alone. It
cannot fetch the address contract to check for more: a contract's verdict has
to be a pure function of its own inputs, or two replicas holding identical
state reach different answers depending on what else has replicated to them.

So a submitter across a reorg can present the bridge's pre-reorg
`ConfirmedOutput` and drop the `Retracted` that superseded it. Every remaining
check passes. The signature is genuine, the claim names this script, the block
is self-consistent, and the fold has nothing left to fold it against.

Omission alone was not what made this a forgery. What finished it was measuring
depth as `supplied_tip − anchor + 1`: that number grows with the chain, so an
assertion the bridge made at depth 1 and has since retracted read as
arbitrarily deep against a current tip.

Depth therefore comes out of the claim. `OutpointStatus::confirmations_at`
returns the lesser of the reader's own tip view and `as_of.height −
anchor.height + 1`, both of the latter inside the bridge's signature. A stale
confirmation is worth stale depth however fresh a tip accompanies it.

**What remains.** To reach depth *d* with a block that was reorged out, the
bridge must have signed that block as *d* deep before it went — which is a
reorg at least *d* blocks deep. A recipient waiting *d* confirmations is
already accepting exactly that risk, so the residual is Bitcoin's own
assumption rather than a property of this design.

**What this does not do.** It bounds a lying *submitter*, not a lying bridge. A
holder of a trusted bridge key can stamp any `as_of` it likes, and that trust
is the headline at the top of this document.

**What it costs.** An application cannot prove more confirmations than its
bridges have asserted, which is why the bridge re-asserts on a ladder and why
`deep_confirmations` is a ceiling rather than a publishing detail.
