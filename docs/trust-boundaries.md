# Trust and security boundaries

What each component may hold, what it must never hold, and what it is trusted
for. Stated as boundaries rather than as prose, because these are the claims
that a reviewer should be able to check against the code.

## Harvest store contract

**Holds (public):** marketplace state, orders, payment requirements, payment
destinations where decentralized validation needs them, fulfilment state.

**Never holds:** any user's arbitrary watch list, Ghost Key credentials, wallet
private keys.

**Trusted for:** nothing. Every field is verified. Order terms carry the
seller's ghostkey signature; the `Paid` transition carries bridge-signed
Bitcoin evidence that any peer re-verifies for itself.

**Cannot do:** invalidate previously-valid state. A reorg produces a forward
`PaymentReversed` transition, never a retroactive rejection, because state
flipping from valid to invalid is what stops replicas converging.

## BitcoinAddressContract

**Holds (public):** authenticated Bitcoin facts for exactly one output script.

**Does not know:** who watches the script, who owns it, which Ghost Key caused
it to be synchronized, or why anyone cares. There is no field for any of it.

**Trusted for:** nothing beyond what its own evidence proves. A claim's SPV
proof is checked against the transaction, the Merkle branch, and the headers'
proof-of-work; the bridge signature only establishes *who asserted it*.

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

**Trusted for:** availability, and for which fork is the best chain — the second
bounded by proof-of-work rather than by its signature. It is **not** trusted to
be truthful about whether a transaction exists, what it paid, or how deeply it
is buried; SPV evidence settles all three independently.

**Can still:** omit a payment or a reorg. Omission is a liveness failure, not a
forgery. An application that cares should name more than one bridge in its
contract parameters.

**Its signing key:** authenticates observations. It is not a Bitcoin key and
holds no funds. Compromising it lets an attacker sign false assertions, which
the SPV evidence then refutes — which is precisely why the two are paired. Two
tests assert that a *trusted* bridge with a *valid* signature still cannot mint
a payment that never happened, nor repoint someone else's payment.

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
| Bridge key compromised, forges a payment | SPV evidence: the txid commits to the amount and destination |
| Bridge repoints someone else's payment to this address | Claim binds `script_id`; SPV checks the output's actual script |
| Replay a signet observation as mainnet | Network folded into `ScriptId` and checked against parameters |
| Replay a captured service authorization for another request | Signature covers a single-use challenge **and** the request body |
| Use the bridge as a signature-verification oracle | Challenge consumed atomically *before* certificate verification |
| Probe which certificates exist via error messages | Every denial returns an identical generic message |
| Forge depth with a chain of easy headers | `PowFloor` rejects headers claiming implausibly low work |
| Withhold a retraction to keep an order looking paid | Proof must carry the whole claim history for the outpoint; the verifier re-runs the same fold |
| Seller marks their own order paid without payment | Requires evidence any peer re-verifies; a bare signature is not accepted |
| Flood one address contract to exhaust state | `MAX_CLAIMS` cap, pruned deterministically, keeping the most recent evidence |
| Enumerate who watches what | No registry exists to enumerate |
