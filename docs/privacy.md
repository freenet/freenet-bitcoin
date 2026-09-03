# Privacy: what leaks, to whom

An honest account of what each party learns. Where something leaks, it is
recorded here rather than glossed over, because a privacy claim that is not
precise is worse than none.

## The principle

> A Bitcoin address becomes public only when application semantics require it.
> Merely watching an address never makes it public.

Three facts are kept distinct throughout:

1. **Bitcoin script X exists.** Public — it is on a public blockchain.
2. **`BitcoinAddressContract(X)` is addressable in Freenet.** Public, and
   derivable by anyone who knows X. Knowing the contract's address tells you
   nothing about who cares about it.
3. **A particular user is watching X.** Private. This is the fact the design
   works to protect.

## What was deliberately not built

There is no `WatchRegistry` contract, and there will not be one. It would make
the bridge's job trivial and it is exactly the wrong artifact: Freenet contracts
are reachable by anyone who knows the key and are replicated indefinitely, so
such a registry would be a permanent, globally enumerable index of who cares
about which Bitcoin address. No mapping of the following forms exists anywhere:

```text
   Ghost Key      →  Bitcoin addresses
   Bitcoin address →  Ghost Key
   user            →  watch list
```

The public `BitcoinAddressContract` contains **no** field for who requested it,
which Ghost Key authorized the request, how many people watch it, or why anyone
cares. A test asserts that the bridge's watch-request format has nowhere to put
a label, an order id, or a user identity, and another asserts that the watch
*response* returns a boolean rather than a watcher count — a count would report
how many other people are watching the same address.

## Who learns what

### Everyone on the Freenet network

- That a `BitcoinAddressContract` exists for a given script, and its contents:
  bridge-signed observations of on-chain activity.
- Everything on the Bitcoin blockchain, which was already public.
- **Not** who is interested in it.

Caveat with teeth: ordinary Freenet traffic analysis can sometimes let an
observer infer that a peer is interested in a particular contract, because a
peer subscribes to what it cares about. This system does not fix that, and does
not claim to. What it refuses to do is make it *easier* by publishing an index.

### The bridge operator

The bridge necessarily learns, and can correlate:

- that somebody it authorized asked it to synchronize script X;
- the requester's source IP;
- with `AuthPolicy::GhostKey`, a **stable fingerprint** of the requesting Ghost
  Key.

**A Ghost Key is a stable identifier, not an anonymous one.** Blind signing
prevents the *notary* from linking a donation to the resulting key. It does
nothing to stop a *verifying service* from recognising the same certificate
across requests. So a bridge operator can link one user's requests to each
other, and colluding operators can link a user across their services.

Mitigations, in descending order of effectiveness:

- **Run your own bridge.** The protocol is generic; a self-hosted bridge with
  `AuthPolicy::Open` produces byte-identical observations. This is the real
  answer and the reason no Ghost Key appears in the contract format.
- **Use a distinct Ghost Key per relying party.** The vault supports this; it
  does not enforce it.
- Reach the bridge over Tor or a VPN to separate the IP from the request.

The bridge is trusted with this correlation. Nobody else is. It stays in one
SQLite file and is never replicated.

### The Harvest contract

- Orders: buyer, seller, amount, payment destination, status.
- **Not** any user's arbitrary watch list, Ghost Key credentials, or wallet keys.

An order's payment destination *is* public, and this is not a regression. It is
application semantics requiring publication: decentralized payment verification
is impossible unless everyone can see what was owed and where it was to be paid.
That is a categorically different thing from publishing a user's list of
addresses they happen to find interesting.

Publishing the destination does mean an observer can watch that address on the
blockchain and see the payment. That is inherent to on-chain settlement of a
publicly-verifiable order, not something this design adds.

### The Harvest delegate — private, local, never replicated

- watched scripts and their private labels
- order ↔ payment associations
- bridge authorization credentials
- future wallet configuration

Automatic order-driven watches share exactly the same storage and code path as
manual ones; the only difference is an `order_id` field. An automatic watch
creates no globally visible "Bob watches X" record either.

### Alice, paying an invoice

Nothing. A payer uses an ordinary Bitcoin wallet, needs no Freenet software, no
Ghost Key, and never learns that Freenet was involved.

## Residual leakage, listed plainly

1. **Bridge correlation.** Stable Ghost Key fingerprint plus source IP plus
   requested scripts, in the operator's database. Mitigated by self-hosting, not
   eliminated by anything in this repo.
2. **Freenet traffic analysis.** Subscribing to `BitcoinAddressContract(X)`
   signals interest in X to an observer well-placed on the network. Inherent to
   the platform.
3. **Public demo addresses.** The operator's curated demonstration addresses are
   public by construction. They are nobody's private watch, and a user cannot
   unwatch them because they are not the user's.
4. **On-chain linkage.** Reusing one address across several Harvest orders links
   those orders on the public blockchain. The right fix is a fresh address per
   order, which the delegate is the natural place to implement and which this
   prototype does not do.
5. **`already_active` on a watch response.** Returns a boolean. A caller learns
   whether *anyone at all* was already watching a script — one bit, and only for
   a script the caller already knew. It is deliberately not a count.

## Lightning changes this picture

Lightning payments leave no public on-chain record, so there is nothing for a
bridge to watch and no watch request to make. The entire bridge-correlation
surface above disappears for Lightning-settled orders. That is a genuine
privacy argument for Lightning, independent of the fee argument.

What replaces it is a different exposure: the payer's Lightning node learns the
route, and the seller's node learns the payment. Neither is a globally
enumerable index, so it is a materially better position — but it is not nothing.
