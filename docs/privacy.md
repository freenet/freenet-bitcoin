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

## The request inbox, and what it is not

A bridge takes watch requests through an inbox contract, because that is the
only way a Freenet web app or delegate can reach it: neither can make an HTTP
request to a bridge. Freenet contracts are reachable by anyone who knows the key
and are replicated indefinitely, so a contract listing who watches what would
be a permanent, globally enumerable index of who cares about which Bitcoin
address. The inbox is built not to be one:

- **What is asked is sealed.** A request (watch or unwatch, which network,
  which scripts) is encrypted to the bridge's key. Peers store and relay only
  ciphertext.
- **Requests are transient.** The bridge removes each one once it has read it,
  and every peer drops a request about three hours after it was made, when the
  inbox's floor, which follows the Bitcoin mainnet tip, passes it.
- **What is visible** is that a given Ghost Key sent this bridge a request,
  when (to the block), and how large the sealed request is. That was accepted
  explicitly in freenet/freenet-bitcoin#3: the Ghost Key has to be visible for
  every peer to check the writer is entitled to write.

No contract holds a mapping of any of these forms:

```text
   Ghost Key      →  Bitcoin addresses
   Bitcoin address →  Ghost Key
   user            →  watch list
```

The public `BitcoinAddressContract` contains **no** field for who requested it,
which Ghost Key authorized the request, how many people watch it, or why anyone
cares. A test pins the request format to four fields (action, network, scripts,
and a scan height), so it has nowhere to put a label, an order id, or a user
identity. The bridge sends no reply at all, so nothing reports how many other
people watch the same address.

## Who learns what

### Everyone on the Freenet network

- That a `BitcoinAddressContract` exists for a given script, and its contents:
  bridge-signed observations of on-chain activity.
- Everything on the Bitcoin blockchain, which was already public.
- **Not** who is interested in it.
- From a bridge's inbox: which Ghost Keys send that bridge requests, when, and
  how large each sealed request is. **Not** what any of them asked for.

Caveat with teeth: ordinary Freenet traffic analysis can sometimes let an
observer infer that a peer is interested in a particular contract, because a
peer subscribes to what it cares about. This system does not fix that, and does
not claim to. What it refuses to do is make it *easier* by publishing an index.

### The bridge operator

The bridge necessarily learns, and can correlate:

- that the holder of a given Ghost Key asked it to synchronize script X, and
  when. It records this in its own database (`script_interests`), because that
  is what lets one requester's unwatch leave other requesters' interest in
  place.

It is no longer handed the requester's IP address: a request travels through
Freenet rather than over a connection to the bridge. Freenet traffic analysis
still applies (see below).

**A Ghost Key is a stable identifier, not an anonymous one.** Blind signing
prevents the *notary* from linking a donation to the resulting key. It does
nothing to stop anyone from recognising the same certificate across requests.
So a bridge operator can link one user's requests to each other, anyone reading
the inbox can do the same without learning what was asked, and colluding
operators can link a user across their services.

Mitigations, in descending order of effectiveness:

- **Run your own bridge**, listing your scripts in its `always_watch`
  configuration. Nothing is then sent to anyone, and the observations are
  byte-identical to any other bridge's. This is the real answer and the reason
  no Ghost Key appears in the observation format.
- **Use a distinct Ghost Key per relying party.** The vault supports this; it
  does not enforce it.

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

1. **Bridge correlation.** Ghost Key plus requested scripts, in the operator's
   database. Mitigated by self-hosting, not eliminated by anything in this repo.
2. **Inbox metadata.** Anyone reading a bridge's inbox sees which Ghost Keys
   send it requests, when, and how large each sealed request is. Requests are
   not padded, so size hints at how many scripts one names.
3. **Freenet traffic analysis.** Subscribing to `BitcoinAddressContract(X)`
   signals interest in X to an observer well-placed on the network. Inherent to
   the platform.
4. **Public demo addresses.** The operator's curated demonstration addresses are
   public by construction. They are nobody's private watch, and a user cannot
   unwatch them because they are not the user's.
5. **On-chain linkage.** Reusing one address across several Harvest orders links
   those orders on the public blockchain. The right fix is a fresh address per
   order, which the delegate is the natural place to implement and which this
   prototype does not do.

## Lightning changes this picture

Lightning payments leave no public on-chain record, so there is nothing for a
bridge to watch and no watch request to make. The entire bridge-correlation
surface above disappears for Lightning-settled orders. That is a genuine
privacy argument for Lightning, independent of the fee argument.

What replaces it is a different exposure: the payer's Lightning node learns the
route, and the seller's node learns the payment. Neither is a globally
enumerable index, so it is a materially better position — but it is not nothing.
