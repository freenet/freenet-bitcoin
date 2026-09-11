# freenet-bitcoin

Bitcoin blockchain state, exposed to Freenet applications through generic
contracts, with a bridge that observes the chain and publishes signed
observations, each carrying the transaction and block evidence behind it so
readers can check what it says against those bytes.

The observations are not specific to any application, to Freenet.org, or to
Ghost Keys: a reader needs no credential. Asking a bridge to watch a script
does need a Ghost Key (see "Service access" below).

## What this is

```text
Bitcoin network -> Bitcoin Core (pruned) -> bridge -> Freenet contracts -> your app
```

- **`BitcoinAddressContract(network, scriptPubKey)`** — observations for one
  output script. A distributed index shard for a payment destination.
- **`BitcoinTipContract(network)`** — the public chain tip and recent blocks, so
  confirmation depth is computed once rather than duplicated per address, and an
  application's first screen can show live Bitcoin data with no credential.
- **`BitcoinInboxContract(bridge)`**: the bridge's request inbox. A Ghost Key
  holder asks the bridge to watch a script by appending a request sealed to
  the bridge; the bridge acts on it and removes it. This is the bridge's only
  interface: it has no network listener.
- **`bitcoin-freenet-bridge`** — observes Bitcoin Core and publishes into those
  contracts. Anyone may run one.

## The two ideas that matter

**Reorgs, without breaking convergence.** Freenet needs state that merges
associatively, commutatively and idempotently. Bitcoin's chain reorganizes. So
nothing is ever edited: state is a grow-only set of signed assertions stamped
with the asserting bridge's chain height, and a reorg adds a *newer* assertion
rather than rewriting an old one. Status is derived by folding, highest height
wins.

**The evidence travels with the claim, and it narrows what the bridge can lie
about.** A signature only proves a bridge *said* something, so every
confirmed-payment claim also carries SPV evidence — the raw transaction, a
Merkle branch, and block headers. Any reader confirms from those bytes that
the txid commits to that amount and that destination, that the transaction is
committed to by that header, and that each header meets the target it names.
So a bridge cannot misreport what a real transaction paid, or to whom.

**The bridge is still trusted, and for the thing that matters most.** Nothing
here anchors a header to Bitcoin — there is no checkpoint, no path to genesis,
no accumulated-work comparison — so *which blocks are on the chain* is the
bridge's word, and so is confirmation depth, which applications compute from
the claim's block height and a bridge-signed tip. A holder of a trusted bridge
key can assert a payment that never happened. The SPV layer is defence in
depth against a lying bridge, not a way to stop trusting one; choose
`trusted_bridges` accordingly. [docs/trust-boundaries.md](docs/trust-boundaries.md)
states the boundary in full.

## Privacy

> A Bitcoin address becomes public only when application semantics require it.
> Merely watching an address never makes it public.

Freenet contracts are readable by anyone who knows the key and replicated
indefinitely, so a contract listing who wants which address synchronized would
be a permanent, globally enumerable surveillance index. The bridge's inbox is a
public contract, so it is built not to be one: each request is sealed to the
bridge, and the bridge removes it once read. The network sees that a given
Ghost Key sent the bridge a request, and when, and never which scripts. The
bridge itself learns which Ghost Key asked for which script and keeps that in
its own database, never replicated. What each party learns is written up in
[docs/privacy.md](docs/privacy.md).

## Service access is not Bitcoin semantics

A bridge decides who may ask it to do work. It takes requests only from Ghost
Key holders: its inbox admits an entry only when it is signed by a key whose
certificate chains to Freenet's Ghost Key master key, and every peer checks
that before storing it. That is what makes a donation buy something concrete,
and what stops the inbox being an open invitation to make the bridge scan
arbitrary scripts. It gates requests only. Observations carry no Ghost Key,
and reading them needs none.

```text
service authorization    "May this caller ask THIS bridge to do work?"
observation authenticity "Did THIS bridge sign this Bitcoin fact?"
```

These are constantly confused and must not be.

## Documentation

- [docs/architecture.md](docs/architecture.md) — design, reorg model, SPV, related-contract limits
- [docs/privacy.md](docs/privacy.md) — what leaks, to whom, and what does not
- [docs/trust-boundaries.md](docs/trust-boundaries.md) — boundaries and the attacks considered
- [docs/deployment.md](docs/deployment.md) — running it, and the traps

## Building

```bash
cargo make test                  # the merge laws, SPV, the inbox and the bridge
./scripts/build-contracts.sh     # never `cargo build` a contract; see docs/deployment.md
cargo build --release -p bitcoin-freenet-bridge
```

## Status

A prototype with a working vertical slice. Real third-party signet payments are
observed, published to Freenet, retrieved, and re-checked against their own
evidence. See [docs/deployment.md](docs/deployment.md) for what is deployed.
