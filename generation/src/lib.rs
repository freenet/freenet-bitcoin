//! Which contract generation a bridge is publishing to, and how a reader finds
//! out without being told at build time.
//!
//! # The failure this exists to remove
//!
//! A contract's address is `BLAKE3(BLAKE3(wasm) || params)`, so the *code* is
//! part of the address. Rebuilding a contract — for a logic change, a
//! dependency bump, or nothing more than a `cargo fmt`, because release
//! binaries embed panic locations as `file:line` — moves every instance of it.
//!
//! Two artifacts have to agree on that address: the bridge, which publishes
//! observations into it, and a reader, which derives it to read them back.
//! When they disagree **nothing errors**. The reader derives an address nobody
//! has written to and gets an empty contract, which is byte-for-byte what "no
//! payments here yet" looks like. Both halves are individually correct and the
//! product is a blank page.
//!
//! # What is actually stable
//!
//! Nothing that is derived from WASM. Every contract in this repository
//! re-keys on any edit to `freenet-bitcoin-common`, which all of them embed.
//! So an anchor cannot be one of our own contracts, and it cannot be a
//! compiled-in address either — that is the thing that goes stale.
//!
//! The one durable identifier in the system is the **bridge's signing key**.
//! It is a file on disk, generated once, and no rebuild touches it.
//! Applications already name it explicitly (`trusted_bridges`), it is already
//! part of every contract's parameters, and every fact a reader displays is
//! already signed by it. Anchoring on it therefore adds no new trust.
//!
//! # The anchor
//!
//! The ecosystem's answer to "stop pinning a key that moves" is a **pointer
//! record**: a tiny contract whose state is an author-signed
//! `(version, code_hash)`, and whose own WASM is frozen forever so that its
//! address never moves. `freenet-migrate` publishes that contract's code hash
//! as a constant, and the bytes are vendored here beside it.
//!
//! ```text
//!   pointer address = BLAKE3( FROZEN_POINTER_CODE_HASH || bridge_key || app_id )
//!                             ^^^^^^^^^^^^^^^^^^^^^^^^    ^^^^^^^^^^   ^^^^^^^
//!                             never changes               a key file   a constant
//! ```
//!
//! Every part of that is fixed, so the pointer is findable with no lookup and
//! no configuration. Inside it the bridge writes the code hash of the
//! generation it is *currently* publishing to, and a reader derives its
//! contract addresses from that rather than from the WASM it happens to ship.
//! The indirection stops there: nothing points at the pointer.
//!
//! # Why this crate is not `freenet-bitcoin-common`
//!
//! `common` is compiled into both contracts, so anything added to it re-keys
//! them. Putting generation-tracking logic there would mean that editing the
//! machinery for detecting a re-key *causes* a re-key. This crate is depended
//! on by the bridge and the webapp and by neither contract, which makes that
//! structurally impossible rather than merely discouraged.

#![deny(unsafe_code)]

use ed25519_dalek::VerifyingKey;
use freenet_bitcoin_common::BridgeId;
use freenet_migrate::pointer::{
    pointer_contract_id, pointer_signing_message, PointerError, PointerFloor, PointerResolver,
};
use freenet_stdlib::prelude::ContractInstanceId;

/// The frozen pointer contract, vendored so the bridge can PUT it the first
/// time a pointer is published.
///
/// These bytes are not build output and must never be rebuilt from source: the
/// whole convention rests on this artifact's hash never moving. They are
/// verifiable rather than merely trusted — `vendored_pointer_is_the_frozen_artifact`
/// checks them against [`POINTER_CODE_HASH_B58`], which arrives from crates.io
/// with `freenet-migrate`. A committed binary that proves what it is against an
/// independently-published constant is a different thing from a committed
/// binary nobody can check.
pub const POINTER_CONTRACT_WASM: &[u8] = include_bytes!("../pointer-v1.wasm");

/// Which of this project's two contracts a pointer describes.
///
/// One pointer per artifact, because they are separate WASM modules with
/// separate code hashes. A pointer record holds exactly one code hash, and
/// `freenet-migrate` gives each `(author, app_id)` pair its own independent
/// version space — so these must not share one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Artifact {
    Address,
    Tip,
}

impl Artifact {
    /// The pointer `app_id`, which is part of the pointer's address.
    ///
    /// Restricted by the pointer contract to `a-z 0-9 . - _`, so these are
    /// lowercase and dot-separated. **Changing one moves the pointer**, which
    /// strands every reader resolving through it, so treat these as wire
    /// constants rather than names.
    pub const fn app_id(self) -> &'static [u8] {
        match self {
            Artifact::Address => b"freenet-bitcoin.address",
            Artifact::Tip => b"freenet-bitcoin.tip",
        }
    }

    /// How to name this artifact to a human.
    pub const fn label(self) -> &'static str {
        match self {
            Artifact::Address => "address contract",
            Artifact::Tip => "tip contract",
        }
    }

    pub const ALL: [Artifact; 2] = [Artifact::Address, Artifact::Tip];
}

/// A bridge id, reinterpreted as the Ed25519 key that signs its pointers.
///
/// [`BridgeId`] is already that key — the same one that signs every claim a
/// reader displays. Failing here means the configured bridge id is not a valid
/// point, in which case it could never have signed anything either.
pub fn author_key(bridge: &BridgeId) -> Result<VerifyingKey, PointerError> {
    VerifyingKey::from_bytes(&bridge.0).map_err(|_| PointerError::ParamsKey)
}

/// Where `bridge`'s pointer for `artifact` lives. Deterministic and offline.
pub fn pointer_id(
    bridge: &BridgeId,
    artifact: Artifact,
) -> Result<ContractInstanceId, PointerError> {
    pointer_contract_id(&author_key(bridge)?, artifact.app_id())
}

/// A resolver for `bridge`'s pointer for `artifact`.
///
/// # Why the floor is the caller's problem
///
/// `floor` is the anti-rollback bound: the highest version this reader has
/// ever verified. A reader with durable storage should persist it and pass it
/// back. A reader with none passes [`PointerFloor::never_resolved`] and
/// accepts that a peer serving a genuine but superseded record can point it at
/// an older generation of our own contracts. That is a display-staleness
/// exposure, not a forgery one: the observations under any generation are
/// signed by the same bridge and re-verified against their own Bitcoin
/// evidence before anything is shown.
pub fn resolver(
    bridge: &BridgeId,
    artifact: Artifact,
    floor: PointerFloor,
) -> Result<PointerResolver, PointerError> {
    PointerResolver::new(&author_key(bridge)?, artifact.app_id(), floor)
}

/// The bytes a bridge signs to publish a pointer record.
///
/// Re-exported through this crate so the bridge and any future publisher agree
/// on the message by construction rather than by both remembering the layout.
pub fn signing_message(
    bridge: &BridgeId,
    artifact: Artifact,
    version: u32,
    code_hash: &[u8; 32],
) -> Result<Vec<u8>, PointerError> {
    let params = freenet_migrate::pointer::pointer_params(&author_key(bridge)?, artifact.app_id())?;
    Ok(pointer_signing_message(&params, version, code_hash))
}

/// The pointer's contract parameters: `author_key || app_id`.
pub fn pointer_params(bridge: &BridgeId, artifact: Artifact) -> Result<Vec<u8>, PointerError> {
    freenet_migrate::pointer::pointer_params(&author_key(bridge)?, artifact.app_id())
}

/// A contract's identity: `BLAKE3` over its WASM.
pub fn code_hash(wasm: &[u8]) -> [u8; 32] {
    *blake3::hash(wasm).as_bytes()
}

/// A code hash abbreviated for a UI, in the base58 Freenet renders hashes in.
///
/// Long enough to distinguish generations at a glance, short enough to sit in
/// a sentence. The full value is always available alongside it; this is for
/// the sentence.
pub fn short(code_hash: &[u8; 32]) -> String {
    let full = bs58::encode(code_hash).into_string();
    full.chars().take(8).collect()
}

/// A code hash rendered the way Freenet renders hashes in text.
pub fn code_hash_b58(code_hash: &[u8; 32]) -> String {
    bs58::encode(code_hash).into_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bridge() -> BridgeId {
        BridgeId::from_bs58("4MZnDAQWccEWXBUb1wt4iTEkDi6Z2MCcZ9WQN1umRsVL").unwrap()
    }

    /// The one check that makes a committed binary legitimate: it is the
    /// artifact `freenet-migrate` names, not merely a file somebody put here.
    ///
    /// If this fails, the vendored copy is not the frozen pointer contract and
    /// every pointer this build publishes or reads is at an address nobody
    /// else uses.
    #[test]
    fn vendored_pointer_is_the_frozen_artifact() {
        assert_eq!(
            code_hash_b58(&code_hash(POINTER_CONTRACT_WASM)),
            freenet_migrate::pointer::POINTER_CODE_HASH_B58,
            "generation/pointer-v1.wasm is not the pointer contract freenet-migrate \
             pins; re-vendor it from freenet-migrate/contracts/pointer-contract/"
        );
    }

    /// A pointer address must be computable from a bridge id alone, since that
    /// is all a reader has before it has read anything.
    #[test]
    fn pointer_addresses_are_derivable_offline() {
        let a = pointer_id(&bridge(), Artifact::Address).unwrap();
        let t = pointer_id(&bridge(), Artifact::Tip).unwrap();
        assert_ne!(a, t, "the two artifacts must not share a version space");
    }

    /// Pinned because these strings are part of an address. A rename that
    /// looks cosmetic strands every reader already resolving through the old
    /// one, with no error anywhere.
    #[test]
    fn app_ids_are_wire_constants() {
        assert_eq!(Artifact::Address.app_id(), b"freenet-bitcoin.address");
        assert_eq!(Artifact::Tip.app_id(), b"freenet-bitcoin.tip");
    }

    /// A different bridge is a different pointer: two operators may genuinely
    /// be running different generations, and a reader must follow the one it
    /// trusts rather than whichever answered first.
    #[test]
    fn each_bridge_has_its_own_pointer() {
        let other = BridgeId(
            ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
                .verifying_key()
                .to_bytes(),
        );
        assert_ne!(
            pointer_id(&bridge(), Artifact::Tip).unwrap(),
            pointer_id(&other, Artifact::Tip).unwrap()
        );
    }

    /// The signing message must cover the artifact, or a record the bridge
    /// signed for one contract would validate as the other's.
    #[test]
    fn the_signed_message_separates_the_two_artifacts() {
        let h = [3u8; 32];
        assert_ne!(
            signing_message(&bridge(), Artifact::Address, 1, &h).unwrap(),
            signing_message(&bridge(), Artifact::Tip, 1, &h).unwrap()
        );
    }
}
