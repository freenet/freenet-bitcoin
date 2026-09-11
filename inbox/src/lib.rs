//! A bridge's request inbox: the one way to ask a bridge to watch Bitcoin
//! scripts, entirely through a Freenet contract.
//!
//! Design of record: freenet/freenet-bitcoin#3. This replaces the bridge's
//! HTTP request API, which neither a published Freenet webapp (the gateway's
//! `connect-src` allows only its own node) nor a delegate (no HTTP capability)
//! could reach, so nothing on Freenet could ask a bridge to watch an address.
//!
//! # Shape
//!
//! One inbox per bridge, addressed by [`InboxParameters`]: the bridge's key and
//! the Ghost Key master key certificates must chain to. Anyone holding a Ghost
//! Key appends an [`InboxEntry`]; the bridge reads it, acts, and removes it.
//!
//! * **The Ghost Key is the gatekeeper, and every peer checks it.** An entry
//!   carries, in the clear, the requester's certificate and a signature by the
//!   certified key. The contract verifies the chain to the master key and the
//!   signature, so an entry nobody entitled could have written is never stored.
//! * **What is asked stays sealed.** The request itself (watch or unwatch,
//!   which network, which scripts) is encrypted to the bridge. The network
//!   learns that a given Ghost Key sent this bridge a request, and when. It
//!   never learns which addresses. That trade was decided explicitly in #3.
//! * **The bridge removes what it has read**, with a signed tombstone, and
//!   advances a signed floor ("ignore anything dated below this") that only
//!   ever rises. Both are needed: without a tombstone, any peer still holding
//!   the entry would merge it straight back.
//!
//! # Dating, and why it is Bitcoin mainnet
//!
//! A contract cannot read a clock, so every entry carries its own date: the
//! Bitcoin **mainnet** block height when it was made, read by the sender from
//! the bridge's mainnet tip contract whichever network the request is for.
//! One reference chain means one floor, and the network stays sealed.
//!
//! # The merge, and the one subtle part
//!
//! State merges by union of entries, union of tombstones and the higher floor,
//! then [`InboxStateV1::normalize`] drops what is below the floor, what is
//! tombstoned, and what exceeds the caps. The caps are the subtle part, because
//! capping and removal usually do not commute: keep "the lowest digests" and a
//! tombstone that frees a slot needs back an entry some peer already discarded,
//! so two peers merging in different orders disagree forever.
//!
//! What makes these caps commute: every discarded record ranks *below* every
//! kept one on height (newest first, then key), the floor only ever removes
//! from the bottom of that order, and a tombstone keeps its entry's slot rather
//! than freeing it. So nothing a peer has discarded can ever be needed again.
//! The merge laws are asserted on exact bytes in this crate's tests, across
//! tombstones, floor advances and both caps.

#![deny(unsafe_code)]

mod bytes;
mod state;

#[cfg(feature = "seal")]
pub mod seal;

#[cfg(test)]
mod tests;

pub use bytes::ByteBuf;
pub use state::{InboxDelta, InboxStateV1, InboxSummary, WireEntry};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use freenet_bitcoin_common::{from_cbor, to_cbor, BitcoinNetwork, BridgeId};
use ghostkey_common::{ScopedPayload, SignatureRequestor};
use ghostkey_lib::armorable::Armorable;
use ghostkey_lib::ghost_key_certificate::GhostkeyCertificateV1;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Limits
//
// Sized from a measurement, not a guess. A contract re-verifies its whole state
// on validation, and each distinct certificate costs a full chain check ending
// in an RSA signature: 344 us natively per certificate (2026-09-10), more in
// WASM. Certificates are stored once and shared, so the worst case is one
// distinct Ghost Key per record, which an attacker pays a donation for each.
// ---------------------------------------------------------------------------

/// How far behind the mainnet tip the bridge keeps its floor, in blocks.
///
/// About an hour. It is the tolerance for a sender whose view of the tip is
/// stale: an entry dated below the floor is dropped, so the sender resends.
pub const FLOOR_LAG_BLOCKS: u32 = 6;

/// Entries dated more than this above the floor are refused.
///
/// Stops anyone dating an entry into the future so that it outlives every
/// floor. Comfortably exceeds [`FLOOR_LAG_BLOCKS`], so a sender dating by the
/// tip is always inside it. Safe as a validity rule because the floor only
/// rises: an entry inside the window stays inside it.
pub const WINDOW_BLOCKS: u32 = 18;

/// Records (entries plus tombstones) the inbox holds at once.
pub const MAX_RECORDS: usize = 128;

/// Records one Ghost Key may hold at once.
///
/// A Ghost Key decides who may write, not how much. A tombstone keeps its
/// entry's slot until the floor passes the entry's height, so this is a limit
/// on requests in flight per Ghost Key per hour or so. One request carries up
/// to [`MAX_SCRIPTS_PER_REQUEST`] scripts, so it binds a flooder, not a seller.
pub const MAX_RECORDS_PER_GHOSTKEY: usize = 8;

/// Scripts one request may name. Enforced by senders and the bridge; the
/// contract cannot see inside a sealed request, and bounds its size instead.
pub const MAX_SCRIPTS_PER_REQUEST: usize = 64;

/// Longest scriptPubKey accepted. Standard scripts are at most 43 bytes.
pub const MAX_SCRIPT_BYTES: usize = 100;

/// Largest scoped payload an entry may carry, which bounds the sealed request.
pub const MAX_SCOPED_PAYLOAD_BYTES: usize = 12 * 1024;

/// Largest certificate accepted. A real one is about 1.7 KB.
pub const MAX_CERTIFICATE_BYTES: usize = 4 * 1024;

// ---------------------------------------------------------------------------
// Domains. Every signature and every identity here is domain-separated, so a
// value of one kind can never be presented as another.
// ---------------------------------------------------------------------------

const ENTRY_DOMAIN: &[u8] = b"freenet-bitcoin/inbox-entry/v1\0";
const FLOOR_DOMAIN: &[u8] = b"freenet-bitcoin/inbox-floor/v1\0";
const TOMBSTONE_DOMAIN: &[u8] = b"freenet-bitcoin/inbox-tombstone/v1\0";
const ENTRY_KEY_DOMAIN: &str = "freenet-bitcoin/inbox-entry-key/v1";
const CERT_KEY_DOMAIN: &str = "freenet-bitcoin/inbox-cert-key/v1";

// ---------------------------------------------------------------------------
// 32-byte identities, encoded as CBOR byte strings.
// ---------------------------------------------------------------------------

/// An entry's identity: a digest of the WHOLE entry, so two entries that differ
/// in any byte are two entries. A tombstone is filed under the key of the entry
/// it removes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct EntryKey(pub [u8; 32]);
freenet_bitcoin_common::impl_bytes32_serde!(EntryKey);

/// A certificate's identity in the state's certificate map.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct CertKey(pub [u8; 32]);
freenet_bitcoin_common::impl_bytes32_serde!(CertKey);

/// A Ghost Key's Ed25519 verifying key: what the per-Ghost Key cap groups by.
///
/// Grouped by the key rather than by certificate bytes, so re-encoding one
/// certificate differently does not buy a second allowance.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct GhostkeyId(pub [u8; 32]);
freenet_bitcoin_common::impl_bytes32_serde!(GhostkeyId);

/// The Ed25519 master key certificates must chain to.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct MasterKey(pub [u8; 32]);
freenet_bitcoin_common::impl_bytes32_serde!(MasterKey);

/// A sender's one-time X25519 public key, part of a sealed request.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct EphemeralKey(pub [u8; 32]);
freenet_bitcoin_common::impl_bytes32_serde!(EphemeralKey);

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

/// Parameters of one inbox instance, and therefore part of its address.
///
/// The master key is here rather than compiled in so an isolated test network
/// can run a whole inbox under a test authority without real donations.
/// Senders derive the production inbox with [`InboxParameters::production`];
/// an inbox under any other master is simply a different contract nobody
/// reads.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct InboxParameters {
    pub bridge: BridgeId,
    pub ghostkey_master: MasterKey,
}

impl InboxParameters {
    /// The inbox a bridge actually reads: certificates chain to Freenet's
    /// published master key.
    pub fn production(bridge: BridgeId) -> Self {
        InboxParameters {
            bridge,
            ghostkey_master: production_master(),
        }
    }
}

/// Freenet's published Ghost Key master key, as compiled into `ghostkey_lib`.
pub fn production_master() -> MasterKey {
    let vk = VerifyingKey::from_base64(ghostkey_lib::FREENET_MASTER_VERIFYING_KEY_BASE64)
        .expect("ghostkey_lib's compiled-in master key decodes");
    MasterKey(*vk.as_bytes())
}

// ---------------------------------------------------------------------------
// The sealed request
// ---------------------------------------------------------------------------

/// What a request asks the bridge to do.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    /// Start, or keep, synchronizing these scripts.
    Watch,
    /// Stop wanting these scripts synchronized. Removes only the sender's own
    /// interest: the bridge stops scanning a script when nobody still wants it.
    Unwatch,
}

/// The plaintext of a request, which only the bridge can read.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct InboxRequest {
    pub action: Action,
    pub network: BitcoinNetwork,
    pub scripts: Vec<ByteBuf>,
    /// A hint that nothing before this height needs scanning: a freshly
    /// derived address has no history. The bridge may ignore it.
    pub scan_from_height: Option<u32>,
}

impl InboxRequest {
    /// The shape rules a well-formed request obeys.
    pub fn check(&self) -> Result<(), String> {
        if self.scripts.is_empty() {
            return Err("a request must name at least one script".into());
        }
        if self.scripts.len() > MAX_SCRIPTS_PER_REQUEST {
            return Err(format!(
                "a request may name at most {MAX_SCRIPTS_PER_REQUEST} scripts, got {}",
                self.scripts.len()
            ));
        }
        for s in &self.scripts {
            if s.is_empty() || s.len() > MAX_SCRIPT_BYTES {
                return Err(format!(
                    "a script must be 1 to {MAX_SCRIPT_BYTES} bytes, got {}",
                    s.len()
                ));
            }
        }
        Ok(())
    }
}

/// A request sealed to one bridge's encryption key. See `seal`.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct Sealed {
    pub ephemeral: EphemeralKey,
    pub nonce: ByteBuf,
    pub ciphertext: ByteBuf,
}

// ---------------------------------------------------------------------------
// Entries
// ---------------------------------------------------------------------------

/// What a sender signs, through the ghostkey delegate.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct InboxEntryBody {
    /// The bridge this entry is for, inside the signature so it cannot be
    /// replayed into another bridge's inbox.
    pub bridge: BridgeId,
    /// Bitcoin mainnet block height when the entry was made.
    pub mainnet_height: u32,
    pub sealed: Sealed,
}

impl InboxEntryBody {
    /// The exact bytes to hand the ghostkey delegate as `SignMessage.message`.
    pub fn signing_payload(&self) -> Result<Vec<u8>, String> {
        let mut v = ENTRY_DOMAIN.to_vec();
        v.extend(to_cbor(self)?);
        Ok(v)
    }

    /// Recover the body from what the ghostkey delegate signed.
    pub fn from_signing_payload(payload: &[u8]) -> Result<Self, String> {
        let body = payload
            .strip_prefix(ENTRY_DOMAIN)
            .ok_or("the signed payload is not an inbox entry")?;
        from_cbor(body)
    }
}

/// An entry as held in inbox state.
///
/// Its certificate lives once in the state's certificate map and is referenced
/// by [`CertKey`]. `mainnet_height` and `ghostkey` are copies of values inside
/// the signed material, kept so the state can be ordered and capped without
/// decoding every entry; [`InboxStateV1::verify`] checks both against the
/// signature.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct InboxEntry {
    pub mainnet_height: u32,
    pub ghostkey: GhostkeyId,
    pub cert: CertKey,
    /// CBOR `ScopedPayload`, exactly as the ghostkey delegate returned it.
    pub scoped_payload: ByteBuf,
    /// Ed25519 by `ghostkey` over `scoped_payload`.
    pub signature: ByteBuf,
}

impl InboxEntry {
    /// This entry's identity. Covers every field, which is the point: an id
    /// that hashed only some of them would let two different entries share one.
    pub fn key(&self) -> EntryKey {
        let bytes = to_cbor(self).unwrap_or_default();
        let mut h = blake3::Hasher::new_derive_key(ENTRY_KEY_DOMAIN);
        h.update(&bytes);
        EntryKey(*h.finalize().as_bytes())
    }
}

/// A certificate's identity: a digest of its armoured text.
pub fn cert_key(pem: &str) -> CertKey {
    let mut h = blake3::Hasher::new_derive_key(CERT_KEY_DOMAIN);
    h.update(pem.as_bytes());
    CertKey(*h.finalize().as_bytes())
}

/// Check a certificate chains to `master`, returning the Ghost Key it certifies.
///
/// This is the expensive check (it ends in an RSA signature), so callers verify
/// each distinct certificate once and share the result.
pub fn verify_certificate(pem: &str, master: &MasterKey) -> Result<VerifyingKey, String> {
    if pem.len() > MAX_CERTIFICATE_BYTES {
        return Err(format!(
            "certificate is {} bytes, limit is {MAX_CERTIFICATE_BYTES}",
            pem.len()
        ));
    }
    let cert = GhostkeyCertificateV1::from_armored_string(pem)
        .map_err(|e| format!("certificate does not parse: {e:?}"))?;
    let master =
        VerifyingKey::from_bytes(&master.0).map_err(|_| "master key is not a valid point")?;
    cert.verify(&Some(master))
        .map_err(|e| format!("certificate does not chain to the master key: {e:?}"))?;
    Ok(cert.verifying_key)
}

/// Check one entry against the Ghost Key its (already verified) certificate
/// certifies, returning the signed body.
pub(crate) fn verify_entry(
    entry: &InboxEntry,
    certified: &VerifyingKey,
    params: &InboxParameters,
) -> Result<InboxEntryBody, String> {
    if entry.ghostkey.0 != *certified.as_bytes() {
        return Err("entry names a different Ghost Key than its certificate certifies".into());
    }
    if entry.scoped_payload.len() > MAX_SCOPED_PAYLOAD_BYTES {
        return Err(format!(
            "scoped payload is {} bytes, limit is {MAX_SCOPED_PAYLOAD_BYTES}",
            entry.scoped_payload.len()
        ));
    }
    let sig: [u8; 64] = entry
        .signature
        .as_ref()
        .try_into()
        .map_err(|_| "signature must be 64 bytes")?;
    certified
        .verify(&entry.scoped_payload, &Signature::from_bytes(&sig))
        .map_err(|_| "the Ghost Key did not sign this entry")?;

    let scoped: ScopedPayload = from_cbor(&entry.scoped_payload)?;
    // Any caller may send a request: a web app today, the seller's own
    // delegate once auto-accept exists. The body binds the signature to this
    // bridge's inbox, which is what stops it being reused elsewhere.
    match scoped.requestor {
        SignatureRequestor::WebApp(_) | SignatureRequestor::Delegate(_) => {}
        _ => return Err("signature was requested by an unknown kind of caller".into()),
    }
    let body = InboxEntryBody::from_signing_payload(&scoped.payload)?;
    if body.bridge != params.bridge {
        return Err("entry is addressed to a different bridge".into());
    }
    if body.mainnet_height != entry.mainnet_height {
        return Err("entry's height does not match what was signed".into());
    }
    if body.sealed.nonce.len() != 12 {
        return Err("sealed nonce must be 12 bytes".into());
    }
    Ok(body)
}

// ---------------------------------------------------------------------------
// What the bridge signs. Laid out by hand rather than as CBOR, so the signed
// bytes are fixed by this code and not by a serializer's future behaviour.
// ---------------------------------------------------------------------------

fn floor_message(bridge: &BridgeId, height: u32) -> Vec<u8> {
    let mut v = FLOOR_DOMAIN.to_vec();
    v.extend_from_slice(&bridge.0);
    v.extend_from_slice(&height.to_le_bytes());
    v
}

fn tombstone_message(bridge: &BridgeId, entry: &EntryKey, height: u32, gk: &GhostkeyId) -> Vec<u8> {
    let mut v = TOMBSTONE_DOMAIN.to_vec();
    v.extend_from_slice(&bridge.0);
    v.extend_from_slice(&entry.0);
    v.extend_from_slice(&height.to_le_bytes());
    v.extend_from_slice(&gk.0);
    v
}

fn check_bridge_sig(bridge: &BridgeId, msg: &[u8], sig: &[u8]) -> Result<(), String> {
    let vk = VerifyingKey::from_bytes(&bridge.0).map_err(|_| "bridge id is not a valid key")?;
    let sig: [u8; 64] = sig.try_into().map_err(|_| "signature must be 64 bytes")?;
    vk.verify(msg, &Signature::from_bytes(&sig))
        .map_err(|_| "not signed by this inbox's bridge".to_string())
}

/// "Ignore anything dated below this": the bridge's floor.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct SignedFloor {
    pub height: u32,
    pub signature: ByteBuf,
}

impl SignedFloor {
    pub fn sign(key: &SigningKey, height: u32) -> Self {
        let bridge = BridgeId(key.verifying_key().to_bytes());
        SignedFloor {
            height,
            signature: ByteBuf(
                key.sign(&floor_message(&bridge, height))
                    .to_bytes()
                    .to_vec(),
            ),
        }
    }

    pub fn verify(&self, bridge: &BridgeId) -> Result<(), String> {
        check_bridge_sig(bridge, &floor_message(bridge, self.height), &self.signature)
    }
}

/// The bridge has read this entry. Filed under the entry's key.
///
/// Carries the entry's height and Ghost Key so it keeps the entry's slot in
/// both the floor order and the per-Ghost Key cap. It lives until the floor
/// passes the ENTRY's height: keyed on the time of removal instead, it could
/// expire while its entry was still above the floor and let it come back.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct SignedTombstone {
    pub entry: EntryKey,
    pub entry_height: u32,
    pub ghostkey: GhostkeyId,
    pub signature: ByteBuf,
}

impl SignedTombstone {
    pub fn for_entry(key: &SigningKey, entry_key: EntryKey, entry: &InboxEntry) -> Self {
        let bridge = BridgeId(key.verifying_key().to_bytes());
        let msg = tombstone_message(&bridge, &entry_key, entry.mainnet_height, &entry.ghostkey);
        SignedTombstone {
            entry: entry_key,
            entry_height: entry.mainnet_height,
            ghostkey: entry.ghostkey,
            signature: ByteBuf(key.sign(&msg).to_bytes().to_vec()),
        }
    }

    pub fn verify(&self, bridge: &BridgeId) -> Result<(), String> {
        let msg = tombstone_message(bridge, &self.entry, self.entry_height, &self.ghostkey);
        check_bridge_sig(bridge, &msg, &self.signature)
    }
}
