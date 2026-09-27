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
//!   certified key, or by a watch key the certified key delegated to (see
//!   [`Delegation`]). The contract verifies the chain to the master key and the
//!   signatures, so an entry nobody entitled could have written is never
//!   stored.
//! * **What is asked stays sealed.** The request itself (watch or unwatch,
//!   which network, which scripts) is encrypted to the bridge. The network
//!   learns that a given Ghost Key sent this bridge a request, and when. It
//!   never learns which addresses. That trade was decided explicitly in #3.
//! * **The bridge removes what it has read**, and advances a signed floor
//!   ("ignore anything dated below this") that only ever rises. Removal leaves
//!   a record behind, because without one any peer still holding the entry
//!   would merge it straight back. The record is small and does not take the
//!   entry's place (see [`RemovalBatch`]).
//!
//! # Dating, and why it is Bitcoin mainnet
//!
//! A contract cannot read a clock, so every entry carries its own date, a
//! Bitcoin **mainnet** block height whichever network the request is for: one
//! reference chain means one floor, and the network stays sealed. The bridge
//! keeps the floor [`FLOOR_LAG_BLOCKS`] behind the mainnet tip.
//!
//! A sender dates its entry with [`sender_height`]: the inbox's current floor,
//! read from the inbox itself, plus [`WINDOW_BLOCKS`] less
//! [`SENDER_SLACK_BLOCKS`]. Records rank newest first when the caps bind, so
//! an entry dated near the top of the window is outranked by height only by
//! the few blocks of slack. The slack is for peers whose floor is a block or
//! two behind the sender's: to them the very top of the window lies beyond it,
//! and they drop such an entry until their floor catches up.
//!
//! # What a sender does after sending
//!
//! The bridge sends no reply. A removal naming the sender's entry
//! ([`InboxStateV1::is_removed`]) means the bridge has READ the request, not
//! that it did what was asked: it removes a request it cannot open, one for a
//! network it does not observe, and a Watch beyond its sender's limit of
//! watched scripts, in the same way as one it acted on. What a Watch did shows
//! up where it matters, in the address contract for the script. If the entry
//! disappears without being removed, because the floor passed it or the caps
//! pushed it out before the bridge read it, the sender seals and sends it
//! again. The floor passes an unread entry about half an hour after it is
//! sent (see [`WINDOW_BLOCKS`]). A sender whose copy of the inbox lags the
//! real floor by three blocks or more dates below it and is dropped at once,
//! so a sender should read the floor just before sending.
//!
//! **A Watch lasts a day, or through the height it names.** The bridge ends a watch once a block
//! it has scanned, buried as deep as it requires of payments, is dated a day after the last Watch
//! that asked for it and is above its [`InboxRequest::watch_until_height`], if it named one, unless
//! a payment to the script is still being buried. A sender that still wants the script sends the
//! Watch again, with a newer `made_at_ms`, well before then: a renewal on its way to the bridge's
//! node when the watch ends does not save it.
//!
//! A sender sends its entry together with the floor it read
//! ([`InboxDelta::submission`]), so a peer whose floor lags takes the floor
//! first and then admits the entry. Each entry goes in its own delta: a delta
//! carrying more than [`MAX_ENTRIES_PER_GHOSTKEY`] entries from one Ghost Key
//! is refused whole.
//!
//! # The merge, and the one subtle part
//!
//! State merges by union of entries, union of removal batches and the higher
//! floor, then [`InboxStateV1::normalize`] drops what is below the floor, what
//! has been removed, and what exceeds the caps. The caps are the subtle part.
//!
//! Removal frees an entry's place under the caps. That is the point: it is
//! what lets a bridge that reads quickly keep its inbox open to everyone. It
//! has a cost. Suppose a peer holding more entries than the caps allow
//! discards the lowest-ranked one, and then learns that a higher-ranked entry
//! was removed. The entry it discarded would now fit, and it no longer has it,
//! while a peer that learned of the removal first kept it. So when the caps
//! overflow, the order records arrive in can decide which entry survives.
//!
//! What holds regardless, and what this crate's tests assert on exact bytes:
//!
//! * **While no cap discards anything, the merge laws hold exactly.** Union,
//!   removal, the floor and the ranking are each independent of order. That
//!   means at no step of a merge, not only in its result: a third entry from
//!   one Ghost Key is discarded on arrival even if a removal later makes room.
//! * **Two peers that exchange state agree afterwards**, because the normal
//!   form is a function of the records present and the floor alone. An entry
//!   one peer discarded comes back from any peer that kept it, if it still
//!   fits under the caps there; one that no peer kept is gone for everyone.
//!   Until the peers agree, a peer whose caps refuse an entry is sent it
//!   again on each exchange.
//!
//! The caps overflow when more requests are waiting than they allow: more
//! than [`MAX_ENTRIES`] in all, which is a flood, a third from one Ghost
//! Key before the bridge has read its first two, or a second from one Ghost
//! Key's watch keys (see [`Delegation`]). Either way some request is
//! dropped whatever the rule, and a sender whose entry vanished without
//! being removed sends it again.

#![deny(unsafe_code)]

mod bytes;
mod state;

#[cfg(feature = "seal")]
pub mod seal;

#[cfg(feature = "test-support")]
pub mod test_support;

#[cfg(test)]
mod tests;

pub use bytes::ByteBuf;
pub use state::{InboxDelta, InboxStateV1, InboxSummary, WireEntry};

use std::collections::BTreeSet;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
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
// WASM. Certificates are stored once and shared, and a certificate's check is
// spent only on an entry that claims the key it names and is signed under it,
// so a state costs at most one check per distinct genuine certificate in it,
// and a refused message at most one: validation stops at the first that
// fails, which is how a fabricated certificate costs its sender one check.
// That bounds the cost; it does not make the worst case cost an attacker
// anything. Genuine entries are public, a floor stays valid once signed, so
// entries from any window can be assembled into a valid state, and the node
// validates the whole state after every update, even one that changes
// nothing.
// ---------------------------------------------------------------------------

/// How far behind the mainnet tip the bridge keeps its floor, in blocks.
///
/// Senders date an entry from the floor, not the tip (see [`sender_height`]),
/// so this only places the floor relative to the chain. It is kept below
/// [`WINDOW_BLOCKS`], so an entry dated by the tip itself is inside the window
/// too: with these values [`sender_height`] is the tip.
pub const FLOOR_LAG_BLOCKS: u32 = 2;

/// Entries dated more than this above the floor are refused.
///
/// Stops anyone dating an entry into the future so that it outlives every
/// floor. Safe as a validity rule because the floor only rises: an entry
/// inside the window stays inside it.
///
/// It also sets how long a request and its removal last. A sender dates at
/// `floor + WINDOW_BLOCKS - SENDER_SLACK_BLOCKS`, and the floor passes that
/// height three blocks later: about half an hour on average, though blocks
/// arrive irregularly and three can take anything from a few minutes to over
/// an hour. The bridge normally reads a request within seconds of it reaching
/// the bridge's node; one it has not read by then is dropped, and its sender
/// sends it again.
pub const WINDOW_BLOCKS: u32 = 4;

/// How far below the top of the window a sender dates its entry. See the
/// module docs: enough for a peer whose floor lags by a block or two, and
/// small, because anything dated in the slack outranks the entry by height.
pub const SENDER_SLACK_BLOCKS: u32 = 2;

/// The height a sender dates an entry with, given the floor it read from the
/// inbox.
pub fn sender_height(floor: u32) -> u32 {
    floor.saturating_add(WINDOW_BLOCKS - SENDER_SLACK_BLOCKS)
}

/// Entries, which are requests not yet read, the inbox holds at once.
///
/// **This is also what censoring the inbox costs.** Holding every place takes
/// `MAX_ENTRIES / MAX_ENTRIES_PER_GHOSTKEY` Ghost Keys, 64 of them. A read
/// entry gives its place up, so they must keep sending; and the bridge reads
/// each Ghost Key only up to its share of [`REMOVAL_BUDGET`], a 64th, before
/// the floor moves on. So the cheapest hold is also what spends the budget:
/// 64 Ghost Keys each sending about 66 requests every five blocks, about 50
/// minutes. Five, not three, because nothing makes an attacker date entries
/// as senders do: dated at the top of the window, they and their removals
/// last until the floor passes that height, and they outrank every entry
/// dated by [`sender_height`] by height alone. The caps rank newest first, and
/// ties at one height are broken by entry key, which a sender can grind. What
/// honest senders get is the refill: between two bridge passes each Ghost Key
/// can put back only its two entries. Raising it means more
/// entries, and every entry's certificate is an RSA check each time a peer
/// validates the state.
pub const MAX_ENTRIES: usize = 128;

/// Of those, how many a watch key the Ghost Key delegated to may hold (see
/// [`Delegation`]): the rest are kept for the Ghost Key's own entries, so a
/// stolen watch key cannot keep its owner's revocation out of the inbox.
pub const MAX_DELEGATED_ENTRIES_PER_GHOSTKEY: usize = 1;

/// Entries one Ghost Key may hold at once.
///
/// A Ghost Key decides who may write; this decides how much of the inbox one
/// can occupy. A read entry gives its place back, so this limits how many
/// requests a sender has waiting, not how many it sends. Requests dated at
/// one height rank by entry key, so a third sent before the bridge has read
/// the first two may displace one of them: send one request naming all your
/// scripts rather than several at once.
pub const MAX_ENTRIES_PER_GHOSTKEY: usize = 2;

/// Bytes of an entry's key a removal keeps.
///
/// Eight rather than thirty-two, because a removal is kept for every entry
/// the bridge reads until the floor passes it. A sender who wanted its own
/// entry's removal to take someone else's pending entry with it would need an
/// entry whose key shares these 8 bytes with a pending one. With up to
/// [`MAX_ENTRIES`] pending entries to aim at, that is about 2^57 tries, each a
/// signature and a hash, against entries that live about half an hour. Two
/// of an attacker's own entries colliding, about 2^32 tries, harms nobody
/// else. A removal names entries of its own height only, so a collision
/// matters only between two entries dated at the same height.
pub const REMOVED_PREFIX_BYTES: usize = 8;

/// Removed entries the inbox may name, across all its removal batches.
///
/// A hard bound on state size: 64 KiB of prefixes. Only the bridge signs
/// removals, and it keeps itself to [`REMOVAL_BUDGET`], half of this. A lagging
/// peer does not need the slack, because every batch travels with the floor
/// it was signed under; what the slack absorbs is a bridge that lost its
/// database within one window and so signed a second, unrelated set of
/// batches for the same heights. Two such losses in one window can exceed
/// this bound, and peers then refuse the bridge's deltas until the floor
/// passes the old batches, within five blocks.
pub const MAX_REMOVED: usize = 8192;

/// How many entries the bridge reads before the floor must move on.
///
/// The bridge removes whatever it reads, and stops reading once the removals
/// the floor has not yet passed reach this; new requests then wait for the
/// floor. The bridge also gives each Ghost Key only a share of it (a 64th,
/// `REMOVAL_SHARE_PER_GHOSTKEY` in the bridge), so reaching it takes 64
/// Ghost Keys each having 64 requests read within five blocks, about 50
/// minutes (about 66 sent each, to hold every place in the inbox as well; see
/// [`MAX_ENTRIES`]).
pub const REMOVAL_BUDGET: usize = MAX_REMOVED / 2;

/// Removal batches the inbox may hold.
///
/// The bridge signs one per height it has read entries at, and a larger batch
/// replaces a smaller one it covers (see [`RemovalBatch`]), so an honest inbox
/// holds about one per height in the window.
pub const MAX_REMOVAL_BATCHES: usize = 64;

/// Scripts one request may name. Enforced by senders and the bridge; the
/// contract cannot see inside a sealed request, and bounds its size instead.
pub const MAX_SCRIPTS_PER_REQUEST: usize = 32;

/// Longest scriptPubKey accepted. Standard scripts are at most 43 bytes.
pub const MAX_SCRIPT_BYTES: usize = 100;

/// Largest scoped payload an entry may carry, which bounds the sealed request.
/// A request naming [`MAX_SCRIPTS_PER_REQUEST`] scripts of
/// [`MAX_SCRIPT_BYTES`] each seals to about 3.4 KB, and the scoped payload
/// wrapping it measures 6,818 bytes: `ghostkey-common` encodes the signed
/// payload as an array of integers, which roughly doubles it. A test pins that
/// the largest allowed request fits.
pub const MAX_SCOPED_PAYLOAD_BYTES: usize = 8 * 1024;

/// Largest certificate accepted. A real one is about 1.7 KB.
pub const MAX_CERTIFICATE_BYTES: usize = 4 * 1024;

// ---------------------------------------------------------------------------
// Domains. Every signature and every identity here is domain-separated, so a
// value of one kind can never be presented as another.
// ---------------------------------------------------------------------------

const ENTRY_DOMAIN: &[u8] = b"freenet-bitcoin/inbox-entry/v1\0";
/// What a watch key signs for an entry. Distinct from [`ENTRY_DOMAIN`], so a
/// watch key's signature can never be taken for a Ghost Key's, or the reverse.
const WATCH_ENTRY_DOMAIN: &[u8] = b"freenet-bitcoin/inbox-watch-key-entry/v1\0";
/// What a Ghost Key signs to delegate its watch requests to a watch key.
const DELEGATION_DOMAIN: &[u8] = b"freenet-bitcoin/inbox-watch-delegation/v1\0";
const DELEGATION_DIGEST_DOMAIN: &str = "freenet-bitcoin/inbox-watch-delegation-digest/v1";
const FLOOR_DOMAIN: &[u8] = b"freenet-bitcoin/inbox-floor/v1\0";
const REMOVAL_DOMAIN: &[u8] = b"freenet-bitcoin/inbox-removal/v1\0";
const BATCH_KEY_DOMAIN: &str = "freenet-bitcoin/inbox-removal-key/v1";
const ENTRY_KEY_DOMAIN: &str = "freenet-bitcoin/inbox-entry-key/v1";
const CERT_KEY_DOMAIN: &str = "freenet-bitcoin/inbox-cert-key/v1";

// ---------------------------------------------------------------------------
// 32-byte identities, encoded as CBOR byte strings.
// ---------------------------------------------------------------------------

/// An entry's identity: a digest of the WHOLE entry, so two entries that differ
/// in any byte are two entries.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct EntryKey(pub [u8; 32]);
freenet_bitcoin_common::impl_bytes32_serde!(EntryKey);

impl EntryKey {
    /// What a removal keeps of this key. See [`REMOVED_PREFIX_BYTES`].
    pub fn removal_prefix(&self) -> RemovedPrefix {
        let mut p = [0u8; REMOVED_PREFIX_BYTES];
        p.copy_from_slice(&self.0[..REMOVED_PREFIX_BYTES]);
        RemovedPrefix(p)
    }
}

/// The part of an entry's key a removal keeps.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct RemovedPrefix(pub [u8; REMOVED_PREFIX_BYTES]);

/// A removal batch's identity: a digest of its height and what it removes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct BatchKey(pub [u8; 32]);
freenet_bitcoin_common::impl_bytes32_serde!(BatchKey);

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

/// A watch key: the Ed25519 key a Ghost Key delegates its watch requests to
/// (see [`Delegation`]).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct WatchKeyId(pub [u8; 32]);
freenet_bitcoin_common::impl_bytes32_serde!(WatchKeyId);

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
    /// Start, or keep, synchronizing these scripts for a day of block time from the later of
    /// `made_at_ms` and when the bridge reads it (by its clock, or the newest block it has scanned
    /// where that is later), counting `made_at_ms` at most a week past that, or through
    /// [`InboxRequest::watch_until_height`] where that is later. Send it again, with a newer
    /// `made_at_ms`, to keep a script watched longer, and keep doing so until any payment awaited
    /// is buried: a transaction still unmined when the watch ends is not found.
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
    /// When the sender made this request, in milliseconds since the Unix epoch by the sender's own
    /// clock. Only the bridge reads it, to apply one sender's requests about one script in the
    /// order they were made, which neither the entries' heights nor their arrival order can tell
    /// it. Untrusted, and only ever compared with the same sender's requests. It must strictly
    /// increase across one sender's requests: a sender making two in one millisecond adds one to
    /// the second. On a tie the bridge takes a withdrawal over a watch. So a sender whose clock ran
    /// ahead keeps its timestamps above those it sent meanwhile: until its clock passes them, a
    /// request dated lower is ignored, a renewal included.
    pub made_at_ms: u64,
    /// For a Watch, the last block of `network` to scan these scripts through: see
    /// [`MAX_WATCH_AHEAD_BLOCKS`], which says what the bridge does with it (freenet-bitcoin#26).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub watch_until_height: Option<u32>,
    /// From the Ghost Key itself: revoke every [`Delegation`] of this Ghost
    /// Key issued at or below this Bitcoin mainnet height
    /// ([`DelegationBody::issued_mainnet_height`]). The bridge refuses them
    /// from then on and withdraws every watch a request under one of them
    /// recorded, renewals of the Ghost Key's own watches included, so send
    /// Watch again for everything still wanted. To rotate, issue the new
    /// delegation at a later height than the old one and revoke through the
    /// height just below it. Nothing lowers a revocation, and a delegation can
    /// be issued no later than the entries that use it are dated, so revoking
    /// through a height far ahead blocks every delegation until then.
    ///
    /// The bridge ignores a value more than [`WINDOW_BLOCKS`] above its
    /// mainnet tip, or any value while it cannot read the tip, so a mistake
    /// in units (a Unix time in seconds fits a `u32`) cannot lock the Ghost
    /// Key out of delegations for decades. Send it again on a later request.
    ///
    /// Applied whatever the request's `made_at_ms`, as a mark that only rises
    /// need not be ordered. Ignored on a request a watch key signed, so a
    /// stolen watch key cannot lock its owner's newer one out. A sender may
    /// send its current value on every request of its own, which also
    /// restores it to a bridge that lost its database. Left out of the
    /// encoding when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoke_watch_keys_through: Option<u32>,
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

    /// The exact bytes a watch key signs for this body under `delegation`,
    /// which the entry carries as its `scoped_payload`: no vault is involved.
    ///
    /// They include a digest of the delegation, so the signature holds only
    /// under the delegation it was made under. Otherwise anyone could re-wrap
    /// a watch key's entry in another delegation to the same key, making a
    /// new entry that takes its Ghost Key's places in the inbox.
    pub fn watch_key_signing_payload(&self, delegation: &Delegation) -> Result<Vec<u8>, String> {
        let mut v = WATCH_ENTRY_DOMAIN.to_vec();
        v.extend_from_slice(&delegation.digest());
        v.extend(to_cbor(self)?);
        Ok(v)
    }

    /// Recover the body from what a watch key signed, and the digest of the
    /// delegation it was signed under.
    pub fn from_watch_key_signing_payload(payload: &[u8]) -> Result<([u8; 32], Self), String> {
        let rest = payload
            .strip_prefix(WATCH_ENTRY_DOMAIN)
            .ok_or("the signed payload is not a watch key's inbox entry")?;
        if rest.len() < 32 {
            return Err("a watch key's inbox entry is too short".into());
        }
        let (digest, body) = rest.split_at(32);
        let mut d = [0u8; 32];
        d.copy_from_slice(digest);
        Ok((d, from_cbor(body)?))
    }
}

// ---------------------------------------------------------------------------
// Delegated watch keys
// ---------------------------------------------------------------------------

/// Largest `scoped_payload` a [`Delegation`] may carry. A real one, from the
/// vault, measures a few hundred bytes (a test pins that one fits).
pub const MAX_DELEGATION_BYTES: usize = 1024;

/// What a Ghost Key signs, through the ghostkey vault, to let a watch key send
/// this bridge Watch and Unwatch requests on its behalf.
///
/// A request a watch key signs under a delegation is acted on as the Ghost
/// Key's own: it counts against the Ghost Key's limits and is ordered with the
/// Ghost Key's other requests by `made_at_ms`. That is all it can do. The
/// inbox carries nothing but Watch and Unwatch requests, the delegation names
/// one bridge, and it is signed in a domain of its own, so neither it nor any
/// signature by the watch key is anything but an inbox entry for that bridge.
///
/// It lets an application's background process, such as a Freenet delegate
/// that cannot reach the Ghost Key, keep asking for watches after the person
/// has gone away, including for addresses derived after they left.
///
/// **One watch key per Ghost Key and bridge.** The bridge honours only the
/// latest-issued delegation of a Ghost Key it has seen used, and of two issued
/// at the same height the one it saw used first, so two applications, or two
/// devices, that each delegate the same Ghost Key to their own key disable
/// one of them. A request under a delegation the bridge refuses as revoked or
/// superseded is left unread, and vanishes when the floor passes it, with no
/// removal; one refused for sharing its delegation's height with another key's
/// is removed as though acted on. Either way nothing says it was refused but
/// the script's scan watermark never appearing, and a sender that resends a
/// request which vanished unremoved will resend such a one for ever: a sender
/// that sees its watch key's requests go unwatched after being sent twice
/// should stop and ask for a new delegation. Share one watch key, or use a
/// Ghost Key each.
///
/// **What the Ghost Key keeps for itself.** An entry a watch key signs takes at
/// most one of its Ghost Key's places in the inbox, and at most all but
/// `OWNER_RESERVE` of its share of the bridge's reading, so a stolen watch key
/// cannot crowd out the Ghost Key's own requests, its revocation included.
///
/// **One request waiting at a time.** That one place means a watch key's
/// second entry, sent before the bridge has read its first, replaces one of
/// the two, not necessarily the older: send one request naming every script
/// (up to [`MAX_SCRIPTS_PER_REQUEST`]), and send the next only once the inbox
/// holds a removal naming it or it has gone.
///
/// It is in the clear in the inbox, where every peer checks it, so it names
/// nothing the inbox otherwise keeps sealed: no network, and no script. A
/// reader of the inbox learns that a Ghost Key delegated to some key, at which
/// block height, and that a request came from the delegated key rather than
/// the Ghost Key.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct DelegationBody {
    /// The one bridge this delegation is for.
    pub bridge: BridgeId,
    /// The key that may sign requests.
    pub watch_key: WatchKeyId,
    /// The Bitcoin mainnet height the delegation was made at: a sender uses
    /// the height it dates its entries by, [`sender_height`] of the floor it
    /// read. It orders one Ghost Key's delegations: the contract keeps, of a
    /// Ghost Key's entries a watch key signed, only the one under the latest
    /// delegation, and the bridge refuses one issued before the latest it has
    /// seen used, or at or below the height the Ghost Key revoked through
    /// ([`InboxRequest::revoke_watch_keys_through`]).
    ///
    /// The contract refuses an entry dated before its delegation was issued,
    /// and entries are dated within a few blocks of the real chain, so no
    /// delegation can be used while it claims a height ahead of the chain.
    /// One signed for a future height becomes usable when the chain reaches
    /// it, and then outranks those issued before it: revoking through that
    /// height, and issuing anew above it, undoes it within a block.
    ///
    /// Two delegations issued at the same height to different keys conflict:
    /// the bridge honours the one it saw used first.
    pub issued_mainnet_height: u32,
    /// The last Bitcoin mainnet height an entry under this delegation may be
    /// dated. The contract enforces it, as entries are dated by the mainnet
    /// height and the floor keeps those dates honest. `None` for none.
    pub expires_mainnet_height: Option<u32>,
}

impl DelegationBody {
    /// The exact bytes to hand the ghostkey vault as `SignMessage.message`.
    pub fn signing_payload(&self) -> Result<Vec<u8>, String> {
        let mut v = DELEGATION_DOMAIN.to_vec();
        v.extend(to_cbor(self)?);
        Ok(v)
    }

    /// Recover the body from what the Ghost Key signed.
    pub fn from_signing_payload(payload: &[u8]) -> Result<Self, String> {
        let body = payload
            .strip_prefix(DELEGATION_DOMAIN)
            .ok_or("the signed payload is not a watch delegation")?;
        from_cbor(body)
    }
}

/// A [`DelegationBody`] as the Ghost Key signed it.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct Delegation {
    /// CBOR `ScopedPayload`, exactly as the ghostkey vault returned it, whose
    /// payload is [`DelegationBody::signing_payload`].
    pub scoped_payload: ByteBuf,
    /// Ed25519 by the Ghost Key over `scoped_payload`.
    pub signature: ByteBuf,
}

impl Delegation {
    /// Build a delegation from what the ghostkey vault's `SignResult`
    /// returned. Nothing is checked here; the contract checks all of it.
    pub fn from_sign_result(scoped_payload: Vec<u8>, signature: Vec<u8>) -> Self {
        Delegation {
            scoped_payload: ByteBuf(scoped_payload),
            signature: ByteBuf(signature),
        }
    }

    /// What a watch key's entry signature binds this delegation by.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new_derive_key(DELEGATION_DIGEST_DOMAIN);
        h.update(&self.scoped_payload);
        *h.finalize().as_bytes()
    }

    /// The body, decoded without checking the signature. Only for entries
    /// already verified.
    pub fn body(&self) -> Result<DelegationBody, String> {
        let scoped: ScopedPayload = from_cbor(&self.scoped_payload)?;
        DelegationBody::from_signing_payload(&scoped.payload)
    }

    /// Check that `ghostkey` signed this delegation for this bridge, and that
    /// it is well formed, returning its body. Ed25519 only.
    pub(crate) fn verify(
        &self,
        ghostkey: &VerifyingKey,
        params: &InboxParameters,
    ) -> Result<DelegationBody, String> {
        if self.scoped_payload.len() > MAX_DELEGATION_BYTES {
            return Err(format!(
                "delegation is {} bytes, limit is {MAX_DELEGATION_BYTES}",
                self.scoped_payload.len()
            ));
        }
        let sig: [u8; 64] = self
            .signature
            .as_ref()
            .try_into()
            .map_err(|_| "delegation signature must be 64 bytes")?;
        ghostkey
            .verify_strict(&self.scoped_payload, &Signature::from_bytes(&sig))
            .map_err(|_| "the Ghost Key did not sign this delegation")?;
        let scoped: ScopedPayload = from_cbor(&self.scoped_payload)?;
        match scoped.requestor {
            SignatureRequestor::WebApp(_) | SignatureRequestor::Delegate(_) => {}
            _ => return Err("delegation was requested by an unknown kind of caller".into()),
        }
        let body = DelegationBody::from_signing_payload(&scoped.payload)?;
        if body.bridge != params.bridge {
            return Err("delegation is for a different bridge".into());
        }
        let watch = VerifyingKey::from_bytes(&body.watch_key.0)
            .map_err(|_| "delegation names a watch key that is not a valid point")?;
        if watch.is_weak() {
            return Err("delegation names a weak watch key, which anyone can sign for".into());
        }
        Ok(body)
    }
}

impl WireEntry {
    /// An entry a watch key signs under `delegation`, carrying the delegating
    /// Ghost Key's certificate. What a background sender, holding the watch
    /// key but not the Ghost Key, sends.
    pub fn delegated(
        certificate_pem: String,
        delegation: Delegation,
        watch_key: &SigningKey,
        body: &InboxEntryBody,
    ) -> Result<Self, String> {
        let certificate_pem = canonical_certificate(&certificate_pem)?;
        let cert = GhostkeyCertificateV1::from_armored_string(&certificate_pem)
            .map_err(|e| format!("certificate does not parse: {e:?}"))?;
        let payload = body.watch_key_signing_payload(&delegation)?;
        let signature = watch_key.sign(&payload).to_bytes().to_vec();
        Ok(WireEntry {
            entry: InboxEntry {
                mainnet_height: body.mainnet_height,
                ghostkey: GhostkeyId(*cert.verifying_key.as_bytes()),
                cert: cert_key(&certificate_pem),
                scoped_payload: ByteBuf(payload),
                signature: ByteBuf(signature),
                delegation: Some(delegation),
            },
            certificate_pem,
        })
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
    /// Without a delegation: CBOR `ScopedPayload`, exactly as the ghostkey
    /// delegate returned it. With one: the watch key's signing payload,
    /// [`InboxEntryBody::watch_key_signing_payload`].
    pub scoped_payload: ByteBuf,
    /// Ed25519 over `scoped_payload`: by `ghostkey`, or with a delegation by
    /// the watch key it names.
    pub signature: ByteBuf,
    /// Present when a watch key, not the Ghost Key, signed this entry: the
    /// Ghost Key's signed permission for that key. Left out of the encoding
    /// when absent, so an entry without one is the same bytes as before
    /// delegations existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<Delegation>,
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

    /// The body this entry's Ghost Key, or its watch key, signed, decoded
    /// without checking the signature. Only for entries already verified, as
    /// every entry in a state that passed [`InboxStateV1::verify`] is.
    pub fn body(&self) -> Result<InboxEntryBody, String> {
        if self.delegation.is_some() {
            return InboxEntryBody::from_watch_key_signing_payload(&self.scoped_payload)
                .map(|(_, body)| body);
        }
        let scoped: ScopedPayload = from_cbor(&self.scoped_payload)?;
        InboxEntryBody::from_signing_payload(&scoped.payload)
    }
}

/// A certificate's one armoured form: parsed, then armoured again.
///
/// `ghostkey_lib` accepts any text around the armour, so without this one
/// certificate would have unlimited spellings, each a distinct key in the state
/// and each costing an RSA check. A production certificate is already in this
/// form, and armouring is a fixed point (both checked 2026-09-10).
pub fn canonical_certificate(pem: &str) -> Result<String, String> {
    if pem.len() > MAX_CERTIFICATE_BYTES {
        return Err(format!(
            "certificate is {} bytes, limit is {MAX_CERTIFICATE_BYTES}",
            pem.len()
        ));
    }
    GhostkeyCertificateV1::from_armored_string(pem)
        .map_err(|e| format!("certificate does not parse: {e:?}"))?
        .to_armored_string()
        .map_err(|e| format!("certificate does not armour: {e:?}"))
}

/// Check that a certificate names the Ghost Key an entry claims, reading the
/// certificate without checking its chain.
///
/// No RSA, so callers run it before [`verify_certificate`]. Otherwise real
/// certificates, which are public, paired with entries signed by keys nobody
/// certified would pass [`verify_entry_signature`] and cost a peer the RSA
/// check before [`certifies`] refused them.
pub(crate) fn names_claimed_key(pem: &str, entry: &InboxEntry) -> Result<(), String> {
    if pem.len() > MAX_CERTIFICATE_BYTES {
        return Err(format!(
            "certificate is {} bytes, limit is {MAX_CERTIFICATE_BYTES}",
            pem.len()
        ));
    }
    let cert = GhostkeyCertificateV1::from_armored_string(pem)
        .map_err(|e| format!("certificate does not parse: {e:?}"))?;
    if *cert.verifying_key.as_bytes() != entry.ghostkey.0 {
        return Err("entry names a different Ghost Key than its certificate certifies".into());
    }
    Ok(())
}

/// A certificate's identity: a digest of its armoured text, which the state
/// holds only in canonical form (see [`canonical_certificate`]).
pub fn cert_key(pem: &str) -> CertKey {
    let mut h = blake3::Hasher::new_derive_key(CERT_KEY_DOMAIN);
    h.update(pem.as_bytes());
    CertKey(*h.finalize().as_bytes())
}

// Certificate chain checks made on this thread, so a test can assert that a
// forgery cost none.
#[cfg(test)]
thread_local! {
    pub(crate) static RSA_CHECKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Check a certificate chains to `master`, returning the Ghost Key it certifies.
///
/// This is the expensive check (it ends in an RSA signature), so callers verify
/// each distinct certificate once and share the result.
pub fn verify_certificate(pem: &str, master: &MasterKey) -> Result<VerifyingKey, String> {
    #[cfg(test)]
    RSA_CHECKS.with(|c| c.set(c.get() + 1));
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
    check_ghostkey(&cert.verifying_key)?;
    Ok(cert.verifying_key)
}

/// Refuse a Ghost Key anyone could sign for.
///
/// The notary blind-signs whatever key a donor submits, so a certificate can
/// certify a low-order point such as the all-zero key. Signatures under such a
/// key can be forged by anyone, so its entries would be anyone's. Strict
/// verification refuses those signatures too; this refuses the certificate.
pub(crate) fn check_ghostkey(key: &VerifyingKey) -> Result<(), String> {
    if key.is_weak() {
        return Err("certificate certifies a weak key, which anyone can sign for".into());
    }
    Ok(())
}

/// Check that a verified certificate certifies the Ghost Key an entry claims.
pub(crate) fn certifies(certified: &VerifyingKey, entry: &InboxEntry) -> Result<(), String> {
    if entry.ghostkey.0 != *certified.as_bytes() {
        return Err("entry names a different Ghost Key than its certificate certifies".into());
    }
    Ok(())
}

/// Check one entry's own signature under the Ghost Key it claims, returning
/// the signed body. The claim means nothing until [`certifies`] ties it to a
/// verified certificate.
///
/// Callers run this, after [`names_claimed_key`], before any certificate's
/// chain. Certificates are public, so anyone can pair real ones with entries
/// of their own; checked in this order, such an entry costs a peer a
/// certificate parse and an Ed25519 check, not an RSA check.
pub(crate) fn verify_entry_signature(
    entry: &InboxEntry,
    params: &InboxParameters,
) -> Result<InboxEntryBody, String> {
    let claimed = VerifyingKey::from_bytes(&entry.ghostkey.0)
        .map_err(|_| "entry names a Ghost Key that is not a valid point")?;
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
    let body = match &entry.delegation {
        // Signed by a watch key the Ghost Key delegated to: the Ghost Key's
        // signature on the delegation first, then the watch key's on the
        // entry. Both Ed25519, so a forgery still costs no RSA check.
        Some(delegation) => {
            let d = delegation.verify(&claimed, params)?;
            if d.issued_mainnet_height > entry.mainnet_height {
                return Err("entry is dated before its delegation was issued".into());
            }
            if d.expires_mainnet_height
                .is_some_and(|last| entry.mainnet_height > last)
            {
                return Err("entry is dated after its delegation expired".into());
            }
            let watch = VerifyingKey::from_bytes(&d.watch_key.0)
                .map_err(|_| "delegation names a watch key that is not a valid point")?;
            watch
                .verify_strict(&entry.scoped_payload, &Signature::from_bytes(&sig))
                .map_err(|_| "the watch key did not sign this entry")?;
            let (digest, body) =
                InboxEntryBody::from_watch_key_signing_payload(&entry.scoped_payload)?;
            if digest != delegation.digest() {
                return Err("the watch key signed this entry under another delegation".into());
            }
            body
        }
        None => {
            claimed
                .verify_strict(&entry.scoped_payload, &Signature::from_bytes(&sig))
                .map_err(|_| "the Ghost Key did not sign this entry")?;
            let scoped: ScopedPayload = from_cbor(&entry.scoped_payload)?;
            // Any caller may send a request: a web app, or the seller's own
            // delegate. The body binds the signature to this bridge's inbox,
            // which is what stops it being reused elsewhere.
            match scoped.requestor {
                SignatureRequestor::WebApp(_) | SignatureRequestor::Delegate(_) => {}
                _ => return Err("signature was requested by an unknown kind of caller".into()),
            }
            InboxEntryBody::from_signing_payload(&scoped.payload)?
        }
    };
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

fn removal_message(bridge: &BridgeId, height: u32, removed: &[u8]) -> Vec<u8> {
    let mut v = REMOVAL_DOMAIN.to_vec();
    v.extend_from_slice(&bridge.0);
    v.extend_from_slice(&height.to_le_bytes());
    v.extend_from_slice(removed);
    v
}

fn check_bridge_sig(bridge: &BridgeId, msg: &[u8], sig: &[u8]) -> Result<(), String> {
    let vk = VerifyingKey::from_bytes(&bridge.0).map_err(|_| "bridge id is not a valid key")?;
    let sig: [u8; 64] = sig.try_into().map_err(|_| "signature must be 64 bytes")?;
    vk.verify_strict(msg, &Signature::from_bytes(&sig))
        .map_err(|_| "not signed by this inbox's bridge".to_string())
}

/// "Ignore anything dated below this": the bridge's floor.
///
/// Ed25519 signing is deterministic, so a bridge that signs one height twice
/// produces one record. The merge still orders two different signatures for
/// one height (the smaller wins), and likewise for removal batches, so a
/// bridge that ever signed non-deterministically would not break convergence
/// by merging. It would break it through summaries, which carry the floor's
/// height and a removal batch's key but not the signature, so such a pair would
/// never be reconciled. Bridges must sign deterministically.
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

/// "The bridge has read these entries": the removal record.
///
/// Names entries by [`RemovedPrefix`], all dated at one block height, and
/// lasts until the floor passes that height. Dated by the ENTRIES' height, not
/// the time of removal: dated by the latter, a removal could expire while its
/// entries were still above the floor and let them come back.
///
/// For each height it has read entries at, the bridge signs one batch naming
/// every entry at that height it has read so far. As it reads more, it signs
/// a larger batch for the height, and a batch another one covers is dropped
/// ([`RemovalBatch::covered_by`]). So batches do not pile up, and a batch that
/// failed to land is superseded by the next rather than resent.
///
/// A removal takes no place under the entry caps: an entry gives its place
/// back as soon as its removal arrives.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct RemovalBatch {
    /// The height of the entries this batch removes.
    pub height: u32,
    /// Their prefixes, concatenated, ascending and distinct.
    pub removed: ByteBuf,
    pub signature: ByteBuf,
}

impl RemovalBatch {
    pub fn sign(key: &SigningKey, height: u32, removed: &BTreeSet<RemovedPrefix>) -> Self {
        let bridge = BridgeId(key.verifying_key().to_bytes());
        let bytes: Vec<u8> = removed.iter().flat_map(|p| p.0).collect();
        let signature = key.sign(&removal_message(&bridge, height, &bytes));
        RemovalBatch {
            height,
            removed: ByteBuf(bytes),
            signature: ByteBuf(signature.to_bytes().to_vec()),
        }
    }

    /// At least one prefix and at most [`MAX_REMOVED`], whole prefixes only,
    /// ascending with no repeats: one set of removals, one byte string. Cheap,
    /// so checked before anything is hashed or verified.
    pub fn check_shape(&self) -> Result<(), String> {
        let b = &self.removed.0;
        if b.is_empty() || !b.len().is_multiple_of(REMOVED_PREFIX_BYTES) {
            return Err("a removal batch must name at least one whole prefix".into());
        }
        if b.len() / REMOVED_PREFIX_BYTES > MAX_REMOVED {
            return Err(format!(
                "a removal batch may name at most {MAX_REMOVED} entries"
            ));
        }
        let mut chunks = b.chunks_exact(REMOVED_PREFIX_BYTES);
        let mut last = chunks.next();
        for p in chunks {
            if last.is_some_and(|l| l >= p) {
                return Err("a removal batch's prefixes must ascend with no repeats".into());
            }
            last = Some(p);
        }
        Ok(())
    }

    pub fn verify(&self, bridge: &BridgeId) -> Result<(), String> {
        self.check_shape()?;
        let msg = removal_message(bridge, self.height, &self.removed.0);
        check_bridge_sig(bridge, &msg, &self.signature)
    }

    /// This batch's identity: its height and what it removes. Not the
    /// signature, which a bridge signing deterministically never varies, and
    /// which it must leave out: [`Self::covered_by`] holds both ways between
    /// batches with the same content, so one content filed under two keys
    /// would have each drop the other.
    pub fn key(&self) -> BatchKey {
        let mut h = blake3::Hasher::new_derive_key(BATCH_KEY_DOMAIN);
        h.update(&self.height.to_le_bytes());
        h.update(&self.removed.0);
        BatchKey(*h.finalize().as_bytes())
    }

    /// How many entries it removes.
    pub fn len(&self) -> usize {
        self.removed.0.len() / REMOVED_PREFIX_BYTES
    }

    pub fn is_empty(&self) -> bool {
        self.removed.0.is_empty()
    }

    pub fn prefixes(&self) -> impl Iterator<Item = RemovedPrefix> + '_ {
        self.removed.0.chunks_exact(REMOVED_PREFIX_BYTES).map(|c| {
            let mut p = [0u8; REMOVED_PREFIX_BYTES];
            p.copy_from_slice(c);
            RemovedPrefix(p)
        })
    }

    /// Whether `other` makes this batch redundant: it is for the same height
    /// and removes everything this one does. A batch at another height names
    /// other entries, however its prefixes compare. Both must pass
    /// [`Self::check_shape`]. A batch covers itself, so callers compare keys.
    ///
    /// Dropping covered batches keeps the batches that nothing covers, which
    /// is the same set whichever order batches arrive in: that is what lets it
    /// sit inside the merge.
    pub fn covered_by(&self, other: &RemovalBatch) -> bool {
        if other.height != self.height || other.len() < self.len() {
            return false;
        }
        let mut theirs = other.removed.0.chunks_exact(REMOVED_PREFIX_BYTES);
        'mine: for p in self.removed.0.chunks_exact(REMOVED_PREFIX_BYTES) {
            for q in theirs.by_ref() {
                match q.cmp(p) {
                    std::cmp::Ordering::Less => continue,
                    std::cmp::Ordering::Equal => continue 'mine,
                    std::cmp::Ordering::Greater => return false,
                }
            }
            return false;
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Watches held through a height (freenet-bitcoin#26). At the end of the file
// on purpose: the inbox contract's bytes include the line and column of every
// panic site in this file, so a line added above one re-keys the contract.
// The docs this change touched above were rewrapped to keep their line counts.
// To check an edit above: `git diff -U0 origin/main -- inbox/src/lib.rs` must
// net zero lines before this block, and scripts/build-contracts.sh must print
// the inbox hash CI printed for main.
// ---------------------------------------------------------------------------

/// How far above its own tip a bridge holds a Watch's
/// [`InboxRequest::watch_until_height`]: 6048 blocks, six weeks at ten minutes
/// a block.
///
/// # What the bridge does with the height
///
/// It keeps the watch until the block it buries as deep as it requires of
/// payments (its deciding block) is above the height, or for the usual day,
/// whichever is later. So a payment mined at or below the height is found and
/// buried in full before the watch ends. The height is held to at most this
/// many blocks above the bridge's tip for the request's network when it reads
/// the request, or above its scan position where the tip cannot be read; a
/// bridge that knows neither keeps no height and gives the watch its day.
///
/// A later Watch never lowers a height already held, so a renewal that names
/// none, from a sender that predates the field, is harmless. An Unwatch ends
/// the watch at once and forgets it, as does the watch running out. Every
/// script counts once against the sender's limit of watched scripts, however
/// far ahead it is held.
///
/// Entries at one inbox height are read in key order, not the order their
/// sender made them, so a Watch naming a height may be read after the same
/// sender's later renewal naming none. Its height still raises the running
/// watch's; nothing else about it is applied.
///
/// The field is left out of the encoding when `None`, so a request without it
/// is the same bytes as before it existed. A bridge from before the field
/// ignores it and gives the watch its day.
///
/// # What a sender can rely on
///
/// * **The height it will get.** At least `min(h, T + MAX_WATCH_AHEAD_BLOCKS)`
///   for a requested `h`, where `T` is the height in this bridge's own tip
///   contract for the network, read before sending. The bridge clamps above
///   the highest of its node's tip, its scan position and the newest block it
///   has recorded, and its tip contract follows its scan, so only a reorg that
///   shortens the chain can make it less, by that reorg's depth.
/// * **That the bridge read the request**, from the removal naming the entry
///   ([`InboxStateV1::is_removed`]). Read is not accepted: a Watch past the
///   sender's limit of watched scripts is removed the same way.
/// * **That the script is being scanned now**, from the scan watermark this
///   bridge publishes to the script's address contract every block for every
///   script it watches, used or not.
///
/// What it cannot tell in advance is that the bridge honours heights at all:
/// a bridge from before the field, one rolled back to such a build included,
/// scans the script exactly as a new one does until the day runs out, and then
/// stops. A sender that must not be wrong for that day either knows which
/// build the bridge it trusts runs, or counts only on the day until it has
/// seen a script's watermark keep advancing for more than a day after the last
/// Watch naming it.
///
/// # Asking for only what is needed
///
/// A held script keeps its place under the sender's limit of watched scripts
/// until its height passes, and only an Unwatch frees it sooner. A sender that
/// asks for the whole six weeks on every script it may use fills that limit
/// far sooner than one whose watches lapse after a day, and a Watch past the
/// limit is refused without a word. Ask for the height the script is actually
/// needed to, and Unwatch what is no longer needed while you can.
///
/// # Why six weeks
///
/// Sized for an application that hands out payment addresses from a pool
/// watched in advance, then needs each one watched for a payment window after
/// handing it out: Harvest needs 2208 blocks for that, which leaves a pool
/// watched this far ahead usable for about four weeks with nobody renewing it.
///
/// It bounds how long a watch nobody renews outlives its requester, not how
/// much a Ghost Key can have watched: the per-Ghost Key limit of watched
/// scripts does that, and a key that renews daily could always hold that many
/// for ever. Each watched script costs the bridge an address contract update
/// per block, so a script held this far ahead and never used costs about 6000
/// updates, where one renewed for a day costs about 150: one request now
/// commits the bridge to about 40 times the work it did, which is the price of
/// a client being able to go away.
///
/// Senders compute what they can rely on from this value, so it is part of the
/// protocol rather than an operator's setting: a bridge that wanted a lower
/// limit would have to say so where senders can read it.
pub const MAX_WATCH_AHEAD_BLOCKS: u32 = 6 * 7 * 144;
