//! Shared wire types for exposing Bitcoin blockchain observations to Freenet
//! applications.
//!
//! This crate is deliberately **generic**. It knows nothing about Harvest,
//! about Freenet.org, or about Ghost Keys. It defines:
//!
//! * how a Bitcoin output script is turned into a Freenet contract instance,
//! * what a bridge asserts about that script, and
//! * how a reader folds a pile of such assertions into a current answer.
//!
//! Anyone may run a bridge. Which bridges an application chooses to *believe*
//! is a per-application policy expressed in contract parameters, not something
//! baked into this format. Who is *allowed to ask* a particular bridge to do
//! work is a third, entirely separate question that lives in the bridge's own
//! service-authorization layer and never appears on the wire here.
//!
//! # What a bridge is trusted for
//!
//! **Chain state.** A bridge asserts which blocks are on Bitcoin, what height
//! each one is at, and where the tip is, and nothing in this crate checks any
//! of that against the real network. A holder of a trusted bridge key can
//! therefore assert a payment that never happened, which is why
//! `trusted_bridges` is a deliberate, per-instance choice.
//!
//! Confirmed-payment claims additionally carry SPV evidence, and it is
//! load-bearing: it binds a claim to a self-consistent transaction and block,
//! so a bridge cannot misreport what a real transaction paid or to whom. It is
//! defence in depth against a lying bridge, not a way to stop trusting one.
//! [`spv`] sets out exactly which properties survive and which do not.
//!
//! # The reorg model, in one paragraph
//!
//! Bitcoin's canonical chain is not monotonic — blocks get reorganized — but
//! Freenet contract state must converge under an associative, commutative,
//! idempotent merge. We reconcile the two by never storing a mutable
//! "confirmed" flag. Instead the state is a **grow-only set of signed,
//! chain-height-stamped assertions**: "bridge B, whose best chain tipped at
//! height H, asserts X". Assertions accumulate and are never deleted or
//! rewritten. A reorg does not retract an old assertion; it produces a *newer*
//! one at a greater `as_of` height. Current status is then **derived** by
//! folding the set and letting the highest `as_of` win per outpoint. Set union
//! is trivially associative, commutative and idempotent, and the fold is a
//! deterministic pure function of the set, so every replica computes the same
//! answer from the same bytes. See [`fold_outpoint_status`].
//!
//! # Why depth comes from the claim, not from the tip
//!
//! The fold is a pure function of the claims it is *handed*, and on a
//! verification path those are the claims a submitter chose to hand over. A
//! submitter holding a pre-reorg confirmation and the retraction that
//! superseded it can present the first and drop the second; nothing in a pure
//! function can tell a complete set from a curated one.
//!
//! What turned that omission into a forgery was measuring confirmation depth
//! as `supplied_tip - anchor + 1`. That number grows with the chain, so a
//! retracted assertion the bridge made at depth 1 read as arbitrarily deep
//! against a current tip. So depth is now bounded by what the signing bridge
//! itself asserted — `as_of.height - anchor.height + 1`, both fields inside
//! the signature — via [`OutpointStatus::confirmations_at`]. A stale
//! confirmation is worth stale depth, and reaching depth `d` with a block that
//! was reorged out requires a reorg at least `d` deep, which is the risk a
//! recipient waiting `d` confirmations already accepts.

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};

pub mod address_state;
pub mod bridge_protocol;
pub mod bytes32;
pub mod digest;
pub mod signing;
pub mod spv;
pub mod tip_state;

pub use address_state::{BitcoinAddressStateV1, ClaimSetV1};
pub use bridge_protocol::{
    BridgeError, BridgeStatus, BroadcastRequest, GhostKeyAuth, RequestBody, ServiceAuth,
    ServiceRequest, ServiceResponse, WatchRequest,
};
pub use signing::{SignedClaim, SignedTipEntry};
pub use spv::{PowFloor, SpvError, SpvProof, SpvVerified};
pub use tip_state::BitcoinTipStateV1;

/// Serialize a value to canonical CBOR bytes.
///
/// Every signature in this crate is over CBOR produced here, so this function
/// is a wire-format commitment: changing it invalidates every signature ever
/// produced and re-keys nothing (the contracts would simply start rejecting
/// historical observations). Do not "improve" it.
pub fn to_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|e| format!("CBOR serialize: {e}"))?;
    Ok(buf)
}

/// Deserialize a value from CBOR bytes.
pub fn from_cbor<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, String> {
    ciborium::from_reader(bytes).map_err(|e| format!("CBOR deserialize: {e}"))
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

/// Which Bitcoin network an observation belongs to.
///
/// This is part of the contract parameters, so the *same* script on mainnet and
/// on signet are two different Freenet contracts and can never be confused for
/// one another. It is also folded into [`ScriptId`], so a signature over a
/// signet observation cannot be replayed as a mainnet one.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum BitcoinNetwork {
    Bitcoin,
    Testnet4,
    Signet,
    Regtest,
}

impl BitcoinNetwork {
    /// Stable byte tag used in domain separation. Never renumber these: doing
    /// so silently changes every [`ScriptId`] and orphans all existing state.
    pub const fn tag(self) -> u8 {
        match self {
            BitcoinNetwork::Bitcoin => 0,
            BitcoinNetwork::Testnet4 => 1,
            BitcoinNetwork::Signet => 2,
            BitcoinNetwork::Regtest => 3,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            BitcoinNetwork::Bitcoin => "bitcoin",
            BitcoinNetwork::Testnet4 => "testnet4",
            BitcoinNetwork::Signet => "signet",
            BitcoinNetwork::Regtest => "regtest",
        }
    }

    /// A conservative minimum proof-of-work for headers on this network.
    ///
    /// A standalone block header does not say what the difficulty at its
    /// height was supposed to be, so without a floor a run of trivially-easy
    /// headers mined on a laptop would satisfy every other SPV check. The
    /// floor need only be a LOWER bound, and difficulty rising over time makes
    /// a fixed floor more conservative rather than less, so this does not go
    /// stale in the dangerous direction.
    ///
    /// **It is a sanity check, not an economic security boundary.** The value
    /// is chosen so it never rejects a genuine block, and that is the whole of
    /// what it buys. `0x1900ffff` corresponds to roughly 4e9 times the genesis
    /// difficulty, which is still of order 10^4 BELOW mainnet's recent
    /// difficulty; do not read it as bounding what a forged header chain
    /// costs. And clearing the floor says nothing about whether a header is on
    /// Bitcoin: no checkpoint, genesis path, or accumulated-work comparison
    /// exists anywhere in this crate. That remains a bridge assertion.
    ///
    /// The test networks get no floor at all. Signet's difficulty is trivial
    /// by design (blocks are authorized by the signet challenge key, not by
    /// work), testnet4 permits minimum-difficulty blocks, and regtest has no
    /// work at all. This is precisely why a signet demo shows the mechanism
    /// working but says nothing about mainnet-grade security.
    pub const fn default_pow_floor(self) -> crate::spv::PowFloor {
        match self {
            BitcoinNetwork::Bitcoin => crate::spv::PowFloor(0x1900_ffff),
            BitcoinNetwork::Testnet4 | BitcoinNetwork::Signet | BitcoinNetwork::Regtest => {
                crate::spv::PowFloor::NONE
            }
        }
    }

    /// How many confirmations this network's applications should treat as
    /// final by default. Mainnet's 6 is the conventional figure; the test
    /// networks use fewer purely so demos do not take an hour.
    pub const fn default_confirmation_target(self) -> u32 {
        match self {
            BitcoinNetwork::Bitcoin => 6,
            BitcoinNetwork::Testnet4 | BitcoinNetwork::Signet => 2,
            BitcoinNetwork::Regtest => 1,
        }
    }
}

impl core::str::FromStr for BitcoinNetwork {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "bitcoin" | "main" | "mainnet" => Ok(BitcoinNetwork::Bitcoin),
            "testnet4" | "testnet" => Ok(BitcoinNetwork::Testnet4),
            "signet" => Ok(BitcoinNetwork::Signet),
            "regtest" => Ok(BitcoinNetwork::Regtest),
            other => Err(format!("unknown bitcoin network: {other}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

/// A 32-byte Bitcoin transaction id, in **internal** (little-endian) byte
/// order — the order `rust-bitcoin` uses in memory, *not* the reversed order
/// block explorers display. [`Txid::to_display_string`] does the reversal.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct Txid(pub [u8; 32]);
crate::impl_bytes32_serde!(Txid);

impl Txid {
    /// Render in the reversed, big-endian order that explorers and wallets show.
    pub fn to_display_string(&self) -> String {
        let mut b = self.0;
        b.reverse();
        hex::encode(b)
    }

    /// Parse from the reversed display order used by explorers and RPC.
    pub fn from_display_string(s: &str) -> Result<Self, String> {
        let mut b =
            <[u8; 32]>::try_from(hex::decode(s.trim()).map_err(|e| format!("txid not hex: {e}"))?)
                .map_err(|_| "txid must be 32 bytes".to_string())?;
        b.reverse();
        Ok(Txid(b))
    }
}

/// A 32-byte block hash, in internal (little-endian) byte order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct BlockHash(pub [u8; 32]);
crate::impl_bytes32_serde!(BlockHash);

impl BlockHash {
    pub fn to_display_string(&self) -> String {
        let mut b = self.0;
        b.reverse();
        hex::encode(b)
    }

    pub fn from_display_string(s: &str) -> Result<Self, String> {
        let mut b = <[u8; 32]>::try_from(
            hex::decode(s.trim()).map_err(|e| format!("block hash not hex: {e}"))?,
        )
        .map_err(|_| "block hash must be 32 bytes".to_string())?;
        b.reverse();
        Ok(BlockHash(b))
    }
}

/// A specific position on a specific chain: both height *and* hash.
///
/// Carrying the hash as well as the height is what makes reorgs detectable at
/// all. Two assertions can name height 900_001 and mean different blocks; only
/// the hash distinguishes them.
#[derive(
    Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default,
)]
pub struct BlockAnchor {
    pub height: u32,
    pub hash: BlockHash,
}

/// A Bitcoin outpoint: which output of which transaction.
#[derive(
    Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default,
)]
pub struct OutPoint {
    pub txid: Txid,
    pub vout: u32,
}

/// The identity of a watched output script, as used inside signed payloads.
///
/// This is `BLAKE3("freenet-bitcoin/script-id/v1" || network_tag ||
/// script_pubkey)`. Using a hash rather than the raw script keeps signed
/// payloads a fixed size regardless of script length, and folding the network
/// tag in means a signature over a signet observation is not a valid signature
/// over the identically-scripted mainnet one.
///
/// It is **not** a privacy measure. The raw `script_pubkey` is a contract
/// parameter and therefore public to anyone who has the contract; `ScriptId`
/// is a binding device, not a blinding one. See `docs/privacy.md`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct ScriptId(pub [u8; 32]);
crate::impl_bytes32_serde!(ScriptId);

impl ScriptId {
    pub fn compute(network: BitcoinNetwork, script_pubkey: &[u8]) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(b"freenet-bitcoin/script-id/v1");
        h.update(&[network.tag()]);
        h.update(script_pubkey);
        ScriptId(*h.finalize().as_bytes())
    }

    pub fn to_bs58(self) -> String {
        bs58::encode(self.0).into_string()
    }
}

/// A bridge's Ed25519 public key, identifying who signed an observation.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct BridgeId(pub [u8; 32]);
crate::impl_bytes32_serde!(BridgeId);

impl BridgeId {
    pub fn to_bs58(self) -> String {
        bs58::encode(self.0).into_string()
    }

    pub fn from_bs58(s: &str) -> Result<Self, String> {
        let v = bs58::decode(s.trim())
            .into_vec()
            .map_err(|e| format!("bridge id not base58: {e}"))?;
        <[u8; 32]>::try_from(v)
            .map(BridgeId)
            .map_err(|_| "bridge id must be 32 bytes".to_string())
    }
}

// ---------------------------------------------------------------------------
// Contract parameters
// ---------------------------------------------------------------------------

/// Parameters that identify one `BitcoinAddressContract` instance.
///
/// Note what is *absent*: there is no ghost key, no requester, no operator,
/// no watcher count. A Bitcoin address contract is a public index shard for a
/// script and nothing else. Adding any of those fields would turn the network
/// into an enumerable record of who cares about which address, which is
/// exactly what this design refuses to build.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct BitcoinAddressParameters {
    pub network: BitcoinNetwork,
    /// Canonical `scriptPubKey` bytes — *not* a human-readable address string.
    /// Addresses are an encoding of a script, several encodings can denote the
    /// same script, and only the script is what actually appears on chain.
    pub script_pubkey: Vec<u8>,
    /// Bridge public keys whose assertions this instance accepts. Assertions
    /// signed by anyone else are rejected outright by `verify`.
    ///
    /// This is where trust policy lives, and it is per-instance: an application
    /// that wants a different bridge, several bridges, or a bridge it runs
    /// itself simply instantiates the contract with different keys. No part of
    /// the format privileges any particular operator.
    pub trusted_bridges: Vec<BridgeId>,
    /// Minimum proof-of-work a block header must claim.
    ///
    /// A standalone header does not say what the difficulty at its height was
    /// supposed to be, so without a floor a chain of trivially-easy headers
    /// would pass every other SPV check. Set this to a value at or below the
    /// network's real recent difficulty. `PowFloor::NONE` is correct for
    /// signet and regtest, where difficulty means nothing.
    ///
    /// A sanity check, not an economic bound: clearing the floor does not
    /// place a header on Bitcoin. See [`PowFloor`] and the [`spv`] module.
    #[serde(default = "default_pow_floor")]
    pub pow_floor: PowFloor,
}

fn default_pow_floor() -> PowFloor {
    PowFloor::NONE
}

impl BitcoinAddressParameters {
    pub fn script_id(&self) -> ScriptId {
        ScriptId::compute(self.network, &self.script_pubkey)
    }

    pub fn trusts(&self, bridge: &BridgeId) -> bool {
        self.trusted_bridges.contains(bridge)
    }
}

/// Parameters identifying one `BitcoinTipContract` instance: a per-network
/// public view of the chain tip and recent blocks.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct BitcoinTipParameters {
    pub network: BitcoinNetwork,
    pub trusted_bridges: Vec<BridgeId>,
}

impl BitcoinTipParameters {
    pub fn trusts(&self, bridge: &BridgeId) -> bool {
        self.trusted_bridges.contains(bridge)
    }
}

// ---------------------------------------------------------------------------
// Claims — what a bridge asserts
// ---------------------------------------------------------------------------

/// The payload a bridge signs when asserting something about one script.
///
/// Every field here is inside the signature. In particular `as_of` is signed,
/// which is what stops an attacker replaying an old "confirmed" assertion to
/// override a newer retraction: the fold takes the highest `as_of`, and a
/// forged higher `as_of` would need the bridge's key.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ClaimBody {
    /// Binds this claim to exactly one contract instance.
    pub script_id: ScriptId,
    pub network: BitcoinNetwork,
    /// The bridge's own best-chain tip at the moment it made this assertion.
    /// This, not wall-clock time, is what orders competing assertions.
    pub as_of: BlockAnchor,
    pub claim: Claim,
}

/// What a bridge is actually asserting.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum Claim {
    /// An output paying this script exists in a transaction the bridge has
    /// seen in the mempool but not in any block.
    MempoolOutput { outpoint: OutPoint, value_sats: u64 },
    /// An output paying this script is included in the block named by `anchor`,
    /// and that block is on the bridge's best chain as of `as_of`.
    ///
    /// Carries [`SpvProof`], which is **not optional**. A confirmed payment
    /// that a reader can only take on the bridge's word is precisely what this
    /// design is trying not to produce: with the proof, the bridge cannot
    /// invent a payment, inflate an amount, redirect one to another script, or
    /// overstate how deeply it is buried. It can still omit things, and it is
    /// still trusted to pick the best chain — bounded by proof-of-work rather
    /// than by its signature. See `spv.rs` for the full statement of what
    /// remains trusted.
    ConfirmedOutput {
        outpoint: OutPoint,
        value_sats: u64,
        anchor: BlockAnchor,
        spv: SpvProof,
    },
    /// The bridge previously asserted this outpoint but, as of `as_of`, no
    /// longer sees it on its best chain — a reorg, or a mempool eviction.
    ///
    /// This does **not** delete the earlier assertion. Both remain in state
    /// forever; the fold simply prefers whichever has the higher `as_of`.
    Retracted { outpoint: OutPoint },
    /// The bridge has scanned this script's activity up to `as_of` and
    /// published everything it found.
    ///
    /// This is what lets a reader distinguish "this address has received
    /// nothing" from "nobody has looked yet" — a distinction a UI badly needs
    /// and which a grow-only set of payments cannot otherwise express.
    ScannedTo,
}

impl Claim {
    /// The outpoint this claim is about, if any. `ScannedTo` covers the whole
    /// script rather than one outpoint.
    pub fn outpoint(&self) -> Option<OutPoint> {
        match self {
            Claim::MempoolOutput { outpoint, .. }
            | Claim::ConfirmedOutput { outpoint, .. }
            | Claim::Retracted { outpoint } => Some(*outpoint),
            Claim::ScannedTo => None,
        }
    }

    pub fn value_sats(&self) -> Option<u64> {
        match self {
            Claim::MempoolOutput { value_sats, .. } | Claim::ConfirmedOutput { value_sats, .. } => {
                Some(*value_sats)
            }
            Claim::Retracted { .. } | Claim::ScannedTo => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Chain-tip entries
// ---------------------------------------------------------------------------

/// A bridge's signed summary of one block, for the per-network tip contract.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct TipEntryBody {
    pub network: BitcoinNetwork,
    pub anchor: BlockAnchor,
    pub prev_hash: BlockHash,
    /// The block header's own timestamp. This is Bitcoin's notion of time, not
    /// the host's; contracts must never read a host clock, and this value is
    /// only ever displayed or compared, never trusted as "now".
    pub block_time: u32,
    pub tx_count: u32,
    /// Median time past, useful for showing a sane "last block" age.
    pub median_time: u32,
}

/// The number of recent block summaries a tip contract retains.
///
/// The tip contract prunes to the highest `TIP_RETAIN` heights. Because the
/// summary publishes the lowest height still held, a peer that has already
/// pruned an entry does not endlessly re-request it — see the retention
/// horizon discussion in `docs/architecture.md`.
pub const TIP_RETAIN: usize = 64;

// ---------------------------------------------------------------------------
// Derived status — the fold
// ---------------------------------------------------------------------------

/// What a reader concludes about a single outpoint after folding all claims.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum OutpointStatus {
    /// Seen in the mempool only.
    Unconfirmed { value_sats: u64 },
    /// Included in a block, as of the winning claim's own chain position.
    Confirmed {
        value_sats: u64,
        anchor: BlockAnchor,
        /// How deeply the **bridge itself** said this block was buried, taken
        /// from inside the signature: `as_of.height - anchor.height + 1` on the
        /// claim that won the fold.
        ///
        /// This is the number a verifier must gate on. See
        /// [`OutpointStatus::confirmations_at`] for why a tip-derived count
        /// alone is forgeable by omission.
        attested_depth: u32,
    },
    /// The most recent assertion says this outpoint is no longer on the chain.
    Retracted,
}

impl OutpointStatus {
    /// Confirmations a verifier may **act on**, against a chain tip it holds.
    ///
    /// The lesser of two bounds, and it needs both:
    ///
    /// * [`confirmations`] against `tip_height` — falls to zero while the
    ///   reader's own tip view is behind the block, so a reader cannot count a
    ///   block it has not caught up to;
    /// * `attested_depth` — how deeply the signing bridge said the block was
    ///   buried *at the moment it signed*, which no submitter can inflate
    ///   without the bridge's key.
    ///
    /// # Why the second bound exists
    ///
    /// The claim set handed to a verifier is chosen by whoever submits it, and
    /// a pure verification function cannot tell a complete set from a curated
    /// one. Across a reorg a submitter can present the bridge's pre-reorg
    /// `ConfirmedOutput` and silently drop the [`Claim::Retracted`] that
    /// superseded it: every remaining check passes, because the confirmation
    /// really is signed, really is about this script, and really does name a
    /// self-consistent block.
    ///
    /// What made that a *forgery* rather than a stale reading was pairing it
    /// with a **fresh** tip. Depth computed as `tip - anchor + 1` grows with
    /// the chain, so an assertion the bridge made at depth 1 and has since
    /// retracted reads as arbitrarily deep simply by supplying a current tip.
    /// Capping at `attested_depth` severs that: the stale confirmation carries
    /// a stale `as_of`, so it can never be worth more confirmations than the
    /// bridge had actually seen when it signed.
    ///
    /// The residual is then exactly Bitcoin's own assumption. To reach depth
    /// `d` with an orphaned block, the bridge must have signed that block as
    /// `d` deep before it was reorged out — that is, a reorg at least `d`
    /// blocks deep. A recipient waiting `d` confirmations is already accepting
    /// that risk.
    ///
    /// This bounds a lying **submitter**, not a lying bridge. A bridge holding
    /// a trusted key can still stamp any `as_of` it likes; that trust is
    /// deliberate and is set out in the crate docs and `docs/trust-boundaries.md`.
    pub fn confirmations_at(&self, tip_height: u32) -> u32 {
        match self {
            OutpointStatus::Confirmed {
                anchor,
                attested_depth,
                ..
            } => confirmations(anchor, tip_height).min(*attested_depth),
            OutpointStatus::Unconfirmed { .. } | OutpointStatus::Retracted => 0,
        }
    }

    /// Value if this outpoint is confirmed to at least `min_confirmations`,
    /// measured by [`OutpointStatus::confirmations_at`].
    pub fn confirmed_value_at(&self, tip_height: u32, min_confirmations: u32) -> Option<u64> {
        match self {
            OutpointStatus::Confirmed { value_sats, .. }
                if self.confirmations_at(tip_height) >= min_confirmations =>
            {
                Some(*value_sats)
            }
            _ => None,
        }
    }
}

/// Depth a claim asserts on its own: how far its `as_of` sits above `anchor`.
///
/// Both fields are inside the bridge's signature, so this is not something a
/// submitter can choose. Zero when `as_of` is below `anchor`, which is a
/// malformed assertion (a bridge claiming a block above its own tip) and is
/// treated as proving nothing rather than as a small positive depth.
pub fn attested_depth(anchor: &BlockAnchor, as_of: &BlockAnchor) -> u32 {
    if as_of.height < anchor.height {
        return 0;
    }
    as_of.height - anchor.height + 1
}

/// Fold every claim about one outpoint into a single current status.
///
/// The rule is: **highest `as_of.height` wins**, ties broken by a total order
/// on the claim bytes so the result never depends on iteration order. This is
/// a pure function of the claim set, which is what makes it safe to compute on
/// every replica and get the same answer.
///
/// `claims` may be supplied in any order and may contain duplicates; both are
/// harmless, which is the property that lets the underlying state be a
/// grow-only set merged by union.
///
/// It is a pure function of the claims it is *given*, which is not the same as
/// a function of the claims that exist. Anything acting on the result must
/// measure depth with [`OutpointStatus::confirmations_at`], never with
/// [`confirmations`] against a separately-supplied tip — that is the whole of
/// what stops a submitter proving a payment by omitting its retraction.
pub fn fold_outpoint_status<'a, I>(claims: I) -> Option<OutpointStatus>
where
    I: IntoIterator<Item = &'a ClaimBody>,
{
    let mut best: Option<&ClaimBody> = None;
    for c in claims {
        if matches!(c.claim, Claim::ScannedTo) {
            continue;
        }
        let better = match best {
            None => true,
            Some(b) => match c.as_of.height.cmp(&b.as_of.height) {
                core::cmp::Ordering::Greater => true,
                core::cmp::Ordering::Less => false,
                // Same height: two assertions from the same chain position.
                // Order by the anchor hash so the choice is deterministic
                // rather than dependent on which peer merged first.
                core::cmp::Ordering::Equal => c.as_of.hash.0 > b.as_of.hash.0,
            },
        };
        if better {
            best = Some(c);
        }
    }

    best.map(|c| match &c.claim {
        Claim::MempoolOutput { value_sats, .. } => OutpointStatus::Unconfirmed {
            value_sats: *value_sats,
        },
        Claim::ConfirmedOutput {
            value_sats, anchor, ..
        } => OutpointStatus::Confirmed {
            value_sats: *value_sats,
            anchor: *anchor,
            attested_depth: attested_depth(anchor, &c.as_of),
        },
        Claim::Retracted { .. } => OutpointStatus::Retracted,
        Claim::ScannedTo => unreachable!("ScannedTo filtered above"),
    })
}

/// Group a pile of claims by outpoint and fold each group.
///
/// The same grouping every consumer needs, in one place so the fold and the
/// depth bound cannot drift apart between them.
pub fn fold_claims_by_outpoint<'a, I>(
    claims: I,
) -> std::collections::BTreeMap<OutPoint, OutpointStatus>
where
    I: IntoIterator<Item = &'a ClaimBody>,
{
    let mut by_outpoint: std::collections::BTreeMap<OutPoint, Vec<&ClaimBody>> =
        std::collections::BTreeMap::new();
    for body in claims {
        if let Some(op) = body.claim.outpoint() {
            by_outpoint.entry(op).or_default().push(body);
        }
    }
    by_outpoint
        .into_iter()
        .filter_map(|(op, bodies)| fold_outpoint_status(bodies).map(|s| (op, s)))
        .collect()
}

/// Confirmations for a confirmed anchor against a chain tip.
///
/// Returns 0 if the tip is behind the anchor, which happens legitimately while
/// a reader's tip view is stale.
///
/// # This is an upper bound, not a gate
///
/// `tip_height` comes from wherever the caller got it, and on a verification
/// path that is *whatever the submitter supplied*. Pairing a current tip with
/// a claim the bridge has since retracted is the omission forgery described on
/// [`OutpointStatus::confirmations_at`], and this function cannot see it — it
/// is handed one anchor and one number and has nothing to compare them
/// against.
///
/// Use it to **display** a confirmation count. To decide whether a payment is
/// deep enough to act on, use [`OutpointStatus::confirmations_at`], which caps
/// this by what the bridge actually attested.
pub fn confirmations(anchor: &BlockAnchor, tip_height: u32) -> u32 {
    if tip_height < anchor.height {
        // Our chain view does not reach this block yet, so we have not
        // confirmed it even once. Adding one here would report an unseen block
        // as confirmed, which is the wrong direction to be wrong in.
        return 0;
    }
    tip_height - anchor.height + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor(h: u32, seed: u8) -> BlockAnchor {
        BlockAnchor {
            height: h,
            hash: BlockHash([seed; 32]),
        }
    }

    fn claim(as_of_h: u32, c: Claim) -> ClaimBody {
        ClaimBody {
            script_id: ScriptId([7u8; 32]),
            network: BitcoinNetwork::Signet,
            as_of: anchor(as_of_h, as_of_h as u8),
            claim: c,
        }
    }

    fn op() -> OutPoint {
        OutPoint {
            txid: Txid([1u8; 32]),
            vout: 0,
        }
    }

    /// One real SPV proof, reused across the fold tests.
    ///
    /// These tests are about the FOLD, not about SPV, but a confirmed claim
    /// cannot be constructed without evidence -- which is the intended shape.
    /// Mining at the easiest target costs microseconds.
    fn any_spv() -> spv::SpvProof {
        spv::testing::payment_proof(&[0x51], 1, 1, [0xaa; 32]).0
    }

    #[test]
    fn script_id_separates_networks() {
        let script = [0x00, 0x14, 0xab, 0xcd];
        assert_ne!(
            ScriptId::compute(BitcoinNetwork::Bitcoin, &script),
            ScriptId::compute(BitcoinNetwork::Signet, &script),
            "the same script on two networks must not share a ScriptId, or a \
             signet observation could be replayed as a mainnet one"
        );
    }

    #[test]
    fn fold_prefers_highest_as_of() {
        let seen = claim(
            100,
            Claim::ConfirmedOutput {
                outpoint: op(),
                value_sats: 50_000,
                anchor: anchor(99, 9),
                spv: any_spv(),
            },
        );
        let gone = claim(105, Claim::Retracted { outpoint: op() });
        assert_eq!(
            fold_outpoint_status([&seen, &gone]),
            Some(OutpointStatus::Retracted)
        );
    }

    #[test]
    fn fold_is_order_independent_and_idempotent() {
        let a = claim(
            100,
            Claim::MempoolOutput {
                outpoint: op(),
                value_sats: 1,
            },
        );
        let b = claim(
            101,
            Claim::ConfirmedOutput {
                outpoint: op(),
                value_sats: 1,
                anchor: anchor(101, 3),
                spv: any_spv(),
            },
        );
        let c = claim(102, Claim::Retracted { outpoint: op() });

        let forward = fold_outpoint_status([&a, &b, &c]);
        let backward = fold_outpoint_status([&c, &b, &a]);
        let dupes = fold_outpoint_status([&b, &a, &c, &a, &c, &b]);
        assert_eq!(forward, backward);
        assert_eq!(forward, dupes);
    }

    #[test]
    fn reconfirmation_after_reorg_wins_again() {
        // The sequence a real reorg produces: confirmed, retracted, then
        // re-confirmed in the replacement block at a higher as_of.
        let confirmed = claim(
            100,
            Claim::ConfirmedOutput {
                outpoint: op(),
                value_sats: 50_000,
                anchor: anchor(100, 1),
                spv: any_spv(),
            },
        );
        let retracted = claim(101, Claim::Retracted { outpoint: op() });
        let reconfirmed = claim(
            102,
            Claim::ConfirmedOutput {
                outpoint: op(),
                value_sats: 50_000,
                anchor: anchor(101, 2),
                spv: any_spv(),
            },
        );
        assert_eq!(
            fold_outpoint_status([&confirmed, &retracted, &reconfirmed]),
            Some(OutpointStatus::Confirmed {
                value_sats: 50_000,
                anchor: anchor(101, 2),
                // as_of 102 over an anchor at 101: the bridge saw it one block
                // deep when it re-confirmed.
                attested_depth: 2,
            })
        );
    }

    #[test]
    fn equal_as_of_height_breaks_ties_deterministically() {
        let low = ClaimBody {
            as_of: anchor(100, 1),
            ..claim(100, Claim::Retracted { outpoint: op() })
        };
        let high = ClaimBody {
            as_of: anchor(100, 9),
            ..claim(
                100,
                Claim::ConfirmedOutput {
                    outpoint: op(),
                    value_sats: 7,
                    anchor: anchor(100, 9),
                    spv: any_spv(),
                },
            )
        };
        assert_eq!(
            fold_outpoint_status([&low, &high]),
            fold_outpoint_status([&high, &low])
        );
    }

    /// The forgery this bound exists to stop.
    ///
    /// A submitter holds the bridge's pre-reorg confirmation AND the retraction
    /// that superseded it. Presenting both reaches the honest verdict. Omitting
    /// the retraction leaves a claim set every other check passes -- the
    /// signature is genuine, the script matches, the block is self-consistent
    /// -- and there is nothing left to fold it against.
    ///
    /// What used to finish the job was pairing that stale claim with a CURRENT
    /// tip, because `tip - anchor + 1` grows with the chain. Capping by the
    /// depth the bridge attested inside its own signature severs that link.
    #[test]
    fn omitting_a_newer_retraction_cannot_buy_confirmations() {
        // The bridge saw the payment the moment it was mined: as_of == anchor,
        // so it attested exactly one confirmation.
        let confirmed = claim(
            100,
            Claim::ConfirmedOutput {
                outpoint: op(),
                value_sats: 50_000,
                anchor: anchor(100, 1),
                spv: any_spv(),
            },
        );
        // Five blocks later a reorg took that block out and the bridge said so.
        let retracted = claim(105, Claim::Retracted { outpoint: op() });

        // Honest submission: the payment is gone, at any tip.
        assert_eq!(
            fold_outpoint_status([&confirmed, &retracted]),
            Some(OutpointStatus::Retracted)
        );

        // Curated submission: the retraction is simply not sent.
        let curated = fold_outpoint_status([&confirmed]).expect("still folds");

        // Tip arithmetic alone -- what a verifier used to do -- reads a
        // long-dead payment as ten blocks deep, purely because the chain moved
        // on. This assertion is the ATTACK, kept so the gap stays visible.
        assert_eq!(confirmations(&anchor(100, 1), 109), 10);

        // The bound a verifier must actually gate on says one, however fresh a
        // tip is supplied. An order wanting two confirmations is not paid.
        assert_eq!(curated.confirmations_at(109), 1);
        assert_eq!(curated.confirmations_at(1_000_000), 1);
        assert_eq!(curated.confirmed_value_at(109, 2), None);
        // ... and one confirmation is still one confirmation, so a zero- or
        // one-deep requirement is unaffected. The bound tells the truth; it
        // does not simply refuse.
        assert_eq!(curated.confirmed_value_at(109, 1), Some(50_000));
    }

    /// The honest path the bound must not break: once the bridge has published
    /// a claim asserting real depth, that depth is available.
    #[test]
    fn a_bridge_attested_deep_claim_still_confirms() {
        // Same payment, re-published by the bridge once six blocks buried.
        let deep = claim(
            105,
            Claim::ConfirmedOutput {
                outpoint: op(),
                value_sats: 50_000,
                anchor: anchor(100, 1),
                spv: any_spv(),
            },
        );
        let st = fold_outpoint_status([&deep]).unwrap();
        assert_eq!(st.confirmations_at(105), 6);
        assert_eq!(st.confirmed_value_at(105, 6), Some(50_000));
        // A reader whose own tip view lags still counts only what it can see.
        assert_eq!(st.confirmations_at(102), 3);
        assert_eq!(st.confirmed_value_at(102, 6), None);
    }

    /// A bridge asserting a block above its own tip proves nothing, rather
    /// than proving a little.
    #[test]
    fn an_anchor_above_its_own_as_of_attests_no_depth() {
        let impossible = claim(
            90,
            Claim::ConfirmedOutput {
                outpoint: op(),
                value_sats: 1,
                anchor: anchor(100, 1),
                spv: any_spv(),
            },
        );
        let st = fold_outpoint_status([&impossible]).unwrap();
        assert_eq!(st.confirmations_at(1_000), 0);
        assert_eq!(st.confirmed_value_at(1_000, 1), None);
    }

    #[test]
    fn grouping_by_outpoint_applies_the_same_bound() {
        let a = claim(
            100,
            Claim::ConfirmedOutput {
                outpoint: op(),
                value_sats: 50_000,
                anchor: anchor(100, 1),
                spv: any_spv(),
            },
        );
        let statuses = fold_claims_by_outpoint([&a]);
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[&op()].confirmations_at(999), 1);
    }

    #[test]
    fn txid_display_is_reversed_and_roundtrips() {
        let mut raw = [0u8; 32];
        raw[0] = 0xde;
        raw[31] = 0xad;
        let t = Txid(raw);
        let s = t.to_display_string();
        assert!(s.starts_with("ad"), "display order must be reversed: {s}");
        assert_eq!(Txid::from_display_string(&s).unwrap(), t);
    }

    #[test]
    fn confirmations_saturate_on_stale_tip() {
        assert_eq!(confirmations(&anchor(100, 1), 99), 0);
        assert_eq!(confirmations(&anchor(100, 1), 100), 1);
        assert_eq!(confirmations(&anchor(100, 1), 105), 6);
    }
}
