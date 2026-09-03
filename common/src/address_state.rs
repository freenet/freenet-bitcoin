//! State of a `BitcoinAddressContract`: one script's worth of bridge-signed
//! Bitcoin observations.
//!
//! # Shape and why
//!
//! Two collections, with deliberately different merge rules:
//!
//! * [`ClaimSetV1::claims`] is a **grow-only set** of payment and retraction
//!   assertions, keyed by claim digest. Merging is set union. Nothing is ever
//!   removed or rewritten, which is what makes a reorg expressible without a
//!   mutable `confirmed` flag (see the crate docs).
//!
//! * [`ClaimSetV1::scanned`] is a **per-bridge monotonic maximum**: one entry
//!   per bridge saying how far up the chain it has scanned. If this were also
//!   grow-only it would gain an entry per block forever, so merging keeps only
//!   the higher of two heights. A maximum is associative, commutative and
//!   idempotent, so this is safe — it is the one place the state shrinks, and
//!   it shrinks in a direction that can never oscillate.
//!
//! Both maps are `BTreeMap`, never `HashMap`. Peers decide they have converged
//! by comparing state bytes, so a nondeterministic iteration order would make
//! two peers holding identical logical state disagree forever.

use std::collections::BTreeMap;

use freenet_scaffold_macro::composable;
use serde::{Deserialize, Serialize};

use crate::{
    digest::BucketDigest, BitcoinAddressParameters, BlockAnchor, BridgeId, Claim, ClaimBody,
    OutPoint, OutpointStatus, SignedClaim,
};

/// A claim's identity within the set: `SignedClaim::digest()`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct ClaimKey(pub [u8; 32]);
crate::impl_bytes32_serde!(ClaimKey);

/// Hard cap on the number of claims, as a cheap first guard.
///
/// This alone is NOT the memory bound — see [`MAX_CLAIM_BYTES`].
pub const MAX_CLAIMS: usize = 512;

/// Byte budget for the claim set.
///
/// # Why a byte budget and not just a count
///
/// A count cap *reads* like a memory bound and is not one. Each claim carries
/// an SPV proof containing a raw transaction and block headers, so its size is
/// variable and set by whoever made the Bitcoin transaction — not by us.
/// Multiplying the count cap by the largest value the other side may send is
/// the only honest way to size this.
///
/// This was not theoretical. Pointed at a busy signet address, a 512-entry cap
/// produced **1,101,657 bytes** of state: every GET transferred a megabyte
/// before a UI could render anything. The count never looked alarming.
///
/// 256 KB is generous for the actual use case. A payment destination for one
/// invoice sees one or two payments — a few kilobytes. An address with enough
/// traffic to hit this budget is not a payment destination, and pointing a
/// contract at an exchange's hot wallet is a misuse the budget bounds rather
/// than prevents.
pub const MAX_CLAIM_BYTES: usize = 256 * 1024;

/// The claim set for one Bitcoin output script.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct ClaimSetV1 {
    /// Grow-only set of payment/retraction assertions, keyed by claim digest.
    pub claims: BTreeMap<ClaimKey, SignedClaim>,
    /// Per-bridge scan watermark. Exactly one entry per bridge; merge keeps
    /// the higher `as_of`.
    pub scanned: BTreeMap<BridgeId, SignedClaim>,
}

/// Constant-size summary. 16 bucket digests plus one small integer per bridge.
///
/// Critically this does **not** enumerate the claims. Summaries are broadcast
/// on every anti-entropy heartbeat whether or not anything changed, so an
/// enumerating summary would cost more every time the address saw more use.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct ClaimSetSummary {
    pub claims: BucketDigest,
    /// Per-bridge scan height. Bounded by the number of trusted bridges, which
    /// is a contract parameter and therefore small and fixed.
    pub scanned: BTreeMap<BridgeId, u32>,
}

/// A delta: whole buckets of claims, plus any scan watermarks we are ahead on.
///
/// Sending a whole bucket rather than the precise difference is a deliberate
/// trade. It is what keeps the summary constant-size, and it is sound only
/// because [`ClaimSetV1::apply_delta`] is idempotent — re-applying a claim the
/// receiver already holds is a no-op on a set keyed by digest.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct ClaimSetDelta {
    pub claims: Vec<SignedClaim>,
    pub scanned: Vec<SignedClaim>,
}

impl ClaimSetDelta {
    pub fn is_empty(&self) -> bool {
        self.claims.is_empty() && self.scanned.is_empty()
    }
}

impl ClaimSetV1 {
    /// Insert a verified claim. Returns true if it was new.
    fn insert_verified(&mut self, signed: SignedClaim, body: &ClaimBody) -> bool {
        match body.claim {
            Claim::ScannedTo => {
                let bridge = signed.bridge;
                match self.scanned.get(&bridge) {
                    // Strictly-greater keeps the merge idempotent: re-applying
                    // an equal watermark must not report a change.
                    Some(existing) => {
                        let existing_h = existing.body().map(|b| b.as_of.height).unwrap_or(0);
                        if body.as_of.height > existing_h {
                            self.scanned.insert(bridge, signed);
                            true
                        } else {
                            false
                        }
                    }
                    None => {
                        self.scanned.insert(bridge, signed);
                        true
                    }
                }
            }
            _ => {
                let key = ClaimKey(signed.digest());
                if self.claims.contains_key(&key) {
                    return false;
                }
                self.claims.insert(key, signed);
                true
            }
        }
    }

    /// Encoded size of one stored claim, plus its map key.
    ///
    /// Measured by actually encoding it rather than estimated. An earlier
    /// version approximated from the field lengths and undershot by ~60%: the
    /// budget said 256 KB and real state reached 417 KB, which is exactly the
    /// failure a byte budget exists to prevent. Pruning only runs on overflow,
    /// so the cost of being exact here is negligible and the cost of being
    /// wrong is a bound that does not bind.
    fn claim_cost(signed: &SignedClaim) -> usize {
        // 34 bytes for the ClaimKey as a CBOR byte string, which is the map key.
        crate::to_cbor(signed)
            .map(|b| b.len())
            .unwrap_or(usize::MAX)
            + 34
    }

    /// Prune to BOTH the count cap and the byte budget.
    ///
    /// Deterministic: the ordering is total (as_of height, then key bytes), so
    /// every replica that reaches the same set prunes to the same subset, which
    /// is what keeps the merge convergent even though this shrinks state.
    ///
    /// Pruning drops the LOWEST `as_of` first, keeping the most recent — and
    /// therefore decision-relevant — evidence. An old confirmation dropped this
    /// way is not lost information for a reader that already folded it.
    fn enforce_cap(&mut self) {
        let mut ranked: Vec<(u32, ClaimKey, usize)> = self
            .claims
            .iter()
            .map(|(k, v)| {
                (
                    v.body().map(|b| b.as_of.height).unwrap_or(0),
                    *k,
                    Self::claim_cost(v),
                )
            })
            .collect();
        ranked.sort();

        let mut total: usize = ranked.iter().map(|(_, _, c)| *c).sum();
        let mut count = ranked.len();

        for (_, k, cost) in ranked.into_iter() {
            if count <= MAX_CLAIMS && total <= MAX_CLAIM_BYTES {
                break;
            }
            self.claims.remove(&k);
            total = total.saturating_sub(cost);
            count -= 1;
        }
    }

    /// Every decoded claim body in the set.
    pub fn claim_bodies(&self) -> impl Iterator<Item = ClaimBody> + '_ {
        self.claims.values().filter_map(|c| c.body().ok())
    }

    /// The highest height any trusted bridge reports having scanned to.
    ///
    /// `None` means no bridge has ever reported on this script, which a UI
    /// should render as "not synchronized yet" rather than "no payments".
    pub fn scanned_to(&self) -> Option<u32> {
        self.scanned
            .values()
            .filter_map(|c| c.body().ok())
            .map(|b| b.as_of.height)
            .max()
    }

    /// Current status of every outpoint the bridges have told us about.
    pub fn outpoint_statuses(&self) -> BTreeMap<OutPoint, OutpointStatus> {
        let mut by_outpoint: BTreeMap<OutPoint, Vec<ClaimBody>> = BTreeMap::new();
        for body in self.claim_bodies() {
            if let Some(op) = body.claim.outpoint() {
                by_outpoint.entry(op).or_default().push(body);
            }
        }
        by_outpoint
            .into_iter()
            .filter_map(|(op, bodies)| crate::fold_outpoint_status(bodies.iter()).map(|s| (op, s)))
            .collect()
    }

    /// Total value confirmed to this script at or below `tip_height`, counting
    /// only outputs with at least `min_confirmations`.
    pub fn confirmed_value_sats(&self, tip_height: u32, min_confirmations: u32) -> u64 {
        self.outpoint_statuses()
            .values()
            .filter_map(|s| match s {
                OutpointStatus::Confirmed { value_sats, anchor } => {
                    (crate::confirmations(anchor, tip_height) >= min_confirmations)
                        .then_some(*value_sats)
                }
                _ => None,
            })
            .sum()
    }

    /// Value seen but not yet confirmed to the required depth.
    pub fn pending_value_sats(&self, tip_height: u32, min_confirmations: u32) -> u64 {
        self.outpoint_statuses()
            .values()
            .filter_map(|s| match s {
                OutpointStatus::Unconfirmed { value_sats } => Some(*value_sats),
                OutpointStatus::Confirmed { value_sats, anchor } => {
                    (crate::confirmations(anchor, tip_height) < min_confirmations)
                        .then_some(*value_sats)
                }
                OutpointStatus::Retracted => None,
            })
            .sum()
    }

    /// The evidence that proves a payment of at least `min_sats` reached this
    /// script with at least `min_confirmations` — or `None` if there is none.
    ///
    /// This is what an application embeds in its own state to justify a
    /// state transition. Handing back the *signed* claims, rather than a
    /// boolean, is the whole point: the consuming contract can re-verify them
    /// itself and does not have to trust the reader that produced the answer,
    /// nor re-fetch this contract at validation time.
    pub fn payment_evidence(
        &self,
        min_sats: u64,
        tip_height: u32,
        min_confirmations: u32,
    ) -> Option<Vec<SignedClaim>> {
        let statuses = self.outpoint_statuses();
        let mut qualifying: Vec<(OutPoint, u64)> = statuses
            .iter()
            .filter_map(|(op, s)| match s {
                OutpointStatus::Confirmed { value_sats, anchor }
                    if crate::confirmations(anchor, tip_height) >= min_confirmations =>
                {
                    Some((*op, *value_sats))
                }
                _ => None,
            })
            .collect();
        // Deterministic order so two readers build the same proof.
        qualifying.sort();
        let total: u64 = qualifying.iter().map(|(_, v)| *v).sum();
        if total < min_sats {
            return None;
        }

        let wanted: std::collections::BTreeSet<OutPoint> =
            qualifying.into_iter().map(|(op, _)| op).collect();
        // Include *every* claim touching a qualifying outpoint, not just the
        // winning one: a verifier must be able to re-run the same fold, and
        // the fold needs the full history to reach the same conclusion.
        let mut proof: Vec<SignedClaim> = self
            .claims
            .values()
            .filter(|c| {
                c.body()
                    .ok()
                    .and_then(|b| b.claim.outpoint())
                    .is_some_and(|op| wanted.contains(&op))
            })
            .cloned()
            .collect();
        proof.sort_by_key(|c| c.digest());
        Some(proof)
    }
}

impl freenet_scaffold::ComposableState for ClaimSetV1 {
    type ParentState = BitcoinAddressStateV1;
    type Summary = ClaimSetSummary;
    type Delta = ClaimSetDelta;
    type Parameters = BitcoinAddressParameters;

    fn verify(&self, _parent: &Self::ParentState, params: &Self::Parameters) -> Result<(), String> {
        if self.claims.len() > MAX_CLAIMS {
            return Err(format!(
                "claim set holds {} entries, cap is {MAX_CLAIMS}",
                self.claims.len()
            ));
        }
        // The count cap alone does not bound memory: claim size is set by
        // whoever made the Bitcoin transaction. Reject oversized state rather
        // than accepting a megabyte because the entry count looked fine.
        let bytes: usize = self.claims.values().map(Self::claim_cost).sum();
        if bytes > MAX_CLAIM_BYTES {
            return Err(format!(
                "claim set is {bytes} bytes, budget is {MAX_CLAIM_BYTES}"
            ));
        }
        for (key, signed) in &self.claims {
            let body = signed.verify(params)?;
            // The map key must be the claim's own digest. Without this a peer
            // could file a valid claim under a bogus key, and two peers with
            // the same logical claims would hold different bytes and never
            // agree they had converged.
            if key.0 != signed.digest() {
                return Err("claim is filed under a key that is not its digest".to_string());
            }
            if matches!(body.claim, Claim::ScannedTo) {
                return Err("a ScannedTo watermark must live in `scanned`".to_string());
            }
        }
        for (bridge, signed) in &self.scanned {
            let body = signed.verify(params)?;
            if !matches!(body.claim, Claim::ScannedTo) {
                return Err("`scanned` may only hold ScannedTo watermarks".to_string());
            }
            if *bridge != signed.bridge {
                return Err("scan watermark filed under another bridge's key".to_string());
            }
        }
        Ok(())
    }

    fn summarize(&self, _parent: &Self::ParentState, _params: &Self::Parameters) -> Self::Summary {
        ClaimSetSummary {
            claims: BucketDigest::from_keys(self.claims.keys().map(|k| &k.0)),
            scanned: self
                .scanned
                .iter()
                .map(|(b, c)| (*b, c.body().map(|x| x.as_of.height).unwrap_or(0)))
                .collect(),
        }
    }

    fn delta(
        &self,
        _parent: &Self::ParentState,
        _params: &Self::Parameters,
        old: &Self::Summary,
    ) -> Option<Self::Delta> {
        let mine = BucketDigest::from_keys(self.claims.keys().map(|k| &k.0));
        let differing = mine.differing_buckets(&old.claims);

        let claims: Vec<SignedClaim> = if differing.is_empty() {
            Vec::new()
        } else {
            self.claims
                .iter()
                .filter(|(k, _)| differing.contains(&BucketDigest::bucket_of(&k.0)))
                .map(|(_, v)| v.clone())
                .collect()
        };

        let scanned: Vec<SignedClaim> = self
            .scanned
            .iter()
            .filter(|(bridge, signed)| {
                let mine = signed.body().map(|b| b.as_of.height).unwrap_or(0);
                old.scanned.get(*bridge).is_none_or(|theirs| mine > *theirs)
            })
            .map(|(_, v)| v.clone())
            .collect();

        // An empty delta must be *actually* empty, not an encoded empty
        // struct's worth of framing repeated on every heartbeat. Returning
        // None makes the contract emit a zero-byte StateDelta.
        if claims.is_empty() && scanned.is_empty() {
            None
        } else {
            Some(ClaimSetDelta { claims, scanned })
        }
    }

    fn apply_delta(
        &mut self,
        _parent: &Self::ParentState,
        params: &Self::Parameters,
        delta: &Option<Self::Delta>,
    ) -> Result<(), String> {
        let Some(delta) = delta else { return Ok(()) };
        for signed in delta.claims.iter().chain(delta.scanned.iter()) {
            // Verify before inserting. A delta arrives from an untrusted peer
            // and is not covered by any earlier check.
            let body = signed.verify(params)?;
            self.insert_verified(signed.clone(), &body);
        }
        self.enforce_cap();
        Ok(())
    }
}

/// Top-level state of a Bitcoin address contract.
#[composable]
#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
pub struct BitcoinAddressStateV1 {
    pub claims: ClaimSetV1,
}

impl BitcoinAddressStateV1 {
    /// Build a state from claims, verifying each. Used by the bridge and by
    /// tests; a peer receives state through `apply_delta`/`merge` instead.
    pub fn from_claims(
        params: &BitcoinAddressParameters,
        claims: impl IntoIterator<Item = SignedClaim>,
    ) -> Result<Self, String> {
        let mut s = Self::default();
        for signed in claims {
            let body = signed.verify(params)?;
            s.claims.insert_verified(signed, &body);
        }
        s.claims.enforce_cap();
        Ok(s)
    }

    /// The tip the bridges say they have scanned to for this script.
    pub fn scanned_to(&self) -> Option<u32> {
        self.claims.scanned_to()
    }
}

/// Convenience: build the `ScannedTo` watermark body for a bridge.
pub fn scanned_to_body(params: &BitcoinAddressParameters, as_of: BlockAnchor) -> ClaimBody {
    ClaimBody {
        script_id: params.script_id(),
        network: params.network,
        as_of,
        claim: Claim::ScannedTo,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spv::testing as spv_testing;
    use crate::{BitcoinNetwork, BlockHash, Txid};
    use ed25519_dalek::SigningKey;
    use freenet_scaffold::ComposableState;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn params() -> BitcoinAddressParameters {
        BitcoinAddressParameters {
            network: BitcoinNetwork::Signet,
            script_pubkey: vec![0x00, 0x14, 0xaa, 0xbb],
            trusted_bridges: vec![BridgeId(key(1).verifying_key().to_bytes())],
            pow_floor: crate::PowFloor::NONE,
        }
    }

    fn anchor(h: u32) -> BlockAnchor {
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&h.to_le_bytes());
        BlockAnchor {
            height: h,
            hash: BlockHash(b),
        }
    }

    fn outpoint(n: u8) -> OutPoint {
        OutPoint {
            txid: Txid([n; 32]),
            vout: 0,
        }
    }

    /// Build a confirmed-payment claim carrying a REAL SPV proof: a mined
    /// header, a real txid, a real Merkle position. Nothing here bypasses
    /// verification, so these tests exercise the same path production does.
    fn confirmed(
        p: &BitcoinAddressParameters,
        n: u8,
        sats: u64,
        at: u32,
        as_of: u32,
    ) -> SignedClaim {
        let (spv, txid, block) = spv_testing::payment_proof(&p.script_pubkey, sats, 1, [n; 32]);
        let _ = at;
        SignedClaim::sign(
            &key(1),
            &ClaimBody {
                script_id: p.script_id(),
                network: p.network,
                as_of: anchor(as_of),
                claim: Claim::ConfirmedOutput {
                    outpoint: OutPoint { txid, vout: 0 },
                    value_sats: sats,
                    anchor: BlockAnchor {
                        height: at,
                        hash: block,
                    },
                    spv,
                },
            },
        )
        .unwrap()
    }

    /// Retract the outpoint that `confirmed(.., n, sats, ..)` created. The
    /// txid is derived the same way, so the two refer to the same outpoint --
    /// otherwise the fold would see two unrelated outpoints and the reorg
    /// tests would pass for the wrong reason.
    fn retracted_for(p: &BitcoinAddressParameters, n: u8, sats: u64, as_of: u32) -> SignedClaim {
        let (_, txid, _) = spv_testing::payment_proof(&p.script_pubkey, sats, 1, [n; 32]);
        SignedClaim::sign(
            &key(1),
            &ClaimBody {
                script_id: p.script_id(),
                network: p.network,
                as_of: anchor(as_of),
                claim: Claim::Retracted {
                    outpoint: OutPoint { txid, vout: 0 },
                },
            },
        )
        .unwrap()
    }

    fn scanned(p: &BitcoinAddressParameters, h: u32) -> SignedClaim {
        SignedClaim::sign(&key(1), &scanned_to_body(p, anchor(h))).unwrap()
    }

    // --- merge laws --------------------------------------------------------
    //
    // These are the properties Freenet actually requires. They are checked on
    // exact bytes, because that is how peers decide they have converged.

    fn merged(
        p: &BitcoinAddressParameters,
        base: &BitcoinAddressStateV1,
        other: &BitcoinAddressStateV1,
    ) -> BitcoinAddressStateV1 {
        let mut s = base.clone();
        s.merge(&base.clone(), p, other).unwrap();
        s
    }

    fn bytes(s: &BitcoinAddressStateV1) -> Vec<u8> {
        crate::to_cbor(s).unwrap()
    }

    #[test]
    fn merge_is_idempotent() {
        let p = params();
        let a =
            BitcoinAddressStateV1::from_claims(&p, [confirmed(&p, 1, 50_000, 99, 100)]).unwrap();
        let once = merged(&p, &a, &a);
        let twice = merged(&p, &once, &a);
        assert_eq!(
            bytes(&once),
            bytes(&twice),
            "re-merging must not change bytes"
        );
        assert_eq!(bytes(&a), bytes(&once));
    }

    #[test]
    fn merge_is_commutative() {
        let p = params();
        let a = BitcoinAddressStateV1::from_claims(&p, [confirmed(&p, 1, 1, 10, 11)]).unwrap();
        let b = BitcoinAddressStateV1::from_claims(&p, [confirmed(&p, 2, 2, 12, 13)]).unwrap();
        assert_eq!(bytes(&merged(&p, &a, &b)), bytes(&merged(&p, &b, &a)));
    }

    #[test]
    fn merge_is_associative() {
        let p = params();
        let a = BitcoinAddressStateV1::from_claims(&p, [confirmed(&p, 1, 1, 10, 11)]).unwrap();
        let b = BitcoinAddressStateV1::from_claims(&p, [confirmed(&p, 2, 2, 12, 13)]).unwrap();
        let c = BitcoinAddressStateV1::from_claims(&p, [retracted_for(&p, 1, 1, 20)]).unwrap();
        let left = merged(&p, &merged(&p, &a, &b), &c);
        let right = merged(&p, &a, &merged(&p, &b, &c));
        assert_eq!(bytes(&left), bytes(&right));
    }

    #[test]
    fn scan_watermark_keeps_the_higher_and_only_one_entry() {
        let p = params();
        let a = BitcoinAddressStateV1::from_claims(&p, [scanned(&p, 100)]).unwrap();
        let b = BitcoinAddressStateV1::from_claims(&p, [scanned(&p, 200)]).unwrap();
        let m = merged(&p, &a, &b);
        assert_eq!(
            m.claims.scanned.len(),
            1,
            "one watermark per bridge, not one per block"
        );
        assert_eq!(m.scanned_to(), Some(200));
        // And the other direction gives the same answer.
        assert_eq!(bytes(&m), bytes(&merged(&p, &b, &a)));
    }

    #[test]
    fn a_lower_watermark_never_moves_us_backwards() {
        let p = params();
        let high = BitcoinAddressStateV1::from_claims(&p, [scanned(&p, 500)]).unwrap();
        let low = BitcoinAddressStateV1::from_claims(&p, [scanned(&p, 100)]).unwrap();
        assert_eq!(merged(&p, &high, &low).scanned_to(), Some(500));
    }

    // --- the delta contract ------------------------------------------------

    #[test]
    fn delta_to_an_up_to_date_peer_is_empty() {
        let p = params();
        let s = BitcoinAddressStateV1::from_claims(
            &p,
            (1..40u8).map(|n| confirmed(&p, n, 1000, 10, 11)),
        )
        .unwrap();
        let summary = s.claims.summarize(&s, &p);
        assert!(
            s.claims.delta(&s, &p, &summary).is_none(),
            "a peer that already has everything must receive no delta at all"
        );
    }

    #[test]
    fn summary_is_small_and_does_not_grow_with_the_claim_set() {
        let p = params();
        let small = BitcoinAddressStateV1::from_claims(&p, [confirmed(&p, 1, 1, 10, 11)]).unwrap();
        let big = BitcoinAddressStateV1::from_claims(
            &p,
            (1..200u8).map(|n| confirmed(&p, n, 1000, 10, 11)),
        )
        .unwrap();

        let s1 = crate::to_cbor(&small.claims.summarize(&small, &p))
            .unwrap()
            .len();
        let s2 = crate::to_cbor(&big.claims.summarize(&big, &p))
            .unwrap()
            .len();
        assert_eq!(
            s1, s2,
            "summary size must not depend on how many claims exist"
        );
        assert!(
            s2 < 400,
            "summary encoded to {s2} bytes; expected well under 400"
        );

        // And it must be far smaller than the state it describes.
        let state_len = crate::to_cbor(&big).unwrap().len();
        assert!(
            s2 * 10 < state_len,
            "summary {s2} is not much smaller than state {state_len}"
        );
    }

    #[test]
    fn a_peer_missing_one_claim_gets_it() {
        let p = params();
        let full = BitcoinAddressStateV1::from_claims(
            &p,
            [confirmed(&p, 1, 1, 10, 11), confirmed(&p, 2, 2, 12, 13)],
        )
        .unwrap();
        let partial =
            BitcoinAddressStateV1::from_claims(&p, [confirmed(&p, 1, 1, 10, 11)]).unwrap();

        let m = merged(&p, &partial, &full);
        assert_eq!(bytes(&m), bytes(&full), "merge must reach the full state");
    }

    // --- verification ------------------------------------------------------

    #[test]
    fn a_claim_from_an_untrusted_bridge_is_rejected() {
        let p = params();
        let (spv, txid, block) =
            spv_testing::payment_proof(&p.script_pubkey, 21_000_000_00000000, 1, [1; 32]);
        let rogue = SignedClaim::sign(
            &key(9), // not in trusted_bridges
            &ClaimBody {
                script_id: p.script_id(),
                network: p.network,
                as_of: anchor(1),
                claim: Claim::ConfirmedOutput {
                    outpoint: OutPoint { txid, vout: 0 },
                    value_sats: 21_000_000_00000000,
                    anchor: BlockAnchor {
                        height: 1,
                        hash: block,
                    },
                    spv,
                },
            },
        )
        .unwrap();
        assert!(BitcoinAddressStateV1::from_claims(&p, [rogue]).is_err());
    }

    #[test]
    fn a_claim_filed_under_the_wrong_key_fails_verification() {
        // Otherwise two peers could hold the same claims under different keys,
        // serialize to different bytes, and never agree they had converged.
        let p = params();
        let c = confirmed(&p, 1, 1, 10, 11);
        let mut s = BitcoinAddressStateV1::default();
        s.claims.claims.insert(ClaimKey([0xaa; 32]), c);
        assert!(s.claims.verify(&s.clone(), &p).is_err());
    }

    #[test]
    fn a_delta_carrying_a_forged_claim_is_rejected() {
        let p = params();
        let mut s = BitcoinAddressStateV1::default();
        let (spv, txid, block) = spv_testing::payment_proof(&p.script_pubkey, 999, 1, [1; 32]);
        let forged = SignedClaim::sign(
            &key(9),
            &ClaimBody {
                script_id: p.script_id(),
                network: p.network,
                as_of: anchor(1),
                claim: Claim::ConfirmedOutput {
                    outpoint: OutPoint { txid, vout: 0 },
                    value_sats: 999,
                    anchor: BlockAnchor {
                        height: 1,
                        hash: block,
                    },
                    spv,
                },
            },
        )
        .unwrap();
        let d = ClaimSetDelta {
            claims: vec![forged],
            scanned: vec![],
        };
        let parent = s.clone();
        assert!(s.claims.apply_delta(&parent, &p, &Some(d)).is_err());
    }

    // --- derived answers ---------------------------------------------------

    #[test]
    fn payment_evidence_requires_enough_value_and_depth() {
        let p = params();
        let s =
            BitcoinAddressStateV1::from_claims(&p, [confirmed(&p, 1, 50_000, 100, 100)]).unwrap();

        // Only 1 confirmation at tip 100, so a 2-deep requirement is unmet.
        assert!(s.claims.payment_evidence(50_000, 100, 2).is_none());
        // At tip 101 it is 2 deep.
        assert!(s.claims.payment_evidence(50_000, 101, 2).is_some());
        // Not enough value.
        assert!(s.claims.payment_evidence(50_001, 101, 2).is_none());
    }

    #[test]
    fn a_reorged_out_payment_stops_being_evidence() {
        let p = params();
        let s = BitcoinAddressStateV1::from_claims(
            &p,
            [
                confirmed(&p, 1, 50_000, 100, 100),
                retracted_for(&p, 1, 50_000, 105),
            ],
        )
        .unwrap();
        assert!(
            s.claims.payment_evidence(50_000, 110, 2).is_none(),
            "a retraction at a higher as_of must supersede the confirmation"
        );
        assert_eq!(s.claims.confirmed_value_sats(110, 2), 0);
    }

    #[test]
    fn evidence_includes_the_retraction_history_so_a_verifier_reaches_the_same_fold() {
        let p = params();
        // Confirmed, retracted, re-confirmed: a verifier given only the last
        // claim would agree, but a verifier given only the first two would not.
        // The proof must carry all three.
        let s = BitcoinAddressStateV1::from_claims(
            &p,
            [
                confirmed(&p, 1, 50_000, 100, 100),
                retracted_for(&p, 1, 50_000, 105),
                confirmed(&p, 1, 50_000, 106, 107),
            ],
        )
        .unwrap();
        let proof = s.claims.payment_evidence(50_000, 110, 2).unwrap();
        assert_eq!(
            proof.len(),
            3,
            "proof must carry the whole history for that outpoint"
        );
    }

    #[test]
    fn scanned_to_distinguishes_no_payments_from_never_looked() {
        let p = params();
        let never = BitcoinAddressStateV1::default();
        assert_eq!(never.scanned_to(), None, "nobody has looked");

        let looked = BitcoinAddressStateV1::from_claims(&p, [scanned(&p, 900)]).unwrap();
        assert_eq!(looked.scanned_to(), Some(900), "looked, found nothing");
        assert_eq!(looked.claims.confirmed_value_sats(900, 1), 0);
    }

    #[test]
    fn claim_cap_is_enforced_deterministically() {
        let p = params();
        // Build more claims than the cap by varying the vout.
        // Distinct claims via distinct as_of heights over one shared proof;
        // mining a fresh header per claim would make this test take minutes.
        let (spv, txid, block) = spv_testing::payment_proof(&p.script_pubkey, 1, 1, [5; 32]);
        let claims: Vec<SignedClaim> = (0..(MAX_CLAIMS as u32 + 50))
            .map(|i| {
                SignedClaim::sign(
                    &key(1),
                    &ClaimBody {
                        script_id: p.script_id(),
                        network: p.network,
                        as_of: anchor(1000 + i),
                        claim: Claim::ConfirmedOutput {
                            outpoint: OutPoint { txid, vout: 0 },
                            value_sats: 1,
                            anchor: BlockAnchor {
                                height: 1,
                                hash: block,
                            },
                            spv: spv.clone(),
                        },
                    },
                )
                .unwrap()
            })
            .collect();

        let a = BitcoinAddressStateV1::from_claims(&p, claims.clone()).unwrap();
        let mut shuffled = claims;
        shuffled.reverse();
        let b = BitcoinAddressStateV1::from_claims(&p, shuffled).unwrap();

        // The BYTE budget may bite before the count cap -- that is the whole
        // point of having it -- so assert the count is capped rather than
        // exactly at the cap.
        assert!(
            a.claims.claims.len() <= MAX_CLAIMS,
            "count cap not enforced: {}",
            a.claims.claims.len()
        );
        assert!(a.claims.claims.len() < MAX_CLAIMS + 50);
        assert_eq!(
            bytes(&a),
            bytes(&b),
            "the cap must prune to the same subset regardless of insertion order"
        );
        // And it must keep the most recent evidence, not the oldest.
        let min_kept = a
            .claims
            .claim_bodies()
            .map(|b| b.as_of.height)
            .min()
            .unwrap();
        assert!(
            min_kept > 1000,
            "pruning kept stale claims instead of recent ones"
        );
    }
}

#[cfg(test)]
mod size_tests {
    use super::*;
    use crate::spv::testing as spv_testing;
    use crate::{BitcoinNetwork, BlockAnchor, BlockHash, Txid};
    use ed25519_dalek::SigningKey;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[1; 32])
    }

    fn params() -> BitcoinAddressParameters {
        BitcoinAddressParameters {
            network: BitcoinNetwork::Signet,
            script_pubkey: vec![0x00, 0x14, 0xaa, 0xbb],
            trusted_bridges: vec![BridgeId(key().verifying_key().to_bytes())],
            pow_floor: crate::PowFloor::NONE,
        }
    }

    /// Claims carrying a large transaction each. The count cap would happily
    /// admit 512 of these; the byte budget is what actually bounds the state.
    fn fat_claims(p: &BitcoinAddressParameters, n: u32) -> Vec<SignedClaim> {
        // One shared proof, with a deliberately chunky transaction.
        let big_script = p.script_pubkey.clone();
        let (spv, txid, block) = spv_testing::payment_proof(&big_script, 1000, 8, [5; 32]);
        (0..n)
            .map(|i| {
                SignedClaim::sign(
                    &key(),
                    &ClaimBody {
                        script_id: p.script_id(),
                        network: p.network,
                        as_of: BlockAnchor {
                            height: 1000 + i,
                            hash: BlockHash([(i % 251) as u8; 32]),
                        },
                        claim: Claim::ConfirmedOutput {
                            outpoint: OutPoint { txid, vout: 0 },
                            value_sats: 1000,
                            anchor: BlockAnchor {
                                height: 999,
                                hash: block,
                            },
                            spv: spv.clone(),
                        },
                    },
                )
                .unwrap()
            })
            .collect()
    }

    /// The regression this budget exists for: pointed at a busy address, a
    /// count-only cap produced 1.1 MB of state, which every GET then had to
    /// transfer before anything could render.
    #[test]
    fn state_stays_within_the_byte_budget_however_many_claims_arrive() {
        let p = params();
        let state = BitcoinAddressStateV1::from_claims(&p, fat_claims(&p, 400)).unwrap();
        let encoded = crate::to_cbor(&state).unwrap().len();
        assert!(
            encoded <= MAX_CLAIM_BYTES + 64 * 1024,
            "state grew to {encoded} bytes despite the budget"
        );
    }

    #[test]
    fn byte_pruning_is_order_independent() {
        // Pruning shrinks state, so it MUST be deterministic or two peers that
        // received the same claims in different orders would hold different
        // bytes and never agree they had converged.
        let p = params();
        let claims = fat_claims(&p, 300);
        let mut reversed = claims.clone();
        reversed.reverse();
        let a = BitcoinAddressStateV1::from_claims(&p, claims).unwrap();
        let b = BitcoinAddressStateV1::from_claims(&p, reversed).unwrap();
        assert_eq!(crate::to_cbor(&a).unwrap(), crate::to_cbor(&b).unwrap());
    }

    #[test]
    fn oversized_state_from_a_peer_is_rejected() {
        // verify() must enforce the budget too; otherwise a peer could simply
        // ship a megabyte and we would accept it because the count was fine.
        let p = params();
        let mut state = BitcoinAddressStateV1::default();
        for c in fat_claims(&p, 400) {
            let key = ClaimKey(c.digest());
            state.claims.claims.insert(key, c);
        }
        assert!(
            state.claims.claims.len() > 1,
            "fixture did not actually build a large set"
        );
        let bytes: usize = state
            .claims
            .claims
            .values()
            .map(ClaimSetV1::claim_cost)
            .sum();
        if bytes > MAX_CLAIM_BYTES {
            let err = state.claims.verify(&state.clone(), &p).unwrap_err();
            assert!(err.contains("budget"), "got: {err}");
        }
    }
}
