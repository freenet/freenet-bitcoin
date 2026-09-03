//! State of a `BitcoinTipContract`: one network's public chain-tip view.
//!
//! # Why this is a separate contract
//!
//! Confirmation depth is `tip_height - anchor_height + 1`, so *something* has
//! to know the tip. Embedding it in every address contract would mean every
//! watched address re-replicating the same global fact and re-publishing it on
//! every block — the same bytes, multiplied by the number of addresses anyone
//! is watching. One tip contract per network costs that once.
//!
//! It also does the product work: a first-run screen can show a live chain tip
//! and recent blocks with **no** watched addresses, no order, and no
//! credential of any kind, because this contract is public and generic.
//!
//! # Retention and why the horizon is published
//!
//! The contract keeps the highest [`crate::TIP_RETAIN`] block summaries and
//! prunes the rest. Pruning plus a set-difference delta is a classic
//! non-terminating loop: the receiver prunes what it was just sent, its
//! summary does not change, and the pair re-sends forever. The summary
//! therefore publishes `lowest_height`, the oldest entry still held, and
//! `delta` never offers anything below the requester's horizon. Because the
//! horizon only ever rises, the exchange provably terminates.

use std::collections::BTreeMap;

use freenet_scaffold_macro::composable;
use serde::{Deserialize, Serialize};

use crate::{
    digest::BucketDigest, BitcoinTipParameters, BlockAnchor, SignedTipEntry, TipEntryBody,
    TIP_RETAIN,
};

/// Recent per-block summaries for one network.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct BlockSummariesV1 {
    /// Keyed by height. `BTreeMap` so iteration — and therefore the serialized
    /// bytes — are identical on every peer holding the same blocks.
    pub blocks: BTreeMap<u32, SignedTipEntry>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct BlockSummariesSummary {
    /// Highest height held.
    pub highest: u32,
    /// Lowest height still held.
    pub lowest: u32,
    /// How many blocks are held. Together with `lowest` this is the retention
    /// horizon: the horizon only bites once the peer is actually AT capacity
    /// and has therefore pruned. A peer that merely started late has a high
    /// `lowest` and is not full, and must still be sent older blocks.
    pub count: u32,
    /// Digest over the entries held.
    ///
    /// This must fingerprint the *entries*, not merely their heights. An
    /// earlier version listed heights alone, which made two peers holding
    /// DIFFERENT competing blocks at the same height look identical to each
    /// other, so neither ever sent the other its block and the two never
    /// converged. A reorg is exactly the case where that matters.
    pub digest: BucketDigest,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct BlockSummariesDelta {
    pub blocks: Vec<SignedTipEntry>,
}

impl BlockSummariesV1 {
    fn prune(&mut self) {
        while self.blocks.len() > TIP_RETAIN {
            // BTreeMap iterates ascending, so the first key is the lowest.
            let Some(lowest) = self.blocks.keys().next().copied() else {
                break;
            };
            self.blocks.remove(&lowest);
        }
    }

    /// The best chain tip we know about.
    pub fn tip(&self) -> Option<TipEntryBody> {
        self.blocks.values().next_back().and_then(|e| e.body().ok())
    }

    pub fn tip_height(&self) -> Option<u32> {
        self.blocks.keys().next_back().copied()
    }

    /// Recent blocks, newest first — what a UI renders.
    pub fn recent(&self, n: usize) -> Vec<TipEntryBody> {
        self.blocks
            .values()
            .rev()
            .filter_map(|e| e.body().ok())
            .take(n)
            .collect()
    }

    /// Whether `anchor` is on the chain this contract describes.
    ///
    /// Returns `None` when the anchor is older than the retained window, which
    /// is not the same as "not on the chain" — a caller must treat an
    /// out-of-window anchor as unknown rather than as a reorg.
    pub fn anchor_is_canonical(&self, anchor: &BlockAnchor) -> Option<bool> {
        let lowest = *self.blocks.keys().next()?;
        if anchor.height < lowest {
            return None;
        }
        let entry = self.blocks.get(&anchor.height)?;
        Some(entry.body().ok()?.anchor.hash == anchor.hash)
    }
}

impl freenet_scaffold::ComposableState for BlockSummariesV1 {
    type ParentState = BitcoinTipStateV1;
    type Summary = BlockSummariesSummary;
    type Delta = BlockSummariesDelta;
    type Parameters = BitcoinTipParameters;

    fn verify(&self, _parent: &Self::ParentState, params: &Self::Parameters) -> Result<(), String> {
        if self.blocks.len() > TIP_RETAIN {
            return Err(format!(
                "tip state holds {} blocks, retention is {TIP_RETAIN}",
                self.blocks.len()
            ));
        }
        for (height, entry) in &self.blocks {
            let body = entry.verify(params)?;
            if body.anchor.height != *height {
                return Err("block summary filed under the wrong height".to_string());
            }
        }
        Ok(())
    }

    fn summarize(&self, _parent: &Self::ParentState, _p: &Self::Parameters) -> Self::Summary {
        BlockSummariesSummary {
            highest: self.blocks.keys().next_back().copied().unwrap_or(0),
            lowest: self.blocks.keys().next().copied().unwrap_or(0),
            count: self.blocks.len() as u32,
            digest: BucketDigest::from_keys_owned(self.blocks.values().map(|e| e.digest())),
        }
    }

    fn delta(
        &self,
        _parent: &Self::ParentState,
        _p: &Self::Parameters,
        old: &Self::Summary,
    ) -> Option<Self::Delta> {
        let mine = BucketDigest::from_keys_owned(self.blocks.values().map(|e| e.digest()));
        let differing = mine.differing_buckets(&old.digest);
        if differing.is_empty() {
            return None;
        }

        // The horizon only applies to a peer that is genuinely AT capacity and
        // has therefore pruned. Applying it to a peer that simply has not
        // filled up yet would suppress every block below its lowest -- which
        // is how a peer holding only block 12 ended up never receiving blocks
        // 10 and 11 at all.
        let peer_has_pruned = old.count as usize >= TIP_RETAIN;

        let blocks: Vec<SignedTipEntry> = self
            .blocks
            .iter()
            .filter(|(h, e)| {
                if peer_has_pruned && **h < old.lowest {
                    return false;
                }
                differing.contains(&BucketDigest::bucket_of(&e.digest()))
            })
            .map(|(_, e)| e.clone())
            .collect();

        if blocks.is_empty() {
            None
        } else {
            Some(BlockSummariesDelta { blocks })
        }
    }

    fn apply_delta(
        &mut self,
        _parent: &Self::ParentState,
        params: &Self::Parameters,
        delta: &Option<Self::Delta>,
    ) -> Result<(), String> {
        let Some(delta) = delta else { return Ok(()) };
        for entry in &delta.blocks {
            let body = entry.verify(params)?;
            // A competing block at the same height: keep the one with the
            // greater hash so every replica makes the same choice. Genuine
            // reorgs resolve as the chain advances and the loser falls out of
            // the retention window.
            match self.blocks.get(&body.anchor.height) {
                Some(existing) => {
                    // Total order on (block hash, entry digest). The entry
                    // digest breaks the case where two bridges each signed the
                    // SAME block: without it the winner would depend on which
                    // peer merged first, and the pair would never agree on
                    // bytes even though they agree on the chain.
                    let keep_new = match existing.body() {
                        Ok(e) => {
                            (body.anchor.hash.0, entry.digest())
                                > (e.anchor.hash.0, existing.digest())
                        }
                        Err(_) => true,
                    };
                    if keep_new {
                        self.blocks.insert(body.anchor.height, entry.clone());
                    }
                }
                None => {
                    self.blocks.insert(body.anchor.height, entry.clone());
                }
            }
        }
        self.prune();
        Ok(())
    }
}

/// Top-level state of a Bitcoin tip contract.
#[composable]
#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
pub struct BitcoinTipStateV1 {
    pub blocks: BlockSummariesV1,
}

impl BitcoinTipStateV1 {
    pub fn from_entries(
        params: &BitcoinTipParameters,
        entries: impl IntoIterator<Item = SignedTipEntry>,
    ) -> Result<Self, String> {
        let mut s = Self::default();
        for e in entries {
            let body = e.verify(params)?;
            s.blocks.blocks.insert(body.anchor.height, e);
        }
        s.blocks.prune();
        Ok(s)
    }

    pub fn tip_height(&self) -> Option<u32> {
        self.blocks.tip_height()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BitcoinNetwork, BlockHash, BridgeId};
    use ed25519_dalek::SigningKey;
    use freenet_scaffold::ComposableState;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn params() -> BitcoinTipParameters {
        BitcoinTipParameters {
            network: BitcoinNetwork::Signet,
            trusted_bridges: vec![BridgeId(key(1).verifying_key().to_bytes())],
        }
    }

    fn hash_at(h: u32, variant: u8) -> BlockHash {
        let mut b = [variant; 32];
        b[..4].copy_from_slice(&h.to_le_bytes());
        BlockHash(b)
    }

    fn entry(h: u32, variant: u8) -> SignedTipEntry {
        SignedTipEntry::sign(
            &key(1),
            &TipEntryBody {
                network: BitcoinNetwork::Signet,
                anchor: BlockAnchor {
                    height: h,
                    hash: hash_at(h, variant),
                },
                prev_hash: hash_at(h.saturating_sub(1), variant),
                block_time: 1_700_000_000 + h,
                tx_count: 100 + h,
                median_time: 1_700_000_000 + h - 300,
            },
        )
        .unwrap()
    }

    fn bytes(s: &BitcoinTipStateV1) -> Vec<u8> {
        crate::to_cbor(s).unwrap()
    }

    fn merged(
        p: &BitcoinTipParameters,
        a: &BitcoinTipStateV1,
        b: &BitcoinTipStateV1,
    ) -> BitcoinTipStateV1 {
        let mut s = a.clone();
        s.merge(&a.clone(), p, b).unwrap();
        s
    }

    #[test]
    fn merge_laws_hold() {
        let p = params();
        let a = BitcoinTipStateV1::from_entries(&p, [entry(10, 1), entry(11, 1)]).unwrap();
        let b = BitcoinTipStateV1::from_entries(&p, [entry(12, 1)]).unwrap();
        let c = BitcoinTipStateV1::from_entries(&p, [entry(13, 1)]).unwrap();

        assert_eq!(bytes(&merged(&p, &a, &a)), bytes(&a), "idempotent");
        assert_eq!(
            bytes(&merged(&p, &a, &b)),
            bytes(&merged(&p, &b, &a)),
            "commutative"
        );
        assert_eq!(
            bytes(&merged(&p, &merged(&p, &a, &b), &c)),
            bytes(&merged(&p, &a, &merged(&p, &b, &c))),
            "associative"
        );
    }

    #[test]
    fn retention_is_bounded() {
        let p = params();
        let s =
            BitcoinTipStateV1::from_entries(&p, (0..(TIP_RETAIN as u32 + 40)).map(|h| entry(h, 1)))
                .unwrap();
        assert_eq!(s.blocks.blocks.len(), TIP_RETAIN);
        assert_eq!(s.tip_height(), Some(TIP_RETAIN as u32 + 39));
    }

    /// The failure this design exists to prevent: a pruning peer and a peer
    /// holding older blocks must not trade the same entries forever.
    #[test]
    fn pruned_entries_are_never_re_offered() {
        let p = params();
        // `ahead` has pruned everything below its horizon.
        let ahead = BitcoinTipStateV1::from_entries(
            &p,
            (100..(100 + TIP_RETAIN as u32)).map(|h| entry(h, 1)),
        )
        .unwrap();
        // `behind` still holds much older blocks.
        let behind = BitcoinTipStateV1::from_entries(&p, (0..20).map(|h| entry(h, 1))).unwrap();

        // Merge repeatedly; the state must reach a fixed point rather than
        // oscillating.
        let mut x = ahead.clone();
        let first = {
            x.merge(&ahead.clone(), &p, &behind).unwrap();
            bytes(&x)
        };
        for _ in 0..5 {
            let snapshot = x.clone();
            x.merge(&snapshot, &p, &behind).unwrap();
            assert_eq!(bytes(&x), first, "merge must reach a fixed point");
        }
        assert_eq!(x.blocks.blocks.len(), TIP_RETAIN);
    }

    #[test]
    fn delta_to_an_up_to_date_peer_is_empty() {
        let p = params();
        let s = BitcoinTipStateV1::from_entries(&p, (0..30).map(|h| entry(h, 1))).unwrap();
        let summary = s.blocks.summarize(&s, &p);
        assert!(s.blocks.delta(&s, &p, &summary).is_none());
    }

    #[test]
    fn competing_blocks_at_one_height_resolve_identically_on_every_peer() {
        let p = params();
        let a = BitcoinTipStateV1::from_entries(&p, [entry(50, 1)]).unwrap();
        let b = BitcoinTipStateV1::from_entries(&p, [entry(50, 2)]).unwrap();
        assert_eq!(bytes(&merged(&p, &a, &b)), bytes(&merged(&p, &b, &a)));
    }

    #[test]
    fn an_untrusted_bridge_cannot_publish_a_tip() {
        let p = params();
        let rogue = SignedTipEntry::sign(
            &key(9),
            &TipEntryBody {
                network: BitcoinNetwork::Signet,
                anchor: BlockAnchor {
                    height: 9_999_999,
                    hash: hash_at(9_999_999, 1),
                },
                prev_hash: hash_at(0, 1),
                block_time: 0,
                tx_count: 0,
                median_time: 0,
            },
        )
        .unwrap();
        assert!(BitcoinTipStateV1::from_entries(&p, [rogue]).is_err());
    }

    #[test]
    fn anchor_canonicality_distinguishes_unknown_from_reorged() {
        let p = params();
        let s = BitcoinTipStateV1::from_entries(&p, (100..120).map(|h| entry(h, 1))).unwrap();

        // On chain.
        assert_eq!(
            s.blocks.anchor_is_canonical(&BlockAnchor {
                height: 110,
                hash: hash_at(110, 1)
            }),
            Some(true)
        );
        // Same height, different block: reorged out.
        assert_eq!(
            s.blocks.anchor_is_canonical(&BlockAnchor {
                height: 110,
                hash: hash_at(110, 7)
            }),
            Some(false)
        );
        // Below the window: unknown, NOT false. Conflating these would report
        // every deeply-buried payment as reorged.
        assert_eq!(
            s.blocks.anchor_is_canonical(&BlockAnchor {
                height: 5,
                hash: hash_at(5, 1)
            }),
            None
        );
    }

    #[test]
    fn summary_stays_small() {
        let p = params();
        let s = BitcoinTipStateV1::from_entries(&p, (0..(TIP_RETAIN as u32)).map(|h| entry(h, 1)))
            .unwrap();
        let sum = crate::to_cbor(&s.blocks.summarize(&s, &p)).unwrap().len();
        let state = bytes(&s).len();
        assert!(sum < 500, "tip summary was {sum} bytes");
        assert!(
            sum * 10 < state,
            "summary {sum} not much smaller than state {state}"
        );
    }
}
