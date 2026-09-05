//! The loop that follows Bitcoin and publishes what it sees.
//!
//! # Shape
//!
//! ```text
//!   wait for a block  ->  is our recorded chain still the node's chain?
//!                              |                        |
//!                          yes | no (reorg)             |
//!                              v                        v
//!                        scan forward            find fork point,
//!                        emit ConfirmedOutput    emit Retracted for
//!                              |                 orphaned outputs,
//!                              |                 rescan from the fork
//!                              v
//!                    publish claims + tip entry
//! ```
//!
//! # Why a reorg emits a retraction rather than editing anything
//!
//! Contract state is a grow-only set of chain-height-stamped assertions, so
//! there is nothing to edit. A reorg produces a NEW assertion at a higher
//! `as_of`, and readers fold the set with highest-`as_of`-wins. This is what
//! lets Bitcoin's non-monotonic chain live inside Freenet's requirement that
//! state converge under an idempotent merge.

use std::collections::{HashMap, HashSet};

use anyhow::Result;
use freenet_bitcoin_common::{
    BitcoinAddressParameters, BitcoinNetwork, BitcoinTipParameters, BlockAnchor, BridgeId, Claim,
    ClaimBody, OutPoint, ScriptId, SignedClaim, SignedTipEntry, TipEntryBody,
};

use crate::chain::{ChainClient, ScannedBlock};
use crate::config::NetworkConfig;
use crate::signer::Signer;
use crate::store::Store;

/// Everything one network's observer needs.
pub struct Observer {
    pub chain: ChainClient,
    pub cfg: NetworkConfig,
}

/// Claims produced by processing a block, grouped by the script they concern.
pub type ClaimsByScript = HashMap<Vec<u8>, Vec<SignedClaim>>;

/// An outpoint a reorg took off the bridge's best chain, with the script it
/// paid — a retraction CANDIDATE, not yet a claim. See [`Observer::handle_reorg`].
pub type OrphanedOutpoint = (Vec<u8>, OutPoint);

/// What one round of observation produced, ready to publish.
pub struct Observations {
    pub tip: BlockAnchor,
    pub tip_entry: SignedTipEntry,
    pub claims: ClaimsByScript,
}

impl Observer {
    pub fn new(cfg: NetworkConfig) -> Result<Self> {
        Ok(Observer {
            chain: ChainClient::connect(&cfg)?,
            cfg,
        })
    }

    pub fn network(&self) -> BitcoinNetwork {
        self.cfg.network
    }

    pub fn address_params(&self, script: &[u8], bridge: BridgeId) -> BitcoinAddressParameters {
        BitcoinAddressParameters {
            network: self.cfg.network,
            script_pubkey: script.to_vec(),
            trusted_bridges: vec![bridge],
            pow_floor: self.cfg.network.default_pow_floor(),
        }
    }

    pub fn tip_params(&self, bridge: BridgeId) -> BitcoinTipParameters {
        BitcoinTipParameters {
            network: self.cfg.network,
            trusted_bridges: vec![bridge],
        }
    }

    /// Detect and handle a reorg, returning the height to resume scanning from
    /// and the outpoints the reorg orphaned.
    ///
    /// A reorg is detected by comparing the hash we recorded at a height with
    /// the hash the node reports there now. Everything above the fork point is
    /// orphaned.
    ///
    /// # Why this returns candidates instead of signing retractions
    ///
    /// A retraction says "as of `as_of`, this outpoint is not on my best
    /// chain", and at the moment a reorg is detected the bridge does not yet
    /// know that: the usual outcome of a reorg is that the orphaned
    /// transactions are re-mined in the replacement blocks, which this same
    /// round is about to rescan. Signing here would put a `Retracted` and a
    /// fresh `ConfirmedOutput` for one outpoint at one identical `as_of` into
    /// the same round's output — a contradiction the bridge would have signed
    /// itself, and one no fold can resolve back into the truth, only into a
    /// safe answer.
    ///
    /// So the caller rescans first and then calls [`Observer::retraction_claims`]
    /// with what the rescan actually found.
    pub fn handle_reorg(&self, store: &Store) -> Result<(u32, Vec<OrphanedOutpoint>)> {
        let Some(checkpoint) = store.checkpoint(self.cfg.network)? else {
            // Nothing recorded yet, so nothing can have been orphaned.
            return Ok((0, Vec::new()));
        };

        // Cheap path: the block we last recorded is still the node's block at
        // that height, so no reorg has touched anything we know about.
        let still_current = store
            .block_at(self.cfg.network, checkpoint.height)?
            .map(|recorded| {
                self.chain
                    .block_hash_at(checkpoint.height)
                    .map(|current| current == recorded)
                    .unwrap_or(false)
            })
            .unwrap_or(false);
        if still_current {
            return Ok((checkpoint.height + 1, Vec::new()));
        }

        let fork =
            self.chain
                .find_fork_point(checkpoint.height, self.cfg.max_reorg_depth, |h| {
                    store.block_at(self.cfg.network, h).ok().flatten()
                })?;
        tracing::warn!(
            network = ?self.cfg.network,
            from = checkpoint.height,
            fork_at = fork,
            "reorg detected; retracting orphaned observations"
        );

        let orphaned: Vec<OrphanedOutpoint> = store
            .outputs_above(self.cfg.network, fork)?
            .into_iter()
            .map(|(script, txid, vout)| {
                (
                    script,
                    OutPoint {
                        txid: freenet_bitcoin_common::Txid(txid),
                        vout,
                    },
                )
            })
            .collect();

        store.unconfirm_above(self.cfg.network, fork)?;
        store.forget_blocks_above(self.cfg.network, fork)?;
        Ok((fork + 1, orphaned))
    }

    /// Sign a `Retracted` claim for every orphaned outpoint the round's rescan
    /// did NOT put back on the chain.
    ///
    /// Stamped with the CURRENT tip so it outranks the confirmation it
    /// supersedes; using the orphaned block's height instead would produce a
    /// retraction that loses the fold.
    ///
    /// # The suppression is the point
    ///
    /// `reconfirmed` holds the outpoints this round's rescan found in the
    /// replacement blocks, and those get a `ConfirmedOutput` stamped with the
    /// same tip. Retracting them as well would have the bridge assert, in one
    /// signature-set at one chain position, both that the outpoint is on its
    /// best chain and that it is not. Beyond being false, it hands a third
    /// party a pair of genuinely-signed contradictory claims to submit
    /// selectively. The fold resolves such a pair safely
    /// (`fold_outpoint_status` prefers the claim granting less) but "safely"
    /// there means the payment reads as retracted, so an honestly re-mined
    /// payment would stall until the next block.
    ///
    /// # The residual this does NOT close
    ///
    /// The rescan is capped per round, so a reorg deeper than the round's
    /// window can leave the re-mined block unscanned; the retraction is signed
    /// this round and the re-confirmation next round, and if no new block has
    /// arrived in between both carry the same `as_of`. The fold then reads the
    /// payment as retracted until the next block re-confirms it — a stall,
    /// fail-closed, and self-clearing. Closing it entirely would mean deferring
    /// retractions across rounds, which delays the one claim that is safe to be
    /// early. Nothing here can bound what an ATTACKER assembles from claims
    /// signed in different rounds anyway; that is `fold_outpoint_status`'s job.
    pub fn retraction_claims(
        &self,
        signer: &Signer,
        tip: &BlockAnchor,
        orphaned: &[OrphanedOutpoint],
        reconfirmed: &HashSet<OutPoint>,
        claims: &mut ClaimsByScript,
    ) -> Result<()> {
        for (script, outpoint) in orphaned {
            if reconfirmed.contains(outpoint) {
                tracing::info!(
                    network = ?self.cfg.network,
                    txid = %outpoint.txid.to_display_string(),
                    vout = outpoint.vout,
                    "reorged output was re-mined in the replacement chain; not retracting"
                );
                continue;
            }
            let body = ClaimBody {
                script_id: ScriptId::compute(self.cfg.network, script),
                network: self.cfg.network,
                as_of: *tip,
                claim: Claim::Retracted {
                    outpoint: *outpoint,
                },
            };
            let signed = SignedClaim::sign(signer.key(), &body)
                .map_err(|e| anyhow::anyhow!("signing retraction: {e}"))?;
            claims.entry(script.clone()).or_default().push(signed);
        }
        Ok(())
    }

    /// Turn a scanned block into claims and record what we saw.
    ///
    /// Every outpoint confirmed here is added to `confirmed`, which
    /// [`Observer::retraction_claims`] uses to suppress the retraction of an
    /// output a reorg orphaned and this same rescan put back.
    pub fn claims_from_block(
        &self,
        store: &Store,
        signer: &Signer,
        block: &ScannedBlock,
        tip: &BlockAnchor,
        claims: &mut ClaimsByScript,
        confirmed: &mut HashSet<OutPoint>,
    ) -> Result<()> {
        store.record_block(self.cfg.network, block.anchor.height, &block.anchor.hash)?;

        for found in &block.found {
            store.record_output(
                self.cfg.network,
                &found.script_pubkey,
                &found.txid.0,
                found.vout,
                found.value_sats,
                Some((block.anchor.height, block.anchor.hash)),
            )?;

            // A first-sight claim carries a one-block header run. A deeper
            // claim carrying following headers is published later, once the
            // chain has actually buried it -- see `deep_claims`. Publishing
            // both makes the evidence exhibit the depth being asserted; it
            // does not make depth trustless, since nothing anchors the run to
            // Bitcoin and readers derive confirmations from our asserted
            // block height and tip anyway.
            let spv = freenet_bitcoin_common::spv::SpvProof {
                raw_tx: found.raw_tx.clone(),
                merkle_branch: found.merkle_branch.clone(),
                tx_index: found.tx_index,
                header: block.header,
                following_headers: vec![],
            };
            let outpoint = OutPoint {
                txid: found.txid,
                vout: found.vout,
            };
            confirmed.insert(outpoint);
            let body = ClaimBody {
                script_id: ScriptId::compute(self.cfg.network, &found.script_pubkey),
                network: self.cfg.network,
                as_of: *tip,
                claim: Claim::ConfirmedOutput {
                    outpoint,
                    value_sats: found.value_sats,
                    anchor: block.anchor,
                    spv,
                },
            };
            let signed = SignedClaim::sign(signer.key(), &body)
                .map_err(|e| anyhow::anyhow!("signing observation: {e}"))?;
            claims
                .entry(found.script_pubkey.clone())
                .or_default()
                .push(signed);
        }
        Ok(())
    }

    /// The next depth at which a confirmed payment is worth re-asserting.
    ///
    /// A claim proves only the depth its own `as_of` asserts, so an
    /// application requiring `n` confirmations cannot settle until the bridge
    /// has signed the payment at depth `n` or more — see
    /// `OutpointStatus::confirmations_at`. One claim at `max` would strand
    /// every application wanting less than that until `max` arrives, and one
    /// per block would put `max` claims per output into a byte-budgeted
    /// contract.
    ///
    /// So the rungs double — 2, 4, 8, … — and then `max` itself. That is
    /// `log2(max)` claims per output, and an application waits at most twice
    /// the depth it asked for.
    fn ladder_rung(reached: u32, max: u32) -> u32 {
        let capped = reached.min(max);
        if capped >= max {
            return max;
        }
        if capped < 2 {
            // Depth 0 or 1 is already covered by the first-sight claim, and
            // `leading_zeros` on 0 would underflow the shift below.
            return capped;
        }
        // Largest power of two at or below `capped`.
        1u32 << (u32::BITS - 1 - capped.leading_zeros())
    }

    /// Re-publish payments the chain has buried further than the bridge has so
    /// far asserted, carrying the headers that exhibit that depth.
    ///
    /// Two things depend on this. A reader could otherwise only ever see depth
    /// 1 from the evidence and would have to take the bridge's word for how
    /// deeply a payment is buried. And a verifier bounds confirmations by the
    /// depth the bridge signed, precisely so a submitter cannot pair a stale
    /// claim with a fresh tip — which means an application's required depth is
    /// only reachable if the bridge has asserted it. `deep_confirmations` is
    /// therefore a ceiling on what any application using this bridge can
    /// prove, not merely a publishing detail.
    pub fn deep_claims(
        &self,
        store: &Store,
        signer: &Signer,
        tip: &BlockAnchor,
        claims: &mut ClaimsByScript,
    ) -> Result<()> {
        let max_depth = self.cfg.deep_confirmations;
        for (script, txid, vout, value_sats, height, published) in
            store.outputs_needing_deep_claim(self.cfg.network, tip.height, max_depth)?
        {
            let reached = tip.height.saturating_sub(height).saturating_add(1);
            let rung = Self::ladder_rung(reached, max_depth);
            // `published` may be 1 from an older build, whose column was a
            // boolean; treating it as "rung 1 done" costs one extra round of
            // re-assertion after an upgrade and nothing else.
            if rung <= published.max(1) {
                continue;
            }
            let block_hash = match self.chain.block_hash_at(height) {
                Ok(h) => h,
                Err(e) => {
                    tracing::debug!("cannot re-read block {height}: {e}");
                    continue;
                }
            };
            // Re-scan the block for this one output so we have its raw
            // transaction and Merkle branch again. A pruned node may have
            // discarded it, in which case we simply skip: the shallow claim
            // stands and the payment is still provable, just not to this depth.
            let scanned = match self
                .chain
                .scan_block(&block_hash, std::slice::from_ref(&script))
            {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(
                        "block {height} no longer available ({e}); skipping deep claim"
                    );
                    continue;
                }
            };
            let Some(found) = scanned
                .found
                .iter()
                .find(|f| f.txid.0 == txid && f.vout == vout)
            else {
                continue;
            };
            // Headers are capped separately: `SpvProof` accepts at most
            // `MAX_FOLLOWING_HEADERS`, so a rung beyond that carries the
            // longest run it may and states the rest through `as_of`. Building
            // a longer run would produce a claim every verifier rejects.
            let header_depth =
                rung.min(freenet_bitcoin_common::spv::MAX_FOLLOWING_HEADERS as u32 + 1);
            let Some(spv) = self
                .chain
                .build_spv_proof(found, height, header_depth, tip.height)?
            else {
                continue;
            };

            let body = ClaimBody {
                script_id: ScriptId::compute(self.cfg.network, &script),
                network: self.cfg.network,
                as_of: *tip,
                claim: Claim::ConfirmedOutput {
                    outpoint: freenet_bitcoin_common::OutPoint {
                        txid: freenet_bitcoin_common::Txid(txid),
                        vout,
                    },
                    value_sats,
                    anchor: scanned.anchor,
                    spv,
                },
            };
            let signed = SignedClaim::sign(signer.key(), &body)
                .map_err(|e| anyhow::anyhow!("signing deep observation: {e}"))?;
            claims.entry(script.clone()).or_default().push(signed);
            store.mark_deep_published(self.cfg.network, &txid, vout, rung)?;
        }
        Ok(())
    }

    /// A signed watermark saying how far this bridge has scanned a script.
    ///
    /// Without it a reader cannot tell "this address has received nothing"
    /// from "nobody has looked yet" — a distinction a payment UI badly needs,
    /// and one a grow-only set of payments cannot otherwise express.
    pub fn scan_watermark(
        &self,
        signer: &Signer,
        script: &[u8],
        tip: &BlockAnchor,
    ) -> Result<SignedClaim> {
        let body = ClaimBody {
            script_id: ScriptId::compute(self.cfg.network, script),
            network: self.cfg.network,
            as_of: *tip,
            claim: Claim::ScannedTo,
        };
        SignedClaim::sign(signer.key(), &body)
            .map_err(|e| anyhow::anyhow!("signing scan watermark: {e}"))
    }

    /// A signed summary of one block, for the public tip contract.
    pub fn tip_entry(&self, signer: &Signer, block: &ScannedBlock) -> Result<SignedTipEntry> {
        let body = TipEntryBody {
            network: self.cfg.network,
            anchor: block.anchor,
            prev_hash: block.prev_hash,
            // Bitcoin's own clock, from the header. The bridge never asserts
            // the host's wall time as a fact about the chain.
            block_time: block.time,
            tx_count: block.tx_count,
            median_time: block.median_time,
        };
        SignedTipEntry::sign(signer.key(), &body)
            .map_err(|e| anyhow::anyhow!("signing tip entry: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use freenet_bitcoin_common::{BlockHash, OutpointStatus, Txid};

    /// An observer whose chain client is never used.
    ///
    /// `bitcoincore_rpc::Client::new` builds a transport rather than opening a
    /// connection, so this contacts nothing; the tests below only exercise
    /// `retraction_claims`, which touches neither the chain nor the store.
    fn observer() -> Observer {
        Observer::new(NetworkConfig {
            network: BitcoinNetwork::Signet,
            rpc_url: "http://127.0.0.1:1".into(),
            rpc_cookie_path: None,
            rpc_user: Some("u".into()),
            rpc_password: Some("p".into()),
            deep_confirmations: 6,
            max_reorg_depth: 100,
            always_watch: Vec::new(),
            demo_backfill_blocks: 144,
        })
        .expect("the RPC client is lazy, so no node is contacted")
    }

    fn outpoint(seed: u8, vout: u32) -> OutPoint {
        OutPoint {
            txid: Txid([seed; 32]),
            vout,
        }
    }

    fn bodies(claims: &ClaimsByScript, script: &[u8]) -> Vec<ClaimBody> {
        claims
            .get(script)
            .map(|v| v.iter().map(|c| c.body().unwrap()).collect())
            .unwrap_or_default()
    }

    /// The pair the bridge must never sign.
    ///
    /// A reorg orphans an output and the same round's rescan finds it re-mined
    /// in the replacement chain. Both the retraction and the re-confirmation
    /// are stamped with the round's tip, so they would land at an IDENTICAL
    /// `as_of` — a contradiction the bridge signed itself, and one a third
    /// party could then submit selectively.
    #[test]
    fn an_output_re_mined_in_the_same_round_is_not_also_retracted() {
        let obs = observer();
        let dir = tempfile::tempdir().unwrap();
        let signer = Signer::load_or_create(&dir.path().join("key")).unwrap();
        let tip = BlockAnchor {
            height: 105,
            hash: BlockHash([7; 32]),
        };
        let script = b"spk".to_vec();
        let re_mined = outpoint(1, 0);
        let really_gone = outpoint(2, 1);

        // What the rescan produced for the re-mined output, exactly as
        // `claims_from_block` builds it.
        let mut claims = ClaimsByScript::new();
        let confirmation = ClaimBody {
            script_id: ScriptId::compute(BitcoinNetwork::Signet, &script),
            network: BitcoinNetwork::Signet,
            as_of: tip,
            claim: Claim::ConfirmedOutput {
                outpoint: re_mined,
                value_sats: 50_000,
                anchor: BlockAnchor {
                    height: 104,
                    hash: BlockHash([8; 32]),
                },
                spv: freenet_bitcoin_common::spv::testing::payment_proof(&[0x51], 1, 1, [0xaa; 32])
                    .0,
            },
        };
        claims
            .entry(script.clone())
            .or_default()
            .push(SignedClaim::sign(signer.key(), &confirmation).unwrap());
        let mut reconfirmed = HashSet::new();
        reconfirmed.insert(re_mined);

        obs.retraction_claims(
            &signer,
            &tip,
            &[(script.clone(), re_mined), (script.clone(), really_gone)],
            &reconfirmed,
            &mut claims,
        )
        .unwrap();

        let signed = bodies(&claims, &script);
        let retracted: Vec<OutPoint> = signed
            .iter()
            .filter_map(|b| match &b.claim {
                Claim::Retracted { outpoint } => Some(*outpoint),
                _ => None,
            })
            .collect();
        assert_eq!(
            retracted,
            vec![really_gone],
            "only the output the rescan did NOT find may be retracted"
        );

        // No outpoint carries two claims at one `as_of` -- the property the
        // fold should never have to rescue.
        for op in [re_mined, really_gone] {
            let at_tip = signed
                .iter()
                .filter(|b| b.claim.outpoint() == Some(op) && b.as_of == tip)
                .count();
            assert!(at_tip <= 1, "{op:?} has {at_tip} claims at one anchor");
        }

        // And the re-mined payment reads as paid, which is the whole point of
        // suppressing its retraction rather than leaving the fold to resolve a
        // contradiction (it would resolve it to Retracted).
        let for_re_mined: Vec<&ClaimBody> = signed
            .iter()
            .filter(|b| b.claim.outpoint() == Some(re_mined))
            .collect();
        assert!(matches!(
            freenet_bitcoin_common::fold_outpoint_status(for_re_mined),
            Some(OutpointStatus::Confirmed { .. })
        ));
    }

    /// The suppression must not swallow a retraction that is actually due.
    #[test]
    fn an_output_the_rescan_did_not_find_is_still_retracted() {
        let obs = observer();
        let dir = tempfile::tempdir().unwrap();
        let signer = Signer::load_or_create(&dir.path().join("key")).unwrap();
        let tip = BlockAnchor {
            height: 105,
            hash: BlockHash([7; 32]),
        };
        let script = b"spk".to_vec();
        let gone = outpoint(3, 0);
        let mut claims = ClaimsByScript::new();
        obs.retraction_claims(
            &signer,
            &tip,
            &[(script.clone(), gone)],
            // A different outpoint was re-mined; this one was not.
            &HashSet::from([outpoint(4, 0)]),
            &mut claims,
        )
        .unwrap();
        let signed = bodies(&claims, &script);
        assert_eq!(signed.len(), 1);
        assert_eq!(signed[0].as_of, tip);
        assert!(matches!(signed[0].claim, Claim::Retracted { outpoint } if outpoint == gone));
    }

    #[test]
    fn the_ladder_doubles_and_then_lands_exactly_on_the_ceiling() {
        // Rungs for the default ceiling of 6: 2, 4, 6. An application asking
        // for 3 confirmations settles at 4, one asking for 5 settles at 6.
        let rungs: Vec<u32> = (1..=10).map(|d| Observer::ladder_rung(d, 6)).collect();
        assert_eq!(rungs, vec![1, 2, 2, 4, 4, 6, 6, 6, 6, 6]);
    }

    #[test]
    fn every_required_depth_up_to_the_ceiling_is_eventually_reachable() {
        // The property that matters: for any depth an application may ask
        // for, some rung asserts at least that much. Without it the depth
        // bound in `OutpointStatus::confirmations_at` would strand orders
        // that can never be proved.
        for max in [2u32, 6, 12, 25, 100] {
            for required in 1..=max {
                let reached_needed = (1..=max * 2)
                    .find(|d| Observer::ladder_rung(*d, max) >= required)
                    .expect("some depth must assert at least `required`");
                assert!(
                    reached_needed <= required * 2,
                    "ceiling {max}: {required} confirmations waited until depth {reached_needed}"
                );
            }
        }
    }

    #[test]
    fn the_ladder_is_monotonic_so_a_rung_is_never_revisited() {
        for max in [2u32, 6, 25] {
            let mut last = 0;
            for d in 1..=(max + 5) {
                let r = Observer::ladder_rung(d, max);
                assert!(r >= last, "ceiling {max} went backwards at depth {d}");
                last = r;
            }
        }
    }

    #[test]
    fn a_degenerate_ceiling_asks_for_nothing_rather_than_panicking() {
        assert_eq!(Observer::ladder_rung(0, 0), 0);
        assert_eq!(Observer::ladder_rung(5, 0), 0);
        assert_eq!(Observer::ladder_rung(5, 1), 1);
    }
}
