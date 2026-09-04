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

use std::collections::HashMap;

use anyhow::Result;
use freenet_bitcoin_common::{
    BitcoinAddressParameters, BitcoinNetwork, BitcoinTipParameters, BlockAnchor, BridgeId, Claim,
    ClaimBody, ScriptId, SignedClaim, SignedTipEntry, TipEntryBody,
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

    /// Detect and handle a reorg, returning the height to resume scanning from.
    ///
    /// A reorg is detected by comparing the hash we recorded at a height with
    /// the hash the node reports there now. Everything above the fork point is
    /// orphaned: those outputs get a `Retracted` claim stamped with the CURRENT
    /// tip, so it supersedes the earlier confirmation in every reader's fold.
    pub fn handle_reorg(
        &self,
        store: &Store,
        signer: &Signer,
        tip: &BlockAnchor,
        claims: &mut ClaimsByScript,
    ) -> Result<u32> {
        let Some(checkpoint) = store.checkpoint(self.cfg.network)? else {
            // Nothing recorded yet, so nothing can have been orphaned.
            return Ok(0);
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
            return Ok(checkpoint.height + 1);
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

        for (script, txid, vout) in store.outputs_above(self.cfg.network, fork)? {
            let body = ClaimBody {
                script_id: ScriptId::compute(self.cfg.network, &script),
                network: self.cfg.network,
                // Stamped with the CURRENT tip so it outranks the confirmation
                // it supersedes. Using the orphaned block's height instead
                // would produce a retraction that loses the fold.
                as_of: *tip,
                claim: Claim::Retracted {
                    outpoint: freenet_bitcoin_common::OutPoint {
                        txid: freenet_bitcoin_common::Txid(txid),
                        vout,
                    },
                },
            };
            let signed = SignedClaim::sign(signer.key(), &body)
                .map_err(|e| anyhow::anyhow!("signing retraction: {e}"))?;
            claims.entry(script).or_default().push(signed);
        }

        store.unconfirm_above(self.cfg.network, fork)?;
        store.forget_blocks_above(self.cfg.network, fork)?;
        Ok(fork + 1)
    }

    /// Turn a scanned block into claims and record what we saw.
    pub fn claims_from_block(
        &self,
        store: &Store,
        signer: &Signer,
        block: &ScannedBlock,
        tip: &BlockAnchor,
        claims: &mut ClaimsByScript,
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
            let body = ClaimBody {
                script_id: ScriptId::compute(self.cfg.network, &found.script_pubkey),
                network: self.cfg.network,
                as_of: *tip,
                claim: Claim::ConfirmedOutput {
                    outpoint: freenet_bitcoin_common::OutPoint {
                        txid: found.txid,
                        vout: found.vout,
                    },
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

    /// Re-publish payments that have now reached the configured depth, this
    /// time carrying the headers that prove that depth.
    ///
    /// Without this second claim a reader could only ever see depth 1 from the
    /// evidence, and would have to take the bridge's word for how deeply the
    /// payment is buried — exactly the trust we are trying to remove. It fires
    /// once per output; the claim set is a set, so a duplicate would be
    /// harmless anyway.
    pub fn deep_claims(
        &self,
        store: &Store,
        signer: &Signer,
        tip: &BlockAnchor,
        claims: &mut ClaimsByScript,
    ) -> Result<()> {
        let depth = self.cfg.deep_confirmations;
        for (script, txid, vout, value_sats, height) in
            store.outputs_needing_deep_claim(self.cfg.network, tip.height, depth)?
        {
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
            let Some(spv) = self
                .chain
                .build_spv_proof(found, height, depth, tip.height)?
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
            store.mark_deep_published(self.cfg.network, &txid, vout)?;
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
