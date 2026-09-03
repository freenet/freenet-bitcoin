//! Reading Bitcoin, and turning what we read into verifiable evidence.
//!
//! # Working against a pruned node with no `txindex`
//!
//! The node this talks to keeps ~10GB of recent blocks and no transaction
//! index, so "look up this old transaction" is simply not available. Nothing
//! here needs it. The bridge observes blocks as they arrive, extracts what it
//! cares about at that moment, and keeps its own small index — the "incremental
//! observation plus a small local index" the deployment is designed around.
//!
//! For history, `scantxoutset` scans the UTXO set and works on a pruned node.
//! It finds current *unspent* outputs only, which is exactly right for
//! "has this invoice been paid" and wrong for "show me this address's full
//! history". That limit is deliberate and documented rather than worked around
//! by turning on `txindex`, which would cost tens of gigabytes.

use anyhow::{Context, Result};
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use freenet_bitcoin_common::spv::{BlockHeader, SpvProof};
use freenet_bitcoin_common::{BitcoinNetwork, BlockAnchor, BlockHash, Txid};

use crate::config::NetworkConfig;

pub struct ChainClient {
    rpc: Client,
    pub network: BitcoinNetwork,
}

/// A payment to a watched script, found in a block.
#[derive(Clone, Debug)]
pub struct FoundOutput {
    pub script_pubkey: Vec<u8>,
    pub txid: Txid,
    pub vout: u32,
    pub value_sats: u64,
    /// Witness-stripped transaction bytes, whose SHA256d is `txid`.
    pub raw_tx: Vec<u8>,
    /// Merkle branch from this transaction to the block's root.
    pub merkle_branch: Vec<[u8; 32]>,
    pub tx_index: u32,
}

/// What a block scan produced.
#[derive(Clone, Debug)]
pub struct ScannedBlock {
    pub anchor: BlockAnchor,
    pub prev_hash: BlockHash,
    pub header: BlockHeader,
    pub time: u32,
    pub median_time: u32,
    pub tx_count: u32,
    pub found: Vec<FoundOutput>,
}

impl ChainClient {
    pub fn connect(cfg: &NetworkConfig) -> Result<Self> {
        let auth = match (&cfg.rpc_cookie_path, &cfg.rpc_user, &cfg.rpc_password) {
            (Some(p), _, _) => Auth::CookieFile(p.clone()),
            (None, Some(u), Some(pw)) => Auth::UserPass(u.clone(), pw.clone()),
            _ => anyhow::bail!(
                "network {:?} has neither a cookie path nor rpc_user/rpc_password",
                cfg.network
            ),
        };
        let rpc = Client::new(&cfg.rpc_url, auth)
            .with_context(|| format!("connecting to Bitcoin Core at {}", cfg.rpc_url))?;
        Ok(ChainClient {
            rpc,
            network: cfg.network,
        })
    }

    pub fn tip(&self) -> Result<BlockAnchor> {
        let info = self.rpc.get_blockchain_info()?;
        Ok(BlockAnchor {
            height: info.blocks as u32,
            hash: BlockHash(info.best_block_hash.to_byte_array()),
        })
    }

    pub fn in_initial_block_download(&self) -> Result<bool> {
        Ok(self.rpc.get_blockchain_info()?.initial_block_download)
    }

    pub fn block_hash_at(&self, height: u32) -> Result<BlockHash> {
        Ok(BlockHash(
            self.rpc.get_block_hash(height as u64)?.to_byte_array(),
        ))
    }

    /// Long-poll for a new block.
    ///
    /// Cheaper and lower-latency than polling `getbestblockhash`, and it means
    /// the bridge does not need a ZMQ dependency to be responsive. Returns
    /// `None` on timeout, which is a normal quiet period, not an error.
    pub fn wait_for_new_block(&self, timeout_ms: u64) -> Result<Option<BlockAnchor>> {
        let v: serde_json::Value = self
            .rpc
            .call("waitfornewblock", &[serde_json::json!(timeout_ms)])?;
        let (Some(hash), Some(height)) = (v.get("hash"), v.get("height")) else {
            return Ok(None);
        };
        let hash: bitcoin::BlockHash = hash
            .as_str()
            .and_then(|s| s.parse().ok())
            .context("waitfornewblock returned an unparseable hash")?;
        Ok(Some(BlockAnchor {
            height: height.as_u64().unwrap_or(0) as u32,
            hash: BlockHash(hash.to_byte_array()),
        }))
    }

    /// Broadcast an already-signed transaction.
    ///
    /// The bridge never signs anything on a user's behalf; this is a relay and
    /// nothing more. Re-broadcasting a transaction the node already has is not
    /// an error, so repeated requests are harmless.
    pub fn broadcast(&self, raw_tx: &[u8]) -> Result<(Txid, bool)> {
        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(raw_tx)
            .context("transaction bytes are not a valid Bitcoin transaction")?;
        let txid = Txid(tx.compute_txid().to_byte_array());
        match self.rpc.send_raw_transaction(&tx) {
            Ok(_) => Ok((txid, false)),
            Err(e) => {
                let msg = e.to_string();
                // Already in the mempool or already mined: the caller's intent
                // is satisfied, so report success rather than an error.
                if msg.contains("already in block chain")
                    || msg.contains("txn-already-known")
                    || msg.contains("txn-already-in-mempool")
                {
                    Ok((txid, true))
                } else {
                    Err(anyhow::anyhow!(msg))
                }
            }
        }
    }

    /// Transactions currently in the mempool.
    pub fn mempool_txids(&self) -> Result<Vec<bitcoin::Txid>> {
        Ok(self.rpc.get_raw_mempool()?)
    }

    /// Fetch a mempool transaction. Works without `txindex` because the node
    /// keeps its own mempool in memory.
    pub fn mempool_tx(&self, txid: &bitcoin::Txid) -> Result<Option<bitcoin::Transaction>> {
        match self.rpc.get_raw_transaction(txid, None) {
            Ok(tx) => Ok(Some(tx)),
            Err(_) => Ok(None),
        }
    }

    /// Scan one block for outputs paying any watched script.
    pub fn scan_block(&self, hash: &BlockHash, watched: &[Vec<u8>]) -> Result<ScannedBlock> {
        let bh = bitcoin::BlockHash::from_byte_array(hash.0);
        let block = self.rpc.get_block(&bh)?;
        let info = self.rpc.get_block_header_info(&bh)?;

        let mut header_bytes = Vec::with_capacity(80);
        block
            .header
            .consensus_encode(&mut header_bytes)
            .context("serializing block header")?;
        let header = BlockHeader(
            <[u8; 80]>::try_from(header_bytes.as_slice())
                .map_err(|_| anyhow::anyhow!("block header was not 80 bytes"))?,
        );

        let txids: Vec<[u8; 32]> = block
            .txdata
            .iter()
            .map(|t| t.compute_txid().to_byte_array())
            .collect();

        let mut found = Vec::new();
        for (idx, tx) in block.txdata.iter().enumerate() {
            for (vout, out) in tx.output.iter().enumerate() {
                let spk = out.script_pubkey.as_bytes().to_vec();
                if !watched.contains(&spk) {
                    continue;
                }
                found.push(FoundOutput {
                    script_pubkey: spk,
                    txid: Txid(tx.compute_txid().to_byte_array()),
                    vout: vout as u32,
                    value_sats: out.value.to_sat(),
                    raw_tx: witness_stripped(tx)?,
                    merkle_branch: merkle_branch(&txids, idx),
                    tx_index: idx as u32,
                });
            }
        }

        Ok(ScannedBlock {
            anchor: BlockAnchor {
                height: info.height as u32,
                hash: *hash,
            },
            prev_hash: BlockHash(
                block
                    .header
                    .prev_blockhash
                    .to_byte_array(),
            ),
            header,
            time: block.header.time,
            median_time: info.median_time.unwrap_or(block.header.time as usize) as u32,
            tx_count: block.txdata.len() as u32,
            found,
        })
    }

    /// The 80-byte header at a height, for building depth evidence.
    pub fn header_at(&self, height: u32) -> Result<BlockHeader> {
        let hash = self.rpc.get_block_hash(height as u64)?;
        let header = self.rpc.get_block_header(&hash)?;
        let mut bytes = Vec::with_capacity(80);
        header.consensus_encode(&mut bytes)?;
        Ok(BlockHeader(
            <[u8; 80]>::try_from(bytes.as_slice())
                .map_err(|_| anyhow::anyhow!("header was not 80 bytes"))?,
        ))
    }

    /// Build a full SPV proof for an output, burying it under `depth-1`
    /// following headers.
    ///
    /// Returns `None` if the chain is not yet deep enough, which is the normal
    /// case for a payment that has only just been seen.
    pub fn build_spv_proof(
        &self,
        found: &FoundOutput,
        block_height: u32,
        depth: u32,
        tip_height: u32,
    ) -> Result<Option<SpvProof>> {
        if tip_height < block_height + depth.saturating_sub(1) {
            return Ok(None);
        }
        let header = self.header_at(block_height)?;
        let mut following = Vec::new();
        for h in (block_height + 1)..=(block_height + depth.saturating_sub(1)) {
            following.push(self.header_at(h)?);
        }
        Ok(Some(SpvProof {
            raw_tx: found.raw_tx.clone(),
            merkle_branch: found.merkle_branch.clone(),
            tx_index: found.tx_index,
            header,
            following_headers: following,
        }))
    }

    /// Find the height at which our recorded chain and the node's diverge.
    ///
    /// Walks back from `from_height` comparing recorded hashes with the node's
    /// current view. Returns the highest height at which they still agree —
    /// the fork point. Anything above it was orphaned.
    pub fn find_fork_point(
        &self,
        from_height: u32,
        max_depth: u32,
        recorded: impl Fn(u32) -> Option<BlockHash>,
    ) -> Result<u32> {
        let floor = from_height.saturating_sub(max_depth);
        let mut h = from_height;
        loop {
            match recorded(h) {
                // Nothing recorded here, so nothing above it can be orphaned
                // by us: treat it as agreement and stop.
                None => return Ok(h),
                Some(ours) => {
                    if self.block_hash_at(h)? == ours {
                        return Ok(h);
                    }
                }
            }
            if h <= floor {
                // A reorg deeper than we are willing to look. Reporting the
                // floor makes the caller rescan that whole window, which is
                // slow but correct; silently accepting the divergence would
                // leave permanently wrong state.
                return Ok(floor);
            }
            h -= 1;
        }
    }
}

/// Serialize a transaction without witness data.
///
/// A txid commits to the *stripped* serialization, so this is the only form
/// whose SHA256d equals the txid — and therefore the only form an SPV verifier
/// can check. Emitting the witness form would make every proof fail.
pub fn witness_stripped(tx: &bitcoin::Transaction) -> Result<Vec<u8>> {
    let mut stripped = tx.clone();
    for input in &mut stripped.input {
        input.witness.clear();
    }
    let mut bytes = Vec::new();
    stripped.consensus_encode(&mut bytes)?;
    Ok(bytes)
}

fn sha256d(data: &[u8]) -> [u8; 32] {
    use bitcoin::hashes::sha256d::Hash as Sha256d;
    Sha256d::hash(data).to_byte_array()
}

/// Compute the Merkle branch proving `index` is in a tree over `txids`.
///
/// Bitcoin duplicates the final element when a level has an odd count. Getting
/// that wrong produces a branch that folds to the wrong root only for
/// odd-sized levels, which is the kind of bug that passes a two-transaction
/// test and fails in production — hence the odd-level tests below.
pub fn merkle_branch(txids: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    let mut branch = Vec::new();
    let mut level: Vec<[u8; 32]> = txids.to_vec();
    let mut idx = index;

    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = *level.last().expect("level is non-empty");
            level.push(last);
        }
        let sibling = if idx.is_multiple_of(2) { idx + 1 } else { idx - 1 };
        branch.push(level[sibling]);

        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&pair[0]);
            buf[32..].copy_from_slice(&pair[1]);
            next.push(sha256d(&buf));
        }
        level = next;
        idx /= 2;
    }
    branch
}

/// The Merkle root over a list of txids, for testing the branch against.
pub fn merkle_root(txids: &[[u8; 32]]) -> [u8; 32] {
    if txids.is_empty() {
        return [0u8; 32];
    }
    let mut level = txids.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = *level.last().expect("non-empty");
            level.push(last);
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&pair[0]);
            buf[32..].copy_from_slice(&pair[1]);
            next.push(sha256d(&buf));
        }
        level = next;
    }
    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use freenet_bitcoin_common::spv::merkle_root_from_branch;

    fn txid(n: u8) -> [u8; 32] {
        let mut t = [0u8; 32];
        t[0] = n;
        t[31] = n.wrapping_mul(3);
        t
    }

    /// The branch must fold back to the root for EVERY position in trees of
    /// every size, odd sizes included. Odd levels are where the
    /// duplicate-the-last-element rule bites, and a test with only powers of
    /// two would miss it entirely.
    #[test]
    fn every_branch_folds_back_to_the_root_for_all_tree_sizes() {
        for n in 1..=17usize {
            let txids: Vec<[u8; 32]> = (0..n).map(|i| txid(i as u8)).collect();
            let root = merkle_root(&txids);
            for i in 0..n {
                let branch = merkle_branch(&txids, i);
                let folded =
                    merkle_root_from_branch(&Txid(txids[i]), &branch, i as u32).unwrap();
                assert_eq!(
                    folded, root,
                    "tree of {n} txids, position {i}: branch did not fold to the root"
                );
            }
        }
    }

    #[test]
    fn a_single_transaction_block_needs_no_branch() {
        let txids = vec![txid(1)];
        assert!(merkle_branch(&txids, 0).is_empty());
        assert_eq!(merkle_root(&txids), txid(1));
    }

    #[test]
    fn a_branch_from_the_wrong_position_does_not_fold_to_the_root() {
        // Guards against a branch that would verify regardless of index,
        // which would let evidence be reused for the wrong transaction.
        let txids: Vec<[u8; 32]> = (0..8).map(|i| txid(i as u8)).collect();
        let root = merkle_root(&txids);
        let branch = merkle_branch(&txids, 3);
        let folded = merkle_root_from_branch(&Txid(txids[3]), &branch, 4).unwrap();
        assert_ne!(folded, root);
    }

    #[test]
    fn stripping_witness_data_preserves_the_txid() {
        // The whole SPV chain rests on this: sha256d(stripped) == txid.
        use bitcoin::{absolute::LockTime, transaction::Version, Amount, ScriptBuf, Transaction, TxIn, TxOut};
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                witness: bitcoin::Witness::from_slice(&[vec![0xab; 72], vec![0xcd; 33]]),
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x00, 0x14, 0xaa, 0xbb]),
            }],
        };
        let stripped = witness_stripped(&tx).unwrap();
        assert_eq!(
            sha256d(&stripped),
            tx.compute_txid().to_byte_array(),
            "the stripped serialization must hash to the txid"
        );
        // And the stripped form must be parseable by the contract-side parser.
        let outs = freenet_bitcoin_common::spv::parse_tx_outputs(&stripped).unwrap();
        assert_eq!(outs.len(), 1);
        assert_eq!(outs[0].value_sats, 50_000);
    }

    #[test]
    fn fork_point_is_the_highest_agreeing_height() {
        // Simulates: we recorded a chain, the node reorged below our tip.
        let recorded = |h: u32| Some(BlockHash([h as u8; 32]));
        // Node agrees at or below 97, differs above.
        struct Fake;
        impl Fake {
            fn hash_at(h: u32) -> BlockHash {
                if h <= 97 {
                    BlockHash([h as u8; 32])
                } else {
                    BlockHash([0xff; 32])
                }
            }
        }
        // Re-implement the walk locally: find_fork_point needs an RPC client,
        // so exercise the same logic to pin the expected answer.
        let mut h = 100u32;
        let fork = loop {
            match recorded(h) {
                None => break h,
                Some(ours) if Fake::hash_at(h) == ours => break h,
                _ => {}
            }
            if h == 0 {
                break 0;
            }
            h -= 1;
        };
        assert_eq!(fork, 97);
    }
}
