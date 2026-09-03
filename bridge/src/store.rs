//! Operational persistence for the bridge.
//!
//! # This database is not authoritative
//!
//! Everything here is the bridge's own bookkeeping: which scripts it is
//! synchronizing, where it had got to on the chain, which claims it has
//! already published. The authoritative record of Bitcoin facts is the chain
//! itself, and the authoritative record of what Freenet knows is the contract
//! state. If this file were deleted the bridge would rescan and re-publish,
//! and — because publishing a claim twice is a no-op on a digest-keyed set —
//! converge to exactly the same contract state.
//!
//! # It is also the most privacy-sensitive thing the bridge holds
//!
//! `watched_scripts` is the one place where "somebody asked about this
//! address" is written down, and where a Ghost Key fingerprint sits next to a
//! Bitcoin script. That mapping is deliberately confined to this file, is
//! never replicated to Freenet, and is why `docs/privacy.md` says a bridge
//! operator is trusted with correlation even though nobody else is.

use std::path::Path;

use anyhow::Context;
use freenet_bitcoin_common::{BitcoinNetwork, BlockAnchor, BlockHash};
use rusqlite::{params, Connection, OptionalExtension};

/// `(script_pubkey, txid, vout)` for an output a reorg has orphaned.
pub type OrphanedOutput = (Vec<u8>, [u8; 32], u32);

/// `(script_pubkey, txid, vout, value_sats, block_height)` for an output that
/// is now buried deeply enough to warrant a headers-carrying claim.
pub type PendingDeepClaim = (Vec<u8>, [u8; 32], u32, u64, u32);

pub struct Store {
    conn: Connection,
}

/// A script the bridge is currently synchronizing.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WatchedScript {
    pub network: BitcoinNetwork,
    pub script_pubkey: Vec<u8>,
    pub scan_from_height: u32,
    /// True for scripts in the operator's `always_watch` list, which are
    /// public demo data rather than anybody's private interest.
    pub is_public_demo: bool,
}

impl Store {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).ok();
        }
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        // WAL so a long block scan does not block the HTTP handler, and
        // NORMAL sync because losing the last few writes costs a rescan, not
        // correctness.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let s = Store { conn };
        s.migrate()?;
        Ok(s)
    }

    pub fn open_in_memory() -> anyhow::Result<Self> {
        let s = Store {
            conn: Connection::open_in_memory()?,
        };
        s.migrate()?;
        Ok(s)
    }

    fn migrate(&self) -> anyhow::Result<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS chain_checkpoint (
                network      TEXT PRIMARY KEY,
                height       INTEGER NOT NULL,
                block_hash   BLOB NOT NULL
            );

            -- The bridge's private record of what it has been asked to watch.
            -- Never replicated. See the module docs.
            CREATE TABLE IF NOT EXISTS watched_scripts (
                network          TEXT NOT NULL,
                script_pubkey    BLOB NOT NULL,
                scan_from_height INTEGER NOT NULL,
                is_public_demo   INTEGER NOT NULL DEFAULT 0,
                first_seen_ms    INTEGER NOT NULL,
                PRIMARY KEY (network, script_pubkey)
            );

            -- Recent block hashes by height, so a reorg can be detected by
            -- comparing what we recorded against what the node now reports.
            CREATE TABLE IF NOT EXISTS seen_blocks (
                network    TEXT NOT NULL,
                height     INTEGER NOT NULL,
                block_hash BLOB NOT NULL,
                PRIMARY KEY (network, height)
            );

            -- Claims already published, so a restart does not re-send
            -- everything. Publishing twice is harmless -- the contract's state
            -- is a digest-keyed set -- but it is wasted bandwidth.
            CREATE TABLE IF NOT EXISTS published_claims (
                network      TEXT NOT NULL,
                script_pubkey BLOB NOT NULL,
                claim_digest BLOB NOT NULL,
                PRIMARY KEY (network, script_pubkey, claim_digest)
            );

            -- Outputs we have observed, so a reorg can be turned into
            -- retractions for exactly the outputs that were in the orphaned
            -- blocks, rather than a blind rescan.
            CREATE TABLE IF NOT EXISTS observed_outputs (
                network       TEXT NOT NULL,
                script_pubkey BLOB NOT NULL,
                txid          BLOB NOT NULL,
                vout          INTEGER NOT NULL,
                value_sats    INTEGER NOT NULL,
                block_height  INTEGER,
                block_hash    BLOB,
                deep_published INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (network, txid, vout)
            );

            -- Single-use challenges for service authorization. Rows are
            -- deleted on use, which is what makes a captured authorization
            -- non-replayable.
            CREATE TABLE IF NOT EXISTS challenges (
                challenge  BLOB PRIMARY KEY,
                issued_ms  INTEGER NOT NULL
            );
            "#,
        )?;
        Ok(())
    }

    // --- chain checkpoint --------------------------------------------------

    pub fn checkpoint(&self, net: BitcoinNetwork) -> anyhow::Result<Option<BlockAnchor>> {
        let row = self
            .conn
            .query_row(
                "SELECT height, block_hash FROM chain_checkpoint WHERE network = ?1",
                params![net.as_str()],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        Ok(row.and_then(|(h, hash)| {
            <[u8; 32]>::try_from(hash).ok().map(|b| BlockAnchor {
                height: h as u32,
                hash: BlockHash(b),
            })
        }))
    }

    /// Move the checkpoint BACKWARD so a newly-watched script gets backfilled.
    ///
    /// Without this, `scan_from_height` on a watch request is silently ignored
    /// and a script added today never sees a payment made yesterday -- the
    /// bridge would only ever scan forward from wherever it happened to be.
    ///
    /// Rewinding is safe because rescanning is idempotent: claims are keyed by
    /// digest, so re-observing a payment produces a claim the contract already
    /// holds. The cost of a rewind is bandwidth, never correctness.
    pub fn rewind_checkpoint_to(&self, net: BitcoinNetwork, height: u32) -> anyhow::Result<()> {
        self.conn.execute(
            "UPDATE chain_checkpoint SET height = ?2 WHERE network = ?1 AND height > ?2",
            params![net.as_str(), height as i64],
        )?;
        Ok(())
    }

    pub fn set_checkpoint(&self, net: BitcoinNetwork, a: &BlockAnchor) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO chain_checkpoint (network, height, block_hash) VALUES (?1, ?2, ?3)
             ON CONFLICT(network) DO UPDATE SET height = ?2, block_hash = ?3",
            params![net.as_str(), a.height as i64, a.hash.0.to_vec()],
        )?;
        Ok(())
    }

    // --- watched scripts ---------------------------------------------------

    pub fn add_watch(&self, w: &WatchedScript, now_ms: i64) -> anyhow::Result<bool> {
        let existed: bool = self
            .conn
            .query_row(
                "SELECT 1 FROM watched_scripts WHERE network = ?1 AND script_pubkey = ?2",
                params![w.network.as_str(), w.script_pubkey],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);

        self.conn.execute(
            "INSERT INTO watched_scripts
                 (network, script_pubkey, scan_from_height, is_public_demo, first_seen_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(network, script_pubkey) DO UPDATE SET
                 -- Keep the EARLIEST scan height ever requested: a later
                 -- requester asking to scan from a high block must not make us
                 -- forget history an earlier one is relying on.
                 scan_from_height = MIN(scan_from_height, ?3),
                 is_public_demo   = MAX(is_public_demo, ?4)",
            params![
                w.network.as_str(),
                w.script_pubkey,
                w.scan_from_height as i64,
                w.is_public_demo as i64,
                now_ms
            ],
        )?;
        Ok(existed)
    }

    pub fn remove_watch(&self, net: BitcoinNetwork, script: &[u8]) -> anyhow::Result<()> {
        // Public demo scripts are the operator's, not a user's, so a user
        // asking to unwatch one must not remove it for everybody else.
        self.conn.execute(
            "DELETE FROM watched_scripts
             WHERE network = ?1 AND script_pubkey = ?2 AND is_public_demo = 0",
            params![net.as_str(), script],
        )?;
        Ok(())
    }

    pub fn watched(&self, net: BitcoinNetwork) -> anyhow::Result<Vec<WatchedScript>> {
        let mut stmt = self.conn.prepare(
            "SELECT script_pubkey, scan_from_height, is_public_demo
             FROM watched_scripts WHERE network = ?1",
        )?;
        let rows = stmt
            .query_map(params![net.as_str()], |r| {
                Ok(WatchedScript {
                    network: net,
                    script_pubkey: r.get(0)?,
                    scan_from_height: r.get::<_, i64>(1)? as u32,
                    is_public_demo: r.get::<_, i64>(2)? != 0,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn is_watched(&self, net: BitcoinNetwork, script: &[u8]) -> anyhow::Result<bool> {
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM watched_scripts WHERE network = ?1 AND script_pubkey = ?2",
                params![net.as_str(), script],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false))
    }

    // --- seen blocks (reorg detection) -------------------------------------

    pub fn record_block(
        &self,
        net: BitcoinNetwork,
        height: u32,
        hash: &BlockHash,
    ) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO seen_blocks (network, height, block_hash) VALUES (?1, ?2, ?3)
             ON CONFLICT(network, height) DO UPDATE SET block_hash = ?3",
            params![net.as_str(), height as i64, hash.0.to_vec()],
        )?;
        Ok(())
    }

    pub fn block_at(&self, net: BitcoinNetwork, height: u32) -> anyhow::Result<Option<BlockHash>> {
        let row = self
            .conn
            .query_row(
                "SELECT block_hash FROM seen_blocks WHERE network = ?1 AND height = ?2",
                params![net.as_str(), height as i64],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        Ok(row.and_then(|b| <[u8; 32]>::try_from(b).ok().map(BlockHash)))
    }

    /// Forget blocks above `height` — everything an orphaned branch contained.
    pub fn forget_blocks_above(&self, net: BitcoinNetwork, height: u32) -> anyhow::Result<()> {
        self.conn.execute(
            "DELETE FROM seen_blocks WHERE network = ?1 AND height > ?2",
            params![net.as_str(), height as i64],
        )?;
        Ok(())
    }

    /// Drop block records older than `keep` blocks below the tip, so the table
    /// does not grow without bound over years of operation.
    pub fn prune_blocks(&self, net: BitcoinNetwork, tip: u32, keep: u32) -> anyhow::Result<()> {
        let floor = tip.saturating_sub(keep);
        self.conn.execute(
            "DELETE FROM seen_blocks WHERE network = ?1 AND height < ?2",
            params![net.as_str(), floor as i64],
        )?;
        Ok(())
    }

    // --- observed outputs --------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    pub fn record_output(
        &self,
        net: BitcoinNetwork,
        script: &[u8],
        txid: &[u8; 32],
        vout: u32,
        value_sats: u64,
        block: Option<(u32, BlockHash)>,
    ) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO observed_outputs
                 (network, script_pubkey, txid, vout, value_sats, block_height, block_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(network, txid, vout) DO UPDATE SET
                 block_height = ?6, block_hash = ?7",
            params![
                net.as_str(),
                script,
                txid.to_vec(),
                vout as i64,
                value_sats as i64,
                block.map(|(h, _)| h as i64),
                block.map(|(_, h)| h.0.to_vec()),
            ],
        )?;
        Ok(())
    }

    /// Outputs recorded as confirmed in a block above `height` — the ones a
    /// reorg to `height` has just orphaned.
    pub fn outputs_above(
        &self,
        net: BitcoinNetwork,
        height: u32,
    ) -> anyhow::Result<Vec<OrphanedOutput>> {
        let mut stmt = self.conn.prepare(
            "SELECT script_pubkey, txid, vout FROM observed_outputs
             WHERE network = ?1 AND block_height IS NOT NULL AND block_height > ?2",
        )?;
        let rows = stmt
            .query_map(params![net.as_str(), height as i64], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, i64>(2)? as u32,
                ))
            })?
            .filter_map(|row| {
                row.ok()
                    .and_then(|(s, t, v)| <[u8; 32]>::try_from(t).ok().map(|t| (s, t, v)))
            })
            .collect();
        Ok(rows)
    }

    /// Mark the outputs in orphaned blocks as unconfirmed again.
    pub fn unconfirm_above(&self, net: BitcoinNetwork, height: u32) -> anyhow::Result<()> {
        self.conn.execute(
            "UPDATE observed_outputs SET block_height = NULL, block_hash = NULL, deep_published = 0
             WHERE network = ?1 AND block_height > ?2",
            params![net.as_str(), height as i64],
        )?;
        Ok(())
    }

    /// Confirmed outputs that have not yet had a deep (headers-carrying)
    /// claim published, and are now buried at least `depth` blocks.
    pub fn outputs_needing_deep_claim(
        &self,
        net: BitcoinNetwork,
        tip_height: u32,
        depth: u32,
    ) -> anyhow::Result<Vec<PendingDeepClaim>> {
        let max_height = tip_height.saturating_sub(depth.saturating_sub(1));
        let mut stmt = self.conn.prepare(
            "SELECT script_pubkey, txid, vout, value_sats, block_height
             FROM observed_outputs
             WHERE network = ?1 AND deep_published = 0
               AND block_height IS NOT NULL AND block_height <= ?2",
        )?;
        let rows = stmt
            .query_map(params![net.as_str(), max_height as i64], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, i64>(2)? as u32,
                    r.get::<_, i64>(3)? as u64,
                    r.get::<_, i64>(4)? as u32,
                ))
            })?
            .filter_map(|row| {
                row.ok().and_then(|(s, t, v, val, h)| {
                    <[u8; 32]>::try_from(t).ok().map(|t| (s, t, v, val, h))
                })
            })
            .collect();
        Ok(rows)
    }

    pub fn mark_deep_published(
        &self,
        net: BitcoinNetwork,
        txid: &[u8; 32],
        vout: u32,
    ) -> anyhow::Result<()> {
        self.conn.execute(
            "UPDATE observed_outputs SET deep_published = 1
             WHERE network = ?1 AND txid = ?2 AND vout = ?3",
            params![net.as_str(), txid.to_vec(), vout as i64],
        )?;
        Ok(())
    }

    // --- published claims --------------------------------------------------

    /// Record a claim as published. Returns false if it already was.
    pub fn mark_published(
        &self,
        net: BitcoinNetwork,
        script: &[u8],
        digest: &[u8; 32],
    ) -> anyhow::Result<bool> {
        let n = self.conn.execute(
            "INSERT OR IGNORE INTO published_claims (network, script_pubkey, claim_digest)
             VALUES (?1, ?2, ?3)",
            params![net.as_str(), script, digest.to_vec()],
        )?;
        Ok(n > 0)
    }

    // --- challenges --------------------------------------------------------

    pub fn issue_challenge(&self, challenge: &[u8], now_ms: i64) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO challenges (challenge, issued_ms) VALUES (?1, ?2)",
            params![challenge, now_ms],
        )?;
        Ok(())
    }

    /// Consume a challenge. Returns true only if it existed and was fresh.
    ///
    /// Deleting on consumption is what makes an intercepted authorization
    /// useless to replay, so this must stay a single atomic delete rather than
    /// a check followed by a delete.
    pub fn consume_challenge(
        &self,
        challenge: &[u8],
        now_ms: i64,
        ttl_ms: i64,
    ) -> anyhow::Result<bool> {
        let n = self.conn.execute(
            "DELETE FROM challenges WHERE challenge = ?1 AND issued_ms > ?2",
            params![challenge, now_ms - ttl_ms],
        )?;
        Ok(n > 0)
    }

    pub fn purge_expired_challenges(&self, now_ms: i64, ttl_ms: i64) -> anyhow::Result<()> {
        self.conn.execute(
            "DELETE FROM challenges WHERE issued_ms <= ?1",
            params![now_ms - ttl_ms],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Store {
        Store::open_in_memory().unwrap()
    }

    fn watch(script: &[u8], from: u32, demo: bool) -> WatchedScript {
        WatchedScript {
            network: BitcoinNetwork::Signet,
            script_pubkey: script.to_vec(),
            scan_from_height: from,
            is_public_demo: demo,
        }
    }

    #[test]
    fn watches_round_trip_and_report_whether_they_were_already_present() {
        let s = store();
        assert!(!s.add_watch(&watch(b"abc", 100, false), 0).unwrap());
        assert!(s.add_watch(&watch(b"abc", 100, false), 0).unwrap());
        assert_eq!(s.watched(BitcoinNetwork::Signet).unwrap().len(), 1);
    }

    #[test]
    fn a_second_requester_cannot_raise_the_scan_floor() {
        // If a later request could push scan_from_height up, it would silently
        // blind the bridge to history an earlier watcher depends on.
        let s = store();
        s.add_watch(&watch(b"abc", 100, false), 0).unwrap();
        s.add_watch(&watch(b"abc", 900_000, false), 0).unwrap();
        assert_eq!(
            s.watched(BitcoinNetwork::Signet).unwrap()[0].scan_from_height,
            100
        );
    }

    #[test]
    fn a_user_cannot_unwatch_the_operators_public_demo_script() {
        let s = store();
        s.add_watch(&watch(b"demo", 0, true), 0).unwrap();
        s.remove_watch(BitcoinNetwork::Signet, b"demo").unwrap();
        assert_eq!(s.watched(BitcoinNetwork::Signet).unwrap().len(), 1);
    }

    #[test]
    fn watches_are_per_network() {
        let s = store();
        s.add_watch(&watch(b"abc", 0, false), 0).unwrap();
        let mut main = watch(b"abc", 0, false);
        main.network = BitcoinNetwork::Bitcoin;
        s.add_watch(&main, 0).unwrap();
        assert_eq!(s.watched(BitcoinNetwork::Signet).unwrap().len(), 1);
        assert_eq!(s.watched(BitcoinNetwork::Bitcoin).unwrap().len(), 1);
    }

    #[test]
    fn a_challenge_can_only_be_used_once() {
        // The property that makes a captured authorization useless.
        let s = store();
        s.issue_challenge(b"nonce", 1000).unwrap();
        assert!(s.consume_challenge(b"nonce", 1000, 60_000).unwrap());
        assert!(
            !s.consume_challenge(b"nonce", 1000, 60_000).unwrap(),
            "a challenge must not be reusable"
        );
    }

    #[test]
    fn an_expired_challenge_is_refused() {
        let s = store();
        s.issue_challenge(b"nonce", 1_000).unwrap();
        assert!(!s.consume_challenge(b"nonce", 1_000_000, 60_000).unwrap());
    }

    #[test]
    fn an_unknown_challenge_is_refused() {
        let s = store();
        assert!(!s.consume_challenge(b"never-issued", 0, 60_000).unwrap());
    }

    #[test]
    fn a_reorg_unconfirms_exactly_the_orphaned_outputs() {
        let s = store();
        let net = BitcoinNetwork::Signet;
        s.record_output(
            net,
            b"spk",
            &[1; 32],
            0,
            1000,
            Some((100, BlockHash([9; 32]))),
        )
        .unwrap();
        s.record_output(
            net,
            b"spk",
            &[2; 32],
            0,
            2000,
            Some((105, BlockHash([8; 32]))),
        )
        .unwrap();

        let orphaned = s.outputs_above(net, 102).unwrap();
        assert_eq!(orphaned.len(), 1);
        assert_eq!(orphaned[0].1, [2u8; 32]);

        s.unconfirm_above(net, 102).unwrap();
        assert!(s.outputs_above(net, 102).unwrap().is_empty());
        // The deeper one is untouched.
        assert_eq!(s.outputs_above(net, 99).unwrap().len(), 1);
    }

    #[test]
    fn deep_claims_are_offered_once_and_only_when_buried_enough() {
        let s = store();
        let net = BitcoinNetwork::Signet;
        s.record_output(
            net,
            b"spk",
            &[1; 32],
            0,
            1000,
            Some((100, BlockHash([9; 32]))),
        )
        .unwrap();

        // At tip 104 the output is only 5 deep; a depth-6 requirement is unmet.
        assert!(s
            .outputs_needing_deep_claim(net, 104, 6)
            .unwrap()
            .is_empty());
        // At tip 105 it is 6 deep.
        assert_eq!(s.outputs_needing_deep_claim(net, 105, 6).unwrap().len(), 1);

        s.mark_deep_published(net, &[1; 32], 0).unwrap();
        assert!(
            s.outputs_needing_deep_claim(net, 200, 6)
                .unwrap()
                .is_empty(),
            "a deep claim must not be published twice"
        );
    }

    #[test]
    fn checkpoints_round_trip() {
        let s = store();
        let a = BlockAnchor {
            height: 12345,
            hash: BlockHash([7; 32]),
        };
        s.set_checkpoint(BitcoinNetwork::Signet, &a).unwrap();
        assert_eq!(s.checkpoint(BitcoinNetwork::Signet).unwrap(), Some(a));
    }

    #[test]
    fn published_claims_are_reported_new_exactly_once() {
        let s = store();
        let net = BitcoinNetwork::Signet;
        assert!(s.mark_published(net, b"spk", &[3; 32]).unwrap());
        assert!(!s.mark_published(net, b"spk", &[3; 32]).unwrap());
    }

    #[test]
    fn block_pruning_keeps_the_recent_window() {
        let s = store();
        let net = BitcoinNetwork::Signet;
        for h in 0..200u32 {
            s.record_block(net, h, &BlockHash([h as u8; 32])).unwrap();
        }
        s.prune_blocks(net, 199, 50).unwrap();
        assert!(s.block_at(net, 100).unwrap().is_none());
        assert!(s.block_at(net, 180).unwrap().is_some());
    }
}
