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

/// `(script_pubkey, txid, vout, value_sats, block_height, published_depth)`
/// for a confirmed output that may be due another headers-carrying claim.
///
/// `published_depth` is the highest depth already asserted for it, so the
/// caller can decide which rung of the depth ladder is next — see
/// `Observer::deep_claims`.
pub type PendingDeepClaim = (Vec<u8>, [u8; 32], u32, u64, u32, u32);

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
                -- Highest confirmation depth already asserted for this
                -- output, or 0 for none. NOT a boolean: an application's
                -- required depth is bounded by what the bridge has actually
                -- signed (see `OutpointStatus::confirmations_at`), so the
                -- bridge re-asserts as the payment is buried and this records
                -- how far it has got. Rows written by an older build hold 1,
                -- which reads as "rung 1 done" and simply costs one extra
                -- round of re-assertion after an upgrade.
                deep_published INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (network, txid, vout)
            );

            -- Which contract code hash the published_claims rows refer to.
            --
            -- This exists because a contract's key is
            -- BLAKE3(BLAKE3(wasm) || params): when the WASM changes, every
            -- instance moves to a NEW contract, and the old published_claims
            -- rows describe a contract nobody reads any more. Without this,
            -- the bridge sees "already published" and skips, leaving the new
            -- contract permanently EMPTY -- which reads to a client exactly
            -- like "this address has no activity".
            --
            -- Observed for real: a cargo fmt re-keyed the contracts and the
            -- successor came up with zero claims and stayed that way.
            CREATE TABLE IF NOT EXISTS publish_generation (
                id             INTEGER PRIMARY KEY CHECK (id = 1),
                code_hash      BLOB NOT NULL
            );

            -- Migration outcomes, recorded per (contract instance, generation).
            --
            -- Written ONLY for a DEFINITIVE outcome -- a recovery, or a walk in
            -- which every predecessor positively answered. An indeterminate
            -- walk (some predecessor never replied) writes nothing and is
            -- retried on the next run, because a marker saying "predecessor had
            -- nothing" is permanent and can never be taken back.
            CREATE TABLE IF NOT EXISTS migration_done (
                instance_id BLOB NOT NULL,
                generation  BLOB NOT NULL,
                outcome     TEXT NOT NULL,
                PRIMARY KEY (instance_id, generation)
            );

            -- The version counter behind each generation pointer record.
            --
            -- A pointer record is `version || code_hash || signature`, and the
            -- pointer contract accepts a record only if it supersedes what it
            -- holds. So the version must be monotonic across restarts, and
            -- that memory has to live somewhere durable.
            --
            -- Losing this table is survivable and must be: the publisher reads
            -- the record already on the network first and, if that record
            -- verifies under this bridge's own key, continues from ITS version.
            -- Without that, a restored-from-nothing database would sign
            -- version 1 forever, every write would be refused as stale, and
            -- the pointer would silently freeze at whatever generation it last
            -- held -- pointing readers at contracts the bridge stopped
            -- publishing to.
            CREATE TABLE IF NOT EXISTS pointer_versions (
                app_id     TEXT PRIMARY KEY,
                version    INTEGER NOT NULL,
                code_hash  BLOB NOT NULL
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

    /// Confirmed outputs whose asserted depth is behind the chain, and by how
    /// far: every output at least two blocks deep whose `deep_published` has
    /// not yet reached `max_depth`.
    ///
    /// Deliberately generous — it returns candidates, and the caller picks the
    /// ladder rung. Rungs are a policy question and belong next to the code
    /// that builds the proof, not in SQL.
    pub fn outputs_needing_deep_claim(
        &self,
        net: BitcoinNetwork,
        tip_height: u32,
        max_depth: u32,
    ) -> anyhow::Result<Vec<PendingDeepClaim>> {
        // Two deep, because depth 1 is already covered by the first-sight
        // claim the bridge published when it scanned the block.
        let max_height = tip_height.saturating_sub(1);
        let mut stmt = self.conn.prepare(
            "SELECT script_pubkey, txid, vout, value_sats, block_height, deep_published
             FROM observed_outputs
             WHERE network = ?1 AND deep_published < ?3
               AND block_height IS NOT NULL AND block_height <= ?2",
        )?;
        let rows = stmt
            .query_map(
                params![net.as_str(), max_height as i64, max_depth as i64],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, i64>(2)? as u32,
                        r.get::<_, i64>(3)? as u64,
                        r.get::<_, i64>(4)? as u32,
                        r.get::<_, i64>(5)? as u32,
                    ))
                },
            )?
            .filter_map(|row| {
                row.ok().and_then(|(s, t, v, val, h, d)| {
                    <[u8; 32]>::try_from(t).ok().map(|t| (s, t, v, val, h, d))
                })
            })
            .collect();
        Ok(rows)
    }

    /// Record the highest depth asserted for an output.
    ///
    /// Monotonic within a generation of the chain: `unconfirm_above` resets it
    /// to 0 when a reorg orphans the block, because nothing is asserted about
    /// a block that is no longer there.
    pub fn mark_deep_published(
        &self,
        net: BitcoinNetwork,
        txid: &[u8; 32],
        vout: u32,
        depth: u32,
    ) -> anyhow::Result<()> {
        self.conn.execute(
            "UPDATE observed_outputs SET deep_published = MAX(deep_published, ?4)
             WHERE network = ?1 AND txid = ?2 AND vout = ?3",
            params![net.as_str(), txid.to_vec(), vout as i64, depth as i64],
        )?;
        Ok(())
    }

    // --- migration bookkeeping ----------------------------------------------

    /// Whether this instance has already been migrated under this code hash.
    pub fn migration_done(
        &self,
        instance_id: &[u8],
        generation: &[u8; 32],
    ) -> anyhow::Result<bool> {
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM migration_done WHERE instance_id = ?1 AND generation = ?2",
                params![instance_id, generation.to_vec()],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false))
    }

    /// Record a DEFINITIVE migration outcome.
    ///
    /// Never call this for an indeterminate walk. The marker is permanent, so
    /// recording "nothing to recover" over a predecessor that merely failed to
    /// answer would make its data unreachable for good.
    pub fn set_migration_done(
        &self,
        instance_id: &[u8],
        generation: &[u8; 32],
        outcome: &str,
    ) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO migration_done (instance_id, generation, outcome)
             VALUES (?1, ?2, ?3)",
            params![instance_id, generation.to_vec(), outcome],
        )?;
        Ok(())
    }

    // --- publish generation ------------------------------------------------

    /// Point the publish record at `code_hash`, discarding it if the contract
    /// WASM has changed since the rows were written.
    ///
    /// Returns true if a reset happened, so the caller can say so: a silent
    /// reset would hide a re-key, and a re-key is exactly the thing an
    /// operator needs to notice.
    pub fn set_publish_generation(&self, code_hash: &[u8; 32]) -> anyhow::Result<bool> {
        let current: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT code_hash FROM publish_generation WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .optional()?;

        let changed = match &current {
            Some(existing) => existing.as_slice() != code_hash.as_slice(),
            None => false,
        };
        if changed {
            // These rows describe contracts that no longer exist. Keeping them
            // would suppress republishing to the successor.
            self.conn.execute("DELETE FROM published_claims", [])?;
        }
        self.conn.execute(
            "INSERT INTO publish_generation (id, code_hash) VALUES (1, ?1)
             ON CONFLICT(id) DO UPDATE SET code_hash = ?1",
            params![code_hash.to_vec()],
        )?;
        Ok(changed)
    }

    // --- generation pointers -----------------------------------------------

    /// The `(version, code_hash)` this bridge last published for `app_id`.
    pub fn pointer_record(&self, app_id: &str) -> anyhow::Result<Option<(u32, [u8; 32])>> {
        let row: Option<(i64, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT version, code_hash FROM pointer_versions WHERE app_id = ?1",
                params![app_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(row.and_then(|(v, h)| {
            let h: [u8; 32] = h.try_into().ok()?;
            u32::try_from(v).ok().map(|v| (v, h))
        }))
    }

    /// Remember what was published, so the next run can supersede it.
    pub fn set_pointer_record(
        &self,
        app_id: &str,
        version: u32,
        code_hash: &[u8; 32],
    ) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO pointer_versions (app_id, version, code_hash) VALUES (?1, ?2, ?3)
             ON CONFLICT(app_id) DO UPDATE SET version = ?2, code_hash = ?3",
            params![app_id, version as i64, code_hash.to_vec()],
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
    fn deep_claims_are_offered_as_the_chain_buries_them_and_stop_at_the_ceiling() {
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

        // At tip 100 the output is one deep, which the first-sight claim
        // already asserts, so there is nothing to re-publish.
        assert!(s
            .outputs_needing_deep_claim(net, 100, 6)
            .unwrap()
            .is_empty());

        // From two deep it is a candidate, carrying how far it has been
        // asserted so the caller can pick the next ladder rung.
        let due = s.outputs_needing_deep_claim(net, 101, 6).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].5, 0, "nothing asserted beyond first sight yet");

        // Asserting rung 2 retires it until the chain passes rung 4.
        s.mark_deep_published(net, &[1; 32], 0, 2).unwrap();
        assert_eq!(s.outputs_needing_deep_claim(net, 103, 6).unwrap()[0].5, 2);

        // Once the ceiling is asserted the output drops out for good: nothing
        // deeper than `deep_confirmations` is ever published.
        s.mark_deep_published(net, &[1; 32], 0, 6).unwrap();
        assert!(
            s.outputs_needing_deep_claim(net, 10_000, 6)
                .unwrap()
                .is_empty(),
            "the ceiling must terminate the ladder"
        );

        // And the record only ever moves forward, so a late round cannot
        // rewind it and re-publish a rung already asserted.
        s.mark_deep_published(net, &[1; 32], 0, 2).unwrap();
        assert!(s
            .outputs_needing_deep_claim(net, 10_000, 6)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_reorg_resets_the_asserted_depth() {
        // Depth is asserted about a block. When the block is orphaned nothing
        // is asserted any more, so the ladder must start over rather than
        // resume from a rung that described a chain that no longer exists.
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
        s.mark_deep_published(net, &[1; 32], 0, 4).unwrap();
        s.unconfirm_above(net, 99).unwrap();
        s.record_output(
            net,
            b"spk",
            &[1; 32],
            0,
            1000,
            Some((100, BlockHash([7; 32]))),
        )
        .unwrap();
        assert_eq!(s.outputs_needing_deep_claim(net, 110, 6).unwrap()[0].5, 0);
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

#[cfg(test)]
mod generation_tests {
    use super::*;

    /// The bug this guards: published_claims is keyed by script and claim
    /// digest with no notion of WHICH contract, so after a re-key the bridge
    /// believed it had already published and skipped, leaving the successor
    /// contract permanently empty.
    #[test]
    fn a_code_hash_change_clears_the_publish_record() {
        let s = Store::open_in_memory().unwrap();
        let net = BitcoinNetwork::Signet;
        let hash_a = [1u8; 32];
        let hash_b = [2u8; 32];

        assert!(
            !s.set_publish_generation(&hash_a).unwrap(),
            "first run is not a change"
        );
        assert!(
            s.mark_published(net, b"spk", &[9; 32]).unwrap(),
            "claim is new"
        );
        assert!(
            !s.mark_published(net, b"spk", &[9; 32]).unwrap(),
            "and now known"
        );

        // Same WASM: the record must survive, or every restart re-publishes
        // everything.
        assert!(!s.set_publish_generation(&hash_a).unwrap());
        assert!(
            !s.mark_published(net, b"spk", &[9; 32]).unwrap(),
            "still known"
        );

        // Changed WASM: the record must be discarded.
        assert!(
            s.set_publish_generation(&hash_b).unwrap(),
            "must report the change"
        );
        assert!(
            s.mark_published(net, b"spk", &[9; 32]).unwrap(),
            "after a re-key the claim must look new again, or the successor \
             contract is never populated"
        );
    }

    #[test]
    fn a_restart_with_no_wasm_change_does_not_republish() {
        let s = Store::open_in_memory().unwrap();
        let h = [7u8; 32];
        s.set_publish_generation(&h).unwrap();
        s.mark_published(BitcoinNetwork::Signet, b"spk", &[1; 32])
            .unwrap();
        for _ in 0..3 {
            assert!(!s.set_publish_generation(&h).unwrap());
        }
        assert!(!s
            .mark_published(BitcoinNetwork::Signet, b"spk", &[1; 32])
            .unwrap());
    }
}

#[cfg(test)]
mod migration_marker_tests {
    use super::*;

    /// The asymmetry that makes markers dangerous: they are permanent. So an
    /// indeterminate walk must leave no trace, and only a definitive outcome
    /// may be recorded.
    #[test]
    fn a_marker_is_written_only_when_asked_and_is_scoped_to_a_generation() {
        let s = Store::open_in_memory().unwrap();
        let inst = b"instance-1";
        let gen_a = [1u8; 32];
        let gen_b = [2u8; 32];

        assert!(!s.migration_done(inst, &gen_a).unwrap());
        s.set_migration_done(inst, &gen_a, "recovered").unwrap();
        assert!(s.migration_done(inst, &gen_a).unwrap());

        // A NEW generation is a different contract and must be migrated again;
        // otherwise the first re-key after a successful migration is skipped.
        assert!(
            !s.migration_done(inst, &gen_b).unwrap(),
            "a marker must not carry across a re-key"
        );
    }

    #[test]
    fn markers_are_per_instance() {
        let s = Store::open_in_memory().unwrap();
        let gen = [7u8; 32];
        s.set_migration_done(b"a", &gen, "seed_local").unwrap();
        assert!(!s.migration_done(b"b", &gen).unwrap());
    }
}
