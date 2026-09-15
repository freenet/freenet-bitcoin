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
//! `watched_scripts` and `script_interests` are where "somebody asked about
//! this address" is written down, and `script_interests` is where a Ghost Key
//! sits next to a Bitcoin script: it records who asked for each script, which
//! is what lets one requester's unwatch leave everyone else's interest in
//! place. That mapping is deliberately confined to this file, is never
//! replicated to Freenet, and is why `docs/privacy.md` says a bridge operator
//! is trusted with correlation even though nobody else is.

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

/// The requester recorded for a script someone watched before anyone asked
/// for it through the inbox. No certificate certifies this key, so no request
/// can ever withdraw it.
///
/// Zero bytes long: every requester is identified by a 32-byte Ghost Key, so
/// no request can ever name this one. (An earlier version used the all-zero
/// key, which a certificate can certify.)
pub const OPERATOR_INTEREST: &[u8] = &[];

/// One requester's request about one script.
#[derive(Clone, Copy, Debug)]
pub struct Interest<'a> {
    pub network: BitcoinNetwork,
    pub script: &'a [u8],
    pub ghostkey: &'a [u8; 32],
    pub watching: bool,
    /// When the sender made the request, by the sender's clock.
    pub request_ms: u64,
}

/// What [`Store::set_interest`] did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InterestChange {
    /// Not newer than this requester's last request about this script.
    Stale,
    /// Would take this requester past its limit of watched scripts.
    OverCap,
    /// The requester now wants the script.
    Watching,
    /// The requester no longer wants it; `last` when nobody else does either.
    Withdrawn { last: bool },
    /// A withdrawal from a requester that was not watching it.
    Unchanged,
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
        // WAL so a long block scan does not block the inbox worker, and
        // NORMAL sync because losing the last few writes costs a rescan, not
        // correctness.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // The observer and the inbox worker each hold a connection and both
        // write, so a write that meets the other's lock has to wait its turn.
        // This restates rusqlite's own default (5 s, set in `Connection::open`
        // as of 0.40), which is why removing it changes nothing today; it is
        // kept so the reliance is written down and survives a change of that
        // default.
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
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

    /// One transaction, so two connections opening one database at once
    /// cannot both run a step meant to run once, such as adding a column.
    fn migrate(&self) -> anyhow::Result<()> {
        self.with_transaction(|| self.migrate_steps())
    }

    fn migrate_steps(&self) -> anyhow::Result<()> {
        // `script_interests` first shipped with one `since_ms` column and no
        // record of withdrawals, on a branch that never ran against a real
        // database. Such a table holds nothing worth keeping and would stop
        // the index below, so it is replaced.
        if self
            .conn
            .prepare("SELECT 1 FROM pragma_table_info('script_interests') WHERE name = 'since_ms'")?
            .exists([])?
        {
            self.conn.execute_batch("DROP TABLE script_interests;")?;
        }
        // `inbox_handled` first had no requester column. Its rows are still
        // good (they are what removals are built from), so the column is added
        // rather than the table replaced; old rows count against the whole
        // budget and no Ghost Key's share. Added before the batch below,
        // whose index needs it.
        let handled_exists = self
            .conn
            .prepare("SELECT 1 FROM pragma_table_info('inbox_handled')")?
            .exists([])?;
        let handled_has_requester = self
            .conn
            .prepare("SELECT 1 FROM pragma_table_info('inbox_handled') WHERE name = 'ghostkey'")?
            .exists([])?;
        if handled_exists && !handled_has_requester {
            self.conn.execute_batch(
                "ALTER TABLE inbox_handled ADD COLUMN ghostkey BLOB NOT NULL DEFAULT X'';",
            )?;
        }
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

            -- Who asked for each script, by Ghost Key, and whether they still
            -- want it: one row per (script, requester) holding that
            -- requester's latest request. A withdrawal is kept for a day, so a
            -- delayed older Watch cannot bring the interest back. Never
            -- replicated. See the module docs.
            CREATE TABLE IF NOT EXISTS script_interests (
                network        TEXT NOT NULL,
                script_pubkey  BLOB NOT NULL,
                ghostkey       BLOB NOT NULL,
                watching       INTEGER NOT NULL,
                request_ms     INTEGER NOT NULL,
                recorded_ms    INTEGER NOT NULL,
                PRIMARY KEY (network, script_pubkey, ghostkey)
            );
            CREATE INDEX IF NOT EXISTS script_interests_by_ghostkey
                ON script_interests (ghostkey, watching);

            -- Watch expiry asks, for each watch that ran out, whether a
            -- payment to its script is still being buried.
            CREATE INDEX IF NOT EXISTS observed_outputs_by_script
                ON observed_outputs (network, script_pubkey);

            -- Every observer round asks which scripts have a payment in
            -- doubt; the table is never pruned, so read only those rows.
            CREATE INDEX IF NOT EXISTS observed_outputs_in_doubt
                ON observed_outputs (network, script_pubkey)
                WHERE block_height IS NULL;

            -- The inbox's own bookkeeping. Today only `signed_floor`, the
            -- highest floor this bridge has signed: entries below it are never
            -- acted on, even if a stale copy of the inbox presents them again.
            CREATE TABLE IF NOT EXISTS inbox_meta (
                name   TEXT PRIMARY KEY,
                value  INTEGER NOT NULL
            );

            -- Inbox entries already acted on, from which each removal batch
            -- is built. A removal can fail to land,
            -- and without this record a Watch whose removal was lost would
            -- be acted on again after the same requester's later Unwatch had
            -- been, bringing back an interest they withdrew. Pruned once the
            -- inbox floor passes an entry, because the inbox drops the entry
            -- itself from then on.
            CREATE TABLE IF NOT EXISTS inbox_handled (
                entry_key     BLOB PRIMARY KEY,
                entry_height  INTEGER NOT NULL,
                -- Who sent it, so no one sender spends the removal budget.
                ghostkey      BLOB NOT NULL DEFAULT X''
            );
            CREATE INDEX IF NOT EXISTS inbox_handled_by_ghostkey
                ON inbox_handled (ghostkey);

            -- Left behind by the HTTP request service this bridge used to run.
            DROP TABLE IF EXISTS challenges;
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

    /// Move the checkpoint back to `height`, never forward, and never create
    /// one. Only the startup rewinds call this (the demo scripts' backfill and
    /// the tip contract's refill), before the observer starts. A watch request
    /// does not: see freenet/freenet-bitcoin#7.
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
                 -- Keep the lowest height recorded. Nothing reads it to
                 -- decide a scan yet (freenet/freenet-bitcoin#7); once a
                 -- backfill does, a later requester must not cut short the
                 -- history an earlier one asked for.
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

    /// Scripts with an output a reorg moved out of its block and that no scan
    /// has seen again since, each once: the observer keeps scanning for them,
    /// watched or not, until it does. See `observer::scan_set`.
    pub fn scripts_with_unconfirmed_outputs(
        &self,
        net: BitcoinNetwork,
    ) -> anyhow::Result<Vec<Vec<u8>>> {
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT script_pubkey FROM observed_outputs
             WHERE network = ?1 AND block_height IS NULL",
        )?;
        // A row that fails to read must fail the round, not drop its script
        // from the scan and leave its payment retracted.
        let rows = stmt
            .query_map(params![net.as_str()], |r| r.get::<_, Vec<u8>>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Whether this exact output was moved out of its block by a reorg and no
    /// scan has seen it since.
    pub fn is_output_in_doubt(
        &self,
        net: BitcoinNetwork,
        txid: &[u8; 32],
        vout: u32,
    ) -> anyhow::Result<bool> {
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM observed_outputs
             WHERE network = ?1 AND txid = ?2 AND vout = ?3 AND block_height IS NULL)",
            params![net.as_str(), txid.to_vec(), vout as i64],
            |r| r.get::<_, bool>(0),
        )?)
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

    // --- who asked for each script ------------------------------------------

    /// Record one requester's latest request about one script.
    ///
    /// Requests are applied in the order their sender made them, by
    /// `request_ms`, whatever order they arrive in: a request no newer than
    /// the one already recorded for that requester and script changes
    /// nothing. Call inside [`Store::with_transaction`] together with the
    /// watch change it implies, so the two cannot come apart.
    pub fn set_interest(
        &self,
        i: &Interest,
        max_per_ghostkey: usize,
        now_ms: i64,
    ) -> anyhow::Result<InterestChange> {
        let net = i.network.as_str();
        let gk = i.ghostkey.to_vec();
        let request_ms = i.request_ms.min(i64::MAX as u64) as i64;
        let existing: Option<(bool, i64)> = self
            .conn
            .query_row(
                "SELECT watching, request_ms FROM script_interests
                 WHERE network = ?1 AND script_pubkey = ?2 AND ghostkey = ?3",
                params![net, i.script, gk],
                |r| Ok((r.get::<_, i64>(0)? != 0, r.get::<_, i64>(1)?)),
            )
            .optional()?;
        if let Some((prev_watching, prev)) = existing {
            // Same millisecond: a withdrawal wins over a watch, so a Watch and
            // an Unwatch that tie end unwatched whichever arrives first.
            let newer = request_ms > prev || (request_ms == prev && prev_watching && !i.watching);
            if !newer {
                return Ok(InterestChange::Stale);
            }
        }
        let was_watching = existing.is_some_and(|(w, _)| w);

        // A withdrawal is kept so a delayed older Watch cannot land after it.
        // Each requester may hold a bounded number, like watches, or one could
        // fill the table; a day's pruning clears them. The bound counts every
        // withdrawal the requester holds, and at the bound a withdrawal of a
        // script it never watched is simply not recorded.
        if !i.watching && existing.is_none() {
            let held: i64 = self.conn.query_row(
                "SELECT COUNT(*) FROM script_interests WHERE ghostkey = ?1 AND watching = 0",
                params![gk],
                |r| r.get(0),
            )?;
            if held as usize >= max_per_ghostkey {
                return Ok(InterestChange::Unchanged);
            }
        }

        if i.watching && !was_watching {
            let held: i64 = self.conn.query_row(
                "SELECT COUNT(*) FROM script_interests WHERE ghostkey = ?1 AND watching = 1",
                params![gk],
                |r| r.get(0),
            )?;
            if held as usize >= max_per_ghostkey {
                return Ok(InterestChange::OverCap);
            }
            // A script watched before anyone asked for it through the inbox,
            // an operator's demo script or one registered before the inbox
            // existed, has no requester on record. Give it one that never
            // leaves, so inbox requesters leaving cannot end it.
            if self.watchers(i.network, i.script)? == 0 && self.is_watched(i.network, i.script)? {
                self.conn.execute(
                    "INSERT OR IGNORE INTO script_interests
                         (network, script_pubkey, ghostkey, watching, request_ms, recorded_ms)
                     VALUES (?1, ?2, ?3, 1, 0, ?4)",
                    params![net, i.script, OPERATOR_INTEREST.to_vec(), now_ms],
                )?;
            }
        }

        self.conn.execute(
            "INSERT INTO script_interests
                 (network, script_pubkey, ghostkey, watching, request_ms, recorded_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(network, script_pubkey, ghostkey) DO UPDATE SET
                 watching = ?4, request_ms = ?5, recorded_ms = ?6",
            params![net, i.script, gk, i.watching as i64, request_ms, now_ms],
        )?;

        Ok(match (i.watching, was_watching) {
            (true, _) => InterestChange::Watching,
            (false, false) => InterestChange::Unchanged,
            (false, true) => InterestChange::Withdrawn {
                last: self.watchers(i.network, i.script)? == 0,
            },
        })
    }

    /// How many requesters currently want `script`.
    fn watchers(&self, net: BitcoinNetwork, script: &[u8]) -> anyhow::Result<usize> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM script_interests
             WHERE network = ?1 AND script_pubkey = ?2 AND watching = 1",
            params![net.as_str(), script],
            |r| r.get(0),
        )?;
        Ok(n as usize)
    }

    /// Requesters on `net` whose latest request, a Watch, was recorded before
    /// `cutoff_ms`, as (script, Ghost Key): the watches that have run out.
    /// Operator interests never run out and are left out.
    pub fn watches_recorded_before(
        &self,
        net: BitcoinNetwork,
        cutoff_ms: i64,
    ) -> anyhow::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut stmt = self.conn.prepare(
            "SELECT script_pubkey, ghostkey FROM script_interests
             WHERE network = ?1 AND watching = 1 AND recorded_ms < ?2 AND ghostkey != ?3
             ORDER BY script_pubkey, ghostkey",
        )?;
        let rows = stmt
            .query_map(
                params![net.as_str(), cutoff_ms, OPERATOR_INTEREST.to_vec()],
                |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )?
            // A row that fails to read fails the expiry, which is logged and
            // tried again, rather than vanishing without a word.
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// End one requester's watch because it ran out, returning whether
    /// anyone still wants the script.
    ///
    /// Recorded as a withdrawal made now, with the expired Watch's timestamp,
    /// so a delayed copy of that Watch cannot bring it back, while any newer
    /// Watch from the requester renews it. Call inside
    /// [`Store::with_transaction`] with the watch removal it implies.
    pub fn expire_interest(
        &self,
        net: BitcoinNetwork,
        script: &[u8],
        ghostkey: &[u8],
        now_ms: i64,
    ) -> anyhow::Result<bool> {
        self.conn.execute(
            "UPDATE script_interests SET watching = 0, recorded_ms = ?4
             WHERE network = ?1 AND script_pubkey = ?2 AND ghostkey = ?3 AND watching = 1",
            params![net.as_str(), script, ghostkey, now_ms],
        )?;
        Ok(self.watchers(net, script)? == 0)
    }

    /// Whether a payment to `script` has been seen that the chain has not yet
    /// buried `deep` blocks below `tip`: confirmed fewer than `deep` deep, or
    /// moved out of its block by a reorg and not yet seen again.
    ///
    /// A payment a reorg removed for good, double-spent rather than re-mined,
    /// stays in the second case forever, and keeps its watch alive. That
    /// errs towards watching: it costs updates, never a missed payment.
    pub fn has_shallow_output(
        &self,
        net: BitcoinNetwork,
        script: &[u8],
        tip: u32,
        deep: u32,
    ) -> anyhow::Result<bool> {
        // Depth is tip - height + 1, so fewer than `deep` deep means a height
        // above tip + 1 - deep.
        let above = tip as i64 + 1 - deep as i64;
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM observed_outputs
             WHERE network = ?1 AND script_pubkey = ?2
               AND (block_height IS NULL OR block_height > ?3))",
            params![net.as_str(), script, above],
            |r| r.get::<_, bool>(0),
        )?)
    }

    /// Forget withdrawals recorded before `cutoff_ms`. A withdrawal only has
    /// to outlive any older request still in the inbox, which is hours.
    pub fn prune_withdrawals_before(&self, cutoff_ms: i64) -> anyhow::Result<()> {
        self.conn.execute(
            "DELETE FROM script_interests WHERE watching = 0 AND recorded_ms < ?1",
            params![cutoff_ms],
        )?;
        Ok(())
    }

    // --- inbox bookkeeping --------------------------------------------------

    /// The highest floor this bridge's key has signed for its inbox, whether
    /// this bridge sent it or read it back from the inbox.
    pub fn signed_floor(&self) -> anyhow::Result<Option<u32>> {
        Ok(self
            .conn
            .query_row(
                "SELECT value FROM inbox_meta WHERE name = 'signed_floor'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .map(|v| v as u32))
    }

    /// Record a floor this bridge signed. Only ever raises the record.
    pub fn set_signed_floor(&self, height: u32) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO inbox_meta (name, value) VALUES ('signed_floor', ?1)
             ON CONFLICT(name) DO UPDATE SET value = MAX(value, ?1)",
            params![height as i64],
        )?;
        Ok(())
    }

    /// Run `f` as one SQLite transaction: everything it writes lands, or none
    /// of it does. Taken as a write transaction from the start, so it waits
    /// for the observer's lock (see the busy timeout in `open`) rather than
    /// failing when it first writes.
    pub fn with_transaction<T>(&self, f: impl FnOnce() -> anyhow::Result<T>) -> anyhow::Result<T> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.conn,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let out = f()?;
        tx.commit()?;
        Ok(out)
    }

    /// Run arbitrary SQL, for tests that need to arrange a failure.
    #[cfg(test)]
    pub fn execute_for_test(&self, sql: &str) -> anyhow::Result<()> {
        self.conn.execute_batch(sql)?;
        Ok(())
    }

    /// Replace the busy timeout with `handler`, for tests that need to see
    /// each time a write meets another connection's lock.
    #[cfg(test)]
    pub fn busy_handler_for_test(&self, handler: Option<fn(i32) -> bool>) -> anyhow::Result<()> {
        self.conn.busy_handler(handler)?;
        Ok(())
    }

    // --- inbox entries already acted on ------------------------------------

    pub fn is_handled(&self, entry_key: &[u8; 32]) -> anyhow::Result<bool> {
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM inbox_handled WHERE entry_key = ?1",
                params![entry_key.to_vec()],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false))
    }

    pub fn mark_handled(
        &self,
        entry_key: &[u8; 32],
        entry_height: u32,
        ghostkey: &[u8],
    ) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO inbox_handled (entry_key, entry_height, ghostkey)
             VALUES (?1, ?2, ?3)",
            params![entry_key.to_vec(), entry_height as i64, ghostkey],
        )?;
        Ok(())
    }

    /// Entries read from one Ghost Key that the floor has not yet passed: its
    /// part of [`Store::handled_count`].
    pub fn handled_count_for(&self, ghostkey: &[u8]) -> anyhow::Result<usize> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM inbox_handled WHERE ghostkey = ?1",
            params![ghostkey],
            |r| r.get(0),
        )?;
        Ok(n as usize)
    }

    /// Forget entries dated below `floor`: the inbox has dropped them, so
    /// they can never be presented again.
    pub fn prune_handled_below(&self, floor: u32) -> anyhow::Result<()> {
        self.conn.execute(
            "DELETE FROM inbox_handled WHERE entry_height < ?1",
            params![floor as i64],
        )?;
        Ok(())
    }

    /// Entries read that the floor has not yet passed, which is how many
    /// removals the inbox still has to hold for this bridge. Accurate once
    /// [`Store::prune_handled_below`] has run for the current floor.
    ///
    /// Can undercount what the network holds: it is pruned to the highest
    /// floor this bridge signed, which may not have landed yet, and a restored
    /// database starts again from nothing. The bridge's budget is half the
    /// bound peers enforce to leave room for exactly that.
    pub fn handled_count(&self) -> anyhow::Result<usize> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM inbox_handled", [], |r| r.get(0))?;
        Ok(n as usize)
    }

    /// The keys of every entry read at one height: what one removal batch
    /// names.
    pub fn handled_at(&self, entry_height: u32) -> anyhow::Result<Vec<[u8; 32]>> {
        let mut stmt = self
            .conn
            .prepare("SELECT entry_key FROM inbox_handled WHERE entry_height = ?1")?;
        // A row that fails to read is logged and left out, not made to fail
        // the pass: failing would stop the bridge reading anything until the
        // floor passed the row, while leaving it out costs only that entry's
        // removal, and the entry is not acted on twice.
        let keys = stmt
            .query_map(params![entry_height as i64], |r| r.get::<_, Vec<u8>>(0))?
            .filter_map(|row| match row.map(<[u8; 32]>::try_from) {
                Ok(Ok(k)) => Some(k),
                Ok(Err(k)) => {
                    tracing::warn!(
                        len = k.len(),
                        entry_height,
                        "an entry key on record is not 32 bytes"
                    );
                    None
                }
                Err(e) => {
                    tracing::warn!(entry_height, "an entry key on record cannot be read: {e}");
                    None
                }
            })
            .collect();
        Ok(keys)
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
        // Informational until freenet/freenet-bitcoin#7. Once a backfill reads
        // it, a later request pushing it up would cut short the history an
        // earlier watcher asked for.
        let s = store();
        s.add_watch(&watch(b"abc", 100, false), 0).unwrap();
        s.add_watch(&watch(b"abc", 900_000, false), 0).unwrap();
        assert_eq!(
            s.watched(BitcoinNetwork::Signet).unwrap()[0].scan_from_height,
            100
        );
    }

    /// A rewind that moved the cursor forward would skip the blocks between,
    /// and every payment in them would never be seen.
    #[test]
    fn a_rewind_only_ever_moves_the_checkpoint_back() {
        let s = store();
        let at = |h| BlockAnchor {
            height: h,
            hash: BlockHash([0; 32]),
        };
        s.set_checkpoint(BitcoinNetwork::Signet, &at(500)).unwrap();
        s.rewind_checkpoint_to(BitcoinNetwork::Signet, 800).unwrap();
        assert_eq!(
            s.checkpoint(BitcoinNetwork::Signet)
                .unwrap()
                .unwrap()
                .height,
            500
        );
        s.rewind_checkpoint_to(BitcoinNetwork::Signet, 300).unwrap();
        assert_eq!(
            s.checkpoint(BitcoinNetwork::Signet)
                .unwrap()
                .unwrap()
                .height,
            300
        );
        s.rewind_checkpoint_to(BitcoinNetwork::Bitcoin, 300)
            .unwrap();
        assert!(s.checkpoint(BitcoinNetwork::Bitcoin).unwrap().is_none());
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

    fn interest<'a>(
        script: &'a [u8],
        gk: &'a [u8; 32],
        watching: bool,
        request_ms: u64,
    ) -> Interest<'a> {
        Interest {
            network: BitcoinNetwork::Signet,
            script,
            ghostkey: gk,
            watching,
            request_ms,
        }
    }

    #[test]
    fn a_requesters_latest_request_wins_whatever_order_they_arrive_in() {
        let s = store();
        let gk = [1u8; 32];
        assert_eq!(
            s.set_interest(&interest(b"abc", &gk, false, 20), 10, 0)
                .unwrap(),
            InterestChange::Unchanged
        );
        assert_eq!(
            s.set_interest(&interest(b"abc", &gk, true, 10), 10, 0)
                .unwrap(),
            InterestChange::Stale,
            "the earlier Watch arrived after the later Unwatch, and changes nothing"
        );
        assert_eq!(
            s.set_interest(&interest(b"abc", &gk, true, 30), 10, 0)
                .unwrap(),
            InterestChange::Watching
        );
        assert_eq!(
            s.set_interest(&interest(b"abc", &gk, true, 30), 10, 0)
                .unwrap(),
            InterestChange::Stale,
            "the same request read twice"
        );
    }

    #[test]
    fn a_withdrawal_says_whether_anyone_still_wants_the_script() {
        let s = store();
        let (a, b) = ([1u8; 32], [2u8; 32]);
        s.set_interest(&interest(b"abc", &a, true, 1), 10, 0)
            .unwrap();
        s.set_interest(&interest(b"abc", &b, true, 1), 10, 0)
            .unwrap();
        assert_eq!(
            s.set_interest(&interest(b"abc", &a, false, 2), 10, 0)
                .unwrap(),
            InterestChange::Withdrawn { last: false }
        );
        assert_eq!(
            s.set_interest(&interest(b"abc", &b, false, 2), 10, 0)
                .unwrap(),
            InterestChange::Withdrawn { last: true }
        );
    }

    #[test]
    fn a_requester_cannot_watch_more_than_its_limit() {
        let s = store();
        let gk = [1u8; 32];
        s.set_interest(&interest(b"s1", &gk, true, 1), 2, 0)
            .unwrap();
        s.set_interest(&interest(b"s2", &gk, true, 1), 2, 0)
            .unwrap();
        assert_eq!(
            s.set_interest(&interest(b"s3", &gk, true, 1), 2, 0)
                .unwrap(),
            InterestChange::OverCap
        );
        s.set_interest(&interest(b"s1", &gk, false, 2), 2, 0)
            .unwrap();
        assert_eq!(
            s.set_interest(&interest(b"s3", &gk, true, 3), 2, 0)
                .unwrap(),
            InterestChange::Watching,
            "a withdrawal frees room"
        );
    }

    #[test]
    fn a_script_watched_before_the_inbox_gets_an_owner_that_never_leaves() {
        let s = store();
        s.add_watch(&watch(b"old", 0, false), 0).unwrap();
        let gk = [1u8; 32];
        s.set_interest(&interest(b"old", &gk, true, 1), 10, 0)
            .unwrap();
        assert_eq!(
            s.set_interest(&interest(b"old", &gk, false, 2), 10, 0)
                .unwrap(),
            InterestChange::Withdrawn { last: false }
        );
    }

    #[test]
    fn old_withdrawals_are_forgotten() {
        let s = store();
        let gk = [1u8; 32];
        s.set_interest(&interest(b"abc", &gk, false, 20), 10, 1_000)
            .unwrap();
        s.prune_withdrawals_before(2_000).unwrap();
        assert_eq!(
            s.set_interest(&interest(b"abc", &gk, true, 10), 10, 3_000)
                .unwrap(),
            InterestChange::Watching,
            "once forgotten, the withdrawal no longer outranks an older request"
        );
    }

    #[test]
    fn the_signed_floor_only_rises() {
        let s = store();
        assert_eq!(s.signed_floor().unwrap(), None);
        s.set_signed_floor(100).unwrap();
        s.set_signed_floor(90).unwrap();
        assert_eq!(s.signed_floor().unwrap(), Some(100));
    }

    #[test]
    fn a_failed_transaction_leaves_nothing_behind() {
        let s = store();
        let r: anyhow::Result<()> = s.with_transaction(|| {
            s.mark_handled(&[1; 32], 100, &[])?;
            anyhow::bail!("the step after it failed")
        });
        assert!(r.is_err());
        assert!(!s.is_handled(&[1; 32]).unwrap());
    }

    #[test]
    fn a_withdrawal_beats_a_watch_made_in_the_same_millisecond() {
        let gk = [1u8; 32];
        let s = store();
        s.set_interest(&interest(b"abc", &gk, true, 5), 10, 0)
            .unwrap();
        assert_eq!(
            s.set_interest(&interest(b"abc", &gk, false, 5), 10, 0)
                .unwrap(),
            InterestChange::Withdrawn { last: true },
            "the Unwatch read second still applies"
        );
        let s = store();
        s.set_interest(&interest(b"abc", &gk, false, 5), 10, 0)
            .unwrap();
        assert_eq!(
            s.set_interest(&interest(b"abc", &gk, true, 5), 10, 0)
                .unwrap(),
            InterestChange::Stale,
            "the Watch read second does not"
        );
    }

    #[test]
    fn withdrawals_of_scripts_never_watched_are_bounded_per_requester() {
        let s = store();
        let gk = [1u8; 32];
        for script in [b"s1", b"s2", b"s3"] {
            s.set_interest(&interest(script, &gk, false, 5), 2, 0)
                .unwrap();
        }
        assert_eq!(
            s.set_interest(&interest(b"s2", &gk, true, 1), 2, 0)
                .unwrap(),
            InterestChange::Stale,
            "the second withdrawal was recorded"
        );
        assert_eq!(
            s.set_interest(&interest(b"s3", &gk, true, 1), 2, 0)
                .unwrap(),
            InterestChange::Watching,
            "the third was over the bound and was not"
        );
    }

    /// The operator's interest is marked by a key no request can carry. The
    /// all-zero key can be certified, so it is just another requester.
    #[test]
    fn the_all_zero_key_is_an_ordinary_requester_not_the_operator() {
        let s = store();
        s.add_watch(&watch(b"old", 0, false), 0).unwrap();
        let zero = [0u8; 32];
        s.set_interest(&interest(b"old", &zero, true, 1), 10, 0)
            .unwrap();
        assert_eq!(
            s.set_interest(&interest(b"old", &zero, false, 2), 10, 0)
                .unwrap(),
            InterestChange::Withdrawn { last: false },
            "the operator still wants it"
        );
    }

    #[test]
    fn a_database_from_the_first_inbox_commit_still_opens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bridge.sqlite");
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch(
                "CREATE TABLE script_interests (
                     network TEXT NOT NULL, script_pubkey BLOB NOT NULL,
                     ghostkey BLOB NOT NULL, since_ms INTEGER NOT NULL,
                     PRIMARY KEY (network, script_pubkey, ghostkey));
                 INSERT INTO script_interests VALUES ('signet', X'00', X'01', 0);",
            )
            .unwrap();
        }
        let s = Store::open(&path).unwrap();
        assert_eq!(
            s.set_interest(&interest(b"abc", &[1u8; 32], true, 1), 10, 0)
                .unwrap(),
            InterestChange::Watching
        );
        drop(s);
        let s = Store::open(&path).expect("and again, once migrated");
        assert_eq!(
            s.set_interest(&interest(b"abc", &[1u8; 32], true, 1), 10, 0)
                .unwrap(),
            InterestChange::Stale,
            "what was recorded after migrating survives the next open"
        );
    }

    /// Only outputs still moved out of their block put a script in doubt,
    /// and each script once.
    #[test]
    fn only_payments_a_reorg_moved_and_nobody_found_again_are_in_doubt() {
        let s = store();
        let net = BitcoinNetwork::Signet;
        let at = Some((100, BlockHash([1; 32])));
        s.record_output(net, b"moved", &[1; 32], 0, 5, None)
            .unwrap();
        s.record_output(net, b"moved", &[1; 32], 1, 5, None)
            .unwrap();
        s.record_output(net, b"settled", &[2; 32], 0, 5, at)
            .unwrap();
        s.record_output(BitcoinNetwork::Bitcoin, b"elsewhere", &[3; 32], 0, 5, None)
            .unwrap();
        assert_eq!(
            s.scripts_with_unconfirmed_outputs(net).unwrap(),
            vec![b"moved".to_vec()]
        );
        s.record_output(net, b"moved", &[1; 32], 0, 5, at).unwrap();
        s.record_output(net, b"moved", &[1; 32], 1, 5, at).unwrap();
        assert!(s.scripts_with_unconfirmed_outputs(net).unwrap().is_empty());
    }

    /// A database whose `inbox_handled` predates the requester column keeps
    /// its rows, which removals are built from, and gains the column.
    #[test]
    fn handled_entries_from_before_their_requester_was_recorded_are_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bridge.sqlite");
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch(
                "CREATE TABLE inbox_handled (
                     entry_key BLOB PRIMARY KEY, entry_height INTEGER NOT NULL);
                 INSERT INTO inbox_handled VALUES (X'01', 7);",
            )
            .unwrap();
        }
        let s = Store::open(&path).unwrap();
        s.mark_handled(&[2u8; 32], 7, &[9u8; 32]).unwrap();
        assert_eq!(s.handled_count().unwrap(), 2);
        assert_eq!(s.handled_count_for(&[9u8; 32]).unwrap(), 1);
        assert_eq!(
            s.handled_at(7).unwrap(),
            vec![[2u8; 32]],
            "the old key is not 32 bytes"
        );
        drop(s);
        Store::open(&path).expect("and again, once migrated");
    }

    /// The observer and the inbox worker write one database through two
    /// connections. A write that meets the other's lock must wait its turn,
    /// not fail.
    ///
    /// The waiting transaction reads before it writes, as `set_interest` does.
    /// That is the case a deferred transaction gets wrong: its read pins a
    /// snapshot the other connection's commit then makes stale, and its write
    /// fails at once instead of waiting.
    #[test]
    fn a_write_waits_for_the_other_connections_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bridge.sqlite");
        let a = Store::open(&path).unwrap();
        let b = Store::open(&path).unwrap();
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            a.with_transaction(|| {
                a.mark_handled(&[1; 32], 100, &[])?;
                locked_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(())
            })
            .unwrap();
        });
        locked_rx.recv().unwrap();
        // b's write blocks inside SQLite, so the lock is released from
        // another thread, well inside the busy timeout.
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(200));
            release_tx.send(()).unwrap();
        });
        b.with_transaction(|| {
            b.is_handled(&[1; 32])?;
            b.mark_handled(&[2; 32], 100, &[])
        })
        .expect("waits for the lock, then writes");
        releaser.join().unwrap();
        holder.join().unwrap();
        assert!(b.is_handled(&[1; 32]).unwrap());
        assert!(b.is_handled(&[2; 32]).unwrap());
    }

    #[test]
    fn handled_entries_are_forgotten_once_the_floor_passes_them() {
        let s = store();
        s.mark_handled(&[1; 32], 100, &[]).unwrap();
        s.mark_handled(&[2; 32], 110, &[]).unwrap();
        s.prune_handled_below(105).unwrap();
        assert!(!s.is_handled(&[1; 32]).unwrap());
        assert!(s.is_handled(&[2; 32]).unwrap());
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
