//! The bridge's side of its request inbox.
//!
//! Clients ask this bridge to watch a Bitcoin script by appending a sealed,
//! Ghost Key signed entry to the bridge's inbox contract (see
//! `freenet_bitcoin_inbox`). This module reads the inbox, acts on each entry,
//! removes it with a signed removal batch, keeps the inbox's floor following
//! the Bitcoin mainnet tip, and ends watches nobody has renewed for a day.
//!
//! # Its own connection
//!
//! `FreenetPublisher` treats the next message on its connection as the reply
//! to the request it just sent, so an update notification from a subscription
//! would be taken as some other request's answer. Here one task owns the
//! connection and handles every message by what it is, so subscribing is
//! safe. What to do with each message is decided by [`Driver`], which does no
//! I/O and is tested on its own.
//!
//! # Order, and acting once
//!
//! Neither the order entries arrive in nor their heights say in which order a
//! sender made its requests: a Watch and a later Unwatch can share a height,
//! and can reach the bridge in separate reads in either order. So each request
//! carries its sender's timestamp, sealed, and the store keeps each
//! requester's latest request per script (`Store::set_interest`). An older
//! request arriving late changes nothing.
//!
//! Entries acted on are also recorded (`inbox_handled`), so an entry whose
//! removal failed to land is removed again rather than acted on again, and
//! the highest floor this bridge has signed is stored, so an entry below it is
//! never acted on even when a stale copy of the inbox presents it. The same
//! record is what each removal batch is built from.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::SigningKey;
use freenet_bitcoin_common::{from_cbor, to_cbor, BitcoinNetwork, BridgeId};
use freenet_bitcoin_inbox::seal::unseal;
use freenet_bitcoin_inbox::{
    Action, EntryKey, InboxDelta, InboxEntry, InboxParameters, InboxStateV1, RemovalBatch,
    RemovedPrefix, SignedFloor, FLOOR_LAG_BLOCKS, REMOVAL_BUDGET, WINDOW_BLOCKS,
};
use freenet_stdlib::client_api::{
    ClientError, ClientRequest, ContractRequest, ContractResponse, ErrorKind, HostResponse, WebApi,
};
use freenet_stdlib::prelude::{
    ContractCode, ContractContainer, ContractKey, ContractWasmAPIVersion, Parameters, StateDelta,
    UpdateData, WrappedContract, WrappedState,
};

use crate::chain::ChainClient;
use crate::config::{BridgeConfig, NetworkConfig};
use crate::freenet::is_not_found;
use crate::store::{Interest, InterestChange, Store, WatchedScript};

/// Scripts one Ghost Key may have this bridge watch at once.
///
/// The inbox bounds how many requests a Ghost Key has in flight, not how many
/// it makes over time, so without this one Ghost Key could grow the watch list,
/// and the work of scanning every block against it, without limit.
pub const MAX_WATCHES_PER_GHOSTKEY: usize = 1000;

/// How often the inbox is read even when no notification arrives.
const POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Longest wait between reconnection attempts.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// How long a read may go unanswered before it is sent again.
const READ_TIMEOUT: Duration = Duration::from_secs(60);

/// Least time between attempts to open an inbox the node reports absent.
const REOPEN_INTERVAL: Duration = Duration::from_secs(60);

/// How long a withdrawal is remembered. It only has to outlive any older
/// request by the same sender still in the inbox, which is hours at most.
const WITHDRAWAL_MEMORY_MS: i64 = 24 * 60 * 60 * 1000;

/// How much of [`REMOVAL_BUDGET`] one Ghost Key may use: a 64th of it.
///
/// Without a share, one Ghost Key sending without pause could spend the whole
/// budget, and while it is spent the bridge reads nothing, so 64 Ghost Keys
/// would hold every place in the inbox without sending again. With it,
/// spending the budget takes 64 Ghost Keys each having 64 requests read within
/// five blocks, about 50 minutes (about 66 sent each, to hold the inbox as
/// well), and a
/// key past its share only makes its own requests
/// wait. An honest sender watching many addresses names up to 32 in one
/// request.
pub const REMOVAL_SHARE_PER_GHOSTKEY: usize = REMOVAL_BUDGET / 64;

/// How long a watch lasts after the Watch that last asked for it.
///
/// Watching costs the bridge an update to the script's address contract with
/// every block, and an application typically watches an address for one
/// payment, so a watch nobody renews ends by itself rather than lasting until
/// someone remembers to withdraw it. A Watch sent again, with a newer
/// timestamp as every request must have, starts the day again. A watch whose
/// script has a payment still being buried outlives its day; see
/// [`Processor::expire_watches`].
pub const WATCH_LIFETIME_MS: i64 = 24 * 60 * 60 * 1000;

/// How long after connecting to its node the bridge waits before raising the
/// floor.
///
/// The node may have been down, or just started, and until it has caught up
/// with the inbox the requests other peers hold are missing from the copy the
/// bridge reads. Raising the floor at once would drop any of those dated
/// below it, unread. A node catches up with one small contract in seconds.
pub const FLOOR_HOLD_MS: i64 = 2 * 60 * 1000;

/// Whether the observer's lag, `behind` blocks (`None`: it has no checkpoint),
/// is worse than when last seen (`previous`, `None` if not lagging then).
fn lag_grew(previous: Option<Option<u32>>, behind: Option<u32>) -> bool {
    let lag = behind.unwrap_or(u32::MAX);
    previous.is_none_or(|p| lag > p.unwrap_or(u32::MAX))
}

/// Whether the floor is still held. The hold is kept on the monotonic clock,
/// so no step of the wall clock stretches it or cuts it short.
fn floor_held(until: Option<Instant>) -> bool {
    until.is_some_and(|t| Instant::now() < t)
}

/// How far past a watch's day the scanned tip's median time past must be
/// before the watch ends: two hours, the most a block's timestamp may run
/// ahead of the clock of a node that accepts it. So the block whose timestamp
/// is the tip's median time past was accepted after the day ended, and every
/// block above the tip came later still: every block from the day lies at or
/// below the tip the observer scanned. The median time past runs about an
/// hour behind the clock, so a watch lasts about 27 hours in practice.
pub const MEDIAN_TIME_MARGIN_MS: i64 = 2 * 60 * 60 * 1000;

/// How long a node may stay syncing before it is reported. A node is briefly
/// behind its headers at every block, which is not worth a line.
const SYNC_WARN_AFTER: std::time::Duration = std::time::Duration::from_secs(600);

/// How long each network's node has been syncing, so that one stuck syncing
/// is reported, once per spell.
#[derive(Debug, Default)]
struct SyncWatch {
    since: HashMap<BitcoinNetwork, Instant>,
    warned: BTreeSet<BitcoinNetwork>,
}

impl SyncWatch {
    /// The networks to report now: syncing for [`SYNC_WARN_AFTER`] and not
    /// yet reported in this spell.
    fn update(&mut self, syncing: &BTreeSet<BitcoinNetwork>, now: Instant) -> Vec<BitcoinNetwork> {
        self.since.retain(|n, _| syncing.contains(n));
        self.warned.retain(|n| syncing.contains(n));
        let mut report = Vec::new();
        for &n in syncing {
            let since = *self.since.entry(n).or_insert(now);
            if now.duration_since(since) >= SYNC_WARN_AFTER && self.warned.insert(n) {
                report.push(n);
            }
        }
        report
    }
}

/// How far behind the tip the observer may be, in blocks, before watches kept
/// for it are worth a warning. A block or two is an observer between rounds;
/// more than this is one that is stuck or catching up after downtime.
const OBSERVER_LAG_WARN_BLOCKS: u32 = 6;

// ---------------------------------------------------------------------------
// One pass over the inbox. No I/O but SQLite, so it is tested directly.
// ---------------------------------------------------------------------------

/// Chain tips a pass needs, read before it runs.
#[derive(Clone, Debug, Default)]
pub struct Tips {
    /// The tip of each network this bridge observes, where it could be read.
    pub by_network: HashMap<BitcoinNetwork, u32>,
    /// Networks whose node is still syncing: in initial block download, or
    /// holding headers it has not fetched the blocks for. Its tip is then
    /// only how far it has got, so no watch ends on it.
    pub syncing: BTreeSet<BitcoinNetwork>,
    /// Each network's tip's median time past, in milliseconds: Bitcoin's own
    /// clock, which a watch's day must pass as well as the host's.
    pub median_time_ms: HashMap<BitcoinNetwork, i64>,
}

impl Tips {
    /// The Bitcoin mainnet tip, which the inbox is dated by.
    pub fn mainnet(&self) -> Option<u32> {
        self.by_network.get(&BitcoinNetwork::Bitcoin).copied()
    }
}

/// What a pass decided.
#[derive(Debug, Default)]
pub struct Pass {
    /// Removals and floor to send back to the inbox.
    pub delta: InboxDelta,
    /// Entries acted on for the first time.
    pub acted: usize,
    /// Entries left unread because the removal budget was spent.
    pub deferred: usize,
    /// The Ghost Keys of those entries. Their watches do not end in this
    /// pass, since a waiting request may be the Watch that renews one.
    pub waiting: BTreeSet<[u8; 32]>,
    /// Something was held back that the same state and tips could release:
    /// the floor was held, or ending watches waited on the observer or
    /// failed. Such a pass must run again, not be passed over as quiet.
    pub gated: bool,
}

pub struct Processor<'a> {
    pub params: &'a InboxParameters,
    pub key: &'a SigningKey,
    pub store: &'a Store,
    /// Networks this bridge observes. A request for any other is dropped.
    pub observed: &'a [BitcoinNetwork],
    /// See [`MAX_WATCHES_PER_GHOSTKEY`]; a field so tests can use a small one.
    pub max_watches_per_ghostkey: usize,
    /// Each observed network's configured `deep_confirmations`: how deep a
    /// payment must be before the watch that found it may end.
    pub deep_confirmations: &'a HashMap<BitcoinNetwork, u32>,
    /// The floor is not raised before this instant; see [`FLOOR_HOLD_MS`].
    pub floor_hold_until: Option<Instant>,
    /// The observer lag last warned about, per network, so a stuck observer
    /// is reported when its lag changes rather than on every pass.
    pub lag_warned: std::cell::RefCell<HashMap<BitcoinNetwork, Option<u32>>>,
}

impl Processor<'_> {
    pub fn pass(&self, state: &InboxStateV1, tips: &Tips, now_ms: i64) -> Result<Pass> {
        // The floor this copy carries, if this bridge's key signed it, is
        // recorded before anything is pruned by it. Otherwise a later, older
        // copy could present entries whose record was pruned here.
        let state_floor = state
            .floor
            .as_ref()
            .filter(|f| f.verify(&self.params.bridge).is_ok())
            .map(|f| f.height);
        if let Some(f) = state_floor {
            self.store.set_signed_floor(f)?;
        }
        // The highest floor known to be in force, from this copy or any other.
        let known = self.store.signed_floor()?;
        if let Some(floor) = known {
            self.store.prune_handled_below(floor)?;
        }
        self.store
            .prune_withdrawals_before(now_ms - WITHDRAWAL_MEMORY_MS)?;

        // Each entry is checked on its own rather than the state as a whole.
        // The node already ran the contract's own checks; these catch a bad
        // record without letting it, or a rule this build and the contract
        // disagree on, stop the bridge reading every good one.
        let mut entries: Vec<(EntryKey, &InboxEntry)> = state.verified_entries(self.params);
        let unverified = state.entries.len().saturating_sub(entries.len());
        if unverified > 0 {
            tracing::warn!(
                unverified,
                "inbox entries that do not verify, or are already removed, were skipped"
            );
        }
        entries.sort_by_key(|(k, e)| (e.mainnet_height, *k));

        let mut pass = Pass::default();
        let mut handled = self.store.handled_count()?;
        let mut read_heights: BTreeSet<u32> = BTreeSet::new();
        for (k, e) in entries {
            // Below a floor this bridge signed: a stale copy of the inbox. It
            // was either acted on already or dropped unread when that floor
            // was set, and the floor sent below removes it. Above that floor's
            // window: no inbox this bridge serves admits it, and the checks on
            // each entry do not cover the window, so it is left alone here.
            if known.is_some_and(|f| {
                e.mainnet_height < f || e.mainnet_height > f.saturating_add(WINDOW_BLOCKS)
            }) {
                continue;
            }
            if !self.store.is_handled(&k.0)? {
                // Every entry read is removed, and a removal lasts until the
                // floor passes it. Past the budget, reading waits for the
                // floor, so a flood leaves requests waiting in the inbox
                // rather than growing the removals past what it may hold; and
                // past its share, a Ghost Key's own requests wait while
                // everyone else's are read.
                if handled >= REMOVAL_BUDGET
                    || self.store.handled_count_for(&e.ghostkey.0)? >= REMOVAL_SHARE_PER_GHOSTKEY
                {
                    pass.deferred += 1;
                    pass.waiting.insert(e.ghostkey.0);
                    continue;
                }
                self.store.with_transaction(|| {
                    self.act(e, tips, now_ms)?;
                    self.store
                        .mark_handled(&k.0, e.mainnet_height, &e.ghostkey.0)
                })?;
                handled += 1;
                pass.acted += 1;
            }
            read_heights.insert(e.mainnet_height);
        }
        if pass.deferred > 0 {
            tracing::warn!(
                deferred = pass.deferred,
                budget = REMOVAL_BUDGET,
                "requests wait for the floor: the removal budget, or their Ghost Key's share of it, is spent"
            );
        }

        // One batch per height, naming every entry ever read at it. It covers
        // any batch sent for that height before, so the inbox keeps only the
        // newest, and a batch that failed to land is made good by this one.
        // Built from the store, which is deterministic, and signed with
        // Ed25519, which is too: an unchanged set is sent as the same bytes.
        for h in read_heights {
            let removed: BTreeSet<RemovedPrefix> = self
                .store
                .handled_at(h)?
                .into_iter()
                .map(|k| EntryKey(k).removal_prefix())
                .collect();
            pass.delta
                .removals
                .push(RemovalBatch::sign(self.key, h, &removed));
        }

        let held = floor_held(self.floor_hold_until);
        let target = match tips.mainnet() {
            Some(tip) if !held => known.max(Some(tip.saturating_sub(FLOOR_LAG_BLOCKS))),
            _ => known,
        };
        if let Some(t) = target {
            if state_floor.is_none_or(|cur| t > cur) {
                self.store.set_signed_floor(t)?;
                pass.delta.floor = Some(SignedFloor::sign(self.key, t));
            }
        }

        // Last, and never allowed to cost the pass its removals and floor.
        // Not while the floor is held, because a node that has just connected
        // may not yet hold the Watch that renews a watch. And a Ghost Key with
        // a request waiting on the removal budget keeps its watches for now,
        // since that request may be the renewal: only its own, so no one
        // sender can hold back every watch on the bridge.
        pass.gated = held;
        if !held {
            match self.expire_watches(tips, now_ms, &pass.waiting) {
                Ok(lagging) => pass.gated |= lagging,
                Err(e) => {
                    pass.gated = true;
                    tracing::warn!(
                        "ending watches that ran out failed; the next pass tries again: {e:#}"
                    );
                }
            }
        }
        Ok(pass)
    }

    /// End watches nobody has renewed within [`WATCH_LIFETIME_MS`].
    ///
    /// Only on a network whose tip can be read and which the observer has
    /// scanned up to that tip. A watch's day is measured by the clock, but a
    /// payment is found by scanning, and after downtime the observer can be
    /// behind: ending a watch then would leave blocks mined during its day
    /// never scanned for it, since nothing rescans them later.
    ///
    /// And not while a payment to the script has been seen and is not yet
    /// `deep_confirmations` deep, so the watch lasts until the payment's
    /// proof is complete. A reorg after that finds a moved payment anyway:
    /// every scan also covers the scripts of payments a reorg moved out of
    /// their block and no scan has found since (`observer::scan_set`).
    ///
    /// Not for a Ghost Key in `waiting`, whose request waiting on the removal
    /// budget may be the renewal.
    ///
    /// Returns whether any watch that ran out was kept only because the
    /// observer was behind, so the caller runs the pass again.
    fn expire_watches(
        &self,
        tips: &Tips,
        now_ms: i64,
        waiting: &BTreeSet<[u8; 32]>,
    ) -> Result<bool> {
        enum Expiry {
            Ended { last: bool },
            Kept,
            Unscanned,
        }
        let (mut ended, mut stopped, mut lagging) = (0usize, 0usize, false);
        'networks: for &net in self.observed {
            let Some(&tip) = tips.by_network.get(&net) else {
                continue;
            };
            // A watch's day is counted by the chain's clock as well as the
            // host's: a node cut off from its peers, or just restarted, can
            // look synced at a stale tip the observer has scanned, and the
            // blocks after it may hold a payment. See MEDIAN_TIME_MARGIN_MS.
            let Some(&median_ms) = tips.median_time_ms.get(&net) else {
                continue;
            };
            let cutoff = now_ms
                .min(median_ms.saturating_sub(MEDIAN_TIME_MARGIN_MS))
                .saturating_sub(WATCH_LIFETIME_MS);
            // Every configured network has a value, since the field has a
            // default; a missing one means a build that disagrees with its
            // config, so keep watches while any payment to them is on record.
            let deep = self
                .deep_confirmations
                .get(&net)
                .copied()
                .unwrap_or(u32::MAX);
            // A row that fails to read stops expiry on its own network only.
            let candidates = match self.store.watches_recorded_before(net, cutoff) {
                Ok(c) => c,
                Err(e) => {
                    lagging = true;
                    tracing::warn!(network = ?net, "reading the watches that ran out failed: {e:#}");
                    continue;
                }
            };
            if candidates.is_empty() {
                self.lag_warned.borrow_mut().remove(&net);
                continue;
            }
            // A node still syncing reports as its tip the last block it has,
            // which the observer may well have scanned. That says nothing of
            // the blocks it has yet to fetch, from the day these watches ran.
            if tips.syncing.contains(&net) {
                lagging = true;
                continue;
            }
            // Checked once here, to spare a transaction per watch while the
            // observer is behind, and again inside each, where it counts.
            // Caught up means exactly at the tip: a checkpoint above it means
            // the node went back (a reindex), and has not fetched those blocks
            // again yet.
            let scanned_to = self.store.checkpoint(net)?.map(|c| c.height);
            if scanned_to != Some(tip) {
                lagging = true;
                let behind = scanned_to.map(|h| tip.saturating_sub(h));
                // Once per lag, not once per pass: a stuck observer is
                // reported each time it falls further behind, and not again
                // while it catches up.
                let previous = self.lag_warned.borrow_mut().insert(net, behind);
                if lag_grew(previous, behind) && behind.is_none_or(|b| b > OBSERVER_LAG_WARN_BLOCKS)
                {
                    tracing::warn!(
                        network = ?net,
                        ?behind,
                        kept = candidates.len(),
                        "watches that ran out are kept until the observer has scanned up to the tip"
                    );
                }
                continue;
            }
            self.lag_warned.borrow_mut().remove(&net);
            for (script, ghostkey) in candidates {
                if <[u8; 32]>::try_from(ghostkey.as_slice()).is_ok_and(|g| waiting.contains(&g)) {
                    continue;
                }
                // Checked inside the transaction that ends the watch, so the
                // observer's progress and outputs are read as they stand then.
                let outcome = self.store.with_transaction(|| {
                    let scanned = self.store.checkpoint(net)?.is_some_and(|c| c.height == tip);
                    if !scanned {
                        return Ok(Expiry::Unscanned);
                    }
                    if self.store.has_shallow_output(net, &script, tip, deep)? {
                        return Ok(Expiry::Kept);
                    }
                    let last = self
                        .store
                        .expire_interest(net, &script, &ghostkey, now_ms)?;
                    if last {
                        self.store.remove_watch(net, &script)?;
                    }
                    Ok(Expiry::Ended { last })
                });
                match outcome {
                    Ok(Expiry::Ended { last }) => {
                        ended += 1;
                        stopped += usize::from(last);
                    }
                    Ok(Expiry::Kept) => {}
                    // The observer moved since the check above (a reorg to
                    // the same height): tried again on the next pass.
                    Ok(Expiry::Unscanned) => lagging = true,
                    // One watch that cannot end must not keep the rest from
                    // ending; it is tried again on the next pass.
                    Err(e) => {
                        lagging = true;
                        tracing::warn!(network = ?net, "ending a watch that ran out failed: {e:#}");
                        // A database too busy to write fails every watch in
                        // turn, each after the busy timeout; stop until the
                        // next pass rather than wait out one per watch.
                        if is_busy(&e) {
                            break 'networks;
                        }
                    }
                }
            }
        }
        if ended > 0 {
            tracing::info!(
                ended,
                stopped,
                "watches nobody renewed for a day ended; `stopped` scripts are no longer scanned"
            );
        }
        Ok(lagging)
    }

    /// Act on one entry. An error here is the store failing, and rolls back
    /// the entry; anything wrong with the entry itself is logged and the entry
    /// is removed like any other, so it stops holding its sender's place. The
    /// removal therefore says the entry was read, not what came of it.
    fn act(&self, e: &InboxEntry, tips: &Tips, now_ms: i64) -> Result<()> {
        let body = match e.body() {
            Ok(b) => b,
            Err(err) => {
                tracing::warn!("dropping an inbox entry whose body does not decode: {err}");
                return Ok(());
            }
        };
        let req = match unseal(self.key, &e.ghostkey, e.mainnet_height, &body.sealed) {
            Ok(r) => r,
            Err(err) => {
                tracing::warn!("dropping an inbox entry this bridge cannot open: {err}");
                return Ok(());
            }
        };
        let net = req.network;
        if !self.observed.contains(&net) {
            tracing::info!(network = ?net, "dropping a request for a network this bridge does not observe");
            return Ok(());
        }

        let mut changed = 0usize;
        let mut refused = 0usize;
        match req.action {
            Action::Watch => {
                // A new script is watched from the observer's next round: it
                // reads its watch list once a round, so blocks left in the
                // round already running are not checked for it. The request's
                // `scan_from_height` hint is not acted on yet:
                // freenet/freenet-bitcoin#7 has why, and the design it needs.
                // The height recorded with the watch is informational, the tip
                // when it began, or `u32::MAX` when no tip was known.
                let tip = match tips.by_network.get(&net) {
                    Some(&t) => Some(t),
                    None => self.store.checkpoint(net)?.map(|a| a.height),
                };
                if req.scan_from_height.is_some() {
                    tracing::debug!(network = ?net, "a watch's rescan hint was not acted on (freenet-bitcoin#7)");
                }
                for script in &req.scripts {
                    let i = Interest {
                        network: net,
                        script: &script.0,
                        ghostkey: &e.ghostkey.0,
                        watching: true,
                        request_ms: req.made_at_ms,
                    };
                    match self
                        .store
                        .set_interest(&i, self.max_watches_per_ghostkey, now_ms)?
                    {
                        InterestChange::Watching => {
                            self.store.add_watch(
                                &WatchedScript {
                                    network: net,
                                    script_pubkey: script.0.clone(),
                                    scan_from_height: tip.unwrap_or(u32::MAX),
                                    is_public_demo: false,
                                },
                                now_ms,
                            )?;
                            changed += 1;
                        }
                        InterestChange::OverCap => refused += 1,
                        _ => {}
                    }
                }
                tracing::info!(network = ?net, scripts = req.scripts.len(), watching = changed, refused, "watch request read");
            }
            Action::Unwatch => {
                for script in &req.scripts {
                    let i = Interest {
                        network: net,
                        script: &script.0,
                        ghostkey: &e.ghostkey.0,
                        watching: false,
                        request_ms: req.made_at_ms,
                    };
                    // Only the sender's own interest is withdrawn. The script
                    // stops being scanned when it was the last one;
                    // `remove_watch` never ends an operator's demo script.
                    if self
                        .store
                        .set_interest(&i, self.max_watches_per_ghostkey, now_ms)?
                        == (InterestChange::Withdrawn { last: true })
                    {
                        self.store.remove_watch(net, &script.0)?;
                        changed += 1;
                    }
                }
                tracing::info!(network = ?net, scripts = req.scripts.len(), stopped = changed, "unwatch request read");
            }
        }
        if refused > 0 {
            tracing::warn!(
                refused,
                "a Ghost Key reached its limit of {} watched scripts",
                self.max_watches_per_ghostkey
            );
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// What to do with each message. No I/O, so it is tested directly.
// ---------------------------------------------------------------------------

/// A message from the node, reduced to what the worker acts on.
#[derive(Debug, PartialEq, Eq)]
pub enum Reply {
    /// The inbox's state, in answer to a read.
    State(Vec<u8>),
    /// The node positively reports there is no such contract.
    Absent,
    /// The inbox changed.
    Changed,
    Subscribed(bool),
    /// The inbox was PUT.
    Opened,
    /// A request failed. `lost` when the connection itself is gone.
    Failed {
        lost: bool,
        not_found: bool,
    },
    /// Anything else, which needs nothing done.
    Other,
}

impl Reply {
    pub fn from_host(msg: Result<HostResponse, ClientError>) -> Self {
        match msg {
            Ok(HostResponse::ContractResponse(resp)) => match resp {
                ContractResponse::GetResponse { state, .. } => {
                    Reply::State(state.as_ref().to_vec())
                }
                ContractResponse::NotFound { .. } => Reply::Absent,
                ContractResponse::UpdateNotification { .. } => Reply::Changed,
                ContractResponse::SubscribeResponse { subscribed, .. } => {
                    Reply::Subscribed(subscribed)
                }
                ContractResponse::PutResponse { .. } => Reply::Opened,
                _ => Reply::Other,
            },
            Ok(_) => Reply::Other,
            Err(e) => Reply::Failed {
                lost: connection_lost(e.kind()),
                not_found: is_not_found(&e.to_string()),
            },
        }
    }
}

/// Something the worker should do.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    Read,
    Subscribe,
    Open,
    Process(Vec<u8>),
    /// The connection is gone; end the session and reconnect.
    Reconnect,
}

/// The session's bookkeeping between messages.
#[derive(Debug, Default)]
pub struct Driver {
    subscribed: bool,
    /// When the outstanding read was sent, if one is.
    read_sent: Option<Instant>,
    /// A change arrived while a read was outstanding: read again after it.
    reread: bool,
    last_open: Option<Instant>,
}

impl Driver {
    /// The poll timer fired. The first tick is the session's first read.
    pub fn on_tick(&mut self, now: Instant) -> Vec<Step> {
        let mut out = Vec::new();
        self.read(now, &mut out);
        if !self.subscribed {
            out.push(Step::Subscribe);
        }
        out
    }

    pub fn on_reply(&mut self, reply: Reply, now: Instant) -> Vec<Step> {
        let mut out = Vec::new();
        match reply {
            Reply::State(bytes) => {
                self.read_sent = None;
                out.push(Step::Process(bytes));
                if std::mem::take(&mut self.reread) {
                    self.read(now, &mut out);
                }
            }
            // A notification may carry a delta rather than state, so read the
            // state itself rather than guess.
            Reply::Changed | Reply::Opened => self.read(now, &mut out),
            Reply::Subscribed(s) => {
                self.subscribed = s;
                if !s {
                    tracing::warn!(
                        "the node refused a subscription to the request inbox; polling instead"
                    );
                }
            }
            Reply::Absent
            | Reply::Failed {
                not_found: true, ..
            } => {
                self.read_sent = None;
                self.open(now, &mut out);
            }
            Reply::Failed { lost: true, .. } => out.push(Step::Reconnect),
            // A failure cannot be tied to the request it answers, so assume it
            // was the read; at worst the next read is sent early.
            Reply::Failed { .. } => self.read_sent = None,
            Reply::Other => {}
        }
        out
    }

    /// Read now, unless a read is already outstanding: then read once more
    /// when it answers. Notifications arriving in a burst cost one read, not
    /// one each.
    fn read(&mut self, now: Instant, out: &mut Vec<Step>) {
        match self.read_sent {
            Some(sent) if now.duration_since(sent) < READ_TIMEOUT => self.reread = true,
            _ => {
                self.read_sent = Some(now);
                self.reread = false;
                out.push(Step::Read);
            }
        }
    }

    fn open(&mut self, now: Instant, out: &mut Vec<Step>) {
        if self
            .last_open
            .is_none_or(|t| now.duration_since(t) >= REOPEN_INTERVAL)
        {
            self.last_open = Some(now);
            out.push(Step::Open);
        }
    }
}

/// The wait before the next connection attempt, given the last wait and how
/// long the session that just ended lasted. A session that ran for a while
/// was working, so the wait starts again from one second.
pub fn next_backoff(last: Duration, session_lasted: Duration) -> Duration {
    if session_lasted > MAX_BACKOFF {
        Duration::from_secs(1)
    } else {
        (last * 2).clamp(Duration::from_secs(1), MAX_BACKOFF)
    }
}

// ---------------------------------------------------------------------------
// The worker: a connection to the node, and the loop around a pass.
// ---------------------------------------------------------------------------

pub struct InboxWorker {
    ws_url: String,
    code: Arc<ContractCode<'static>>,
    params: InboxParameters,
    key: SigningKey,
    db_path: PathBuf,
    networks: Vec<NetworkConfig>,
}

impl InboxWorker {
    pub fn new(cfg: &BridgeConfig, key: SigningKey, inbox_wasm: Vec<u8>) -> Self {
        let bridge = BridgeId(key.verifying_key().to_bytes());
        InboxWorker {
            ws_url: cfg.freenet_ws.clone(),
            code: Arc::new(ContractCode::from(inbox_wasm)),
            params: InboxParameters::production(bridge),
            key,
            db_path: cfg.database_path.clone(),
            networks: cfg.networks.clone(),
        }
    }

    fn params_bytes(&self) -> Result<Vec<u8>> {
        to_cbor(&self.params).map_err(|e| anyhow!("encoding inbox parameters: {e}"))
    }

    /// This build's inbox WASM under this bridge's production parameters.
    pub fn contract_key(&self) -> Result<ContractKey> {
        Ok(ContractKey::from_params_and_code(
            Parameters::from(self.params_bytes()?),
            self.code.as_ref(),
        ))
    }

    /// Serve the inbox for the life of the process, reconnecting whenever the
    /// connection drops.
    pub async fn run(self) {
        if !self
            .networks
            .iter()
            .any(|n| n.network == BitcoinNetwork::Bitcoin)
        {
            tracing::error!(
                "no Bitcoin mainnet network is configured. The request inbox is dated by \
                 mainnet blocks, so it stays closed and nobody can ask this bridge to watch \
                 anything"
            );
            return;
        }
        match self.contract_key() {
            Ok(k) => tracing::info!(contract = %k.id(), "serving the request inbox"),
            Err(e) => {
                tracing::error!("cannot derive the request inbox's key: {e:#}");
                return;
            }
        }

        let mut backoff = Duration::from_secs(1);
        loop {
            let started = Instant::now();
            if let Err(e) = self.session().await {
                tracing::warn!("request inbox connection ended: {e:#}");
            }
            backoff = next_backoff(backoff, started.elapsed());
            tokio::time::sleep(backoff).await;
        }
    }

    /// One connection's worth of serving. Returns only with an error.
    async fn session(&self) -> Result<()> {
        let (stream, _) = tokio_tungstenite::connect_async(&self.ws_url)
            .await
            .with_context(|| format!("connecting to the Freenet node at {}", self.ws_url))?;
        let mut api = WebApi::start(stream);
        let store = Store::open(&self.db_path)?;
        let observed: Vec<BitcoinNetwork> = self.networks.iter().map(|n| n.network).collect();
        let deep: HashMap<BitcoinNetwork, u32> = self
            .networks
            .iter()
            .map(|n| (n.network, n.deep_confirmations))
            .collect();
        let processor = Processor {
            params: &self.params,
            key: &self.key,
            store: &store,
            observed: &observed,
            max_watches_per_ghostkey: MAX_WATCHES_PER_GHOSTKEY,
            deep_confirmations: &deep,
            floor_hold_until: Some(
                Instant::now() + std::time::Duration::from_millis(FLOOR_HOLD_MS as u64),
            ),
            lag_warned: Default::default(),
        };
        let key = self.contract_key()?;
        let mut session = Session {
            chains: HashMap::new(),
            sync: SyncWatch::default(),
            quiet: QuietCache::default(),
        };

        let mut driver = Driver::default();
        let mut poll = tokio::time::interval(POLL_INTERVAL);
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let steps = tokio::select! {
                _ = poll.tick() => driver.on_tick(Instant::now()),
                msg = api.recv() => driver.on_reply(Reply::from_host(msg), Instant::now()),
            };
            for step in steps {
                match step {
                    Step::Read => send(&mut api, read(key)).await?,
                    Step::Subscribe => {
                        send(
                            &mut api,
                            ContractRequest::Subscribe {
                                key: key.into(),
                                summary: None,
                            },
                        )
                        .await?
                    }
                    Step::Open => self.open(&mut api, &mut session, &store).await?,
                    Step::Process(bytes) => {
                        self.on_state(&mut api, key, &processor, &mut session, &bytes)
                            .await?
                    }
                    Step::Reconnect => return Err(anyhow!("the node closed the connection")),
                }
            }
        }
    }

    async fn on_state(
        &self,
        api: &mut WebApi,
        key: ContractKey,
        processor: &Processor<'_>,
        session: &mut Session,
        bytes: &[u8],
    ) -> Result<()> {
        let tips = session.tips(&self.networks);
        let held = floor_held(processor.floor_hold_until);
        let fingerprint = QuietCache::fingerprint(bytes, &tips, held);
        if session.quiet.is_quiet(&fingerprint) {
            return Ok(());
        }
        let state: InboxStateV1 = if bytes.is_empty() {
            InboxStateV1::default()
        } else {
            match from_cbor(bytes) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("the request inbox holds state this build cannot decode: {e}");
                    return Ok(());
                }
            }
        };
        let pass = match processor.pass(&state, &tips, now_ms()) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("request inbox pass failed: {e:#}");
                return Ok(());
            }
        };
        session
            .quiet
            .after_pass(fingerprint, !pass.delta.is_empty() || pass.gated);
        if pass.acted > 0 {
            tracing::info!(acted = pass.acted, "read the request inbox");
        }
        if !pass.delta.is_empty() {
            let bytes =
                to_cbor(&pass.delta).map_err(|e| anyhow!("encoding an inbox delta: {e}"))?;
            send(
                api,
                ContractRequest::Update {
                    key,
                    data: UpdateData::Delta(StateDelta::from(bytes)),
                },
            )
            .await?;
        }
        Ok(())
    }

    /// PUT the inbox with its first floor. Nothing is admitted before a floor
    /// exists, so until this runs nobody can write to it. See
    /// [`opening_floor`] for which floor.
    async fn open(&self, api: &mut WebApi, session: &mut Session, store: &Store) -> Result<()> {
        let Some(tip) = session.tips(&self.networks).mainnet() else {
            tracing::warn!("cannot open the request inbox: the Bitcoin mainnet tip is unreadable");
            return Ok(());
        };
        let state = InboxStateV1 {
            floor: Some(SignedFloor::sign(
                &self.key,
                opening_floor(store.signed_floor()?, tip),
            )),
            ..Default::default()
        };
        let contract = ContractContainer::from(ContractWasmAPIVersion::V1(WrappedContract::new(
            self.code.clone(),
            Parameters::from(self.params_bytes()?),
        )));
        let state = to_cbor(&state).map_err(|e| anyhow!("encoding the inbox state: {e}"))?;
        tracing::info!("opening the request inbox");
        send(
            api,
            ContractRequest::Put {
                contract,
                state: WrappedState::new(state),
                related_contracts: Default::default(),
                subscribe: true,
                blocking_subscribe: false,
            },
        )
        .await
    }
}

/// Whether `e` is SQLite reporting the database busy past its timeout: a
/// fault of the database, not of whatever row was being written.
fn is_busy(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        matches!(
            c.downcast_ref::<rusqlite::Error>(),
            Some(rusqlite::Error::SqliteFailure(f, _)) if f.code == rusqlite::ErrorCode::DatabaseBusy
        )
    })
}

/// The floor to open the inbox with.
///
/// A node answers NotFound when it has lost the inbox, after a restart or a
/// wiped store, while other peers may still hold it. Opening at the tip's
/// floor would then raise the floor past every request sent while it was
/// away, and the higher floor wins every merge. So a bridge that has signed a
/// floor before opens at that one, and passes raise it once the hold is over.
pub fn opening_floor(signed: Option<u32>, mainnet_tip: u32) -> u32 {
    signed.unwrap_or(mainnet_tip.saturating_sub(FLOOR_LAG_BLOCKS))
}

/// A state's bytes, by hash; every network's tip it was read against, since
/// whether a watch may end depends on its own network's tip; and whether the
/// floor was held, so the first pass after the hold is not passed over.
pub type Fingerprint = ([u8; 32], Vec<(BitcoinNetwork, u32)>, bool);

/// Which state needs no processing again.
///
/// Only a pass that had nothing to send and held nothing back (see
/// [`Pass::gated`]) is remembered. One that sent
/// removals or a floor may have had them refused after sending, so its state
/// is processed again, and they are sent again, until a pass finds nothing
/// left to send. Processing a settled state again would cost an RSA check per
/// certificate for nothing.
#[derive(Debug, Default)]
pub struct QuietCache(Option<Fingerprint>);

impl QuietCache {
    pub fn fingerprint(bytes: &[u8], tips: &Tips, held: bool) -> Fingerprint {
        let mut t: Vec<(BitcoinNetwork, u32)> =
            tips.by_network.iter().map(|(n, h)| (*n, *h)).collect();
        t.sort();
        (*blake3::hash(bytes).as_bytes(), t, held)
    }

    pub fn is_quiet(&self, fp: &Fingerprint) -> bool {
        self.0.as_ref() == Some(fp)
    }

    pub fn after_pass(&mut self, fp: Fingerprint, sent_something: bool) {
        self.0 = if sent_something { None } else { Some(fp) };
    }
}

/// What one connection keeps between messages.
struct Session {
    /// A Bitcoin Core client per network, made once and remade after a
    /// failure.
    chains: HashMap<BitcoinNetwork, ChainClient>,
    quiet: QuietCache,
    sync: SyncWatch,
}

impl Session {
    /// Read each observed network's tip.
    ///
    /// Blocking RPC on this worker's runtime, which serves only this worker
    /// and its connection, so the cost is a short stall of its own traffic.
    fn tips(&mut self, networks: &[NetworkConfig]) -> Tips {
        let mut tips = Tips::default();
        for n in networks {
            let client = match self.chains.entry(n.network) {
                std::collections::hash_map::Entry::Occupied(o) => o.into_mut(),
                std::collections::hash_map::Entry::Vacant(v) => match ChainClient::connect(n) {
                    Ok(c) => v.insert(c),
                    Err(e) => {
                        tracing::warn!(network = ?n.network, "cannot reach Bitcoin Core: {e}");
                        continue;
                    }
                },
            };
            match client.sync_status() {
                Ok(s) => {
                    tips.by_network.insert(n.network, s.tip.height);
                    tips.median_time_ms.insert(n.network, s.median_time_ms);
                    if !s.synced {
                        tips.syncing.insert(n.network);
                    }
                }
                Err(e) => {
                    tracing::warn!(network = ?n.network, "cannot read the chain tip: {e}");
                    self.chains.remove(&n.network);
                }
            }
        }
        for n in self.sync.update(&tips.syncing, Instant::now()) {
            tracing::warn!(
                network = ?n,
                "Bitcoin Core has been syncing for ten minutes; no watch ends on this network until it has finished"
            );
        }
        tips
    }
}

fn read(key: ContractKey) -> ContractRequest<'static> {
    ContractRequest::Get {
        key: key.into(),
        return_contract_code: false,
        subscribe: false,
        blocking_subscribe: false,
    }
}

async fn send(api: &mut WebApi, req: ContractRequest<'static>) -> Result<()> {
    api.send(ClientRequest::ContractOp(req))
        .await
        .map_err(|e| anyhow!("sending to the node: {e}"))
}

fn connection_lost(kind: &ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::ChannelClosed
            | ErrorKind::Disconnect
            | ErrorKind::TransportProtocolDisconnect
            | ErrorKind::Shutdown
    )
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use freenet_bitcoin_common::{BlockAnchor, BlockHash};
    use freenet_bitcoin_inbox::test_support::{TestAuthority, TestGhostkey};
    use freenet_bitcoin_inbox::{ByteBuf, InboxRequest, WireEntry};

    use super::*;

    const MAINNET_TIP: u32 = 900_000;
    const SIGNET_TIP: u32 = 200_000;
    /// Where the floor settles for [`MAINNET_TIP`].
    const FLOOR: u32 = MAINNET_TIP - FLOOR_LAG_BLOCKS;
    const OBSERVED: &[BitcoinNetwork] = &[BitcoinNetwork::Bitcoin, BitcoinNetwork::Signet];
    const SIGNET: BitcoinNetwork = BitcoinNetwork::Signet;

    fn authority() -> &'static TestAuthority {
        static A: OnceLock<TestAuthority> = OnceLock::new();
        A.get_or_init(TestAuthority::new)
    }

    fn ghostkeys() -> &'static [TestGhostkey] {
        static G: OnceLock<Vec<TestGhostkey>> = OnceLock::new();
        G.get_or_init(|| (0..3).map(|_| authority().mint()).collect())
    }

    fn bridge_key() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    fn bridge() -> BridgeId {
        BridgeId(bridge_key().verifying_key().to_bytes())
    }

    fn params() -> InboxParameters {
        authority().params(bridge())
    }

    fn tips() -> Tips {
        Tips {
            by_network: HashMap::from([
                (BitcoinNetwork::Bitcoin, MAINNET_TIP),
                (SIGNET, SIGNET_TIP),
            ]),
            median_time_ms: HashMap::from([
                (BitcoinNetwork::Bitcoin, i64::MAX),
                (SIGNET, i64::MAX),
            ]),
            ..Default::default()
        }
    }

    fn request(action: Action, script: &[u8], made_at_ms: u64) -> InboxRequest {
        InboxRequest {
            action,
            network: SIGNET,
            scripts: vec![ByteBuf(script.to_vec())],
            scan_from_height: None,
            made_at_ms,
        }
    }

    fn entry(gk: &TestGhostkey, height: u32, req: &InboxRequest) -> WireEntry {
        gk.request(bridge(), height, req)
    }

    fn inbox(floor: u32, entries: Vec<WireEntry>) -> InboxStateV1 {
        let mut s = InboxStateV1::default();
        s.apply_delta(
            &params(),
            &InboxDelta {
                floor: Some(SignedFloor::sign(&bridge_key(), floor)),
                entries,
                removals: vec![],
            },
        )
        .unwrap();
        s
    }

    fn try_run_held(
        store: &Store,
        state: &InboxStateV1,
        tips: &Tips,
        cap: usize,
        now_ms: i64,
        floor_hold_until: Option<Instant>,
    ) -> Result<Pass> {
        let params = params();
        let key = bridge_key();
        let deep = HashMap::from([(BitcoinNetwork::Bitcoin, 6), (SIGNET, 6)]);
        Processor {
            params: &params,
            key: &key,
            store,
            observed: OBSERVED,
            max_watches_per_ghostkey: cap,
            deep_confirmations: &deep,
            floor_hold_until,
            lag_warned: Default::default(),
        }
        .pass(state, tips, now_ms)
    }

    fn try_run(
        store: &Store,
        state: &InboxStateV1,
        tips: &Tips,
        cap: usize,
        now_ms: i64,
    ) -> Result<Pass> {
        try_run_held(store, state, tips, cap, now_ms, None)
    }

    /// Entries a pass removes, across its batches.
    fn removed(pass: &Pass) -> usize {
        pass.delta.removals.iter().map(RemovalBatch::len).sum()
    }

    fn run_with(store: &Store, state: &InboxStateV1, tips: &Tips, cap: usize) -> Pass {
        try_run(store, state, tips, cap, 0).unwrap()
    }

    fn run_at(store: &Store, state: &InboxStateV1, tips: &Tips, now_ms: i64) -> Pass {
        try_run(store, state, tips, MAX_WATCHES_PER_GHOSTKEY, now_ms).unwrap()
    }

    fn run(store: &Store, state: &InboxStateV1, tips: &Tips) -> Pass {
        run_with(store, state, tips, MAX_WATCHES_PER_GHOSTKEY)
    }

    fn watched(store: &Store) -> Vec<Vec<u8>> {
        store
            .watched(SIGNET)
            .unwrap()
            .into_iter()
            .map(|w| w.script_pubkey)
            .collect()
    }

    // --- one pass ----------------------------------------------------------------

    #[test]
    fn a_watch_request_is_acted_on_and_removed() {
        let store = Store::open_in_memory().unwrap();
        let state = inbox(
            FLOOR,
            vec![entry(
                &ghostkeys()[0],
                FLOOR + 1,
                &request(Action::Watch, b"spk", 1),
            )],
        );
        let pass = run(&store, &state, &tips());
        assert_eq!(pass.acted, 1);
        assert_eq!(watched(&store), vec![b"spk".to_vec()]);

        // The inbox accepts what the bridge sends back, and it removes the entry.
        let mut after = state.clone();
        after.apply_delta(&params(), &pass.delta).unwrap();
        assert!(after.entries.is_empty());
        assert_eq!(after.removals.len(), 1);
        after.verify(&params()).unwrap();
    }

    /// A second pass reads a new entry at a height already read at, and signs
    /// one batch naming both: it covers the first, which the inbox drops.
    #[test]
    fn one_batch_per_height_names_everything_read_there_and_replaces_the_last() {
        let store = Store::open_in_memory().unwrap();
        let (a, b) = (&ghostkeys()[0], &ghostkeys()[1]);
        let wa = entry(a, FLOOR + 1, &request(Action::Watch, b"a", 1));
        let wb = entry(b, FLOOR + 1, &request(Action::Watch, b"b", 1));
        let mut state = inbox(FLOOR, vec![wa]);
        let first = run(&store, &state, &tips());
        state.apply_delta(&params(), &first.delta).unwrap();

        state
            .apply_delta(&params(), &InboxDelta::submission(None, wb))
            .unwrap();
        let second = run(&store, &state, &tips());
        assert_eq!(second.delta.removals.len(), 1);
        assert_eq!(removed(&second), 2);
        assert!(first.delta.removals[0].covered_by(&second.delta.removals[0]));
        state.apply_delta(&params(), &second.delta).unwrap();
        assert!(state.entries.is_empty());
        assert_eq!(
            state.removals.len(),
            1,
            "the first batch is covered and goes"
        );
        state.verify(&params()).unwrap();
    }

    /// Filled to one short of the budget with entries already read; the pass
    /// reads one more and leaves the other waiting, until the floor passes the
    /// old removals and frees the budget.
    #[test]
    fn past_the_removal_budget_reading_waits_for_the_floor() {
        let store = Store::open_in_memory().unwrap();
        store
            .with_transaction(|| {
                for i in 0..(REMOVAL_BUDGET - 1) as u64 {
                    let mut k = [0u8; 32];
                    k[..8].copy_from_slice(&i.to_be_bytes());
                    // Many senders, each within its share.
                    store.mark_handled(&k, FLOOR + 1, &k)?;
                }
                Ok(())
            })
            .unwrap();
        let (a, b) = (&ghostkeys()[0], &ghostkeys()[1]);
        let two = vec![
            entry(a, FLOOR + 2, &request(Action::Watch, b"a", 1)),
            entry(b, FLOOR + 2, &request(Action::Watch, b"b", 1)),
        ];
        let pass = run(&store, &inbox(FLOOR, two.clone()), &tips());
        assert_eq!((pass.acted, pass.deferred), (1, 1));
        assert_eq!(watched(&store).len(), 1);
        assert_eq!(removed(&pass), 1, "only what was read is removed");

        let pass = run(&store, &inbox(FLOOR + 2, two), &tips());
        assert_eq!((pass.acted, pass.deferred), (1, 0));
        assert_eq!(watched(&store).len(), 2);
    }

    /// One Ghost Key at its share: its next request waits, and another
    /// sender's is read.
    #[test]
    fn one_ghostkey_cannot_spend_the_removal_budget_for_everyone() {
        let store = Store::open_in_memory().unwrap();
        let (a, b) = (&ghostkeys()[0], &ghostkeys()[1]);
        store
            .with_transaction(|| {
                for i in 0..REMOVAL_SHARE_PER_GHOSTKEY as u64 {
                    let mut k = [0u8; 32];
                    k[..8].copy_from_slice(&i.to_be_bytes());
                    store.mark_handled(&k, FLOOR + 1, &a.id().0)?;
                }
                Ok(())
            })
            .unwrap();
        let from_a = entry(a, FLOOR + 2, &request(Action::Watch, b"a", 1));
        let from_b = entry(b, FLOOR + 2, &request(Action::Watch, b"b", 1));
        let pass = run(&store, &inbox(FLOOR, vec![from_a, from_b]), &tips());
        assert_eq!((pass.acted, pass.deferred), (1, 1));
        assert_eq!(watched(&store), vec![b"b".to_vec()]);
    }

    #[test]
    fn the_floor_is_held_for_a_while_after_connecting_and_then_follows_the_tip() {
        let store = Store::open_in_memory().unwrap();
        let state = inbox(FLOOR - 10, vec![]);
        let held = try_run_held(
            &store,
            &state,
            &tips(),
            3,
            1_000,
            Some(Instant::now() + Duration::from_secs(3600)),
        )
        .unwrap();
        assert!(held.delta.floor.is_none());
        let moved = try_run_held(&store, &state, &tips(), 3, 2_000, Some(Instant::now())).unwrap();
        assert_eq!(moved.delta.floor.map(|f| f.height), Some(FLOOR));
    }

    // --- how long a watch lasts ------------------------------------------------

    const HOUR: i64 = 3_600_000;
    const T0: i64 = 1_700_000_000_000;

    fn watch_at(store: &Store, gk: &TestGhostkey, made_at_ms: u64, now_ms: i64) {
        let w = entry(gk, FLOOR + 1, &request(Action::Watch, b"spk", made_at_ms));
        run_at(store, &inbox(FLOOR, vec![w]), &tips(), now_ms);
    }

    /// The observer has scanned signet up to its tip.
    fn caught_up(store: &Store) {
        store
            .set_checkpoint(
                SIGNET,
                &BlockAnchor {
                    height: SIGNET_TIP,
                    hash: BlockHash([0; 32]),
                },
            )
            .unwrap();
    }

    /// A pass over an empty inbox, with the observer caught up.
    fn tick(store: &Store, tips: &Tips, now_ms: i64) {
        caught_up(store);
        run_at(store, &inbox(FLOOR, vec![]), tips, now_ms);
    }

    fn payment(store: &Store, height: Option<u32>) {
        store
            .record_output(
                SIGNET,
                b"spk",
                &[7u8; 32],
                0,
                10_000,
                height.map(|h| (h, BlockHash([1; 32]))),
            )
            .unwrap();
    }

    #[test]
    fn a_watch_ends_a_day_after_it_was_last_asked_for() {
        let store = Store::open_in_memory().unwrap();
        watch_at(&store, &ghostkeys()[0], 1, T0);
        tick(&store, &tips(), T0 + 23 * HOUR);
        assert_eq!(watched(&store), vec![b"spk".to_vec()]);
        tick(&store, &tips(), T0 + 25 * HOUR);
        assert!(watched(&store).is_empty());
    }

    #[test]
    fn a_watch_sent_again_starts_the_day_again() {
        let store = Store::open_in_memory().unwrap();
        let a = &ghostkeys()[0];
        watch_at(&store, a, 1, T0);
        watch_at(&store, a, 2, T0 + 20 * HOUR);
        tick(&store, &tips(), T0 + 25 * HOUR);
        assert_eq!(watched(&store), vec![b"spk".to_vec()]);
        tick(&store, &tips(), T0 + 45 * HOUR);
        assert!(watched(&store).is_empty());
    }

    /// Ended by running out, it is a withdrawal like any other: a delayed copy
    /// of the Watch it ended cannot bring it back, a newer Watch can.
    #[test]
    fn a_watch_that_ran_out_comes_back_only_for_a_newer_request() {
        let store = Store::open_in_memory().unwrap();
        let a = &ghostkeys()[0];
        watch_at(&store, a, 10, T0);
        tick(&store, &tips(), T0 + 25 * HOUR);
        watch_at(&store, a, 5, T0 + 26 * HOUR);
        assert!(
            watched(&store).is_empty(),
            "older than the one that ran out"
        );
        watch_at(&store, a, 20, T0 + 26 * HOUR);
        assert_eq!(watched(&store), vec![b"spk".to_vec()]);
    }

    #[test]
    fn a_watch_whose_payment_is_still_being_buried_outlives_its_day() {
        // Five deep, one short of `deep_confirmations`.
        let store = Store::open_in_memory().unwrap();
        watch_at(&store, &ghostkeys()[0], 1, T0);
        payment(&store, Some(SIGNET_TIP - 4));
        tick(&store, &tips(), T0 + 25 * HOUR);
        assert_eq!(watched(&store), vec![b"spk".to_vec()]);

        // Six deep: buried, and the watch ends.
        let store = Store::open_in_memory().unwrap();
        watch_at(&store, &ghostkeys()[0], 1, T0);
        payment(&store, Some(SIGNET_TIP - 5));
        tick(&store, &tips(), T0 + 25 * HOUR);
        assert!(watched(&store).is_empty());

        // Moved out of its block by a reorg and not seen again.
        let store = Store::open_in_memory().unwrap();
        watch_at(&store, &ghostkeys()[0], 1, T0);
        payment(&store, None);
        tick(&store, &tips(), T0 + 25 * HOUR);
        assert_eq!(watched(&store), vec![b"spk".to_vec()]);
    }

    #[test]
    fn nothing_ends_on_a_network_whose_tip_cannot_be_read() {
        let store = Store::open_in_memory().unwrap();
        watch_at(&store, &ghostkeys()[0], 1, T0);
        let mut no_signet = tips();
        no_signet.by_network.remove(&SIGNET);
        tick(&store, &no_signet, T0 + 25 * HOUR);
        assert_eq!(watched(&store), vec![b"spk".to_vec()]);
    }

    #[test]
    fn a_watch_from_before_the_inbox_never_runs_out() {
        let store = Store::open_in_memory().unwrap();
        store
            .add_watch(
                &WatchedScript {
                    network: SIGNET,
                    script_pubkey: b"spk".to_vec(),
                    scan_from_height: 0,
                    is_public_demo: false,
                },
                0,
            )
            .unwrap();
        watch_at(&store, &ghostkeys()[0], 1, T0);
        tick(&store, &tips(), T0 + 25 * HOUR);
        assert_eq!(watched(&store), vec![b"spk".to_vec()]);
    }

    #[test]
    fn an_unwatch_withdraws_only_its_senders_interest() {
        let store = Store::open_in_memory().unwrap();
        let (a, b) = (&ghostkeys()[0], &ghostkeys()[1]);
        run(
            &store,
            &inbox(
                FLOOR,
                vec![
                    entry(a, FLOOR + 1, &request(Action::Watch, b"spk", 1)),
                    entry(b, FLOOR + 1, &request(Action::Watch, b"spk", 1)),
                ],
            ),
            &tips(),
        );
        run(
            &store,
            &inbox(
                FLOOR,
                vec![entry(a, FLOOR + 2, &request(Action::Unwatch, b"spk", 2))],
            ),
            &tips(),
        );
        assert_eq!(watched(&store), vec![b"spk".to_vec()], "b still wants it");
        run(
            &store,
            &inbox(
                FLOOR,
                vec![entry(b, FLOOR + 2, &request(Action::Unwatch, b"spk", 2))],
            ),
            &tips(),
        );
        assert!(watched(&store).is_empty());
    }

    /// Same height, so the heights cannot order them, and read in separate
    /// passes in the reverse of the order they were made.
    #[test]
    fn a_later_unwatch_wins_whatever_order_it_is_read_in() {
        let store = Store::open_in_memory().unwrap();
        let a = &ghostkeys()[0];
        let w = entry(a, FLOOR + 1, &request(Action::Watch, b"spk", 10));
        let u = entry(a, FLOOR + 1, &request(Action::Unwatch, b"spk", 20));
        run(&store, &inbox(FLOOR, vec![u.clone()]), &tips());
        run(&store, &inbox(FLOOR, vec![w.clone()]), &tips());
        assert!(
            watched(&store).is_empty(),
            "read second, the Watch is older"
        );

        let store = Store::open_in_memory().unwrap();
        run(&store, &inbox(FLOOR, vec![w, u]), &tips());
        assert!(watched(&store).is_empty(), "read together, likewise");
    }

    #[test]
    fn a_watch_whose_removal_was_lost_is_removed_again_not_acted_on_again() {
        let store = Store::open_in_memory().unwrap();
        let w = entry(
            &ghostkeys()[0],
            FLOOR + 1,
            &request(Action::Watch, b"spk", 1),
        );
        run(&store, &inbox(FLOOR, vec![w.clone()]), &tips());
        let pass = run(&store, &inbox(FLOOR, vec![w]), &tips());
        assert_eq!(pass.acted, 0);
        assert_eq!(removed(&pass), 1, "the lost removal is sent again");
    }

    #[test]
    fn a_request_the_bridge_cannot_serve_is_removed_without_effect() {
        let store = Store::open_in_memory().unwrap();
        let (a, b) = (&ghostkeys()[0], &ghostkeys()[1]);

        let mut regtest = request(Action::Watch, b"spk", 1);
        regtest.network = BitcoinNetwork::Regtest;

        // Someone copies another sender's sealed request into an entry of
        // their own. It was sealed for `a`'s entry, so it does not open here.
        let sealed_for_a = freenet_bitcoin_inbox::seal::seal(
            &bridge(),
            &a.id(),
            FLOOR + 1,
            &request(Action::Watch, b"copied", 1),
        )
        .unwrap();
        let copied = b.entry(bridge(), FLOOR + 1, sealed_for_a);

        let state = inbox(FLOOR, vec![entry(a, FLOOR + 1, &regtest), copied]);
        let pass = run(&store, &state, &tips());
        assert!(watched(&store).is_empty());
        assert!(store.watched(BitcoinNetwork::Regtest).unwrap().is_empty());
        assert_eq!(removed(&pass), 2, "both are removed");
    }

    /// The inbox is dated by mainnet whatever network a request is for, so a
    /// request held back for another network's tip would hold the floor while
    /// senders' dates moved on, until the window closed the inbox to everyone.
    #[test]
    fn a_watch_is_served_even_when_its_networks_tip_is_unreadable() {
        let store = Store::open_in_memory().unwrap();
        let state = inbox(
            FLOOR,
            vec![entry(
                &ghostkeys()[0],
                FLOOR + 1,
                &request(Action::Watch, b"spk", 1),
            )],
        );
        let mut no_signet = tips();
        no_signet.by_network.remove(&SIGNET);
        let pass = run(&store, &state, &no_signet);
        assert_eq!(pass.acted, 1);
        assert_eq!(watched(&store), vec![b"spk".to_vec()]);
        assert_eq!(removed(&pass), 1);
        assert_eq!(
            store.watched(SIGNET).unwrap()[0].scan_from_height,
            u32::MAX,
            "no tip or checkpoint was known, so no height is recorded"
        );
    }

    /// With the tip unreadable, the height recorded is where the scan has got
    /// to, rather than no height at all.
    #[test]
    fn a_watch_with_its_networks_tip_unreadable_records_the_checkpoint() {
        let store = Store::open_in_memory().unwrap();
        store
            .set_checkpoint(
                SIGNET,
                &BlockAnchor {
                    height: SIGNET_TIP - 3,
                    hash: BlockHash([0; 32]),
                },
            )
            .unwrap();
        let mut no_signet = tips();
        no_signet.by_network.remove(&SIGNET);
        run(
            &store,
            &inbox(
                FLOOR,
                vec![entry(
                    &ghostkeys()[0],
                    FLOOR + 1,
                    &request(Action::Watch, b"spk", 1),
                )],
            ),
            &no_signet,
        );
        assert_eq!(
            store.watched(SIGNET).unwrap()[0].scan_from_height,
            SIGNET_TIP - 3
        );
    }

    /// Checked here because the per-entry checks do not cover the window.
    #[test]
    fn an_entry_above_the_window_is_not_acted_on() {
        let store = Store::open_in_memory().unwrap();
        let mut state = inbox(FLOOR, vec![]);
        let far = entry(
            &ghostkeys()[0],
            FLOOR + WINDOW_BLOCKS + 5,
            &request(Action::Watch, b"spk", 1),
        );
        state
            .certificates
            .insert(far.entry.cert, far.certificate_pem.clone());
        state.entries.insert(far.entry.key(), far.entry.clone());
        let pass = run(&store, &state, &tips());
        assert_eq!(pass.acted, 0);
        assert!(watched(&store).is_empty());
    }

    #[test]
    fn the_floor_follows_the_mainnet_tip_and_never_falls() {
        let store = Store::open_in_memory().unwrap();
        let pass = run(&store, &inbox(FLOOR - 50, vec![]), &tips());
        assert_eq!(pass.delta.floor.map(|f| f.height), Some(FLOOR));

        let mut stale = tips();
        stale
            .by_network
            .insert(BitcoinNetwork::Bitcoin, MAINNET_TIP - 20);
        let pass = run(&store, &inbox(FLOOR, vec![]), &stale);
        assert!(
            pass.delta.is_empty(),
            "a stale tip must not lower the floor, and a settled inbox is sent nothing"
        );
    }

    /// A copy of the inbox from before this bridge's last floor, served by a
    /// peer that missed it. Its entries were dealt with when that floor was
    /// set, and the record of them may be gone.
    #[test]
    fn a_stale_copy_below_a_floor_this_bridge_signed_is_not_acted_on() {
        let store = Store::open_in_memory().unwrap();
        store.set_signed_floor(FLOOR + 5).unwrap();
        let old = entry(
            &ghostkeys()[0],
            FLOOR + 1,
            &request(Action::Watch, b"spk", 1),
        );
        let pass = run(&store, &inbox(FLOOR, vec![old]), &tips());
        assert_eq!(pass.acted, 0);
        assert!(watched(&store).is_empty());
        assert_eq!(
            pass.delta.floor.map(|f| f.height),
            Some(FLOOR + 5),
            "the higher floor is sent to the copy"
        );
    }

    /// Until freenet-bitcoin#7, a request cannot move the scan cursor at all:
    /// every way this PR tried to let it do so raced the observer, which is
    /// the only thing that should move it.
    #[test]
    fn a_watchs_rescan_hint_moves_no_cursor() {
        let store = Store::open_in_memory().unwrap();
        // Behind the tip, so recording the tip and recording the checkpoint
        // differ.
        store
            .set_checkpoint(
                SIGNET,
                &BlockAnchor {
                    height: SIGNET_TIP - 3,
                    hash: BlockHash([0; 32]),
                },
            )
            .unwrap();
        let mut from_genesis = request(Action::Watch, b"spk", 1);
        from_genesis.scan_from_height = Some(0);
        run(
            &store,
            &inbox(
                FLOOR,
                vec![entry(&ghostkeys()[0], FLOOR + 1, &from_genesis)],
            ),
            &tips(),
        );
        assert_eq!(
            store.checkpoint(SIGNET).unwrap().unwrap().height,
            SIGNET_TIP - 3
        );
        assert_eq!(
            store.watched(SIGNET).unwrap()[0].scan_from_height,
            SIGNET_TIP,
            "watched from where the tip was"
        );
    }

    #[test]
    fn an_unwatch_from_someone_who_never_asked_ends_nothing() {
        let store = Store::open_in_memory().unwrap();
        run(
            &store,
            &inbox(
                FLOOR,
                vec![entry(
                    &ghostkeys()[0],
                    FLOOR + 1,
                    &request(Action::Watch, b"spk", 1),
                )],
            ),
            &tips(),
        );
        let stranger = entry(
            &ghostkeys()[2],
            FLOOR + 1,
            &request(Action::Unwatch, b"spk", 5),
        );
        run(&store, &inbox(FLOOR, vec![stranger]), &tips());
        assert_eq!(watched(&store), vec![b"spk".to_vec()]);
    }

    #[test]
    fn a_watch_from_before_the_inbox_outlives_its_inbox_watchers() {
        let store = Store::open_in_memory().unwrap();
        store
            .add_watch(
                &WatchedScript {
                    network: SIGNET,
                    script_pubkey: b"spk".to_vec(),
                    scan_from_height: 0,
                    is_public_demo: false,
                },
                0,
            )
            .unwrap();
        let a = &ghostkeys()[0];
        run(
            &store,
            &inbox(
                FLOOR,
                vec![entry(a, FLOOR + 1, &request(Action::Watch, b"spk", 1))],
            ),
            &tips(),
        );
        run(
            &store,
            &inbox(
                FLOOR,
                vec![entry(a, FLOOR + 2, &request(Action::Unwatch, b"spk", 2))],
            ),
            &tips(),
        );
        assert_eq!(watched(&store), vec![b"spk".to_vec()]);
    }

    #[test]
    fn a_ghostkey_cannot_grow_the_watch_list_past_its_limit() {
        let store = Store::open_in_memory().unwrap();
        let mut req = request(Action::Watch, b"s1", 1);
        req.scripts = (0..5u8).map(|i| ByteBuf(vec![i; 20])).collect();
        run_with(
            &store,
            &inbox(FLOOR, vec![entry(&ghostkeys()[0], FLOOR + 1, &req)]),
            &tips(),
            3,
        );
        assert_eq!(watched(&store).len(), 3);
    }

    /// Every other test runs at time zero, where the day's memory of a
    /// withdrawal can never lapse. This one moves the clock.
    #[test]
    fn a_withdrawal_is_remembered_for_a_day_and_then_forgotten() {
        const HOUR_MS: i64 = 3_600_000;
        let t0 = 1_700_000_000_000i64;
        let store = Store::open_in_memory().unwrap();
        let a = &ghostkeys()[0];
        let unwatch = entry(a, FLOOR + 1, &request(Action::Unwatch, b"spk", 20));
        run_at(&store, &inbox(FLOOR, vec![unwatch]), &tips(), t0);

        let older_watch = entry(a, FLOOR + 1, &request(Action::Watch, b"spk", 10));
        run_at(
            &store,
            &inbox(FLOOR, vec![older_watch]),
            &tips(),
            t0 + HOUR_MS,
        );
        assert!(
            watched(&store).is_empty(),
            "within the day, the later withdrawal outranks it"
        );

        let resent = entry(a, FLOOR + 1, &request(Action::Watch, b"spk", 10));
        run_at(
            &store,
            &inbox(FLOOR, vec![resent]),
            &tips(),
            t0 + 25 * HOUR_MS,
        );
        assert_eq!(
            watched(&store),
            vec![b"spk".to_vec()],
            "a day later the withdrawal is forgotten"
        );
    }

    /// The rollback that matters is the one inside a real pass: a Watch that
    /// fails on its second script must leave no trace of its first, or the
    /// retry would find that interest recorded and skip the script.
    #[test]
    fn a_store_failure_part_way_through_a_watch_leaves_nothing_half_done() {
        let store = Store::open_in_memory().unwrap();
        store
            .execute_for_test(
                "CREATE TRIGGER boom BEFORE INSERT ON watched_scripts
                 WHEN NEW.script_pubkey = X'626f6f6d'
                 BEGIN SELECT RAISE(ABORT, 'boom'); END;",
            )
            .unwrap();
        let mut req = request(Action::Watch, b"fine", 1);
        req.scripts = vec![ByteBuf(b"fine".to_vec()), ByteBuf(b"boom".to_vec())];
        let w = entry(&ghostkeys()[0], FLOOR + 1, &req);
        let state = inbox(FLOOR, vec![w.clone()]);

        assert!(try_run(&store, &state, &tips(), MAX_WATCHES_PER_GHOSTKEY, 0).is_err());
        assert!(watched(&store).is_empty());
        assert!(!store.is_handled(&w.entry.key().0).unwrap());

        store.execute_for_test("DROP TRIGGER boom").unwrap();
        let pass = run(&store, &state, &tips());
        assert_eq!(pass.acted, 1);
        assert_eq!(watched(&store).len(), 2, "both scripts, on the retry");
    }

    /// The bridge's rules and the contract its node runs can disagree, as
    /// when one is upgraded before the other. A state the bridge would not
    /// accept as a whole must still have its good entries served.
    #[test]
    fn entries_are_served_even_when_the_state_fails_verification_as_a_whole() {
        let store = Store::open_in_memory().unwrap();
        let g = &ghostkeys()[0];
        let es: Vec<WireEntry> = [b"a", b"b", b"c"]
            .iter()
            .enumerate()
            .map(|(i, s)| entry(g, FLOOR + 1, &request(Action::Watch, *s, i as u64 + 1)))
            .collect();
        let mut state = inbox(FLOOR, es[..2].to_vec());
        state.entries.insert(es[2].entry.key(), es[2].entry.clone());
        assert!(
            state.verify(&params()).is_err(),
            "three records for one Ghost Key"
        );
        let pass = run(&store, &state, &tips());
        assert_eq!(pass.acted, 3);
        assert_eq!(watched(&store).len(), 3);
    }

    #[test]
    fn a_floor_read_back_from_the_inbox_is_remembered() {
        let store = Store::open_in_memory().unwrap();
        let mut no_mainnet = tips();
        no_mainnet.by_network.remove(&BitcoinNetwork::Bitcoin);
        run(&store, &inbox(FLOOR + 5, vec![]), &no_mainnet);
        assert_eq!(store.signed_floor().unwrap(), Some(FLOOR + 5));
    }

    #[test]
    fn a_state_is_passed_over_only_after_a_pass_that_sent_nothing() {
        let mut q = QuietCache::default();
        let fp = QuietCache::fingerprint(b"state", &tips(), false);
        assert!(!q.is_quiet(&fp));
        q.after_pass(fp.clone(), true);
        assert!(
            !q.is_quiet(&fp),
            "it sent something, which the node may have refused"
        );
        q.after_pass(fp.clone(), false);
        assert!(q.is_quiet(&fp));
        let mut moved = tips();
        moved
            .by_network
            .insert(BitcoinNetwork::Bitcoin, MAINNET_TIP + 1);
        assert!(!q.is_quiet(&QuietCache::fingerprint(b"state", &moved, false)));
        let mut signet_moved = tips();
        signet_moved.by_network.insert(SIGNET, SIGNET_TIP + 1);
        assert!(
            !q.is_quiet(&QuietCache::fingerprint(b"state", &signet_moved, false)),
            "whether a watch may end depends on its own network's tip"
        );
        assert!(
            !q.is_quiet(&QuietCache::fingerprint(b"state", &tips(), true)),
            "the pass that ends the hold must not be passed over"
        );
    }

    #[test]
    fn an_inbox_opened_again_keeps_the_floor_it_had() {
        assert_eq!(opening_floor(Some(FLOOR - 50), MAINNET_TIP), FLOOR - 50);
        assert_eq!(opening_floor(None, MAINNET_TIP), FLOOR);
    }

    /// After downtime the observer is behind: the watch's day is over by the
    /// clock, but blocks from that day have not been scanned for it yet.
    #[test]
    fn a_watch_does_not_end_before_the_observer_has_scanned_its_day() {
        let store = Store::open_in_memory().unwrap();
        watch_at(&store, &ghostkeys()[0], 1, T0);
        store
            .set_checkpoint(
                SIGNET,
                &BlockAnchor {
                    height: SIGNET_TIP - 3,
                    hash: BlockHash([0; 32]),
                },
            )
            .unwrap();
        let pass = run_at(&store, &inbox(FLOOR, vec![]), &tips(), T0 + 25 * HOUR);
        assert_eq!(watched(&store), vec![b"spk".to_vec()]);
        assert!(
            pass.gated,
            "kept for the observer, so not passed over as quiet"
        );
        tick(&store, &tips(), T0 + 26 * HOUR);
        assert!(watched(&store).is_empty());
    }

    #[test]
    fn a_script_another_requester_still_wants_stays_scanned() {
        let store = Store::open_in_memory().unwrap();
        let (a, b) = (&ghostkeys()[0], &ghostkeys()[1]);
        watch_at(&store, a, 1, T0);
        watch_at(&store, b, 1, T0 + 20 * HOUR);
        tick(&store, &tips(), T0 + 25 * HOUR);
        assert_eq!(watched(&store), vec![b"spk".to_vec()], "b still wants it");
        tick(&store, &tips(), T0 + 45 * HOUR);
        assert!(watched(&store).is_empty());
    }

    /// A node that has just connected may not yet hold the Watch that renews
    /// a watch, so nothing ends while the floor is held; and a request
    /// waiting on the budget may be that Watch, so its sender's watches wait
    /// with it, and only its sender's.
    #[test]
    fn a_watch_is_kept_while_the_floor_is_held_or_its_renewal_waits() {
        let store = Store::open_in_memory().unwrap();
        let (owner, other) = (&ghostkeys()[0], &ghostkeys()[2]);
        watch_at(&store, owner, 1, T0);
        run_at(
            &store,
            &inbox(
                FLOOR,
                vec![entry(other, FLOOR + 1, &request(Action::Watch, b"spk2", 1))],
            ),
            &tips(),
            T0,
        );
        caught_up(&store);
        let later = T0 + 25 * HOUR;
        let held = try_run_held(
            &store,
            &inbox(FLOOR, vec![]),
            &tips(),
            MAX_WATCHES_PER_GHOSTKEY,
            later,
            Some(Instant::now() + Duration::from_secs(3600)),
        )
        .unwrap();
        assert!(held.gated, "a held pass is not passed over as quiet");
        assert_eq!(watched(&store).len(), 2, "held");

        store
            .with_transaction(|| {
                for i in 0..REMOVAL_BUDGET as u64 {
                    let mut k = [0xffu8; 32];
                    k[..8].copy_from_slice(&i.to_be_bytes());
                    store.mark_handled(&k, FLOOR + 1, &k)?;
                }
                Ok(())
            })
            .unwrap();
        // The owner's renewal waits on the spent budget.
        let renewal = entry(owner, FLOOR + 1, &request(Action::Watch, b"spk", 2));
        let pass = run_at(&store, &inbox(FLOOR, vec![renewal]), &tips(), later);
        assert_eq!(pass.deferred, 1);
        assert_eq!(
            watched(&store),
            vec![b"spk".to_vec()],
            "the owner's watch waits for its renewal; the other one ends"
        );

        tick(&store, &tips(), later);
        assert!(watched(&store).is_empty());
    }

    #[test]
    fn a_failure_ending_watches_still_sends_the_removals_and_floor() {
        let store = Store::open_in_memory().unwrap();
        store
            .with_transaction(|| {
                store.set_interest(
                    &Interest {
                        network: SIGNET,
                        script: b"spk",
                        ghostkey: &[9u8; 32],
                        watching: true,
                        request_ms: 1,
                    },
                    MAX_WATCHES_PER_GHOSTKEY,
                    T0,
                )?;
                store.add_watch(
                    &WatchedScript {
                        network: SIGNET,
                        script_pubkey: b"spk".to_vec(),
                        scan_from_height: 0,
                        is_public_demo: false,
                    },
                    T0,
                )?;
                Ok(())
            })
            .unwrap();
        caught_up(&store);
        // Fails where ending watches starts, before any one watch is tried.
        store
            .execute_for_test("DROP TABLE chain_checkpoint")
            .unwrap();
        let fresh = entry(
            &ghostkeys()[1],
            FLOOR - 4,
            &request(Action::Watch, b"other", 1),
        );
        let pass = run_at(
            &store,
            &inbox(FLOOR - 5, vec![fresh]),
            &tips(),
            T0 + 25 * HOUR,
        );
        assert_eq!(removed(&pass), 1);
        assert_eq!(pass.delta.floor.map(|f| f.height), Some(FLOOR));
        assert!(pass.gated, "the pass runs again");
        assert!(
            watched(&store).contains(&b"spk".to_vec()),
            "the failed expiry changed nothing"
        );
    }

    /// One watch whose ending fails keeps no other watch from ending. The
    /// failing one comes first, since watches are tried in script order.
    #[test]
    fn one_watch_that_cannot_end_keeps_no_other_from_ending() {
        let store = Store::open_in_memory().unwrap();
        let (a, b) = (&ghostkeys()[0], &ghostkeys()[1]);
        let stuck = entry(a, FLOOR + 1, &request(Action::Watch, b"boom", 1));
        run_at(&store, &inbox(FLOOR, vec![stuck]), &tips(), T0);
        watch_at(&store, b, 1, T0);
        store
            .execute_for_test(
                "CREATE TRIGGER boom BEFORE UPDATE ON script_interests
                 WHEN NEW.script_pubkey = X'626f6f6d'
                 BEGIN SELECT RAISE(ABORT, 'boom'); END;",
            )
            .unwrap();
        caught_up(&store);
        let pass = run_at(&store, &inbox(FLOOR, vec![]), &tips(), T0 + 25 * HOUR);
        assert_eq!(watched(&store), vec![b"boom".to_vec()]);
        assert!(
            pass.gated,
            "the watch that failed is tried again, so the pass is not quiet"
        );
    }

    #[test]
    fn only_a_busy_database_counts_as_a_fault_of_the_database() {
        let busy = rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(5), None);
        assert!(is_busy(
            &anyhow::Error::from(busy).context("ending a watch")
        ));
        let constraint = rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(19), None);
        assert!(!is_busy(&anyhow::Error::from(constraint)));
        assert!(!is_busy(&anyhow!("anything else")));
    }

    /// A database too busy to write fails every watch in turn, so the first
    /// busy failure ends expiry for the pass, on every network, rather than
    /// costing the busy timeout once per watch. Watches are tried mainnet
    /// first, then two on signet: one busy failure is right, two means the
    /// stop reached only its own network, three that nothing stopped.
    #[test]
    fn a_busy_database_stops_expiry_on_every_network() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static BUSY: AtomicUsize = AtomicUsize::new(0);
        fn refuse(attempt: i32) -> bool {
            if attempt == 0 {
                BUSY.fetch_add(1, Ordering::SeqCst);
            }
            false
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bridge.sqlite");
        let store = Store::open(&path).unwrap();
        let (a, b) = (&ghostkeys()[0], &ghostkeys()[1]);
        let mainnet = InboxRequest {
            network: BitcoinNetwork::Bitcoin,
            ..request(Action::Watch, b"spk", 1)
        };
        run_at(
            &store,
            &inbox(FLOOR, vec![entry(a, FLOOR + 1, &mainnet)]),
            &tips(),
            T0,
        );
        watch_at(&store, a, 1, T0);
        watch_at(&store, b, 1, T0);
        caught_up(&store);
        store
            .set_checkpoint(
                BitcoinNetwork::Bitcoin,
                &BlockAnchor {
                    height: MAINNET_TIP,
                    hash: BlockHash([0; 32]),
                },
            )
            .unwrap();

        // Another connection holds the write lock throughout.
        let other = rusqlite::Connection::open(&path).unwrap();
        other.execute_batch("BEGIN IMMEDIATE").unwrap();
        store.busy_handler_for_test(Some(refuse)).unwrap();
        let params = params();
        let key = bridge_key();
        let deep = HashMap::from([(BitcoinNetwork::Bitcoin, 6), (SIGNET, 6)]);
        let processor = Processor {
            params: &params,
            key: &key,
            store: &store,
            observed: OBSERVED,
            max_watches_per_ghostkey: MAX_WATCHES_PER_GHOSTKEY,
            deep_confirmations: &deep,
            floor_hold_until: None,
            lag_warned: Default::default(),
        };
        let lagging = processor
            .expire_watches(&tips(), T0 + 25 * HOUR, &BTreeSet::new())
            .unwrap();
        assert!(lagging, "the watches are tried again next pass");
        assert_eq!(
            BUSY.load(Ordering::SeqCst),
            1,
            "one busy failure, then no more tries"
        );
        other.execute_batch("ROLLBACK").unwrap();
        assert_eq!(watched(&store), vec![b"spk".to_vec()], "nothing ended");
    }

    /// A node syncing after downtime reports as its tip the last block it
    /// has, which the observer may already have scanned.
    #[test]
    fn a_watch_does_not_end_while_its_node_is_still_syncing() {
        let store = Store::open_in_memory().unwrap();
        watch_at(&store, &ghostkeys()[0], 1, T0);
        caught_up(&store);
        let mut syncing = tips();
        syncing.syncing.insert(SIGNET);
        let pass = run_at(&store, &inbox(FLOOR, vec![]), &syncing, T0 + 25 * HOUR);
        assert_eq!(watched(&store), vec![b"spk".to_vec()]);
        assert!(pass.gated, "kept for the node, so not passed over as quiet");
        tick(&store, &tips(), T0 + 25 * HOUR);
        assert!(watched(&store).is_empty());
    }

    /// A reindexing node reports a tip below what the observer scanned
    /// before, and has not fetched the blocks above it again yet.
    #[test]
    fn a_checkpoint_above_the_tip_is_not_caught_up() {
        let store = Store::open_in_memory().unwrap();
        watch_at(&store, &ghostkeys()[0], 1, T0);
        store
            .set_checkpoint(
                SIGNET,
                &BlockAnchor {
                    height: SIGNET_TIP + 5,
                    hash: BlockHash([0; 32]),
                },
            )
            .unwrap();
        let pass = run_at(&store, &inbox(FLOOR, vec![]), &tips(), T0 + 25 * HOUR);
        assert_eq!(watched(&store), vec![b"spk".to_vec()]);
        assert!(pass.gated);
        tick(&store, &tips(), T0 + 26 * HOUR);
        assert!(watched(&store).is_empty());
    }

    #[test]
    fn the_observer_lag_is_reported_when_it_grows_and_not_while_it_shrinks() {
        assert!(lag_grew(None, Some(10)), "newly lagging");
        assert!(lag_grew(Some(Some(10)), Some(11)));
        assert!(!lag_grew(Some(Some(10)), Some(10)), "unchanged");
        assert!(!lag_grew(Some(Some(10)), Some(9)), "catching up");
        assert!(lag_grew(Some(Some(10)), None), "checkpoint lost");
        assert!(
            !lag_grew(Some(None), Some(500)),
            "a first checkpoint is progress"
        );
    }

    /// A node cut off from its peers, or just restarted after less than a
    /// day, looks synced at a stale tip the observer has scanned. The chain's
    /// own clock says the watch's day has not been scanned yet.
    #[test]
    fn a_watch_does_not_end_before_the_chain_has_passed_its_day() {
        let store = Store::open_in_memory().unwrap();
        watch_at(&store, &ghostkeys()[0], 1, T0);
        caught_up(&store);
        let mut stale = tips();
        stale.median_time_ms.insert(SIGNET, T0 + 20 * HOUR);
        run_at(&store, &inbox(FLOOR, vec![]), &stale, T0 + 30 * HOUR);
        assert_eq!(
            watched(&store),
            vec![b"spk".to_vec()],
            "the chain is behind the day"
        );
        let day = T0 + WATCH_LIFETIME_MS;
        stale
            .median_time_ms
            .insert(SIGNET, day + MEDIAN_TIME_MARGIN_MS - 1);
        run_at(&store, &inbox(FLOOR, vec![]), &stale, T0 + 30 * HOUR);
        assert_eq!(
            watched(&store),
            vec![b"spk".to_vec()],
            "past the day, not the margin"
        );
        stale
            .median_time_ms
            .insert(SIGNET, day + MEDIAN_TIME_MARGIN_MS + 1);
        run_at(&store, &inbox(FLOOR, vec![]), &stale, T0 + 30 * HOUR);
        assert!(watched(&store).is_empty());
    }

    /// Mainnet is tried first, so its unreadable row must not keep signet's
    /// watch from ending.
    #[test]
    fn a_watch_row_that_cannot_be_read_stops_expiry_on_its_network_alone() {
        let store = Store::open_in_memory().unwrap();
        watch_at(&store, &ghostkeys()[0], 1, T0);
        store
            .execute_for_test("INSERT INTO script_interests VALUES ('bitcoin', X'00', 7, 1, 0, 0);")
            .unwrap();
        caught_up(&store);
        let pass = run_at(&store, &inbox(FLOOR, vec![]), &tips(), T0 + 25 * HOUR);
        assert!(watched(&store).is_empty(), "signet's watch ended");
        assert!(pass.gated, "mainnet's expiry is tried again");
    }

    #[test]
    fn a_node_still_syncing_after_ten_minutes_is_reported_once() {
        let mut w = SyncWatch::default();
        let syncing = BTreeSet::from([SIGNET]);
        assert!(w.update(&syncing, at(0)).is_empty());
        assert!(w.update(&syncing, at(599)).is_empty());
        assert_eq!(w.update(&syncing, at(600)), vec![SIGNET]);
        assert!(w.update(&syncing, at(1200)).is_empty(), "once per spell");
        assert!(w.update(&BTreeSet::new(), at(1201)).is_empty());
        assert!(
            w.update(&syncing, at(1202)).is_empty(),
            "a new spell starts again"
        );
    }

    // --- the driver ------------------------------------------------------------

    fn at(secs: u64) -> Instant {
        static BASE: OnceLock<Instant> = OnceLock::new();
        *BASE.get_or_init(Instant::now) + Duration::from_secs(secs)
    }

    #[test]
    fn the_first_tick_reads_and_subscribes() {
        let mut d = Driver::default();
        assert_eq!(d.on_tick(at(0)), vec![Step::Read, Step::Subscribe]);
    }

    #[test]
    fn changes_during_a_read_cost_one_more_read_not_one_each() {
        let mut d = Driver::default();
        d.on_tick(at(0));
        assert!(d.on_reply(Reply::Changed, at(1)).is_empty());
        assert!(d.on_reply(Reply::Changed, at(2)).is_empty());
        assert_eq!(
            d.on_reply(Reply::State(vec![1]), at(3)),
            vec![Step::Process(vec![1]), Step::Read]
        );
        assert_eq!(
            d.on_reply(Reply::State(vec![2]), at(4)),
            vec![Step::Process(vec![2])]
        );
    }

    #[test]
    fn a_read_that_never_answers_is_sent_again() {
        let mut d = Driver::default();
        d.on_tick(at(0));
        d.on_reply(Reply::Subscribed(true), at(0));
        assert!(d.on_tick(at(30)).is_empty(), "still waiting");
        assert_eq!(d.on_tick(at(61)), vec![Step::Read]);
    }

    #[test]
    fn subscribing_is_repeated_until_the_node_confirms_it() {
        let mut d = Driver::default();
        d.on_tick(at(0));
        d.on_reply(Reply::State(vec![]), at(1));
        assert!(d.on_tick(at(30)).contains(&Step::Subscribe));
        d.on_reply(Reply::Subscribed(true), at(31));
        assert!(!d.on_tick(at(60)).contains(&Step::Subscribe));
    }

    #[test]
    fn an_absent_inbox_is_opened_at_most_once_a_minute() {
        let mut d = Driver::default();
        d.on_tick(at(0));
        assert_eq!(d.on_reply(Reply::Absent, at(1)), vec![Step::Open]);
        let again = Reply::Failed {
            lost: false,
            not_found: true,
        };
        assert!(d.on_reply(again, at(20)).is_empty());
        assert_eq!(d.on_reply(Reply::Absent, at(62)), vec![Step::Open]);
        assert_eq!(d.on_reply(Reply::Opened, at(63)), vec![Step::Read]);
    }

    #[test]
    fn a_lost_connection_ends_the_session() {
        let mut d = Driver::default();
        let lost = Reply::Failed {
            lost: true,
            not_found: false,
        };
        assert_eq!(d.on_reply(lost, at(0)), vec![Step::Reconnect]);
    }

    #[test]
    fn a_closed_channel_counts_as_a_lost_connection_and_a_refusal_does_not() {
        assert!(connection_lost(&ErrorKind::ChannelClosed));
        assert!(connection_lost(&ErrorKind::Disconnect));
        assert!(!connection_lost(&ErrorKind::FailedOperation));
        assert!(!connection_lost(&ErrorKind::OperationError {
            cause: "update refused".into()
        }));
    }

    #[test]
    fn reconnection_backs_off_to_a_minute_and_resets_after_a_working_session() {
        let mut b = Duration::from_secs(1);
        for _ in 0..10 {
            b = next_backoff(b, Duration::from_secs(1));
        }
        assert_eq!(b, MAX_BACKOFF);
        assert_eq!(
            next_backoff(b, Duration::from_secs(600)),
            Duration::from_secs(1)
        );
    }
}
