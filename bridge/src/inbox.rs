//! The bridge's side of its request inbox.
//!
//! Clients ask this bridge to watch a Bitcoin script by appending a sealed,
//! Ghost Key signed entry to the bridge's inbox contract (see
//! `freenet_bitcoin_inbox`). This module reads the inbox, acts on each entry,
//! removes it with a signed tombstone, and keeps the inbox's floor following
//! the Bitcoin mainnet tip.
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
//! tombstone failed to land is removed again rather than acted on again, and
//! the highest floor this bridge has signed is stored, so an entry below it is
//! never acted on even when a stale copy of the inbox presents it.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::SigningKey;
use freenet_bitcoin_common::{from_cbor, to_cbor, BitcoinNetwork, BridgeId};
use freenet_bitcoin_inbox::seal::unseal;
use freenet_bitcoin_inbox::{
    Action, EntryKey, InboxDelta, InboxEntry, InboxParameters, InboxStateV1, SignedFloor,
    SignedTombstone, FLOOR_LAG_BLOCKS, WINDOW_BLOCKS,
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

// ---------------------------------------------------------------------------
// One pass over the inbox. No I/O but SQLite, so it is tested directly.
// ---------------------------------------------------------------------------

/// Chain tips a pass needs, read before it runs.
#[derive(Clone, Debug, Default)]
pub struct Tips {
    /// The tip of each network this bridge observes, where it could be read.
    pub by_network: HashMap<BitcoinNetwork, u32>,
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
    /// Tombstones and floor to send back to the inbox.
    pub delta: InboxDelta,
    /// Entries acted on for the first time.
    pub acted: usize,
}

pub struct Processor<'a> {
    pub params: &'a InboxParameters,
    pub key: &'a SigningKey,
    pub store: &'a Store,
    /// Networks this bridge observes. A request for any other is dropped.
    pub observed: &'a [BitcoinNetwork],
    /// See [`MAX_WATCHES_PER_GHOSTKEY`]; a field so tests can use a small one.
    pub max_watches_per_ghostkey: usize,
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
                self.store.with_transaction(|| {
                    self.act(e, tips, now_ms)?;
                    self.store.mark_handled(&k.0, e.mainnet_height)
                })?;
                pass.acted += 1;
            }
            // Ed25519 signatures are deterministic, so re-sending a tombstone
            // that was lost sends the same bytes.
            pass.delta
                .tombstones
                .push(SignedTombstone::for_entry(self.key, k, e));
        }

        let target = match tips.mainnet() {
            Some(tip) => known.max(Some(tip.saturating_sub(FLOOR_LAG_BLOCKS))),
            None => known,
        };
        if let Some(t) = target {
            if state_floor.is_none_or(|cur| t > cur) {
                self.store.set_signed_floor(t)?;
                pass.delta.floor = Some(SignedFloor::sign(self.key, t));
            }
        }
        Ok(pass)
    }

    /// Act on one entry. An error here is the store failing, and rolls back
    /// the entry; anything wrong with the entry itself is logged and the entry
    /// is removed like any other, so it stops holding its sender's slot. The
    /// tombstone therefore says the entry was read, not what came of it.
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
                // A new script is watched from wherever the scan cursor is.
                // The request's `scan_from_height` hint is not acted on yet:
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
        let processor = Processor {
            params: &self.params,
            key: &self.key,
            store: &store,
            observed: &observed,
            max_watches_per_ghostkey: MAX_WATCHES_PER_GHOSTKEY,
        };
        let key = self.contract_key()?;
        let mut session = Session {
            chains: HashMap::new(),
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
                    Step::Open => self.open(&mut api, &mut session).await?,
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
        let fingerprint = QuietCache::fingerprint(bytes, &tips);
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
            .after_pass(fingerprint, !pass.delta.is_empty());
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
    /// exists, so until this runs nobody can write to it.
    async fn open(&self, api: &mut WebApi, session: &mut Session) -> Result<()> {
        let Some(tip) = session.tips(&self.networks).mainnet() else {
            tracing::warn!("cannot open the request inbox: the Bitcoin mainnet tip is unreadable");
            return Ok(());
        };
        let state = InboxStateV1 {
            floor: Some(SignedFloor::sign(
                &self.key,
                tip.saturating_sub(FLOOR_LAG_BLOCKS),
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

/// A state's bytes, by hash, and the mainnet tip it was read against.
pub type Fingerprint = ([u8; 32], Option<u32>);

/// Which state needs no processing again.
///
/// Only a pass that had nothing to send is remembered. One that sent
/// tombstones or a floor may have had them refused after sending, so its state
/// is processed again, and they are sent again, until a pass finds nothing
/// left to send. Processing a settled state again would cost an RSA check per
/// certificate for nothing.
#[derive(Debug, Default)]
pub struct QuietCache(Option<Fingerprint>);

impl QuietCache {
    pub fn fingerprint(bytes: &[u8], tips: &Tips) -> Fingerprint {
        (*blake3::hash(bytes).as_bytes(), tips.mainnet())
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
            match client.tip() {
                Ok(a) => {
                    tips.by_network.insert(n.network, a.height);
                }
                Err(e) => {
                    tracing::warn!(network = ?n.network, "cannot read the chain tip: {e}");
                    self.chains.remove(&n.network);
                }
            }
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
                tombstones: vec![],
            },
        )
        .unwrap();
        s
    }

    fn try_run(
        store: &Store,
        state: &InboxStateV1,
        tips: &Tips,
        cap: usize,
        now_ms: i64,
    ) -> Result<Pass> {
        let params = params();
        let key = bridge_key();
        Processor {
            params: &params,
            key: &key,
            store,
            observed: OBSERVED,
            max_watches_per_ghostkey: cap,
        }
        .pass(state, tips, now_ms)
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
        assert_eq!(after.tombstones.len(), 1);
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
    fn a_watch_whose_tombstone_was_lost_is_removed_again_not_acted_on_again() {
        let store = Store::open_in_memory().unwrap();
        let w = entry(
            &ghostkeys()[0],
            FLOOR + 1,
            &request(Action::Watch, b"spk", 1),
        );
        run(&store, &inbox(FLOOR, vec![w.clone()]), &tips());
        let pass = run(&store, &inbox(FLOOR, vec![w]), &tips());
        assert_eq!(pass.acted, 0);
        assert_eq!(
            pass.delta.tombstones.len(),
            1,
            "the lost tombstone is sent again"
        );
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
        assert_eq!(pass.delta.tombstones.len(), 2, "both are removed");
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
        assert_eq!(pass.delta.tombstones.len(), 1);
        assert_eq!(
            store.watched(SIGNET).unwrap()[0].scan_from_height,
            u32::MAX,
            "no rescan was asked for, so no height is recorded"
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
        store
            .set_checkpoint(
                SIGNET,
                &BlockAnchor {
                    height: SIGNET_TIP,
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
            SIGNET_TIP
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
        let fp = QuietCache::fingerprint(b"state", &tips());
        assert!(!q.is_quiet(&fp));
        q.after_pass(fp, true);
        assert!(
            !q.is_quiet(&fp),
            "it sent something, which the node may have refused"
        );
        q.after_pass(fp, false);
        assert!(q.is_quiet(&fp));
        let mut moved = tips();
        moved
            .by_network
            .insert(BitcoinNetwork::Bitcoin, MAINNET_TIP + 1);
        assert!(!q.is_quiet(&QuietCache::fingerprint(b"state", &moved)));
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
