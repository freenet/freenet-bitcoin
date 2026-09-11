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
//! safe.
//!
//! # Acting exactly once
//!
//! A tombstone can fail to land, so the same entry can be read again after it
//! was acted on. Re-acting is harmless for one entry alone, but not across
//! two: a Watch read again after the same requester's Unwatch would bring back
//! an interest they withdrew. So entries acted on are recorded in the store
//! (`inbox_handled`) and only re-tombstoned, never re-acted, until the floor
//! passes them and the inbox drops them for good.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::SigningKey;
use freenet_bitcoin_common::{from_cbor, to_cbor, BitcoinNetwork, BridgeId};
use freenet_bitcoin_inbox::seal::unseal;
use freenet_bitcoin_inbox::{
    Action, EntryKey, InboxEntry, InboxParameters, InboxStateV1, SignedFloor, SignedTombstone,
    FLOOR_LAG_BLOCKS,
};
use freenet_stdlib::client_api::{
    ClientRequest, ContractRequest, ContractResponse, ErrorKind, HostResponse, WebApi,
};
use freenet_stdlib::prelude::{
    ContractCode, ContractContainer, ContractKey, ContractWasmAPIVersion, Parameters, StateDelta,
    UpdateData, WrappedContract, WrappedState,
};

use crate::chain::ChainClient;
use crate::config::{BridgeConfig, NetworkConfig};
use crate::freenet::is_not_found;
use crate::store::{Store, WatchedScript};

/// How far back one request may make the bridge rescan, in blocks.
///
/// A request's `scan_from_height` rewinds the scan cursor of its whole
/// network, so without a bound one Ghost Key could make the bridge rescan the
/// chain from the start. A week of blocks covers what the hint is for, an
/// address handed out recently; a freshly derived address needs none.
pub const MAX_REQUEST_BACKFILL_BLOCKS: u32 = 1008;

/// How often the inbox is read even when no notification arrives.
const POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Longest wait between reconnection attempts.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

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
    pub delta: freenet_bitcoin_inbox::InboxDelta,
    /// Entries acted on for the first time.
    pub acted: usize,
    /// Entries left in place because something they need was unavailable.
    pub deferred: usize,
}

enum Outcome {
    /// Acted on, or found to be nothing this bridge can act on. Removed
    /// either way, so it stops holding its sender's slot.
    Done,
    /// Needs something unavailable right now. Left for a later pass.
    Later(String),
}

pub struct Processor<'a> {
    pub params: &'a InboxParameters,
    pub key: &'a SigningKey,
    pub store: &'a Store,
    /// Networks this bridge observes. A request for any other is dropped.
    pub observed: &'a [BitcoinNetwork],
}

impl Processor<'_> {
    pub fn pass(&self, state: &InboxStateV1, tips: &Tips, now_ms: i64) -> Result<Pass> {
        state
            .verify(self.params)
            .map_err(|e| anyhow!("the inbox state does not verify: {e}"))?;
        // The inbox has dropped everything below its floor, so none of it can
        // be presented again and the record of having handled it can go.
        if let Some(floor) = state.floor_height() {
            self.store.prune_handled_below(floor)?;
        }

        let mut pass = Pass::default();
        let mut oldest_deferred: Option<u32> = None;

        // Oldest first, so one requester's Watch and later Unwatch are applied
        // in the order they were made.
        let mut entries: Vec<(&EntryKey, &InboxEntry)> = state.entries.iter().collect();
        entries.sort_by_key(|(k, e)| (e.mainnet_height, **k));

        for (k, e) in entries {
            if !self.store.is_handled(&k.0)? {
                match self.act(e, tips, now_ms)? {
                    Outcome::Done => {
                        self.store.mark_handled(&k.0, e.mainnet_height)?;
                        pass.acted += 1;
                    }
                    Outcome::Later(why) => {
                        tracing::info!(
                            height = e.mainnet_height,
                            "inbox entry left for later: {why}"
                        );
                        pass.deferred += 1;
                        oldest_deferred = Some(
                            oldest_deferred.map_or(e.mainnet_height, |h| h.min(e.mainnet_height)),
                        );
                        continue;
                    }
                }
            }
            // Handled, in this pass or an earlier one. Ed25519 signatures are
            // deterministic, so re-sending a tombstone that was lost sends the
            // same bytes.
            pass.delta
                .tombstones
                .push(SignedTombstone::for_entry(self.key, *k, e));
        }

        if let Some(tip) = tips.mainnet() {
            let mut target = tip.saturating_sub(FLOOR_LAG_BLOCKS);
            // Never past an entry not yet acted on: the inbox would drop it
            // unread.
            if let Some(h) = oldest_deferred {
                target = target.min(h);
            }
            if state.floor_height().is_none_or(|cur| target > cur) {
                pass.delta.floor = Some(SignedFloor::sign(self.key, target));
            }
        }
        Ok(pass)
    }

    /// Act on one entry. An error here is the store failing, and aborts the
    /// pass; anything wrong with the entry itself is `Done`, so it is removed.
    fn act(&self, e: &InboxEntry, tips: &Tips, now_ms: i64) -> Result<Outcome> {
        let body = match e.body() {
            Ok(b) => b,
            Err(err) => {
                tracing::warn!("dropping an inbox entry whose body does not decode: {err}");
                return Ok(Outcome::Done);
            }
        };
        let req = match unseal(self.key, &body.sealed) {
            Ok(r) => r,
            Err(err) => {
                tracing::warn!("dropping an inbox entry this bridge cannot open: {err}");
                return Ok(Outcome::Done);
            }
        };
        if let Err(err) = req.check() {
            tracing::warn!("dropping a malformed request: {err}");
            return Ok(Outcome::Done);
        }
        let net = req.network;
        if !self.observed.contains(&net) {
            tracing::info!(network = ?net, "dropping a request for a network this bridge does not observe");
            return Ok(Outcome::Done);
        }
        let ghostkey = &e.ghostkey.0;

        match req.action {
            Action::Watch => {
                let Some(&tip) = tips.by_network.get(&net) else {
                    return Ok(Outcome::Later(format!(
                        "the {} tip could not be read",
                        net.as_str()
                    )));
                };
                let earliest = tip.saturating_sub(MAX_REQUEST_BACKFILL_BLOCKS);
                let scan_from = req.scan_from_height.unwrap_or(tip).clamp(earliest, tip);
                for script in &req.scripts {
                    self.store.add_interest(net, &script.0, ghostkey, now_ms)?;
                    self.store.add_watch(
                        &WatchedScript {
                            network: net,
                            script_pubkey: script.0.clone(),
                            scan_from_height: scan_from,
                            is_public_demo: false,
                        },
                        now_ms,
                    )?;
                }
                if scan_from < tip {
                    self.store.rewind_checkpoint_to(net, scan_from)?;
                }
                tracing::info!(network = ?net, scripts = req.scripts.len(), scan_from, "watch request accepted");
            }
            Action::Unwatch => {
                let mut stopped = 0;
                for script in &req.scripts {
                    // Only when the sender held an interest and was the last
                    // to: a stranger's unwatch ends nothing, and
                    // `remove_watch` never ends an operator's demo script.
                    if self.store.remove_interest(net, &script.0, ghostkey)? == Some(0) {
                        self.store.remove_watch(net, &script.0)?;
                        stopped += 1;
                    }
                }
                tracing::info!(network = ?net, scripts = req.scripts.len(), stopped, "unwatch request accepted");
            }
        }
        Ok(Outcome::Done)
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
            if started.elapsed() > MAX_BACKOFF {
                backoff = Duration::from_secs(1);
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
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
        };
        let key = self.contract_key()?;

        let mut subscribed = false;
        let mut poll = tokio::time::interval(POLL_INTERVAL);
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                // The first tick fires at once, which is the initial read.
                _ = poll.tick() => {
                    send(&mut api, get(key)).await?;
                    if !subscribed {
                        send(&mut api, ContractRequest::Subscribe { key: key.into(), summary: None })
                            .await?;
                    }
                }
                msg = api.recv() => match msg {
                    Ok(HostResponse::ContractResponse(resp)) => match resp {
                        ContractResponse::GetResponse { state, .. } => {
                            self.on_state(&mut api, key, &processor, state.as_ref()).await?;
                        }
                        ContractResponse::NotFound { .. } => self.open(&mut api).await?,
                        // The notification may carry a delta rather than state,
                        // so read the state itself rather than guess.
                        ContractResponse::UpdateNotification { .. } => {
                            send(&mut api, get(key)).await?;
                        }
                        ContractResponse::SubscribeResponse { subscribed: s, .. } => {
                            subscribed = s;
                            if !s {
                                tracing::warn!("the node refused a subscription to the request inbox; polling instead");
                            }
                        }
                        ContractResponse::PutResponse { .. } => {
                            tracing::info!("opened the request inbox");
                            send(&mut api, get(key)).await?;
                        }
                        other => tracing::debug!(?other, "request inbox reply"),
                    },
                    Ok(other) => tracing::debug!(?other, "ignoring a host response"),
                    Err(e) if connection_lost(e.kind()) => {
                        return Err(anyhow!("the node closed the connection: {e}"));
                    }
                    Err(e) if is_not_found(&e.to_string()) => self.open(&mut api).await?,
                    Err(e) => tracing::warn!("a request inbox operation failed: {e}"),
                }
            }
        }
    }

    async fn on_state(
        &self,
        api: &mut WebApi,
        key: ContractKey,
        processor: &Processor<'_>,
        bytes: &[u8],
    ) -> Result<()> {
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
        let tips = self.tips();
        let pass = match processor.pass(&state, &tips, now_ms()) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("request inbox pass failed: {e:#}");
                return Ok(());
            }
        };
        if pass.acted > 0 || pass.deferred > 0 {
            tracing::info!(
                acted = pass.acted,
                deferred = pass.deferred,
                "read the request inbox"
            );
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
    async fn open(&self, api: &mut WebApi) -> Result<()> {
        let Some(tip) = self.tips().mainnet() else {
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

    /// Read each observed network's tip.
    ///
    /// Blocking RPC on this worker's runtime, which serves only this worker
    /// and its connection, so the cost is a short stall of its own traffic.
    fn tips(&self) -> Tips {
        let mut tips = Tips::default();
        for n in &self.networks {
            match ChainClient::connect(n).and_then(|c| c.tip()) {
                Ok(a) => {
                    tips.by_network.insert(n.network, a.height);
                }
                Err(e) => tracing::warn!(network = ?n.network, "cannot read the chain tip: {e}"),
            }
        }
        tips
    }
}

fn get(key: ContractKey) -> ContractRequest<'static> {
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
    use freenet_bitcoin_inbox::seal::seal;
    use freenet_bitcoin_inbox::test_support::{TestAuthority, TestGhostkey};
    use freenet_bitcoin_inbox::{ByteBuf, InboxDelta, InboxRequest, WireEntry};

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

    fn request(action: Action, script: &[u8], scan_from: Option<u32>) -> InboxRequest {
        InboxRequest {
            action,
            network: SIGNET,
            scripts: vec![ByteBuf(script.to_vec())],
            scan_from_height: scan_from,
        }
    }

    fn entry(gk: &TestGhostkey, height: u32, req: &InboxRequest) -> WireEntry {
        gk.entry(bridge(), height, seal(&bridge(), req).unwrap())
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

    fn run(store: &Store, state: &InboxStateV1, tips: &Tips) -> Pass {
        let params = params();
        let key = bridge_key();
        Processor {
            params: &params,
            key: &key,
            store,
            observed: OBSERVED,
        }
        .pass(state, tips, 0)
        .unwrap()
    }

    fn watched(store: &Store) -> Vec<Vec<u8>> {
        store
            .watched(SIGNET)
            .unwrap()
            .into_iter()
            .map(|w| w.script_pubkey)
            .collect()
    }

    #[test]
    fn a_watch_request_is_acted_on_and_removed() {
        let store = Store::open_in_memory().unwrap();
        let state = inbox(
            FLOOR,
            vec![entry(
                &ghostkeys()[0],
                FLOOR + 1,
                &request(Action::Watch, b"spk", None),
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
        let both = inbox(
            FLOOR,
            vec![
                entry(a, FLOOR + 1, &request(Action::Watch, b"spk", None)),
                entry(b, FLOOR + 1, &request(Action::Watch, b"spk", None)),
            ],
        );
        run(&store, &both, &tips());

        let a_leaves = inbox(
            FLOOR,
            vec![entry(a, FLOOR + 2, &request(Action::Unwatch, b"spk", None))],
        );
        run(&store, &a_leaves, &tips());
        assert_eq!(watched(&store), vec![b"spk".to_vec()], "b still wants it");

        let b_leaves = inbox(
            FLOOR,
            vec![entry(b, FLOOR + 2, &request(Action::Unwatch, b"spk", None))],
        );
        run(&store, &b_leaves, &tips());
        assert!(watched(&store).is_empty());
    }

    /// The hazard `inbox_handled` exists for. Also checks entries are taken
    /// oldest first: in the reverse order the first pass would leave the
    /// script watched.
    #[test]
    fn a_watch_whose_tombstone_was_lost_is_not_acted_on_again() {
        let store = Store::open_in_memory().unwrap();
        let a = &ghostkeys()[0];
        let w = entry(a, FLOOR + 1, &request(Action::Watch, b"spk", None));
        let u = entry(a, FLOOR + 2, &request(Action::Unwatch, b"spk", None));
        run(&store, &inbox(FLOOR, vec![w.clone(), u]), &tips());
        assert!(watched(&store).is_empty());

        // Only the Unwatch's tombstone landed, so the Watch is read again.
        let pass = run(&store, &inbox(FLOOR, vec![w]), &tips());
        assert_eq!(pass.acted, 0);
        assert!(
            watched(&store).is_empty(),
            "an interest the requester withdrew must stay withdrawn"
        );
        assert_eq!(
            pass.delta.tombstones.len(),
            1,
            "the lost tombstone is sent again"
        );
    }

    #[test]
    fn a_request_the_bridge_cannot_serve_is_removed_without_effect() {
        let store = Store::open_in_memory().unwrap();
        let a = &ghostkeys()[0];

        let mut regtest = request(Action::Watch, b"spk", None);
        regtest.network = BitcoinNetwork::Regtest;
        let other_bridge = BridgeId(
            SigningKey::from_bytes(&[5u8; 32])
                .verifying_key()
                .to_bytes(),
        );
        let sealed_to_another = a.entry(
            bridge(),
            FLOOR + 1,
            seal(&other_bridge, &request(Action::Watch, b"spk2", None)).unwrap(),
        );

        let state = inbox(
            FLOOR,
            vec![entry(a, FLOOR + 1, &regtest), sealed_to_another],
        );
        let pass = run(&store, &state, &tips());
        assert!(watched(&store).is_empty());
        assert!(store.watched(BitcoinNetwork::Regtest).unwrap().is_empty());
        assert_eq!(pass.delta.tombstones.len(), 2, "both are removed");
    }

    #[test]
    fn an_entry_waiting_on_an_unreadable_tip_holds_the_floor_at_it() {
        let store = Store::open_in_memory().unwrap();
        let old_floor = FLOOR - 10;
        let state = inbox(
            old_floor,
            vec![entry(
                &ghostkeys()[0],
                old_floor + 2,
                &request(Action::Watch, b"spk", None),
            )],
        );
        let mut no_signet = tips();
        no_signet.by_network.remove(&SIGNET);

        let pass = run(&store, &state, &no_signet);
        assert_eq!(pass.deferred, 1);
        assert!(pass.delta.tombstones.is_empty(), "not removed unread");
        assert_eq!(
            pass.delta.floor.as_ref().map(|f| f.height),
            Some(old_floor + 2),
            "the floor may rise to the waiting entry, never past it"
        );

        let pass = run(&store, &state, &tips());
        assert_eq!(pass.acted, 1, "served once the tip is readable");
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

    #[test]
    fn a_request_cannot_rewind_the_scan_past_the_backfill_bound() {
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
        let from_genesis = request(Action::Watch, b"spk", Some(0));
        run(
            &store,
            &inbox(
                FLOOR,
                vec![entry(&ghostkeys()[0], FLOOR + 1, &from_genesis)],
            ),
            &tips(),
        );
        let earliest = SIGNET_TIP - MAX_REQUEST_BACKFILL_BLOCKS;
        assert_eq!(store.watched(SIGNET).unwrap()[0].scan_from_height, earliest);
        assert_eq!(store.checkpoint(SIGNET).unwrap().unwrap().height, earliest);
    }

    #[test]
    fn an_unwatch_from_someone_who_never_asked_ends_nothing() {
        let store = Store::open_in_memory().unwrap();
        // A watch registered some other way, such as before the inbox existed.
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
        let stranger = entry(
            &ghostkeys()[2],
            FLOOR + 1,
            &request(Action::Unwatch, b"spk", None),
        );
        run(&store, &inbox(FLOOR, vec![stranger]), &tips());
        assert_eq!(watched(&store), vec![b"spk".to_vec()]);
    }
}
