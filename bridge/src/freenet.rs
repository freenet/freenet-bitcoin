//! Publishing Bitcoin observations into Freenet contracts.
//!
//! # Idempotence is the whole design here
//!
//! The bridge republishes freely — on restart, on retry, on a duplicate node
//! event — because the contracts it writes to merge by set union over a
//! digest-keyed map. Re-applying a claim a peer already holds changes nothing.
//! That is what lets this layer be simple: there is no delivery bookkeeping to
//! get wrong, and the worst case of a redundant publish is wasted bandwidth
//! rather than corrupted state.
//!
//! The bridge tracks what it has already sent purely as an optimisation, and
//! losing that record is harmless.

use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use freenet_bitcoin_common::{
    to_cbor, BitcoinAddressParameters, BitcoinTipParameters, SignedClaim, SignedTipEntry,
};
use freenet_stdlib::client_api::{
    ClientError, ClientRequest, ContractRequest, ContractResponse, ErrorKind, HostResponse, WebApi,
};
use freenet_stdlib::prelude::{
    ContractCode, ContractContainer, ContractInstanceId, ContractKey, ContractWasmAPIVersion,
    Parameters, UpdateData, WrappedContract, WrappedState,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// How long a request may wait to be handed to the connection's task.
///
/// Normally immediate. It waits only when that task is itself stuck delivering
/// a reply nobody collected, and then it would wait forever.
pub(crate) const SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// How long opening a connection to the node may take.
///
/// The node is local, but it is also the thing under load here: a node busy
/// enough to be slow completing a websocket upgrade is exactly the case this
/// module exists for, so this is generous rather than tight.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// The first and longest waits before dialling a node that refused.
const RECONNECT_BACKOFF_MIN: Duration = Duration::from_secs(1);
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(30);

/// One websocket to the node, replaced whenever its replies cannot be trusted.
///
/// A reply is matched to its request by order and nothing else. So a reply
/// that arrives after its request timed out, or an extra message the node
/// sends unasked, is read as the answer to the NEXT request, and so on down
/// the line. Worse, the client's request and response channels hold one
/// message each, and its task stops reading the socket while it waits to hand
/// over a reply. Once two replies go uncollected the next request fills the
/// request channel, and the one after that waits in `send` forever while
/// holding the publisher's lock. That froze the observer on 2026-09-17 with a
/// confirmed payment unpublished.
///
/// A stale reply cannot always be told from a current one, and the only way to
/// discard it is to discard the connection it would arrive on. So the
/// connection is dropped after a request that is not answered in time, a send
/// that cannot be handed over, an error reply (which names no contract, so
/// cannot be checked), and any reply the caller finds is not the answer to
/// what it asked (`discard`). The next request opens a fresh one.
///
/// Two layers, on purpose: discarding keeps stale replies from piling up, and
/// the send timeout is what still frees the lock if they ever do.
///
/// # What this does not catch
///
/// A stale reply for the SAME contract as the request in flight. The client
/// API carries no request id, so order is all there is, and two consecutive
/// writes to one address contract are ordinary here. The mitigation is only
/// that a stale reply cannot survive a timeout or an unmatched reply, both of
/// which take the connection with them.
struct Link {
    ws_url: String,
    api: Option<WebApi>,
    /// No new connection is attempted before this, after one failed.
    retry_at: Option<Instant>,
    backoff: Duration,
}

impl Link {
    fn new(ws_url: &str, api: Option<WebApi>) -> Self {
        Link {
            ws_url: ws_url.to_string(),
            api,
            retry_at: None,
            backoff: RECONNECT_BACKOFF_MIN,
        }
    }

    async fn open(ws_url: &str) -> Result<WebApi> {
        let (stream, _) =
            tokio::time::timeout(CONNECT_TIMEOUT, tokio_tungstenite::connect_async(ws_url))
                .await
                .map_err(|_| anyhow!("timed out connecting to the Freenet node at {ws_url}"))?
                .with_context(|| format!("connecting to the Freenet node at {ws_url}"))?;
        Ok(WebApi::start(stream))
    }

    /// The open connection, or a new one.
    ///
    /// A node that refused is not dialled again until its backoff has passed.
    /// Without that, a stopped node would be dialled once per request, several
    /// times per watched address, every two-second round.
    async fn connection(&mut self) -> Result<WebApi> {
        if let Some(api) = self.api.take() {
            return Ok(api);
        }
        if let Some(at) = self.retry_at {
            let now = Instant::now();
            if now < at {
                return Err(LinkUnusable(format!(
                    "the Freenet node at {} was unreachable; next attempt in {}ms",
                    self.ws_url,
                    (at - now).as_millis()
                ))
                .into());
            }
        }
        match Self::open(&self.ws_url).await {
            Ok(api) => {
                // The backoff is NOT reset here. A node that answers "not
                // joined yet" completes the dial every time, so resetting on a
                // successful dial pinned the wait at its minimum for the whole
                // of that window. It is reset by a successful REQUEST, which
                // is what says the node is actually serving.
                self.retry_at = None;
                Ok(api)
            }
            Err(e) => {
                self.arm_backoff();
                Err(LinkUnusable(format!("{e:#}")).into())
            }
        }
    }

    /// Send `req` and wait up to `timeout` for the reply.
    ///
    /// `Err` means no reply was received. `Ok` carries what the node said; an
    /// error reply comes back as `Ok(Err(..))`, with the connection already
    /// dropped. A caller that finds a reply is not the answer it asked for
    /// must call [`Link::discard`].
    async fn request(
        &mut self,
        req: ContractRequest<'static>,
        timeout: Duration,
    ) -> Result<std::result::Result<HostResponse, ClientError>> {
        let mut api = self.connection().await?;
        match tokio::time::timeout(SEND_TIMEOUT, api.send(ClientRequest::ContractOp(req))).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(LinkUnusable(format!("sending to the node: {e}")).into()),
            Err(_) => {
                return Err(LinkUnusable(
                    "timed out handing a request to the node connection".to_string(),
                )
                .into())
            }
        }
        let reply = tokio::time::timeout(timeout, api.recv())
            .await
            .map_err(|_| LinkUnusable("timed out waiting for the node's reply".to_string()))?;
        match &reply {
            Ok(_) => {
                // A served request is what says the node is working, so this
                // is where the backoff is cleared.
                self.backoff = RECONNECT_BACKOFF_MIN;
                self.api = Some(api);
            }
            // An error reply names no contract, so it cannot be checked
            // against what was asked; the connection goes either way. What
            // the error says about the NODE is worth passing on, so a caller
            // about to make the same request for another contract can stop.
            Err(e) if reply_is_about_the_node(e.kind()) => {
                // Backed off as if the dial had failed. The dial did NOT fail
                // -- a node that answers "not joined yet" is listening -- so
                // without this the bridge opens a fresh connection per request
                // for the whole of that window, which is the node's worst
                // moment to be hammered.
                self.arm_backoff();
                return Err(LinkUnusable(format!("the node answered: {e}")).into());
            }
            Err(_) => {}
        }
        Ok(reply)
    }

    /// Wait before dialling again, as if a dial had just failed.
    fn arm_backoff(&mut self) {
        self.retry_at = Some(Instant::now() + jittered(self.backoff));
        self.backoff = (self.backoff * 2).min(RECONNECT_BACKOFF_MAX);
    }

    /// Drop the connection, after a reply that is not the answer to what was
    /// asked.
    fn discard(&mut self) {
        self.api = None;
    }
}

/// The link to the node could not carry a request.
///
/// Distinguished from every other publish failure because it says something
/// about the CONNECTION rather than about what was being published: a caller
/// that is about to make the same call for another contract will fail the
/// same way, and can stop. A claim the node rejected, or one this bridge
/// refuses to publish, says nothing about the next one.
#[derive(Debug)]
pub struct LinkUnusable(String);

impl std::fmt::Display for LinkUnusable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LinkUnusable {}

/// Whether `e` is [`LinkUnusable`], however deeply it is wrapped.
pub fn link_unusable(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| cause.is::<LinkUnusable>())
}

/// Whether an error REPLY is about the node rather than about the request.
///
/// A node that has not joined, has no ring connections, or is shutting down
/// answers an error rather than failing the socket, and it will answer the
/// next request the same way. Every other kind, including a contract's own
/// error, says something about the request and nothing about the next one.
/// `ErrorKind` is `#[non_exhaustive]`, so an unrecognised kind is treated as
/// per-request: the cost of being wrong that way is one retry.
fn reply_is_about_the_node(kind: &ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::EmptyRing
            | ErrorKind::PeerNotJoined
            | ErrorKind::NodeUnavailable
            | ErrorKind::Disconnect
            | ErrorKind::ChannelClosed
            | ErrorKind::TransportProtocolDisconnect
            | ErrorKind::Shutdown
    )
}

/// `base` scaled by a factor between 0.8 and 1.2, so a restart of the node
/// does not meet every waiting client at the same instant.
fn jittered(base: Duration) -> Duration {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    base * (80 + nanos % 41) / 100
}

/// The contract WASM a bridge runs, read from its `contract_dir`.
pub struct ContractWasm {
    pub address: Vec<u8>,
    pub tip: Vec<u8>,
    pub inbox: Vec<u8>,
}

impl ContractWasm {
    pub fn load(dir: &Path) -> Result<Self> {
        let read = |name: &str| {
            std::fs::read(dir.join(name))
                .with_context(|| format!("reading {name} from {}", dir.display()))
        };
        Ok(ContractWasm {
            address: read("bitcoin_address_contract.wasm")?,
            tip: read("bitcoin_tip_contract.wasm")?,
            inbox: read("bitcoin_inbox_contract.wasm")?,
        })
    }
}

/// A connection to a local Freenet node, plus the contract WASM needed to
/// derive keys and to PUT a contract that does not exist yet.
pub struct FreenetPublisher {
    link: Arc<Mutex<Link>>,
    address_code: Arc<ContractCode<'static>>,
    tip_code: Arc<ContractCode<'static>>,
    /// Held for its code hash, which the inbox generation pointer names. The
    /// inbox itself is read and written by `inbox::InboxWorker` over its own
    /// connection.
    inbox_code: Arc<ContractCode<'static>>,
    /// The frozen pointer contract. Vendored bytes, never rebuilt: the whole
    /// point of a pointer is that its own address does not move.
    pointer_code: Arc<ContractCode<'static>>,
}

impl FreenetPublisher {
    /// Build a publisher for the node at `ws_url`.
    ///
    /// Deliberately does NOT dial. It used to, and a startup where the node
    /// was slow or not yet up left `main` with no publisher at all for the
    /// life of the process, so the bridge silently published nothing until
    /// somebody restarted it. `Link` reconnects on demand under a backoff, so
    /// there is nothing to gain from failing here.
    pub fn new(ws_url: &str, wasm: &ContractWasm) -> Self {
        FreenetPublisher {
            link: Arc::new(Mutex::new(Link::new(ws_url, None))),
            address_code: Arc::new(ContractCode::from(wasm.address.clone())),
            tip_code: Arc::new(ContractCode::from(wasm.tip.clone())),
            inbox_code: Arc::new(ContractCode::from(wasm.inbox.clone())),
            pointer_code: Arc::new(ContractCode::from(
                freenet_bitcoin_generation::POINTER_CONTRACT_WASM.to_vec(),
            )),
        }
    }

    /// Contract key for a Bitcoin address contract instance.
    pub fn address_key(&self, params: &BitcoinAddressParameters) -> Result<ContractKey> {
        let bytes = to_cbor(params).map_err(|e| anyhow!(e))?;
        Ok(ContractKey::from_params_and_code(
            Parameters::from(bytes),
            self.address_code.as_ref(),
        ))
    }

    pub fn tip_key(&self, params: &BitcoinTipParameters) -> Result<ContractKey> {
        let bytes = to_cbor(params).map_err(|e| anyhow!(e))?;
        Ok(ContractKey::from_params_and_code(
            Parameters::from(bytes),
            self.tip_code.as_ref(),
        ))
    }

    /// The 32-byte code hash of the address contract WASM.
    ///
    /// Applications need this to derive an address contract's key themselves,
    /// so the bridge publishes it in a generation pointer rather than making
    /// every client hardcode it — a hardcoded code hash goes stale silently on
    /// the next rebuild.
    pub fn address_code_hash(&self) -> [u8; 32] {
        let bytes: &[u8] = self.address_code.hash().as_ref();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes[..32]);
        out
    }

    /// The 32-byte code hash of the tip contract WASM.
    ///
    /// Same role as [`Self::address_code_hash`]: it is what a generation
    /// pointer names, so a reader can derive the tip contract's key without
    /// shipping the WASM itself.
    pub fn tip_code_hash(&self) -> [u8; 32] {
        let bytes: &[u8] = self.tip_code.hash().as_ref();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes[..32]);
        out
    }

    /// The 32-byte code hash of the request inbox contract WASM, which the
    /// inbox generation pointer names.
    pub fn inbox_code_hash(&self) -> [u8; 32] {
        let bytes: &[u8] = self.inbox_code.hash().as_ref();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes[..32]);
        out
    }

    /// PUT or UPDATE a generation pointer record.
    ///
    /// `params` and `state` are the pointer contract's own encodings, built by
    /// `freenet-migrate`; nothing here interprets them. The contract verifies
    /// the signature against the author key inside `params` and refuses any
    /// record that does not supersede what it already holds, so a stale or
    /// forged record is rejected by the network rather than by this call.
    pub async fn publish_pointer(&self, params: Vec<u8>, state: Vec<u8>) -> Result<ContractKey> {
        let key = ContractKey::from_params_and_code(
            Parameters::from(params.clone()),
            self.pointer_code.as_ref(),
        );
        let container = ContractContainer::from(ContractWasmAPIVersion::V1(WrappedContract::new(
            self.pointer_code.clone(),
            Parameters::from(params),
        )));
        self.put_or_update(key, container, state).await?;
        Ok(key)
    }

    /// Recover a predecessor generation's observations, if any, BEFORE this
    /// instance is first written to.
    ///
    /// Ordering is the whole point. The bridge is the only writer, so if it
    /// published first there would be nothing to distinguish a fresh contract
    /// from a migrated one, and a probe run afterwards would be reading state
    /// it had just written itself.
    ///
    /// Returns the state to publish forward: either the fold of every
    /// predecessor generation with `local`, or `local` unchanged.
    pub async fn migrate_address_forward(
        &self,
        params: &BitcoinAddressParameters,
        local: freenet_bitcoin_common::address_state::BitcoinAddressStateV1,
    ) -> (
        freenet_bitcoin_common::address_state::BitcoinAddressStateV1,
        String,
        crate::migrate::Found,
    ) {
        use crate::migrate::{address_lineage, address_policy, describe, AddressOps, Found};
        use freenet_migrate::{migrate_contract, Outcome};

        let param_bytes = match to_cbor(params) {
            Ok(b) => b,
            Err(e) => return (local, format!("cannot encode params: {e}"), Found::Unknown),
        };
        let params_wrapped = Parameters::from(param_bytes);
        let ops = AddressOps {
            params: params.clone(),
        };
        let mut io = FreenetProbe { publisher: self };

        match migrate_contract(
            ops,
            &mut io,
            local.clone(),
            &params_wrapped,
            address_lineage(),
            address_policy(),
        )
        .await
        {
            Ok(o) => {
                let note = describe(&o);
                let found = Found::from(&o);
                match o {
                    Outcome::Recovered { merged, .. } => (merged, note, found),
                    _ => (local, note, found),
                }
            }
            Err(e) => (local, format!("probe aborted: {e:?}"), Found::Unknown),
        }
    }

    /// PUT an already-built address state forward under the current key.
    ///
    /// Split out from `publish_claims` because the migration path already
    /// holds a merged state and must not re-verify it claim-by-claim: it was
    /// produced by the contract's own merge, which verified as it went.
    pub async fn publish_state(
        &self,
        params: &BitcoinAddressParameters,
        state: &freenet_bitcoin_common::address_state::BitcoinAddressStateV1,
    ) -> Result<ContractKey> {
        let param_bytes = to_cbor(params).map_err(|e| anyhow!(e))?;
        let state_bytes = to_cbor(state).map_err(|e| anyhow!(e))?;
        let key = ContractKey::from_params_and_code(
            Parameters::from(param_bytes.clone()),
            self.address_code.as_ref(),
        );
        let container = ContractContainer::from(ContractWasmAPIVersion::V1(WrappedContract::new(
            self.address_code.clone(),
            Parameters::from(param_bytes),
        )));
        self.put_or_update(key, container, state_bytes).await?;
        Ok(key)
    }

    /// Ensure an address contract exists and carries these claims.
    ///
    /// PUTs the contract with the claims as its initial state. If it already
    /// exists the node merges rather than replaces, because `update_state`
    /// merges — so this is safe to call repeatedly and safe to call when
    /// another bridge has already published to the same instance.
    pub async fn publish_claims(
        &self,
        params: &BitcoinAddressParameters,
        claims: &[SignedClaim],
    ) -> Result<ContractKey> {
        use freenet_bitcoin_common::address_state::BitcoinAddressStateV1;

        let state = BitcoinAddressStateV1::from_claims(params, claims.iter().cloned())
            .map_err(|e| anyhow!("refusing to publish claims we cannot verify ourselves: {e}"))?;
        let param_bytes = to_cbor(params).map_err(|e| anyhow!(e))?;
        let state_bytes = to_cbor(&state).map_err(|e| anyhow!(e))?;

        let key = ContractKey::from_params_and_code(
            Parameters::from(param_bytes.clone()),
            self.address_code.as_ref(),
        );
        let container = ContractContainer::from(ContractWasmAPIVersion::V1(WrappedContract::new(
            self.address_code.clone(),
            Parameters::from(param_bytes),
        )));

        self.put_or_update(key, container, state_bytes).await?;
        Ok(key)
    }

    /// Ensure the per-network tip contract exists and carries these entries.
    pub async fn publish_tip(
        &self,
        params: &BitcoinTipParameters,
        entries: &[SignedTipEntry],
    ) -> Result<ContractKey> {
        use freenet_bitcoin_common::tip_state::BitcoinTipStateV1;

        let state = BitcoinTipStateV1::from_entries(params, entries.iter().cloned())
            .map_err(|e| anyhow!("refusing to publish tip entries we cannot verify: {e}"))?;
        let param_bytes = to_cbor(params).map_err(|e| anyhow!(e))?;
        let state_bytes = to_cbor(&state).map_err(|e| anyhow!(e))?;

        let key = ContractKey::from_params_and_code(
            Parameters::from(param_bytes.clone()),
            self.tip_code.as_ref(),
        );
        let container = ContractContainer::from(ContractWasmAPIVersion::V1(WrappedContract::new(
            self.tip_code.clone(),
            Parameters::from(param_bytes),
        )));

        self.put_or_update(key, container, state_bytes).await?;
        Ok(key)
    }

    /// Try UPDATE first, fall back to PUT.
    ///
    /// UPDATE is the cheap path for a contract that already exists — it ships
    /// a state that the contract's own `update_state` merges. PUT is needed
    /// only the first time an instance appears anywhere on the network. Doing
    /// it in this order avoids re-sending the WASM on every observation.
    async fn put_or_update(
        &self,
        key: ContractKey,
        container: ContractContainer,
        state_bytes: Vec<u8>,
    ) -> Result<()> {
        let mut link = self.link.lock().await;

        let update = ContractRequest::Update {
            key,
            data: UpdateData::State(state_bytes.clone().into()),
        };
        let reply = link
            .request(update, REQUEST_TIMEOUT)
            .await
            .context("UPDATE")?;
        match classify_update_reply(&key, &reply) {
            UpdateReply::Updated => return Ok(()),
            // The instance does not exist yet, so PUT it.
            UpdateReply::Missing => {}
            UpdateReply::Unmatched => {
                // Not an answer about this contract. PUT anyway, as a missing
                // contract is the usual reason, but on a fresh connection.
                link.discard();
                tracing::debug!(
                    "UPDATE of {} answered with {}; trying PUT",
                    key.id(),
                    describe_reply(&reply)
                );
            }
        }

        let put = ContractRequest::Put {
            contract: container,
            state: WrappedState::new(state_bytes),
            related_contracts: Default::default(),
            // The bridge does not want update notifications for contracts it
            // writes; subscribing would only add traffic it ignores.
            subscribe: false,
            blocking_subscribe: false,
        };
        let reply = link.request(put, REQUEST_TIMEOUT).await.context("PUT")?;
        if put_answered(&key, &reply) {
            return Ok(());
        }
        link.discard();
        Err(anyhow!(
            "PUT of {} answered with {}",
            key.id(),
            describe_reply(&reply)
        ))
    }

    /// Fetch a contract's current state from the network.
    ///
    /// Used by `verify`, which exists so an operator can confirm that
    /// observations actually became retrievable Freenet state rather than
    /// merely being accepted by the local node. "The PUT returned Ok" and
    /// "the data is readable" are different claims, and only the second one
    /// means the integration works.
    pub async fn get_state(&self, key: ContractKey) -> Result<Vec<u8>> {
        let mut link = self.link.lock().await;
        let req = ContractRequest::Get {
            key: key.into(),
            return_contract_code: false,
            subscribe: false,
            blocking_subscribe: false,
        };
        let reply = link.request(req, REQUEST_TIMEOUT).await.context("GET")?;
        match classify_get_reply(key.id(), &reply) {
            GetReply::State(state) => Ok(state),
            GetReply::Missing => Err(anyhow!("the node found no contract {}", key.id())),
            GetReply::Unmatched => {
                link.discard();
                Err(anyhow!(
                    "GET of {} answered with {}",
                    key.id(),
                    describe_reply(&reply)
                ))
            }
        }
    }
}

/// What a reply to an UPDATE says about the contract it was for.
#[derive(Debug, PartialEq, Eq)]
enum UpdateReply {
    Updated,
    /// The node answered that it has no such contract.
    Missing,
    /// Not an answer about this contract.
    Unmatched,
}

fn classify_update_reply(
    key: &ContractKey,
    reply: &std::result::Result<HostResponse, ClientError>,
) -> UpdateReply {
    match reply {
        Ok(HostResponse::ContractResponse(ContractResponse::UpdateResponse {
            key: answered,
            ..
        })) if answered.id() == key.id() => UpdateReply::Updated,
        Ok(HostResponse::ContractResponse(ContractResponse::NotFound { instance_id }))
            if instance_id == key.id() =>
        {
            UpdateReply::Missing
        }
        _ => UpdateReply::Unmatched,
    }
}

/// Whether a reply to a PUT says that contract was stored.
fn put_answered(key: &ContractKey, reply: &std::result::Result<HostResponse, ClientError>) -> bool {
    matches!(
        reply,
        Ok(HostResponse::ContractResponse(ContractResponse::PutResponse { key: answered }))
            if answered.id() == key.id()
    )
}

/// What a reply to a GET says about the contract it was for.
#[derive(Debug, PartialEq, Eq)]
enum GetReply {
    State(Vec<u8>),
    /// The node answered that it has no such contract. See
    /// [`classify_probe_reply`] for how little that proves.
    Missing,
    /// Not an answer about this contract.
    Unmatched,
}

fn classify_get_reply(
    asked: &ContractInstanceId,
    reply: &std::result::Result<HostResponse, ClientError>,
) -> GetReply {
    match reply {
        Ok(HostResponse::ContractResponse(ContractResponse::GetResponse {
            key, state, ..
        })) if key.id() == asked => GetReply::State(state.as_ref().to_vec()),
        Ok(HostResponse::ContractResponse(ContractResponse::NotFound { instance_id }))
            if instance_id == asked =>
        {
            GetReply::Missing
        }
        // An older node reported a miss as an error, which names no contract.
        Err(e) if is_not_found(&e.to_string()) => GetReply::Missing,
        _ => GetReply::Unmatched,
    }
}

/// A short account of a reply for a log line, without its state bytes.
fn describe_reply(reply: &std::result::Result<HostResponse, ClientError>) -> String {
    match reply {
        Ok(HostResponse::ContractResponse(response)) => match response {
            ContractResponse::GetResponse { key, .. } => format!("GetResponse for {}", key.id()),
            ContractResponse::PutResponse { key } => format!("PutResponse for {}", key.id()),
            ContractResponse::UpdateResponse { key, .. } => {
                format!("UpdateResponse for {}", key.id())
            }
            ContractResponse::NotFound { instance_id } => format!("NotFound for {instance_id}"),
            _ => "another contract response".to_string(),
        },
        Ok(_) => "a response that is not about a contract".to_string(),
        Err(e) => format!("an error: {e}"),
    }
}

/// Render a contract instance id the way applications quote it.
pub fn instance_id_b58(key: &ContractKey) -> String {
    key.id().to_string()
}

/// Derive an address contract's instance id from a code hash and parameters,
/// without needing the WASM itself.
///
/// This is what a client does: it learns the code hash once (from the bridge's
/// status response) and can then compute the key for any address. Hardcoding
/// the code hash instead is the mistake that breaks silently on the next
/// rebuild.
pub fn address_instance_id(
    code_hash: &[u8; 32],
    params: &BitcoinAddressParameters,
) -> Result<ContractInstanceId> {
    let param_bytes = to_cbor(params).map_err(|e| anyhow!(e))?;
    let mut h = blake3::Hasher::new();
    h.update(code_hash);
    h.update(&param_bytes);
    Ok(ContractInstanceId::new(*h.finalize().as_bytes()))
}

/// Probe adapter: answers the migration driver's GETs over this connection.
///
/// # The mapping that matters
///
/// `ProbeAnswer` is three-way on purpose, and collapsing it to two loses data
/// permanently (freenet-migrate#19). The rule:
///
/// * `NotFound` -> `Absent`. The network answered, positively, that there is
///   nothing there.
/// * a timeout, a transport fault, an unexpected response -> `Unknown`. We did
///   not hear back. That is NOT the same fact, and treating it as absence
///   makes the driver conclude a predecessor was empty when it may hold
///   everything.
///
/// Only `Absent` may be typed for an answer actually received.
pub struct FreenetProbe<'a> {
    pub publisher: &'a FreenetPublisher,
}

impl freenet_migrate::ProbeIo for FreenetProbe<'_> {
    type Error = std::convert::Infallible;

    async fn get(
        &mut self,
        id: ContractInstanceId,
    ) -> Result<freenet_migrate::ProbeAnswer, Self::Error> {
        // Every recoverable condition is mapped to a per-candidate non-answer
        // rather than an abort: an abort drops the driver and the local
        // snapshot with it.
        Ok(self.publisher.probe_get(id).await)
    }
}

impl FreenetPublisher {
    /// One probe GET, classified three ways.
    pub async fn probe_get(&self, id: ContractInstanceId) -> freenet_migrate::ProbeAnswer {
        use freenet_migrate::ProbeAnswer;

        let req = ContractRequest::Get {
            key: id,
            return_contract_code: false,
            subscribe: false,
            blocking_subscribe: false,
        };
        let mut link = self.link.lock().await;
        let reply = match link
            .request(
                req,
                Duration::from_millis(freenet_migrate::RECOMMENDED_PROBE_TIMEOUT_MS),
            )
            .await
        {
            Ok(reply) => reply,
            // Silence. Never absence.
            Err(_) => return ProbeAnswer::Unknown,
        };
        let answer = classify_probe_reply(&id, &reply);
        if answer == ProbeReply::Unmatched {
            link.discard();
        }
        answer.into_answer()
    }
}

/// What one reply to a probe GET says.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ProbeReply {
    State(Vec<u8>),
    /// The node answered that it found nothing. That is `Absent` to the
    /// driver, and it is weak evidence: a node gives the same answer when its
    /// GET merely ran out of retries. `migrate::count_walk` is where that
    /// weakness is accounted for.
    Absent,
    /// Not an answer about the contract asked about.
    Unmatched,
}

impl ProbeReply {
    fn into_answer(self) -> freenet_migrate::ProbeAnswer {
        use freenet_migrate::ProbeAnswer;
        match self {
            ProbeReply::State(state) => ProbeAnswer::State(state),
            ProbeReply::Absent => ProbeAnswer::Absent,
            ProbeReply::Unmatched => ProbeAnswer::Unknown,
        }
    }
}

/// Classify the node's reply to a probe GET of `asked`.
///
/// A current node reports a missing contract as a successful
/// `ContractResponse::NotFound`, not as an error. Reading that as "no answer"
/// made every predecessor of every watched address look unreachable, so the
/// migration never finished and re-sent all of its GETs on every round.
pub(crate) fn classify_probe_reply(
    asked: &ContractInstanceId,
    reply: &std::result::Result<HostResponse, ClientError>,
) -> ProbeReply {
    match classify_get_reply(asked, reply) {
        GetReply::State(state) => ProbeReply::State(state),
        GetReply::Missing => ProbeReply::Absent,
        GetReply::Unmatched => ProbeReply::Unmatched,
    }
}

/// Whether a client error is the network positively reporting no such state.
///
/// Deliberately narrow. Anything not recognised here is `Unknown`, because the
/// cost of a false `Absent` is permanent data loss and the cost of a false
/// `Unknown` is one retry.
pub(crate) fn is_not_found(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("not found") || m.contains("notfound")
}

#[cfg(test)]
mod probe_tests {
    use super::is_not_found;

    #[test]
    fn only_an_explicit_not_found_counts_as_absence() {
        assert!(is_not_found("ContractResponse: contract NotFound"));
        assert!(is_not_found("contract not found"));
    }

    /// The property that keeps a migration from sealing over live data.
    #[test]
    fn nothing_ambiguous_is_treated_as_absence() {
        for msg in [
            "timed out waiting for response",
            "connection reset",
            "websocket closed",
            "operation aborted",
            "no route to peer",
            "",
        ] {
            assert!(
                !is_not_found(msg),
                "{msg:?} must classify as Unknown, never Absent"
            );
        }
    }
}

#[cfg(test)]
mod link_tests {
    use super::*;
    use futures::{SinkExt, StreamExt};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;
    use tokio_tungstenite::tungstenite::Message;

    type HostResult = std::result::Result<HostResponse, ClientError>;

    fn id(byte: u8) -> ContractInstanceId {
        ContractInstanceId::new([byte; 32])
    }

    fn code() -> ContractCode<'static> {
        ContractCode::from(vec![0u8, 1, 2, 3])
    }

    fn key(byte: u8) -> ContractKey {
        ContractKey::from_params_and_code(Parameters::from(vec![byte]), code())
    }

    fn not_found(instance_id: ContractInstanceId) -> HostResult {
        Ok(HostResponse::ContractResponse(ContractResponse::NotFound {
            instance_id,
        }))
    }

    fn update_response(key: ContractKey) -> HostResult {
        Ok(HostResponse::ContractResponse(
            ContractResponse::UpdateResponse {
                key,
                summary: freenet_stdlib::prelude::StateSummary::from(vec![]),
            },
        ))
    }

    fn put_response(key: ContractKey) -> HostResult {
        Ok(HostResponse::ContractResponse(
            ContractResponse::PutResponse { key },
        ))
    }

    fn get_response(key: ContractKey, state: Vec<u8>) -> HostResult {
        Ok(HostResponse::ContractResponse(
            ContractResponse::GetResponse {
                key,
                contract: None,
                state: WrappedState::new(state),
            },
        ))
    }

    fn error(text: &str) -> HostResult {
        Err(ClientError::from(text.to_string()))
    }

    // --- classification ----------------------------------------------------

    #[test]
    fn a_probe_reply_is_about_the_contract_asked_about_or_it_is_nothing() {
        let asked = key(1);
        assert_eq!(
            classify_probe_reply(asked.id(), &not_found(*asked.id())),
            ProbeReply::Absent
        );
        assert_eq!(
            classify_probe_reply(asked.id(), &get_response(asked, vec![7])),
            ProbeReply::State(vec![7])
        );
        assert_eq!(
            classify_probe_reply(asked.id(), &not_found(id(9))),
            ProbeReply::Unmatched
        );
        assert_eq!(
            classify_probe_reply(asked.id(), &get_response(key(2), vec![7])),
            ProbeReply::Unmatched
        );
        assert_eq!(
            classify_probe_reply(asked.id(), &put_response(asked)),
            ProbeReply::Unmatched
        );
        assert_eq!(
            classify_probe_reply(asked.id(), &error("contract not found")),
            ProbeReply::Absent,
            "an older node reported a miss as an error"
        );
        assert_eq!(
            classify_probe_reply(asked.id(), &error("operation aborted")),
            ProbeReply::Unmatched
        );
    }

    #[test]
    fn only_an_update_or_not_found_for_the_same_contract_answers_an_update() {
        let asked = key(1);
        assert_eq!(
            classify_update_reply(&asked, &update_response(asked)),
            UpdateReply::Updated
        );
        assert_eq!(
            classify_update_reply(&asked, &not_found(*asked.id())),
            UpdateReply::Missing
        );
        for reply in [
            update_response(key(2)),
            not_found(id(9)),
            put_response(asked),
            get_response(asked, vec![]),
            error("contract not found"),
        ] {
            assert_eq!(
                classify_update_reply(&asked, &reply),
                UpdateReply::Unmatched
            );
        }
    }

    #[test]
    fn only_a_put_response_for_the_same_contract_answers_a_put() {
        let asked = key(1);
        assert!(put_answered(&asked, &put_response(asked)));
        assert!(!put_answered(&asked, &put_response(key(2))));
        assert!(!put_answered(&asked, &update_response(asked)));
        assert!(!put_answered(&asked, &not_found(*asked.id())));
    }

    // --- a node over a real websocket ----------------------------------------

    /// What the fake node does with one request.
    enum Action {
        Reply(HostResult),
        /// Send these, in order, for one request.
        Replies(Vec<HostResult>),
        /// Hold the reply until `release`, then send it and signal `sent`.
        Late {
            reply: HostResult,
            release: Arc<Notify>,
            sent: Arc<Notify>,
        },
    }

    /// `script(connection, request)` decides each answer. `connection` counts
    /// from 0 in the order connections were accepted.
    type Script = Arc<dyn Fn(usize, &ContractRequest<'_>) -> Action + Send + Sync>;

    struct Node {
        url: String,
        connections: Arc<AtomicUsize>,
    }

    async fn node(script: Script) -> Node {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/", listener.local_addr().unwrap());
        let connections = Arc::new(AtomicUsize::new(0));
        let accepted = connections.clone();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let connection = accepted.fetch_add(1, Ordering::SeqCst);
                let script = script.clone();
                tokio::spawn(async move {
                    let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await else {
                        return;
                    };
                    while let Some(Ok(msg)) = ws.next().await {
                        let Message::Binary(bytes) = msg else {
                            continue;
                        };
                        let action = match bincode::deserialize::<ClientRequest<'_>>(&bytes) {
                            Ok(ClientRequest::ContractOp(req)) => script(connection, &req),
                            _ => continue,
                        };
                        let (replies, after) = match action {
                            Action::Reply(reply) => (vec![reply], None),
                            Action::Replies(replies) => (replies, None),
                            Action::Late {
                                reply,
                                release,
                                sent,
                            } => {
                                release.notified().await;
                                (vec![reply], Some(sent))
                            }
                        };
                        let mut open = true;
                        for reply in replies {
                            let bytes = bincode::serialize(&reply).unwrap();
                            open &= ws.send(Message::Binary(bytes.into())).await.is_ok();
                        }
                        if let Some(sent) = after {
                            sent.notify_one();
                        }
                        if !open {
                            return;
                        }
                    }
                });
            }
        });
        Node { url, connections }
    }

    fn asked_id(req: &ContractRequest<'_>) -> ContractInstanceId {
        match req {
            ContractRequest::Get { key, .. } => *key,
            ContractRequest::Update { key, .. } => *key.id(),
            ContractRequest::Put { contract, .. } => *contract.key().id(),
            _ => panic!("the fake node was sent {req:?}"),
        }
    }

    fn get(instance: ContractInstanceId) -> ContractRequest<'static> {
        ContractRequest::Get {
            key: instance,
            return_contract_code: false,
            subscribe: false,
            blocking_subscribe: false,
        }
    }

    async fn link(url: &str) -> Link {
        Link::new(url, Some(Link::open(url).await.unwrap()))
    }

    async fn publisher(url: &str) -> FreenetPublisher {
        FreenetPublisher::new(
            url,
            &ContractWasm {
                address: vec![0, 1, 2, 3],
                tip: vec![4, 5, 6, 7],
                inbox: vec![8, 9, 10, 11],
            },
        )
    }

    /// The PUT's contract. The fake node answers by what it is told to, so
    /// only its shape matters.
    fn container() -> ContractContainer {
        ContractContainer::from(ContractWasmAPIVersion::V1(WrappedContract::new(
            Arc::new(code()),
            Parameters::from(vec![1u8]),
        )))
    }

    /// The first reply comes after its request gave up. The next requests
    /// must each get their own answer, not that late one.
    #[tokio::test]
    async fn a_late_reply_is_never_read_as_the_next_requests_answer() {
        let release = Arc::new(Notify::new());
        let sent = Arc::new(Notify::new());
        let (r, s) = (release.clone(), sent.clone());
        let node = node(Arc::new(move |connection, req| {
            let reply = not_found(asked_id(req));
            if connection == 0 {
                Action::Late {
                    reply,
                    release: r.clone(),
                    sent: s.clone(),
                }
            } else {
                Action::Reply(reply)
            }
        }))
        .await;
        let mut link = link(&node.url).await;

        let first = link.request(get(id(1)), Duration::from_millis(100)).await;
        assert!(
            first.unwrap_err().to_string().contains("timed out waiting"),
            "the held reply must time out"
        );
        release.notify_one();
        sent.notified().await;

        for asked in [id(2), id(3)] {
            let reply = link
                .request(get(asked), Duration::from_secs(5))
                .await
                .expect("a prompt node answers");
            assert_eq!(
                classify_probe_reply(&asked, &reply),
                ProbeReply::Absent,
                "the reply to {asked} must be about {asked}"
            );
        }
        assert_eq!(node.connections.load(Ordering::SeqCst), 2);
    }

    /// The shape of the 2026-09-17 freeze: a node that sends more than one
    /// message per request, so uncollected replies build up.
    ///
    /// The caller here deliberately does NOT discard on an unmatched reply,
    /// which leaves `SEND_TIMEOUT` as the only thing standing between the
    /// link and a wait that never ends. Every request must still return.
    #[tokio::test]
    async fn a_link_never_waits_forever_even_when_replies_pile_up() {
        let node = node(Arc::new(|_, req| {
            Action::Replies(vec![not_found(asked_id(req)), not_found(asked_id(req))])
        }))
        .await;
        let mut link = link(&node.url).await;

        let all = async {
            for n in 1..=12u8 {
                let _ = link.request(get(id(n)), Duration::from_secs(2)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(120), all)
            .await
            .expect("every request returns");
    }

    /// The other half: a caller that does discard never reads a piled-up
    /// reply as the answer to what it asked.
    #[tokio::test]
    async fn a_piled_up_reply_is_never_read_as_another_requests_answer() {
        let node = node(Arc::new(|_, req| {
            Action::Replies(vec![not_found(asked_id(req)), not_found(asked_id(req))])
        }))
        .await;
        let mut link = link(&node.url).await;

        for n in 1..=12u8 {
            let asked = id(n);
            if let Ok(reply) = link.request(get(asked), Duration::from_secs(2)).await {
                match classify_probe_reply(&asked, &reply) {
                    ProbeReply::Unmatched => link.discard(),
                    answer => assert_eq!(answer, ProbeReply::Absent, "request {n}"),
                }
            }
        }
    }

    #[tokio::test]
    async fn an_update_answered_for_another_contract_is_put_on_a_fresh_connection() {
        let asked = key(1);
        let node = node(Arc::new(move |connection, req| match (connection, req) {
            (0, ContractRequest::Update { .. }) => Action::Reply(update_response(key(2))),
            (1, ContractRequest::Put { .. }) => Action::Reply(put_response(asked)),
            _ => Action::Reply(error("unexpected")),
        }))
        .await;
        let publisher = publisher(&node.url).await;

        publisher
            .put_or_update(asked, container(), vec![1])
            .await
            .expect("stored by the PUT");
        assert_eq!(node.connections.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_put_answered_for_another_contract_fails_and_drops_the_connection() {
        let asked = key(1);
        let node = node(Arc::new(move |connection, req| match (connection, req) {
            (0, ContractRequest::Update { .. }) => Action::Reply(not_found(*asked.id())),
            (0, ContractRequest::Put { .. }) => Action::Reply(put_response(key(2))),
            (_, ContractRequest::Get { .. }) => Action::Reply(get_response(asked, vec![5])),
            _ => Action::Reply(error("unexpected")),
        }))
        .await;
        let publisher = publisher(&node.url).await;

        let err = publisher
            .put_or_update(asked, container(), vec![1])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("PutResponse for"), "{err}");
        assert!(
            !link_unusable(&err),
            "a reply about another contract is not the node refusing"
        );
        assert_eq!(publisher.get_state(asked).await.unwrap(), vec![5]);
        assert_eq!(
            node.connections.load(Ordering::SeqCst),
            2,
            "a fresh connection after the bad PUT"
        );
    }

    #[tokio::test]
    async fn a_get_answered_for_another_contract_fails_and_drops_the_connection() {
        let asked = key(1);
        let node = node(Arc::new(move |connection, _| {
            if connection == 0 {
                Action::Reply(get_response(key(2), vec![9]))
            } else {
                Action::Reply(get_response(asked, vec![5]))
            }
        }))
        .await;
        let publisher = publisher(&node.url).await;

        assert!(publisher.get_state(asked).await.is_err());
        assert_eq!(publisher.get_state(asked).await.unwrap(), vec![5]);
        assert_eq!(node.connections.load(Ordering::SeqCst), 2);
    }

    /// **A failure that is about the node stops the caller; one about the
    /// request does not.**
    ///
    /// The round abandons the remaining scripts on the first kind and carries
    /// on for the second, so getting this wrong either starves every later
    /// script (a claim this bridge refuses to publish is permanent and
    /// particular to one address) or hammers a node that has not joined yet,
    /// once per script, every two seconds.
    #[tokio::test]
    async fn a_failure_about_the_node_is_link_unusable_and_backs_off() {
        let node = node(Arc::new(|_, _| {
            Action::Reply(Err(ClientError::from(ErrorKind::PeerNotJoined)))
        }))
        .await;
        let publisher = publisher(&node.url).await;

        let not_joined = publisher.get_state(key(1)).await.unwrap_err();
        assert!(link_unusable(&not_joined), "{not_joined:#}");

        // A node answering "not joined yet" is listening, so the dial
        // succeeds; without arming the backoff the bridge would open a fresh
        // connection per request for the whole of that window.
        let backed_off = publisher.get_state(key(1)).await.unwrap_err();
        assert!(
            format!("{backed_off:#}").contains("next attempt"),
            "{backed_off:#}"
        );
        assert_eq!(
            node.connections.load(Ordering::SeqCst),
            1,
            "the second request did not dial again"
        );
    }

    /// **The wait grows while the node keeps answering that it cannot
    /// serve.**
    ///
    /// It did not, because a node answering "not joined yet" completes the
    /// dial, and the backoff was reset on every successful dial. So the
    /// bridge dialled about once a second for the whole of that window
    /// instead of backing away from it.
    #[tokio::test]
    async fn the_wait_grows_while_the_node_keeps_refusing_to_serve() {
        let node = node(Arc::new(|_, _| {
            Action::Reply(Err(ClientError::from(ErrorKind::EmptyRing)))
        }))
        .await;
        let mut link = link(&node.url).await;

        let mut waits = Vec::new();
        for _ in 0..3 {
            // The reply arms the backoff; the next request is refused by it
            // and says how long is left.
            let _ = link.request(get(id(1)), Duration::from_secs(5)).await;
            let refused = link
                .request(get(id(1)), Duration::from_secs(5))
                .await
                .unwrap_err();
            let text = format!("{refused:#}");
            let ms: u64 = text
                .rsplit_once("in ")
                .and_then(|(_, tail)| tail.trim_end_matches("ms").parse().ok())
                .unwrap_or_else(|| panic!("no wait in {text}"));
            waits.push(ms);
            // Let it expire so the next request reaches the node again.
            tokio::time::sleep(Duration::from_millis(ms + 50)).await;
        }
        assert!(
            waits.windows(2).all(|w| w[1] > w[0]),
            "each wait must be longer than the last: {waits:?}"
        );
    }

    #[tokio::test]
    async fn a_failure_about_the_request_is_not_link_unusable() {
        let asked = key(1);
        let node = node(Arc::new(move |connection, _| {
            if connection == 0 {
                // An answer about another contract: this request's problem,
                // not the node's.
                Action::Reply(get_response(key(2), vec![9]))
            } else {
                Action::Reply(get_response(asked, vec![5]))
            }
        }))
        .await;
        let publisher = publisher(&node.url).await;

        let wrong_contract = publisher.get_state(asked).await.unwrap_err();
        assert!(!link_unusable(&wrong_contract), "{wrong_contract:#}");
        assert_eq!(
            publisher.get_state(asked).await.unwrap(),
            vec![5],
            "so the next request is tried at once, on a fresh connection"
        );
    }

    /// Every kind in the node-level list, and two that are not.
    #[test]
    fn the_node_level_error_kinds_are_the_list_that_decides() {
        for kind in [
            ErrorKind::EmptyRing,
            ErrorKind::PeerNotJoined,
            ErrorKind::NodeUnavailable,
            ErrorKind::Disconnect,
            ErrorKind::ChannelClosed,
            ErrorKind::TransportProtocolDisconnect,
            ErrorKind::Shutdown,
        ] {
            assert!(
                reply_is_about_the_node(&kind),
                "{kind:?} says the next request fails the same way"
            );
        }
        for kind in [
            ErrorKind::FailedOperation,
            ErrorKind::OperationError {
                cause: "a contract refused it".into(),
            },
        ] {
            assert!(
                !reply_is_about_the_node(&kind),
                "{kind:?} is about this request"
            );
        }
    }

    #[tokio::test]
    async fn an_unreachable_node_is_not_dialled_on_every_request() {
        // Accepts TCP and closes at once, so every websocket handshake fails.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/", listener.local_addr().unwrap());
        let dials = Arc::new(AtomicUsize::new(0));
        let counted = dials.clone();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                counted.fetch_add(1, Ordering::SeqCst);
                drop(tcp);
            }
        });
        let mut link = Link::new(&url, None);

        assert!(link
            .request(get(id(1)), Duration::from_secs(1))
            .await
            .is_err());
        let refused = link
            .request(get(id(2)), Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(refused.to_string().contains("next attempt"), "{refused}");
        assert_eq!(
            dials.load(Ordering::SeqCst),
            1,
            "the second request did not dial"
        );
    }
}
