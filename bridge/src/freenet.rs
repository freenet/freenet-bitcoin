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

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use freenet_bitcoin_common::{
    to_cbor, BitcoinAddressParameters, BitcoinTipParameters, SignedClaim, SignedTipEntry,
};
use freenet_stdlib::client_api::{
    ClientRequest, ContractRequest, ContractResponse, HostResponse, WebApi,
};
use freenet_stdlib::prelude::{
    ContractCode, ContractContainer, ContractInstanceId, ContractKey, ContractWasmAPIVersion,
    Parameters, UpdateData, WrappedContract, WrappedState,
};
use tokio::sync::Mutex;

const REQUEST_TIMEOUT_S: u64 = 60;

/// A connection to a local Freenet node, plus the contract WASM needed to
/// derive keys and to PUT a contract that does not exist yet.
pub struct FreenetPublisher {
    api: Arc<Mutex<WebApi>>,
    address_code: Arc<ContractCode<'static>>,
    tip_code: Arc<ContractCode<'static>>,
}

impl FreenetPublisher {
    pub async fn connect(ws_url: &str, address_wasm: Vec<u8>, tip_wasm: Vec<u8>) -> Result<Self> {
        let (stream, _) = tokio_tungstenite::connect_async(ws_url)
            .await
            .with_context(|| format!("connecting to the Freenet node at {ws_url}"))?;
        Ok(FreenetPublisher {
            api: Arc::new(Mutex::new(WebApi::start(stream))),
            address_code: Arc::new(ContractCode::from(address_wasm)),
            tip_code: Arc::new(ContractCode::from(tip_wasm)),
        })
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
    /// so the bridge publishes it in its status response rather than making
    /// every client hardcode it — a hardcoded code hash goes stale silently on
    /// the next rebuild.
    pub fn address_code_hash(&self) -> [u8; 32] {
        let bytes: &[u8] = self.address_code.hash().as_ref();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes[..32]);
        out
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
        let mut api = self.api.lock().await;

        let update = ContractRequest::Update {
            key,
            data: UpdateData::State(state_bytes.clone().into()),
        };
        api.send(ClientRequest::ContractOp(update))
            .await
            .map_err(|e| anyhow!("sending UPDATE: {e}"))?;

        match tokio::time::timeout(
            std::time::Duration::from_secs(REQUEST_TIMEOUT_S),
            api.recv(),
        )
        .await
        {
            Ok(Ok(HostResponse::ContractResponse(ContractResponse::UpdateResponse { .. }))) => {
                return Ok(())
            }
            Ok(Ok(_other)) => {
                // Anything else -- most often "contract not found" -- means the
                // instance does not exist yet, so fall through to PUT.
            }
            Ok(Err(e)) => {
                tracing::debug!("UPDATE rejected ({e}); falling back to PUT");
            }
            Err(_) => return Err(anyhow!("timed out waiting for UPDATE response")),
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
        api.send(ClientRequest::ContractOp(put))
            .await
            .map_err(|e| anyhow!("sending PUT: {e}"))?;

        match tokio::time::timeout(
            std::time::Duration::from_secs(REQUEST_TIMEOUT_S),
            api.recv(),
        )
        .await
        {
            Ok(Ok(HostResponse::ContractResponse(ContractResponse::PutResponse { .. }))) => Ok(()),
            Ok(Ok(other)) => Err(anyhow!("unexpected response to PUT: {other:?}")),
            Ok(Err(e)) => Err(anyhow!("PUT failed: {e}")),
            Err(_) => Err(anyhow!("timed out waiting for PUT response")),
        }
    }

    /// Fetch a contract's current state from the network.
    ///
    /// Used by `verify`, which exists so an operator can confirm that
    /// observations actually became retrievable Freenet state rather than
    /// merely being accepted by the local node. "The PUT returned Ok" and
    /// "the data is readable" are different claims, and only the second one
    /// means the integration works.
    pub async fn get_state(&self, key: ContractKey) -> Result<Vec<u8>> {
        let mut api = self.api.lock().await;
        api.send(ClientRequest::ContractOp(ContractRequest::Get {
            key: key.into(),
            return_contract_code: false,
            subscribe: false,
            blocking_subscribe: false,
        }))
        .await
        .map_err(|e| anyhow!("sending GET: {e}"))?;

        match tokio::time::timeout(
            std::time::Duration::from_secs(REQUEST_TIMEOUT_S),
            api.recv(),
        )
        .await
        {
            Ok(Ok(HostResponse::ContractResponse(ContractResponse::GetResponse {
                state, ..
            }))) => Ok(state.as_ref().to_vec()),
            Ok(Ok(other)) => Err(anyhow!("unexpected response to GET: {other:?}")),
            Ok(Err(e)) => Err(anyhow!("GET failed: {e}")),
            Err(_) => Err(anyhow!("timed out waiting for GET response")),
        }
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
