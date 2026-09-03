//! The bridge's request API.
//!
//! # Why this is an ordinary HTTP service and not a Freenet contract
//!
//! Because a contract would be *replicated*. A `WatchRegistry` contract
//! listing the scripts people want synchronized would be a permanent,
//! globally enumerable index of who cares about which Bitcoin address — the
//! one thing this design refuses to produce. Freenet contracts are reachable
//! by anyone who knows the key, so "just put it in a contract" is not a
//! neutral implementation choice here.
//!
//! So requests are ephemeral and point-to-point. The bridge notes the script
//! in its own private database and nothing about the request is ever
//! replicated. What leaks, and to whom, is written up in `docs/privacy.md`
//! rather than glossed over: the operator of a bridge you use learns that
//! somebody it authorized asked about script X, and can link one user's
//! requests to each other via the Ghost Key fingerprint.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use freenet_bitcoin_common::bridge_protocol::{
    BridgeStatus, RequestBody, ServiceRequest, ServiceResponse,
};
use freenet_bitcoin_common::{to_cbor, BitcoinNetwork, BridgeError};

use crate::auth::{self, Authorized, CHALLENGE_TTL_MS};
use crate::config::{AuthPolicy, BridgeConfig};
use crate::observer::Observer;
use crate::signer::Signer;
use crate::store::{Store, WatchedScript};

pub struct ServiceState {
    pub cfg: BridgeConfig,
    pub signer: Signer,
    /// One observer per configured network.
    pub observers: Vec<Observer>,
    /// Guarded because SQLite connections are not `Sync`.
    pub store: std::sync::Mutex<Store>,
    /// Address-contract code hash, published so clients derive contract keys
    /// rather than hardcoding one that goes stale on the next rebuild.
    pub address_code_hash: Option<[u8; 32]>,
    pub tip_contract_ids: std::collections::HashMap<BitcoinNetwork, String>,
}

impl ServiceState {
    fn observer(&self, net: BitcoinNetwork) -> Option<&Observer> {
        self.observers.iter().find(|o| o.network() == net)
    }
}

pub fn router(state: Arc<ServiceState>) -> Router {
    Router::new()
        .route("/v1/status", get(status))
        .route("/v1/challenge", post(challenge))
        .route("/v1/request", post(handle))
        .with_state(state)
        // Bound the body so a hostile caller cannot make the bridge buffer an
        // arbitrary amount of memory. A broadcast request carries a raw
        // transaction, so the cap has to clear Bitcoin's 1MB tx limit.
        .layer(tower_http::limit::RequestBodyLimitLayer::new(2 * 1024 * 1024))
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Public, unauthenticated status.
///
/// Deliberately requires no credential: it is what lets an application render
/// a live "bridge online, tip 921,004" panel before the user has authenticated
/// with anything, so the feature is discoverable rather than hidden behind a
/// paywall. It reveals nothing about who uses the bridge.
async fn status(State(st): State<Arc<ServiceState>>) -> impl IntoResponse {
    let mut out = Vec::new();
    for obs in &st.observers {
        let (tip, ibd) = match (obs.chain.tip(), obs.chain.in_initial_block_download()) {
            (Ok(t), Ok(i)) => (t, i),
            _ => continue,
        };
        out.push(BridgeStatus {
            bridge: st.signer.bridge_id(),
            network: obs.network(),
            tip_height: tip.height,
            initial_block_download: ibd,
            tip_block_time: 0,
            accepted_auth: vec![match st.cfg.auth {
                AuthPolicy::Open => "none".to_string(),
                AuthPolicy::GhostKey { .. } => "ghostkey".to_string(),
            }],
            tip_contract_id: st.tip_contract_ids.get(&obs.network()).cloned(),
        });
    }
    Json(serde_json::json!({
        "bridge_id": st.signer.bridge_id().to_bs58(),
        "address_code_hash": st.address_code_hash.map(hex::encode),
        "networks": out.iter().map(|s| serde_json::json!({
            "network": s.network.as_str(),
            "tip_height": s.tip_height,
            "initial_block_download": s.initial_block_download,
            "accepted_auth": s.accepted_auth,
            "tip_contract_id": s.tip_contract_id,
        })).collect::<Vec<_>>(),
    }))
}

/// Issue a single-use challenge.
///
/// Unauthenticated by necessity — the caller cannot authenticate until it has
/// one. Cheap and self-expiring, so handing them out freely costs nothing.
async fn challenge(State(st): State<Arc<ServiceState>>) -> impl IntoResponse {
    let c = auth::new_challenge();
    let now = now_ms();
    {
        let store = st.store.lock().expect("store mutex poisoned");
        let _ = store.purge_expired_challenges(now, CHALLENGE_TTL_MS);
        if let Err(e) = store.issue_challenge(&c, now) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            );
        }
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "challenge": hex::encode(&c),
            "expires_in_s": CHALLENGE_TTL_MS / 1000,
        })),
    )
}

async fn handle(
    State(st): State<Arc<ServiceState>>,
    Json(req): Json<ServiceRequest>,
) -> impl IntoResponse {
    let resp = process(&st, req).await;
    let code = match &resp {
        ServiceResponse::Error(BridgeError::NotAuthorized { .. }) => StatusCode::FORBIDDEN,
        ServiceResponse::Error(BridgeError::StaleChallenge) => StatusCode::UNAUTHORIZED,
        ServiceResponse::Error(BridgeError::RateLimited { .. }) => StatusCode::TOO_MANY_REQUESTS,
        ServiceResponse::Error(BridgeError::Internal { .. }) => StatusCode::INTERNAL_SERVER_ERROR,
        ServiceResponse::Error(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::OK,
    };
    (code, Json(resp))
}

async fn process(st: &Arc<ServiceState>, req: ServiceRequest) -> ServiceResponse {
    // Status is public. Authorizing it would make the integration undiscoverable
    // to anyone who has not already donated, which is the opposite of the point.
    if matches!(req.body, RequestBody::Status) {
        let Some(obs) = st.observers.first() else {
            return ServiceResponse::Error(BridgeError::UnsupportedNetwork);
        };
        let tip = obs.chain.tip().unwrap_or_default();
        let ibd = obs.chain.in_initial_block_download().unwrap_or(true);
        return ServiceResponse::Status(BridgeStatus {
            bridge: st.signer.bridge_id(),
            network: obs.network(),
            tip_height: tip.height,
            initial_block_download: ibd,
            tip_block_time: 0,
            accepted_auth: vec![match st.cfg.auth {
                AuthPolicy::Open => "none".into(),
                AuthPolicy::GhostKey { .. } => "ghostkey".into(),
            }],
            tip_contract_id: st.tip_contract_ids.get(&obs.network()).cloned(),
        });
    }

    // The signature must cover the exact body bytes, so a captured
    // authorization for one request cannot be replayed as another.
    let body_cbor = match to_cbor(&req.body) {
        Ok(b) => b,
        Err(e) => return ServiceResponse::Error(BridgeError::Internal { detail: e }),
    };

    let authorized = {
        let store = st.store.lock().expect("store mutex poisoned");
        match auth::authorize(&st.cfg.auth, &req.auth, &body_cbor, &store, now_ms()) {
            Ok(a) => a,
            Err(e) => return ServiceResponse::Error(e),
        }
    };
    tracing::debug!(?authorized, "request authorized");

    match req.body {
        RequestBody::Status => unreachable!("handled above"),

        RequestBody::Watch(w) => {
            let Some(obs) = st.observer(w.network) else {
                return ServiceResponse::Error(BridgeError::UnsupportedNetwork);
            };
            let tip = match obs.chain.tip() {
                Ok(t) => t,
                Err(e) => {
                    return ServiceResponse::Error(BridgeError::Internal {
                        detail: e.to_string(),
                    })
                }
            };
            // A hint above our tip would silently blind us, so clamp it.
            let scan_from = w.scan_from_height.unwrap_or(tip.height).min(tip.height);

            let store = st.store.lock().expect("store mutex poisoned");
            let already = match store.add_watch(
                &WatchedScript {
                    network: w.network,
                    script_pubkey: w.script_pubkey.clone(),
                    scan_from_height: scan_from,
                    is_public_demo: false,
                },
                now_ms(),
            ) {
                Ok(a) => a,
                Err(e) => {
                    return ServiceResponse::Error(BridgeError::Internal {
                        detail: e.to_string(),
                    })
                }
            };

            let contract_id = st
                .address_code_hash
                .and_then(|h| {
                    crate::freenet::address_instance_id(
                        &h,
                        &obs.address_params(&w.script_pubkey, st.signer.bridge_id()),
                    )
                    .ok()
                })
                .map(|id| id.to_string())
                .unwrap_or_default();

            ServiceResponse::Watching {
                contract_id,
                scan_from_height: scan_from,
                // A boolean, never a count. A count would tell the caller how
                // many other people are watching the same address.
                already_active: already,
            }
        }

        RequestBody::Unwatch(w) => {
            let store = st.store.lock().expect("store mutex poisoned");
            match store.remove_watch(w.network, &w.script_pubkey) {
                Ok(()) => ServiceResponse::Unwatched,
                Err(e) => ServiceResponse::Error(BridgeError::Internal {
                    detail: e.to_string(),
                }),
            }
        }

        RequestBody::Broadcast(b) => {
            let Some(obs) = st.observer(b.network) else {
                return ServiceResponse::Error(BridgeError::UnsupportedNetwork);
            };
            // The bridge relays bytes it did not create and cannot sign. The
            // user's keys never come near it.
            match obs.chain.broadcast(&b.raw_tx) {
                Ok((txid, already_known)) => ServiceResponse::Broadcast {
                    txid,
                    already_known,
                },
                Err(e) => ServiceResponse::Error(BridgeError::RejectedByNode {
                    reason: e.to_string(),
                }),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use freenet_bitcoin_common::bridge_protocol::ServiceAuth;
    use freenet_bitcoin_common::WatchRequest;

    /// A watch response must never disclose how many others watch the script.
    /// `already_active` is a boolean for exactly this reason.
    #[test]
    fn the_watch_response_carries_no_watcher_count() {
        let r = ServiceResponse::Watching {
            contract_id: "abc".into(),
            scan_from_height: 100,
            already_active: true,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("count"), "watcher count leaked: {json}");
        assert!(!json.contains("watchers"), "watcher list leaked: {json}");
    }

    /// Nothing on the request path carries a private label, an order id, or a
    /// Freenet identity. The bridge learns the script and nothing about why.
    #[test]
    fn a_watch_request_carries_only_the_script() {
        let req = ServiceRequest {
            body: RequestBody::Watch(WatchRequest {
                network: BitcoinNetwork::Signet,
                script_pubkey: vec![1, 2, 3],
                scan_from_height: Some(100),
            }),
            auth: ServiceAuth::None,
        };
        let json = serde_json::to_string(&req).unwrap();
        for forbidden in ["label", "order", "fingerprint", "user"] {
            assert!(
                !json.contains(forbidden),
                "request format has a field for `{forbidden}`: {json}"
            );
        }
    }

    #[test]
    fn status_needs_no_credential() {
        let req = ServiceRequest {
            body: RequestBody::Status,
            auth: ServiceAuth::None,
        };
        // Round-trips as-is, and `process` short-circuits before authorize().
        let bytes = serde_json::to_vec(&req).unwrap();
        let back: ServiceRequest = serde_json::from_slice(&bytes).unwrap();
        assert!(matches!(back.body, RequestBody::Status));
    }
}
