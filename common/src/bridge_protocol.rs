//! The request protocol between a client (a Freenet app's delegate) and a
//! bridge operator's service.
//!
//! # Why this is not a Freenet contract
//!
//! The obvious design is a `WatchRegistry` contract that lists the scripts
//! people want synchronized, which the bridge reads. It is obvious, it is
//! simple, and it is exactly what this project refuses to build: it would
//! publish a globally enumerable, permanently replicated index of which
//! Bitcoin addresses somebody cares about. Freenet contracts are *designed* to
//! be reachable by anyone who knows the key, so "who is watching what" would
//! become a queryable surveillance asset for as long as the network exists.
//!
//! So requests are **ephemeral and point-to-point**: the client speaks
//! directly to a bridge over HTTPS, the bridge notes the script in its own
//! private operational database, and nothing about the request is ever
//! replicated. The bridge learns that *somebody* asked about script X. It is
//! the only party that learns it, and it learns nothing more if it plays by
//! the rules described in `docs/privacy.md`.
//!
//! # The two authorizations, which are not the same thing
//!
//! ```text
//!   service authorization   "May this caller ask THIS bridge to do work?"
//!                           -> lives here, in ServiceAuth. Operator policy.
//!
//!   observation authenticity "Did THIS bridge sign this Bitcoin fact?"
//!                           -> lives in signing.rs. Protocol-level.
//! ```
//!
//! Freenet.org gates its bridge on Ghost Key eligibility because that gives
//! donors something concrete. That is *one operator's policy*, expressed in
//! [`ServiceAuth::GhostKey`]. Another operator can run a byte-compatible
//! bridge with [`ServiceAuth::None`], or add a variant of their own, and every
//! Bitcoin contract in existence keeps working unchanged — because no Ghost
//! Key ever reaches the contracts.

use serde::{Deserialize, Serialize};

use crate::{BitcoinNetwork, BridgeId, Txid};

/// How a caller claims to be entitled to this bridge's service.
///
/// This value never appears in any Freenet contract. It exists only on the
/// direct client→bridge request path.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum ServiceAuth {
    /// The bridge serves anyone. Sensible for a bridge you run for yourself,
    /// or a public one funded some other way.
    None,
    /// The caller holds a Ghost Key — an anonymous certificate proving a
    /// donation to Freenet — and has signed this specific request with it.
    ///
    /// The certificate proves *eligibility*, and the signature proves the
    /// caller holds the corresponding private key right now rather than having
    /// copied a certificate out of somebody else's traffic.
    ///
    /// Note what the bridge deliberately does not receive: any statement of
    /// *why* the caller wants this script, or any link to a Freenet identity,
    /// a Harvest store, or an order.
    GhostKey(GhostKeyAuth),
}

/// A Ghost Key eligibility proof over one specific request.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct GhostKeyAuth {
    /// The ghost key certificate, PEM-armoured, exactly as the holder stores
    /// it. The bridge verifies its chain to the published Freenet.org master
    /// key; that is what makes it a proof of donation.
    pub certificate_pem: String,
    /// A server-issued nonce this signature is bound to.
    ///
    /// Without it, a bridge operator (or anyone who saw one request) could
    /// replay a captured authorization to add scripts the holder never asked
    /// for. The nonce is single-use and short-lived.
    pub challenge: Vec<u8>,
    /// Signature by the ghost key over the domain-separated request bytes.
    /// See [`auth_signing_input`].
    pub signature: Vec<u8>,
}

/// The exact bytes a Ghost Key signs when authorizing a service request.
///
/// Binding the *body* of the request, not just the challenge, is what stops a
/// captured authorization for "watch script A" being reused as "watch script
/// B" or "broadcast transaction T".
pub fn auth_signing_input(challenge: &[u8], request_body_cbor: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(48 + challenge.len() + request_body_cbor.len());
    v.extend_from_slice(b"freenet-bitcoin/service-auth/v1\0");
    v.extend_from_slice(&(challenge.len() as u32).to_le_bytes());
    v.extend_from_slice(challenge);
    v.extend_from_slice(request_body_cbor);
    v
}

/// Ask a bridge to start (or keep) synchronizing a Bitcoin output script.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct WatchRequest {
    pub network: BitcoinNetwork,
    /// Canonical `scriptPubKey` bytes. The bridge derives everything else.
    pub script_pubkey: Vec<u8>,
    /// Optional hint: do not bother scanning for activity before this height.
    ///
    /// A brand-new payment address has no history, so a client that knows the
    /// address was just generated can say so and save the bridge a rescan.
    /// It is a hint only — the bridge is free to ignore it.
    pub scan_from_height: Option<u32>,
}

/// Ask a bridge to relay an already-signed Bitcoin transaction.
///
/// The bridge never signs anything on a user's behalf and never holds a user
/// key. It is a dumb relay: it hands the bytes to Bitcoin Core and reports
/// what Bitcoin Core said.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct BroadcastRequest {
    pub network: BitcoinNetwork,
    /// Fully-signed raw transaction bytes.
    pub raw_tx: Vec<u8>,
}

/// The body of a service request — the part a Ghost Key signature covers.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum RequestBody {
    Watch(WatchRequest),
    Unwatch(WatchRequest),
    Broadcast(BroadcastRequest),
    /// Public, unauthenticated: what network is this bridge on, how fresh is
    /// it, which key does it sign with. Anyone may ask, which is what lets an
    /// application show a live "bridge online, tip 921,004" panel before the
    /// user has authenticated with anything.
    Status,
}

/// A complete request as sent to a bridge.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ServiceRequest {
    pub body: RequestBody,
    pub auth: ServiceAuth,
}

/// A bridge's public self-description. Deliberately free of anything about
/// who uses it.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct BridgeStatus {
    pub bridge: BridgeId,
    pub network: BitcoinNetwork,
    /// Height of the bridge's Bitcoin Core best chain.
    pub tip_height: u32,
    /// Whether Bitcoin Core still considers itself in initial block download.
    /// While true, an absence of payments means nothing.
    pub initial_block_download: bool,
    /// Header timestamp of the tip block. Bitcoin's clock, not the host's.
    pub tip_block_time: u32,
    /// Which authorization schemes this operator accepts, so a client can tell
    /// whether it needs a Ghost Key before it tries.
    pub accepted_auth: Vec<String>,
    /// Freenet contract instance id (bs58) of this network's tip contract, so
    /// a client can subscribe without hardcoding a key.
    pub tip_contract_id: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum ServiceResponse {
    /// The script is now being synchronized. `contract_id` is where the
    /// observations will appear, so the client can subscribe immediately.
    Watching {
        contract_id: String,
        /// Height the bridge will scan from; may differ from the request hint.
        scan_from_height: u32,
        /// True if this bridge was already watching the script for somebody.
        /// Returned so a client can tell "newly started" from "already live",
        /// and deliberately NOT a count — a count would leak how many other
        /// people are interested.
        already_active: bool,
    },
    Unwatched,
    /// Bitcoin Core accepted the transaction, or already had it.
    Broadcast {
        txid: Txid,
        already_known: bool,
    },
    Status(BridgeStatus),
    /// A challenge the client must sign to authenticate. Returned when a
    /// request needs authorization and did not carry a fresh one.
    Challenge {
        challenge: Vec<u8>,
        expires_in_s: u32,
    },
    Error(BridgeError),
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum BridgeError {
    /// Caller is not entitled to this bridge's service. The message is
    /// deliberately generic and identical whether the certificate was absent,
    /// malformed, expired or revoked: a precise error is an oracle for probing
    /// which certificates exist.
    NotAuthorized {
        detail: String,
    },
    /// The challenge was unknown, already used, or expired.
    StaleChallenge,
    /// The bridge is up but cannot answer usefully yet.
    NotSynced {
        tip_height: u32,
    },
    /// Bitcoin Core rejected the transaction. `reason` is passed through
    /// verbatim because a payer genuinely needs it.
    RejectedByNode {
        reason: String,
    },
    /// This operator does not serve that network.
    UnsupportedNetwork,
    /// Too many requests. Applies per-credential and per-source.
    RateLimited {
        retry_after_s: u32,
    },
    Internal {
        detail: String,
    },
}

impl core::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BridgeError::NotAuthorized { detail } => write!(f, "not authorized: {detail}"),
            BridgeError::StaleChallenge => write!(f, "challenge expired or already used"),
            BridgeError::NotSynced { tip_height } => {
                write!(f, "bridge still syncing (at height {tip_height})")
            }
            BridgeError::RejectedByNode { reason } => write!(f, "node rejected: {reason}"),
            BridgeError::UnsupportedNetwork => write!(f, "network not served by this bridge"),
            BridgeError::RateLimited { retry_after_s } => {
                write!(f, "rate limited, retry in {retry_after_s}s")
            }
            BridgeError::Internal { detail } => write!(f, "bridge error: {detail}"),
        }
    }
}

impl std::error::Error for BridgeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::to_cbor;

    #[test]
    fn auth_input_binds_the_request_body() {
        // The property that matters: an authorization captured for one request
        // must not validate a different one.
        let watch_a = to_cbor(&RequestBody::Watch(WatchRequest {
            network: BitcoinNetwork::Signet,
            script_pubkey: vec![1, 2, 3],
            scan_from_height: None,
        }))
        .unwrap();
        let watch_b = to_cbor(&RequestBody::Watch(WatchRequest {
            network: BitcoinNetwork::Signet,
            script_pubkey: vec![9, 9, 9],
            scan_from_height: None,
        }))
        .unwrap();
        let chal = b"nonce".to_vec();
        assert_ne!(
            auth_signing_input(&chal, &watch_a),
            auth_signing_input(&chal, &watch_b)
        );
    }

    #[test]
    fn auth_input_binds_the_challenge() {
        let body = to_cbor(&RequestBody::Status).unwrap();
        assert_ne!(
            auth_signing_input(b"nonce-1", &body),
            auth_signing_input(b"nonce-2", &body)
        );
    }

    #[test]
    fn challenge_length_is_prefixed_so_fields_cannot_be_shifted() {
        // Without the length prefix, ("ab", "cd") and ("a", "bcd") would
        // produce identical signing input, letting a signature move bytes
        // between the challenge and the body.
        let a = auth_signing_input(b"ab", b"cd");
        let b = auth_signing_input(b"a", b"bcd");
        assert_ne!(a, b);
    }

    #[test]
    fn status_request_needs_no_authorization() {
        // Public status is what makes the first-run UI useful before a user
        // has any credential at all, so it must be expressible with no auth.
        let req = ServiceRequest {
            body: RequestBody::Status,
            auth: ServiceAuth::None,
        };
        let round: ServiceRequest = crate::from_cbor(&to_cbor(&req).unwrap()).unwrap();
        assert_eq!(round, req);
    }
}
