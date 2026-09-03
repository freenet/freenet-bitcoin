//! Service authorization: may this caller ask THIS bridge to do work?
//!
//! # The distinction this module exists to protect
//!
//! ```text
//!   service authorization    "May this caller ask me to synchronize X?"
//!                            -> here. Operator policy. Never on the wire.
//!
//!   observation authenticity "Did this bridge sign this Bitcoin fact?"
//!                            -> signer.rs. Protocol-level. Always on the wire.
//! ```
//!
//! They are constantly confused and must not be. If a Ghost Key ever reached a
//! Bitcoin contract, the public network would carry evidence of who is
//! interested in which address — the exact surveillance index this whole
//! design refuses to build. Nothing in this module produces a value that is
//! published anywhere.
//!
//! Freenet.org gates its bridge on Ghost Key eligibility because that gives
//! donors something concrete for their donation. That is one operator's
//! policy. [`AuthPolicy::Open`] is equally valid and equally supported, and a
//! bridge running it emits byte-identical observations.

use anyhow::Result;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use freenet_bitcoin_common::bridge_protocol::{auth_signing_input, GhostKeyAuth, ServiceAuth};
use freenet_bitcoin_common::BridgeError;
use ghostkey_lib::armorable::Armorable;
use ghostkey_lib::ghost_key_certificate::GhostkeyCertificateV1;

use crate::config::AuthPolicy;
use crate::store::Store;

/// How long an issued challenge stays usable.
///
/// Short, because its only job is to prove the holder is acting now. Long
/// enough that a slow delegate round-trip does not fail.
pub const CHALLENGE_TTL_MS: i64 = 120_000;

/// Bytes of entropy in a challenge.
pub const CHALLENGE_LEN: usize = 32;

/// What the bridge concluded about a caller.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Authorized {
    /// The operator serves everyone.
    Open,
    /// A valid Ghost Key holder.
    ///
    /// `fingerprint` is a stable identifier for this credential. The bridge
    /// needs it for rate limiting, and holding it is exactly why
    /// `docs/privacy.md` says a bridge operator can correlate one user's
    /// requests with each other. It is never published.
    GhostKey { fingerprint: String },
}

pub fn new_challenge() -> Vec<u8> {
    use rand::RngCore;
    let mut b = vec![0u8; CHALLENGE_LEN];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

/// Fingerprint a ghost key's verifying key: BLAKE3, base58, truncated.
///
/// Used only as a local database key and rate-limit bucket.
pub fn fingerprint(vk: &VerifyingKey) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"freenet-bitcoin/ghostkey-fp/v1");
    h.update(vk.as_bytes());
    bs58::encode(&h.finalize().as_bytes()[..16]).into_string()
}

/// Decide whether a request is authorized under this operator's policy.
///
/// `request_body_cbor` is the exact encoded request body the signature must
/// cover, so an authorization captured for "watch A" cannot be replayed as
/// "watch B" or "broadcast T".
pub fn authorize(
    policy: &AuthPolicy,
    auth: &ServiceAuth,
    request_body_cbor: &[u8],
    store: &Store,
    now_ms: i64,
) -> Result<Authorized, BridgeError> {
    match policy {
        AuthPolicy::Open => Ok(Authorized::Open),
        AuthPolicy::GhostKey {
            master_verifying_key_b64,
        } => {
            let ServiceAuth::GhostKey(gk) = auth else {
                return Err(BridgeError::NotAuthorized {
                    detail: "this bridge serves Ghost Key holders".to_string(),
                });
            };
            verify_ghost_key(
                gk,
                master_verifying_key_b64.as_deref(),
                request_body_cbor,
                store,
                now_ms,
            )
        }
    }
}

fn verify_ghost_key(
    gk: &GhostKeyAuth,
    master_b64: Option<&str>,
    request_body_cbor: &[u8],
    store: &Store,
    now_ms: i64,
) -> Result<Authorized, BridgeError> {
    // Consume the challenge FIRST, and atomically. If it were checked after
    // the (relatively expensive) certificate verification, an attacker could
    // use the bridge as a signature-verification oracle; and if consumption
    // were not atomic, two concurrent requests could both spend one challenge.
    if !store
        .consume_challenge(&gk.challenge, now_ms, CHALLENGE_TTL_MS)
        .map_err(|e| BridgeError::Internal {
            detail: e.to_string(),
        })?
    {
        return Err(BridgeError::StaleChallenge);
    }

    // Every failure below returns the same generic message. A precise error
    // ("expired certificate", "unknown notary") would be an oracle letting an
    // attacker probe which certificates exist and what state they are in.
    let deny = || BridgeError::NotAuthorized {
        detail: "a valid Ghost Key is required for this bridge's service".to_string(),
    };

    let cert =
        GhostkeyCertificateV1::from_armored_string(&gk.certificate_pem).map_err(|_| deny())?;

    let master = match master_b64 {
        Some(b64) => Some(VerifyingKey::from_base64(b64).map_err(|_| deny())?),
        // None means "use the key compiled into ghostkey_lib", which is
        // Freenet's published master key.
        None => None,
    };
    cert.verify(&master).map_err(|_| deny())?;

    // The certificate proves eligibility. It does NOT prove the caller holds
    // the corresponding private key -- a certificate is not secret, and one
    // copied from somebody else's traffic would otherwise work. The signature
    // over (challenge, request body) is what proves live possession.
    let sig_bytes: [u8; 64] = gk.signature.as_slice().try_into().map_err(|_| deny())?;
    let input = auth_signing_input(&gk.challenge, request_body_cbor);
    cert.verifying_key
        .verify(&input, &Signature::from_bytes(&sig_bytes))
        .map_err(|_| deny())?;

    Ok(Authorized::GhostKey {
        fingerprint: fingerprint(&cert.verifying_key),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use freenet_bitcoin_common::bridge_protocol::RequestBody;
    use freenet_bitcoin_common::{to_cbor, BitcoinNetwork, WatchRequest};

    fn body() -> Vec<u8> {
        to_cbor(&RequestBody::Watch(WatchRequest {
            network: BitcoinNetwork::Signet,
            script_pubkey: vec![1, 2, 3],
            scan_from_height: None,
        }))
        .unwrap()
    }

    #[test]
    fn an_open_bridge_serves_a_caller_with_no_credential() {
        // A bridge anybody can run, with no donation policy, must work.
        let store = Store::open_in_memory().unwrap();
        assert_eq!(
            authorize(&AuthPolicy::Open, &ServiceAuth::None, &body(), &store, 0).unwrap(),
            Authorized::Open
        );
    }

    #[test]
    fn a_ghost_key_bridge_refuses_a_caller_with_no_credential() {
        let store = Store::open_in_memory().unwrap();
        let policy = AuthPolicy::GhostKey {
            master_verifying_key_b64: None,
        };
        assert!(matches!(
            authorize(&policy, &ServiceAuth::None, &body(), &store, 0),
            Err(BridgeError::NotAuthorized { .. })
        ));
    }

    #[test]
    fn a_challenge_that_was_never_issued_is_refused() {
        let store = Store::open_in_memory().unwrap();
        let policy = AuthPolicy::GhostKey {
            master_verifying_key_b64: None,
        };
        let gk = GhostKeyAuth {
            certificate_pem: "not a certificate".into(),
            challenge: b"never issued".to_vec(),
            signature: vec![0u8; 64],
        };
        assert_eq!(
            authorize(&policy, &ServiceAuth::GhostKey(gk), &body(), &store, 0),
            Err(BridgeError::StaleChallenge)
        );
    }

    #[test]
    fn a_challenge_is_consumed_even_when_the_certificate_is_bad() {
        // Otherwise a challenge could be probed repeatedly with different
        // certificates, turning the bridge into a verification oracle.
        let store = Store::open_in_memory().unwrap();
        store.issue_challenge(b"c1", 0).unwrap();
        let policy = AuthPolicy::GhostKey {
            master_verifying_key_b64: None,
        };
        let gk = GhostKeyAuth {
            certificate_pem: "garbage".into(),
            challenge: b"c1".to_vec(),
            signature: vec![0u8; 64],
        };
        let first = authorize(
            &policy,
            &ServiceAuth::GhostKey(gk.clone()),
            &body(),
            &store,
            0,
        );
        assert!(matches!(first, Err(BridgeError::NotAuthorized { .. })));
        let second = authorize(&policy, &ServiceAuth::GhostKey(gk), &body(), &store, 0);
        assert_eq!(
            second,
            Err(BridgeError::StaleChallenge),
            "the challenge must be spent by the first attempt"
        );
    }

    #[test]
    fn the_denial_message_does_not_reveal_why() {
        // A precise reason would let an attacker distinguish "no such
        // certificate" from "expired" from "wrong notary".
        let store = Store::open_in_memory().unwrap();
        store.issue_challenge(b"c1", 0).unwrap();
        let policy = AuthPolicy::GhostKey {
            master_verifying_key_b64: None,
        };
        let gk = GhostKeyAuth {
            certificate_pem: "garbage".into(),
            challenge: b"c1".to_vec(),
            signature: vec![0u8; 64],
        };
        let Err(BridgeError::NotAuthorized { detail }) =
            authorize(&policy, &ServiceAuth::GhostKey(gk), &body(), &store, 0)
        else {
            panic!("expected NotAuthorized");
        };
        assert!(!detail.to_lowercase().contains("parse"));
        assert!(!detail.to_lowercase().contains("expired"));
        assert!(!detail.to_lowercase().contains("notary"));
    }

    #[test]
    fn fingerprints_are_stable_and_distinguish_keys() {
        let a = SigningKey::from_bytes(&[1; 32]).verifying_key();
        let b = SigningKey::from_bytes(&[2; 32]).verifying_key();
        assert_eq!(fingerprint(&a), fingerprint(&a));
        assert_ne!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn challenges_are_unpredictable_and_long_enough() {
        let a = new_challenge();
        assert_eq!(a.len(), CHALLENGE_LEN);
        assert_ne!(a, new_challenge());
    }

    /// The core replay property, tested with a real Ed25519 key standing in
    /// for a ghost key: a signature over one request body must not authorize a
    /// different one. (The full path also checks the certificate chain, which
    /// needs a real Freenet-issued certificate we cannot mint in a unit test.)
    #[test]
    fn a_signature_for_one_request_does_not_authorize_another() {
        let sk = SigningKey::from_bytes(&[9; 32]);
        let challenge = new_challenge();
        let body_a = body();
        let body_b = to_cbor(&RequestBody::Watch(WatchRequest {
            network: BitcoinNetwork::Signet,
            script_pubkey: vec![9, 9, 9],
            scan_from_height: None,
        }))
        .unwrap();

        let sig = sk.sign(&auth_signing_input(&challenge, &body_a));
        assert!(sk
            .verifying_key()
            .verify(&auth_signing_input(&challenge, &body_a), &sig)
            .is_ok());
        assert!(
            sk.verifying_key()
                .verify(&auth_signing_input(&challenge, &body_b), &sig)
                .is_err(),
            "a captured authorization must not transfer to another request"
        );
    }
}
