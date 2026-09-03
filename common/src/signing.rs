//! Bridge signatures over Bitcoin observations.
//!
//! # What a bridge signature is, and what it is not
//!
//! A bridge signature answers exactly one question: *did this bridge assert
//! this Bitcoin fact?* It says nothing about whether the asserting bridge was
//! entitled to run, who asked it to watch the script, or whether the requester
//! paid, donated or was invited. Those are **service authorization** questions
//! and they live in `bridge_protocol` and in the bridge's own database. They
//! never appear on the Freenet wire.
//!
//! Conflating the two is the single easiest way to wreck this design, because
//! it would make the public Bitcoin contracts carry evidence of who is
//! interested in which address. They must not.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{
    to_cbor, BitcoinAddressParameters, BitcoinTipParameters, BridgeId, ClaimBody, TipEntryBody,
};

/// Domain separator prefixed to every claim signature.
///
/// Without this, a signature over a `ClaimBody` could in principle be
/// presented as a signature over some other CBOR structure that happens to
/// encode identically. The tags also keep claim signatures and tip signatures
/// in disjoint universes.
const CLAIM_DOMAIN: &[u8] = b"freenet-bitcoin/claim/v1\0";
const TIP_DOMAIN: &[u8] = b"freenet-bitcoin/tip/v1\0";

fn signing_input(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(domain.len() + body.len());
    v.extend_from_slice(domain);
    v.extend_from_slice(body);
    v
}

/// A [`ClaimBody`] together with the bridge signature over it.
///
/// The CBOR encoding of `body` is stored verbatim rather than re-serialized at
/// verify time. Re-serializing would make verification depend on the encoder
/// producing byte-identical output forever, which is a fragile promise to make
/// across serde and ciborium upgrades; keeping the signed bytes removes the
/// question entirely.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct SignedClaim {
    /// Canonical CBOR of a [`ClaimBody`], exactly as signed.
    pub body_cbor: Vec<u8>,
    pub bridge: BridgeId,
    pub signature: Vec<u8>,
}

impl SignedClaim {
    pub fn sign(key: &SigningKey, body: &ClaimBody) -> Result<Self, String> {
        let body_cbor = to_cbor(body)?;
        let sig = key.sign(&signing_input(CLAIM_DOMAIN, &body_cbor));
        Ok(SignedClaim {
            body_cbor,
            bridge: BridgeId(key.verifying_key().to_bytes()),
            signature: sig.to_bytes().to_vec(),
        })
    }

    /// Decode the body without checking the signature.
    ///
    /// Only for callers that have already verified, or that are inspecting
    /// untrusted input for diagnostics. Everything that makes a decision must
    /// go through [`SignedClaim::verify`].
    pub fn body(&self) -> Result<ClaimBody, String> {
        crate::from_cbor(&self.body_cbor)
    }

    /// Verify the signature and that the claim belongs to this contract
    /// instance, returning the decoded body.
    ///
    /// Three checks, all of which matter:
    ///
    /// 1. the signing bridge is one this instance trusts;
    /// 2. the signature is valid over the exact signed bytes;
    /// 3. the claim's `script_id` and `network` match these parameters — so a
    ///    validly-signed observation about a *different* address cannot be
    ///    parked in this contract's state.
    pub fn verify(&self, params: &BitcoinAddressParameters) -> Result<ClaimBody, String> {
        if !params.trusts(&self.bridge) {
            return Err(format!(
                "claim signed by untrusted bridge {}",
                self.bridge.to_bs58()
            ));
        }
        let vk = VerifyingKey::from_bytes(&self.bridge.0)
            .map_err(|e| format!("bridge key invalid: {e}"))?;
        let sig_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| "claim signature must be 64 bytes".to_string())?;
        vk.verify(
            &signing_input(CLAIM_DOMAIN, &self.body_cbor),
            &Signature::from_bytes(&sig_bytes),
        )
        .map_err(|e| format!("claim signature invalid: {e}"))?;

        let body: ClaimBody = crate::from_cbor(&self.body_cbor)?;
        if body.network != params.network {
            return Err(format!(
                "claim is for network {:?} but this contract is {:?}",
                body.network, params.network
            ));
        }
        if body.script_id != params.script_id() {
            return Err("claim script_id does not match this contract instance".to_string());
        }

        // A valid signature only establishes that the bridge said this. For a
        // confirmed payment we go further and check the Bitcoin evidence
        // itself, so that a compromised bridge key cannot mint payments that
        // never happened.
        if let crate::Claim::ConfirmedOutput {
            outpoint,
            value_sats,
            anchor,
            spv,
        } = &body.claim
        {
            crate::spv::verify_spv_proof(
                spv,
                &outpoint.txid,
                outpoint.vout,
                &params.script_pubkey,
                *value_sats,
                &anchor.hash,
                params.pow_floor,
            )
            .map_err(|e| format!("bitcoin evidence rejected: {e}"))?;
        }
        Ok(body)
    }

    /// A stable 32-byte identity for this claim, used as the map key in
    /// contract state so that re-delivering the same claim is a no-op.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"freenet-bitcoin/claim-digest/v1");
        h.update(&self.bridge.0);
        h.update(&self.body_cbor);
        h.update(&self.signature);
        *h.finalize().as_bytes()
    }
}

/// A [`TipEntryBody`] together with the bridge signature over it.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct SignedTipEntry {
    pub body_cbor: Vec<u8>,
    pub bridge: BridgeId,
    pub signature: Vec<u8>,
}

impl SignedTipEntry {
    pub fn sign(key: &SigningKey, body: &TipEntryBody) -> Result<Self, String> {
        let body_cbor = to_cbor(body)?;
        let sig = key.sign(&signing_input(TIP_DOMAIN, &body_cbor));
        Ok(SignedTipEntry {
            body_cbor,
            bridge: BridgeId(key.verifying_key().to_bytes()),
            signature: sig.to_bytes().to_vec(),
        })
    }

    pub fn body(&self) -> Result<TipEntryBody, String> {
        crate::from_cbor(&self.body_cbor)
    }

    pub fn verify(&self, params: &BitcoinTipParameters) -> Result<TipEntryBody, String> {
        if !params.trusts(&self.bridge) {
            return Err(format!(
                "tip entry signed by untrusted bridge {}",
                self.bridge.to_bs58()
            ));
        }
        let vk = VerifyingKey::from_bytes(&self.bridge.0)
            .map_err(|e| format!("bridge key invalid: {e}"))?;
        let sig_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| "tip signature must be 64 bytes".to_string())?;
        vk.verify(
            &signing_input(TIP_DOMAIN, &self.body_cbor),
            &Signature::from_bytes(&sig_bytes),
        )
        .map_err(|e| format!("tip signature invalid: {e}"))?;

        let body: TipEntryBody = crate::from_cbor(&self.body_cbor)?;
        if body.network != params.network {
            return Err(format!(
                "tip entry is for network {:?} but this contract is {:?}",
                body.network, params.network
            ));
        }
        Ok(body)
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"freenet-bitcoin/tip-digest/v1");
        h.update(&self.bridge.0);
        h.update(&self.body_cbor);
        h.update(&self.signature);
        *h.finalize().as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BitcoinNetwork, BlockAnchor, BlockHash, Claim, OutPoint, ScriptId, Txid,
    };
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn params(bridges: Vec<BridgeId>) -> BitcoinAddressParameters {
        BitcoinAddressParameters {
            network: BitcoinNetwork::Signet,
            script_pubkey: vec![0x00, 0x14, 0xaa, 0xbb],
            trusted_bridges: bridges,
            pow_floor: crate::PowFloor::NONE,
        }
    }

    fn body_for(p: &BitcoinAddressParameters) -> ClaimBody {
        let (spv, txid, block) =
            crate::spv::testing::payment_proof(&p.script_pubkey, 50_000, 1, [3; 32]);
        ClaimBody {
            script_id: p.script_id(),
            network: p.network,
            as_of: BlockAnchor {
                height: 500,
                hash: BlockHash([3; 32]),
            },
            claim: Claim::ConfirmedOutput {
                outpoint: OutPoint { txid, vout: 0 },
                value_sats: 50_000,
                anchor: BlockAnchor {
                    height: 499,
                    hash: block,
                },
                spv,
            },
        }
    }

    #[test]
    fn roundtrip_verifies() {
        let k = key(1);
        let p = params(vec![BridgeId(k.verifying_key().to_bytes())]);
        let signed = SignedClaim::sign(&k, &body_for(&p)).unwrap();
        assert_eq!(signed.verify(&p).unwrap(), body_for(&p));
    }

    #[test]
    fn untrusted_bridge_is_rejected() {
        let signer = key(1);
        let other = key(2);
        let p = params(vec![BridgeId(other.verifying_key().to_bytes())]);
        let signed = SignedClaim::sign(&signer, &body_for(&p)).unwrap();
        let err = signed.verify(&p).unwrap_err();
        assert!(err.contains("untrusted bridge"), "got: {err}");
    }

    #[test]
    fn tampering_with_the_body_fails() {
        let k = key(1);
        let p = params(vec![BridgeId(k.verifying_key().to_bytes())]);
        let mut signed = SignedClaim::sign(&k, &body_for(&p)).unwrap();
        // Flip a byte inside the signed CBOR: the value being claimed.
        let idx = signed.body_cbor.len() / 2;
        signed.body_cbor[idx] ^= 0xff;
        assert!(signed.verify(&p).is_err(), "tampered body must not verify");
    }

    #[test]
    fn claim_for_another_script_is_rejected() {
        let k = key(1);
        let bid = BridgeId(k.verifying_key().to_bytes());
        let p = params(vec![bid]);
        let mut body = body_for(&p);
        body.script_id = ScriptId([0xff; 32]); // some other address entirely
        let signed = SignedClaim::sign(&k, &body).unwrap();
        let err = signed.verify(&p).unwrap_err();
        assert!(err.contains("script_id"), "got: {err}");
    }

    #[test]
    fn claim_from_another_network_is_rejected() {
        let k = key(1);
        let bid = BridgeId(k.verifying_key().to_bytes());
        let p = params(vec![bid]);
        let mut body = body_for(&p);
        body.network = BitcoinNetwork::Bitcoin;
        let signed = SignedClaim::sign(&k, &body).unwrap();
        assert!(signed.verify(&p).is_err());
    }

    #[test]
    fn tip_and_claim_signatures_do_not_cross_verify() {
        // A signature made in the tip domain must not verify as a claim.
        // Domain separation is the only thing preventing this.
        let k = key(1);
        let bid = BridgeId(k.verifying_key().to_bytes());
        let p = params(vec![bid]);
        let body = body_for(&p);
        let body_cbor = to_cbor(&body).unwrap();
        let wrong = SignedClaim {
            signature: k
                .sign(&signing_input(TIP_DOMAIN, &body_cbor))
                .to_bytes()
                .to_vec(),
            body_cbor,
            bridge: bid,
        };
        assert!(wrong.verify(&p).is_err());
    }

    /// The property the whole SPV layer exists for: a bridge whose key is
    /// TRUSTED and whose signature is VALID still cannot assert a payment that
    /// did not happen. Everything about the signature checks out here; only
    /// the Bitcoin evidence does not.
    #[test]
    fn a_trusted_bridge_cannot_mint_a_payment_that_never_happened() {
        let k = key(1);
        let p = params(vec![BridgeId(k.verifying_key().to_bytes())]);

        // Real proof, but for a transaction paying 1 sat.
        let (spv, txid, block) =
            crate::spv::testing::payment_proof(&p.script_pubkey, 1, 1, [3; 32]);

        // The bridge claims it was 50,000.
        let lie = ClaimBody {
            script_id: p.script_id(),
            network: p.network,
            as_of: BlockAnchor { height: 500, hash: BlockHash([3; 32]) },
            claim: Claim::ConfirmedOutput {
                outpoint: OutPoint { txid, vout: 0 },
                value_sats: 50_000,
                anchor: BlockAnchor { height: 499, hash: block },
                spv,
            },
        };
        let signed = SignedClaim::sign(&k, &lie).unwrap();
        let err = signed.verify(&p).unwrap_err();
        assert!(err.contains("bitcoin evidence rejected"), "got: {err}");
    }

    /// Likewise it cannot redirect somebody else's payment to this address.
    #[test]
    fn a_trusted_bridge_cannot_repoint_another_addresss_payment_here() {
        let k = key(1);
        let p = params(vec![BridgeId(k.verifying_key().to_bytes())]);

        // A genuine payment -- to a DIFFERENT script.
        let (spv, txid, block) =
            crate::spv::testing::payment_proof(&[0x00, 0x14, 0x99, 0x88], 50_000, 1, [4; 32]);

        let lie = ClaimBody {
            script_id: p.script_id(),
            network: p.network,
            as_of: BlockAnchor { height: 500, hash: BlockHash([3; 32]) },
            claim: Claim::ConfirmedOutput {
                outpoint: OutPoint { txid, vout: 0 },
                value_sats: 50_000,
                anchor: BlockAnchor { height: 499, hash: block },
                spv,
            },
        };
        let signed = SignedClaim::sign(&k, &lie).unwrap();
        assert!(signed.verify(&p).is_err());
    }

    #[test]
    fn digest_is_stable_and_distinguishes_claims() {
        let k = key(1);
        let p = params(vec![BridgeId(k.verifying_key().to_bytes())]);
        let a = SignedClaim::sign(&k, &body_for(&p)).unwrap();
        let b = SignedClaim::sign(&k, &body_for(&p)).unwrap();
        assert_eq!(a.digest(), b.digest(), "same claim -> same digest");

        let mut other_body = body_for(&p);
        other_body.as_of.height = 501;
        let c = SignedClaim::sign(&k, &other_body).unwrap();
        assert_ne!(a.digest(), c.digest());
    }
}
