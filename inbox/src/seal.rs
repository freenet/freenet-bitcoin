//! Sealing a request so only the bridge can read it.
//!
//! The bridge's encryption key is derived from its Ed25519 identity, the key
//! that already signs every claim it publishes. A sender therefore needs
//! nothing beyond the bridge id it already trusts: no lookup, no status
//! endpoint, no second key to discover.
//!
//! The scheme: an ephemeral X25519 agreement with the bridge's key, a key
//! derived by BLAKE3 from the shared secret and both public keys, and
//! ChaCha20-Poly1305 with the bridge id as associated data, so a sealed
//! request cannot be moved to another bridge's inbox and still open.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{SigningKey, VerifyingKey};
use freenet_bitcoin_common::{from_cbor, to_cbor, BridgeId};
use rand_core::{OsRng, RngCore};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::{ByteBuf, EphemeralKey, InboxRequest, Sealed};

const SEAL_KEY_DOMAIN: &str = "freenet-bitcoin/inbox-seal/v1";

/// The X25519 key requests to `bridge` are sealed to.
pub fn bridge_encryption_key(bridge: &BridgeId) -> Result<PublicKey, String> {
    let vk = VerifyingKey::from_bytes(&bridge.0).map_err(|_| "bridge id is not a valid key")?;
    Ok(PublicKey::from(vk.to_montgomery().to_bytes()))
}

/// The bridge's side of that key.
pub fn bridge_decryption_key(signing: &SigningKey) -> StaticSecret {
    StaticSecret::from(signing.to_scalar_bytes())
}

fn seal_key(shared: &[u8; 32], ephemeral: &[u8; 32], recipient: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(SEAL_KEY_DOMAIN);
    h.update(shared);
    h.update(ephemeral);
    h.update(recipient);
    *h.finalize().as_bytes()
}

/// Seal `request` so only `bridge` can open it.
pub fn seal(bridge: &BridgeId, request: &InboxRequest) -> Result<Sealed, String> {
    request.check()?;
    let recipient = bridge_encryption_key(bridge)?;
    let eph = EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph);
    let shared = eph.diffie_hellman(&recipient);
    // A low-order recipient point would make the "shared" secret a constant
    // anyone can compute.
    if !shared.was_contributory() {
        return Err("bridge key is a low-order point".into());
    }
    let key = seal_key(shared.as_bytes(), eph_pub.as_bytes(), recipient.as_bytes());
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let plaintext = to_cbor(request)?;
    let ciphertext = ChaCha20Poly1305::new(Key::from_slice(&key))
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &bridge.0,
            },
        )
        .map_err(|_| "sealing failed")?;
    Ok(Sealed {
        ephemeral: EphemeralKey(*eph_pub.as_bytes()),
        nonce: ByteBuf(nonce.to_vec()),
        ciphertext: ByteBuf(ciphertext),
    })
}

/// Open a request sealed to this bridge.
pub fn unseal(signing: &SigningKey, sealed: &Sealed) -> Result<InboxRequest, String> {
    let secret = bridge_decryption_key(signing);
    let recipient = PublicKey::from(&secret);
    let bridge = BridgeId(signing.verifying_key().to_bytes());
    let shared = secret.diffie_hellman(&PublicKey::from(sealed.ephemeral.0));
    if !shared.was_contributory() {
        return Err("sender key is a low-order point".into());
    }
    if sealed.nonce.len() != 12 {
        return Err("nonce must be 12 bytes".into());
    }
    let key = seal_key(shared.as_bytes(), &sealed.ephemeral.0, recipient.as_bytes());
    let plaintext = ChaCha20Poly1305::new(Key::from_slice(&key))
        .decrypt(
            Nonce::from_slice(&sealed.nonce),
            Payload {
                msg: &sealed.ciphertext,
                aad: &bridge.0,
            },
        )
        .map_err(|_| "request does not open with this bridge's key")?;
    let request: InboxRequest = from_cbor(&plaintext)?;
    request.check()?;
    Ok(request)
}
