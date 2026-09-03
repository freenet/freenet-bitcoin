//! The bridge's observation-signing key.
//!
//! This key answers "did THIS bridge assert this Bitcoin fact". It is not a
//! Bitcoin key, holds no funds, and can move no money. Compromising it lets an
//! attacker sign false assertions — which the SPV evidence carried inside each
//! claim then refutes, because a reader checks the transaction and the
//! proof-of-work rather than the signature alone. That is the point of pairing
//! the two.

use std::path::Path;

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use freenet_bitcoin_common::BridgeId;

pub struct Signer {
    key: SigningKey,
}

impl Signer {
    /// Load the key, creating one on first run.
    ///
    /// Written 0600. A bridge that silently regenerated its key would change
    /// its `BridgeId`, and every application trusting the old id would quietly
    /// stop believing its observations — a failure that looks like "the bridge
    /// went down" rather than "the key changed", so it is worth being loud.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            let raw = std::fs::read(path)
                .with_context(|| format!("reading signing key {}", path.display()))?;
            let bytes: [u8; 32] = raw
                .get(..32)
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "{} is not a 32-byte Ed25519 seed; refusing to overwrite it",
                        path.display()
                    )
                })?;
            return Ok(Signer {
                key: SigningKey::from_bytes(&bytes),
            });
        }

        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).ok();
        }
        std::fs::write(path, seed)
            .with_context(|| format!("writing new signing key to {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        tracing::warn!(
            path = %path.display(),
            bridge_id = %BridgeId(SigningKey::from_bytes(&seed).verifying_key().to_bytes()).to_bs58(),
            "generated a NEW bridge signing key; applications must be told this id \
             or they will not accept this bridge's observations"
        );
        Ok(Signer {
            key: SigningKey::from_bytes(&seed),
        })
    }

    pub fn key(&self) -> &SigningKey {
        &self.key
    }

    pub fn bridge_id(&self) -> BridgeId {
        BridgeId(self.key.verifying_key().to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_created_once_and_then_reused() {
        // Regenerating silently would change the BridgeId and invalidate every
        // observation applications have learned to trust.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("key");
        let a = Signer::load_or_create(&p).unwrap().bridge_id();
        let b = Signer::load_or_create(&p).unwrap().bridge_id();
        assert_eq!(a, b);
    }

    #[test]
    fn a_corrupt_key_file_is_an_error_not_a_silent_regeneration() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("key");
        std::fs::write(&p, b"too short").unwrap();
        assert!(Signer::load_or_create(&p).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_new_key_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("key");
        Signer::load_or_create(&p).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "signing key must not be group/world readable");
    }
}
