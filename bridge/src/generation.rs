//! Telling readers which contract generation this bridge publishes to.
//!
//! # The failure
//!
//! A contract's address is `BLAKE3(BLAKE3(wasm) || params)`. The bridge writes
//! observations into an address derived from the WASM it was installed with;
//! an application derives an address from the WASM it was built with. Rebuild
//! one and not the other — and a `cargo fmt` is enough, because release
//! binaries embed panic locations as `file:line` — and the two addresses
//! differ.
//!
//! Nothing then errors. The application reads a contract nobody has written
//! to, which is byte-identical to a contract with nothing in it, and shows an
//! empty page. That is indistinguishable from "the bridge is down" and from
//! "this address has never been paid". Both halves are working correctly.
//!
//! # What this publishes
//!
//! One [pointer record](freenet_bitcoin_generation) per contract, signed with
//! the bridge's own key, naming the code hash it is currently publishing to.
//! A reader that knows only the bridge id — which it must know anyway, since
//! trusting the bridge is the whole security decision — can derive the
//! pointer's address offline, read the code hash, and derive the real contract
//! from that instead of from whatever WASM it happens to ship.
//!
//! # Why the network is consulted before writing
//!
//! The pointer contract refuses a record that does not supersede the one it
//! holds, so versions must be monotonic. The local counter is the fast path,
//! but it lives in a database the deployment notes describe as disposable
//! ("delete it and the bridge rescans"). Deleted, the counter restarts at 1,
//! every write is refused as stale, and the pointer silently freezes at an old
//! generation — pointing every reader at contracts this bridge no longer
//! writes to, which is exactly the failure the pointer exists to prevent.
//!
//! So the published record is read back first, and its version is adopted as
//! the baseline whenever it verifies under this bridge's own key. A record
//! signed by anyone else is ignored, and an unreachable pointer is treated as
//! "I do not know", not as "nothing is there".

use anyhow::Result;
use freenet_bitcoin_generation::{code_hash_b58, Artifact};
use freenet_migrate::pointer::PointerRecord;
use freenet_migrate::ProbeAnswer;

use crate::freenet::FreenetPublisher;
use crate::signer::Signer;
use crate::store::Store;

/// What this bridge believes about one artifact's pointer, after publishing.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PointerState {
    pub artifact: Artifact,
    /// Where the record lives, base58. Derivable offline from the bridge id.
    pub pointer_id: String,
    /// The code hash the bridge is publishing observations to.
    pub code_hash: [u8; 32],
    /// The version now standing at that pointer.
    pub version: u32,
    /// True when this run moved the pointer to a new generation.
    pub advanced: bool,
}

/// Publish a pointer record for each contract, and return what now stands.
///
/// Failures are reported, never fatal. A bridge that cannot publish a pointer
/// is still doing its real job; what it loses is a reader's ability to notice
/// that it re-keyed. Returning the per-artifact results rather than logging
/// only lets `--print-generation` show an operator the same facts the daemon
/// acted on.
pub async fn publish_pointers(
    publisher: &FreenetPublisher,
    signer: &Signer,
    store: &Store,
) -> Vec<Result<PointerState>> {
    let mut out = Vec::new();
    for artifact in Artifact::ALL {
        let hash = match artifact {
            Artifact::Address => publisher.address_code_hash(),
            Artifact::Tip => publisher.tip_code_hash(),
        };
        out.push(publish_one(publisher, signer, store, artifact, hash).await);
    }
    out
}

async fn publish_one(
    publisher: &FreenetPublisher,
    signer: &Signer,
    store: &Store,
    artifact: Artifact,
    code_hash: [u8; 32],
) -> Result<PointerState> {
    let bridge = signer.bridge_id();
    let app_id = String::from_utf8_lossy(artifact.app_id()).into_owned();
    let pointer_id = freenet_bitcoin_generation::pointer_id(&bridge, artifact)
        .map_err(|e| anyhow::anyhow!("deriving the pointer address: {e}"))?;
    let params = freenet_bitcoin_generation::pointer_params(&bridge, artifact)
        .map_err(|e| anyhow::anyhow!("building pointer params: {e}"))?;

    let stored = store.pointer_record(&app_id)?;
    let published = read_published(publisher, pointer_id, &params, &bridge).await;

    // Take the higher of the two baselines. `stored` is what this bridge
    // remembers; `published` is what the network will actually compare
    // against. They differ when the database was lost, when another instance
    // of this bridge published, or when a write failed after being recorded.
    let baseline = match (stored, published) {
        (Some(a), Some(b)) if b.0 > a.0 => Some(b),
        (Some(a), _) => Some(a),
        (None, b) => b,
    };

    let (version, advanced) = match baseline {
        // Nothing has ever been published for this artifact.
        None => (1, true),
        // The standing record already names this generation. Republishing the
        // identical record is a no-op the contract absorbs, and it is worth
        // doing: it heals a pointer whose only copy was on a peer that has
        // since dropped it.
        Some((v, h)) if h == code_hash => (v, false),
        // A different generation stands. Supersede it.
        Some((v, _)) => (v.saturating_add(1), true),
    };

    let message =
        freenet_bitcoin_generation::signing_message(&bridge, artifact, version, &code_hash)
            .map_err(|e| anyhow::anyhow!("building the pointer signing message: {e}"))?;
    let signature = {
        use ed25519_dalek::Signer as _;
        signer.key().sign(&message).to_bytes()
    };
    let record = PointerRecord {
        version,
        code_hash,
        signature,
    };

    publisher
        .publish_pointer(params, record.encode().to_vec())
        .await?;
    store.set_pointer_record(&app_id, version, &code_hash)?;

    if advanced {
        tracing::warn!(
            artifact = artifact.label(),
            pointer = %pointer_id,
            code_hash = %code_hash_b58(&code_hash),
            version,
            "published a NEW contract generation; readers following this pointer will \
             move with it, and any reader that does not will read an empty contract"
        );
    } else {
        tracing::info!(
            artifact = artifact.label(),
            pointer = %pointer_id,
            code_hash = %code_hash_b58(&code_hash),
            version,
            "generation pointer re-asserted"
        );
    }

    Ok(PointerState {
        artifact,
        pointer_id: pointer_id.to_string(),
        code_hash,
        version,
        advanced,
    })
}

/// The record currently standing at this bridge's pointer, if we can read one
/// and it is ours.
///
/// `None` covers three different things on purpose — nothing published, not
/// reachable, not signed by us — because all three lead to the same action:
/// fall back to the local counter. What matters is that a record signed by
/// somebody else can never raise our version, since acting on it would let a
/// third party push this bridge's counter to `u32::MAX` and wedge the pointer
/// permanently.
async fn read_published(
    publisher: &FreenetPublisher,
    pointer_id: freenet_stdlib::prelude::ContractInstanceId,
    params: &[u8],
    bridge: &freenet_bitcoin_common::BridgeId,
) -> Option<(u32, [u8; 32])> {
    let state = match publisher.probe_get(pointer_id).await {
        ProbeAnswer::State(bytes) => bytes,
        ProbeAnswer::Absent => return None,
        // Silence. Never absence: treating an unreachable pointer as unpublished
        // would restart the version counter and wedge the real record.
        _ => {
            tracing::debug!(pointer = %pointer_id, "pointer unreachable; using the local counter");
            return None;
        }
    };
    let author = freenet_bitcoin_generation::author_key(bridge).ok()?;
    let record = PointerRecord::decode(&state).ok()?;
    if record.verify(params, &author).is_err() {
        tracing::warn!(
            pointer = %pointer_id,
            "a record at this bridge's pointer address is not signed by this bridge; ignoring it"
        );
        return None;
    }
    Some((record.version, record.code_hash))
}

#[cfg(test)]
mod tests {
    use crate::store::Store;

    /// The whole point of consulting the network: a lost database must not
    /// restart the version counter, because the pointer contract would then
    /// refuse every write and freeze at an old generation.
    ///
    /// Exercised at the store level, which is the half that persists; the
    /// version arithmetic it feeds is covered by `version_arithmetic` below.
    #[test]
    fn a_lost_database_forgets_the_version() {
        let s = Store::open_in_memory().unwrap();
        assert_eq!(s.pointer_record("freenet-bitcoin.tip").unwrap(), None);
        s.set_pointer_record("freenet-bitcoin.tip", 4, &[1u8; 32])
            .unwrap();
        assert_eq!(
            s.pointer_record("freenet-bitcoin.tip").unwrap(),
            Some((4, [1u8; 32]))
        );
        // A fresh store is a lost database.
        let fresh = Store::open_in_memory().unwrap();
        assert_eq!(fresh.pointer_record("freenet-bitcoin.tip").unwrap(), None);
    }

    /// The two artifacts have independent version spaces; sharing one would
    /// make a re-key of either look like a rollback of the other.
    #[test]
    fn the_two_artifacts_do_not_share_a_version() {
        let s = Store::open_in_memory().unwrap();
        s.set_pointer_record("freenet-bitcoin.address", 7, &[2u8; 32])
            .unwrap();
        s.set_pointer_record("freenet-bitcoin.tip", 1, &[3u8; 32])
            .unwrap();
        assert_eq!(
            s.pointer_record("freenet-bitcoin.address").unwrap(),
            Some((7, [2u8; 32]))
        );
        assert_eq!(
            s.pointer_record("freenet-bitcoin.tip").unwrap(),
            Some((1, [3u8; 32]))
        );
    }

    /// The rule the publisher applies, stated as a table so it can be checked
    /// without a node: only a genuine change to the code hash advances the
    /// version, and the higher of the local and published baselines wins.
    fn next_version(
        stored: Option<(u32, [u8; 32])>,
        published: Option<(u32, [u8; 32])>,
        code_hash: [u8; 32],
    ) -> (u32, bool) {
        let baseline = match (stored, published) {
            (Some(a), Some(b)) if b.0 > a.0 => Some(b),
            (Some(a), _) => Some(a),
            (None, b) => b,
        };
        match baseline {
            None => (1, true),
            Some((v, h)) if h == code_hash => (v, false),
            Some((v, _)) => (v.saturating_add(1), true),
        }
    }

    #[test]
    fn version_arithmetic() {
        let a = [1u8; 32];
        let b = [2u8; 32];

        assert_eq!(next_version(None, None, a), (1, true), "first publish");
        assert_eq!(
            next_version(Some((3, a)), None, a),
            (3, false),
            "unchanged generation must not burn a version"
        );
        assert_eq!(
            next_version(Some((3, a)), None, b),
            (4, true),
            "a re-key advances"
        );
        assert_eq!(
            next_version(None, Some((9, a)), b),
            (10, true),
            "a lost database follows the published record rather than restarting at 1"
        );
        assert_eq!(
            next_version(Some((2, a)), Some((9, a)), b),
            (10, true),
            "the higher baseline wins, so a stale local counter cannot wedge the pointer"
        );
        assert_eq!(
            next_version(Some((9, a)), Some((2, a)), b),
            (10, true),
            "and a stale PUBLISHED record cannot walk the counter backwards either"
        );
    }
}
