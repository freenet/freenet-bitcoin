//! Carrying observations forward when the contracts re-key.
//!
//! # Why the bridge drives this, and not a client
//!
//! A contract's key is `BLAKE3(BLAKE3(wasm) || params)`, so every rebuild moves
//! every instance. Freenet has no core mechanism to carry state across that —
//! deliberately, and permanently — so it is app-level work.
//!
//! The bridge is the right driver for one reason above all: **the probe's
//! trigger is that the new key has no real state yet, so any write to the new
//! key that lands first permanently suppresses it** (freenet/river#621). The
//! bridge is the only writer here. If it published before probing, it would
//! destroy the trigger with its own first write, and the migration would
//! silently never run while everything looked healthy.
//!
//! So the probe runs once per contract instance, *before* that instance is
//! first published to in this process.
//!
//! # Why this is worth doing even though observations are reconstructible
//!
//! The bridge could re-derive everything from Bitcoin instead. But a rescan is
//! bounded by what a PRUNED node still has and by the backfill window, so deep
//! history genuinely cannot be recovered from the chain — whereas it survives
//! in the predecessor contract. Folding forward keeps it.

use freenet_bitcoin_common::address_state::BitcoinAddressStateV1;
use freenet_bitcoin_common::tip_state::BitcoinTipStateV1;
use freenet_bitcoin_common::{from_cbor, BitcoinAddressParameters, BitcoinTipParameters};
use freenet_migrate::{ContractLineageEntry, FoldAllAck, Outcome, ProbeStateOps, SelectionPolicy};
use freenet_scaffold::ComposableState;
use freenet_stdlib::prelude::ContractInstanceId;

// The codegen emits an (empty) DELEGATE_LINEAGE alongside the contract one.
// There are no delegates in this repo yet; allow it rather than editing
// generated code.
#[allow(dead_code)]
mod address_lineage_gen {
    include!(concat!(env!("OUT_DIR"), "/legacy_address_contract.rs"));
}
pub use address_lineage_gen::LEGACY_ADDRESS_CONTRACT_HASHES;
#[allow(dead_code)]
mod tip_lineage {
    include!(concat!(env!("OUT_DIR"), "/legacy_tip_contract.rs"));
}
pub use tip_lineage::LEGACY_TIP_CONTRACT_HASHES;

/// Merge rules for an address contract's state.
pub struct AddressOps {
    pub params: BitcoinAddressParameters,
}

impl ProbeStateOps for AddressOps {
    type State = BitcoinAddressStateV1;

    fn decode(&self, bytes: &[u8]) -> Option<Self::State> {
        from_cbor(bytes).ok()
    }

    /// "Real" means a bridge has actually said something about this script.
    ///
    /// An empty state is what a freshly-created contract holds, so adopting one
    /// would be adopting nothing while reporting a hit.
    fn is_real(&self, state: &Self::State) -> bool {
        !state.claims.claims.is_empty() || !state.claims.scanned.is_empty()
    }

    fn merge_with_local(&self, recovered: Self::State, local: &Self::State) -> Self::State {
        fold(recovered, local, &self.params)
    }

    /// Fold an older generation in. This is the SAME merge the network runs
    /// between peers, so folding generations is not a bespoke code path whose
    /// correctness has to be argued separately.
    fn merge_generations(&self, newer: Self::State, older: Self::State) -> Self::State {
        fold(newer, &older, &self.params)
    }
}

fn fold(
    mut base: BitcoinAddressStateV1,
    other: &BitcoinAddressStateV1,
    params: &BitcoinAddressParameters,
) -> BitcoinAddressStateV1 {
    let snapshot = base.clone();
    // On a merge failure keep the primary rather than losing it -- the shipped
    // keep-primary behaviour the trait documents.
    if base.merge(&snapshot, params, other).is_err() {
        return snapshot;
    }
    base
}

/// Merge rules for the per-network tip contract.
pub struct TipOps {
    pub params: BitcoinTipParameters,
}

impl ProbeStateOps for TipOps {
    type State = BitcoinTipStateV1;

    fn decode(&self, bytes: &[u8]) -> Option<Self::State> {
        from_cbor(bytes).ok()
    }

    fn is_real(&self, state: &Self::State) -> bool {
        state.tip_height().is_some()
    }

    fn merge_with_local(&self, recovered: Self::State, local: &Self::State) -> Self::State {
        let snapshot = recovered.clone();
        let mut out = recovered;
        if out.merge(&snapshot, &self.params, local).is_err() {
            return snapshot;
        }
        out
    }
}

/// Selection policy for address contracts.
///
/// `FoldAll`, and the acknowledgement is earned rather than waved through.
/// Fold-all resurrects data deleted by ABSENCE, so it is only sound where
/// deletions are explicit. Here they are:
///
/// * A reorg is not a deletion. It is a **`Retracted` claim at a higher
///   `as_of`** — an explicit tombstone that folds in alongside the
///   confirmation it supersedes and wins the fold. So folding an old
///   generation cannot resurrect a payment that was reorged away.
/// * The one non-tombstoned removal is capacity pruning (the byte budget).
///   Folding can re-admit a pruned claim, and that is harmless and
///   self-correcting: `apply_delta` re-runs `enforce_cap`, so the fold result
///   is pruned again by the same deterministic rule.
///
/// The merge is also commutative and idempotent, asserted on exact bytes in
/// `freenet-bitcoin-common` and re-checked here with the crate's own
/// `policy_check` helpers.
pub fn address_policy() -> SelectionPolicy {
    SelectionPolicy::FoldAll(FoldAllAck::i_understand_fold_all_resurrects_without_tombstones())
}

/// Selection policy for the tip contract.
///
/// `NewestFirstWins`, not fold-all: the tip contract holds only a short window
/// of recent blocks and prunes the rest, so an older generation has strictly
/// less useful data and folding it in would only feed the pruner.
pub fn tip_policy() -> SelectionPolicy {
    SelectionPolicy::NewestFirstWins
}

/// Report what an outcome means, in the app's terms.
///
/// `Indeterminate` is read deliberately rather than absorbed: it means adopt
/// nothing, seal nothing, retry — and treating it as "nothing to recover"
/// is how a migration silently loses data.
pub fn describe<S>(outcome: &Outcome<S>) -> String {
    match outcome {
        Outcome::Recovered { source, .. } => {
            format!("recovered state from predecessor {source}")
        }
        Outcome::SeedLocal { .. } => {
            "every predecessor answered, none held state; keeping local".to_string()
        }
        Outcome::Indeterminate { unresolved, .. } => format!(
            "{} predecessor(s) did not answer; adopting nothing and retrying later",
            unresolved.len()
        ),
        _ => "unrecognised migration outcome".to_string(),
    }
}

pub use freenet_migrate::contract_id_from_code_hash;

/// The predecessor instance ids for one address contract's parameters.
pub fn address_lineage() -> &'static [ContractLineageEntry] {
    LEGACY_ADDRESS_CONTRACT_HASHES
}

pub fn tip_lineage() -> &'static [ContractLineageEntry] {
    LEGACY_TIP_CONTRACT_HASHES
}

/// Marker so callers cannot forget the ordering constraint.
pub fn probe_ids(
    lineage: &[ContractLineageEntry],
    params: &freenet_stdlib::prelude::Parameters<'_>,
) -> Vec<ContractInstanceId> {
    lineage
        .iter()
        .map(|e| contract_id_from_code_hash(&e.code_hash, params))
        .collect()
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use freenet_bitcoin_common::spv::testing as spv_testing;
    use freenet_bitcoin_common::{
        to_cbor, BitcoinNetwork, BlockAnchor, BridgeId, Claim, ClaimBody, OutPoint, PowFloor,
        SignedClaim,
    };

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[1; 32])
    }

    fn params() -> BitcoinAddressParameters {
        BitcoinAddressParameters {
            network: BitcoinNetwork::Signet,
            script_pubkey: vec![0x00, 0x14, 0xaa, 0xbb],
            trusted_bridges: vec![BridgeId(key().verifying_key().to_bytes())],
            pow_floor: PowFloor::NONE,
        }
    }

    fn state(seed: u8, sats: u64, as_of: u32) -> BitcoinAddressStateV1 {
        let p = params();
        let (spv, txid, block) = spv_testing::payment_proof(&p.script_pubkey, sats, 1, [seed; 32]);
        let claim = SignedClaim::sign(
            &key(),
            &ClaimBody {
                script_id: p.script_id(),
                network: p.network,
                as_of: BlockAnchor {
                    height: as_of,
                    hash: block,
                },
                claim: Claim::ConfirmedOutput {
                    outpoint: OutPoint { txid, vout: 0 },
                    value_sats: sats,
                    anchor: BlockAnchor {
                        height: as_of - 1,
                        hash: block,
                    },
                    spv,
                },
            },
        )
        .unwrap();
        BitcoinAddressStateV1::from_claims(&p, [claim]).unwrap()
    }

    /// The crate asks for these to be run over representative states BEFORE
    /// opting into FoldAll. Running them here rather than asserting the
    /// property in prose is the whole point of the ack being a token.
    #[test]
    fn fold_all_preconditions_hold_for_the_address_state() {
        let ops = AddressOps { params: params() };
        let samples = vec![
            state(1, 50_000, 100),
            state(2, 70_000, 101),
            state(3, 900, 102),
        ];
        // The helpers take values, matching `merge_generations` exactly.
        let merge =
            |a: BitcoinAddressStateV1, b: BitcoinAddressStateV1| ops.merge_generations(a, b);

        freenet_migrate::driver::policy_check::assert_merge_commutative(&samples, merge);
        freenet_migrate::driver::policy_check::assert_merge_idempotent(&samples, merge);
        freenet_migrate::driver::policy_check::assert_fold_order_invariant(&samples, merge);
    }

    /// The precondition FoldAll is actually risky for: a deletion expressed by
    /// ABSENCE would be resurrected. Here a reorg is expressed by a
    /// `Retracted` claim at a higher `as_of` -- a tombstone -- so folding an
    /// older generation that still shows the payment as confirmed does NOT
    /// bring it back to life.
    #[test]
    fn folding_an_old_generation_cannot_resurrect_a_reorged_payment() {
        let p = params();
        let ops = AddressOps { params: p.clone() };

        let old_confirmed = state(1, 50_000, 100);

        // The newer generation carries both the confirmation and its retraction.
        let (_, txid, block) = spv_testing::payment_proof(&p.script_pubkey, 50_000, 1, [1u8; 32]);
        let retraction = SignedClaim::sign(
            &key(),
            &ClaimBody {
                script_id: p.script_id(),
                network: p.network,
                as_of: BlockAnchor {
                    height: 120,
                    hash: block,
                },
                claim: Claim::Retracted {
                    outpoint: OutPoint { txid, vout: 0 },
                },
            },
        )
        .unwrap();
        let mut newer = old_confirmed.clone();
        let snap = newer.clone();
        newer
            .merge(
                &snap,
                &p,
                &BitcoinAddressStateV1::from_claims(&p, [retraction]).unwrap(),
            )
            .unwrap();

        let folded = ops.merge_generations(newer, old_confirmed);
        assert_eq!(
            folded.claims.confirmed_value_sats(200, 1),
            0,
            "folding an older generation must not un-retract a reorged payment"
        );
    }

    #[test]
    fn an_empty_predecessor_is_not_real_and_is_a_miss() {
        let ops = AddressOps { params: params() };
        assert!(!ops.is_real(&BitcoinAddressStateV1::default()));
        assert!(ops.is_real(&state(1, 1, 10)));
    }

    #[test]
    fn the_lineage_is_non_empty_and_ordered() {
        let l = address_lineage();
        assert!(
            !l.is_empty(),
            "an empty lineage probes nothing and reports success"
        );
        let gens: Vec<u32> = l.iter().map(|e| e.generation).collect();
        let mut sorted = gens.clone();
        sorted.sort_unstable();
        assert_eq!(gens, sorted, "generations must be recorded in order");
    }

    #[test]
    fn decode_rejects_garbage_rather_than_panicking() {
        let ops = AddressOps { params: params() };
        assert!(ops.decode(b"not cbor at all").is_none());
        assert!(ops.decode(&to_cbor(&"a string").unwrap()).is_none());
    }
}
