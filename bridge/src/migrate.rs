//! Carrying observations forward when the contracts re-key.
//!
//! # Why the bridge drives this, and not a client
//!
//! A contract's key is `BLAKE3(BLAKE3(wasm) || params)`, so every rebuild moves
//! every instance. Freenet has no core mechanism to carry state across that —
//! deliberately, and permanently — so it is app-level work.
//!
//! The bridge is the right driver because it is the only writer here, so
//! nothing else can be carrying this data forward.
//!
//! A note on ordering, because an earlier version of this doc had it wrong and
//! a later reader acted on it: the probe does NOT have to run before the
//! current instance is first published to. `migrate_contract` GETs only the
//! ids the lineage yields, never the current key, so a claim published to the
//! current instance cannot be mistaken for a predecessor's state. That is what
//! lets [`WalkClock`] hold the first walk back while publishing carries on.
//! (freenet/river#621 is about an app whose probe DID read the current key.)
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

/// What one walk over an address's predecessors found.
///
/// Separate from [`Walk`] on purpose. This decides whether there is anything
/// to carry forward; `Walk` decides whether the walk may count towards
/// stopping. Collapsing the two lost a partial recovery: a fold that
/// recovered from the predecessors it could reach, while one stayed silent,
/// is incomplete evidence AND real data that must be published.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Found {
    /// A predecessor held state. `complete` is false when some generation was
    /// never probed or never answered, so the fold is missing whatever those
    /// hold.
    Recovered { complete: bool },
    /// Every predecessor answered, and none held state.
    Nothing,
    /// Some predecessor did not answer, and nothing was recovered.
    Unknown,
}

impl<S> From<&Outcome<S>> for Found {
    fn from(outcome: &Outcome<S>) -> Self {
        match outcome {
            Outcome::Recovered {
                unresolved,
                truncated_fold,
                ..
            } => Found::Recovered {
                complete: unresolved.is_empty() && !truncated_fold,
            },
            Outcome::SeedLocal { .. } => Found::Nothing,
            _ => Found::Unknown,
        }
    }
}

impl Found {
    /// Whether the walk produced state to publish under the current key.
    pub fn has_state(&self) -> bool {
        matches!(self, Found::Recovered { .. })
    }
}

/// Whether one walk may count towards recording a migration as finished.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Walk {
    /// Every predecessor answered, and what any of them held is now published
    /// under the current key.
    Agrees,
    /// Proves nothing: a predecessor did not answer, the fold was incomplete,
    /// or what was recovered did not get published.
    ProvesNothing,
}

/// What a finished walk may be counted as.
///
/// A recovery counts only when the forward PUT succeeded: counted on the
/// strength of a PUT that failed, several such walks would record the
/// migration as finished over exactly the data they failed to move.
pub fn agreement(found: Found, published_forward: bool) -> Walk {
    match found {
        Found::Recovered { complete: true } if published_forward => Walk::Agrees,
        Found::Nothing => Walk::Agrees,
        _ => Walk::ProvesNothing,
    }
}

/// How long to wait before walking an address's predecessors again.
pub const WALK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// How far apart two walks must be to count as separate evidence.
pub const SEAL_SPACING: std::time::Duration = std::time::Duration::from_secs(6 * 60 * 60);

/// [`SEAL_SPACING`] in milliseconds, for the persisted wall-clock stamp.
pub const SEAL_SPACING_MS: u64 = SEAL_SPACING.as_millis() as u64;

/// How many separate walks must agree before a migration is recorded as
/// finished.
pub const SEAL_AFTER_WALKS: u32 = 4;

/// How many separate agreeing walks an address has to its name, and when the
/// last of them was counted.
///
/// Persisted (`Store::migration_agreement`), because the walks that have to
/// agree are the better part of a day apart and a bridge restarts more often
/// than that. Held only in memory, an address would never reach the count and
/// would pay its predecessor GETs forever.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Agreement {
    pub walks: u32,
    /// Wall clock, not `Instant`: it outlives the process.
    pub last_counted_ms: Option<u64>,
}

/// Count a finished walk, and say whether the migration may now be recorded
/// as finished.
///
/// # Why one walk is not enough
///
/// Recording a migration as finished is permanent: that address is never
/// probed again, so anything a predecessor still holds is abandoned. And a
/// "not found" is weak evidence. A node answers `NotFound` when its GET runs
/// out of retries, whether or not the contract exists, and freenet-migrate
/// measured that case at about 99.6% of production not-found traffic. So a
/// migration is sealed only after [`SEAL_AFTER_WALKS`] walks agree, each at
/// least [`SEAL_SPACING_MS`] after the last one counted, which is the better
/// part of a day of the same answer.
///
/// Waiting is close to free, which is why the spacing is hours rather than
/// minutes: an unsealed address costs one walk per [`WALK_INTERVAL`], and
/// sealing saves only that. Getting it wrong costs a predecessor's signed
/// payment evidence, which the module doc explains a chain rescan cannot
/// always rebuild.
///
/// # The residual
///
/// A lineage that is unreachable for the whole agreement window still seals.
/// Nothing available here can tell that from an empty lineage: absence is
/// unauthenticated, and the bridge's own record of what it published is wiped
/// on a re-key (`Store::set_publish_generation`), so it cannot serve as a
/// witness either. freenet-migrate's README suggests a connectivity witness,
/// a GET for something known to exist; doing that honestly needs a key this
/// bridge has NOT written locally, or the node answers from its own store and
/// the witness proves nothing.
pub fn count_walk(prev: Agreement, walk: Walk, now_ms: u64) -> (Agreement, bool) {
    if walk == Walk::ProvesNothing {
        return (prev, false);
    }
    match prev.last_counted_ms {
        // A stamp in the future is a clock that ran fast and was corrected.
        // The stamp is brought back to now so the address is not left waiting
        // for real time to catch up, which can be years, but THIS walk does
        // not count: otherwise every backward correction would buy a walk's
        // worth of evidence, and four of them would seal.
        Some(last) if last > now_ms => {
            return (
                Agreement {
                    walks: prev.walks,
                    last_counted_ms: Some(now_ms),
                },
                false,
            )
        }
        Some(last) if now_ms - last < SEAL_SPACING_MS => return (prev, false),
        _ => {}
    }
    let next = Agreement {
        walks: prev.walks + 1,
        last_counted_ms: Some(now_ms),
    };
    (next, next.walks >= SEAL_AFTER_WALKS)
}

/// When each address is next due a walk.
///
/// Until sealed, a walk re-sends a GET for every predecessor. Run on every
/// observation round, that was eight GETs every few seconds per watched
/// address, and it was that load that made a slow reply, and so the freeze in
/// `freenet::Link`, likely. So an unsealed address is walked at most once per
/// [`WALK_INTERVAL`]. Publishing is not held back meanwhile: the walk reads
/// only predecessor keys, never the current one, so it cannot read back what
/// this bridge has just written.
/// # Why nothing is walked for the first [`WALK_INTERVAL`]
///
/// This clock is in memory, so every address is due the moment a process
/// starts. The agreement count is not in memory, so a walk taken seconds
/// after launch can be the one that counts, and with walks six hours apart it
/// is usually the ONLY one that can count in its window. A just-started
/// node's GET dead-ends for want of peers and answers `NotFound` like any
/// other, so that arrangement drew the evidence for a permanent decision from
/// the least trustworthy moment available. Nothing is walked until the node
/// has had this long to find peers.
///
/// # Why an agreeing walk waits longer
///
/// Nothing a walk finds can be counted until [`SEAL_SPACING`] after the last
/// one that was, so walking every ten minutes in between only re-sends GETs,
/// and re-PUTs a recovered state that has not changed. A walk that agreed is
/// therefore not repeated until it could count again; one that proved nothing
/// is retried on the shorter interval, because it may be a transient failure.
pub struct WalkClock {
    started: std::time::Instant,
    next: std::collections::HashMap<Vec<u8>, std::time::Instant>,
    /// What was last published forward for an address, so an unchanged
    /// recovery is not re-sent on every walk.
    published: std::collections::HashMap<Vec<u8>, [u8; 32]>,
}

impl Default for WalkClock {
    fn default() -> Self {
        WalkClock {
            started: std::time::Instant::now(),
            next: std::collections::HashMap::new(),
            published: std::collections::HashMap::new(),
        }
    }
}

impl WalkClock {
    /// Whether `address` is due a walk.
    pub fn due(&self, address: &[u8], now: std::time::Instant) -> bool {
        if now.saturating_duration_since(self.started) < WALK_INTERVAL {
            return false;
        }
        self.next.get(address).is_none_or(|next| now >= *next)
    }

    /// Record that a walk just ran, and when the next one is worth taking.
    pub fn walked(&mut self, address: &[u8], walk: Walk, now: std::time::Instant) {
        let wait = match walk {
            Walk::Agrees => SEAL_SPACING,
            Walk::ProvesNothing => WALK_INTERVAL,
        };
        self.next.insert(address.to_vec(), now + wait);
    }

    /// Whether `digest` differs from what was last published FORWARD and
    /// accepted for this address.
    ///
    /// Read-only on purpose. Recorded here rather than in
    /// [`Self::published_forward`], a PUT that then failed would leave the
    /// digest behind, the next walk would skip the PUT as unchanged and report
    /// success, and the address could reach agreement over state the node
    /// never stored.
    pub fn publish_is_new(&self, address: &[u8], digest: [u8; 32]) -> bool {
        self.published.get(address) != Some(&digest)
    }

    /// Record that `digest` is now published forward for this address.
    pub fn published_forward(&mut self, address: &[u8], digest: [u8; 32]) {
        self.published.insert(address.to_vec(), digest);
    }

    /// Forget an address, once its migration is recorded as finished.
    pub fn forget(&mut self, address: &[u8]) {
        self.next.remove(address);
        self.published.remove(address);
    }
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

#[cfg(test)]
mod walk_tests {
    use super::*;
    use freenet_stdlib::prelude::ContractInstanceId;
    use std::time::{Duration, Instant};

    fn recovered(
        unresolved: Vec<ContractInstanceId>,
        truncated_fold: bool,
    ) -> Outcome<BitcoinAddressStateV1> {
        Outcome::Recovered {
            merged: BitcoinAddressStateV1::default(),
            source: ContractInstanceId::new([1; 32]),
            truncated_fold,
            unresolved,
        }
    }

    #[test]
    fn a_partial_recovery_is_still_state_to_publish() {
        let partial = Found::from(&recovered(vec![ContractInstanceId::new([2; 32])], false));
        assert_eq!(partial, Found::Recovered { complete: false });
        assert!(
            partial.has_state(),
            "the fold recovered real claims from the predecessors it did reach"
        );
        assert_eq!(
            agreement(partial, true),
            Walk::ProvesNothing,
            "but a generation that never answered may hold what the fold is missing"
        );
        assert_eq!(
            Found::from(&recovered(vec![], true)),
            Found::Recovered { complete: false },
            "a truncated fold never probed the oldest generations"
        );
    }

    #[test]
    fn a_recovery_counts_only_once_it_is_published_forward() {
        let complete = Found::from(&recovered(vec![], false));
        assert_eq!(complete, Found::Recovered { complete: true });
        assert_eq!(agreement(complete, true), Walk::Agrees);
        assert_eq!(
            agreement(complete, false),
            Walk::ProvesNothing,
            "a PUT that failed moved nothing, so it proves nothing"
        );
    }

    #[test]
    fn nothing_found_agrees_and_needs_no_publish() {
        assert_eq!(agreement(Found::Nothing, false), Walk::Agrees);
        assert!(!Found::Nothing.has_state());
        assert_eq!(agreement(Found::Unknown, true), Walk::ProvesNothing);
    }

    #[test]
    fn one_agreeing_walk_does_not_seal() {
        let (after, seal) = count_walk(Agreement::default(), Walk::Agrees, 1_000);
        assert_eq!(after.walks, 1);
        assert!(!seal);
    }

    #[test]
    fn walks_close_together_count_once() {
        let mut state = Agreement::default();
        let mut now = 1_000_000;
        let (first, _) = count_walk(state, Walk::Agrees, now);
        state = first;
        for _ in 0..20 {
            now += SEAL_SPACING_MS / 30;
            let (next, seal) = count_walk(state, Walk::Agrees, now);
            assert!(!seal);
            assert_eq!(next.walks, 1, "still one walk's worth of evidence");
            state = next;
        }
    }

    #[test]
    fn separate_agreeing_walks_seal_and_walks_that_prove_nothing_do_not_count() {
        let mut state = Agreement::default();
        let mut now = 1_000_000;
        for _ in 0..SEAL_AFTER_WALKS - 1 {
            let (next, seal) = count_walk(state, Walk::Agrees, now);
            assert!(!seal);
            state = next;
            now += SEAL_SPACING_MS;
            let (unchanged, seal) = count_walk(state, Walk::ProvesNothing, now);
            assert!(!seal);
            assert_eq!(
                unchanged, state,
                "a walk that proves nothing changes nothing"
            );
            now += SEAL_SPACING_MS;
        }
        let (final_state, seal) = count_walk(state, Walk::Agrees, now);
        assert!(seal, "the fourth separate agreeing walk seals");
        assert_eq!(final_state.walks, SEAL_AFTER_WALKS);
    }

    #[test]
    fn walks_that_prove_nothing_never_seal() {
        let mut state = Agreement::default();
        for i in 0..20u64 {
            let (next, seal) = count_walk(state, Walk::ProvesNothing, i * SEAL_SPACING_MS);
            assert!(!seal);
            state = next;
        }
        assert_eq!(state, Agreement::default());
    }

    #[test]
    fn nothing_is_walked_until_the_node_has_had_time_to_find_peers() {
        let clock = WalkClock::default();
        let t0 = Instant::now();
        assert!(!clock.due(b"a", t0), "a just-started node has few peers");
        assert!(!clock.due(b"a", t0 + WALK_INTERVAL - Duration::from_secs(1)));
        assert!(clock.due(b"a", t0 + WALK_INTERVAL));
    }

    #[test]
    fn a_walk_that_agreed_waits_until_it_could_count_again() {
        let mut clock = WalkClock::default();
        let t0 = Instant::now() + WALK_INTERVAL;
        clock.walked(b"a", Walk::Agrees, t0);
        assert!(
            !clock.due(b"a", t0 + SEAL_SPACING - Duration::from_secs(1)),
            "nothing it found could be counted before the spacing anyway"
        );
        assert!(clock.due(b"a", t0 + SEAL_SPACING));

        clock.walked(b"a", Walk::ProvesNothing, t0);
        assert!(
            clock.due(b"a", t0 + WALK_INTERVAL),
            "a walk that proved nothing may have failed transiently"
        );
        assert!(clock.due(b"b", t0), "another address has its own pace");
        clock.forget(b"a");
        assert!(clock.due(b"a", t0));
    }

    #[test]
    fn an_unchanged_recovery_is_not_published_again() {
        let mut clock = WalkClock::default();
        assert!(clock.publish_is_new(b"a", [1; 32]));
        clock.published_forward(b"a", [1; 32]);
        assert!(!clock.publish_is_new(b"a", [1; 32]));
        assert!(
            clock.publish_is_new(b"a", [2; 32]),
            "changed, so worth sending"
        );
        assert!(clock.publish_is_new(b"b", [1; 32]), "a different address");
        clock.forget(b"a");
        assert!(
            clock.publish_is_new(b"a", [1; 32]),
            "forgotten, so sent again"
        );
    }

    /// **A forward PUT that failed is tried again, not remembered as done.**
    ///
    /// The digest was recorded when the decision to publish was taken, so a
    /// PUT that then failed left the memo behind: the next walk skipped the
    /// PUT as unchanged and reported success, and the address could reach
    /// agreement over state the node never stored.
    #[test]
    fn a_recovery_whose_publish_failed_is_published_again() {
        let mut clock = WalkClock::default();
        assert!(clock.publish_is_new(b"a", [1; 32]), "first attempt");
        // The PUT failed, so nothing is recorded.
        assert!(
            clock.publish_is_new(b"a", [1; 32]),
            "the same state must be sent again after a failed PUT"
        );
        clock.published_forward(b"a", [1; 32]);
        assert!(!clock.publish_is_new(b"a", [1; 32]));
    }

    /// **A clock corrected backwards neither stalls an address nor pays it.**
    ///
    /// Left alone, a stamp written while the clock read years ahead would
    /// stop the address counting anything until real time passed it. Counted,
    /// every backward correction would buy a walk's worth of evidence towards
    /// a permanent decision, and four would seal.
    #[test]
    fn a_stamp_from_a_clock_that_ran_fast_neither_strands_nor_pays_an_address() {
        let now = 1_700_000_000_000;
        let future = Agreement {
            walks: 1,
            last_counted_ms: Some(10_000_000_000_000),
        };
        let (after, seal) = count_walk(future, Walk::Agrees, now);
        assert!(!seal);
        assert_eq!(after.walks, 1, "the correction itself is not evidence");
        assert_eq!(
            after.last_counted_ms,
            Some(now),
            "but the stamp is brought back, so the next walk can count"
        );
        let (later, _) = count_walk(after, Walk::Agrees, now + SEAL_SPACING_MS);
        assert_eq!(later.walks, 2, "and it does, a spacing later");
    }
}
