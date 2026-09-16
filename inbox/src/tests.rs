//! Tests. The merge tests are the ones that matter most: they are what would
//! catch a cap or removal rule that broke the laws below the caps, or stopped
//! two peers agreeing above them.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use ed25519_dalek::{Signer, SigningKey};
use freenet_bitcoin_common::{to_cbor, BridgeId};
use freenet_stdlib::prelude::{CodeHash, ContractInstanceId, DelegateKey};
use ghostkey_common::{ScopedPayload, SignatureRequestor};
use ghostkey_lib::armorable::Armorable;
use ghostkey_lib::ghost_key_certificate::GhostkeyCertificateV1;
use ghostkey_lib::notary_certificate::NotaryCertificateV1;
use ghostkey_lib::util::create_keypair;
use rand::rngs::{OsRng, StdRng};
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};

use crate::*;

// --- fixtures ---------------------------------------------------------------

/// A test Ghost Key authority. RSA key generation is slow, so it is made once.
struct Authority {
    master: MasterKey,
    notary: NotaryCertificateV1,
    notary_sk: blind_rsa_signatures::SecretKey,
}

fn authority() -> &'static Authority {
    static A: OnceLock<Authority> = OnceLock::new();
    A.get_or_init(|| {
        let (master_sk, master_vk) = create_keypair(&mut OsRng).unwrap();
        let (notary, notary_sk) =
            NotaryCertificateV1::new(&master_sk, &"test notary".to_string()).unwrap();
        Authority {
            master: MasterKey(*master_vk.as_bytes()),
            notary,
            notary_sk,
        }
    })
}

struct Gk {
    sk: SigningKey,
    pem: String,
}

/// A pool of Ghost Keys under the test authority, made once.
fn ghostkeys() -> &'static Vec<Gk> {
    static G: OnceLock<Vec<Gk>> = OnceLock::new();
    G.get_or_init(|| {
        let a = authority();
        (0..(MAX_ENTRIES + 4))
            .map(|_| {
                let (cert, sk) = GhostkeyCertificateV1::new(&a.notary, &a.notary_sk);
                Gk {
                    sk,
                    pem: cert.to_armored_string().unwrap(),
                }
            })
            .collect()
    })
}

fn bridge_sk() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

fn bridge() -> BridgeId {
    BridgeId(bridge_sk().verifying_key().to_bytes())
}

fn params() -> InboxParameters {
    InboxParameters {
        bridge: bridge(),
        ghostkey_master: authority().master,
    }
}

fn webapp() -> SignatureRequestor {
    SignatureRequestor::WebApp(ContractInstanceId::new([7u8; 32]))
}

fn sealed(tag: u8) -> Sealed {
    Sealed {
        ephemeral: EphemeralKey([tag; 32]),
        nonce: ByteBuf(vec![tag; 12]),
        ciphertext: ByteBuf(vec![tag; 40]),
    }
}

fn entry_with(gk: &Gk, height: u32, tag: u8, requestor: SignatureRequestor) -> WireEntry {
    let body = InboxEntryBody {
        bridge: bridge(),
        mainnet_height: height,
        sealed: sealed(tag),
    };
    let scoped = to_cbor(&ScopedPayload {
        requestor,
        payload: body.signing_payload().unwrap(),
    })
    .unwrap();
    let sig = gk.sk.sign(&scoped).to_bytes().to_vec();
    WireEntry::from_sign_result(gk.pem.clone(), scoped, sig).unwrap()
}

fn entry(gk: &Gk, height: u32, tag: u8) -> WireEntry {
    entry_with(gk, height, tag, webapp())
}

fn open_at(floor: u32) -> InboxStateV1 {
    let mut s = InboxStateV1::default();
    s.apply_delta(
        &params(),
        &InboxDelta {
            floor: Some(SignedFloor::sign(&bridge_sk(), floor)),
            ..Default::default()
        },
    )
    .unwrap();
    s
}

fn with_entries(floor: u32, es: &[WireEntry]) -> InboxStateV1 {
    let mut s = open_at(floor);
    s.apply_delta(
        &params(),
        &InboxDelta {
            entries: es.to_vec(),
            ..Default::default()
        },
    )
    .unwrap();
    s
}

fn bytes(s: &InboxStateV1) -> Vec<u8> {
    to_cbor(s).unwrap()
}

/// The batch the bridge signs to remove `es`, all dated `height`.
fn removal(height: u32, es: &[&WireEntry]) -> RemovalBatch {
    let set: BTreeSet<RemovedPrefix> = es.iter().map(|w| w.entry.key().removal_prefix()).collect();
    RemovalBatch::sign(&bridge_sk(), height, &set)
}

fn apply_removals(s: &mut InboxStateV1, removals: Vec<RemovalBatch>) -> Result<(), String> {
    s.apply_delta(
        &params(),
        &InboxDelta {
            removals,
            ..Default::default()
        },
    )
}

fn add_entries(s: &mut InboxStateV1, entries: Vec<WireEntry>) {
    s.apply_delta(
        &params(),
        &InboxDelta {
            entries,
            ..Default::default()
        },
    )
    .unwrap();
}

/// A state that received `es` one delta each, as peers receive a stream of
/// submissions: a single delta may carry at most two entries from one Ghost
/// Key.
fn one_by_one(floor: u32, es: &[WireEntry]) -> InboxStateV1 {
    let mut s = open_at(floor);
    for w in es {
        add_entries(&mut s, vec![w.clone()]);
    }
    s
}

/// `n` prefixes naming no entry, from `start`: removals still count them.
fn prefixes(start: u64, n: usize) -> BTreeSet<RemovedPrefix> {
    (start..start + n as u64)
        .map(|i| RemovedPrefix(i.to_be_bytes()))
        .collect()
}

// --- certificates -------------------------------------------------------------

#[test]
fn a_fixture_certificate_verifies_under_its_authority_and_not_production() {
    let pem = &ghostkeys()[0].pem;
    assert!(verify_certificate(pem, &authority().master).is_ok());
    assert!(
        verify_certificate(pem, &production_master()).is_err(),
        "a certificate minted by a test authority must not verify as a real one"
    );
}

// --- one entry ----------------------------------------------------------------

#[test]
fn a_well_formed_entry_is_admitted_and_the_state_verifies() {
    let s = with_entries(100, &[entry(&ghostkeys()[0], 104, 1)]);
    assert_eq!(s.entries.len(), 1);
    assert_eq!(s.certificates.len(), 1);
    s.verify(&params()).unwrap();
}

#[test]
fn a_delegate_may_request_as_well_as_a_web_app() {
    let d = SignatureRequestor::Delegate(DelegateKey::new([9u8; 32], CodeHash::new([8u8; 32])));
    let s = with_entries(100, &[entry_with(&ghostkeys()[0], 104, 1, d)]);
    s.verify(&params()).unwrap();
}

/// Tamper with each signed or copied field and confirm admission refuses it.
#[test]
fn tampering_with_any_field_is_refused() {
    let gk = &ghostkeys()[0];
    // One below the window's top, so the tampered height is still inside it
    // and must be refused rather than dropped.
    let good = entry(gk, 100 + WINDOW_BLOCKS - 1, 1);
    let admit = |w: WireEntry| {
        let mut s = open_at(100);
        s.apply_delta(
            &params(),
            &InboxDelta {
                entries: vec![w],
                ..Default::default()
            },
        )
    };
    assert!(admit(good.clone()).is_ok());

    let mut w = good.clone();
    w.entry.mainnet_height += 1;
    assert!(admit(w).is_err(), "copied height must match the signed one");

    let mut w = good.clone();
    let last = w.entry.scoped_payload.0.len() - 1;
    w.entry.scoped_payload.0[last] ^= 1;
    assert!(admit(w).is_err(), "scoped payload is signed");

    let mut w = good.clone();
    w.entry.signature.0[0] ^= 1;
    assert!(admit(w).is_err(), "signature must verify");

    let mut w = good.clone();
    w.entry.ghostkey = GhostkeyId([1u8; 32]);
    assert!(admit(w).is_err(), "Ghost Key must be the certified one");

    let mut w = good.clone();
    w.certificate_pem = ghostkeys()[1].pem.clone();
    assert!(
        admit(w).is_err(),
        "certificate must be the one the entry names"
    );

    let mut w = good.clone();
    w.entry.cert = cert_key(&ghostkeys()[1].pem);
    w.certificate_pem = ghostkeys()[1].pem.clone();
    assert!(
        admit(w).is_err(),
        "another Ghost Key's certificate does not certify this signer"
    );
}

#[test]
fn an_entry_for_another_bridge_is_refused() {
    let gk = &ghostkeys()[0];
    let body = InboxEntryBody {
        bridge: BridgeId([3u8; 32]),
        mainnet_height: 104,
        sealed: sealed(1),
    };
    let scoped = to_cbor(&ScopedPayload {
        requestor: webapp(),
        payload: body.signing_payload().unwrap(),
    })
    .unwrap();
    let sig = gk.sk.sign(&scoped).to_bytes().to_vec();
    let w = WireEntry::from_sign_result(gk.pem.clone(), scoped, sig).unwrap();
    let mut s = open_at(100);
    assert!(s
        .apply_delta(
            &params(),
            &InboxDelta {
                entries: vec![w],
                ..Default::default()
            }
        )
        .is_err());
}

#[test]
fn nothing_is_admitted_before_the_bridge_opens_the_inbox() {
    let mut s = InboxStateV1::default();
    let r = s.apply_delta(
        &params(),
        &InboxDelta {
            entries: vec![entry(&ghostkeys()[0], 104, 1)],
            ..Default::default()
        },
    );
    assert!(r.is_err());
}

#[test]
fn a_floor_signed_by_anyone_but_the_bridge_is_refused() {
    let mut s = InboxStateV1::default();
    let r = s.apply_delta(
        &params(),
        &InboxDelta {
            floor: Some(SignedFloor::sign(&SigningKey::from_bytes(&[1u8; 32]), 100)),
            ..Default::default()
        },
    );
    assert!(r.is_err());
}

// --- the window -----------------------------------------------------------------

#[test]
fn the_window_admits_its_top_edge_and_drops_what_lies_beyond() {
    let gk = &ghostkeys()[0];
    let mut s = open_at(100);
    let top = entry(gk, 100 + WINDOW_BLOCKS, 1);
    let beyond = entry(gk, 100 + WINDOW_BLOCKS + 1, 2);
    s.apply_delta(
        &params(),
        &InboxDelta {
            entries: vec![top.clone(), beyond.clone()],
            ..Default::default()
        },
    )
    .unwrap();
    assert!(s.entries.contains_key(&top.entry.key()));
    assert!(
        !s.entries.contains_key(&beyond.entry.key()),
        "dropped, and the rest of the delta still applied"
    );
    s.verify(&params()).unwrap();
}

/// A sender dates below the very top of the window so that a peer whose
/// floor is a block or two behind still takes the entry.
#[test]
fn an_entry_dated_by_sender_height_reaches_a_peer_two_blocks_behind() {
    let floor = 100;
    let w = entry(&ghostkeys()[0], sender_height(floor), 1);
    let behind = with_entries(floor - SENDER_SLACK_BLOCKS, std::slice::from_ref(&w));
    assert!(behind.entries.contains_key(&w.entry.key()));
    let further = with_entries(floor - SENDER_SLACK_BLOCKS - 1, std::slice::from_ref(&w));
    assert!(
        further.entries.is_empty(),
        "three behind is past the slack, and waits for its floor"
    );
}

#[test]
fn an_entry_below_the_floor_is_dropped_not_rejected() {
    // A peer whose floor was lower can legitimately send one.
    let s = with_entries(100, &[entry(&ghostkeys()[0], 99, 1)]);
    assert!(s.entries.is_empty());
    assert!(
        s.certificates.is_empty(),
        "an unused certificate must go too"
    );
    s.verify(&params()).unwrap();
}

// --- removal ---------------------------------------------------------------------

#[test]
fn a_removal_removes_its_entry_and_lasts_until_the_floor_passes_the_entry() {
    let w = entry(&ghostkeys()[0], 100, 1);
    let key = w.entry.key();
    let mut s = with_entries(97, std::slice::from_ref(&w));
    apply_removals(&mut s, vec![removal(100, &[&w])]).unwrap();
    assert!(s.entries.is_empty());
    assert!(s.is_removed(&key, 100));
    s.verify(&params()).unwrap();

    // A peer that still holds the entry cannot bring it back, and nor can its
    // sender by sending it again.
    let holder = with_entries(97, std::slice::from_ref(&w));
    let mut merged = s.clone();
    merged.merge(&params(), &holder).unwrap();
    assert!(
        merged.entries.is_empty(),
        "a removed entry must not resurrect"
    );
    merged
        .apply_delta(&params(), &InboxDelta::submission(None, w.clone()))
        .unwrap();
    assert!(merged.entries.is_empty(), "nor be sent again");

    // Floor at the entry's height: removal kept.
    let at = InboxDelta {
        floor: Some(SignedFloor::sign(&bridge_sk(), 100)),
        ..Default::default()
    };
    s.apply_delta(&params(), &at).unwrap();
    assert!(s.is_removed(&key, 100));

    // Floor past it: removal gone, and the old entry can no longer return.
    let past = InboxDelta {
        floor: Some(SignedFloor::sign(&bridge_sk(), 101)),
        ..Default::default()
    };
    s.apply_delta(&params(), &past).unwrap();
    assert!(s.removals.is_empty());
    s.merge(&params(), &holder).unwrap();
    assert!(
        s.entries.is_empty(),
        "below the floor, the entry is gone for good"
    );
    s.verify(&params()).unwrap();
}

#[test]
fn a_removal_is_admitted_only_as_the_bridge_signed_it() {
    let w = entry(&ghostkeys()[0], 102, 1);
    let mut s = with_entries(100, std::slice::from_ref(&w));
    let before = bytes(&s);
    let set: BTreeSet<RemovedPrefix> = [w.entry.key().removal_prefix()].into();
    let forged = RemovalBatch::sign(&SigningKey::from_bytes(&[1u8; 32]), 102, &set);
    assert!(apply_removals(&mut s, vec![forged]).is_err());
    let mut moved = removal(102, &[&w]);
    moved.height = 103;
    assert!(
        apply_removals(&mut s, vec![moved]).is_err(),
        "the height is signed: moved later, a removal would outlive its entry's window"
    );
    assert_eq!(bytes(&s), before);
}

/// One set of removals has one spelling, or two peers holding the same
/// removals could hold different bytes.
#[test]
fn a_removal_batch_in_any_shape_but_its_one_form_is_refused() {
    let signed = |raw: Vec<u8>| RemovalBatch {
        height: 101,
        signature: ByteBuf(
            bridge_sk()
                .sign(&crate::removal_message(&bridge(), 101, &raw))
                .to_bytes()
                .to_vec(),
        ),
        removed: ByteBuf(raw),
    };
    let (a, b) = ([1u8; 8], [2u8; 8]);
    let too_many: Vec<u8> = (0..=MAX_REMOVED as u64)
        .flat_map(|i| i.to_be_bytes())
        .collect();
    for (raw, why) in [
        (vec![], "empty"),
        ([a, a].concat(), "a repeat"),
        ([b, a].concat(), "out of order"),
        (vec![1u8; 7], "a partial prefix"),
        (too_many, "more than a state may hold"),
    ] {
        let mut s = open_at(100);
        assert!(apply_removals(&mut s, vec![signed(raw)]).is_err(), "{why}");
    }
    let mut s = open_at(100);
    apply_removals(&mut s, vec![signed([a, b].concat())]).unwrap();
    s.verify(&params()).unwrap();
}

#[test]
fn a_larger_batch_for_a_height_replaces_the_smaller_one_it_covers() {
    let gks = ghostkeys();
    let (x, y) = (entry(&gks[0], 102, 1), entry(&gks[1], 102, 2));
    let mut s = with_entries(100, &[x.clone(), y.clone()]);
    apply_removals(&mut s, vec![removal(102, &[&x])]).unwrap();
    assert_eq!((s.removals.len(), s.entries.len()), (1, 1));
    apply_removals(&mut s, vec![removal(102, &[&x, &y])]).unwrap();
    assert_eq!(s.removals.len(), 1, "the smaller batch is covered and goes");
    assert!(s.entries.is_empty());
    s.verify(&params()).unwrap();

    let before = bytes(&s);
    apply_removals(&mut s, vec![removal(102, &[&x])]).unwrap();
    assert_eq!(bytes(&s), before, "arriving late, it changes nothing");
}

#[test]
fn a_batch_is_covered_only_by_one_at_its_height_that_removes_as_much() {
    let x = entry(&ghostkeys()[0], 102, 1);
    let y = entry(&ghostkeys()[1], 102, 2);
    assert!(
        !removal(101, &[&x]).covered_by(&removal(103, &[&x])),
        "a batch at another height names other entries"
    );
    assert!(!removal(103, &[&x]).covered_by(&removal(101, &[&x])));
    assert!(!removal(102, &[&x, &y]).covered_by(&removal(102, &[&x])));
    assert!(!removal(102, &[&x]).covered_by(&removal(102, &[&y])));
    assert!(removal(102, &[&x]).covered_by(&removal(102, &[&y, &x])));
}

/// What `verify` would have to be told: a state with a covered batch still in
/// it is not in normal form.
#[test]
fn verify_refuses_a_covered_batch_left_in_place() {
    let (x, y) = (
        entry(&ghostkeys()[0], 102, 1),
        entry(&ghostkeys()[1], 102, 2),
    );
    let mut s = open_at(100);
    apply_removals(&mut s, vec![removal(102, &[&x, &y])]).unwrap();
    let small = removal(102, &[&x]);
    s.removals.insert(small.key(), small);
    assert!(s.verify(&params()).is_err());
}

#[test]
fn removals_past_their_bound_are_refused_whole() {
    let mut s = open_at(100);
    let a = RemovalBatch::sign(&bridge_sk(), 101, &prefixes(0, MAX_REMOVED / 2));
    let b = RemovalBatch::sign(&bridge_sk(), 102, &prefixes(1 << 32, MAX_REMOVED / 2));
    apply_removals(&mut s, vec![a, b]).unwrap();
    s.verify(&params()).unwrap();
    let before = bytes(&s);
    let one_more = RemovalBatch::sign(&bridge_sk(), 103, &prefixes(1 << 40, 1));
    assert!(apply_removals(&mut s, vec![one_more]).is_err());
    assert_eq!(bytes(&s), before);

    // Removals the floor has passed no longer count.
    s.apply_delta(
        &params(),
        &InboxDelta {
            floor: Some(SignedFloor::sign(&bridge_sk(), 102)),
            ..Default::default()
        },
    )
    .unwrap();
    let one_more = RemovalBatch::sign(&bridge_sk(), 103, &prefixes(1 << 40, 1));
    apply_removals(&mut s, vec![one_more]).unwrap();
}

#[test]
fn removal_batches_past_their_count_are_refused() {
    // Batches at one height naming one different prefix each: none covers
    // another, so none is dropped.
    let batch = |i: u64| RemovalBatch::sign(&bridge_sk(), 101, &prefixes(i, 1));
    let mut s = open_at(100);
    apply_removals(&mut s, (0..MAX_REMOVAL_BATCHES as u64).map(batch).collect()).unwrap();
    assert_eq!(s.removals.len(), MAX_REMOVAL_BATCHES);
    let before = bytes(&s);
    assert!(apply_removals(&mut s, vec![batch(MAX_REMOVAL_BATCHES as u64)]).is_err());
    assert_eq!(bytes(&s), before);
}

#[test]
fn a_floor_never_goes_down() {
    let mut s = open_at(100);
    s.apply_delta(
        &params(),
        &InboxDelta {
            floor: Some(SignedFloor::sign(&bridge_sk(), 90)),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(s.floor_height(), Some(100));
}

// --- caps -------------------------------------------------------------------------

#[test]
fn one_ghostkey_keeps_only_its_newest_records() {
    let gk = &ghostkeys()[0];
    let es: Vec<WireEntry> = (0..(MAX_ENTRIES_PER_GHOSTKEY as u32 + 3))
        .map(|i| entry(gk, 100 + (i % WINDOW_BLOCKS), i as u8))
        .collect();
    let s = one_by_one(100, &es);
    assert_eq!(s.entries.len(), MAX_ENTRIES_PER_GHOSTKEY);
    let lowest_kept = s.entries.values().map(|e| e.mainnet_height).min().unwrap();
    let highest_dropped = es
        .iter()
        .filter(|w| !s.entries.contains_key(&w.entry.key()))
        .map(|w| w.entry.mainnet_height)
        .max()
        .unwrap();
    assert!(
        highest_dropped <= lowest_kept,
        "the oldest are the ones dropped"
    );
    s.verify(&params()).unwrap();
}

#[test]
fn the_inbox_as_a_whole_keeps_only_its_newest_records() {
    let es: Vec<WireEntry> = ghostkeys()
        .iter()
        .enumerate()
        .map(|(i, gk)| entry(gk, 100 + (i as u32 % WINDOW_BLOCKS), 1))
        .collect();
    assert!(es.len() > MAX_ENTRIES);
    // More than one delta may carry, so in two.
    let mut s = with_entries(100, &es[..MAX_ENTRIES]);
    add_entries(&mut s, es[MAX_ENTRIES..].to_vec());
    assert_eq!(s.entries.len(), MAX_ENTRIES);
    s.verify(&params()).unwrap();
}

/// The point of the change from tombstones: a read entry gives its place
/// back at once, rather than holding it until the floor passes.
#[test]
fn a_removal_frees_its_entrys_place_under_either_cap() {
    // One Ghost Key's allowance.
    let gk = &ghostkeys()[0];
    let es: Vec<WireEntry> = (0..MAX_ENTRIES_PER_GHOSTKEY as u32)
        .map(|i| entry(gk, 103, i as u8))
        .collect();
    let mut s = with_entries(100, &es);
    let older = entry(gk, 101, 200);
    add_entries(&mut s, vec![older.clone()]);
    assert!(!s.entries.contains_key(&older.entry.key()), "full");
    apply_removals(&mut s, vec![removal(103, &[&es[0]])]).unwrap();
    add_entries(&mut s, vec![older.clone()]);
    assert!(
        s.entries.contains_key(&older.entry.key()),
        "one read, one free"
    );
    s.verify(&params()).unwrap();

    // Arriving together, as in any whole-state merge: the removal is applied
    // before the caps, so the removed entry's place goes to the older one.
    let mut s = with_entries(100, &es);
    s.apply_delta(
        &params(),
        &InboxDelta {
            entries: vec![older.clone()],
            removals: vec![removal(103, &[&es[0]])],
            ..Default::default()
        },
    )
    .unwrap();
    assert!(
        s.entries.contains_key(&older.entry.key()),
        "removal first, then the caps"
    );

    // The whole inbox.
    let gks = ghostkeys();
    let full: Vec<WireEntry> = gks[..MAX_ENTRIES]
        .iter()
        .map(|g| entry(g, 103, 1))
        .collect();
    let mut s = with_entries(100, &full);
    let late = entry(&gks[MAX_ENTRIES], 101, 1);
    add_entries(&mut s, vec![late.clone()]);
    assert!(!s.entries.contains_key(&late.entry.key()), "full");
    apply_removals(&mut s, vec![removal(103, &[&full[0]])]).unwrap();
    add_entries(&mut s, vec![late.clone()]);
    assert!(s.entries.contains_key(&late.entry.key()));
    s.verify(&params()).unwrap();
}

/// Superseded batches stay signed and public, so a peer must not verify one
/// that a batch it holds already covers. A corrupted signature shows it was
/// not verified, and the state shows it changed nothing.
#[test]
fn a_batch_already_covered_is_passed_over_without_being_checked() {
    let (x, y) = (
        entry(&ghostkeys()[0], 102, 1),
        entry(&ghostkeys()[1], 102, 2),
    );
    let mut s = open_at(100);
    apply_removals(&mut s, vec![removal(102, &[&x, &y])]).unwrap();
    let before = bytes(&s);
    let mut stale = removal(102, &[&x]);
    stale.signature.0[0] ^= 1;
    apply_removals(&mut s, vec![stale]).unwrap();
    assert_eq!(bytes(&s), before);
}

/// A batch removes only entries of its own height. One dated below an entry
/// whose prefix it shares, as a collision between a sender's own entries
/// would make it, neither hides the entry nor lets the grouping of a three-way
/// merge decide whether it survives; so below the caps the merge laws hold
/// exactly, even under a collision.
#[test]
fn a_batch_at_another_height_leaves_an_entry_sharing_its_prefix_alone() {
    let e = entry(&ghostkeys()[0], 103, 1);
    let named: BTreeSet<RemovedPrefix> = [e.entry.key().removal_prefix()].into();
    let a = with_entries(100, std::slice::from_ref(&e));
    let mut b = open_at(100);
    apply_removals(&mut b, vec![RemovalBatch::sign(&bridge_sk(), 100, &named)]).unwrap();
    let c = open_at(101);
    let left = merged(&merged(&a, &b), &c);
    let right = merged(&a, &merged(&b, &c));
    assert_eq!(bytes(&left), bytes(&right), "associative");
    assert!(left.entries.contains_key(&e.entry.key()));
    merged(&a, &b).verify(&params()).unwrap();

    // At the entry's own height, the same prefix does remove it.
    let mut d = a.clone();
    apply_removals(&mut d, vec![RemovalBatch::sign(&bridge_sk(), 103, &named)]).unwrap();
    assert!(d.entries.is_empty());
}

/// An honest delta carries at most two entries from one Ghost Key: it comes
/// from a state in normal form, or is one sender's submission. More is
/// refused before anything is verified, so one Ghost Key cannot make every
/// peer check a hundred of its entries per delta.
#[test]
fn a_delta_with_more_entries_from_one_ghostkey_than_a_state_holds_is_refused() {
    let gk = &ghostkeys()[0];
    let es: Vec<WireEntry> = (0..=MAX_ENTRIES_PER_GHOSTKEY as u8)
        .map(|i| entry(gk, 103, i))
        .collect();
    let mut s = open_at(100);
    let before = bytes(&s);
    let err = s
        .apply_delta(
            &params(),
            &InboxDelta {
                entries: es,
                ..Default::default()
            },
        )
        .unwrap_err();
    assert!(err.contains("from one Ghost Key"), "{err}");
    assert_eq!(bytes(&s), before);
}

/// A state can carry batches built so that every comparison between them
/// walks to the end, and needs no signature to do it. The total is bounded
/// first: two batches, one covering the other, and too many prefixes between
/// them, must fail on the total rather than on the covering.
#[test]
fn verify_bounds_the_removals_before_comparing_them() {
    let mut s = open_at(100);
    for n in [MAX_REMOVED / 2 + 1, MAX_REMOVED / 2 + 2] {
        let b = RemovalBatch::sign(&bridge_sk(), 101, &prefixes(0, n));
        s.removals.insert(b.key(), b);
    }
    let err = s.verify(&params()).unwrap_err();
    assert!(err.contains("removed entries"), "{err}");
}

/// A batch the floor has passed removes nothing, even in the merge that
/// raises the floor past it, so below the caps the laws hold exactly. The
/// batch names the entry's prefix, as an 8-byte prefix collision would.
#[test]
fn a_batch_below_a_newly_raised_floor_removes_nothing_in_that_merge() {
    let e = entry(&ghostkeys()[0], 103, 1);
    let named: BTreeSet<RemovedPrefix> = [e.entry.key().removal_prefix()].into();
    let mut a = open_at(100);
    apply_removals(&mut a, vec![RemovalBatch::sign(&bridge_sk(), 100, &named)]).unwrap();
    let c = with_entries(101, std::slice::from_ref(&e));
    assert_eq!(bytes(&merged(&a, &c)), bytes(&merged(&c, &a)));
    assert!(merged(&a, &c).entries.contains_key(&e.entry.key()));

    // Likewise when the delta that raises the floor carries a removal too.
    let other = entry(&ghostkeys()[1], 103, 2);
    let mut d = a.clone();
    d.apply_delta(
        &params(),
        &InboxDelta {
            floor: Some(SignedFloor::sign(&bridge_sk(), 101)),
            entries: vec![e.clone()],
            removals: vec![removal(103, &[&other])],
        },
    )
    .unwrap();
    assert!(d.entries.contains_key(&e.entry.key()));
}

/// Certificates are public, so a state carrying ones no entry uses must be
/// refused before any of them costs an RSA check. This one would fail its
/// RSA-backed check, so the error shows which check came first.
#[test]
fn verify_refuses_an_unused_certificate_before_checking_any() {
    let mut s = with_entries(100, &[entry(&ghostkeys()[0], 103, 1)]);
    let weak = certify(ed25519_dalek::VerifyingKey::from_bytes(&[0u8; 32]).unwrap());
    s.certificates.insert(cert_key(&weak), weak);
    let err = s.verify(&params()).unwrap_err();
    assert!(err.contains("no entry uses"), "{err}");
}

// --- the merge, on exact bytes -------------------------------------------------------

/// Entries from `gks`, `per_key` each, dated across the window above 100,
/// and removal batches over them: for each height, nested batches (so one
/// covers another) and disjoint ones (so neither does).
fn pool(gks: &[Gk], per_key: usize) -> (Vec<WireEntry>, Vec<RemovalBatch>) {
    let mut entries = Vec::new();
    for (gi, gk) in gks.iter().enumerate() {
        for i in 0..per_key {
            entries.push(entry(
                gk,
                100 + ((i * 3 + gi) as u32 % (WINDOW_BLOCKS + 1)),
                (i + 10 * gi) as u8,
            ));
        }
    }
    let mut batches = Vec::new();
    for h in 100..=100 + WINDOW_BLOCKS {
        let at: Vec<&WireEntry> = entries
            .iter()
            .filter(|w| w.entry.mainnet_height == h)
            .collect();
        if at.is_empty() {
            continue;
        }
        let half = at.len().div_ceil(2);
        batches.push(removal(h, &at[..half]));
        batches.push(removal(
            h,
            &at[half..].iter().copied().take(1).collect::<Vec<_>>(),
        ));
        batches.push(removal(h, &at));
        if at.len() > 2 {
            batches.push(removal(h, &at[1..2]));
        }
    }
    batches.retain(|b| !b.is_empty());
    (entries, batches)
}

/// A random valid state drawn from a shared pool, so different states
/// overlap, collide on caps, and remove each other's entries.
fn random_state(rng: &mut StdRng, entries: &[WireEntry], batches: &[RemovalBatch]) -> InboxStateV1 {
    // Sometimes a peer that has never seen the inbox opened: the commonest
    // first contact, and a different path through the merge.
    if rng.gen_bool(0.15) {
        return InboxStateV1::default();
    }
    let floor = 100 + rng.gen_range(0..3);
    let mut s = open_at(floor);
    let chosen: Vec<WireEntry> = entries
        .iter()
        .filter(|_| rng.gen_bool(0.5))
        .cloned()
        .collect();
    add_entries(&mut s, chosen);
    let chosen: Vec<RemovalBatch> = batches
        .iter()
        .filter(|_| rng.gen_bool(0.3))
        .cloned()
        .collect();
    apply_removals(&mut s, chosen).unwrap();
    s
}

fn merged(a: &InboxStateV1, b: &InboxStateV1) -> InboxStateV1 {
    let mut x = a.clone();
    x.merge(&params(), b).unwrap();
    x
}

/// Below the caps nothing is discarded, and the merge laws hold exactly.
#[test]
fn below_the_caps_the_merge_is_commutative_associative_and_idempotent() {
    // Two entries per Ghost Key and far fewer than the inbox holds: no cap
    // binds, and every removal path is exercised.
    let (entries, batches) = pool(&ghostkeys()[..24], MAX_ENTRIES_PER_GHOSTKEY);
    assert!(entries.len() < MAX_ENTRIES);
    let mut rng = StdRng::seed_from_u64(0x1b0c);
    for round in 0..40 {
        let a = random_state(&mut rng, &entries, &batches);
        let b = random_state(&mut rng, &entries, &batches);
        let c = random_state(&mut rng, &entries, &batches);
        for s in [&a, &b, &c] {
            s.verify(&params()).unwrap();
        }
        assert_eq!(
            bytes(&merged(&a, &b)),
            bytes(&merged(&b, &a)),
            "commutative, round {round}"
        );
        assert_eq!(
            bytes(&merged(&merged(&a, &b), &c)),
            bytes(&merged(&a, &merged(&b, &c))),
            "associative, round {round}"
        );
        assert_eq!(
            bytes(&merged(&a, &a)),
            bytes(&a),
            "idempotent, round {round}"
        );
        merged(&merged(&a, &b), &c).verify(&params()).unwrap();
    }
}

/// The case the crate documentation describes: above the caps, the order
/// records arrive in decides which entry survives. And the recovery: a peer
/// that kept the entry gives it back.
#[test]
fn an_entry_discarded_for_want_of_room_comes_back_from_a_peer_that_kept_it() {
    let gk = &ghostkeys()[0];
    let (hi1, hi2, lo) = (entry(gk, 103, 1), entry(gk, 103, 2), entry(gk, 101, 3));
    let all = [hi1.clone(), hi2.clone(), lo.clone()];

    // Entries first: `lo` ranks third of three and is discarded, and the
    // removal that would have made room comes too late.
    let mut early = one_by_one(100, &all);
    apply_removals(&mut early, vec![removal(103, &[&hi1])]).unwrap();
    assert!(!early.entries.contains_key(&lo.entry.key()));

    // Removal first: there is room for `lo` when it arrives.
    let mut late = open_at(100);
    apply_removals(&mut late, vec![removal(103, &[&hi1])]).unwrap();
    for w in &all {
        add_entries(&mut late, vec![w.clone()]);
    }
    assert!(late.entries.contains_key(&lo.entry.key()));
    assert_ne!(bytes(&early), bytes(&late), "the order decided");

    // One exchange, and both hold the same bytes, with `lo` back.
    assert_eq!(bytes(&merged(&early, &late)), bytes(&merged(&late, &early)));
    assert!(merged(&early, &late).entries.contains_key(&lo.entry.key()));
    merged(&early, &late).verify(&params()).unwrap();
}

/// Above the caps, what still holds: a merge is commutative and idempotent,
/// two peers that exchange state hold the same bytes afterwards, and peers
/// gossiping settle on one state.
#[test]
fn above_the_caps_peers_that_exchange_state_agree_and_gossip_settles() {
    let (entries, batches) = pool(&ghostkeys()[..4], MAX_ENTRIES_PER_GHOSTKEY + 5);
    let mut rng = StdRng::seed_from_u64(0x5eed);
    for round in 0..30 {
        // Each peer receives a random selection one record at a time, in its
        // own order, which is how the discarding happens.
        let mut peers: Vec<InboxStateV1> = (0..4)
            .map(|_| {
                let mut s = open_at(100);
                let mut records: Vec<Result<&WireEntry, &RemovalBatch>> = entries
                    .iter()
                    .filter(|_| rng.gen_bool(0.6))
                    .map(Ok)
                    .collect();
                records.extend(batches.iter().filter(|_| rng.gen_bool(0.4)).map(Err));
                records.shuffle(&mut rng);
                for r in records {
                    match r {
                        Ok(w) => add_entries(&mut s, vec![w.clone()]),
                        Err(b) => apply_removals(&mut s, vec![b.clone()]).unwrap(),
                    }
                }
                s.verify(&params()).unwrap();
                s
            })
            .collect();

        for a in &peers {
            assert_eq!(bytes(&merged(a, a)), bytes(a), "idempotent, round {round}");
            for b in &peers {
                assert_eq!(
                    bytes(&merged(a, b)),
                    bytes(&merged(b, a)),
                    "commutative, round {round}"
                );
            }
        }

        let mut passes = 0;
        loop {
            let mut changed = false;
            for i in 0..peers.len() {
                for j in 0..peers.len() {
                    let m = merged(&peers[i], &peers[j]);
                    if m != peers[i] || m != peers[j] {
                        peers[i] = m.clone();
                        peers[j] = m;
                        changed = true;
                    }
                }
            }
            passes += 1;
            if !changed {
                break;
            }
            assert!(passes < 10, "gossip did not settle, round {round}");
        }
        for p in &peers {
            assert_eq!(bytes(p), bytes(&peers[0]), "round {round}");
        }
        peers[0].verify(&params()).unwrap();
    }
}

#[test]
fn state_bytes_do_not_depend_on_arrival_order() {
    let gk = &ghostkeys()[0];
    let es: Vec<WireEntry> = (0..6).map(|i| entry(gk, 100 + i, i as u8)).collect();
    let mut rev = es.clone();
    rev.reverse();
    assert_eq!(bytes(&one_by_one(100, &es)), bytes(&one_by_one(100, &rev)));
}

/// As above, but closer to how peers really meet: enough Ghost Keys that the
/// inbox-wide cap binds as well as the per-key one (with four only the
/// per-key cap ever does), peers at different floors, and peers exchanging
/// summaries and deltas rather than whole states. Fewer rounds, since every
/// entry costs an RSA check.
#[test]
fn above_both_caps_summary_and_delta_exchange_settles_on_one_full_inbox() {
    let (entries, batches) = pool(&ghostkeys()[..100], MAX_ENTRIES_PER_GHOSTKEY + 1);
    let mut rng = StdRng::seed_from_u64(0xf1_11);
    let mut filled = false;
    let mut varied = false;
    // One direction of an exchange: `to` asks `from` for what it lacks.
    let pull = |to: &mut InboxStateV1, from: &InboxStateV1| {
        if let Some(d) = from.delta(&to.summarize()) {
            to.apply_delta(&params(), &d).unwrap();
        }
    };
    for round in 0..3 {
        let mut peers: Vec<InboxStateV1> = (0..3)
            .map(|_| {
                let mut s = open_at(100 + rng.gen_range(0..2));
                let mut records: Vec<Result<&WireEntry, &RemovalBatch>> = entries
                    .iter()
                    .filter(|_| rng.gen_bool(0.8))
                    .map(Ok)
                    .collect();
                records.extend(batches.iter().filter(|_| rng.gen_bool(0.15)).map(Err));
                records.shuffle(&mut rng);
                for r in records {
                    match r {
                        Ok(w) => add_entries(&mut s, vec![w.clone()]),
                        Err(b) => apply_removals(&mut s, vec![b.clone()]).unwrap(),
                    }
                }
                s
            })
            .collect();
        filled |= peers.iter().any(|p| p.entries.len() == MAX_ENTRIES);
        varied |= peers
            .iter()
            .any(|p| p.floor_height() != peers[0].floor_height());

        let mut settled = false;
        for _ in 0..20 {
            let before: Vec<Vec<u8>> = peers.iter().map(bytes).collect();
            for i in 0..peers.len() {
                for j in 0..peers.len() {
                    if i != j {
                        let from = peers[j].clone();
                        pull(&mut peers[i], &from);
                    }
                }
            }
            if peers.iter().map(bytes).collect::<Vec<_>>() == before {
                settled = true;
                break;
            }
        }
        assert!(settled, "exchange did not settle, round {round}");
        for p in &peers {
            assert_eq!(bytes(p), bytes(&peers[0]), "round {round}");
        }
        peers[0].verify(&params()).unwrap();
    }
    assert!(
        filled,
        "the inbox-wide cap never bound, so this tested nothing new"
    );
    assert!(
        varied,
        "every peer shared one floor, so differing floors went untested"
    );
}

// --- synchronization ------------------------------------------------------------------

#[test]
fn two_peers_converge_through_summaries_and_deltas() {
    let gks = ghostkeys();
    let a = with_entries(100, &[entry(&gks[0], 103, 1), entry(&gks[1], 104, 2)]);
    let b = with_entries(102, &[entry(&gks[2], 105, 3), entry(&gks[0], 103, 1)]);
    assert_eq!(
        (a.entries.len(), b.entries.len()),
        (2, 2),
        "all inside the window"
    );
    let mut a2 = a.clone();
    let mut b2 = b.clone();
    if let Some(d) = b.delta(&a.summarize()) {
        a2.apply_delta(&params(), &d).unwrap();
    }
    if let Some(d) = a.delta(&b.summarize()) {
        b2.apply_delta(&params(), &d).unwrap();
    }
    assert_eq!(bytes(&a2), bytes(&b2));
    assert_eq!(bytes(&a2), bytes(&merged(&a, &b)));
}

/// A sender records a floor broadcast as delivered when it queues it, so it
/// can believe a peer holds a floor the peer never got. The entries it then
/// sends must still be admitted there.
#[test]
fn a_delta_carries_the_floor_that_admits_its_entries() {
    let sender = with_entries(110, &[entry(&ghostkeys()[0], 110 + WINDOW_BLOCKS, 1)]);
    let believed = open_at(110).summarize();
    let d = sender.delta(&believed).unwrap();
    assert!(d.floor.is_some(), "the floor travels with the entry");
    let mut peer = open_at(100);
    peer.apply_delta(&params(), &d).unwrap();
    assert_eq!(peer.entries.len(), 1);

    let w = entry(&ghostkeys()[1], 110 + WINDOW_BLOCKS, 2);
    let mut other = open_at(100);
    other
        .apply_delta(&params(), &InboxDelta::submission(sender.floor.clone(), w))
        .unwrap();
    assert_eq!(other.entries.len(), 1, "and a sender's own submission");
}

/// A peer behind only on the floor still gets the floor, and nothing else.
#[test]
fn a_peer_behind_only_on_the_floor_is_sent_the_floor() {
    let s = with_entries(105, &[entry(&ghostkeys()[0], 106, 1)]);
    let mut behind = s.summarize();
    behind.floor = Some(100);
    let d = s.delta(&behind).unwrap();
    assert_eq!(d.floor.map(|f| f.height), Some(105));
    assert!(d.entries.is_empty() && d.removals.is_empty());
}

#[test]
fn a_converged_peer_is_sent_nothing() {
    let s = with_entries(100, &[entry(&ghostkeys()[0], 104, 1)]);
    assert!(s.delta(&s.summarize()).is_none());
}

/// The summary goes to every interested peer on every heartbeat, so it must
/// not grow with the inbox.
#[test]
fn a_summary_is_the_same_small_size_whatever_the_inbox_holds() {
    let empty = to_cbor(&open_at(100).summarize()).unwrap();
    let es: Vec<WireEntry> = ghostkeys()[..40]
        .iter()
        .enumerate()
        .map(|(i, g)| entry(g, 100 + (i as u32 % WINDOW_BLOCKS), 1))
        .collect();
    let full = to_cbor(&with_entries(100, &es).summarize()).unwrap();
    assert_eq!(empty.len(), full.len());
    assert!(full.len() < 600, "summary is {} bytes", full.len());
}

// --- bounds and canonical forms -----------------------------------------------------

#[test]
fn a_delta_larger_than_the_caps_is_refused_before_anything_is_checked() {
    let w = entry(&ghostkeys()[0], 104, 1);
    let r = removal(104, &[&w]);
    let mut s = open_at(100);
    let before = bytes(&s);
    let many_removals = InboxDelta {
        removals: vec![r; MAX_REMOVAL_BATCHES + 1],
        ..Default::default()
    };
    assert!(s.apply_delta(&params(), &many_removals).is_err());
    let many_entries = InboxDelta {
        entries: vec![w; MAX_ENTRIES + 1],
        ..Default::default()
    };
    assert!(s.apply_delta(&params(), &many_entries).is_err());
    assert_eq!(bytes(&s), before);
}

/// Each batch is hashed whole before it can be passed over, so a delta's
/// total length is bounded before any is. Without that, batches dated below
/// the floor, which change nothing and are accepted, could be sent at any size.
#[test]
fn a_delta_naming_more_removals_than_a_state_may_is_refused() {
    let at =
        |h: u32, start: u64, n: usize| RemovalBatch::sign(&bridge_sk(), h, &prefixes(start, n));
    let mut s = open_at(100);
    let before = bytes(&s);
    let half = MAX_REMOVED / 2;
    apply_removals(&mut s, vec![at(90, 0, half), at(91, 1 << 32, half)]).unwrap();
    assert_eq!(bytes(&s), before, "batches below the floor change nothing");
    assert!(apply_removals(&mut s, vec![at(90, 0, half), at(91, 1 << 32, half + 1)]).is_err());
    assert_eq!(bytes(&s), before);
}

/// Certificates and the floor are public, so anyone can pair real ones with
/// forged entries. Such a delta or state must fail on the entries' own
/// signatures, before any certificate's RSA check is spent on it.
#[test]
fn a_forged_entry_fails_before_its_certificate_is_checked() {
    // Under another master key every certificate fails, so which error comes
    // back says which check ran first.
    let mut other = params();
    other.ghostkey_master.0 = SigningKey::from_bytes(&[9u8; 32])
        .verifying_key()
        .to_bytes();

    let w = entry(&ghostkeys()[0], 104, 1);
    let mut forged = w.clone();
    let mut sig = forged.entry.signature.as_ref().to_vec();
    sig[0] ^= 1;
    forged.entry.signature = ByteBuf(sig);

    let submit = |d: &WireEntry| {
        open_at(100).apply_delta(
            &other,
            &InboxDelta {
                entries: vec![d.clone()],
                ..Default::default()
            },
        )
    };
    let err = submit(&w).unwrap_err();
    assert!(err.contains("does not chain"), "{err}");
    let err = submit(&forged).unwrap_err();
    assert!(err.contains("did not sign"), "{err}");

    let s = with_entries(100, &[w]);
    let err = s.verify(&other).unwrap_err();
    assert!(err.contains("does not chain"), "{err}");
    let mut bad = s.clone();
    bad.entries.clear();
    bad.entries.insert(forged.entry.key(), forged.entry.clone());
    let err = bad.verify(&other).unwrap_err();
    assert!(err.contains("did not sign"), "{err}");
}

/// A certificate for the attacker's own key, carrying someone else's notary
/// signature: it names the key that signs the entry, so only its RSA check
/// refuses it. A message of such entries costs one RSA check however many it
/// carries, since validation stops at the first that fails.
#[test]
fn fabricated_certificates_cost_one_rsa_check_per_message() {
    let rsa = || RSA_CHECKS.with(|c| c.get());
    let fakes: Vec<WireEntry> = (0..3u8)
        .map(|i| {
            let sk = SigningKey::from_bytes(&[20 + i; 32]);
            let mut cert = GhostkeyCertificateV1::from_armored_string(&ghostkeys()[0].pem).unwrap();
            cert.verifying_key = sk.verifying_key();
            let gk = Gk {
                sk,
                pem: cert.to_armored_string().unwrap(),
            };
            entry(&gk, 104, i)
        })
        .collect();

    let before = rsa();
    let err = open_at(100)
        .apply_delta(
            &params(),
            &InboxDelta {
                entries: fakes.clone(),
                ..Default::default()
            },
        )
        .unwrap_err();
    assert!(err.contains("does not chain"), "{err}");
    assert_eq!(rsa() - before, 1, "apply_delta");

    let mut s = open_at(100);
    for w in &fakes {
        s.certificates
            .insert(w.entry.cert, w.certificate_pem.clone());
        s.entries.insert(w.entry.key(), w.entry.clone());
    }
    let before = rsa();
    let err = s.verify(&params()).unwrap_err();
    assert!(err.contains("does not chain"), "{err}");
    assert_eq!(rsa() - before, 1, "verify");
}

/// An entry signed by a key nobody certified, carrying someone else's real
/// certificate. Its signature checks out under the key it claims, so only
/// reading the certificate shows the mismatch, and every path that reads
/// entries must do that before spending the certificate's RSA check.
#[test]
fn an_uncertified_signer_carrying_a_real_certificate_costs_no_rsa_check() {
    let rsa = || RSA_CHECKS.with(|c| c.get());
    let impostor = SigningKey::from_bytes(&[11u8; 32]);
    let mut w = entry(&ghostkeys()[0], 104, 1);
    w.entry.ghostkey = GhostkeyId(impostor.verifying_key().to_bytes());
    w.entry.signature = ByteBuf(impostor.sign(&w.entry.scoped_payload).to_bytes().to_vec());
    assert!(
        verify_entry_signature(&w.entry, &params()).is_ok(),
        "the entry is validly signed under the key it claims"
    );

    let mut s = open_at(100);
    let before = rsa();
    let err = s
        .apply_delta(
            &params(),
            &InboxDelta {
                entries: vec![w.clone()],
                ..Default::default()
            },
        )
        .unwrap_err();
    assert!(err.contains("different Ghost Key"), "{err}");
    assert_eq!(rsa(), before, "apply_delta spent an RSA check");

    // The same entry in a whole state, as a peer or the bridge receives it.
    let mut bad = with_entries(100, &[entry(&ghostkeys()[0], 104, 1)]);
    bad.entries.clear();
    bad.entries.insert(w.entry.key(), w.entry.clone());
    let before = rsa();
    let err = bad.verify(&params()).unwrap_err();
    assert!(err.contains("different Ghost Key"), "{err}");
    assert_eq!(rsa(), before, "verify spent an RSA check");
    assert!(bad.verified_entries(&params()).is_empty());
    assert_eq!(rsa(), before, "verified_entries spent an RSA check");
}

/// A delta refused part-way must leave nothing of itself behind.
#[test]
fn a_refused_delta_changes_nothing() {
    let mut s = open_at(100);
    let before = bytes(&s);
    let good = entry(&ghostkeys()[0], 104, 1);
    // Refused after the floor and the first entry were already taken in.
    let mut forged = entry(&ghostkeys()[1], 105, 2);
    forged.entry.signature.0[0] ^= 1;
    let d = InboxDelta {
        floor: Some(SignedFloor::sign(&bridge_sk(), 101)),
        entries: vec![good, forged],
        ..Default::default()
    };
    assert!(s.apply_delta(&params(), &d).is_err());
    assert_eq!(bytes(&s), before);
}

/// `ghostkey_lib` reads a certificate out of any surrounding text, so one
/// certificate can be sent in unlimited spellings. The state holds one.
#[test]
fn a_certificate_is_stored_in_its_one_form_however_it_was_sent() {
    let g = &ghostkeys()[0];
    let mut w = entry(g, 104, 1);
    w.certificate_pem = format!("any text at all\n{}\nand more after", g.pem);
    let s = with_entries(100, &[w]);
    assert_eq!(s.certificates.values().next(), Some(&g.pem));
    s.verify(&params()).unwrap();
}

/// The spellings a sender can multiply are exactly what the canonical form
/// collapses: two entries, one certificate spelled two ways, one stored copy.
#[test]
fn one_certificate_spelled_two_ways_is_stored_once() {
    let g = &ghostkeys()[0];
    let a = entry(g, 103, 1);
    let mut b = entry(g, 104, 2);
    b.certificate_pem = format!("a prefix\n{}", g.pem);
    let s = with_entries(100, &[a, b]);
    assert_eq!(s.entries.len(), 2);
    assert_eq!(s.certificates.len(), 1);
    s.verify(&params()).unwrap();
}

/// A reader acting on entries one at a time must still leave out every entry
/// that does not check.
#[test]
fn verified_entries_leaves_out_what_does_not_check() {
    let g = ghostkeys();
    let good = entry(&g[0], 104, 1);
    let mut s = with_entries(100, std::slice::from_ref(&good));

    let misfiled = entry(&g[1], 105, 2);
    s.certificates
        .insert(misfiled.entry.cert, misfiled.certificate_pem.clone());
    s.entries
        .insert(EntryKey([9u8; 32]), misfiled.entry.clone());

    let uncertified = entry(&g[2], 106, 3);
    s.entries
        .insert(uncertified.entry.key(), uncertified.entry.clone());

    let mut forged = entry(&g[3], 107, 4);
    forged.entry.signature.0[0] ^= 1;
    s.certificates
        .insert(forged.entry.cert, forged.certificate_pem.clone());
    s.entries.insert(forged.entry.key(), forged.entry.clone());

    let kept: Vec<EntryKey> = s
        .verified_entries(&params())
        .into_iter()
        .map(|(k, _)| k)
        .collect();
    assert_eq!(kept, vec![good.entry.key()]);
}

/// The bridge holds every watch back while it reads an entry it cannot
/// accept, and that gate is safe to have only because of one property
/// spanning two functions: every reason `verified_entries` skips an entry is
/// a reason `verify` refuses the whole state. So a state a node validated
/// holds nothing this bridge skips, and the gate cannot be held down by
/// anything a sender sends.
///
/// If that ever stopped holding, no watch would end on any network for as
/// long as the entry sat there, and nothing else in either crate would fail.
/// A comment is not enough to carry that; this asserts it.
///
/// Each case is the base state plus one tampering, and the base is asserted
/// to verify, so a refusal here is caused by the tampering and not by
/// something else in the state. Heights stay inside the window for the same
/// reason.
///
/// What this does not reach, and what a future round should add: the classes
/// where an entry's certificate is real but wrong for it
/// (`names_claimed_key`), where the certificate's own chain does not check
/// (`verify_certificate`, `certifies`), and where a removal batch already
/// covers the entry. Those need a forged chain or a signed batch to build,
/// and they are the classes the certificate ordering has been moved through
/// most, so they are the ones worth the trouble next.
#[test]
fn every_entry_this_bridge_skips_is_one_the_contract_refuses() {
    let g = ghostkeys();
    let good = entry(&g[0], 104, 1);
    let base = with_entries(100, std::slice::from_ref(&good));
    assert!(
        base.verify(&params()).is_ok(),
        "the untampered state verifies"
    );
    assert_eq!(
        base.verified_entries(&params()).len(),
        base.entries.len(),
        "and this bridge skips nothing in it"
    );

    // Each case tampers with the state in one of the ways `verified_entries`
    // skips for. Heights stay inside the window so that the window rule
    // cannot be what makes `verify` refuse.
    let mut cases: Vec<(&str, InboxStateV1)> = Vec::new();

    let misfiled = entry(&g[1], 101, 2);
    let mut s = base.clone();
    s.certificates
        .insert(misfiled.entry.cert, misfiled.certificate_pem.clone());
    s.entries
        .insert(EntryKey([9u8; 32]), misfiled.entry.clone());
    cases.push(("filed under a key that is not its digest", s));

    let uncertified = entry(&g[2], 102, 3);
    let mut s = base.clone();
    s.entries
        .insert(uncertified.entry.key(), uncertified.entry.clone());
    cases.push(("no certificate for it in the state", s));

    let mut forged = entry(&g[3], 103, 4);
    forged.entry.signature.0[0] ^= 1;
    let mut s = base.clone();
    s.certificates
        .insert(forged.entry.cert, forged.certificate_pem.clone());
    s.entries.insert(forged.entry.key(), forged.entry.clone());
    cases.push(("a signature that does not check", s));

    let odd = entry(&g[0], 103, 5);
    let mut s = base.clone();
    let wrong = CertKey([7u8; 32]);
    let mut moved = odd.entry.clone();
    moved.cert = wrong;
    s.certificates.insert(wrong, odd.certificate_pem.clone());
    s.entries.insert(moved.key(), moved);
    cases.push(("a certificate filed under a key that is not its digest", s));

    for (what, s) in cases {
        let skipped = s.entries.len() - s.verified_entries(&params()).len();
        assert_eq!(skipped, 1, "{what}: this bridge skips it");
        assert!(
            s.verify(&params()).is_err(),
            "{what}: so the contract must refuse the whole state"
        );
    }
}

/// The test above asserts the containment for the classes it can build, but
/// it is three examples of a claim about every skip, so a fourth skip added
/// to `verified_entries` with no matching refusal in `verify` ships with
/// every test green. That was measured, not supposed: adding one leaves the
/// whole suite passing.
///
/// This counts the skips instead. It cannot tell whether a new one is
/// matched, which is the point: it fails, and whoever added it has to say.
#[test]
fn every_skip_in_verified_entries_is_accounted_for() {
    let src = include_str!("state.rs");
    let start = src
        .find("pub fn verified_entries")
        .expect("verified_entries is declared in state.rs");
    let body = &src[start..];
    let end = body.find("\n    }\n").expect("its body ends");
    let skips = body[..end].matches("continue;").count();
    assert_eq!(
        skips, 3,
        "`verified_entries` now has {skips} ways of skipping an entry, not \
         the 3 this pin was written for. Every one of them must be a reason \
         `verify` refuses the whole state, or the bridge holds every watch \
         back for ever against a copy the node was right to serve. Add the \
         matching refusal and a case in \
         `every_entry_this_bridge_skips_is_one_the_contract_refuses`, then \
         correct this count."
    );
}

/// A certificate for `key`, signed by the test notary the way the real one
/// signs: it certifies whatever key it is given.
fn certify(key: ed25519_dalek::VerifyingKey) -> String {
    let a = authority();
    let pair =
        blind_rsa_signatures::KeyPair::new(a.notary_sk.public_key().unwrap(), a.notary_sk.clone());
    let signature =
        ghostkey_lib::util::unblinded_rsa_sign(&pair, &Armorable::to_bytes(&key).unwrap()).unwrap();
    GhostkeyCertificateV1 {
        notary: a.notary.clone(),
        verifying_key: key,
        signature,
    }
    .to_armored_string()
    .unwrap()
}

/// The check below on the key alone is only worth something if the
/// certificate check calls it; this goes through the certificate.
#[test]
fn a_certificate_for_a_weak_key_is_refused() {
    let ordinary = SigningKey::from_bytes(&[3u8; 32]).verifying_key();
    assert!(
        verify_certificate(&certify(ordinary), &authority().master).is_ok(),
        "the construction makes valid certificates"
    );
    let weak = ed25519_dalek::VerifyingKey::from_bytes(&[0u8; 32]).unwrap();
    assert!(verify_certificate(&certify(weak), &authority().master).is_err());
}

/// A low-order key signs for everyone. The all-zero key is one, and the
/// notary would certify it if asked.
#[test]
fn a_weak_ghost_key_is_refused() {
    let weak = ed25519_dalek::VerifyingKey::from_bytes(&[0u8; 32])
        .expect("the all-zero key decodes, as a low-order point");
    assert!(crate::check_ghostkey(&weak).is_err());
    assert!(crate::check_ghostkey(&ghostkeys()[0].sk.verifying_key()).is_ok());
}

#[test]
fn a_state_in_any_encoding_but_its_own_is_refused() {
    fn first_bytes_as_array(v: &mut ciborium::Value) -> bool {
        match v {
            ciborium::Value::Bytes(b) => {
                let arr = b
                    .iter()
                    .map(|x| ciborium::Value::Integer((*x).into()))
                    .collect();
                *v = ciborium::Value::Array(arr);
                true
            }
            ciborium::Value::Array(a) => a.iter_mut().any(first_bytes_as_array),
            ciborium::Value::Map(m) => m.iter_mut().any(|(_, x)| first_bytes_as_array(x)),
            ciborium::Value::Tag(_, x) => first_bytes_as_array(x),
            _ => false,
        }
    }
    let s = with_entries(100, &[entry(&ghostkeys()[0], 104, 1)]);
    let canonical = bytes(&s);
    assert_eq!(InboxStateV1::decode_canonical(&canonical).unwrap(), s);
    assert_eq!(
        InboxStateV1::decode_canonical(&[]).unwrap(),
        InboxStateV1::default()
    );

    let mut value: ciborium::Value = ciborium::de::from_reader(canonical.as_slice()).unwrap();
    assert!(first_bytes_as_array(&mut value));
    let mut respelled = Vec::new();
    ciborium::ser::into_writer(&value, &mut respelled).unwrap();
    let decoded: InboxStateV1 = freenet_bitcoin_common::from_cbor(&respelled).unwrap();
    assert_eq!(decoded, s, "the same content, which a plain decode accepts");
    assert!(InboxStateV1::decode_canonical(&respelled).is_err());
}

#[test]
fn verify_refuses_a_certificate_not_in_its_one_form() {
    let g = &ghostkeys()[0];
    let good = with_entries(100, &[entry(g, 104, 1)]);
    let wrapped = format!("wrapped\n{}", g.pem);
    let mut e = good.entries.values().next().unwrap().clone();
    e.cert = cert_key(&wrapped);
    let mut s = good.clone();
    s.entries = [(e.key(), e)].into_iter().collect();
    s.certificates = [(cert_key(&wrapped), wrapped)].into_iter().collect();
    assert!(s.verify(&params()).is_err());
}

#[test]
fn a_floor_and_removals_arriving_together_apply_as_one_after_the_other() {
    let g = &ghostkeys()[0];
    let low = entry(g, 101, 1);
    let high = entry(g, 104, 2);
    let base = with_entries(100, &[low, high.clone()]);
    let floor = SignedFloor::sign(&bridge_sk(), 102);
    let t = removal(104, &[&high]);

    let mut together = base.clone();
    together
        .apply_delta(
            &params(),
            &InboxDelta {
                floor: Some(floor.clone()),
                removals: vec![t.clone()],
                ..Default::default()
            },
        )
        .unwrap();

    let mut apart = base;
    apply_removals(&mut apart, vec![t]).unwrap();
    apart
        .apply_delta(
            &params(),
            &InboxDelta {
                floor: Some(floor),
                ..Default::default()
            },
        )
        .unwrap();

    assert_eq!(bytes(&together), bytes(&apart));
    assert!(
        together.entries.is_empty(),
        "one below the floor, one removed"
    );
    assert_eq!(together.removals.len(), 1);
    together.verify(&params()).unwrap();
}

#[test]
fn a_byte_buf_encodes_as_one_byte_string_and_still_reads_an_array() {
    let encoded = to_cbor(&ByteBuf(vec![1, 2, 200])).unwrap();
    assert_eq!(encoded, vec![0x43, 1, 2, 200], "major type 2, length 3");
    let from_array: ByteBuf =
        freenet_bitcoin_common::from_cbor(&to_cbor(&vec![1u8, 2, 200]).unwrap()).unwrap();
    assert_eq!(from_array, ByteBuf(vec![1, 2, 200]));
}

// --- normal form ------------------------------------------------------------------

#[test]
fn verify_refuses_a_state_that_is_not_in_normal_form() {
    let w = entry(&ghostkeys()[0], 104, 1);
    let good = with_entries(100, std::slice::from_ref(&w));

    let mut s = good.clone();
    s.certificates
        .insert(cert_key(&ghostkeys()[1].pem), ghostkeys()[1].pem.clone());
    assert!(s.verify(&params()).is_err(), "unreferenced certificate");

    let mut s = good.clone();
    let e = s.entries.values().next().unwrap().clone();
    s.entries.clear();
    s.entries.insert(EntryKey([5u8; 32]), e);
    assert!(s.verify(&params()).is_err(), "entry under the wrong key");

    let mut s = good.clone();
    let r = removal(104, &[&w]);
    s.removals.insert(r.key(), r);
    assert!(s.verify(&params()).is_err(), "removed entry still present");

    let mut s = good.clone();
    let r = removal(104, &[&w]);
    s.removals.insert(BatchKey([6u8; 32]), r);
    s.entries.clear();
    s.certificates.clear();
    assert!(s.verify(&params()).is_err(), "batch under the wrong key");

    let mut s = good.clone();
    let pem = s.certificates.values().next().unwrap().clone();
    s.certificates.clear();
    s.certificates.insert(CertKey([7u8; 32]), pem);
    assert!(
        s.verify(&params()).is_err(),
        "certificate under the wrong key"
    );

    let mut s = open_at(100);
    let old = entry(&ghostkeys()[1], 99, 3);
    let r = removal(99, &[&old]);
    s.removals.insert(r.key(), r);
    assert!(s.verify(&params()).is_err(), "removal below the floor");

    let mut s = open_at(100);
    let r = removal(100 + WINDOW_BLOCKS + 1, &[&old]);
    s.removals.insert(r.key(), r);
    assert!(s.verify(&params()).is_err(), "removal beyond the window");
}

// --- sealing ----------------------------------------------------------------------

#[cfg(feature = "seal")]
mod sealing {
    use super::*;
    use crate::seal::*;

    fn request() -> InboxRequest {
        InboxRequest {
            action: Action::Watch,
            network: freenet_bitcoin_common::BitcoinNetwork::Bitcoin,
            scripts: vec![ByteBuf(vec![0x00, 0x14, 1, 2, 3])],
            scan_from_height: Some(900_000),
            made_at_ms: 1_757_000_000_000,
        }
    }

    fn gk() -> GhostkeyId {
        GhostkeyId([9u8; 32])
    }

    #[test]
    fn the_bridges_two_halves_of_its_encryption_key_agree() {
        let sk = bridge_sk();
        let public = bridge_encryption_key(&bridge()).unwrap();
        let from_secret = x25519_dalek::PublicKey::from(&bridge_decryption_key(&sk));
        assert_eq!(public.as_bytes(), from_secret.as_bytes());
    }

    #[test]
    fn a_sealed_request_opens_for_its_bridge_and_no_other() {
        let s = seal(&bridge(), &gk(), 100, &request()).unwrap();
        assert_eq!(unseal(&bridge_sk(), &gk(), 100, &s).unwrap(), request());
        assert!(unseal(&SigningKey::from_bytes(&[1u8; 32]), &gk(), 100, &s).is_err());
    }

    /// Without this, anyone could copy another sender's sealed request into
    /// an entry of their own, and the bridge would record the interest under
    /// the copier's Ghost Key, where the real sender could never withdraw it.
    #[test]
    fn a_sealed_request_opens_only_in_the_entry_it_was_made_for() {
        let s = seal(&bridge(), &gk(), 100, &request()).unwrap();
        assert!(
            unseal(&bridge_sk(), &GhostkeyId([8u8; 32]), 100, &s).is_err(),
            "another sender's entry"
        );
        assert!(
            unseal(&bridge_sk(), &gk(), 101, &s).is_err(),
            "the same sender, another entry"
        );
    }

    #[test]
    fn a_tampered_sealed_request_does_not_open() {
        let mut s = seal(&bridge(), &gk(), 100, &request()).unwrap();
        s.ciphertext.0[0] ^= 1;
        assert!(unseal(&bridge_sk(), &gk(), 100, &s).is_err());
    }

    #[test]
    fn a_malformed_request_is_refused_before_sealing() {
        let mut r = request();
        r.scripts.clear();
        assert!(seal(&bridge(), &gk(), 100, &r).is_err());
        let mut r = request();
        r.scripts = vec![ByteBuf(vec![1u8; MAX_SCRIPT_BYTES + 1])];
        assert!(seal(&bridge(), &gk(), 100, &r).is_err());
        let mut r = request();
        r.scripts = vec![ByteBuf(vec![1u8; 20]); MAX_SCRIPTS_PER_REQUEST + 1];
        assert!(seal(&bridge(), &gk(), 100, &r).is_err());
    }

    /// The largest request allowed must fit in an entry, or a sender following
    /// every rule could still be refused.
    #[test]
    fn the_largest_allowed_request_fits_in_an_entry() {
        let mut r = request();
        r.scripts = vec![ByteBuf(vec![0xab; MAX_SCRIPT_BYTES]); MAX_SCRIPTS_PER_REQUEST];
        let sealed = seal(&bridge(), &gk(), 100, &r).unwrap();
        let body = InboxEntryBody {
            bridge: bridge(),
            mainnet_height: 100,
            sealed,
        };
        let scoped = to_cbor(&ScopedPayload {
            requestor: webapp(),
            payload: body.signing_payload().unwrap(),
        })
        .unwrap();
        assert!(
            scoped.len() <= MAX_SCOPED_PAYLOAD_BYTES,
            "{} bytes against a limit of {MAX_SCOPED_PAYLOAD_BYTES}",
            scoped.len()
        );
    }

    /// Pinned because docs/privacy.md relies on it: a request has nowhere to
    /// put a label, an order id or a user identity. Adding a field here is a
    /// privacy decision, not a refactor.
    #[test]
    fn a_request_carries_only_what_the_bridge_needs() {
        let bytes = freenet_bitcoin_common::to_cbor(&request()).unwrap();
        let value: ciborium::Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        let mut fields: Vec<String> = value
            .as_map()
            .expect("a request encodes as a map")
            .iter()
            .map(|(k, _)| k.as_text().expect("field names are text").to_string())
            .collect();
        fields.sort();
        assert_eq!(
            fields,
            [
                "action",
                "made_at_ms",
                "network",
                "scan_from_height",
                "scripts"
            ]
        );
    }
}
