//! Tests. The merge-law tests are the ones that matter most: they are what
//! would catch a cap or removal rule that stopped commuting.

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
        (0..(MAX_RECORDS + 4))
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
    let good = entry(gk, 104, 1);
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
fn a_tombstone_removes_its_entry_and_lasts_until_the_floor_passes_the_entry() {
    let w = entry(&ghostkeys()[0], 100, 1);
    let key = w.entry.key();
    let mut s = with_entries(95, std::slice::from_ref(&w));
    let t = SignedTombstone::for_entry(&bridge_sk(), key, &w.entry);
    s.apply_delta(
        &params(),
        &InboxDelta {
            tombstones: vec![t],
            ..Default::default()
        },
    )
    .unwrap();
    assert!(s.entries.is_empty());
    assert!(s.tombstones.contains_key(&key));

    // A peer that still holds the entry cannot bring it back.
    let holder = with_entries(95, std::slice::from_ref(&w));
    let mut merged = s.clone();
    merged.merge(&params(), &holder).unwrap();
    assert!(
        merged.entries.is_empty(),
        "a removed entry must not resurrect"
    );

    // Floor at the entry's height: tombstone kept.
    let at = InboxDelta {
        floor: Some(SignedFloor::sign(&bridge_sk(), 100)),
        ..Default::default()
    };
    s.apply_delta(&params(), &at).unwrap();
    assert!(s.tombstones.contains_key(&key));

    // Floor past it: tombstone gone, and the old entry can no longer return.
    let past = InboxDelta {
        floor: Some(SignedFloor::sign(&bridge_sk(), 101)),
        ..Default::default()
    };
    s.apply_delta(&params(), &past).unwrap();
    assert!(s.tombstones.is_empty());
    s.merge(&params(), &holder).unwrap();
    assert!(
        s.entries.is_empty(),
        "below the floor, the entry is gone for good"
    );
    s.verify(&params()).unwrap();
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
    let es: Vec<WireEntry> = (0..(MAX_RECORDS_PER_GHOSTKEY as u32 + 3))
        .map(|i| entry(gk, 100 + (i % WINDOW_BLOCKS), i as u8))
        .collect();
    let s = with_entries(100, &es);
    assert_eq!(s.entries.len(), MAX_RECORDS_PER_GHOSTKEY);
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
    assert!(es.len() > MAX_RECORDS);
    // More than one delta may carry, so in two.
    let mut s = with_entries(100, &es[..MAX_RECORDS]);
    s.apply_delta(
        &params(),
        &InboxDelta {
            entries: es[MAX_RECORDS..].to_vec(),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(s.entries.len(), MAX_RECORDS);
    s.verify(&params()).unwrap();
}

#[test]
fn a_tombstone_keeps_its_entrys_slot() {
    // Fill one Ghost Key's allowance, tombstone the newest, then offer one more:
    // it must not fit, or removal would be freeing slots.
    let gk = &ghostkeys()[0];
    let es: Vec<WireEntry> = (0..MAX_RECORDS_PER_GHOSTKEY as u32)
        .map(|i| entry(gk, 110, i as u8))
        .collect();
    let mut s = with_entries(100, &es);
    let w = &es[0];
    let t = SignedTombstone::for_entry(&bridge_sk(), w.entry.key(), &w.entry);
    s.apply_delta(
        &params(),
        &InboxDelta {
            tombstones: vec![t],
            ..Default::default()
        },
    )
    .unwrap();
    let older = entry(gk, 105, 200);
    s.apply_delta(
        &params(),
        &InboxDelta {
            entries: vec![older.clone()],
            ..Default::default()
        },
    )
    .unwrap();
    assert!(
        !s.entries.contains_key(&older.entry.key()),
        "a tombstone must hold its slot until the floor passes it"
    );
    s.verify(&params()).unwrap();
}

// --- merge laws, on exact bytes ------------------------------------------------------

/// A random valid state drawn from a shared pool of records, so different
/// states overlap, collide on caps, and tombstone each other's entries.
fn random_state(rng: &mut StdRng, pool: &[WireEntry]) -> InboxStateV1 {
    // Sometimes a peer that has never seen the inbox opened: the commonest
    // first contact, and a different path through the merge.
    if rng.gen_bool(0.15) {
        return InboxStateV1::default();
    }
    let floor = 100 + rng.gen_range(0..6);
    let mut s = open_at(floor);
    let chosen: Vec<WireEntry> = pool.iter().filter(|_| rng.gen_bool(0.5)).cloned().collect();
    s.apply_delta(
        &params(),
        &InboxDelta {
            entries: chosen.clone(),
            ..Default::default()
        },
    )
    .unwrap();
    let tombs: Vec<SignedTombstone> = pool
        .iter()
        .filter(|_| rng.gen_bool(0.2))
        .map(|w| SignedTombstone::for_entry(&bridge_sk(), w.entry.key(), &w.entry))
        .collect();
    s.apply_delta(
        &params(),
        &InboxDelta {
            tombstones: tombs,
            ..Default::default()
        },
    )
    .unwrap();
    s
}

fn merged(a: &InboxStateV1, b: &InboxStateV1) -> InboxStateV1 {
    let mut x = a.clone();
    x.merge(&params(), b).unwrap();
    x
}

#[test]
fn merge_is_commutative_associative_and_idempotent_on_exact_bytes() {
    // Few Ghost Keys, many records each, heights across several floors: every
    // cap and every removal path gets exercised.
    let gks = &ghostkeys()[..4];
    let mut pool = Vec::new();
    for (gi, gk) in gks.iter().enumerate() {
        for i in 0..(MAX_RECORDS_PER_GHOSTKEY + 6) {
            pool.push(entry(
                gk,
                100 + ((i * 3 + gi) as u32 % WINDOW_BLOCKS),
                (i + 10 * gi) as u8,
            ));
        }
    }
    let mut rng = StdRng::seed_from_u64(0x1b0c);
    for round in 0..40 {
        let a = random_state(&mut rng, &pool);
        let b = random_state(&mut rng, &pool);
        let c = random_state(&mut rng, &pool);
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

#[test]
fn state_bytes_do_not_depend_on_arrival_order() {
    let gk = &ghostkeys()[0];
    let es: Vec<WireEntry> = (0..6).map(|i| entry(gk, 100 + i, i as u8)).collect();
    let mut rev = es.clone();
    rev.reverse();
    assert_eq!(
        bytes(&with_entries(100, &es)),
        bytes(&with_entries(100, &rev))
    );
}

// --- synchronization ------------------------------------------------------------------

#[test]
fn two_peers_converge_through_summaries_and_deltas() {
    let gks = ghostkeys();
    let a = with_entries(100, &[entry(&gks[0], 104, 1), entry(&gks[1], 105, 2)]);
    let b = with_entries(102, &[entry(&gks[2], 106, 3), entry(&gks[0], 104, 1)]);
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
    assert!(d.entries.is_empty() && d.tombstones.is_empty());
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
    let t = SignedTombstone::for_entry(&bridge_sk(), w.entry.key(), &w.entry);
    let mut s = open_at(100);
    let before = bytes(&s);
    let many_tombstones = InboxDelta {
        tombstones: vec![t; MAX_RECORDS + 1],
        ..Default::default()
    };
    assert!(s.apply_delta(&params(), &many_tombstones).is_err());
    let many_entries = InboxDelta {
        entries: vec![w; MAX_RECORDS + 1],
        ..Default::default()
    };
    assert!(s.apply_delta(&params(), &many_entries).is_err());
    assert_eq!(bytes(&s), before);
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
    let a = entry(g, 104, 1);
    let mut b = entry(g, 105, 2);
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
fn a_floor_and_tombstones_arriving_together_apply_as_one_after_the_other() {
    let g = &ghostkeys()[0];
    let low = entry(g, 104, 1);
    let high = entry(g, 110, 2);
    let base = with_entries(100, &[low, high.clone()]);
    let floor = SignedFloor::sign(&bridge_sk(), 105);
    let t = SignedTombstone::for_entry(&bridge_sk(), high.entry.key(), &high.entry);

    let mut together = base.clone();
    together
        .apply_delta(
            &params(),
            &InboxDelta {
                floor: Some(floor.clone()),
                tombstones: vec![t.clone()],
                ..Default::default()
            },
        )
        .unwrap();

    let mut apart = base;
    apart
        .apply_delta(
            &params(),
            &InboxDelta {
                tombstones: vec![t],
                ..Default::default()
            },
        )
        .unwrap();
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
    assert_eq!(together.tombstones.len(), 1);
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
    let t = SignedTombstone::for_entry(&bridge_sk(), w.entry.key(), &w.entry);
    s.tombstones.insert(t.entry, t);
    assert!(s.verify(&params()).is_err(), "removed entry still present");

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
    let t = SignedTombstone::for_entry(&bridge_sk(), old.entry.key(), &old.entry);
    s.tombstones.insert(t.entry, t);
    assert!(s.verify(&params()).is_err(), "tombstone below the floor");
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
