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
fn the_window_admits_its_top_edge_and_refuses_one_block_beyond() {
    let gk = &ghostkeys()[0];
    let mut s = open_at(100);
    let top = entry(gk, 100 + WINDOW_BLOCKS, 1);
    s.apply_delta(
        &params(),
        &InboxDelta {
            entries: vec![top],
            ..Default::default()
        },
    )
    .unwrap();
    let beyond = entry(gk, 100 + WINDOW_BLOCKS + 1, 2);
    assert!(s
        .apply_delta(
            &params(),
            &InboxDelta {
                entries: vec![beyond],
                ..Default::default()
            }
        )
        .is_err());
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
    let s = with_entries(100, &es);
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

#[test]
fn a_converged_peer_is_sent_nothing() {
    let s = with_entries(100, &[entry(&ghostkeys()[0], 104, 1)]);
    assert!(s.delta(&s.summarize()).is_none());
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
        }
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
        let s = seal(&bridge(), &request()).unwrap();
        assert_eq!(unseal(&bridge_sk(), &s).unwrap(), request());
        assert!(unseal(&SigningKey::from_bytes(&[1u8; 32]), &s).is_err());
    }

    #[test]
    fn a_tampered_sealed_request_does_not_open() {
        let mut s = seal(&bridge(), &request()).unwrap();
        s.ciphertext.0[0] ^= 1;
        assert!(unseal(&bridge_sk(), &s).is_err());
    }

    #[test]
    fn a_malformed_request_is_refused_before_sealing() {
        let mut r = request();
        r.scripts.clear();
        assert!(seal(&bridge(), &r).is_err());
        let mut r = request();
        r.scripts = vec![ByteBuf(vec![1u8; MAX_SCRIPT_BYTES + 1])];
        assert!(seal(&bridge(), &r).is_err());
    }
}
