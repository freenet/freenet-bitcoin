//! Emit real parameters and states for `fdev verify-merge`.
//!
//! These are genuine states built through the same constructors the contract
//! uses, with genuine SPV proofs — not hand-written bytes. A corpus of
//! fabricated states would exercise the verifier rather than the contract.

use std::fs;

use ed25519_dalek::SigningKey;
use freenet_bitcoin_common::address_state::BitcoinAddressStateV1;
use freenet_bitcoin_common::spv::testing as spv_testing;
use freenet_bitcoin_common::{
    to_cbor, BitcoinAddressParameters, BitcoinNetwork, BlockAnchor, Claim, ClaimBody, OutPoint,
    PowFloor, SignedClaim,
};

fn key() -> SigningKey {
    SigningKey::from_bytes(&[1; 32])
}

fn params() -> BitcoinAddressParameters {
    BitcoinAddressParameters {
        network: BitcoinNetwork::Signet,
        script_pubkey: vec![0x00, 0x14, 0xaa, 0xbb, 0xcc, 0xdd],
        trusted_bridges: vec![freenet_bitcoin_common::BridgeId(
            key().verifying_key().to_bytes(),
        )],
        pow_floor: PowFloor::NONE,
    }
}

fn confirmed(p: &BitcoinAddressParameters, seed: u8, sats: u64, as_of: u32) -> SignedClaim {
    let (spv, txid, block) = spv_testing::payment_proof(&p.script_pubkey, sats, 1, [seed; 32]);
    SignedClaim::sign(
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
    .unwrap()
}

fn retracted(p: &BitcoinAddressParameters, seed: u8, sats: u64, as_of: u32) -> SignedClaim {
    let (_, txid, block) = spv_testing::payment_proof(&p.script_pubkey, sats, 1, [seed; 32]);
    SignedClaim::sign(
        &key(),
        &ClaimBody {
            script_id: p.script_id(),
            network: p.network,
            as_of: BlockAnchor {
                height: as_of,
                hash: block,
            },
            claim: Claim::Retracted {
                outpoint: OutPoint { txid, vout: 0 },
            },
        },
    )
    .unwrap()
}

fn write(dir: &str, name: &str, bytes: &[u8]) {
    let path = format!("{dir}/{name}");
    fs::write(&path, bytes).unwrap();
    println!("{} ({} bytes)", path, bytes.len());
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp/vm".into());
    fs::create_dir_all(&dir).unwrap();
    let p = params();

    write(&dir, "params.bin", &to_cbor(&p).unwrap());

    // Empty: the state a contract starts from.
    let empty = BitcoinAddressStateV1::default();
    write(&dir, "s0.bin", &to_cbor(&empty).unwrap());

    // One payment.
    let a = BitcoinAddressStateV1::from_claims(&p, [confirmed(&p, 1, 50_000, 100)]).unwrap();
    write(&dir, "s1.bin", &to_cbor(&a).unwrap());

    // A different payment — the divergent-peer case.
    let b = BitcoinAddressStateV1::from_claims(&p, [confirmed(&p, 2, 70_000, 101)]).unwrap();
    write(&dir, "s2.bin", &to_cbor(&b).unwrap());

    // Both, plus a reorg retraction: the case the whole design exists for.
    let c = BitcoinAddressStateV1::from_claims(
        &p,
        [
            confirmed(&p, 1, 50_000, 100),
            confirmed(&p, 2, 70_000, 101),
            retracted(&p, 1, 50_000, 110),
        ],
    )
    .unwrap();
    write(&dir, "s3.bin", &to_cbor(&c).unwrap());

    // A genuine transition: base is what the peer HELD, result is what it
    // REACHED by merging b into a. Argument order is load-bearing for
    // transition_path_agreement, so it is produced here rather than guessed.
    let mut reached = a.clone();
    {
        use freenet_scaffold::ComposableState;
        let base = reached.clone();
        reached.merge(&base, &p, &b).unwrap();
    }
    write(&dir, "t_base.bin", &to_cbor(&a).unwrap());
    write(&dir, "t_result.bin", &to_cbor(&reached).unwrap());

    dump_tip(&dir);
}

/// Tip-contract corpus, emitted alongside the address one.
///
/// The tip contract is the harder case: it PRUNES to a retention window, so
/// its merge shrinks state. That is exactly where an order-dependent
/// implementation would show up.
fn dump_tip(dir: &str) {
    use freenet_bitcoin_common::tip_state::BitcoinTipStateV1;
    use freenet_bitcoin_common::{BitcoinTipParameters, BlockHash, SignedTipEntry, TipEntryBody};

    let p = BitcoinTipParameters {
        network: BitcoinNetwork::Signet,
        trusted_bridges: vec![freenet_bitcoin_common::BridgeId(
            key().verifying_key().to_bytes(),
        )],
    };
    let entry = |h: u32, variant: u8| {
        let mut hash = [variant; 32];
        hash[..4].copy_from_slice(&h.to_le_bytes());
        let mut prev = [variant; 32];
        prev[..4].copy_from_slice(&h.saturating_sub(1).to_le_bytes());
        SignedTipEntry::sign(
            &key(),
            &TipEntryBody {
                network: BitcoinNetwork::Signet,
                anchor: BlockAnchor {
                    height: h,
                    hash: BlockHash(hash),
                },
                prev_hash: BlockHash(prev),
                block_time: 1_700_000_000 + h * 600,
                tx_count: 100 + h,
                median_time: 1_700_000_000 + h * 600 - 300,
            },
        )
        .unwrap()
    };

    fs::write(format!("{dir}/tip_params.bin"), to_cbor(&p).unwrap()).unwrap();
    let a = BitcoinTipStateV1::from_entries(&p, (100..140).map(|h| entry(h, 1))).unwrap();
    let b = BitcoinTipStateV1::from_entries(&p, (130..175).map(|h| entry(h, 1))).unwrap();
    // A competing block at one height: the reorg case for the tip contract.
    let c = BitcoinTipStateV1::from_entries(
        &p,
        (100..140).map(|h| entry(h, if h == 120 { 9 } else { 1 })),
    )
    .unwrap();
    // Past the retention window, so pruning is exercised.
    let d = BitcoinTipStateV1::from_entries(&p, (100..300).map(|h| entry(h, 1))).unwrap();

    for (n, s) in [
        ("tip_s0", &a),
        ("tip_s1", &b),
        ("tip_s2", &c),
        ("tip_s3", &d),
    ] {
        let bytes = to_cbor(s).unwrap();
        fs::write(format!("{dir}/{n}.bin"), &bytes).unwrap();
        println!("{dir}/{n}.bin ({} bytes)", bytes.len());
    }
}
