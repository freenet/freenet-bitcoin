//! Verifying a Bitcoin payment from the transaction itself, without trusting
//! the bridge that reported it.
//!
//! # What the bridge signature alone would prove
//!
//! Only that a particular bridge asserted something. That makes every reader a
//! client of the bridge's honesty, which is a poor foundation for a
//! marketplace: a compromised bridge key could mint payments that never
//! happened.
//!
//! Most of the claim is checkable from first principles, so this module checks
//! it. Given the raw transaction, a Merkle branch and a run of block headers,
//! a verifier confirms:
//!
//! 1. **The txid is what it claims.** A txid *is* `SHA256d` of the transaction
//!    (witness data stripped), so it cannot be chosen independently of the
//!    transaction's contents.
//! 2. **The output really pays this script this much.** Read straight out of
//!    the parsed transaction.
//! 3. **The transaction is in the block.** Fold the txid up the Merkle branch
//!    and compare with the header's merkle root.
//! 4. **The block is real work.** Hash the 80-byte header and check it against
//!    the target encoded in its own `nBits`.
//! 5. **It is buried this deep.** Each following header must chain by
//!    `prev_hash` and meet its own target.
//!
//! # What is still trusted, stated plainly
//!
//! * **Which fork is the best chain.** Proof-of-work bounds this rather than
//!   eliminating it: on mainnet, fabricating even one valid header at current
//!   difficulty is wildly uneconomic, and six is out of reach. On **signet**
//!   the difficulty is trivial and blocks are authorized by the signet
//!   challenge key, so signet SPV is a structural demonstration, not a
//!   security guarantee. Do not read a green signet demo as proof of mainnet
//!   security.
//! * **`nBits` being the *correct* difficulty** for that height. Verifying
//!   that needs the retarget history, which a contract cannot afford to hold.
//!   Instead, parameters carry a `min_pow_bits` floor and a header claiming
//!   easier work than the floor is rejected — see [`PowFloor`]. That bounds
//!   the "low-difficulty fork" attack without a full header chain.
//! * **Completeness.** Nothing here stops a bridge *omitting* a payment or a
//!   reorg. Omission is a liveness failure, not a forgery, and it is why an
//!   application should be able to point at more than one bridge.
//!
//! So the bridge is trusted for availability and chain selection; it is *not*
//! trusted to be truthful about whether a given transaction exists, what it
//! paid, or how deeply it is buried.

use serde::{Deserialize, Serialize};

use crate::{BlockHash, Txid};

/// Largest raw transaction we will accept as evidence.
///
/// Bitcoin's consensus limit is 1 MB, but a payment proof rides inside Freenet
/// contract state, where a megabyte per claim would be ruinous. 64 KB covers
/// any plausible payment transaction with wide margin.
pub const MAX_RAW_TX: usize = 64 * 1024;

/// Longest Merkle branch accepted. A branch of depth *d* covers up to `2^d`
/// transactions, so 24 covers 16.7M — far beyond any real block.
pub const MAX_MERKLE_DEPTH: usize = 24;

/// Most following headers accepted, bounding proof size.
pub const MAX_FOLLOWING_HEADERS: usize = 24;

pub const HEADER_LEN: usize = 80;

/// An 80-byte Bitcoin block header.
///
/// A newtype rather than a bare `[u8; 80]` for two reasons: serde implements
/// `Deserialize` only for arrays up to length 32, and a derived encoding would
/// emit an array of 80 integers costing up to 160 bytes. This encodes as one
/// 82-byte CBOR byte string, and headers are the bulk of a deep proof.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BlockHeader(pub [u8; HEADER_LEN]);

impl Default for BlockHeader {
    fn default() -> Self {
        BlockHeader([0u8; HEADER_LEN])
    }
}

impl serde::Serialize for BlockHeader {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for BlockHeader {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = BlockHeader;
            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(f, "{HEADER_LEN} bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<BlockHeader, E> {
                <[u8; HEADER_LEN]>::try_from(v)
                    .map(BlockHeader)
                    .map_err(|_| E::invalid_length(v.len(), &"exactly 80 bytes"))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<BlockHeader, A::Error> {
                let mut out = [0u8; HEADER_LEN];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq.next_element::<u8>()?.ok_or_else(|| {
                        <A::Error as serde::de::Error>::invalid_length(i, &"exactly 80 bytes")
                    })?;
                }
                Ok(BlockHeader(out))
            }
        }
        d.deserialize_bytes(V)
    }
}

/// A minimum-work floor, as a compact `nBits` value.
///
/// A header whose target is *easier* than this is rejected. Without such a
/// floor an attacker could mine a chain of trivially-easy headers and satisfy
/// every other check, because nothing in a standalone header says what the
/// difficulty at that height was supposed to be.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub struct PowFloor(pub u32);

impl PowFloor {
    /// No floor: every header with valid self-consistent work is accepted.
    /// Correct for regtest and for signet, where difficulty is meaningless.
    pub const NONE: PowFloor = PowFloor(0x207fffff);
}

/// Self-contained evidence that a transaction paying a script is buried in the
/// chain, checkable without trusting whoever supplied it.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct SpvProof {
    /// The transaction, serialized **without** witness data.
    ///
    /// Witness-stripped because that is the serialization a txid commits to;
    /// including witnesses would let the same logical transaction present
    /// several byte encodings, only one of which hashes to the txid.
    pub raw_tx: Vec<u8>,
    /// Sibling hashes from the transaction up to the Merkle root.
    pub merkle_branch: Vec<[u8; 32]>,
    /// Index of the transaction within its block. Its bits choose, at each
    /// level, whether our running hash is the left or the right operand.
    pub tx_index: u32,
    /// The 80-byte header of the block containing the transaction.
    pub header: BlockHeader,
    /// Headers built on top of it, oldest first.
    pub following_headers: Vec<BlockHeader>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SpvError {
    TxTooLarge(usize),
    MalformedTx(&'static str),
    /// The transaction does not hash to the txid the claim names.
    TxidMismatch {
        computed: Txid,
        claimed: Txid,
    },
    NoSuchOutput(u32),
    /// The output exists but pays a different script.
    ScriptMismatch,
    /// The output exists but for a different amount.
    ValueMismatch {
        in_tx: u64,
        claimed: u64,
    },
    MerkleTooDeep(usize),
    /// The Merkle fold did not reach the header's root.
    MerkleMismatch,
    /// The header does not hash to the block hash the claim names.
    BlockHashMismatch,
    /// A header's hash does not satisfy its own target.
    InsufficientWork,
    /// A header claims easier work than the configured floor.
    BelowPowFloor,
    /// A following header does not build on its predecessor.
    BrokenChain(usize),
    TooManyHeaders(usize),
    /// The proof carries fewer headers than the required depth.
    InsufficientDepth {
        have: u32,
        need: u32,
    },
}

impl core::fmt::Display for SpvError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SpvError::TxTooLarge(n) => {
                write!(f, "raw transaction is {n} bytes, cap is {MAX_RAW_TX}")
            }
            SpvError::MalformedTx(w) => write!(f, "malformed transaction: {w}"),
            SpvError::TxidMismatch { computed, claimed } => write!(
                f,
                "transaction hashes to {} but the claim names {}",
                computed.to_display_string(),
                claimed.to_display_string()
            ),
            SpvError::NoSuchOutput(v) => write!(f, "transaction has no output {v}"),
            SpvError::ScriptMismatch => write!(f, "that output pays a different script"),
            SpvError::ValueMismatch { in_tx, claimed } => {
                write!(f, "output pays {in_tx} sats, claim says {claimed}")
            }
            SpvError::MerkleTooDeep(d) => {
                write!(f, "merkle branch depth {d} exceeds {MAX_MERKLE_DEPTH}")
            }
            SpvError::MerkleMismatch => write!(f, "merkle branch does not reach the block's root"),
            SpvError::BlockHashMismatch => write!(f, "header does not hash to the claimed block"),
            SpvError::InsufficientWork => write!(f, "block header does not meet its own target"),
            SpvError::BelowPowFloor => write!(f, "block header claims less work than permitted"),
            SpvError::BrokenChain(i) => {
                write!(f, "following header {i} does not build on its predecessor")
            }
            SpvError::TooManyHeaders(n) => {
                write!(f, "{n} following headers, cap is {MAX_FOLLOWING_HEADERS}")
            }
            SpvError::InsufficientDepth { have, need } => {
                write!(f, "proof establishes {have} confirmations, {need} required")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

fn sha256d(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

/// Decode a Bitcoin compact-size integer, returning the value and its width.
fn read_varint(b: &[u8], at: usize) -> Result<(u64, usize), SpvError> {
    let first = *b.get(at).ok_or(SpvError::MalformedTx("truncated varint"))?;
    let need = |n: usize| -> Result<(), SpvError> {
        if b.len() < at + 1 + n {
            Err(SpvError::MalformedTx("truncated varint body"))
        } else {
            Ok(())
        }
    };
    match first {
        0..=0xfc => Ok((first as u64, 1)),
        0xfd => {
            need(2)?;
            Ok((u16::from_le_bytes([b[at + 1], b[at + 2]]) as u64, 3))
        }
        0xfe => {
            need(4)?;
            let mut v = [0u8; 4];
            v.copy_from_slice(&b[at + 1..at + 5]);
            Ok((u32::from_le_bytes(v) as u64, 5))
        }
        _ => {
            need(8)?;
            let mut v = [0u8; 8];
            v.copy_from_slice(&b[at + 1..at + 9]);
            Ok((u64::from_le_bytes(v), 9))
        }
    }
}

/// One output of a Bitcoin transaction.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TxOutput {
    pub value_sats: u64,
    pub script_pubkey: Vec<u8>,
}

/// Parse the outputs of a witness-stripped transaction.
///
/// Deliberately minimal: it walks the legacy serialization far enough to read
/// the outputs and does not attempt to be a general Bitcoin library. It
/// **rejects** the segwit marker, because a transaction carrying witness data
/// does not hash to its own txid and accepting one would break check (1).
pub fn parse_tx_outputs(raw: &[u8]) -> Result<Vec<TxOutput>, SpvError> {
    if raw.len() > MAX_RAW_TX {
        return Err(SpvError::TxTooLarge(raw.len()));
    }
    if raw.len() < 10 {
        return Err(SpvError::MalformedTx("too short to be a transaction"));
    }
    let mut at = 4; // version

    // A segwit transaction serializes marker 0x00, flag 0x01 here. Its txid is
    // computed over the stripped form, so evidence must be stripped already.
    if raw[at] == 0x00 {
        return Err(SpvError::MalformedTx(
            "witness data present; evidence must use the witness-stripped serialization",
        ));
    }

    let (n_in, w) = read_varint(raw, at)?;
    at += w;
    for _ in 0..n_in {
        at = at
            .checked_add(36)
            .ok_or(SpvError::MalformedTx("input overflow"))?; // prevout
        let (script_len, w) = read_varint(raw, at)?;
        at += w;
        at = at
            .checked_add(script_len as usize)
            .and_then(|x| x.checked_add(4)) // sequence
            .ok_or(SpvError::MalformedTx("input script overflow"))?;
        if at > raw.len() {
            return Err(SpvError::MalformedTx("truncated inputs"));
        }
    }

    let (n_out, w) = read_varint(raw, at)?;
    at += w;
    if n_out as usize > raw.len() {
        return Err(SpvError::MalformedTx("implausible output count"));
    }
    let mut outputs = Vec::with_capacity(n_out as usize);
    for _ in 0..n_out {
        if at + 8 > raw.len() {
            return Err(SpvError::MalformedTx("truncated output value"));
        }
        let mut v = [0u8; 8];
        v.copy_from_slice(&raw[at..at + 8]);
        at += 8;
        let (script_len, w) = read_varint(raw, at)?;
        at += w;
        let end = at
            .checked_add(script_len as usize)
            .ok_or(SpvError::MalformedTx("output script overflow"))?;
        if end > raw.len() {
            return Err(SpvError::MalformedTx("truncated output script"));
        }
        outputs.push(TxOutput {
            value_sats: u64::from_le_bytes(v),
            script_pubkey: raw[at..end].to_vec(),
        });
        at = end;
    }
    Ok(outputs)
}

/// Expand a compact `nBits` into a 256-bit target, big-endian.
fn target_from_bits(bits: u32) -> [u8; 32] {
    let exponent = (bits >> 24) as usize;
    let mantissa = bits & 0x007f_ffff; // sign bit is never set in valid headers
    let mut target = [0u8; 32];
    if exponent <= 3 {
        let shifted = mantissa >> (8 * (3 - exponent));
        target[29..32].copy_from_slice(&shifted.to_be_bytes()[1..4]);
    } else if exponent <= 32 {
        // Mantissa occupies bytes [32-exponent, 32-exponent+3).
        let start = 32 - exponent;
        let m = mantissa.to_be_bytes(); // [0, hi, mid, lo]
        for (i, byte) in m[1..4].iter().enumerate() {
            if start + i < 32 {
                target[start + i] = *byte;
            }
        }
    }
    target
}

/// Does `hash` (internal little-endian order) satisfy `target` (big-endian)?
fn meets_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    // A block hash is compared as a big-endian number, and internal order is
    // reversed, so walk the hash backwards against the target forwards.
    for i in 0..32 {
        let h = hash[31 - i];
        let t = target[i];
        if h < t {
            return true;
        }
        if h > t {
            return false;
        }
    }
    true // exactly equal is acceptable
}

/// The pieces of a block header a verifier needs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HeaderView {
    pub hash: BlockHash,
    pub prev_hash: BlockHash,
    pub merkle_root: [u8; 32],
    pub time: u32,
    pub bits: u32,
}

/// Read a header and check it satisfies its own target and the floor.
pub fn verify_header(header: &BlockHeader, floor: PowFloor) -> Result<HeaderView, SpvError> {
    let header = &header.0;
    let hash = sha256d(header);

    let mut prev = [0u8; 32];
    prev.copy_from_slice(&header[4..36]);
    let mut root = [0u8; 32];
    root.copy_from_slice(&header[36..68]);
    let time = u32::from_le_bytes([header[68], header[69], header[70], header[71]]);
    let bits = u32::from_le_bytes([header[72], header[73], header[74], header[75]]);

    // The floor first: a header claiming absurdly easy work is rejected even
    // though it satisfies its own (easy) target.
    let floor_target = target_from_bits(floor.0);
    let this_target = target_from_bits(bits);
    // An easier target is a numerically LARGER value.
    if this_target > floor_target {
        return Err(SpvError::BelowPowFloor);
    }
    if !meets_target(&hash, &this_target) {
        return Err(SpvError::InsufficientWork);
    }

    Ok(HeaderView {
        hash: BlockHash(hash),
        prev_hash: BlockHash(prev),
        merkle_root: root,
        time,
        bits,
    })
}

/// Fold a txid up a Merkle branch to a root.
pub fn merkle_root_from_branch(
    txid: &Txid,
    branch: &[[u8; 32]],
    mut index: u32,
) -> Result<[u8; 32], SpvError> {
    if branch.len() > MAX_MERKLE_DEPTH {
        return Err(SpvError::MerkleTooDeep(branch.len()));
    }
    let mut acc = txid.0;
    for sibling in branch {
        let mut buf = [0u8; 64];
        if index & 1 == 0 {
            buf[..32].copy_from_slice(&acc);
            buf[32..].copy_from_slice(sibling);
        } else {
            buf[..32].copy_from_slice(sibling);
            buf[32..].copy_from_slice(&acc);
        }
        acc = sha256d(&buf);
        index >>= 1;
    }
    Ok(acc)
}

/// What a verified SPV proof establishes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SpvVerified {
    pub txid: Txid,
    pub block_hash: BlockHash,
    pub value_sats: u64,
    /// Confirmations proven by the headers supplied: 1 + following headers.
    pub depth: u32,
}

/// Verify an SPV proof end to end.
///
/// Every check is on the caller's own bytes; nothing here consults the
/// network, a clock, or a bridge. `expected_*` come from the claim being
/// checked, so a proof for some other transaction, output, script or amount is
/// rejected rather than silently accepted.
#[allow(clippy::too_many_arguments)]
pub fn verify_spv_proof(
    proof: &SpvProof,
    expected_txid: &Txid,
    expected_vout: u32,
    expected_script: &[u8],
    expected_value: u64,
    expected_block: &BlockHash,
    floor: PowFloor,
) -> Result<SpvVerified, SpvError> {
    if proof.raw_tx.len() > MAX_RAW_TX {
        return Err(SpvError::TxTooLarge(proof.raw_tx.len()));
    }
    if proof.following_headers.len() > MAX_FOLLOWING_HEADERS {
        return Err(SpvError::TooManyHeaders(proof.following_headers.len()));
    }

    // 1. The txid is not a free parameter: it is the hash of these bytes.
    let computed = Txid(sha256d(&proof.raw_tx));
    if computed != *expected_txid {
        return Err(SpvError::TxidMismatch {
            computed,
            claimed: *expected_txid,
        });
    }

    // 2. The output really pays this script this much.
    let outputs = parse_tx_outputs(&proof.raw_tx)?;
    let out = outputs
        .get(expected_vout as usize)
        .ok_or(SpvError::NoSuchOutput(expected_vout))?;
    if out.script_pubkey != expected_script {
        return Err(SpvError::ScriptMismatch);
    }
    if out.value_sats != expected_value {
        return Err(SpvError::ValueMismatch {
            in_tx: out.value_sats,
            claimed: expected_value,
        });
    }

    // 3/4. The block is real work and contains the transaction.
    let head = verify_header(&proof.header, floor)?;
    if head.hash != *expected_block {
        return Err(SpvError::BlockHashMismatch);
    }
    let root = merkle_root_from_branch(&computed, &proof.merkle_branch, proof.tx_index)?;
    if root != head.merkle_root {
        return Err(SpvError::MerkleMismatch);
    }

    // 5. Each following header must build on the last and carry its own work.
    let mut prev = head;
    for (i, h) in proof.following_headers.iter().enumerate() {
        let view = verify_header(h, floor)?;
        if view.prev_hash != prev.hash {
            return Err(SpvError::BrokenChain(i));
        }
        prev = view;
    }

    Ok(SpvVerified {
        txid: computed,
        block_hash: head.hash,
        value_sats: out.value_sats,
        depth: 1 + proof.following_headers.len() as u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal legacy transaction with the given outputs.
    fn make_tx(outputs: &[(u64, Vec<u8>)]) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(&2u32.to_le_bytes()); // version
        t.push(1); // one input
        t.extend_from_slice(&[0u8; 32]); // prevout txid
        t.extend_from_slice(&0u32.to_le_bytes()); // prevout vout
        t.push(0); // empty scriptSig
        t.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence
        t.push(outputs.len() as u8);
        for (v, spk) in outputs {
            t.extend_from_slice(&v.to_le_bytes());
            t.push(spk.len() as u8);
            t.extend_from_slice(spk);
        }
        t.extend_from_slice(&0u32.to_le_bytes()); // locktime
        t
    }

    /// Mine a header at the easiest possible target so tests are instant.
    fn mine_header(prev: [u8; 32], merkle_root: [u8; 32], bits: u32) -> BlockHeader {
        let target = target_from_bits(bits);
        let mut h = [0u8; 80];
        h[..4].copy_from_slice(&1u32.to_le_bytes());
        h[4..36].copy_from_slice(&prev);
        h[36..68].copy_from_slice(&merkle_root);
        h[68..72].copy_from_slice(&1_700_000_000u32.to_le_bytes());
        h[72..76].copy_from_slice(&bits.to_le_bytes());
        for nonce in 0u32..u32::MAX {
            h[76..80].copy_from_slice(&nonce.to_le_bytes());
            if meets_target(&sha256d(&h), &target) {
                return BlockHeader(h);
            }
        }
        panic!("could not find a nonce at the easiest target");
    }

    const EASY: u32 = 0x207f_ffff;

    struct Fixture {
        proof: SpvProof,
        txid: Txid,
        block: BlockHash,
        script: Vec<u8>,
        value: u64,
    }

    fn fixture(following: usize) -> Fixture {
        let script = vec![0x00, 0x14, 0xab, 0xcd, 0xef, 0x01];
        let value = 50_000u64;
        let raw = make_tx(&[(value, script.clone())]);
        let txid = Txid(sha256d(&raw));

        // Single-transaction block: the merkle root is the txid itself.
        let header = mine_header([0u8; 32], txid.0, EASY);
        let block = BlockHash(sha256d(&header.0));

        let mut following_headers = Vec::new();
        let mut prev = header;
        for _ in 0..following {
            let h = mine_header(sha256d(&prev.0), [7u8; 32], EASY);
            following_headers.push(h);
            prev = h;
        }

        Fixture {
            proof: SpvProof {
                raw_tx: raw,
                merkle_branch: vec![],
                tx_index: 0,
                header,
                following_headers,
            },
            txid,
            block,
            script,
            value,
        }
    }

    fn verify(f: &Fixture) -> Result<SpvVerified, SpvError> {
        verify_spv_proof(
            &f.proof,
            &f.txid,
            0,
            &f.script,
            f.value,
            &f.block,
            PowFloor::NONE,
        )
    }

    #[test]
    fn a_good_proof_verifies_and_reports_depth() {
        let f = fixture(5);
        let v = verify(&f).unwrap();
        assert_eq!(v.value_sats, 50_000);
        assert_eq!(v.depth, 6, "1 containing block + 5 following headers");
    }

    #[test]
    fn a_forged_amount_is_caught_because_the_txid_commits_to_it() {
        // This is the property that matters most: the bridge cannot inflate a
        // payment, because changing the amount changes the txid.
        let mut f = fixture(1);
        let bigger = make_tx(&[(50_000_000, f.script.clone())]);
        f.proof.raw_tx = bigger;
        assert!(matches!(verify(&f), Err(SpvError::TxidMismatch { .. })));
    }

    #[test]
    fn a_transaction_paying_a_different_script_is_rejected() {
        let script = vec![0x00, 0x14, 0x11, 0x22, 0x33, 0x44];
        let raw = make_tx(&[(50_000, script)]);
        let txid = Txid(sha256d(&raw));
        let header = mine_header([0u8; 32], txid.0, EASY);
        let f = Fixture {
            proof: SpvProof {
                raw_tx: raw,
                merkle_branch: vec![],
                tx_index: 0,
                header,
                following_headers: vec![],
            },
            txid,
            block: BlockHash(sha256d(&header.0)),
            script: vec![0x00, 0x14, 0xab, 0xcd, 0xef, 0x01], // what we expected
            value: 50_000,
        };
        assert_eq!(verify(&f), Err(SpvError::ScriptMismatch));
    }

    #[test]
    fn a_header_that_does_not_meet_its_target_is_rejected() {
        // Claim genesis-era difficulty in the header without having done the
        // work. This cannot be tested at the EASY target: there, almost any
        // nonce satisfies the target, so tampering with the nonce proves
        // nothing and the test passes vacuously.
        let mut f = fixture(0);
        f.proof.header.0[72..76].copy_from_slice(&0x1d00_ffffu32.to_le_bytes());
        let tampered = BlockHash(sha256d(&f.proof.header.0));
        let r = verify_spv_proof(
            &f.proof,
            &f.txid,
            0,
            &f.script,
            f.value,
            &tampered,
            PowFloor::NONE,
        );
        assert_eq!(r, Err(SpvError::InsufficientWork));
    }

    #[test]
    fn a_following_header_that_does_not_chain_is_rejected() {
        let mut f = fixture(2);
        // Replace the second following header with one built on nothing.
        f.proof.following_headers[1] = mine_header([0x99u8; 32], [1u8; 32], EASY);
        assert_eq!(verify(&f), Err(SpvError::BrokenChain(1)));
    }

    #[test]
    fn a_header_below_the_work_floor_is_rejected() {
        let f = fixture(0);
        // Demand mainnet-ish work from a header mined at the easiest target.
        let r = verify_spv_proof(
            &f.proof,
            &f.txid,
            0,
            &f.script,
            f.value,
            &f.block,
            PowFloor(0x1703_98e4),
        );
        assert_eq!(r, Err(SpvError::BelowPowFloor));
    }

    #[test]
    fn merkle_branch_folds_correctly_for_a_non_zero_index() {
        // Two-transaction block: root = H(other || ours) when ours is index 1.
        let script = vec![0x51];
        let raw = make_tx(&[(1234, script.clone())]);
        let txid = Txid(sha256d(&raw));
        let sibling = [0x42u8; 32];
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&sibling);
        buf[32..].copy_from_slice(&txid.0);
        let root = sha256d(&buf);

        let header = mine_header([0u8; 32], root, EASY);
        let proof = SpvProof {
            raw_tx: raw,
            merkle_branch: vec![sibling],
            tx_index: 1,
            header,
            following_headers: vec![],
        };
        let v = verify_spv_proof(
            &proof,
            &txid,
            0,
            &script,
            1234,
            &BlockHash(sha256d(&header.0)),
            PowFloor::NONE,
        )
        .unwrap();
        assert_eq!(v.depth, 1);
    }

    #[test]
    fn a_wrong_merkle_position_is_rejected() {
        // Same data, wrong index: the fold hashes the pair the other way
        // round and must not reach the root.
        let script = vec![0x51];
        let raw = make_tx(&[(1234, script.clone())]);
        let txid = Txid(sha256d(&raw));
        let sibling = [0x42u8; 32];
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&sibling);
        buf[32..].copy_from_slice(&txid.0);
        let root = sha256d(&buf);
        let header = mine_header([0u8; 32], root, EASY);
        let proof = SpvProof {
            raw_tx: raw,
            merkle_branch: vec![sibling],
            tx_index: 0, // wrong: we are on the right, not the left
            header,
            following_headers: vec![],
        };
        assert_eq!(
            verify_spv_proof(
                &proof,
                &txid,
                0,
                &script,
                1234,
                &BlockHash(sha256d(&header.0)),
                PowFloor::NONE
            ),
            Err(SpvError::MerkleMismatch)
        );
    }

    #[test]
    fn segwit_serialization_is_refused_rather_than_misparsed() {
        // A witness-serialized transaction does not hash to its own txid, so
        // silently parsing one would break the entire chain of reasoning.
        let mut raw = make_tx(&[(1, vec![0x51])]);
        raw.insert(4, 0x01); // flag
        raw.insert(4, 0x00); // marker
        assert!(matches!(
            parse_tx_outputs(&raw),
            Err(SpvError::MalformedTx(_))
        ));
    }

    #[test]
    fn truncated_transactions_are_rejected_not_panicked_on() {
        // These bytes arrive from untrusted peers, so the parser must fail
        // cleanly on every prefix rather than index out of bounds.
        let full = make_tx(&[(50_000, vec![0x00, 0x14, 0xaa])]);
        for n in 0..full.len() {
            let _ = parse_tx_outputs(&full[..n]); // must not panic
        }
    }

    #[test]
    fn target_expansion_matches_known_values() {
        // Bitcoin's genesis difficulty: 0x1d00ffff -> 0x00000000FFFF0000...
        let t = target_from_bits(0x1d00_ffff);
        assert_eq!(t[0..4], [0x00, 0x00, 0x00, 0x00]);
        assert_eq!(t[4..6], [0xff, 0xff]);
        assert!(t[6..].iter().all(|b| *b == 0));
    }

    #[test]
    fn varint_forms_all_decode() {
        assert_eq!(read_varint(&[0x10], 0).unwrap(), (0x10, 1));
        assert_eq!(read_varint(&[0xfd, 0x34, 0x12], 0).unwrap(), (0x1234, 3));
        assert_eq!(
            read_varint(&[0xfe, 0x78, 0x56, 0x34, 0x12], 0).unwrap(),
            (0x1234_5678, 5)
        );
        assert!(
            read_varint(&[0xfd, 0x00], 0).is_err(),
            "truncated must error"
        );
    }
}

/// Builders for constructing genuine SPV proofs in tests and demos.
///
/// These mine real (trivially easy) headers and compute real Merkle branches,
/// so a test using them exercises the actual verification path rather than a
/// stub. That matters: a fixture that fabricated a "valid" proof by bypassing
/// the checks would let a regression in the verifier pass unnoticed.
#[cfg(any(test, feature = "test-support"))]
pub mod testing {
    use super::*;

    /// The easiest permitted target — regtest's. Lets a test mine a header in
    /// microseconds. Never use for anything but tests.
    pub const EASIEST_BITS: u32 = 0x207f_ffff;

    pub fn sha256d_pub(data: &[u8]) -> [u8; 32] {
        super::sha256d(data)
    }

    /// Serialize a minimal legacy (non-witness) transaction with these outputs.
    pub fn build_tx(outputs: &[(u64, Vec<u8>)]) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(&2u32.to_le_bytes());
        t.push(1);
        t.extend_from_slice(&[0u8; 32]);
        t.extend_from_slice(&0u32.to_le_bytes());
        t.push(0);
        t.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        t.push(outputs.len() as u8);
        for (v, spk) in outputs {
            t.extend_from_slice(&v.to_le_bytes());
            t.push(spk.len() as u8);
            t.extend_from_slice(spk);
        }
        t.extend_from_slice(&0u32.to_le_bytes());
        t
    }

    /// Mine a header meeting `bits`.
    pub fn mine(prev: [u8; 32], merkle_root: [u8; 32], time: u32, bits: u32) -> BlockHeader {
        let target = super::target_from_bits(bits);
        let mut h = [0u8; HEADER_LEN];
        h[..4].copy_from_slice(&1u32.to_le_bytes());
        h[4..36].copy_from_slice(&prev);
        h[36..68].copy_from_slice(&merkle_root);
        h[68..72].copy_from_slice(&time.to_le_bytes());
        h[72..76].copy_from_slice(&bits.to_le_bytes());
        for nonce in 0u32..u32::MAX {
            h[76..80].copy_from_slice(&nonce.to_le_bytes());
            if super::meets_target(&super::sha256d(&h), &target) {
                return BlockHeader(h);
            }
        }
        panic!("no nonce found");
    }

    /// A single-transaction block paying `value` to `script`, buried under
    /// `depth - 1` further blocks. Returns the proof and the containing
    /// block's hash and txid.
    pub fn payment_proof(
        script: &[u8],
        value: u64,
        depth: u32,
        prev: [u8; 32],
    ) -> (SpvProof, Txid, BlockHash) {
        let raw = build_tx(&[(value, script.to_vec())]);
        let txid = Txid(super::sha256d(&raw));
        let header = mine(prev, txid.0, 1_700_000_000, EASIEST_BITS);
        let block = BlockHash(super::sha256d(&header.0));

        let mut following = Vec::new();
        let mut last = header;
        for i in 1..depth {
            let h = mine(
                super::sha256d(&last.0),
                [i as u8; 32],
                1_700_000_000 + i * 600,
                EASIEST_BITS,
            );
            following.push(h);
            last = h;
        }

        (
            SpvProof {
                raw_tx: raw,
                merkle_branch: vec![],
                tx_index: 0,
                header,
                following_headers: following,
            },
            txid,
            block,
        )
    }
}
