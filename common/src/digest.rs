//! Constant-size bucketed summaries.
//!
//! Freenet summaries go out to every interested peer on every anti-entropy
//! heartbeat, whether or not anything changed — measured at roughly a quarter
//! of all outbound bytes on the network. A summary that enumerates its
//! collection therefore grows without bound as an application succeeds, and
//! costs that growth on every heartbeat forever.
//!
//! So the address contract does not enumerate its claims. It hashes each claim
//! into one of [`BUCKETS`] fixed buckets and publishes one 8-byte digest per
//! bucket: a fixed 128 bytes regardless of whether the script has one payment
//! or ten thousand.
//!
//! The trade is that `delta()` becomes *lossy in the safe direction*: when a
//! bucket digest differs, we resend every claim in that bucket, not just the
//! missing one. That is sound only because applying an already-held claim is a
//! no-op — the state is a set keyed by claim digest. Verify that property
//! before copying this pattern anywhere else.

/// Number of summary buckets. 16 buckets × 8 bytes = 128 bytes of digest,
/// which is the whole cost of the claim half of an address summary.
///
/// Raising this shrinks the resend amplification on a change but grows every
/// heartbeat; lowering it does the reverse. 16 was chosen because a watched
/// payment address realistically holds a handful of claims, so amplification
/// is near zero in practice while the constant cost stays small.
pub const BUCKETS: usize = 16;

/// A fixed-size digest over a set of items, bucketed so it stays constant-size
/// as the set grows.
///
/// Combination is XOR, which makes the digest **order-independent** — the same
/// property the underlying state needs. It also means a bucket containing the
/// same item twice digests as if it contained it zero times; that is fine here
/// because the state is a set and cannot contain duplicates, but it is a real
/// hazard if this is reused over a multiset.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BucketDigest(pub [u64; BUCKETS]);

// Encoded as one fixed-width CBOR byte string, never as an array of integers.
//
// A derived `[u64; 16]` encodes each element by VALUE: a zero bucket costs one
// byte, a saturated one costs nine. That makes the encoded summary grow as the
// set grows -- undoing the entire point of bucketing, and doing it invisibly,
// because a test built from small keys leaves most buckets at zero and reports
// a flatteringly small number. `bucketed_digest_is_fixed_width` pins this.
impl serde::Serialize for BucketDigest {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut out = [0u8; BUCKETS * 8];
        for (i, v) in self.0.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&v.to_le_bytes());
        }
        s.serialize_bytes(&out)
    }
}

impl<'de> serde::Deserialize<'de> for BucketDigest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = BucketDigest;
            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(f, "{} bytes", BUCKETS * 8)
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<BucketDigest, E> {
                if v.len() != BUCKETS * 8 {
                    return Err(E::invalid_length(v.len(), &"BUCKETS * 8 bytes"));
                }
                let mut out = [0u64; BUCKETS];
                for (i, slot) in out.iter_mut().enumerate() {
                    let mut e = [0u8; 8];
                    e.copy_from_slice(&v[i * 8..(i + 1) * 8]);
                    *slot = u64::from_le_bytes(e);
                }
                Ok(BucketDigest(out))
            }
        }
        d.deserialize_bytes(V)
    }
}

impl Default for BucketDigest {
    fn default() -> Self {
        BucketDigest([0; BUCKETS])
    }
}

impl BucketDigest {
    /// Which bucket an item's 32-byte key falls in.
    pub fn bucket_of(key: &[u8; 32]) -> usize {
        (key[0] as usize) % BUCKETS
    }

    /// Fold one item into the digest.
    ///
    /// The 8 bytes mixed in are taken from a domain-separated hash of the key
    /// rather than from the key itself, so that an adversary who can choose
    /// keys cannot trivially construct two different sets with equal digests
    /// by XOR cancellation. 64 bits of digest per bucket is sized against an
    /// adversary who controls only one side of the comparison: the claims in
    /// a bucket are all bridge-signed, so grinding both sides means forging a
    /// signature first.
    pub fn insert(&mut self, key: &[u8; 32]) {
        let mut h = blake3::Hasher::new();
        h.update(b"freenet-bitcoin/bucket/v1");
        h.update(key);
        let d = h.finalize();
        let mut eight = [0u8; 8];
        eight.copy_from_slice(&d.as_bytes()[..8]);
        let idx = Self::bucket_of(key);
        self.0[idx] ^= u64::from_le_bytes(eight);
    }

    /// Same as [`BucketDigest::from_keys`] for keys produced by value, e.g. a
    /// digest computed on the fly rather than stored.
    pub fn from_keys_owned<I: IntoIterator<Item = [u8; 32]>>(keys: I) -> Self {
        let mut d = Self::default();
        for k in keys {
            d.insert(&k);
        }
        d
    }

    pub fn from_keys<'a, I: IntoIterator<Item = &'a [u8; 32]>>(keys: I) -> Self {
        let mut d = Self::default();
        for k in keys {
            d.insert(k);
        }
        d
    }

    /// Buckets where this digest and `other` disagree — the buckets whose
    /// contents need resending.
    pub fn differing_buckets(&self, other: &Self) -> Vec<usize> {
        (0..BUCKETS).filter(|i| self.0[*i] != other.0[*i]).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = n;
        k[1] = n.wrapping_mul(7);
        k
    }

    #[test]
    fn digest_is_order_independent() {
        let ks = [key(1), key(2), key(3), key(200)];
        let a = BucketDigest::from_keys(ks.iter());
        let b = BucketDigest::from_keys(ks.iter().rev());
        assert_eq!(a, b);
    }

    #[test]
    fn equal_sets_have_no_differing_buckets() {
        let ks = [key(4), key(9), key(88)];
        let a = BucketDigest::from_keys(ks.iter());
        let b = BucketDigest::from_keys(ks.iter());
        assert!(a.differing_buckets(&b).is_empty());
    }

    #[test]
    fn an_added_item_shows_up_in_exactly_one_bucket() {
        let base = [key(4), key(9)];
        let a = BucketDigest::from_keys(base.iter());
        let extra = key(77);
        let mut b = a;
        b.insert(&extra);
        let diff = a.differing_buckets(&b);
        assert_eq!(diff, vec![BucketDigest::bucket_of(&extra)]);
    }

    #[test]
    fn bucketed_digest_is_fixed_width_regardless_of_bucket_values() {
        // The regression this pins: a derived encoding makes an all-zero
        // digest far cheaper than a saturated one, so a summary silently grows
        // with the collection. Both must encode to the same length.
        let empty = BucketDigest::default();
        let full = BucketDigest([u64::MAX; BUCKETS]);
        let a = crate::to_cbor(&empty).unwrap();
        let b = crate::to_cbor(&full).unwrap();
        assert_eq!(a.len(), b.len());
        assert_eq!(
            a.len(),
            BUCKETS * 8 + 2,
            "expected a fixed-width byte string"
        );
        assert_eq!(crate::from_cbor::<BucketDigest>(&b).unwrap(), full);
    }

    #[test]
    fn digest_size_is_constant_in_set_size() {
        // The whole point: 10_000 claims summarize to the same byte count as 1.
        let small = BucketDigest::from_keys([key(1)].iter());
        let manys: Vec<[u8; 32]> = (0..10_000u32)
            .map(|i| {
                let mut k = [0u8; 32];
                k[..4].copy_from_slice(&i.to_le_bytes());
                k
            })
            .collect();
        let big = BucketDigest::from_keys(manys.iter());
        let a = crate::to_cbor(&small).unwrap().len();
        let b = crate::to_cbor(&big).unwrap().len();
        assert_eq!(a, b, "bucketed digest must not grow with the set");
        // And it must actually be small.
        assert!(
            b < 300,
            "digest encoded to {b} bytes, expected well under 300"
        );
    }
}
