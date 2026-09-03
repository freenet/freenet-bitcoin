//! Hand-written CBOR encoding for the 32-byte newtypes.
//!
//! # Why this is not a `derive`
//!
//! `#[derive(Serialize)]` on a newtype wrapping `[u8; 32]` emits a CBOR
//! *array* of 32 integers. ciborium encodes every element >= 24 as two bytes,
//! so a 32-byte value costs up to 65 bytes on the wire -- roughly double.
//!
//! These types are the most frequently repeated values in the whole system:
//! every claim carries a `ScriptId`, a `BridgeId`, a `Txid` and two
//! `BlockHash`es, and claims are what both state and deltas are made of. Using
//! `serialize_bytes` makes each one a 34-byte CBOR byte string with no
//! per-element overhead, and makes the encoded size *independent of the byte
//! values*, which is what stops a test built from small integers reporting a
//! misleadingly cheap number.
//!
//! The encoding is a wire-format commitment. Changing it invalidates every
//! signature ever produced, because signatures are over CBOR of structures
//! containing these types.

/// Implement `Serialize`/`Deserialize` for a newtype over `[u8; 32]` as a CBOR
/// byte string, accepting either a byte string or a sequence on the way in.
#[macro_export]
macro_rules! impl_bytes32_serde {
    ($t:ty) => {
        impl serde::Serialize for $t {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_bytes(&self.0)
            }
        }

        impl<'de> serde::Deserialize<'de> for $t {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                struct V;
                impl<'de> serde::de::Visitor<'de> for V {
                    type Value = [u8; 32];
                    fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                        f.write_str("32 bytes")
                    }
                    fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<[u8; 32], E> {
                        <[u8; 32]>::try_from(v)
                            .map_err(|_| E::invalid_length(v.len(), &"exactly 32 bytes"))
                    }
                    fn visit_seq<A: serde::de::SeqAccess<'de>>(
                        self,
                        mut seq: A,
                    ) -> Result<[u8; 32], A::Error> {
                        // Tolerated so anything encoded by an older
                        // derive-based build still decodes. Nothing emits it.
                        let mut out = [0u8; 32];
                        for (i, slot) in out.iter_mut().enumerate() {
                            *slot = seq.next_element::<u8>()?.ok_or_else(|| {
                                <A::Error as serde::de::Error>::invalid_length(
                                    i,
                                    &"exactly 32 bytes",
                                )
                            })?;
                        }
                        if seq.next_element::<u8>()?.is_some() {
                            return Err(<A::Error as serde::de::Error>::invalid_length(
                                33,
                                &"exactly 32 bytes",
                            ));
                        }
                        Ok(out)
                    }
                }
                d.deserialize_bytes(V).map(Self)
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use crate::{from_cbor, to_cbor, BlockHash, BridgeId, ScriptId, Txid};

    /// The golden vector: fixed inputs, fixed expected byte length. A
    /// randomised size check would miss a regression to the derive encoding on
    /// some byte values but not others.
    #[test]
    fn bytes32_encodes_to_34_cbor_bytes_regardless_of_content() {
        // 0x00 encodes as one byte under a derive; 0xff as two. If the
        // encoding were derived, these two would differ in length.
        assert_eq!(to_cbor(&Txid([0x00; 32])).unwrap().len(), 34);
        assert_eq!(to_cbor(&Txid([0xff; 32])).unwrap().len(), 34);
    }

    #[test]
    fn all_four_newtypes_use_the_byte_string_encoding() {
        assert_eq!(to_cbor(&Txid([0xab; 32])).unwrap().len(), 34);
        assert_eq!(to_cbor(&BlockHash([0xab; 32])).unwrap().len(), 34);
        assert_eq!(to_cbor(&ScriptId([0xab; 32])).unwrap().len(), 34);
        assert_eq!(to_cbor(&BridgeId([0xab; 32])).unwrap().len(), 34);
    }

    #[test]
    fn roundtrips_as_a_cbor_byte_string() {
        let t = Txid([7; 32]);
        let bytes = to_cbor(&t).unwrap();
        assert_eq!(bytes[0], 0x58, "expected a CBOR byte-string header");
        assert_eq!(from_cbor::<Txid>(&bytes).unwrap(), t);
    }

    #[test]
    fn a_legacy_sequence_encoding_still_decodes() {
        let mut buf = Vec::new();
        ciborium::into_writer(&vec![9u8; 32], &mut buf).unwrap();
        assert_eq!(from_cbor::<Txid>(&buf).unwrap(), Txid([9; 32]));
    }

    #[test]
    fn wrong_length_is_rejected() {
        let mut buf = Vec::new();
        ciborium::into_writer(&vec![1u8; 31], &mut buf).unwrap();
        assert!(from_cbor::<Txid>(&buf).is_err());
    }
}
