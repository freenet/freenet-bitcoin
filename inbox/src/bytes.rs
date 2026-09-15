//! A byte vector that encodes as a CBOR byte string.
//!
//! `Vec<u8>` through serde becomes a CBOR *array* of integers, and ciborium
//! spends two bytes on every element >= 24, so an arbitrary payload roughly
//! doubles on the wire. Entries here carry a sealed request and a scoped
//! payload of up to several kilobytes each, and the inbox's worst-case state is
//! sized by exactly those fields, so the doubling would be paid on every
//! heartbeat. Same reasoning as `freenet_bitcoin_common::bytes32`.

use core::fmt;
use core::ops::Deref;

/// Bytes, encoded as one CBOR byte string.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ByteBuf(pub Vec<u8>);

impl Deref for ByteBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for ByteBuf {
    fn from(v: Vec<u8>) -> Self {
        ByteBuf(v)
    }
}

impl fmt::Debug for ByteBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ByteBuf({} bytes)", self.0.len())
    }
}

impl serde::Serialize for ByteBuf {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for ByteBuf {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a byte string")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
                Ok(v.to_vec())
            }
            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(v)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Vec<u8>, A::Error> {
                let mut out = Vec::new();
                while let Some(b) = seq.next_element::<u8>()? {
                    out.push(b);
                }
                Ok(out)
            }
        }
        d.deserialize_byte_buf(V).map(ByteBuf)
    }
}
