//! Serialisation of byte slices to `0x`-prefixed hexadecimal strings.
//!
//! Adapted from [`cowprotocol/services`] (MIT OR Apache-2.0).
//!
//! [`cowprotocol/services`]: https://github.com/cowprotocol/services/blob/main/crates/bytes-hex/src/lib.rs

use serde::{Deserialize, Deserializer, Serializer, de::Error};
use serde_with::{DeserializeAs, SerializeAs};
use std::borrow::Cow;

/// Serialise a byte slice as a `0x`-prefixed lowercase hex string.
pub fn serialize<S, T>(bytes: T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: AsRef<[u8]>,
{
    let mut v = vec![0u8; 2 + bytes.as_ref().len() * 2];
    v[0] = b'0';
    v[1] = b'x';
    // Only possible error is a wrong-sized destination slice, which cannot happen here.
    const_hex::encode_to_slice(bytes, &mut v[2..]).unwrap();
    // The encoded data is always valid UTF-8.
    serializer.serialize_str(&String::from_utf8(v).unwrap())
}

/// Deserialise a `0x`-prefixed hex string into a `Vec<u8>`. The prefix is required.
pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let prefixed_hex_str = Cow::<str>::deserialize(deserializer)?;
    let hex_str = prefixed_hex_str
        .strip_prefix("0x")
        .ok_or_else(|| D::Error::custom("missing '0x' prefix"))?;
    const_hex::decode(hex_str).map_err(D::Error::custom)
}

/// [`serde_with`] adapter for `0x`-prefixed hex byte strings.
#[derive(Debug)]
pub struct BytesHex(());

impl<T> SerializeAs<T> for BytesHex
where
    T: AsRef<[u8]>,
{
    fn serialize_as<S>(bytes: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize(bytes, serializer)
    }
}

impl<'de> DeserializeAs<'de, Vec<u8>> for BytesHex {
    fn deserialize_as<D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize(deserializer)
    }
}

#[cfg(test)]
mod tests {
    #[derive(Debug, serde::Deserialize, serde::Serialize, Eq, PartialEq)]
    struct S {
        #[serde(with = "super")]
        b: Vec<u8>,
    }

    #[test]
    fn json_round_trip() {
        let orig = S { b: vec![0, 1] };
        let serialized = serde_json::to_value(&orig).unwrap();
        let expected = serde_json::json!({ "b": "0x0001" });
        assert_eq!(serialized, expected);
        let deserialized: S = serde_json::from_value(expected).unwrap();
        assert_eq!(orig, deserialized);
    }

    #[test]
    fn missing_prefix_errors() {
        let input = serde_json::json!({ "b": "0001" });
        let result: Result<S, _> = serde_json::from_value(input);
        assert!(result.is_err());
    }
}
