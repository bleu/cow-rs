//! The `appData` field of a CoW Protocol order: a 32-byte digest of the
//! application metadata document, encoded as `0x`-prefixed hex when sent
//! over the wire.

use {
    serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _},
    std::fmt,
};

/// 32-byte digest of an [app-data] document.
///
/// The digest is the keccak256 of the deterministically-stringified JSON
/// document and is embedded directly in the signed order payload. It is
/// **not** an IPFS CID — derive the multihash off the same digest when one
/// is needed.
///
/// [app-data]: https://docs.cow.fi/cow-protocol/reference/core/intents/app-data
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
pub struct AppDataHash(pub [u8; 32]);

impl fmt::Debug for AppDataHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut hex = [0u8; 64];
        const_hex::encode_to_slice(self.0, &mut hex).unwrap();
        f.write_str("AppDataHash(0x")?;
        f.write_str(std::str::from_utf8(&hex).unwrap())?;
        f.write_str(")")
    }
}

impl From<[u8; 32]> for AppDataHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for AppDataHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for AppDataHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        crate::bytes_hex::serialize(self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for AppDataHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = crate::bytes_hex::deserialize(deserializer)?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| D::Error::custom(format!("expected 32 bytes, got {}", bytes.len())))?;
        Ok(Self(arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_round_trip_zero() {
        let zero = AppDataHash([0; 32]);
        let json = serde_json::to_value(zero).unwrap();
        assert_eq!(
            json,
            serde_json::json!("0x0000000000000000000000000000000000000000000000000000000000000000")
        );
        let parsed: AppDataHash = serde_json::from_value(json).unwrap();
        assert_eq!(parsed, zero);
    }

    #[test]
    fn json_round_trip_non_zero() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xab;
        bytes[31] = 0xcd;
        let original = AppDataHash(bytes);
        let json = serde_json::to_value(original).unwrap();
        let parsed: AppDataHash = serde_json::from_value(json).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn rejects_wrong_length() {
        let json = serde_json::json!("0xabcd");
        let result: Result<AppDataHash, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_missing_prefix() {
        let json =
            serde_json::json!("0000000000000000000000000000000000000000000000000000000000000000");
        let result: Result<AppDataHash, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }
}
