//! The `appData` field of a CoW Protocol order: a 32-byte digest of the
//! application metadata document, encoded as `0x`-prefixed hex when sent
//! over the wire.
//!
//! This module also exposes [`AppDataDoc`], a builder for the canonical
//! JSON document the digest points at. The doc serialises to a
//! deterministic, sorted-keys, whitespace-free JSON string so the
//! resulting [`AppDataHash`] is stable across runs and matches the digest
//! the orderbook pins to IPFS.
//!
//! [`AppDataCid`] derives the IPFS CID under which the orderbook pins the
//! document. The derivation is pure: it concatenates a 4-byte CIDv1 prefix
//! with the existing 32-byte digest and emits the bytes in base32 lower-case
//! (RFC 4648, no padding) with the `b` multibase tag.

use alloy_primitives::{Address, keccak256};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use std::fmt;

use crate::order::OrderClass;

/// 32-byte digest of an [app-data] document.
///
/// The digest is the keccak256 of the deterministically-stringified JSON
/// document and is embedded directly in the signed order payload. It is
/// **not** itself an IPFS CID: call [`AppDataHash::to_cid`] (or
/// [`AppDataCid::from_hash`]) to derive the CID the orderbook pins the
/// document under.
///
/// [app-data]: https://docs.cow.fi/cow-protocol/reference/core/intents/app-data
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AppDataHash(pub [u8; 32]);

impl fmt::Debug for AppDataHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AppDataHash({})", const_hex::encode_prefixed(self.0))
    }
}

impl fmt::Display for AppDataHash {
    /// `0x`-prefixed lower-case hex, matching the wire form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut bytes = [0u8; 2 + 64];
        bytes[..2].copy_from_slice(b"0x");
        const_hex::encode_to_slice(self.0, &mut bytes[2..]).unwrap();
        f.write_str(std::str::from_utf8(&bytes).unwrap())
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

impl AppDataHash {
    /// Derive the IPFS CID the orderbook pins this document under.
    ///
    /// Shortcut for [`AppDataCid::from_hash`]; see that type for the wire
    /// format.
    pub fn to_cid(&self) -> AppDataCid {
        AppDataCid::from_hash(*self)
    }
}

/// `keccak256("{}")`: the digest of the canonical empty app-data document.
///
/// The orderbook accepts an unset / empty app-data digest, but for fixtures
/// and tests we mirror cow-sdk's convention of explicitly pinning the empty
/// document.
pub const EMPTY_APP_DATA_HASH: AppDataHash = AppDataHash(hex_literal::hex!(
    "b48d38f93eaa084033fc5970bf96e559c33c4cdc07d889ab00b4d63f9590739d"
));

/// JSON representation of the empty app-data document (`"{}"`).
///
/// Paired with [`EMPTY_APP_DATA_HASH`] when submitting orders without
/// custom app-data metadata.
pub const EMPTY_APP_DATA_JSON: &str = "{}";

/// Current SemVer of the app-data schema this crate emits.
///
/// Matches the version tag the cow-sdk / cow-py canonical documents pin at
/// the time of writing. Bump in lock-step with upstream when the schema
/// changes; see `cow-protocol/reference/core/intents/app-data.mdx`.
pub const LATEST_APP_DATA_VERSION: &str = "1.6.0";

/// Maximum byte length of a `fullAppData` document the orderbook will
/// accept on `PUT /api/v1/app_data/{hash}`. Mirrors the server-side
/// `Validator::DEFAULT_SIZE_LIMIT` in `cowprotocol/services/crates/shared/
/// src/app_data.rs`. Clients that build a document larger than this
/// should refuse to sign an order against its hash; the orderbook will
/// otherwise reject the document with `400 Bad Request` after the
/// signature is already committed to the digest.
pub const APP_DATA_SIZE_LIMIT: usize = 8192;

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

/// Canonical app-data JSON document.
///
/// Mirrors the v1.x schema family used by cow-sdk's `@cowprotocol/app-data`
/// and cow-py's `AppDataDoc`. Only the fields most integrations need are
/// modelled explicitly; involved nested structures (notably hooks) fall
/// through as opaque JSON so callers can pass them as-is.
///
/// The struct is deliberately additive: every field except `version` is
/// optional and is skipped from the serialised JSON when unset, so the
/// minimal document mirrors what cow-py emits for an empty `AppDataDoc`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppDataDoc {
    /// SemVer of the schema, e.g. `"1.6.0"`.
    pub version: String,
    /// Who built the integration. Freeform; cow-sdk recommends a stable,
    /// human-readable identifier per integration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_code: Option<String>,
    /// Optional environment marker (`"prod"`, `"staging"`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    /// Application metadata. Always present in the serialised JSON; an
    /// all-`None` value renders as `{}`.
    #[serde(default)]
    pub metadata: AppDataMetadata,
}

/// `metadata` sub-document of [`AppDataDoc`].
///
/// All fields are optional and skipped when unset. The more involved
/// sub-types ([`AppDataHooks`]) are modelled as opaque JSON so callers can
/// thread arbitrary pre- / post-hook arrays through without this crate
/// needing to track every schema tweak.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppDataMetadata {
    /// Quote-time metadata (slippage hint and version tag).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote: Option<AppDataQuote>,
    /// Order classification (market / limit / liquidity).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order_class: Option<AppDataOrderClass>,
    /// Partner-fee instructions (basis-point cut + recipient).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partner_fee: Option<AppDataPartnerFee>,
    /// Referrer attribution (wallet address).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referrer: Option<AppDataReferrer>,
    /// UTM campaign tracking parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utm: Option<AppDataUtm>,
    /// Pre- and post-trade hooks. Opaque JSON: see the cow-hooks SDK and
    /// `cow-protocol/reference/core/intents/hooks` for the structure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hooks: Option<serde_json::Value>,
}

/// Quote metadata: only the slippage hint is modelled explicitly.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppDataQuote {
    /// Slippage applied to the quote, in basis points (`10_000 == 100 %`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slippage_bips: Option<u32>,
    /// Optional version tag for the quote sub-document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// `metadata.orderClass` sub-document.
///
/// Wraps [`crate::order::OrderClass`] in the JSON envelope cow-sdk emits.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppDataOrderClass {
    /// The class tag carried in `metadata.orderClass.orderClass`.
    pub order_class: crate::order::OrderClass,
}

/// `metadata.partnerFee` sub-document.
///
/// Solvers route the configured basis-point cut of order surplus to
/// `recipient`. See `cow-protocol/reference/core/intents/app-data.mdx`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppDataPartnerFee {
    /// Basis points (`100 == 1 %`).
    pub bps: u32,
    /// Address that receives the partner fee.
    pub recipient: Address,
}

/// `metadata.referrer` sub-document.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppDataReferrer {
    /// Referrer wallet address.
    pub address: Address,
    /// Optional version tag for the referrer sub-document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// `metadata.utm` sub-document: campaign attribution.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppDataUtm {
    /// `utm_source`: origin of the traffic (e.g. `"telegram"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utm_source: Option<String>,
    /// `utm_medium`: broad channel (e.g. `"social"`, `"email"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utm_medium: Option<String>,
    /// `utm_campaign`: campaign identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utm_campaign: Option<String>,
    /// `utm_content`: freeform graffiti / per-order tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utm_content: Option<String>,
    /// `utm_term`: paid-search keyword / segmentation tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utm_term: Option<String>,
}

/// Opaque hooks payload alias, kept around so callers can refer to the
/// expected shape by name even though we don't model the nested arrays.
pub type AppDataHooks = serde_json::Value;

impl AppDataDoc {
    /// Minimal constructor. Pins `version` to [`LATEST_APP_DATA_VERSION`]
    /// and leaves every other field unset.
    pub fn new(app_code: impl Into<String>) -> Self {
        Self {
            version: LATEST_APP_DATA_VERSION.to_string(),
            app_code: Some(app_code.into()),
            environment: None,
            metadata: AppDataMetadata::default(),
        }
    }

    /// Builder: attach a referrer address.
    pub fn with_referrer(mut self, address: Address) -> Self {
        self.metadata.referrer = Some(AppDataReferrer {
            address,
            version: None,
        });
        self
    }

    /// Builder: attach a partner fee.
    pub const fn with_partner_fee(mut self, bps: u32, recipient: Address) -> Self {
        self.metadata.partner_fee = Some(AppDataPartnerFee { bps, recipient });
        self
    }

    /// Builder: tag the order with an order class.
    pub const fn with_order_class(mut self, order_class: OrderClass) -> Self {
        self.metadata.order_class = Some(AppDataOrderClass { order_class });
        self
    }

    /// Builder: attach a slippage hint to the quote sub-document.
    pub fn with_slippage_bips(mut self, slippage_bips: u32) -> Self {
        let quote = self
            .metadata
            .quote
            .get_or_insert_with(AppDataQuote::default);
        quote.slippage_bips = Some(slippage_bips);
        self
    }

    /// Builder: mark the environment (`"prod"`, `"staging"`, …).
    pub fn with_environment(mut self, environment: impl Into<String>) -> Self {
        self.environment = Some(environment.into());
        self
    }

    /// Serialise the document to deterministic JSON.
    ///
    /// The output has all object keys sorted lexicographically and no
    /// whitespace, mirroring cow-py's `stringify_deterministic`. This is
    /// the byte string the orderbook hashes (and pins to IPFS).
    ///
    /// We round-trip via [`serde_json::Value`] because, with
    /// `preserve_order` disabled, its `Map` is a `BTreeMap` whose keys
    /// iterate in sorted order: re-serialising the value therefore emits
    /// sorted keys regardless of the struct field declaration order.
    pub fn canonical_json(&self) -> String {
        let value = serde_json::to_value(self).expect("AppDataDoc must serialise");
        let sorted = sort_value(value);
        serde_json::to_string(&sorted).expect("Value must re-serialise")
    }

    /// `keccak256(canonical_json())`. This is the digest written into the
    /// signed `Order.appData` field.
    pub fn hash(&self) -> AppDataHash {
        let digest = keccak256(self.canonical_json().as_bytes());
        AppDataHash(digest.0)
    }
}

/// Recursively rebuild a [`serde_json::Value`] so every object's keys are
/// in sorted order. `serde_json::Map` is a `BTreeMap` when the
/// `preserve_order` feature is off (the workspace default), so this is
/// effectively a deep clone: but doing the walk explicitly future-proofs
/// the helper against the feature flipping on later.
fn sort_value(value: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            let mut sorted = serde_json::Map::new();
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            for (k, v) in entries {
                sorted.insert(k, sort_value(v));
            }
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sort_value).collect()),
        other => other,
    }
}

/// IPFS CID that the orderbook pins app-data documents under.
///
/// Format: `cidv1(raw codec 0x55, multihash keccak-256 0x1b 0x20 || hash)`,
/// base32-encoded (RFC 4648 lower-case alphabet, no padding) and prefixed
/// with the `b` multibase tag. The multihash hash function is **keccak-256**,
/// matching the digest the orderbook stores in the signed order; the CID
/// therefore round-trips with [`AppDataHash`] without any further hashing.
///
/// This matches the derivation in `cowprotocol/services` (`crates/app-data`,
/// `create_ipfs_cid`) and the legacy-free path in cow-sdk's
/// `appDataHexToCid` and cow-py's `AppDataHex.to_cid`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AppDataCid(String);

/// CIDv1 version byte: `0x01`.
const CID_V1: u8 = 0x01;
/// IPFS multicodec for raw bytes: `0x55`.
const CID_CODEC_RAW: u8 = 0x55;
/// Multihash code for keccak-256: `0x1b`.
const MULTIHASH_KECCAK_256: u8 = 0x1b;
/// Multihash digest length for 32-byte hashes.
const MULTIHASH_LEN_32: u8 = 0x20;
/// Total size of the binary CID before multibase encoding.
const CID_BYTES_LEN: usize = 4 + 32;

impl AppDataCid {
    /// Derive the CID a 32-byte app-data digest pins to.
    ///
    /// Pure offline derivation: builds the 36-byte CID
    /// `[0x01, 0x55, 0x1b, 0x20, ..hash]` and base32-encodes it with the
    /// `b` multibase prefix.
    pub fn from_hash(hash: AppDataHash) -> Self {
        let mut bytes = [0u8; CID_BYTES_LEN];
        bytes[0] = CID_V1;
        bytes[1] = CID_CODEC_RAW;
        bytes[2] = MULTIHASH_KECCAK_256;
        bytes[3] = MULTIHASH_LEN_32;
        bytes[4..].copy_from_slice(&hash.0);

        let mut out = String::with_capacity(1 + base32_encoded_len(CID_BYTES_LEN));
        out.push('b');
        base32_encode_into(&bytes, &mut out);
        Self(out)
    }

    /// Borrow the canonical `b...` string representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Extract the embedded [`AppDataHash`] back out of the CID.
    ///
    /// Accepts both `b`-prefixed (RFC 4648 lower-case base32, no padding)
    /// and `f`-prefixed (lower-case base16) multibase encodings. cow-rs
    /// only emits the `b` form, matching `cowprotocol/services` and the
    /// orderbook's IPFS pin, but cow-sdk (TypeScript) emits `f` so
    /// round-tripping a CID handed to us by the canonical JS SDK
    /// requires accepting both. Validates version, codec, multihash
    /// code, and digest length before returning the trailing 32 bytes.
    pub fn to_hash(&self) -> Result<AppDataHash, AppDataCidError> {
        let bytes = match self.0.as_bytes().first() {
            Some(b'b') => base32_decode(&self.0[1..])?,
            Some(b'f') => {
                const_hex::decode(&self.0[1..]).map_err(|_| AppDataCidError::InvalidBase16Body)?
            }
            _ => return Err(AppDataCidError::MissingMultibasePrefix),
        };
        if bytes.len() != CID_BYTES_LEN {
            return Err(AppDataCidError::InvalidLength {
                expected: CID_BYTES_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[0] != CID_V1 {
            return Err(AppDataCidError::UnexpectedVersion(bytes[0]));
        }
        if bytes[1] != CID_CODEC_RAW {
            return Err(AppDataCidError::UnexpectedCodec(bytes[1]));
        }
        if bytes[2] != MULTIHASH_KECCAK_256 {
            return Err(AppDataCidError::UnexpectedMultihashCode(bytes[2]));
        }
        if bytes[3] != MULTIHASH_LEN_32 {
            return Err(AppDataCidError::UnexpectedDigestLength(bytes[3]));
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes[4..]);
        Ok(AppDataHash(digest))
    }
}

impl fmt::Display for AppDataCid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for AppDataCid {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Errors raised while parsing an [`AppDataCid`] back into an
/// [`AppDataHash`].
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum AppDataCidError {
    /// The CID string was not multibase base32 (`b`) or base16 (`f`).
    #[error("expected multibase `b` (base32) or `f` (base16) prefix")]
    MissingMultibasePrefix,
    /// A character outside the RFC 4648 lower-case alphabet was found.
    #[error("invalid base32 character {0:?}")]
    InvalidBase32Char(char),
    /// The base16-encoded body contained a character outside `[0-9a-f]`.
    #[error("invalid base16 (hex) body")]
    InvalidBase16Body,
    /// The decoded CID body had the wrong length.
    #[error("expected {expected}-byte CID body, got {actual}")]
    InvalidLength {
        /// Number of bytes we expect (`36`).
        expected: usize,
        /// Number of bytes actually decoded.
        actual: usize,
    },
    /// The version byte was not `0x01`.
    #[error("expected CIDv1 (0x01), got 0x{0:02x}")]
    UnexpectedVersion(u8),
    /// The codec byte was not the raw codec `0x55`.
    #[error("expected raw codec (0x55), got 0x{0:02x}")]
    UnexpectedCodec(u8),
    /// The multihash code was not keccak-256 (`0x1b`).
    #[error("expected keccak-256 multihash (0x1b), got 0x{0:02x}")]
    UnexpectedMultihashCode(u8),
    /// The multihash length byte was not `0x20`.
    #[error("expected 32-byte digest (0x20), got 0x{0:02x}")]
    UnexpectedDigestLength(u8),
}

/// RFC 4648 base32 lower-case alphabet, no padding.
const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Output length of base32 encoding without padding.
const fn base32_encoded_len(input_len: usize) -> usize {
    input_len.div_ceil(5) * 8
}

/// Encode `input` as RFC 4648 base32 lower-case (no padding) into `out`.
fn base32_encode_into(input: &[u8], out: &mut String) {
    // Walk 5-byte groups, pack into 40 bits, slice off the high 5-bit chunks.
    // The final partial group emits only the bytes its bits actually cover,
    // which matches "no padding" by simply stopping early.
    let mut chunks = input.chunks_exact(5);
    for chunk in chunks.by_ref() {
        let buf: u64 = (u64::from(chunk[0]) << 32)
            | (u64::from(chunk[1]) << 24)
            | (u64::from(chunk[2]) << 16)
            | (u64::from(chunk[3]) << 8)
            | u64::from(chunk[4]);
        for shift in (0..8).rev() {
            let idx = ((buf >> (shift * 5)) & 0x1f) as usize;
            out.push(BASE32_ALPHABET[idx] as char);
        }
    }
    let tail = chunks.remainder();
    if !tail.is_empty() {
        let mut buf: u64 = 0;
        for (i, b) in tail.iter().enumerate() {
            buf |= u64::from(*b) << ((4 - i) * 8);
        }
        // Bytes per remainder length: 1->2, 2->4, 3->5, 4->7.
        let out_chars = match tail.len() {
            1 => 2,
            2 => 4,
            3 => 5,
            4 => 7,
            _ => unreachable!("chunks_exact remainder is < 5"),
        };
        for i in 0..out_chars {
            let idx = ((buf >> ((7 - i) * 5)) & 0x1f) as usize;
            out.push(BASE32_ALPHABET[idx] as char);
        }
    }
}

/// Decode an RFC 4648 base32 lower-case string (no padding).
///
/// Accepts the encoding produced by [`base32_encode_into`] and rejects any
/// character outside the lower-case alphabet. Upper-case input is rejected
/// to keep the round-trip canonical.
fn base32_decode(input: &str) -> Result<Vec<u8>, AppDataCidError> {
    let bytes = input.as_bytes();
    // Strip any trailing `=` padding tolerantly: the canonical form has none,
    // but accepting it costs nothing and survives copy-paste of padded CIDs.
    let len = bytes.iter().rposition(|b| *b != b'=').map_or(0, |p| p + 1);
    let trimmed = &bytes[..len];

    let mut out = Vec::with_capacity(trimmed.len() * 5 / 8);
    let mut buf: u64 = 0;
    let mut bits: u32 = 0;
    for &b in trimmed {
        let value = match b {
            b'a'..=b'z' => b - b'a',
            b'2'..=b'7' => b - b'2' + 26,
            _ => return Err(AppDataCidError::InvalidBase32Char(b as char)),
        };
        buf = (buf << 5) | u64::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            let byte = ((buf >> bits) & 0xff) as u8;
            out.push(byte);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use {super::*, alloy_primitives::address};

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

    /// Lock [`EMPTY_APP_DATA_HASH`] against `keccak256("{}")`: any drift
    /// would either break interop with cow-sdk fixtures or signal that the
    /// canonical empty document changed.
    #[test]
    fn empty_app_data_hash_matches_keccak() {
        let computed = alloy_primitives::keccak256(EMPTY_APP_DATA_JSON);
        assert_eq!(EMPTY_APP_DATA_HASH.0, *computed);
    }

    #[test]
    fn empty_doc_matches_constant() {
        let doc = AppDataDoc::new("");
        // Every metadata field is `None` by default.
        assert!(doc.metadata.quote.is_none());
        assert!(doc.metadata.order_class.is_none());
        assert!(doc.metadata.partner_fee.is_none());
        assert!(doc.metadata.referrer.is_none());
        assert!(doc.metadata.utm.is_none());
        assert!(doc.metadata.hooks.is_none());

        let json = doc.canonical_json();
        assert_eq!(json, r#"{"appCode":"","metadata":{},"version":"1.6.0"}"#);

        // Round-trip back into a doc.
        let parsed: AppDataDoc = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, doc);
    }

    #[test]
    fn referrer_doc_round_trips() {
        let referrer = address!("1234567890AbcdEF1234567890aBcdef12345678");
        let doc = AppDataDoc::new("my-app").with_referrer(referrer);

        let json = doc.canonical_json();
        // alloy's `Address` serialises with EIP-55 mixed-case checksum, so
        // assert on the case-insensitive hex rather than a literal string.
        assert!(
            json.to_lowercase()
                .contains(r#""referrer":{"address":"0x1234567890abcdef1234567890abcdef12345678"}"#)
        );

        let hash = doc.hash();
        // Re-hash from the JSON string and compare: guards against any
        // path where canonical_json and hash drift apart.
        let direct = alloy_primitives::keccak256(json.as_bytes());
        assert_eq!(hash.0, *direct);

        let parsed: AppDataDoc = serde_json::from_str(&json).unwrap();
        let parsed_referrer = parsed.metadata.referrer.expect("referrer preserved");
        assert_eq!(parsed_referrer.address, referrer);
    }

    /// Golden vector: locks the canonical bytes and hash of the minimal
    /// `AppDataDoc::new("")` document. Computed independently with Python
    /// (`json.dumps(..., sort_keys=True, separators=(",", ":"))` + keccak)
    ///: any drift here means our deterministic serialisation changed and
    /// will silently re-hash existing fixtures.
    #[test]
    fn minimal_doc_golden_hash() {
        let doc = AppDataDoc::new("");
        assert_eq!(
            doc.canonical_json(),
            r#"{"appCode":"","metadata":{},"version":"1.6.0"}"#
        );
        let expected =
            hex_literal::hex!("3929e2c230dc41c0c053ff5f9211eb32def3a737b2bf36eb5b8862ea317fcd9e");
        assert_eq!(doc.hash().0, expected);
    }

    #[test]
    fn canonical_json_sorts_keys_deterministically() {
        // Build a doc with several metadata fields and confirm the
        // emitted JSON is sorted at every level.
        let doc = AppDataDoc::new("app")
            .with_referrer(address!("0000000000000000000000000000000000000001"))
            .with_partner_fee(50, address!("0000000000000000000000000000000000000002"))
            .with_order_class(OrderClass::Limit)
            .with_slippage_bips(25)
            .with_environment("prod");

        let json = doc.canonical_json();

        // Top-level keys appear in lexicographic order.
        let app_code_pos = json.find("appCode").unwrap();
        let environment_pos = json.find("environment").unwrap();
        let metadata_pos = json.find("metadata").unwrap();
        let version_pos = json.find("\"version\"").unwrap();
        assert!(app_code_pos < environment_pos);
        assert!(environment_pos < metadata_pos);
        assert!(metadata_pos < version_pos);

        // The output is stable run-to-run.
        assert_eq!(json, doc.canonical_json());
    }

    #[test]
    fn partner_fee_round_trips() {
        let recipient = address!("00000000219AB540356CBb839CbE05303D7705FA");
        let doc = AppDataDoc::new("app").with_partner_fee(75, recipient);
        let json = doc.canonical_json();
        let parsed: AppDataDoc = serde_json::from_str(&json).unwrap();
        let fee = parsed.metadata.partner_fee.expect("partner fee preserved");
        assert_eq!(fee.bps, 75);
        assert_eq!(fee.recipient, recipient);
    }

    #[test]
    fn order_class_serialises_as_lowercase() {
        let doc = AppDataDoc::new("app").with_order_class(OrderClass::Market);
        let json = doc.canonical_json();
        assert!(json.contains(r#""orderClass":{"orderClass":"market"}"#));
    }

    #[test]
    fn hooks_pass_through_as_opaque_json() {
        let mut doc = AppDataDoc::new("app");
        doc.metadata.hooks = Some(serde_json::json!({
            "version": "0.1.0",
            "pre": [{"target": "0xabc", "callData": "0xdef", "gasLimit": "21000"}],
            "post": [],
        }));
        let json = doc.canonical_json();
        let parsed: AppDataDoc = serde_json::from_str(&json).unwrap();
        let hooks = parsed.metadata.hooks.expect("hooks preserved");
        assert_eq!(hooks["version"], "0.1.0");
        assert_eq!(hooks["pre"][0]["target"], "0xabc");
    }

    /// Round-trip every byte position so any off-by-one in the base32 packer
    /// or in the `to_hash` slice arithmetic shows up immediately.
    #[test]
    fn cid_round_trip_default_and_walking_bytes() {
        let default = AppDataHash::default();
        assert_eq!(default.to_cid().to_hash().unwrap(), default);

        for i in 0..32 {
            let mut bytes = [0u8; 32];
            bytes[i] = 0xff;
            let hash = AppDataHash(bytes);
            let cid = hash.to_cid();
            assert_eq!(
                cid.to_hash().unwrap(),
                hash,
                "round-trip failed at byte {i}"
            );
            // Multibase tag is always `b`, body is always lower-case alpha
            // or `234567`, never any other character.
            assert!(cid.as_str().starts_with('b'));
            assert!(
                cid.as_str()
                    .chars()
                    .skip(1)
                    .all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c))
            );
        }
    }

    /// `bafkrw` is the base32 multibase rendering of the constant CID prefix
    /// `01 55 1b 20` (CIDv1, raw codec, keccak-256, 32 bytes). Any digest
    /// that uses this prefix must encode to a string starting with
    /// `bafkrw`. The legacy sha2-256 path that gives `bafkrei` is **not**
    /// what the orderbook pins under.
    #[test]
    fn cid_for_empty_app_data_hash_starts_with_bafkrw() {
        let cid = EMPTY_APP_DATA_HASH.to_cid();
        assert!(
            cid.as_str().starts_with("bafkrw"),
            "expected bafkrw prefix, got {}",
            cid.as_str()
        );
    }

    /// Golden vector lifted from `cowprotocol/services`
    /// (`crates/app-data/src/app_data_hash.rs::tests::known_good`). The
    /// services repo additionally cites the equivalent `ipfs cid format
    /// -b base16` and `-b base32` strings, both of which we lock here.
    #[test]
    fn cid_matches_services_known_good_vector() {
        let hash = AppDataHash(hex_literal::hex!(
            "8af4e8c9973577b08ac21d17d331aade86c11ebcc5124744d621ca8365ec9424"
        ));
        let cid = hash.to_cid();
        assert_eq!(
            cid.as_str(),
            "bafkrwiek6tumtfzvo6yivqq5c7jtdkw6q3ar5pgfcjdujvrbzkbwl3eueq"
        );
        assert_eq!(cid.to_hash().unwrap(), hash);
    }

    /// Lock the canonical CID for the default-empty document
    /// (`keccak256("{}")`), independently computed via Python's `base32`
    /// over `01 55 1b 20 || EMPTY_APP_DATA_HASH`.
    #[test]
    fn cid_for_empty_doc_golden() {
        let cid = EMPTY_APP_DATA_HASH.to_cid();
        assert_eq!(
            cid.as_str(),
            "bafkrwifuru4pspvkbbadh7czoc7znzkzym6ezxah3ce2wafu2y7zledttu"
        );
    }

    #[test]
    fn cid_parse_rejects_missing_multibase_prefix() {
        // Drop the leading `b`.
        let cid =
            AppDataCid("afkrwifuru4pspvkbbadh7czoc7znzkzym6ezxah3ce2wafu2y7zledttu".to_string());
        assert_eq!(
            cid.to_hash().unwrap_err(),
            AppDataCidError::MissingMultibasePrefix
        );
    }

    /// Round-trip the same `services` golden vector through the `f`
    /// (base16) multibase prefix. cow-sdk's TypeScript
    /// `appDataHexToCid` emits this form by default; the orderbook
    /// accepts either prefix, so cow-rs must too.
    #[test]
    fn cid_parse_accepts_base16_multibase_prefix() {
        let hash = AppDataHash(hex_literal::hex!(
            "8af4e8c9973577b08ac21d17d331aade86c11ebcc5124744d621ca8365ec9424"
        ));
        let mut hex_body = String::with_capacity(2 * CID_BYTES_LEN);
        hex_body.push_str("01551b20");
        hex_body.push_str(&const_hex::encode(hash.0));
        let cid = AppDataCid(format!("f{hex_body}"));
        assert_eq!(cid.to_hash().unwrap(), hash);
    }

    #[test]
    fn cid_parse_rejects_invalid_base16_body() {
        let cid = AppDataCid("f01551b20zzzz".to_string());
        assert_eq!(
            cid.to_hash().unwrap_err(),
            AppDataCidError::InvalidBase16Body
        );
    }

    #[test]
    fn cid_parse_rejects_wrong_codec() {
        // Build a CID where the codec byte is `0x70` (dag-pb) instead of
        // raw. Keccak code stays at `0x1b`, length stays at `0x20`.
        let mut bytes = [0u8; CID_BYTES_LEN];
        bytes[0] = 0x01;
        bytes[1] = 0x70; // dag-pb, not raw
        bytes[2] = 0x1b;
        bytes[3] = 0x20;
        bytes[4..].copy_from_slice(&EMPTY_APP_DATA_HASH.0);
        let mut s = String::from("b");
        base32_encode_into(&bytes, &mut s);
        let cid = AppDataCid(s);
        assert_eq!(
            cid.to_hash().unwrap_err(),
            AppDataCidError::UnexpectedCodec(0x70)
        );
    }

    #[test]
    fn cid_parse_rejects_wrong_multihash() {
        // sha2-256 (0x12) instead of keccak-256 (0x1b): this is the
        // distinct "legacy" CID family that cow-sdk's `appDataHexToCidLegacy`
        // emits. We do **not** want to silently accept it as our CID since
        // its digest semantics are different.
        let mut bytes = [0u8; CID_BYTES_LEN];
        bytes[0] = 0x01;
        bytes[1] = 0x55;
        bytes[2] = 0x12; // sha2-256
        bytes[3] = 0x20;
        bytes[4..].copy_from_slice(&EMPTY_APP_DATA_HASH.0);
        let mut s = String::from("b");
        base32_encode_into(&bytes, &mut s);
        let cid = AppDataCid(s);
        assert_eq!(
            cid.to_hash().unwrap_err(),
            AppDataCidError::UnexpectedMultihashCode(0x12)
        );
    }

    #[test]
    fn cid_parse_rejects_wrong_length() {
        // Truncate the base32 body so the decoded byte length is wrong.
        let cid = AppDataCid("babcdefgh".to_string());
        match cid.to_hash() {
            Err(AppDataCidError::InvalidLength { expected, actual }) => {
                assert_eq!(expected, CID_BYTES_LEN);
                assert_ne!(actual, CID_BYTES_LEN);
            }
            other => panic!("expected InvalidLength, got {other:?}"),
        }
    }

    #[test]
    fn cid_parse_rejects_wrong_version() {
        // Version byte `0x00` (CIDv0 marker) is invalid in this raw form.
        let mut bytes = [0u8; CID_BYTES_LEN];
        bytes[0] = 0x00;
        bytes[1] = 0x55;
        bytes[2] = 0x1b;
        bytes[3] = 0x20;
        bytes[4..].copy_from_slice(&EMPTY_APP_DATA_HASH.0);
        let mut s = String::from("b");
        base32_encode_into(&bytes, &mut s);
        let cid = AppDataCid(s);
        assert_eq!(
            cid.to_hash().unwrap_err(),
            AppDataCidError::UnexpectedVersion(0x00)
        );
    }

    #[test]
    fn cid_parse_rejects_wrong_digest_length() {
        // Multihash length `0x10` (16 bytes) instead of `0x20` (32). Pad
        // with the digest so the overall body length matches the constant.
        let mut bytes = [0u8; CID_BYTES_LEN];
        bytes[0] = 0x01;
        bytes[1] = 0x55;
        bytes[2] = 0x1b;
        bytes[3] = 0x10; // 16, not 32
        bytes[4..].copy_from_slice(&EMPTY_APP_DATA_HASH.0);
        let mut s = String::from("b");
        base32_encode_into(&bytes, &mut s);
        let cid = AppDataCid(s);
        assert_eq!(
            cid.to_hash().unwrap_err(),
            AppDataCidError::UnexpectedDigestLength(0x10)
        );
    }

    #[test]
    fn cid_parse_rejects_invalid_base32_char() {
        // `8` is outside RFC 4648's lower-case 32-char alphabet.
        let cid = AppDataCid("b8".to_string());
        assert_eq!(
            cid.to_hash().unwrap_err(),
            AppDataCidError::InvalidBase32Char('8')
        );
    }

    /// Cover base32 encoding for every remainder length so a fix to one
    /// branch does not silently corrupt another. Vectors are RFC 4648
    /// §10 ("Test vectors"), lower-cased and stripped of padding.
    #[test]
    fn base32_encode_rfc4648_vectors() {
        let cases: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "my"),
            (b"fo", "mzxq"),
            (b"foo", "mzxw6"),
            (b"foob", "mzxw6yq"),
            (b"fooba", "mzxw6ytb"),
            (b"foobar", "mzxw6ytboi"),
        ];
        for (input, expected) in cases {
            let mut out = String::new();
            base32_encode_into(input, &mut out);
            assert_eq!(&out, expected, "encode mismatch for {input:?}");
            let decoded = base32_decode(expected).unwrap();
            assert_eq!(&decoded, input, "decode mismatch for {expected:?}");
        }
    }
}
