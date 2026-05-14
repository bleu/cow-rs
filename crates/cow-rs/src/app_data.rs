//! The `appData` field of a CoW Protocol order: a 32-byte digest of the
//! application metadata document, encoded as `0x`-prefixed hex when sent
//! over the wire.
//!
//! This module also exposes [`AppDataDoc`], a builder for the canonical
//! JSON document the digest points at. The doc serialises to a
//! deterministic, sorted-keys, whitespace-free JSON string so the
//! resulting [`AppDataHash`] is stable across runs and matches the digest
//! the orderbook pins to IPFS.

use alloy_primitives::{Address, keccak256};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use std::fmt;

use crate::order::OrderClass;

/// 32-byte digest of an [app-data] document.
///
/// The digest is the keccak256 of the deterministically-stringified JSON
/// document and is embedded directly in the signed order payload. It is
/// **not** an IPFS CID: derive the multihash off the same digest when one
/// is needed.
///
/// [app-data]: https://docs.cow.fi/cow-protocol/reference/core/intents/app-data
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
}
