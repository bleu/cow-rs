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
//! [`app_data_cid`] derives the IPFS CID under which the orderbook pins
//! the document, returning a [`cid::Cid`] whose `Display` already emits
//! the base32 lower-case (`b`-prefixed) multibase string the orderbook
//! indexes by.

use alloy_primitives::{Address, B256, Bytes, U256, b256, keccak256};
use cid::multihash::Multihash;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use serde_with::{DisplayFromStr, serde_as};

use crate::order::{OrderClass, OrderUid};

/// 32-byte keccak256 digest of an [app-data] document, embedded directly
/// in the signed order's `appData` field. Type-aliased onto alloy's
/// [`B256`] so the `Debug` / `Display` / serde / `FromStr` / `AsRef<[u8]>`
/// surface comes from there for free; call [`app_data_cid`] for the IPFS
/// CID the orderbook pins the document under.
///
/// [app-data]: https://docs.cow.fi/cow-protocol/reference/core/intents/app-data
pub type AppDataHash = B256;

/// `keccak256("{}")`: digest of the canonical empty app-data document.
pub const EMPTY_APP_DATA_HASH: AppDataHash =
    b256!("b48d38f93eaa084033fc5970bf96e559c33c4cdc07d889ab00b4d63f9590739d");

/// JSON representation of the empty app-data document (`"{}"`).
pub const EMPTY_APP_DATA_JSON: &str = "{}";

/// SemVer of the schema this crate emits. Bump in lock-step with
/// upstream; see `cow-protocol/reference/core/intents/app-data.mdx`.
pub const LATEST_APP_DATA_VERSION: &str = "1.6.0";

/// `appCode` tag for the native Rust SDK. Apply via
/// [`AppDataDoc::sdk_attribution`].
pub const COW_RS_APP_CODE: &str = "cow-rs";

/// `appCode` tag for the wasm shim (`cow-sdk-wasm` on npm).
pub const COW_RS_WASM_APP_CODE: &str = "cow-rs-wasm";

/// Maximum `fullAppData` size the orderbook accepts on
/// `PUT /api/v1/app_data/{hash}`. Mirrors
/// `Validator::DEFAULT_SIZE_LIMIT` in `cowprotocol/services`.
pub const APP_DATA_SIZE_LIMIT: usize = 8192;

/// Canonical app-data JSON document. Mirrors cow-sdk's
/// `@cowprotocol/app-data` v1.x schema and cow-py's `AppDataDoc`.
/// Common fields are typed; hooks remain opaque JSON. Every field
/// except `version` is optional and skipped when unset.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppDataDoc {
    /// Schema SemVer, e.g. `"1.6.0"`.
    pub version: String,
    /// Integration identifier (freeform).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_code: Option<String>,
    /// `"prod"`, `"staging"`, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    /// Optional sub-document carrying SDK / partner attribution and hooks.
    #[serde(default)]
    pub metadata: AppDataMetadata,
}

/// `metadata` sub-document of [`AppDataDoc`]. Hooks stay opaque so
/// callers can thread arbitrary pre/post arrays without this crate
/// chasing schema tweaks.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppDataMetadata {
    /// Slippage / quote-time attribution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote: Option<AppDataQuote>,
    /// Market / limit / liquidity classification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order_class: Option<AppDataOrderClass>,
    /// Optional partner-fee policy and recipient.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partner_fee: Option<AppDataPartnerFee>,
    /// Optional referrer for analytics / rev-share.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referrer: Option<AppDataReferrer>,
    /// Optional UTM campaign tracking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utm: Option<AppDataUtm>,
    /// Pre- and post-trade hooks; opaque JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hooks: Option<serde_json::Value>,
    /// Optional flashloan parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flashloan: Option<AppDataFlashloan>,
    /// UID of the order this one replaces.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaced_order: Option<AppDataReplacedOrder>,
    /// Skipped when empty so a wrapper-free document hashes the same
    /// digest it did before the field was added.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wrappers: Vec<AppDataWrapperCall>,
}

/// `metadata.quote`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppDataQuote {
    /// Slippage in basis points (`10_000 == 100 %`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slippage_bips: Option<u32>,
    /// Optional quote schema version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// `metadata.orderClass` envelope around [`crate::order::OrderClass`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppDataOrderClass {
    /// Inner [`crate::order::OrderClass`] discriminant.
    pub order_class: crate::order::OrderClass,
}

/// `metadata.partnerFee`. Policy fields are flattened alongside
/// `recipient` on the wire, matching
/// `cowprotocol/services::app_data::PartnerFee`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppDataPartnerFee {
    /// Policy describing how the fee is computed.
    pub policy: FeePolicy,
    /// Address that receives the partner fee.
    pub recipient: Address,
}

impl Serialize for AppDataPartnerFee {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeMap as _;

        let entry_count = match self.policy {
            FeePolicy::Volume { .. } => 2,
            FeePolicy::Surplus { .. } | FeePolicy::PriceImprovement { .. } => 3,
        };
        let mut map = serializer.serialize_map(Some(entry_count))?;
        match self.policy {
            FeePolicy::Volume { bps } => {
                // Legacy `bps` key: preserves existing app-data hashes
                // and is still accepted by the upstream deserializer.
                map.serialize_entry("bps", &bps)?;
            }
            FeePolicy::Surplus {
                bps,
                max_volume_bps,
            } => {
                map.serialize_entry("surplusBps", &bps)?;
                map.serialize_entry("maxVolumeBps", &max_volume_bps)?;
            }
            FeePolicy::PriceImprovement {
                bps,
                max_volume_bps,
            } => {
                map.serialize_entry("priceImprovementBps", &bps)?;
                map.serialize_entry("maxVolumeBps", &max_volume_bps)?;
            }
        }
        map.serialize_entry("recipient", &self.recipient)?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for AppDataPartnerFee {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Helper {
            recipient: Address,
            #[serde(default)]
            bps: Option<u64>,
            #[serde(default)]
            volume_bps: Option<u64>,
            #[serde(default)]
            surplus_bps: Option<u64>,
            #[serde(default)]
            price_improvement_bps: Option<u64>,
            #[serde(default)]
            max_volume_bps: Option<u64>,
        }

        let h = Helper::deserialize(deserializer)?;
        let policy = match h {
            Helper {
                surplus_bps: Some(bps),
                max_volume_bps: Some(max_volume_bps),
                price_improvement_bps: None,
                volume_bps: None,
                bps: None,
                ..
            } => FeePolicy::Surplus {
                bps,
                max_volume_bps,
            },
            Helper {
                surplus_bps: None,
                max_volume_bps: Some(max_volume_bps),
                price_improvement_bps: Some(bps),
                volume_bps: None,
                bps: None,
                ..
            } => FeePolicy::PriceImprovement {
                bps,
                max_volume_bps,
            },
            Helper {
                surplus_bps: None,
                max_volume_bps: None,
                price_improvement_bps: None,
                volume_bps: Some(bps),
                bps: None,
                ..
            }
            | Helper {
                surplus_bps: None,
                max_volume_bps: None,
                price_improvement_bps: None,
                volume_bps: None,
                bps: Some(bps),
                ..
            } => FeePolicy::Volume { bps },
            _ => {
                return Err(D::Error::custom("unknown partner-fee policy shape"));
            }
        };
        validate_fee_policy(&policy).map_err(D::Error::custom)?;
        Ok(Self {
            policy,
            recipient: h.recipient,
        })
    }
}

/// Reject [`FeePolicy`] values whose bps fields exceed
/// [`PARTNER_FEE_BPS_MAX`]. A hostile document otherwise pins a
/// `bps = u64::MAX` that the contract silently clamps.
pub fn validate_fee_policy(policy: &FeePolicy) -> Result<(), AppDataError> {
    let check = |field: &'static str, value: u64| -> Result<(), AppDataError> {
        if value > PARTNER_FEE_BPS_MAX {
            Err(AppDataError::FeeOutOfRange {
                field,
                value,
                max: PARTNER_FEE_BPS_MAX,
            })
        } else {
            Ok(())
        }
    };
    match *policy {
        FeePolicy::Volume { bps } => check("bps", bps),
        FeePolicy::Surplus {
            bps,
            max_volume_bps,
        } => {
            check("surplusBps", bps)?;
            check("maxVolumeBps", max_volume_bps)
        }
        FeePolicy::PriceImprovement {
            bps,
            max_volume_bps,
        } => {
            check("priceImprovementBps", bps)?;
            check("maxVolumeBps", max_volume_bps)
        }
    }
}

impl AppDataPartnerFee {
    /// Construct a partner-fee binding with bps validation. Prefer
    /// this over hand-building when the policy values come from
    /// untrusted input.
    pub fn new(policy: FeePolicy, recipient: Address) -> Result<Self, AppDataError> {
        validate_fee_policy(&policy)?;
        Ok(Self { policy, recipient })
    }
}

/// Fee-policy variant for [`AppDataPartnerFee`]. Flattened alongside
/// `recipient` on the wire; matches the upstream `FeePolicy`
/// deserializer. `Volume` serialises as the legacy `bps` key (not
/// `volumeBps`) so previously-hashed digests stay stable; the
/// deserialiser accepts either.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeePolicy {
    /// `bps` charged on swap volume.
    Volume {
        /// Fee in basis points (`10_000 == 100 %`).
        bps: u64,
    },
    /// `bps` of captured surplus, capped at `max_volume_bps` of swap
    /// volume.
    Surplus {
        /// Surplus-capture rate, in basis points.
        bps: u64,
        /// Hard cap on the resulting fee, expressed as `bps` of volume.
        max_volume_bps: u64,
    },
    /// `bps` of price improvement vs the reference quote, capped at
    /// `max_volume_bps` of swap volume.
    PriceImprovement {
        /// Improvement-capture rate, in basis points.
        bps: u64,
        /// Hard cap on the resulting fee, expressed as `bps` of volume.
        max_volume_bps: u64,
    },
}

/// `metadata.flashloan`. Describes a flashloan attached to the order
/// (lender, adapter, receiver, token, atomic amount). Mirrors
/// `ProtocolAppData::flashloan` in `cowprotocol/services`.
#[serde_as]
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppDataFlashloan {
    /// Address of the lending pool funding the loan.
    pub liquidity_provider: Address,
    /// Adapter contract called by the solver to draw and repay the loan.
    pub protocol_adapter: Address,
    /// Address that receives the loaned tokens during settlement.
    pub receiver: Address,
    /// Token being borrowed.
    pub token: Address,
    /// Atomic-unit amount to borrow.
    #[serde_as(as = "DisplayFromStr")]
    pub amount: U256,
}

/// `metadata.replacedOrder`. UID of the order this one replaces;
/// solvers cancel the prior order when settling the replacement.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AppDataReplacedOrder {
    /// UID of the order being replaced.
    pub uid: OrderUid,
}

/// `metadata.wrappers[]` entry: wrapper-contract calls the solver
/// invokes as part of the settlement transaction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppDataWrapperCall {
    /// Wrapper-contract address invoked during settlement.
    pub address: Address,
    /// Wrapper calldata; serialises as `0x`-prefixed hex.
    pub data: Bytes,
    /// If `true`, solvers may settle without invoking the wrapper.
    #[serde(default)]
    pub is_omittable: bool,
}

/// `metadata.referrer`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppDataReferrer {
    /// Referrer address (analytics / rev-share recipient).
    pub address: Address,
    /// Optional referrer schema version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// `metadata.utm`: campaign attribution.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppDataUtm {
    /// UTM `source` parameter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utm_source: Option<String>,
    /// UTM `medium` parameter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utm_medium: Option<String>,
    /// UTM `campaign` parameter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utm_campaign: Option<String>,
    /// UTM `content` parameter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utm_content: Option<String>,
    /// UTM `term` parameter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utm_term: Option<String>,
}

/// Opaque hooks payload alias; the nested arrays are intentionally
/// not modelled.
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

    /// SDK-attribution document. Pins `appCode` to the given tag
    /// ([`COW_RS_APP_CODE`] or [`COW_RS_WASM_APP_CODE`]) and
    /// `metadata.quote.version` to `CARGO_PKG_VERSION`. Integrators
    /// with their own `appCode` should build [`AppDataDoc`] directly.
    pub fn sdk_attribution(app_code: &str) -> Self {
        Self {
            version: LATEST_APP_DATA_VERSION.to_string(),
            app_code: Some(app_code.to_string()),
            environment: None,
            metadata: AppDataMetadata {
                quote: Some(AppDataQuote {
                    slippage_bips: None,
                    version: Some(env!("CARGO_PKG_VERSION").to_string()),
                }),
                ..AppDataMetadata::default()
            },
        }
    }

    /// Attach a referrer address.
    pub fn with_referrer(mut self, address: Address) -> Self {
        self.metadata.referrer = Some(AppDataReferrer {
            address,
            version: None,
        });
        self
    }

    /// Attach a *volume* partner fee (`bps` of the swap value to
    /// `recipient`). Fails closed via [`AppDataError::FeeOutOfRange`]
    /// when `bps > PARTNER_FEE_BPS_MAX` (`10_000`), so an
    /// attacker-controlled value cannot be folded into the signed
    /// app-data digest unchecked.
    pub fn with_partner_fee(mut self, bps: u32, recipient: Address) -> Result<Self, AppDataError> {
        let policy = FeePolicy::Volume { bps: bps as u64 };
        validate_fee_policy(&policy)?;
        self.metadata.partner_fee = Some(AppDataPartnerFee { policy, recipient });
        Ok(self)
    }

    /// Attach a partner fee with an explicit [`FeePolicy`]. Fails
    /// closed via [`AppDataError::FeeOutOfRange`] on any over-cap
    /// `bps` / `maxVolumeBps`; see [`Self::with_partner_fee`].
    pub fn with_partner_fee_policy(
        mut self,
        policy: FeePolicy,
        recipient: Address,
    ) -> Result<Self, AppDataError> {
        validate_fee_policy(&policy)?;
        self.metadata.partner_fee = Some(AppDataPartnerFee { policy, recipient });
        Ok(self)
    }

    /// Attach a typed [`AppDataFlashloan`].
    pub const fn with_flashloan(mut self, flashloan: AppDataFlashloan) -> Self {
        self.metadata.flashloan = Some(flashloan);
        self
    }

    /// Mark this order as replacing an earlier one.
    pub const fn with_replaced_order(mut self, uid: OrderUid) -> Self {
        self.metadata.replaced_order = Some(AppDataReplacedOrder { uid });
        self
    }

    /// Append a wrapper-contract call.
    pub fn with_wrapper(mut self, wrapper: AppDataWrapperCall) -> Self {
        self.metadata.wrappers.push(wrapper);
        self
    }

    /// Tag the order with an order class.
    pub const fn with_order_class(mut self, order_class: OrderClass) -> Self {
        self.metadata.order_class = Some(AppDataOrderClass { order_class });
        self
    }

    /// Attach a slippage hint to the quote sub-document.
    pub fn with_slippage_bips(mut self, slippage_bips: u32) -> Self {
        self.metadata
            .quote
            .get_or_insert_with(AppDataQuote::default)
            .slippage_bips = Some(slippage_bips);
        self
    }

    /// Mark the environment (`"prod"`, `"staging"`, …).
    pub fn with_environment(mut self, environment: impl Into<String>) -> Self {
        self.environment = Some(environment.into());
        self
    }

    /// Serialise to deterministic JSON: lex-sorted keys, no
    /// whitespace, **raw UTF-8 for non-ASCII** (matching the
    /// orderbook's `keccak256(toUtf8Bytes(fullAppData))` and cow-sdk's
    /// TS implementation; cow-py's `ensure_ascii=True` default
    /// diverges on non-ASCII, the orderbook is the source of truth).
    ///
    /// Round-trips via `serde_json::Value`, whose `BTreeMap`-backed
    /// `Map` (without `preserve_order`) emits keys in sorted order
    /// independently of struct declaration order.
    pub fn canonical_json(&self) -> String {
        let value = serde_json::to_value(self).expect("AppDataDoc must serialise");
        let sorted = sort_value(value);
        serde_json::to_string(&sorted).expect("Value must re-serialise")
    }

    /// Parse a canonical JSON document, rejecting input larger than
    /// [`APP_DATA_SIZE_LIMIT`] before allocating any nested structure.
    pub fn try_from_str(json: &str) -> Result<Self, AppDataError> {
        if json.len() > APP_DATA_SIZE_LIMIT {
            return Err(AppDataError::DocumentTooLarge {
                len: json.len(),
                max: APP_DATA_SIZE_LIMIT,
            });
        }
        serde_json::from_str(json).map_err(|e| AppDataError::Parse(e.to_string()))
    }

    /// `keccak256(canonical_json())`. This is the digest written into the
    /// signed `Order.appData` field.
    ///
    /// Panics if the canonical JSON exceeds [`APP_DATA_SIZE_LIMIT`];
    /// use [`Self::try_hash`] with untrusted input.
    pub fn hash(&self) -> AppDataHash {
        self.try_hash()
            .expect("AppDataDoc must fit within APP_DATA_SIZE_LIMIT")
    }

    /// Fallible [`Self::hash`]; rejects documents above
    /// [`APP_DATA_SIZE_LIMIT`] before the orderbook would.
    pub fn try_hash(&self) -> Result<AppDataHash, AppDataError> {
        let json = self.canonical_json();
        if json.len() > APP_DATA_SIZE_LIMIT {
            return Err(AppDataError::DocumentTooLarge {
                len: json.len(),
                max: APP_DATA_SIZE_LIMIT,
            });
        }
        Ok(keccak256(json.as_bytes()))
    }
}

/// Errors raised while validating an [`AppDataDoc`] before signing.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum AppDataError {
    /// Canonical JSON exceeded [`APP_DATA_SIZE_LIMIT`].
    #[error("app-data document too large: {len} bytes (max {max})")]
    DocumentTooLarge {
        /// Observed canonical-JSON length, in bytes.
        len: usize,
        /// Configured limit (`APP_DATA_SIZE_LIMIT`).
        max: usize,
    },
    /// A partner-fee `bps` exceeded [`PARTNER_FEE_BPS_MAX`].
    #[error("partner fee {field} = {value} exceeds maximum {max}")]
    FeeOutOfRange {
        /// `bps`, `surplusBps`, `priceImprovementBps`, or `maxVolumeBps`.
        field: &'static str,
        /// Offending value.
        value: u64,
        /// Cap that was exceeded.
        max: u64,
    },
    /// JSON parse failure; captured as text to keep the enum `PartialEq`.
    #[error("invalid app-data JSON: {0}")]
    Parse(String),
}

/// Maximum partner-fee value, in basis points (`10_000 = 100 %`).
/// Mirrors the cap the settlement contract enforces on
/// `metadata.partnerFee.{bps,maxVolumeBps}`.
pub const PARTNER_FEE_BPS_MAX: u64 = 10_000;

/// Recursively rebuild a `serde_json::Value` with sorted object keys.
/// `Map` is a `BTreeMap` under the workspace's default (no
/// `preserve_order`); the explicit walk future-proofs against a flip.
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

/// IPFS CID the orderbook pins app-data under: `cidv1(raw=0x55,
/// multihash=keccak-256(hash))`. Aliased onto [`cid::Cid`] so `Display`
/// (base32 lower-case with the `b` multibase prefix), `FromStr` and
/// validation come from the upstream crate. Build one with
/// [`app_data_cid`] and recover the embedded digest with
/// [`app_data_hash_from_cid`].
pub type AppDataCid = cid::Cid;

/// Raw codec (`0x55`) used for the app-data CID payload.
const CID_CODEC_RAW: u64 = 0x55;
/// Keccak-256 multihash code (`0x1b`).
const MULTIHASH_KECCAK_256: u64 = 0x1b;

/// Build the IPFS CID the orderbook pins for an app-data digest. Pure
/// offline derivation: wraps `hash` in a keccak-256 multihash and folds
/// it into a CIDv1 with the raw codec. The resulting [`cid::Cid`]
/// displays as the canonical `b...` base32 string and round-trips
/// through `cid::Cid::from_str`.
pub fn app_data_cid(hash: AppDataHash) -> AppDataCid {
    let multihash = Multihash::<32>::wrap(MULTIHASH_KECCAK_256, hash.as_slice())
        .expect("digest fits a 32-byte multihash by construction");
    AppDataCid::new_v1(CID_CODEC_RAW, multihash.resize().expect("32 <= 64"))
}

/// Recover the embedded 32-byte digest from an [`AppDataCid`].
/// Validates the codec, multihash code, and digest length match
/// `cidv1(raw=0x55, multihash=keccak-256/32)` so a hostile string cannot
/// silently re-route the orderbook lookup to a different document.
pub fn app_data_hash_from_cid(cid: &AppDataCid) -> Result<AppDataHash, AppDataCidError> {
    if cid.codec() != CID_CODEC_RAW {
        return Err(AppDataCidError::UnexpectedCodec(cid.codec()));
    }
    let multihash = cid.hash();
    if multihash.code() != MULTIHASH_KECCAK_256 {
        return Err(AppDataCidError::UnexpectedMultihashCode(multihash.code()));
    }
    let digest = multihash.digest();
    if digest.len() != 32 {
        return Err(AppDataCidError::UnexpectedDigestLength(digest.len()));
    }
    Ok(AppDataHash::from_slice(digest))
}

/// Errors raised while parsing an [`AppDataCid`] back into an
/// [`AppDataHash`]. Wraps [`cid::Error`] for syntactic failures and
/// surfaces dedicated variants for codec / multihash / digest-length
/// drift, which the upstream parser would otherwise silently accept.
#[derive(Debug, thiserror::Error)]
pub enum AppDataCidError {
    /// The string could not be parsed as a CID at all (bad multibase
    /// prefix, invalid varint, truncated body, etc).
    #[error("invalid CID: {0}")]
    InvalidCid(#[from] cid::Error),
    /// The CID codec was not the raw codec (`0x55`).
    #[error("expected raw codec (0x55), got 0x{0:02x}")]
    UnexpectedCodec(u64),
    /// The multihash code was not keccak-256 (`0x1b`).
    #[error("expected keccak-256 multihash (0x1b), got 0x{0:02x}")]
    UnexpectedMultihashCode(u64),
    /// The multihash digest was not 32 bytes long.
    #[error("expected 32-byte digest, got {0}")]
    UnexpectedDigestLength(usize),
}

#[cfg(test)]
mod tests {
    use {super::*, alloy_primitives::address};

    #[test]
    fn json_round_trip_zero() {
        let zero = AppDataHash::default();
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
        let original = AppDataHash::from(bytes);
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

    /// Lock [`EMPTY_APP_DATA_HASH`] against `keccak256("{}")`: any drift
    /// would either break interop with cow-sdk fixtures or signal that the
    /// canonical empty document changed.
    #[test]
    fn empty_app_data_hash_matches_keccak() {
        let computed = alloy_primitives::keccak256(EMPTY_APP_DATA_JSON);
        assert_eq!(EMPTY_APP_DATA_HASH, computed);
    }

    /// SDK-attribution doc pins appCode + metadata.quote.version. The
    /// orderbook indexer reads these fields to count which integrators
    /// produced an order; a regression here means orders silently stop
    /// being attributable. Build the canonical JSON, then parse it
    /// back so we lock both the in-memory builder and the wire shape.
    #[test]
    fn sdk_attribution_doc_pins_app_code_and_version() {
        for app_code in [COW_RS_APP_CODE, COW_RS_WASM_APP_CODE] {
            let doc = AppDataDoc::sdk_attribution(app_code);
            assert_eq!(doc.app_code.as_deref(), Some(app_code));

            let json = doc.canonical_json();
            let value: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert_eq!(value["appCode"], app_code);
            assert_eq!(
                value["metadata"]["quote"]["version"],
                env!("CARGO_PKG_VERSION")
            );
            assert_eq!(value["version"], LATEST_APP_DATA_VERSION);

            // Hash is stable across calls for a given app_code (and
            // changes when the app_code does).
            assert_eq!(
                AppDataDoc::sdk_attribution(app_code).hash(),
                AppDataDoc::sdk_attribution(app_code).hash(),
            );
        }
        assert_ne!(
            AppDataDoc::sdk_attribution(COW_RS_APP_CODE).hash(),
            AppDataDoc::sdk_attribution(COW_RS_WASM_APP_CODE).hash(),
            "cow-rs and cow-rs-wasm must produce distinct app-data digests"
        );
    }

    #[test]
    fn empty_doc_matches_constant() {
        let doc = AppDataDoc::new("");
        // Every metadata field is `None` (or empty) by default.
        assert!(doc.metadata.quote.is_none());
        assert!(doc.metadata.order_class.is_none());
        assert!(doc.metadata.partner_fee.is_none());
        assert!(doc.metadata.referrer.is_none());
        assert!(doc.metadata.utm.is_none());
        assert!(doc.metadata.hooks.is_none());
        assert!(doc.metadata.flashloan.is_none());
        assert!(doc.metadata.replaced_order.is_none());
        assert!(doc.metadata.wrappers.is_empty());

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
        assert_eq!(hash, direct);

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
        let expected = b256!("3929e2c230dc41c0c053ff5f9211eb32def3a737b2bf36eb5b8862ea317fcd9e");
        assert_eq!(doc.hash(), expected);
    }

    /// `canonical_json` must emit non-ASCII characters as raw UTF-8
    /// bytes (matching the orderbook's
    /// `keccak256(toUtf8Bytes(fullAppData))` digest input), not as
    /// `\uXXXX` ASCII escapes. A regression that flips the escape mode
    /// would silently re-hash every document containing non-ASCII
    /// content (utm campaigns with emoji, non-Latin appCodes) and orders
    /// signed against the old digest would be rejected by the orderbook.
    #[test]
    fn canonical_json_preserves_utf8_non_ascii_bytes() {
        // Build a doc whose appCode contains a non-ASCII character.
        let doc = AppDataDoc::new("café-\u{1F40c}"); // "café-🐌"
        let json = doc.canonical_json();

        // Raw UTF-8: the `é` byte sequence (0xc3 0xa9) and the snail
        // emoji (4 bytes) must appear verbatim in the canonical JSON,
        // and NOT as `é` / `🐌` escapes.
        assert!(
            json.contains("café-\u{1F40c}"),
            "expected raw UTF-8 non-ASCII bytes in canonical JSON, got: {json}"
        );
        assert!(
            !json.contains("\\u00e9"),
            "expected raw UTF-8, found ASCII escape: {json}"
        );
        assert!(
            !json.contains("\\ud83d"),
            "expected raw UTF-8, found surrogate-pair escape: {json}"
        );

        // The digest is `keccak256(canonical_json.as_bytes())`. Lock
        // it against the bytes produced by the current path so any
        // serialiser flip (raw → escaped) trips this test.
        let direct = alloy_primitives::keccak256(json.as_bytes());
        assert_eq!(doc.hash(), direct);

        // Round-trip: parsing back through serde must reconstruct the
        // same appCode bytes.
        let parsed: AppDataDoc = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.app_code.as_deref(), Some("café-\u{1F40c}"));
    }

    #[test]
    fn canonical_json_sorts_keys_deterministically() {
        // Build a doc with several metadata fields and confirm the
        // emitted JSON is sorted at every level.
        let doc = AppDataDoc::new("app")
            .with_referrer(address!("0000000000000000000000000000000000000001"))
            .with_partner_fee(50, address!("0000000000000000000000000000000000000002"))
            .unwrap()
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
    fn partner_fee_volume_round_trips_with_legacy_bps_key() {
        let recipient = address!("00000000219AB540356CBb839CbE05303D7705FA");
        let doc = AppDataDoc::new("app")
            .with_partner_fee(75, recipient)
            .unwrap();
        let json = doc.canonical_json();
        // Volume serialises with the legacy `"bps"` key so existing
        // app-data hashes stay stable. The `recipient` is in the same
        // flat object, not nested under `policy`.
        assert!(
            json.to_lowercase()
                .contains(r#""partnerfee":{"bps":75,"recipient":"#),
            "got: {json}",
        );
        let parsed: AppDataDoc = serde_json::from_str(&json).unwrap();
        let fee = parsed.metadata.partner_fee.expect("partner fee preserved");
        assert!(matches!(fee.policy, FeePolicy::Volume { bps: 75 }));
        assert_eq!(fee.recipient, recipient);
    }

    /// Surplus policy emits `surplusBps` + `maxVolumeBps` flat alongside
    /// `recipient`. Locks the wire shape against the upstream
    /// `FeePolicy` deserializer.
    #[test]
    fn partner_fee_surplus_emits_typed_keys() {
        let recipient = address!("00000000219AB540356CBb839CbE05303D7705FA");
        let doc = AppDataDoc::new("app")
            .with_partner_fee_policy(
                FeePolicy::Surplus {
                    bps: 25,
                    max_volume_bps: 100,
                },
                recipient,
            )
            .unwrap();
        let json = doc.canonical_json();
        assert!(json.contains(r#""maxVolumeBps":100"#), "got: {json}");
        assert!(json.contains(r#""surplusBps":25"#), "got: {json}");

        let parsed: AppDataDoc = serde_json::from_str(&json).unwrap();
        let fee = parsed.metadata.partner_fee.expect("partner fee preserved");
        assert!(matches!(
            fee.policy,
            FeePolicy::Surplus {
                bps: 25,
                max_volume_bps: 100,
            }
        ));
    }

    /// PriceImprovement policy emits `priceImprovementBps` +
    /// `maxVolumeBps`.
    #[test]
    fn partner_fee_price_improvement_emits_typed_keys() {
        let recipient = address!("00000000219AB540356CBb839CbE05303D7705FA");
        let doc = AppDataDoc::new("app")
            .with_partner_fee_policy(
                FeePolicy::PriceImprovement {
                    bps: 30,
                    max_volume_bps: 150,
                },
                recipient,
            )
            .unwrap();
        let json = doc.canonical_json();
        assert!(json.contains(r#""priceImprovementBps":30"#), "got: {json}");
        assert!(json.contains(r#""maxVolumeBps":150"#), "got: {json}");

        let parsed: AppDataDoc = serde_json::from_str(&json).unwrap();
        let fee = parsed.metadata.partner_fee.expect("partner fee preserved");
        assert!(matches!(
            fee.policy,
            FeePolicy::PriceImprovement {
                bps: 30,
                max_volume_bps: 150,
            }
        ));
    }

    /// Volume can also be expressed as `volumeBps` on the wire, which
    /// the upstream deserializer accepts. We accept it too.
    #[test]
    fn partner_fee_deserialises_volume_bps_alias() {
        let recipient = address!("00000000219AB540356CBb839CbE05303D7705FA");
        let json = format!(r#"{{"volumeBps":42,"recipient":"{recipient:?}"}}"#,);
        let fee: AppDataPartnerFee = serde_json::from_str(&json).unwrap();
        assert!(matches!(fee.policy, FeePolicy::Volume { bps: 42 }));
        assert_eq!(fee.recipient, recipient);
    }

    /// The builder paths refuse to fold an over-cap `bps` into the
    /// document. Locks R10 closed: a previous `const fn` builder
    /// accepted `u32::MAX` without checking against
    /// `PARTNER_FEE_BPS_MAX`, so an attacker-controlled partner-fee
    /// tier could be committed to the signed app-data digest.
    #[test]
    fn partner_fee_builder_rejects_over_cap_bps() {
        let recipient = address!("00000000219AB540356CBb839CbE05303D7705FA");

        let err = AppDataDoc::new("app")
            .with_partner_fee(10_001, recipient)
            .unwrap_err();
        assert!(matches!(
            err,
            AppDataError::FeeOutOfRange {
                field: "bps",
                value: 10_001,
                max: PARTNER_FEE_BPS_MAX,
            }
        ));

        // `with_partner_fee_policy` walks every typed variant.
        let err = AppDataDoc::new("app")
            .with_partner_fee_policy(
                FeePolicy::Surplus {
                    bps: 1,
                    max_volume_bps: 10_001,
                },
                recipient,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            AppDataError::FeeOutOfRange {
                field: "maxVolumeBps",
                value: 10_001,
                ..
            }
        ));

        let err = AppDataDoc::new("app")
            .with_partner_fee_policy(
                FeePolicy::PriceImprovement {
                    bps: 10_001,
                    max_volume_bps: 1,
                },
                recipient,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            AppDataError::FeeOutOfRange {
                field: "priceImprovementBps",
                value: 10_001,
                ..
            }
        ));

        // At the cap is still accepted.
        let _ = AppDataDoc::new("app")
            .with_partner_fee(PARTNER_FEE_BPS_MAX as u32, recipient)
            .expect("bps at the cap must be accepted");
    }

    /// Ambiguous policy combinations are rejected outright.
    #[test]
    fn partner_fee_rejects_mixed_policy_fields() {
        let recipient = address!("00000000219AB540356CBb839CbE05303D7705FA");
        let json = format!(
            r#"{{"surplusBps":10,"priceImprovementBps":20,"maxVolumeBps":50,"recipient":"{recipient:?}"}}"#,
        );
        let err = serde_json::from_str::<AppDataPartnerFee>(&json).unwrap_err();
        assert!(err.to_string().contains("unknown partner-fee policy"));
    }

    /// Lock the wire shape and round-trip of `metadata.flashloan`.
    #[test]
    fn flashloan_round_trips() {
        let flashloan = AppDataFlashloan {
            liquidity_provider: address!("1111111111111111111111111111111111111111"),
            protocol_adapter: address!("2222222222222222222222222222222222222222"),
            receiver: address!("3333333333333333333333333333333333333333"),
            token: address!("4444444444444444444444444444444444444444"),
            amount: U256::from(1_000_000_u64),
        };
        let doc = AppDataDoc::new("app").with_flashloan(flashloan.clone());
        let json = doc.canonical_json();
        assert!(
            json.contains(r#""amount":"1000000""#),
            "amount must serialise as decimal string, got: {json}",
        );
        let parsed: AppDataDoc = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.metadata.flashloan.expect("flashloan preserved"),
            flashloan
        );
    }

    /// `metadata.replacedOrder.uid` round-trips through the wire form.
    #[test]
    fn replaced_order_round_trips() {
        let uid = OrderUid::from([0x55; 56]);
        let doc = AppDataDoc::new("app").with_replaced_order(uid);
        let json = doc.canonical_json();
        assert!(
            json.contains(r#""replacedOrder":{"uid":"0x"#),
            "got: {json}"
        );
        let parsed: AppDataDoc = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.metadata.replaced_order.expect("replaced order").uid,
            uid
        );
    }

    /// `metadata.wrappers[]` round-trips with hex-encoded call data, and
    /// is skipped from the canonical JSON when empty (preserving the
    /// digest of documents authored before this field existed).
    #[test]
    fn wrappers_round_trip_and_skip_when_empty() {
        // Empty wrappers must not appear in canonical JSON, otherwise
        // the document's hash drifts away from what older SDKs computed.
        let doc = AppDataDoc::new("app");
        assert!(!doc.canonical_json().contains("wrappers"));

        let wrapper = AppDataWrapperCall {
            address: address!("5555555555555555555555555555555555555555"),
            data: Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]),
            is_omittable: true,
        };
        let doc = doc.with_wrapper(wrapper.clone());
        let json = doc.canonical_json();
        assert!(json.contains(r#""data":"0xdeadbeef""#), "got: {json}");
        assert!(json.contains(r#""isOmittable":true"#), "got: {json}");
        let parsed: AppDataDoc = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.metadata.wrappers, vec![wrapper]);
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
    /// or in the `app_data_hash_from_cid` recovery shows up immediately.
    #[test]
    fn cid_round_trip_default_and_walking_bytes() {
        let default = AppDataHash::default();
        assert_eq!(
            app_data_hash_from_cid(&app_data_cid(default)).unwrap(),
            default
        );

        for i in 0..32 {
            let mut bytes = [0u8; 32];
            bytes[i] = 0xff;
            let hash = AppDataHash::from(bytes);
            let cid = app_data_cid(hash);
            let rendered = cid.to_string();
            assert_eq!(
                app_data_hash_from_cid(&cid).unwrap(),
                hash,
                "round-trip failed at byte {i}"
            );
            // Multibase tag is always `b`, body is always lower-case alpha
            // or `234567`, never any other character.
            assert!(rendered.starts_with('b'));
            assert!(
                rendered
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
        let cid = app_data_cid(EMPTY_APP_DATA_HASH).to_string();
        assert!(
            cid.starts_with("bafkrw"),
            "expected bafkrw prefix, got {cid}"
        );
    }

    /// Golden vector lifted from `cowprotocol/services`
    /// (`crates/app-data/src/app_data_hash.rs::tests::known_good`). The
    /// services repo additionally cites the equivalent `ipfs cid format
    /// -b base16` and `-b base32` strings, both of which we lock here.
    #[test]
    fn cid_matches_services_known_good_vector() {
        let hash = b256!("8af4e8c9973577b08ac21d17d331aade86c11ebcc5124744d621ca8365ec9424");
        let cid = app_data_cid(hash);
        assert_eq!(
            cid.to_string(),
            "bafkrwiek6tumtfzvo6yivqq5c7jtdkw6q3ar5pgfcjdujvrbzkbwl3eueq"
        );
        assert_eq!(app_data_hash_from_cid(&cid).unwrap(), hash);
    }

    /// Lock the canonical CID for the default-empty document
    /// (`keccak256("{}")`), independently computed via Python's `base32`
    /// over `01 55 1b 20 || EMPTY_APP_DATA_HASH`.
    #[test]
    fn cid_for_empty_doc_golden() {
        let cid = app_data_cid(EMPTY_APP_DATA_HASH);
        assert_eq!(
            cid.to_string(),
            "bafkrwifuru4pspvkbbadh7czoc7znzkzym6ezxah3ce2wafu2y7zledttu"
        );
    }

    #[test]
    fn cid_parse_rejects_missing_multibase_prefix() {
        // Drop the leading `b`. `cid::Cid::from_str` rejects via the
        // upstream multibase decoder (no prefix => parse failure).
        let err = "afkrwifuru4pspvkbbadh7czoc7znzkzym6ezxah3ce2wafu2y7zledttu"
            .parse::<AppDataCid>()
            .unwrap_err();
        assert!(matches!(err, cid::Error::ParsingError), "got: {err:?}");
    }

    /// Round-trip the same `services` golden vector through the `f`
    /// (base16) multibase prefix. cow-sdk's TypeScript
    /// `appDataHexToCid` emits this form by default; the orderbook
    /// accepts either prefix, so cow-rs must too.
    #[test]
    fn cid_parse_accepts_base16_multibase_prefix() {
        let hash = b256!("8af4e8c9973577b08ac21d17d331aade86c11ebcc5124744d621ca8365ec9424");
        let mut hex_body = String::with_capacity(72);
        hex_body.push_str("01551b20");
        hex_body.push_str(&const_hex::encode(hash));
        let cid = format!("f{hex_body}").parse::<AppDataCid>().unwrap();
        assert_eq!(app_data_hash_from_cid(&cid).unwrap(), hash);
    }

    #[test]
    fn cid_parse_rejects_invalid_base16_body() {
        let err = "f01551b20zzzz".parse::<AppDataCid>().unwrap_err();
        assert!(matches!(err, cid::Error::ParsingError), "got: {err:?}");
    }

    #[test]
    fn cid_parse_rejects_wrong_codec() {
        // dag-pb (0x70) codec instead of raw (0x55). Build via the cid
        // crate so the byte layout matches what a real CID parser sees.
        let multihash =
            Multihash::<32>::wrap(MULTIHASH_KECCAK_256, EMPTY_APP_DATA_HASH.as_slice()).unwrap();
        let cid = AppDataCid::new_v1(0x70, multihash.resize().unwrap());
        let err = app_data_hash_from_cid(&cid).unwrap_err();
        assert!(
            matches!(err, AppDataCidError::UnexpectedCodec(0x70)),
            "got: {err:?}"
        );
    }

    #[test]
    fn cid_parse_rejects_wrong_multihash() {
        // sha2-256 (0x12) instead of keccak-256 (0x1b): this is the
        // distinct "legacy" CID family that cow-sdk's `appDataHexToCidLegacy`
        // emits. We do not want to silently accept it as our CID since
        // its digest semantics are different.
        let multihash = Multihash::<32>::wrap(0x12, EMPTY_APP_DATA_HASH.as_slice()).unwrap();
        let cid = AppDataCid::new_v1(CID_CODEC_RAW, multihash.resize().unwrap());
        let err = app_data_hash_from_cid(&cid).unwrap_err();
        assert!(
            matches!(err, AppDataCidError::UnexpectedMultihashCode(0x12)),
            "got: {err:?}"
        );
    }

    #[test]
    fn cid_parse_rejects_truncated_body() {
        // Body too short to even contain a valid CID header. The cid
        // parser raises one of several syntactic errors depending on
        // exactly where the truncation lands; all are acceptable here.
        let err = "babcdefgh".parse::<AppDataCid>().unwrap_err();
        assert!(
            matches!(
                err,
                cid::Error::ParsingError
                    | cid::Error::VarIntDecodeError
                    | cid::Error::InputTooShort
                    | cid::Error::InvalidExplicitCidV0
                    | cid::Error::Io(_)
            ),
            "got: {err:?}"
        );
    }

    #[test]
    fn cid_parse_rejects_wrong_version() {
        // Version byte `0x00` is the CIDv0 marker. The cid crate rejects
        // it in CIDv1-shaped input via `InvalidExplicitCidV0`.
        let bytes = [
            0x00, 0x55, 0x1b, 0x20, 0xb4, 0x8d, 0x38, 0xf9, 0x3e, 0xaa, 0x08, 0x40, 0x33, 0xfc,
            0x59, 0x70, 0xbf, 0x96, 0xe5, 0x59, 0xc3, 0x3c, 0x4c, 0xdc, 0x07, 0xd8, 0x89, 0xab,
            0x00, 0xb4, 0xd6, 0x3f, 0x95, 0x90, 0x73, 0x9d,
        ];
        let encoded = cid::multibase::encode(cid::multibase::Base::Base32Lower, bytes);
        let err = encoded.parse::<AppDataCid>().unwrap_err();
        assert!(
            matches!(err, cid::Error::InvalidExplicitCidV0),
            "got: {err:?}"
        );
    }

    #[test]
    fn cid_parse_rejects_wrong_digest_length() {
        // Multihash length 16 (0x10) instead of 32 (0x20).
        let multihash =
            Multihash::<32>::wrap(MULTIHASH_KECCAK_256, &EMPTY_APP_DATA_HASH.as_slice()[..16])
                .unwrap();
        let cid = AppDataCid::new_v1(CID_CODEC_RAW, multihash.resize().unwrap());
        let err = app_data_hash_from_cid(&cid).unwrap_err();
        assert!(
            matches!(err, AppDataCidError::UnexpectedDigestLength(16)),
            "got: {err:?}"
        );
    }

    #[test]
    fn cid_parse_rejects_invalid_base32_char() {
        // `8` is outside RFC 4648's lower-case 32-char alphabet.
        let err = "b8".parse::<AppDataCid>().unwrap_err();
        assert!(
            matches!(err, cid::Error::ParsingError | cid::Error::InputTooShort),
            "got: {err:?}"
        );
    }
}
