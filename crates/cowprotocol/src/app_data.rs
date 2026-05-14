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

use alloy_primitives::{Address, U256, keccak256};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use serde_with::{DisplayFromStr, serde_as};
use std::fmt;

use crate::bytes_hex::BytesHex;
use crate::order::{OrderClass, OrderUid};

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
        f.write_str(&const_hex::encode_prefixed(self.0))
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

/// Canonical `appCode` for orders built through the native Rust SDK
/// (this crate, called directly from Rust). Mirrors the
/// `appCode: "CoW Swap"` convention the frontend uses and the
/// `appCode: "cow-py"` cow-py defaults to. Lets the orderbook indexer
/// count how many orders flow through the Rust SDK vs other clients.
/// Apply via [`AppDataDoc::sdk_attribution`].
pub const COW_RS_APP_CODE: &str = "cow-rs";

/// Canonical `appCode` for orders built through the wasm shim
/// (`cow-sdk-wasm` published to npm). Distinct from
/// [`COW_RS_APP_CODE`] so the orderbook indexer can tell native Rust
/// callers and JS-via-wasm callers apart.
pub const COW_RS_WASM_APP_CODE: &str = "cow-rs-wasm";

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
    /// Flashloan attached to this order. Mirrors the upstream
    /// `ProtocolAppData.flashloan` field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flashloan: Option<AppDataFlashloan>,
    /// UID of the order this one replaces. Solvers cancel the prior
    /// order when settling the replacement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaced_order: Option<AppDataReplacedOrder>,
    /// Wrapper-contract calls that wrap the order's settlement.
    ///
    /// Skipped when empty so a wrapper-free document still hashes to the
    /// same digest it did before this field was added.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wrappers: Vec<AppDataWrapperCall>,
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
/// Solvers route the configured cut of order surplus / volume to
/// `recipient` according to the policy carried in [`Self::policy`]. The
/// policy fields are *flattened* into the same JSON object as
/// `recipient`, matching the wire shape used by
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
/// [`PARTNER_FEE_BPS_MAX`]. Used by [`AppDataPartnerFee::deserialize`]
/// and the policy constructors so a hostile app-data document cannot
/// pin a `bps = u64::MAX` that the contract would silently clamp.
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
    /// Construct a partner-fee binding with bps validation. Use this
    /// instead of building [`AppDataPartnerFee`] by hand when the policy
    /// values come from caller input you do not fully trust.
    pub fn new(policy: FeePolicy, recipient: Address) -> Result<Self, AppDataError> {
        validate_fee_policy(&policy)?;
        Ok(Self { policy, recipient })
    }
}

/// Fee-policy variant used inside [`AppDataPartnerFee`].
///
/// The policy is *flattened* alongside `recipient` in the wire JSON,
/// matching the upstream `FeePolicy` deserializer in
/// `cowprotocol/services::app_data`. Mirroring it:
///
/// - [`FeePolicy::Surplus`] emits `surplusBps` + `maxVolumeBps`.
/// - [`FeePolicy::PriceImprovement`] emits `priceImprovementBps` +
///   `maxVolumeBps`.
/// - [`FeePolicy::Volume`] emits the legacy `bps` field (rather than
///   the equivalent `volumeBps`) so docs hashed with previous SDK
///   versions keep their digests stable.
///
/// Deserialisation accepts either `bps` or `volumeBps` for the volume
/// variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeePolicy {
    /// Volume fee: `bps` charged on the swap volume.
    Volume {
        /// Basis-point fee (`100 == 1 %`).
        bps: u64,
    },
    /// Surplus fee: `bps` of the captured surplus, capped at
    /// `max_volume_bps` of the swap volume.
    Surplus {
        /// Basis-point cut of the surplus.
        bps: u64,
        /// Maximum cut as a basis-point fraction of swap volume.
        max_volume_bps: u64,
    },
    /// Price-improvement fee: `bps` of the price improvement over the
    /// reference quote, capped at `max_volume_bps` of the swap volume.
    PriceImprovement {
        /// Basis-point cut of the price improvement.
        bps: u64,
        /// Maximum cut as a basis-point fraction of swap volume.
        max_volume_bps: u64,
    },
}

/// `metadata.flashloan` sub-document.
///
/// Describes a flashloan attached to the order: the protocol that lends
/// the funds, the adapter contract that bridges the loan to the
/// settlement, the receiver of the loan, the borrowed `token`, and the
/// `amount` in atomic units. Mirrors `ProtocolAppData::flashloan` in
/// `cowprotocol/services`.
#[serde_as]
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppDataFlashloan {
    /// Liquidity-providing protocol (e.g. Aave pool address).
    pub liquidity_provider: Address,
    /// Adapter that proxies the loan into the settlement.
    pub protocol_adapter: Address,
    /// Account that receives the borrowed funds for the duration of the
    /// settlement.
    pub receiver: Address,
    /// Token being borrowed.
    pub token: Address,
    /// Atomic-unit amount of `token` to borrow.
    #[serde_as(as = "DisplayFromStr")]
    pub amount: U256,
}

/// `metadata.replacedOrder` sub-document.
///
/// The UID of the order this one replaces. Solvers cancel the prior
/// order when settling the replacement. Mirrors
/// `ProtocolAppData::replaced_order`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AppDataReplacedOrder {
    /// UID of the order being replaced.
    pub uid: OrderUid,
}

/// `metadata.wrappers[]` entry.
///
/// Wrapper-contract calls that wrap the order's settlement; solvers
/// invoke them as part of the settlement transaction. Mirrors
/// `ProtocolAppData::wrappers[*]`.
#[serde_as]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppDataWrapperCall {
    /// Wrapper contract address.
    pub address: Address,
    /// Call data passed to the wrapper. Serialised as `0x`-prefixed hex.
    #[serde_as(as = "BytesHex")]
    pub data: Vec<u8>,
    /// If `true`, solvers may settle without invoking the wrapper when
    /// it is uneconomical to do so.
    #[serde(default)]
    pub is_omittable: bool,
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

    /// SDK-attribution document. Sets `appCode` to the supplied
    /// identifier (pass [`COW_RS_APP_CODE`] when building from native
    /// Rust, [`COW_RS_WASM_APP_CODE`] when building from the wasm
    /// shim) and `metadata.quote.version` to this crate's
    /// `CARGO_PKG_VERSION` so the orderbook indexer can identify
    /// orders that originated from this SDK and from which release.
    ///
    /// Integrators with their own `appCode` should construct an
    /// [`AppDataDoc`] directly instead.
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

    /// Builder: attach a referrer address.
    pub fn with_referrer(mut self, address: Address) -> Self {
        self.metadata.referrer = Some(AppDataReferrer {
            address,
            version: None,
        });
        self
    }

    /// Builder: attach a *volume* partner fee (`bps` of the swap value
    /// to `recipient`). Shortcut for [`AppDataDoc::with_partner_fee_policy`]
    /// with a [`FeePolicy::Volume`].
    pub const fn with_partner_fee(mut self, bps: u32, recipient: Address) -> Self {
        self.metadata.partner_fee = Some(AppDataPartnerFee {
            policy: FeePolicy::Volume { bps: bps as u64 },
            recipient,
        });
        self
    }

    /// Builder: attach a partner fee with an explicit [`FeePolicy`].
    pub const fn with_partner_fee_policy(mut self, policy: FeePolicy, recipient: Address) -> Self {
        self.metadata.partner_fee = Some(AppDataPartnerFee { policy, recipient });
        self
    }

    /// Builder: attach a typed [`AppDataFlashloan`].
    pub const fn with_flashloan(mut self, flashloan: AppDataFlashloan) -> Self {
        self.metadata.flashloan = Some(flashloan);
        self
    }

    /// Builder: mark this order as replacing an earlier one.
    pub const fn with_replaced_order(mut self, uid: OrderUid) -> Self {
        self.metadata.replaced_order = Some(AppDataReplacedOrder { uid });
        self
    }

    /// Builder: append a wrapper-contract call.
    pub fn with_wrapper(mut self, wrapper: AppDataWrapperCall) -> Self {
        self.metadata.wrappers.push(wrapper);
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
    /// The output has all object keys sorted lexicographically, no
    /// whitespace, and **raw UTF-8 bytes for any non-ASCII character**
    /// — this matches the orderbook's `keccak256(toUtf8Bytes(fullAppData))`
    /// digest input. cow-py's default `stringify_deterministic` produces
    /// the same bytes for any document whose values are pure ASCII (the
    /// overwhelmingly common case); a document with non-ASCII strings
    /// would diverge from cow-py's `ensure_ascii=True` default, but
    /// still agrees with the orderbook (and with cow-sdk's
    /// TypeScript implementation, which also keeps raw UTF-8).
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

    /// Parse a canonical JSON document, rejecting any input larger than
    /// [`APP_DATA_SIZE_LIMIT`]. Bounds the deserialiser before it
    /// allocates the parent struct or any opaque nested JSON (`hooks`,
    /// `flashloan`, `wrappers`), so a hostile orderbook cannot stream a
    /// multi-MiB document into the SDK.
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
    /// Panics if the canonical JSON exceeds [`APP_DATA_SIZE_LIMIT`]; use
    /// [`AppDataDoc::try_hash`] for the fallible variant when working with
    /// caller-supplied documents that may legitimately overflow.
    pub fn hash(&self) -> AppDataHash {
        self.try_hash()
            .expect("AppDataDoc must fit within APP_DATA_SIZE_LIMIT")
    }

    /// Like [`AppDataDoc::hash`], but rejects documents whose canonical
    /// JSON would exceed [`APP_DATA_SIZE_LIMIT`]. The orderbook enforces
    /// the same cap server-side and would otherwise reject the document
    /// after the user has already signed an order against the digest.
    pub fn try_hash(&self) -> Result<AppDataHash, AppDataError> {
        let json = self.canonical_json();
        if json.len() > APP_DATA_SIZE_LIMIT {
            return Err(AppDataError::DocumentTooLarge {
                len: json.len(),
                max: APP_DATA_SIZE_LIMIT,
            });
        }
        Ok(AppDataHash(keccak256(json.as_bytes()).0))
    }
}

/// Errors raised while validating an [`AppDataDoc`] before signing.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum AppDataError {
    /// Canonical JSON exceeded [`APP_DATA_SIZE_LIMIT`] (8 KiB). The
    /// orderbook enforces the same cap server-side, so this would
    /// otherwise reject post-sign.
    #[error("app-data document too large: {len} bytes (max {max})")]
    DocumentTooLarge {
        /// Length of the offending canonical JSON, in bytes.
        len: usize,
        /// Maximum accepted length: [`APP_DATA_SIZE_LIMIT`].
        max: usize,
    },
    /// A partner-fee `bps` field exceeded `10_000` (100%). The CoW
    /// settlement contract caps partner fees at one hundred percent, so
    /// over-cap values would either be silently clamped or rejected
    /// post-settle.
    #[error("partner fee {field} = {value} exceeds maximum {max}")]
    FeeOutOfRange {
        /// Which bps field overflowed (`bps`, `surplusBps`,
        /// `priceImprovementBps`, or `maxVolumeBps`).
        field: &'static str,
        /// Value supplied by the caller / wire.
        value: u64,
        /// Maximum accepted value (`10_000`).
        max: u64,
    },
    /// JSON parse failure. The underlying `serde_json` error is captured
    /// as text so this enum stays `PartialEq` for tests.
    #[error("invalid app-data JSON: {0}")]
    Parse(String),
}

/// Maximum partner-fee value, in basis points. `10_000 = 100 %`. Mirrors
/// the cap the CoW settlement contract enforces on the `bps` and
/// `maxVolumeBps` fields of `metadata.partnerFee`.
pub const PARTNER_FEE_BPS_MAX: u64 = 10_000;

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
/// Upper bound on the multibase-encoded CID string. Real CIDs are at most
/// 73 chars (`f` + 72 base16 nibbles); 96 leaves slack for trailing
/// whitespace or unusual padding without permitting attacker-driven
/// gigabyte allocations in [`AppDataCid::to_hash`].
const CID_STRING_MAX_LEN: usize = 96;

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
        if self.0.len() > CID_STRING_MAX_LEN {
            return Err(AppDataCidError::CidTooLong {
                len: self.0.len(),
                max: CID_STRING_MAX_LEN,
            });
        }
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
    /// The CID string was longer than `CID_STRING_MAX_LEN`. Real CIDs
    /// are at most 73 chars; longer inputs are rejected before any
    /// attacker-driven allocation runs.
    #[error("cid string too long: {len} chars (max {max})")]
    CidTooLong {
        /// Length of the offending CID string.
        len: usize,
        /// Maximum accepted length.
        max: usize,
    },
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
        assert_eq!(doc.hash().0, *direct);

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
        let doc = AppDataDoc::new("app").with_partner_fee(75, recipient);
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
        let doc = AppDataDoc::new("app").with_partner_fee_policy(
            FeePolicy::Surplus {
                bps: 25,
                max_volume_bps: 100,
            },
            recipient,
        );
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
        let doc = AppDataDoc::new("app").with_partner_fee_policy(
            FeePolicy::PriceImprovement {
                bps: 30,
                max_volume_bps: 150,
            },
            recipient,
        );
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
        let uid = OrderUid([0x55; 56]);
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
            data: vec![0xde, 0xad, 0xbe, 0xef],
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
