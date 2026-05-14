//! The signed order payload (`OrderData`) and supporting types.
//!
//! `OrderData` is the exact struct that is hashed and signed by the order
//! owner and verified by the GPv2Settlement contract. The other types in
//! this module ([`OrderKind`], [`SellTokenSource`], [`BuyTokenDestination`]
//! and [`OrderUid`]) exist to make the payload typeable and the resulting
//! identifier addressable.
//!
//! Adapted from [`cowprotocol/services`] (MIT OR Apache-2.0).
//!
//! [`cowprotocol/services`]: https://github.com/cowprotocol/services/blob/main/crates/model/src/order.rs

use alloy_primitives::{Address, B256, U256, keccak256};
use hex_literal::hex;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use serde_with::{DisplayFromStr, serde_as};
use std::fmt::{self, Debug, Display};
use std::str::FromStr;

use crate::app_data::AppDataHash;
use crate::domain::{DomainSeparator, hashed_eip712_message};

/// Sentinel address used in place of a buy token to indicate that the order
/// pays out in the chain's native currency (e.g. ETH on mainnet, xDAI on
/// Gnosis Chain).
pub const BUY_ETH_ADDRESS: Address = Address::repeat_byte(0xee);

/// Server-side lifecycle status returned by
/// `GET /api/v1/orders/{uid}`.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum OrderStatus {
    /// On-chain pre-signature has not yet been observed.
    PresignaturePending,
    /// Order is live and may be matched.
    #[default]
    Open,
    /// Order is fully filled.
    Fulfilled,
    /// Order was cancelled (off-chain delete or on-chain pre-sign reversal).
    Cancelled,
    /// `validTo` passed before the order could be filled.
    Expired,
}

/// Server-side classification of an order, returned alongside the lifecycle
/// status. Determines fee handling and solver routing.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OrderClass {
    /// Standard market order, settled quickly.
    #[default]
    Market,
    /// Solver-internal liquidity order: placed by whitelisted participants.
    Liquidity,
    /// Limit order: fee taken from surplus once the price target is met.
    Limit,
}

/// The exact 12 fields signed by the order owner and verified by the
/// settlement contract.
///
/// See [`GPv2Order.Data`] for the Solidity counterpart.
///
/// [`GPv2Order.Data`]: https://github.com/cowprotocol/contracts/blob/v1.1.2/src/contracts/libraries/GPv2Order.sol
#[serde_as]
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderData {
    /// Token the owner is selling.
    pub sell_token: Address,
    /// Token the owner is buying.
    pub buy_token: Address,
    /// Optional recipient of the buy token; the owner receives it when `None`.
    #[serde(default)]
    pub receiver: Option<Address>,
    /// Amount of `sell_token` the owner is willing to part with, in atomic units.
    #[serde_as(as = "DisplayFromStr")]
    pub sell_amount: U256,
    /// Amount of `buy_token` the owner expects to receive, in atomic units.
    #[serde_as(as = "DisplayFromStr")]
    pub buy_amount: U256,
    /// Unix timestamp (seconds) after which the order is no longer valid.
    pub valid_to: u32,
    /// 32-byte digest of the app-data document.
    pub app_data: AppDataHash,
    /// Protocol fee charged in `sell_token` atomic units. Zero for limit
    /// orders (their fee is taken from surplus) and for liquidity orders.
    #[serde_as(as = "DisplayFromStr")]
    pub fee_amount: U256,
    /// Whether the owner is fixing the sell amount or the buy amount.
    pub kind: OrderKind,
    /// Whether partial fills are allowed.
    pub partially_fillable: bool,
    /// Source from which the sell token is drawn.
    #[serde(default)]
    pub sell_token_balance: SellTokenSource,
    /// Destination to which the buy token is paid out.
    #[serde(default)]
    pub buy_token_balance: BuyTokenDestination,
}

impl OrderData {
    /// EIP-712 `typeHash` of the canonical `Order` struct.
    ///
    /// `keccak256(`
    /// `"Order(address sellToken,address buyToken,address receiver,uint256 sellAmount,"`
    /// `"uint256 buyAmount,uint32 validTo,bytes32 appData,uint256 feeAmount,"`
    /// `"string kind,bool partiallyFillable,string sellTokenBalance,string buyTokenBalance)"`
    /// `)`
    ///
    /// Note that `kind`, `sellTokenBalance` and `buyTokenBalance` are declared
    /// as `string` in the EIP-712 schema, even though `GPv2Order.Data` stores
    /// them as `bytes32` markers: see
    /// [`GPv2Order.sol`](https://github.com/cowprotocol/contracts/blob/main/src/contracts/libraries/GPv2Order.sol).
    pub const TYPE_HASH: [u8; 32] =
        hex!("d5a25ba2e97094ad7d83dc28a6572da797d6b3e7fc6663bd93efb789fc17e489");

    /// EIP-712 `hashStruct` over the order, per
    /// <https://eips.ethereum.org/EIPS/eip-712#definition-of-hashstruct>.
    ///
    /// The output is the 32-byte input expected by
    /// [`hashed_eip712_message`].
    pub fn hash_struct(&self) -> [u8; 32] {
        let mut hash_data = [0u8; 416];
        hash_data[0..32].copy_from_slice(&Self::TYPE_HASH);
        // Most slots are left zero so the address / uint32 fields are left-padded
        // to 32 bytes.
        hash_data[44..64].copy_from_slice(self.sell_token.as_slice());
        hash_data[76..96].copy_from_slice(self.buy_token.as_slice());
        hash_data[108..128].copy_from_slice(self.receiver.unwrap_or(Address::ZERO).as_slice());
        hash_data[128..160].copy_from_slice(&self.sell_amount.to_be_bytes::<32>());
        hash_data[160..192].copy_from_slice(&self.buy_amount.to_be_bytes::<32>());
        hash_data[220..224].copy_from_slice(&self.valid_to.to_be_bytes());
        hash_data[224..256].copy_from_slice(&self.app_data.0);
        hash_data[256..288].copy_from_slice(&self.fee_amount.to_be_bytes::<32>());
        hash_data[288..320].copy_from_slice(match self.kind {
            OrderKind::Sell => &OrderKind::SELL,
            OrderKind::Buy => &OrderKind::BUY,
        });
        hash_data[351] = self.partially_fillable as u8;
        hash_data[352..384].copy_from_slice(&self.sell_token_balance.as_bytes());
        hash_data[384..416].copy_from_slice(&self.buy_token_balance.as_bytes());
        *keccak256(hash_data)
    }

    /// Compute the 56-byte order UID for this order on a given chain and
    /// for a given owner.
    pub fn uid(&self, domain: &DomainSeparator, owner: Address) -> OrderUid {
        OrderUid::from_parts(
            hashed_eip712_message(domain, &self.hash_struct()),
            owner,
            self.valid_to,
        )
    }

    /// Sign this order with an ECDSA signer. Equivalent to calling
    /// [`crate::signature::EcdsaSignature::sign`] over
    /// [`OrderData::hash_struct`] and promoting the result into a
    /// [`crate::signature::Signature`].
    pub fn sign<S: alloy_signer::SignerSync>(
        &self,
        scheme: crate::signing_scheme::EcdsaSigningScheme,
        domain: &DomainSeparator,
        signer: &S,
    ) -> Result<crate::signature::Signature, crate::signature::SignatureError> {
        let ecdsa =
            crate::signature::EcdsaSignature::sign(scheme, domain, &self.hash_struct(), signer)?;
        Ok(ecdsa.to_signature(scheme))
    }
}

/// Fluent builder for [`OrderData`].
///
/// Mirrors the shape of `OrderBuilder` in `cowprotocol/services` and
/// `@cowprotocol/cow-sdk`. Every field has a sensible default
/// ([`OrderData::default`]); the constructor takes the two mandatory
/// fields (`sell_token`, `buy_token`) and the rest are set fluently.
///
/// ```
/// use cowprotocol::{OrderBuilder, OrderKind};
/// use alloy_primitives::{U256, address};
///
/// let order = OrderBuilder::new(
///     address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
///     address!("6B175474E89094C44Da98b954EedeAC495271d0F"),
/// )
/// .sell_amount(U256::from(1_000_000_u64))
/// .buy_amount(U256::from(999_000_u64))
/// .valid_to(1_700_000_000)
/// .kind(OrderKind::Sell)
/// .build();
/// assert_eq!(order.sell_amount, U256::from(1_000_000_u64));
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct OrderBuilder(OrderData);

impl OrderBuilder {
    /// Start a builder anchored to the two mandatory fields.
    pub fn new(sell_token: Address, buy_token: Address) -> Self {
        Self(OrderData {
            sell_token,
            buy_token,
            ..OrderData::default()
        })
    }

    /// Start from an existing [`OrderData`].
    pub const fn from_order_data(data: OrderData) -> Self {
        Self(data)
    }

    /// Set the order recipient. `None` defaults the receiver to the owner.
    pub const fn receiver(mut self, receiver: Option<Address>) -> Self {
        self.0.receiver = receiver;
        self
    }

    /// Set the sell amount in atomic units.
    pub const fn sell_amount(mut self, amount: U256) -> Self {
        self.0.sell_amount = amount;
        self
    }

    /// Set the buy amount in atomic units.
    pub const fn buy_amount(mut self, amount: U256) -> Self {
        self.0.buy_amount = amount;
        self
    }

    /// Set the Unix-seconds expiry timestamp.
    pub const fn valid_to(mut self, valid_to: u32) -> Self {
        self.0.valid_to = valid_to;
        self
    }

    /// Set the 32-byte app-data digest.
    pub const fn app_data(mut self, hash: AppDataHash) -> Self {
        self.0.app_data = hash;
        self
    }

    /// Set the user-signed fee amount. At submission this must be `0`;
    /// [`crate::OrderQuoteResponse::to_signed_order_data`] handles that
    /// for callers who project from a quote.
    pub const fn fee_amount(mut self, amount: U256) -> Self {
        self.0.fee_amount = amount;
        self
    }

    /// Set the order direction (buy or sell).
    pub const fn kind(mut self, kind: OrderKind) -> Self {
        self.0.kind = kind;
        self
    }

    /// Whether the order may be filled in parts (default: `false`).
    pub const fn partially_fillable(mut self, partially_fillable: bool) -> Self {
        self.0.partially_fillable = partially_fillable;
        self
    }

    /// Source from which the sell token is drawn.
    pub const fn sell_token_balance(mut self, balance: SellTokenSource) -> Self {
        self.0.sell_token_balance = balance;
        self
    }

    /// Destination to which the buy token is paid.
    pub const fn buy_token_balance(mut self, balance: BuyTokenDestination) -> Self {
        self.0.buy_token_balance = balance;
        self
    }

    /// Finalise the builder.
    pub const fn build(self) -> OrderData {
        self.0
    }

    /// Convenience: [`OrderData::sign`] on the built payload.
    pub fn sign<S: alloy_signer::SignerSync>(
        self,
        scheme: crate::signing_scheme::EcdsaSigningScheme,
        domain: &DomainSeparator,
        signer: &S,
    ) -> Result<crate::signature::Signature, crate::signature::SignatureError> {
        self.0.sign(scheme, domain, signer)
    }
}

/// Full order representation returned by `GET /api/v1/orders/{uid}`.
///
/// Carries the 12 signed-payload fields of [`OrderData`] (via `#[serde(flatten)]`)
/// plus server-derived metadata: identity, signature, lifecycle status,
/// execution counters. Less-common contextual sub-objects (`quote`,
/// `interactions`, `ethflowData`, `onchainOrderData`) are preserved as
/// opaque [`serde_json::Value`]s in this first iteration so the type stays
/// forward-compatible with orderbook schema additions.
#[serde_as]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Order {
    /// The 12 fields that were signed.
    #[serde(flatten)]
    pub data: OrderData,
    /// 56-byte order UID assigned by the orderbook at submission.
    pub uid: OrderUid,
    /// Recovered (or declared) signer.
    pub owner: alloy_primitives::Address,
    /// Off-chain signing scheme used to authenticate the order.
    pub signing_scheme: crate::signing_scheme::SigningScheme,
    /// Raw signature bytes, hex-encoded.
    pub signature: String,
    /// ISO-8601 timestamp at which the orderbook accepted the order.
    pub creation_date: String,
    /// Lifecycle status.
    pub status: OrderStatus,
    /// Solver-routing classification.
    pub class: OrderClass,
    /// Cumulative buy-token amount filled so far.
    #[serde_as(as = "DisplayFromStr")]
    pub executed_buy_amount: alloy_primitives::U256,
    /// Cumulative sell-token amount filled so far.
    #[serde_as(as = "DisplayFromStr")]
    pub executed_sell_amount: alloy_primitives::U256,
    /// Cumulative fee charged in `executed_fee_token` atomic units.
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[serde(default)]
    pub executed_fee: Option<alloy_primitives::U256>,
    /// Token the executed fee was charged in.
    #[serde(default)]
    pub executed_fee_token: Option<alloy_primitives::Address>,
    /// Whether the order has been invalidated (e.g. cancelled).
    #[serde(default)]
    pub invalidated: bool,
    /// Whether the order was placed by a whitelisted liquidity provider.
    #[serde(default)]
    pub is_liquidity_order: bool,
    /// Canonical JSON of the app-data document, when the orderbook has seen it.
    #[serde(default)]
    pub full_app_data: Option<String>,
    /// Quote that produced the order, when one was supplied at submission.
    #[serde(default)]
    pub quote: Option<serde_json::Value>,
    /// Pre/post settlement interactions attached via app-data hooks.
    #[serde(default)]
    pub interactions: Option<serde_json::Value>,
    /// EthFlow-specific metadata for native-sell orders.
    #[serde(default)]
    pub ethflow_data: Option<serde_json::Value>,
    /// On-chain placement metadata for orders posted via `EthFlow`.
    #[serde(default)]
    pub onchain_order_data: Option<serde_json::Value>,
    /// On-chain user that placed the order (distinct from `owner` for
    /// proxy/relayer flows).
    #[serde(default)]
    pub onchain_user: Option<alloy_primitives::Address>,
    /// Settlement contract this order is bound to.
    #[serde(default)]
    pub settlement_contract: Option<alloy_primitives::Address>,
}

/// Direction of an order: whether the owner is fixing the buy side or the
/// sell side.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OrderKind {
    /// The owner is fixing the amount of `buy_token` they receive.
    #[default]
    Buy,
    /// The owner is fixing the amount of `sell_token` they part with.
    Sell,
}

impl OrderKind {
    /// `keccak256("buy")`: the EIP-712 string encoding of [`OrderKind::Buy`]
    /// and the on-chain `bytes32` marker stored in `GPv2Order.Data.kind`.
    pub const BUY: [u8; 32] =
        hex!("6ed88e868af0a1983e3886d5f3e95a2fafbd6c3450bc229e27342283dc429ccc");
    /// `keccak256("sell")`: the EIP-712 string encoding of [`OrderKind::Sell`]
    /// and the on-chain `bytes32` marker stored in `GPv2Order.Data.kind`.
    pub const SELL: [u8; 32] =
        hex!("f3b277728b3fee749481eb3e0b3b48980dbbab78658fc419025cb16eee346775");

    /// Lower-case wire form (`"buy"` / `"sell"`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Buy => "buy",
            Self::Sell => "sell",
        }
    }
}

impl Display for OrderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Source from which `sellAmount` is transferred into the settlement
/// contract on fulfilment.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SellTokenSource {
    /// Drawn from the owner's regular ERC-20 allowance to the Vault relayer.
    #[default]
    Erc20,
    /// Drawn from the owner's ERC-20 balance via Balancer external balances.
    External,
    /// Drawn from the owner's Balancer Vault internal balances.
    Internal,
}

impl SellTokenSource {
    /// `keccak256("erc20")`: EIP-712 string encoding and on-chain marker.
    pub const ERC20: [u8; 32] =
        hex!("5a28e9363bb942b639270062aa6bb295f434bcdfc42c97267bf003f272060dc9");
    /// `keccak256("external")`: EIP-712 string encoding and on-chain marker.
    pub const EXTERNAL: [u8; 32] =
        hex!("abee3b73373acd583a130924aad6dc38cfdc44ba0555ba94ce2ff63980ea0632");
    /// `keccak256("internal")`: EIP-712 string encoding and on-chain marker.
    pub const INTERNAL: [u8; 32] =
        hex!("4ac99ace14ee0a5ef932dc609df0943ab7ac16b7583634612f8dc35a4289a6ce");

    /// 32-byte EIP-712 encoding of this variant for inclusion in `hash_struct`.
    pub const fn as_bytes(&self) -> [u8; 32] {
        match self {
            Self::Erc20 => Self::ERC20,
            Self::External => Self::EXTERNAL,
            Self::Internal => Self::INTERNAL,
        }
    }
}

/// Destination to which `buyAmount` is paid out to the receiver on fulfilment.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BuyTokenDestination {
    /// Paid out as a regular ERC-20 transfer.
    #[default]
    Erc20,
    /// Paid out as a Balancer Vault internal balance transfer.
    Internal,
}

impl BuyTokenDestination {
    /// `keccak256("erc20")`: EIP-712 string encoding and on-chain marker.
    pub const ERC20: [u8; 32] =
        hex!("5a28e9363bb942b639270062aa6bb295f434bcdfc42c97267bf003f272060dc9");
    /// `keccak256("internal")`: EIP-712 string encoding and on-chain marker.
    pub const INTERNAL: [u8; 32] =
        hex!("4ac99ace14ee0a5ef932dc609df0943ab7ac16b7583634612f8dc35a4289a6ce");

    /// 32-byte EIP-712 encoding of this variant for inclusion in `hash_struct`.
    pub const fn as_bytes(&self) -> [u8; 32] {
        match self {
            Self::Erc20 => Self::ERC20,
            Self::Internal => Self::INTERNAL,
        }
    }
}

/// 56-byte order identifier: `32-byte digest || 20-byte owner || 4-byte validTo`.
///
/// The digest is `keccak256(0x19 0x01 || domain_separator || order_struct_hash)`.
#[derive(Clone, Copy, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct OrderUid(pub [u8; 56]);

impl OrderUid {
    /// Assemble a UID from its three parts.
    pub fn from_parts(hash: B256, owner: Address, valid_to: u32) -> Self {
        let mut uid = [0; 56];
        uid[0..32].copy_from_slice(hash.as_slice());
        uid[32..52].copy_from_slice(owner.as_slice());
        uid[52..56].copy_from_slice(&valid_to.to_be_bytes());
        Self(uid)
    }

    /// Build a UID with the first four bytes of the digest set to `i`
    /// (big-endian) and every other byte zero.
    ///
    /// Test-only ergonomics: lets callers fabricate distinct order UIDs
    /// without going through a full `hash_struct` /
    /// `hashed_eip712_message` pipeline. Mirrors
    /// `cowprotocol/services::OrderUid::from_integer`.
    pub const fn from_integer(i: u32) -> Self {
        let mut uid = [0u8; 56];
        let bytes = i.to_be_bytes();
        uid[0] = bytes[0];
        uid[1] = bytes[1];
        uid[2] = bytes[2];
        uid[3] = bytes[3];
        Self(uid)
    }

    /// Split a UID into its three parts.
    pub fn parts(&self) -> (B256, Address, u32) {
        (
            B256::from_slice(&self.0[0..32]),
            Address::from_slice(&self.0[32..52]),
            u32::from_be_bytes(self.0[52..].try_into().unwrap()),
        )
    }
}

impl Default for OrderUid {
    fn default() -> Self {
        Self([0u8; 56])
    }
}

impl Display for OrderUid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&const_hex::encode_prefixed(self.0))
    }
}

impl Debug for OrderUid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl FromStr for OrderUid {
    type Err = const_hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let mut value = [0u8; 56];
        const_hex::decode_to_slice(s, value.as_mut())?;
        Ok(Self(value))
    }
}

impl Serialize for OrderUid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for OrderUid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;
        impl de::Visitor<'_> for Visitor {
            type Value = OrderUid;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a 56-byte order UID as a 0x-prefixed hex string")
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                OrderUid::from_str(s).map_err(de::Error::custom)
            }
        }
        deserializer.deserialize_str(Visitor)
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::address;
    use hex_literal::hex;

    use super::*;

    use crate::contracts::GPV2_SETTLEMENT as SETTLEMENT;

    /// Build the canonical sample order shared with the cross-chain golden
    /// vectors generated by `tools/vector-gen`.
    fn sample_order() -> OrderData {
        OrderData {
            sell_token: Address::from(hex!("0101010101010101010101010101010101010101")),
            buy_token: Address::from(hex!("0202020202020202020202020202020202020202")),
            receiver: Some(Address::from(hex!(
                "0303030303030303030303030303030303030303"
            ))),
            sell_amount: U256::from(0x0246ddf97976680000_u128),
            buy_amount: U256::from(0xb98bc829a6f90000_u128),
            valid_to: 0xffffffff,
            app_data: AppDataHash([0u8; 32]),
            fee_amount: U256::from(0x0de0b6b3a7640000_u128),
            kind: OrderKind::Sell,
            partially_fillable: false,
            sell_token_balance: SellTokenSource::Erc20,
            buy_token_balance: BuyTokenDestination::Erc20,
        }
    }

    /// Sample-order owner, also shared with `tools/vector-gen`.
    fn sample_owner() -> Address {
        address!("70997970C51812dc3A010C7d01b50e0d17dc79C8")
    }

    /// Locks the full `OrderData::uid` output for the sample order against
    /// the byte-perfect golden vector lifted from
    /// `cowprotocol/services/crates/model/src/order.rs::compute_order_uid`.
    /// The domain here is the synthetic value baked into the services test,
    /// not a real chain, so a drift in `TYPE_HASH`, `hash_struct`,
    /// `DomainSeparator` packing, `hashed_eip712_message` or
    /// `OrderUid::from_parts` fails this test.
    #[test]
    fn compute_order_uid_matches_services_golden() {
        let domain = DomainSeparator(hex!(
            "74e0b11bd18120612556bae4578cfd3a254d7e2495f543c569a92ff5794d9b09"
        ));
        let expected = hex!(
            "0e45d31fd31b28c26031cdd81b35a8938b2ccca2cc425fcf440fd3bfed1eede9\
             70997970c51812dc3a010c7d01b50e0d17dc79c8\
             ffffffff"
        );
        assert_eq!(sample_order().uid(&domain, sample_owner()).0, expected);
    }

    /// Locks `hash_struct` against the value produced by ethers
    /// `TypedDataEncoder.hashStruct("Order", types, sample_order)`.
    /// The value is identical across chains because the EIP-712 struct hash
    /// does not depend on the domain. Regenerate via `tools/vector-gen`.
    #[test]
    fn sample_order_struct_hash_matches_ethers() {
        assert_eq!(
            sample_order().hash_struct(),
            hex!("7d9bf070168f9950003bdad00194ef63a5389dd0b594a1288407d551abf147d5")
        );
    }

    /// Locks `DomainSeparator::new` against ethers
    /// `TypedDataEncoder.hashDomain` for every one of the eleven chains
    /// cow-rs supports, using the canonical GPv2Settlement deployment.
    /// Regenerate via `tools/vector-gen`.
    #[test]
    fn cross_chain_domain_separators_match_ethers() {
        let cases: [(u64, [u8; 32]); 11] = [
            (
                1,
                hex!("c078f884a2676e1345748b1feace7b0abee5d00ecadb6e574dcdd109a63e8943"),
            ),
            (
                56,
                hex!("0cbb18dfca28d2ceac8c72a17289168e03c1ad121338f5573e3b0c3255207fc7"),
            ),
            (
                100,
                hex!("8f05589c4b810bc2f706854508d66d447cd971f8354a4bb0b3471ceb0a466bc7"),
            ),
            (
                137,
                hex!("132e0e39721b0cb53216fc42764f69c300d4d21e0caf24e0713b1e3e11120dc2"),
            ),
            (
                8453,
                hex!("d72ffa789b6fae41254d0b5a13e6e1e92ed947ec6a251edf1cf0b6c02c257b4b"),
            ),
            (
                9745,
                hex!("e1f9c97768e45812440cd3317c07069178cc2f69971fb204c0211d8bfb1f8e76"),
            ),
            (
                42161,
                hex!("69d78e7a7cafcaf924483f99f65e8f4e303a99a446db7ab319f9d40e940bced2"),
            ),
            (
                43114,
                hex!("81fd4ff99b8f80b96c946c146cd5b79181aaf08ecb5808eeee1d047c1de267a5"),
            ),
            (
                57073,
                hex!("5aced6090755c424bc1d6bbd39a2cdf57e6abfb4663598f4c3c821fb942d52e0"),
            ),
            (
                59144,
                hex!("b219bb2b8733b80b7ebef0229e7f0c91436f9a0a5b9705fa519237ae0493addb"),
            ),
            (
                11_155_111,
                hex!("daee378bd0eb30ddf479272accf91761e697bc00e067a268f95f1d2732ed230b"),
            ),
        ];

        for (chain_id, expected) in cases {
            let separator = DomainSeparator::new(chain_id, SETTLEMENT);
            assert_eq!(
                separator.0, expected,
                "domain separator for chain {chain_id}"
            );
        }
    }

    /// Locks the full UID pipeline against ethers
    /// `TypedDataEncoder.hash(domain, types, sample_order)` packed with the
    /// sample owner and `validTo`, for every chain cow-rs supports.
    /// Regenerate via `tools/vector-gen`.
    #[test]
    fn cross_chain_uids_match_ethers() {
        const TAIL: [u8; 24] = hex!("70997970c51812dc3a010c7d01b50e0d17dc79c8ffffffff");
        let cases: [(u64, [u8; 32]); 11] = [
            (
                1,
                hex!("8295b35c74972663a29a02be0fa8de8a157215b36938caa461fdf183e02cd82e"),
            ),
            (
                56,
                hex!("f676f63e14dc6a9da6bbe9e57398f060a2cc24d79e12345709ac15c8e4f5b8c1"),
            ),
            (
                100,
                hex!("3dee66b2accacd71dd607b281d1485ef960c37beff85374f4b7c65eb05ed1252"),
            ),
            (
                137,
                hex!("f2a78d43cf0922ef45e56a7f36d7eba13a8eb9407c1dc59e087322388e622fbb"),
            ),
            (
                8453,
                hex!("28862a0c28aab4b8a4403fdf5cfd71686e7dd665db1469ec7f84bf45d1a3dd9b"),
            ),
            (
                9745,
                hex!("f7941fdf92e8d5b4815995973c1cdf0e58cbe3f404ba4a8f672da5a951832e4c"),
            ),
            (
                42161,
                hex!("c5677211ea383a13f4d47c092fc48fb3a0a5ade451c82f19dff69a400080f34b"),
            ),
            (
                43114,
                hex!("310880582f800792d606e89b94c8f23529469003cf71da6aa172737702b8a4be"),
            ),
            (
                57073,
                hex!("7daedf408aec4bacb29278b0febf3c40ce52c7911d0a23eb5c4c116a8dd44852"),
            ),
            (
                59144,
                hex!("5aa640f484ef090ab25171d6cbc6adff0cbda7a342ed7ef6371636a1575eca40"),
            ),
            (
                11_155_111,
                hex!("d69c063b99b74a6690df5541787acc942828219a0ba12fded27eff853da8f6fd"),
            ),
        ];

        let order = sample_order();
        let owner = sample_owner();
        for (chain_id, expected_digest) in cases {
            let domain = DomainSeparator::new(chain_id, SETTLEMENT);
            let uid = order.uid(&domain, owner).0;
            let mut expected = [0u8; 56];
            expected[0..32].copy_from_slice(&expected_digest);
            expected[32..56].copy_from_slice(&TAIL);
            assert_eq!(uid, expected, "uid for chain {chain_id}");
        }
    }

    /// Locks `OrderData::hash_struct` against ethers for permutations
    /// that exercise specific byte slots: `kind = Buy`,
    /// `partiallyFillable = true`, the three `SellTokenSource` variants,
    /// the two `BuyTokenDestination` variants, and `receiver = None`.
    /// Regenerate via `tools/vector-gen`.
    #[test]
    fn hash_struct_byte_permutations_match_ethers() {
        let mut buy = sample_order();
        buy.kind = OrderKind::Buy;
        assert_eq!(
            buy.hash_struct(),
            hex!("7f6ff8bfee1c5f54ca8ac13dabf84e6646592775700fce0e5ead7049620f9ea5")
        );

        let mut partial = sample_order();
        partial.partially_fillable = true;
        assert_eq!(
            partial.hash_struct(),
            hex!("4a7892b4e3cc787cc8dbb22afb249a52b144ae7aec066d2f41f521aa05c7388c")
        );

        let mut external = sample_order();
        external.sell_token_balance = SellTokenSource::External;
        assert_eq!(
            external.hash_struct(),
            hex!("250972eafa5a01e4103f50f3987422339582583b36d2a47e3c6920b4acca3509")
        );

        let mut internal_sell = sample_order();
        internal_sell.sell_token_balance = SellTokenSource::Internal;
        assert_eq!(
            internal_sell.hash_struct(),
            hex!("c94d0a2b1c1b41042d41e0d9f2d05bc91fbe1cb053b716176850029cdb88f679")
        );

        let mut internal_buy = sample_order();
        internal_buy.buy_token_balance = BuyTokenDestination::Internal;
        assert_eq!(
            internal_buy.hash_struct(),
            hex!("4d19213af5ed0adb5ec3d67b00cdcd360ea0f9378a9392f599de132106a558d9")
        );

        // None-receiver should encode the same 20 zero bytes that an
        // explicit Address::ZERO does.
        let mut no_receiver = sample_order();
        no_receiver.receiver = None;
        let mut zero_receiver = sample_order();
        zero_receiver.receiver = Some(Address::ZERO);
        assert_eq!(no_receiver.hash_struct(), zero_receiver.hash_struct());
        assert_eq!(
            no_receiver.hash_struct(),
            hex!("5388e8a0f9cf9129fd0fd54d3192e502cf5519ee4316f0c77860bfc0c3f42994")
        );
    }

    /// Locks `OrderData::TYPE_HASH` against the canonical EIP-712 type
    /// signature published in
    /// [`GPv2Order.sol`](https://github.com/cowprotocol/contracts/blob/main/src/contracts/libraries/GPv2Order.sol).
    /// Note that `kind`, `sellTokenBalance` and `buyTokenBalance` are typed
    /// as `string` in the EIP-712 schema even though `GPv2Order.Data` stores
    /// them as `bytes32` markers.
    #[test]
    fn order_type_hash_matches_canonical_signature() {
        let signature = b"Order(\
            address sellToken,\
            address buyToken,\
            address receiver,\
            uint256 sellAmount,\
            uint256 buyAmount,\
            uint32 validTo,\
            bytes32 appData,\
            uint256 feeAmount,\
            string kind,\
            bool partiallyFillable,\
            string sellTokenBalance,\
            string buyTokenBalance\
        )";
        assert_eq!(OrderData::TYPE_HASH, *keccak256(signature));
    }

    #[test]
    fn buy_eth_address_matches_canonical_sentinel() {
        // Source: cowprotocol/contracts/src/ts/order.ts (BUY_ETH_ADDRESS).
        assert_eq!(
            BUY_ETH_ADDRESS,
            address!("EeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE")
        );
    }

    #[test]
    fn order_kind_keccak_constants() {
        assert_eq!(OrderKind::BUY, *keccak256(b"buy"));
        assert_eq!(OrderKind::SELL, *keccak256(b"sell"));
    }

    #[test]
    fn sell_token_source_keccak_constants() {
        assert_eq!(SellTokenSource::ERC20, *keccak256(b"erc20"));
        assert_eq!(SellTokenSource::EXTERNAL, *keccak256(b"external"));
        assert_eq!(SellTokenSource::INTERNAL, *keccak256(b"internal"));
    }

    #[test]
    fn buy_token_destination_keccak_constants() {
        assert_eq!(BuyTokenDestination::ERC20, *keccak256(b"erc20"));
        assert_eq!(BuyTokenDestination::INTERNAL, *keccak256(b"internal"));
    }

    #[test]
    fn order_uid_round_trips_via_string() {
        let original = OrderUid::from_str(
            "0x5668997bd3fb981d1b3ec44e8483e7c369756df47d10241c1c7a26fde4d1090e89984d17af2f18f8c54873c0de68a56cc5a23e0f695ba915",
        )
        .unwrap();
        let (hash, owner, valid_to) = original.parts();
        assert_eq!(
            hash,
            B256::from(hex!(
                "5668997bd3fb981d1b3ec44e8483e7c369756df47d10241c1c7a26fde4d1090e"
            ))
        );
        assert_eq!(
            owner,
            address!("0x89984d17af2f18f8c54873c0de68a56cc5a23e0f")
        );
        assert_eq!(valid_to, 0x695ba915);

        let rebuilt = OrderUid::from_parts(hash, owner, valid_to);
        assert_eq!(rebuilt, original);
    }

    #[test]
    fn order_uid_displays_as_prefixed_hex() {
        let mut uid = OrderUid::default();
        uid.0[0] = 0x01;
        uid.0[55] = 0xff;
        let expected = "0x01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ff";
        assert_eq!(uid.to_string(), expected);
    }

    /// Mirrors `packOrderUidParams` from
    /// `cowprotocol/contracts/test/GPv2Order/PackOrderUidParams.t.sol`,
    /// which derives `(digest, owner, validTo)` from keccak-256 of UTF-8
    /// constants. Locks the 56-byte packing layout `digest || owner || validTo`.
    #[test]
    fn order_uid_pack_matches_contracts_solidity_reference() {
        let digest = keccak256(b"order digest");
        let owner_seed = keccak256(b"owner");
        let owner = Address::from_slice(&owner_seed[12..32]);
        let valid_to_seed = keccak256(b"valid to");
        let valid_to = u32::from_be_bytes(valid_to_seed[28..32].try_into().unwrap());

        let uid = OrderUid::from_parts(digest, owner, valid_to);

        let mut expected = [0u8; 56];
        expected[0..32].copy_from_slice(digest.as_slice());
        expected[32..52].copy_from_slice(owner.as_slice());
        expected[52..56].copy_from_slice(&valid_to.to_be_bytes());
        assert_eq!(uid.0, expected);

        let (round_digest, round_owner, round_valid_to) = uid.parts();
        assert_eq!(round_digest, digest);
        assert_eq!(round_owner, owner);
        assert_eq!(round_valid_to, valid_to);
    }
}
