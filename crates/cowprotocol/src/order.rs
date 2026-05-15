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

#[cfg(test)]
use alloy_primitives::keccak256;
use alloy_primitives::{Address, B256, FixedBytes, U256};
use hex_literal::hex;
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};
use std::fmt::{self, Display};

use crate::app_data::AppDataHash;
use crate::domain::{DomainSeparator, hashed_eip712_message};

/// Private `sol!` view of [`OrderData`] used to derive the EIP-712
/// `typeHash` and `hashStruct` via [`alloy_sol_types::SolStruct`]. Lives
/// in a sub-module so the generated `pub struct Order` is not part of
/// the public API: callers should not have to know about it. The
/// Solidity name `Order` is load-bearing: it appears verbatim in the
/// EIP-712 type string that `GPv2Settlement` verifies.
///
/// `kind`, `sellTokenBalance` and `buyTokenBalance` are declared `string`
/// here even though the on-chain [`crate::contracts::GPv2OrderData`]
/// stores them as `bytes32`: the EIP-712 type string the contract
/// verifies against uses `string`, and the resulting 32-byte slots are
/// identical because the bytes32 values are pre-computed `keccak256` of
/// the same strings.
pub(crate) mod eip712 {
    use alloy_sol_types::sol;

    sol! {
        #[derive(Debug)]
        struct Order {
            address sellToken;
            address buyToken;
            address receiver;
            uint256 sellAmount;
            uint256 buyAmount;
            uint32 validTo;
            bytes32 appData;
            uint256 feeAmount;
            string kind;
            bool partiallyFillable;
            string sellTokenBalance;
            string buyTokenBalance;
        }
    }
}

/// Sentinel buy token meaning the order pays out in the chain's
/// native currency (ETH on mainnet, xDAI on Gnosis, etc.).
pub const BUY_ETH_ADDRESS: Address = Address::repeat_byte(0xee);

/// Server-side lifecycle status from `GET /api/v1/orders/{uid}`.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum OrderStatus {
    /// Awaiting on-chain pre-signature.
    PresignaturePending,
    /// Live; waiting for a solver to settle.
    #[default]
    Open,
    /// Fully matched on-chain.
    Fulfilled,
    /// Off-chain delete or on-chain pre-sign reversal.
    Cancelled,
    /// `validTo` passed before any fill.
    Expired,
}

/// Server-side order classification. Drives fee handling and solver
/// routing.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OrderClass {
    /// Standard market order.
    #[default]
    Market,
    /// Solver-internal, placed by whitelisted participants.
    Liquidity,
    /// Limit order; fee taken from surplus once the target is met.
    Limit,
}

/// The 12 fields signed by the order owner and verified by
/// `GPv2Settlement`. Mirrors [`GPv2Order.Data`].
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
    /// `None` means the owner receives the buy token.
    #[serde(default)]
    pub receiver: Option<Address>,
    /// Atomic units of `sell_token`.
    #[serde_as(as = "DisplayFromStr")]
    pub sell_amount: U256,
    /// Atomic units of `buy_token`.
    #[serde_as(as = "DisplayFromStr")]
    pub buy_amount: U256,
    /// Unix seconds.
    pub valid_to: u32,
    /// 32-byte digest of the app-data document.
    pub app_data: AppDataHash,
    /// Protocol fee in `sell_token` atomic units. Zero for limit and
    /// liquidity orders (fee taken from surplus).
    #[serde_as(as = "DisplayFromStr")]
    pub fee_amount: U256,
    /// Sell-side vs buy-side fix.
    pub kind: OrderKind,
    /// Whether partial fills are allowed.
    pub partially_fillable: bool,
    /// Source the sell token is drawn from.
    #[serde(default)]
    pub sell_token_balance: SellTokenSource,
    /// Destination the buy token is paid to.
    #[serde(default)]
    pub buy_token_balance: BuyTokenDestination,
}

impl OrderData {
    /// EIP-712 `hashStruct` over the order; the 32-byte input expected
    /// by [`hashed_eip712_message`]. Delegates to
    /// [`alloy_sol_types::SolStruct`] applied to the private
    /// [`eip712::Order`] declaration, whose `typeHash` and field encoding
    /// are conformance-locked against the canonical contract type string.
    pub fn hash_struct(&self) -> [u8; 32] {
        use alloy_sol_types::SolStruct;
        eip712::Order::from(self).eip712_hash_struct().0
    }

    /// 56-byte order UID on `domain` for `owner`.
    pub fn uid(&self, domain: &DomainSeparator, owner: Address) -> OrderUid {
        OrderUid::from_parts(
            hashed_eip712_message(domain, &self.hash_struct()),
            owner,
            self.valid_to,
        )
    }

    /// Sign with an ECDSA signer; equivalent to
    /// [`crate::signature::EcdsaSignature::sign`] over
    /// [`Self::hash_struct`] promoted into a
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

impl From<&OrderData> for eip712::Order {
    fn from(d: &OrderData) -> Self {
        Self {
            sellToken: d.sell_token,
            buyToken: d.buy_token,
            receiver: d.receiver.unwrap_or(Address::ZERO),
            sellAmount: d.sell_amount,
            buyAmount: d.buy_amount,
            validTo: d.valid_to,
            appData: d.app_data.0,
            feeAmount: d.fee_amount,
            kind: match d.kind {
                OrderKind::Sell => "sell".to_owned(),
                OrderKind::Buy => "buy".to_owned(),
            },
            partiallyFillable: d.partially_fillable,
            sellTokenBalance: match d.sell_token_balance {
                SellTokenSource::Erc20 => "erc20".to_owned(),
                SellTokenSource::External => "external".to_owned(),
                SellTokenSource::Internal => "internal".to_owned(),
            },
            buyTokenBalance: match d.buy_token_balance {
                BuyTokenDestination::Erc20 => "erc20".to_owned(),
                BuyTokenDestination::Internal => "internal".to_owned(),
            },
        }
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

    /// Set the order recipient. `None` (and `Some(Address::ZERO)`) default
    /// the receiver to the owner; the explicit zero is normalised to `None`
    /// so the wire form, signed hash and contract decoding all agree
    /// (`cow-sdk` and `cow-py` treat the two as the same sentinel).
    pub fn receiver(mut self, receiver: Option<Address>) -> Self {
        self.0.receiver = match receiver {
            Some(addr) if addr == Address::ZERO => None,
            other => other,
        };
        self
    }

    /// Sell amount in atomic units.
    pub const fn sell_amount(mut self, amount: U256) -> Self {
        self.0.sell_amount = amount;
        self
    }

    /// Buy amount in atomic units.
    pub const fn buy_amount(mut self, amount: U256) -> Self {
        self.0.buy_amount = amount;
        self
    }

    /// Unix-seconds expiry timestamp.
    pub const fn valid_to(mut self, valid_to: u32) -> Self {
        self.0.valid_to = valid_to;
        self
    }

    /// 32-byte app-data digest.
    pub const fn app_data(mut self, hash: AppDataHash) -> Self {
        self.0.app_data = hash;
        self
    }

    /// User-signed fee amount. Must be `0` at submission;
    /// [`crate::OrderQuoteResponse::to_signed_order_data`] handles
    /// that for callers projecting from a quote.
    pub const fn fee_amount(mut self, amount: U256) -> Self {
        self.0.fee_amount = amount;
        self
    }

    /// Order direction.
    pub const fn kind(mut self, kind: OrderKind) -> Self {
        self.0.kind = kind;
        self
    }

    /// Whether the order may be filled in parts (default: `false`).
    pub const fn partially_fillable(mut self, partially_fillable: bool) -> Self {
        self.0.partially_fillable = partially_fillable;
        self
    }

    /// Source for the sell-side token balance.
    pub const fn sell_token_balance(mut self, balance: SellTokenSource) -> Self {
        self.0.sell_token_balance = balance;
        self
    }

    /// Destination for the buy-side token balance.
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

/// Full order returned by `GET /api/v1/orders/{uid}`. Flattens the
/// 12 [`OrderData`] fields plus server-derived metadata; less-common
/// contextual objects stay as opaque JSON for forward-compat.
#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Order {
    /// The 12 signed fields ([`OrderData`]).
    #[serde(flatten)]
    pub data: OrderData,
    /// 56-byte order UID against the chain's settlement domain.
    pub uid: OrderUid,
    /// Owner that signed the order.
    pub owner: alloy_primitives::Address,
    /// Signing scheme used by the owner.
    pub signing_scheme: crate::signing_scheme::SigningScheme,
    /// Raw signature bytes, hex-encoded.
    pub signature: String,
    /// ISO-8601 timestamp the orderbook accepted the order.
    pub creation_date: String,
    /// Current server-side lifecycle status.
    pub status: OrderStatus,
    /// Server-side order classification.
    pub class: OrderClass,
    /// Cumulative buy-side fill, atomic units.
    #[serde_as(as = "DisplayFromStr")]
    pub executed_buy_amount: alloy_primitives::U256,
    /// Cumulative sell-side fill, atomic units.
    #[serde_as(as = "DisplayFromStr")]
    pub executed_sell_amount: alloy_primitives::U256,
    /// Executed fee in `executed_fee_token` atomic units.
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[serde(default)]
    pub executed_fee: Option<alloy_primitives::U256>,
    /// Token used to charge `executed_fee`.
    #[serde(default)]
    pub executed_fee_token: Option<alloy_primitives::Address>,
    /// `true` once the order is invalidated (cancelled / replaced).
    #[serde(default)]
    pub invalidated: bool,
    /// `true` if classified as a liquidity order.
    #[serde(default)]
    pub is_liquidity_order: bool,
    /// Full app-data document, when the orderbook stored it.
    #[serde(default)]
    pub full_app_data: Option<String>,
    /// Quote that produced the order, when one was supplied.
    #[serde(default)]
    pub quote: Option<serde_json::Value>,
    /// Pre/post settlement interactions from app-data hooks.
    #[serde(default)]
    pub interactions: Option<serde_json::Value>,
    /// EthFlow metadata for native-sell orders.
    #[serde(default)]
    pub ethflow_data: Option<serde_json::Value>,
    /// On-chain placement metadata for EthFlow orders.
    #[serde(default)]
    pub onchain_order_data: Option<serde_json::Value>,
    /// On-chain user (distinct from `owner` for proxy/relayer flows).
    #[serde(default)]
    pub onchain_user: Option<alloy_primitives::Address>,
    /// Settlement contract that processed the trade, when known.
    #[serde(default)]
    pub settlement_contract: Option<alloy_primitives::Address>,
}

/// Order direction.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OrderKind {
    /// Owner fixes the `buy_token` amount.
    #[default]
    Buy,
    /// Owner fixes the `sell_token` amount.
    Sell,
}

impl OrderKind {
    /// `keccak256("buy")`: EIP-712 encoding + on-chain `bytes32` marker.
    pub const BUY: [u8; 32] =
        hex!("6ed88e868af0a1983e3886d5f3e95a2fafbd6c3450bc229e27342283dc429ccc");
    /// `keccak256("sell")`: EIP-712 encoding + on-chain `bytes32` marker.
    pub const SELL: [u8; 32] =
        hex!("f3b277728b3fee749481eb3e0b3b48980dbbab78658fc419025cb16eee346775");

    /// Lower-case wire form (`"buy"` / `"sell"`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Buy => "buy",
            Self::Sell => "sell",
        }
    }

    /// Parse the 32-byte on-chain marker (as returned by `GPv2Order.Data.kind`)
    /// into a Rust enum. Returns `None` for unknown markers; the contract
    /// itself only ever writes `BUY` or `SELL`.
    pub const fn from_contract_bytes(bytes: [u8; 32]) -> Option<Self> {
        if matches_bytes(&bytes, &Self::BUY) {
            Some(Self::Buy)
        } else if matches_bytes(&bytes, &Self::SELL) {
            Some(Self::Sell)
        } else {
            None
        }
    }
}

const fn matches_bytes(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut i = 0;
    while i < 32 {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

impl Display for OrderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Source the sell amount is transferred from on fulfilment.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SellTokenSource {
    /// Owner's ERC-20 allowance to the Vault relayer.
    #[default]
    Erc20,
    /// Owner's ERC-20 balance via Balancer external balances.
    External,
    /// Owner's Balancer Vault internal balance.
    Internal,
}

impl SellTokenSource {
    /// `keccak256("erc20")`.
    pub const ERC20: [u8; 32] =
        hex!("5a28e9363bb942b639270062aa6bb295f434bcdfc42c97267bf003f272060dc9");
    /// `keccak256("external")`.
    pub const EXTERNAL: [u8; 32] =
        hex!("abee3b73373acd583a130924aad6dc38cfdc44ba0555ba94ce2ff63980ea0632");
    /// `keccak256("internal")`.
    pub const INTERNAL: [u8; 32] =
        hex!("4ac99ace14ee0a5ef932dc609df0943ab7ac16b7583634612f8dc35a4289a6ce");

    /// Parse the on-chain `GPv2Order.Data.sellTokenBalance` marker.
    /// Returns `None` for unknown values.
    pub const fn from_contract_bytes(bytes: [u8; 32]) -> Option<Self> {
        if matches_bytes(&bytes, &Self::ERC20) {
            Some(Self::Erc20)
        } else if matches_bytes(&bytes, &Self::EXTERNAL) {
            Some(Self::External)
        } else if matches_bytes(&bytes, &Self::INTERNAL) {
            Some(Self::Internal)
        } else {
            None
        }
    }
}

/// Destination the buy amount is paid to on fulfilment.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BuyTokenDestination {
    /// Regular ERC-20 transfer.
    #[default]
    Erc20,
    /// Balancer Vault internal balance.
    Internal,
}

impl BuyTokenDestination {
    /// `keccak256("erc20")`.
    pub const ERC20: [u8; 32] =
        hex!("5a28e9363bb942b639270062aa6bb295f434bcdfc42c97267bf003f272060dc9");
    /// `keccak256("internal")`.
    pub const INTERNAL: [u8; 32] =
        hex!("4ac99ace14ee0a5ef932dc609df0943ab7ac16b7583634612f8dc35a4289a6ce");

    /// Parse the on-chain `GPv2Order.Data.buyTokenBalance` marker.
    /// Returns `None` for unknown values.
    pub const fn from_contract_bytes(bytes: [u8; 32]) -> Option<Self> {
        if matches_bytes(&bytes, &Self::ERC20) {
            Some(Self::Erc20)
        } else if matches_bytes(&bytes, &Self::INTERNAL) {
            Some(Self::Internal)
        } else {
            None
        }
    }
}

/// 56-byte order identifier:
/// `32-byte digest || 20-byte owner || 4-byte validTo`. The digest is
/// `keccak256(0x19 0x01 || domain_separator || order_struct_hash)`.
///
/// Newtype over [`FixedBytes<56>`]: inherits its `Debug` / `Display` /
/// serde behaviour (`0x`-prefixed lower-case hex on the wire) and its
/// `From<[u8; 56]>` / `AsRef<[u8]>` impls.
#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct OrderUid(pub FixedBytes<56>);

impl OrderUid {
    /// Assemble a UID from its three parts.
    pub fn from_parts(hash: B256, owner: Address, valid_to: u32) -> Self {
        let mut uid = [0u8; 56];
        uid[0..32].copy_from_slice(hash.as_slice());
        uid[32..52].copy_from_slice(owner.as_slice());
        uid[52..56].copy_from_slice(&valid_to.to_be_bytes());
        Self(FixedBytes::new(uid))
    }

    /// UID with the first four bytes set to `i` (big-endian) and the
    /// rest zeroed. Test-only ergonomics; mirrors
    /// `cowprotocol/services::OrderUid::from_integer`.
    pub const fn from_integer(i: u32) -> Self {
        let mut uid = [0u8; 56];
        let bytes = i.to_be_bytes();
        uid[0] = bytes[0];
        uid[1] = bytes[1];
        uid[2] = bytes[2];
        uid[3] = bytes[3];
        Self(FixedBytes(uid))
    }

    /// Split a UID into its three parts.
    pub fn parts(&self) -> (B256, Address, u32) {
        let bytes = self.0.as_slice();
        let mut valid_to = [0u8; 4];
        valid_to.copy_from_slice(&bytes[52..56]);
        (
            B256::from_slice(&bytes[0..32]),
            Address::from_slice(&bytes[32..52]),
            u32::from_be_bytes(valid_to),
        )
    }
}

impl From<[u8; 56]> for OrderUid {
    fn from(bytes: [u8; 56]) -> Self {
        Self(FixedBytes::new(bytes))
    }
}

impl AsRef<[u8]> for OrderUid {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Display for OrderUid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl std::str::FromStr for OrderUid {
    type Err = <FixedBytes<56> as std::str::FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<FixedBytes<56>>().map(Self)
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{address, b256};
    use hex_literal::hex;
    use std::str::FromStr;

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
            app_data: AppDataHash::default(),
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
        let domain = DomainSeparator(b256!(
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

    /// Locks the [`eip712::Order`] `SolStruct::eip712_type_hash` derivation
    /// against the canonical
    /// `keccak256("Order(address sellToken,..,string buyTokenBalance)")`
    /// value the GPv2Settlement contract verifies signatures with. Any
    /// drift in the `sol!` field types or order would diverge from the
    /// contract's `typeHash` and silently invalidate every signature.
    #[test]
    fn eip712_order_type_hash_matches_canonical() {
        use alloy_sol_types::SolStruct;

        let sol_order = eip712::Order::from(&sample_order());
        assert_eq!(
            <eip712::Order as SolStruct>::eip712_type_hash(&sol_order).0,
            hex!("d5a25ba2e97094ad7d83dc28a6572da797d6b3e7fc6663bd93efb789fc17e489"),
            "Order(...) typeHash must match the GPv2Settlement-verified value",
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

    /// Locks the [`eip712::Order`] `typeHash` against the canonical
    /// EIP-712 type signature published in
    /// [`GPv2Order.sol`](https://github.com/cowprotocol/contracts/blob/main/src/contracts/libraries/GPv2Order.sol).
    /// Note that `kind`, `sellTokenBalance` and `buyTokenBalance` are typed
    /// as `string` in the EIP-712 schema even though `GPv2Order.Data` stores
    /// them as `bytes32` markers.
    #[test]
    fn order_type_hash_matches_canonical_signature() {
        use alloy_sol_types::SolStruct;

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
        let sol_order = eip712::Order::from(&sample_order());
        assert_eq!(
            <eip712::Order as SolStruct>::eip712_type_hash(&sol_order),
            keccak256(signature),
        );
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
