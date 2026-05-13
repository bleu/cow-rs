//! The signed order payload (`OrderData`) and supporting types.
//!
//! `OrderData` is the exact struct that is hashed and signed by the order
//! owner and verified by the GPv2Settlement contract. The other types in
//! this module — [`OrderKind`], [`SellTokenSource`], [`BuyTokenDestination`]
//! and [`OrderUid`] — exist to make the payload typeable and the resulting
//! identifier addressable.
//!
//! Adapted from [`cowprotocol/services`] (MIT OR Apache-2.0).
//!
//! [`cowprotocol/services`]: https://github.com/cowprotocol/services/blob/main/crates/model/src/order.rs

use {
    crate::{
        app_data::AppDataHash,
        domain::{DomainSeparator, hashed_eip712_message},
    },
    alloy_primitives::{Address, B256, U256, keccak256},
    hex_literal::hex,
    serde::{Deserialize, Deserializer, Serialize, Serializer, de},
    std::{
        fmt::{self, Debug, Display},
        str::FromStr,
    },
};

/// Sentinel address used in place of a buy token to indicate that the order
/// pays out in the chain's native currency (e.g. ETH on mainnet, xDAI on
/// Gnosis Chain).
pub const BUY_ETH_ADDRESS: Address = Address::repeat_byte(0xee);

/// The exact 12 fields signed by the order owner and verified by the
/// settlement contract.
///
/// See [`GPv2Order.Data`] for the Solidity counterpart.
///
/// [`GPv2Order.Data`]: https://github.com/cowprotocol/contracts/blob/v1.1.2/src/contracts/libraries/GPv2Order.sol
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
    pub sell_amount: U256,
    /// Amount of `buy_token` the owner expects to receive, in atomic units.
    pub buy_amount: U256,
    /// Unix timestamp (seconds) after which the order is no longer valid.
    pub valid_to: u32,
    /// 32-byte digest of the app-data document.
    pub app_data: AppDataHash,
    /// Protocol fee charged in `sell_token` atomic units. Zero for limit
    /// orders (their fee is taken from surplus) and for liquidity orders.
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
    /// EIP-712 `typeHash` of the `GPv2Order.Data` struct.
    ///
    /// `keccak256("Order(address sellToken,address buyToken,address receiver,uint256 sellAmount,uint256 buyAmount,uint32 validTo,bytes32 appData,uint256 feeAmount,bytes32 kind,bool partiallyFillable,bytes32 sellTokenBalance,bytes32 buyTokenBalance)")`
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
}

/// Direction of an order — whether the owner is fixing the buy side or the
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
    /// `keccak256("buy")` — used as the on-chain encoding of [`OrderKind::Buy`].
    pub const BUY: [u8; 32] =
        hex!("6ed88e868af0a1983e3886d5f3e95a2fafbd6c3450bc229e27342283dc429ccc");
    /// `keccak256("sell")` — used as the on-chain encoding of [`OrderKind::Sell`].
    pub const SELL: [u8; 32] =
        hex!("f3b277728b3fee749481eb3e0b3b48980dbbab78658fc419025cb16eee346775");
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
    /// `keccak256("erc20")`.
    pub const ERC20: [u8; 32] =
        hex!("5a28e9363bb942b639270062aa6bb295f434bcdfc42c97267bf003f272060dc9");
    /// `keccak256("external")`.
    pub const EXTERNAL: [u8; 32] =
        hex!("abee3b73373acd583a130924aad6dc38cfdc44ba0555ba94ce2ff63980ea0632");
    /// `keccak256("internal")`.
    pub const INTERNAL: [u8; 32] =
        hex!("4ac99ace14ee0a5ef932dc609df0943ab7ac16b7583634612f8dc35a4289a6ce");

    /// On-chain `bytes32` encoding of this variant.
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
    /// `keccak256("erc20")`.
    pub const ERC20: [u8; 32] =
        hex!("5a28e9363bb942b639270062aa6bb295f434bcdfc42c97267bf003f272060dc9");
    /// `keccak256("internal")`.
    pub const INTERNAL: [u8; 32] =
        hex!("4ac99ace14ee0a5ef932dc609df0943ab7ac16b7583634612f8dc35a4289a6ce");

    /// On-chain `bytes32` encoding of this variant.
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
        let mut bytes = [0u8; 2 + 56 * 2];
        bytes[..2].copy_from_slice(b"0x");
        const_hex::encode_to_slice(self.0.as_slice(), &mut bytes[2..]).unwrap();
        f.write_str(std::str::from_utf8(&bytes).unwrap())
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
    use {super::*, alloy_primitives::address, hex_literal::hex};

    /// Locks the full `OrderData::uid` output for a known order against the
    /// byte-perfect golden vector lifted from
    /// `cowprotocol/services/crates/model/src/order.rs::compute_order_uid`.
    /// Any drift in `TYPE_HASH`, `hash_struct`, `DomainSeparator` packing,
    /// `hashed_eip712_message`, or `OrderUid::from_parts` will fail this test.
    #[test]
    fn compute_order_uid_matches_services_golden() {
        let domain = DomainSeparator(hex!(
            "74e0b11bd18120612556bae4578cfd3a254d7e2495f543c569a92ff5794d9b09"
        ));
        let owner = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");
        let order = OrderData {
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
        };

        let expected = hex!(
            "0e45d31fd31b28c26031cdd81b35a8938b2ccca2cc425fcf440fd3bfed1eede9\
             70997970c51812dc3a010c7d01b50e0d17dc79c8\
             ffffffff"
        );

        assert_eq!(order.uid(&domain, owner).0, expected);
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
}
