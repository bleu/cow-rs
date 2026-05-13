//! Chains on which the CoW Protocol orderbook is reachable.
//!
//! The CoW orderbook is hosted at `https://api.cow.fi/<slug>/api/v1/...`.
//! Each variant of [`Chain`] records both the canonical chain id and the
//! URL slug used by that orderbook deployment.

use {
    serde::{Deserialize, Deserializer, de},
    std::{fmt, str::FromStr},
};

/// A chain supported by the CoW Protocol orderbook.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u64)]
pub enum Chain {
    /// Ethereum mainnet (chain id 1).
    Mainnet = 1,
    /// Gnosis Chain — xDAI (chain id 100).
    Gnosis = 100,
    /// Base mainnet (chain id 8453).
    Base = 8453,
    /// Arbitrum One (chain id 42161).
    ArbitrumOne = 42161,
    /// Sepolia testnet (chain id 11155111).
    Sepolia = 11_155_111,
}

impl Chain {
    /// Canonical chain id.
    pub const fn id(self) -> u64 {
        self as u64
    }

    /// Orderbook URL slug used by `api.cow.fi`. Mirrors the slugs published
    /// by `@cowprotocol/cow-sdk`.
    pub const fn orderbook_slug(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Gnosis => "xdai",
            Self::Base => "base",
            Self::ArbitrumOne => "arbitrum_one",
            Self::Sepolia => "sepolia",
        }
    }

    /// Production orderbook base URL, e.g. `https://api.cow.fi/mainnet`.
    pub fn orderbook_base_url(self) -> url::Url {
        // `Url::parse` is fallible only on user-supplied input; the strings
        // here are constants and are validated by the test below.
        url::Url::parse(&format!("https://api.cow.fi/{}", self.orderbook_slug()))
            .expect("hard-coded orderbook URL")
    }
}

impl TryFrom<u64> for Chain {
    type Error = UnsupportedChain;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Mainnet),
            100 => Ok(Self::Gnosis),
            8453 => Ok(Self::Base),
            42_161 => Ok(Self::ArbitrumOne),
            11_155_111 => Ok(Self::Sepolia),
            other => Err(UnsupportedChain(other)),
        }
    }
}

impl FromStr for Chain {
    type Err = UnsupportedChain;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let id: u64 = s.parse().map_err(|_| UnsupportedChain(0))?;
        Self::try_from(id)
    }
}

/// Returned when a chain id is not in [`Chain`].
#[derive(Clone, Copy, Debug, thiserror::Error, Eq, PartialEq)]
#[error("unsupported chain id {0}")]
pub struct UnsupportedChain(pub u64);

impl<'de> Deserialize<'de> for Chain {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;
        impl de::Visitor<'_> for Visitor {
            type Value = Chain;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a chain id as integer or stringified integer")
            }

            fn visit_u64<E>(self, v: u64) -> Result<Chain, E>
            where
                E: de::Error,
            {
                Chain::try_from(v).map_err(de::Error::custom)
            }

            fn visit_i64<E>(self, v: i64) -> Result<Chain, E>
            where
                E: de::Error,
            {
                u64::try_from(v)
                    .map_err(de::Error::custom)
                    .and_then(|u| Chain::try_from(u).map_err(de::Error::custom))
            }

            fn visit_str<E>(self, v: &str) -> Result<Chain, E>
            where
                E: de::Error,
            {
                v.parse::<Chain>().map_err(de::Error::custom)
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_match_canonical_values() {
        assert_eq!(Chain::Mainnet.id(), 1);
        assert_eq!(Chain::Gnosis.id(), 100);
        assert_eq!(Chain::Base.id(), 8453);
        assert_eq!(Chain::ArbitrumOne.id(), 42_161);
        assert_eq!(Chain::Sepolia.id(), 11_155_111);
    }

    #[test]
    fn orderbook_base_urls_parse() {
        for chain in [
            Chain::Mainnet,
            Chain::Gnosis,
            Chain::Base,
            Chain::ArbitrumOne,
            Chain::Sepolia,
        ] {
            let url = chain.orderbook_base_url();
            assert_eq!(url.scheme(), "https");
            assert_eq!(url.host_str(), Some("api.cow.fi"));
            assert!(url.path().contains(chain.orderbook_slug()));
        }
    }

    #[test]
    fn try_from_round_trips_supported_ids() {
        for chain in [
            Chain::Mainnet,
            Chain::Gnosis,
            Chain::Base,
            Chain::ArbitrumOne,
            Chain::Sepolia,
        ] {
            assert_eq!(Chain::try_from(chain.id()), Ok(chain));
        }
    }

    #[test]
    fn try_from_rejects_unsupported_id() {
        assert_eq!(Chain::try_from(2), Err(UnsupportedChain(2)));
    }

    #[test]
    fn deserialise_accepts_integer_and_string() {
        assert_eq!(serde_json::from_str::<Chain>("1").unwrap(), Chain::Mainnet);
        assert_eq!(
            serde_json::from_str::<Chain>("\"100\"").unwrap(),
            Chain::Gnosis
        );
        assert!(serde_json::from_str::<Chain>("999").is_err());
    }
}
