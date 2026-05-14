//! Chains on which the CoW Protocol orderbook is reachable.
//!
//! The CoW orderbook is hosted at `https://api.cow.fi/<slug>/api/v1/...`.
//! Each variant of [`Chain`] records both the canonical chain id and the
//! URL slug used by that orderbook deployment.

use alloy_primitives::Address;
use serde::{Deserialize, Deserializer, de};
use std::fmt;
use std::str::FromStr;

use crate::contracts::{GPV2_SETTLEMENT, GPV2_VAULT_RELAYER};

/// A chain supported by the CoW Protocol orderbook.
///
/// Variants are ordered by chain id (ascending) to keep `match` arms and
/// `TryFrom` impl in a single sensible order.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u64)]
pub enum Chain {
    /// Ethereum mainnet (chain id 1).
    Mainnet = 1,
    /// BNB Smart Chain (chain id 56).
    Bnb = 56,
    /// Gnosis Chain: xDAI (chain id 100).
    Gnosis = 100,
    /// Polygon PoS (chain id 137).
    Polygon = 137,
    /// Base mainnet (chain id 8453).
    Base = 8453,
    /// Plasma (chain id 9745).
    Plasma = 9745,
    /// Arbitrum One (chain id 42161).
    ArbitrumOne = 42_161,
    /// Avalanche C-Chain (chain id 43114).
    Avalanche = 43_114,
    /// Ink (chain id 57073).
    Ink = 57_073,
    /// Linea (chain id 59144).
    Linea = 59_144,
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
            Self::Bnb => "bnb",
            Self::Gnosis => "xdai",
            Self::Polygon => "polygon",
            Self::Base => "base",
            Self::Plasma => "plasma",
            Self::ArbitrumOne => "arbitrum_one",
            Self::Avalanche => "avalanche",
            Self::Ink => "ink",
            Self::Linea => "linea",
            Self::Sepolia => "sepolia",
        }
    }

    /// Deployment address of `GPv2Settlement` on this chain. Identical on
    /// every variant via CREATE2; the accessor exists for symmetry with
    /// [`Chain::orderbook_base_url`] so call sites can write
    /// `chain.settlement()` instead of reaching for the module-level
    /// constant.
    pub const fn settlement(self) -> Address {
        // Suppress the unused-self warning on a method that intentionally
        // returns the same address on every variant.
        let _ = self;
        GPV2_SETTLEMENT
    }

    /// Deployment address of `GPv2VaultRelayer` on this chain. This is
    /// the spender ERC-20 `approve` calls should target before submitting
    /// an order.
    pub const fn vault_relayer(self) -> Address {
        let _ = self;
        GPV2_VAULT_RELAYER
    }

    /// Production orderbook base URL, e.g. `https://api.cow.fi/mainnet`.
    pub fn orderbook_base_url(self) -> url::Url {
        // `Url::parse` is fallible only on user-supplied input; the strings
        // here are constants and are validated by the test below.
        url::Url::parse(&format!("https://api.cow.fi/{}", self.orderbook_slug()))
            .expect("hard-coded orderbook URL")
    }

    /// Staging ("barn") orderbook base URL, e.g.
    /// `https://barn.api.cow.fi/mainnet`. Returns `None` for chains
    /// that do not have a published barn deployment.
    ///
    /// Barn is the pre-production environment the CoW team runs
    /// alongside production. Integrators wire their staging stack
    /// against barn before flipping the prod feature flag.
    pub fn orderbook_barn_url(self) -> Option<url::Url> {
        if !self.has_barn_deployment() {
            return None;
        }
        Some(
            url::Url::parse(&format!("https://barn.api.cow.fi/{}", self.orderbook_slug()))
                .expect("hard-coded barn URL"),
        )
    }

    /// Whether the orderbook team operates a staging ("barn")
    /// deployment for this chain. Mainnet, Gnosis Chain, Sepolia and
    /// Arbitrum One are barn-eligible; the other deployments only have
    /// production endpoints.
    pub const fn has_barn_deployment(self) -> bool {
        matches!(
            self,
            Self::Mainnet | Self::Gnosis | Self::Sepolia | Self::ArbitrumOne
        )
    }

    /// CoW Protocol subgraph URL on The Graph Studio, mirroring
    /// `cowdao_cowpy.subgraph.deployments.NETWORK_SUBGRAPH_IDS_MAP`.
    ///
    /// Returns `None` for chains that do not have a published studio
    /// deployment. Studio endpoints are best-effort: they suit
    /// development and indexer-status pings, but the production path is
    /// `gateway.thegraph.com` with an API key, which the caller wires
    /// directly via [`crate::SubgraphClient::with_bearer_token`].
    pub const fn subgraph_studio_url(self) -> Option<&'static str> {
        match self {
            Self::Mainnet => Some(
                "https://api.studio.thegraph.com/query/49707/cow-subgraph-mainnet/version/latest",
            ),
            Self::Gnosis => Some(
                "https://api.studio.thegraph.com/query/49707/cow-subgraph-gnosis/version/latest",
            ),
            Self::ArbitrumOne => {
                Some("https://api.studio.thegraph.com/query/49707/cow-subgraph-arb/version/latest")
            }
            Self::Base => {
                Some("https://api.studio.thegraph.com/query/49707/cow-subgraph-base/version/latest")
            }
            Self::Sepolia => Some(
                "https://api.studio.thegraph.com/query/49707/cow-subgraph-sepolia/version/latest",
            ),
            Self::Bnb
            | Self::Polygon
            | Self::Plasma
            | Self::Avalanche
            | Self::Ink
            | Self::Linea => None,
        }
    }
}

impl TryFrom<u64> for Chain {
    type Error = UnsupportedChain;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Mainnet),
            56 => Ok(Self::Bnb),
            100 => Ok(Self::Gnosis),
            137 => Ok(Self::Polygon),
            8453 => Ok(Self::Base),
            9745 => Ok(Self::Plasma),
            42_161 => Ok(Self::ArbitrumOne),
            43_114 => Ok(Self::Avalanche),
            57_073 => Ok(Self::Ink),
            59_144 => Ok(Self::Linea),
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

impl fmt::Display for Chain {
    /// Render as `<orderbook-slug>(<chain-id>)`, e.g. `mainnet(1)`. The
    /// slug is the canonical orderbook identifier; the parenthesised
    /// numeric id stays close at hand for logs and error contexts.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})", self.orderbook_slug(), self.id())
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
    use std::collections::HashSet;

    use super::*;

    /// Every chain currently supported by the CoW Protocol orderbook.
    const ALL: &[Chain] = &[
        Chain::Mainnet,
        Chain::Bnb,
        Chain::Gnosis,
        Chain::Polygon,
        Chain::Base,
        Chain::Plasma,
        Chain::ArbitrumOne,
        Chain::Avalanche,
        Chain::Ink,
        Chain::Linea,
        Chain::Sepolia,
    ];

    #[test]
    fn ids_match_canonical_values() {
        assert_eq!(Chain::Mainnet.id(), 1);
        assert_eq!(Chain::Bnb.id(), 56);
        assert_eq!(Chain::Gnosis.id(), 100);
        assert_eq!(Chain::Polygon.id(), 137);
        assert_eq!(Chain::Base.id(), 8453);
        assert_eq!(Chain::Plasma.id(), 9745);
        assert_eq!(Chain::ArbitrumOne.id(), 42_161);
        assert_eq!(Chain::Avalanche.id(), 43_114);
        assert_eq!(Chain::Ink.id(), 57_073);
        assert_eq!(Chain::Linea.id(), 59_144);
        assert_eq!(Chain::Sepolia.id(), 11_155_111);
    }

    #[test]
    fn orderbook_base_urls_parse() {
        for chain in ALL {
            let url = chain.orderbook_base_url();
            assert_eq!(url.scheme(), "https");
            assert_eq!(url.host_str(), Some("api.cow.fi"));
            assert!(url.path().contains(chain.orderbook_slug()));
        }
    }

    #[test]
    fn all_slugs_are_unique_and_parseable_urls() {
        assert_eq!(ALL.len(), 11, "expected 11 supported chains");

        let mut seen: HashSet<&'static str> = HashSet::new();
        for chain in ALL {
            let slug = chain.orderbook_slug();
            assert!(!slug.is_empty(), "empty slug for {chain:?}");
            assert!(seen.insert(slug), "duplicate slug {slug:?}");

            let url = chain.orderbook_base_url();
            assert_eq!(url.scheme(), "https");
            assert_eq!(url.host_str(), Some("api.cow.fi"));
        }
        assert_eq!(seen.len(), 11);
    }

    #[test]
    fn orderbook_barn_url_only_set_for_barn_chains() {
        for chain in ALL {
            match chain.orderbook_barn_url() {
                Some(url) => {
                    assert!(chain.has_barn_deployment(), "{chain:?}");
                    assert_eq!(url.scheme(), "https");
                    assert_eq!(url.host_str(), Some("barn.api.cow.fi"));
                    assert!(url.path().contains(chain.orderbook_slug()));
                }
                None => {
                    assert!(!chain.has_barn_deployment(), "{chain:?}");
                }
            }
        }
        // Sanity: at least the four canonical barn chains are present.
        assert!(Chain::Mainnet.has_barn_deployment());
        assert!(Chain::Gnosis.has_barn_deployment());
        assert!(Chain::Sepolia.has_barn_deployment());
        assert!(Chain::ArbitrumOne.has_barn_deployment());
        // ...and at least one non-barn chain is correctly excluded.
        assert!(!Chain::Bnb.has_barn_deployment());
    }

    #[test]
    fn try_from_round_trips_supported_ids() {
        for chain in ALL {
            assert_eq!(Chain::try_from(chain.id()), Ok(*chain));
        }
    }

    #[test]
    fn try_from_rejects_unsupported_id() {
        assert_eq!(Chain::try_from(999_999), Err(UnsupportedChain(999_999)));
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
