//! Thin GraphQL client for the CoW Protocol subgraph.
//!
//! The CoW subgraph indexes on-chain settlement data and exposes it via
//! The Graph. This module ships a small typed client covering the
//! canonical queries published by `cow-py` and `@cowprotocol/cow-sdk`:
//! [`SubgraphClient::totals`], [`SubgraphClient::last_days_volume`] and
//! [`SubgraphClient::last_hours_volume`]. Anything else can be sent with
//! [`SubgraphClient::execute`].
//!
//! ## Endpoints
//!
//! The Graph's hosted service has been retired; production subgraphs now
//! live on `gateway.thegraph.com`, which requires an API key. Pass the URL
//! and the bearer token directly:
//!
//! ```no_run
//! use cowprotocol::SubgraphClient;
//! # async fn run() -> cowprotocol::Result<()> {
//! let client = SubgraphClient::new(
//!     "https://gateway.thegraph.com/api/<key>/subgraphs/id/<id>"
//!         .parse()
//!         .unwrap(),
//! );
//! let totals = client.totals().await?;
//! println!("orders: {}", totals.orders);
//! # Ok(()) }
//! ```
//!
//! For dev work against The Graph Studio (free, less stable) the URL has
//! the same shape: `https://api.studio.thegraph.com/query/<account>/<slug>/version/latest`.

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    chain::Chain,
    error::{Error, Result},
};

/// Returned by [`SubgraphClient::for_chain_studio`] when the chain has no
/// published Graph Studio deployment.
#[derive(Clone, Copy, Debug, thiserror::Error, Eq, PartialEq)]
#[error(
    "chain {0:?} has no published Graph Studio subgraph; pass a gateway URL via SubgraphClient::with_bearer_token"
)]
pub struct ChainSubgraphUnavailable(pub Chain);

/// Errors specific to subgraph queries.
#[derive(Debug, thiserror::Error)]
pub enum SubgraphError {
    /// The subgraph returned a non-empty `errors` array. GraphQL servers
    /// emit HTTP 200 even for query errors, so we surface them as a
    /// dedicated variant.
    #[error("subgraph returned {} graphql error(s); first: {first}", errors.len())]
    GraphQl {
        /// Full list of errors.
        errors: Vec<GraphQlError>,
        /// First error message, for easy `{}` printing.
        first: String,
    },
    /// The response envelope was missing both `data` and `errors`, or had
    /// a non-conformant shape.
    #[error("subgraph response had neither `data` nor `errors`")]
    EmptyResponse,
}

/// One element of a GraphQL `errors` array.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GraphQlError {
    /// Human-readable error message.
    pub message: String,
    /// Optional location pointer into the query.
    #[serde(default)]
    pub locations: Vec<serde_json::Value>,
    /// Optional path into the response data.
    #[serde(default)]
    pub path: Vec<serde_json::Value>,
    /// Implementation-defined extensions (e.g. error code).
    #[serde(default)]
    pub extensions: Option<serde_json::Value>,
}

/// Aggregate protocol statistics returned by the `totals` query.
///
/// Strings are kept as-is from the subgraph (`BigInt` / `BigDecimal`) so
/// callers can feed them into their preferred big-number parser without
/// lossy float conversions.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Totals {
    /// Unique tokens that have been traded through the protocol.
    pub tokens: String,
    /// Total number of orders ever created.
    pub orders: String,
    /// Unique trader addresses.
    pub traders: String,
    /// Total number of settlement transactions.
    pub settlements: String,
    /// All-time volume denominated in USD.
    #[serde(default)]
    pub volume_usd: Option<String>,
    /// All-time volume denominated in ETH.
    #[serde(default)]
    pub volume_eth: Option<String>,
    /// All-time fees collected, in USD.
    #[serde(default)]
    pub fees_usd: Option<String>,
    /// All-time fees collected, in ETH.
    #[serde(default)]
    pub fees_eth: Option<String>,
}

/// One row of a `dailyTotals` aggregate.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DailyTotal {
    /// Unix-second timestamp anchoring the day window.
    pub timestamp: String,
    /// Volume traded that day, in USD.
    #[serde(default)]
    pub volume_usd: Option<String>,
}

/// One row of an `hourlyTotals` aggregate.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HourlyTotal {
    /// Unix-second timestamp anchoring the hour window.
    pub timestamp: String,
    /// Volume traded that hour, in USD.
    #[serde(default)]
    pub volume_usd: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Envelope<T> {
    #[serde(default = "Option::default")]
    data: Option<T>,
    #[serde(default)]
    errors: Vec<GraphQlError>,
}

#[derive(Debug, Serialize)]
struct Request<'a, V: Serialize> {
    query: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    variables: Option<V>,
}

#[derive(Debug, Deserialize)]
struct TotalsData {
    totals: Vec<Totals>,
}

#[derive(Debug, Deserialize)]
struct DailyTotalsData {
    #[serde(rename = "dailyTotals")]
    daily_totals: Vec<DailyTotal>,
}

#[derive(Debug, Deserialize)]
struct HourlyTotalsData {
    #[serde(rename = "hourlyTotals")]
    hourly_totals: Vec<HourlyTotal>,
}

#[derive(Debug, Serialize)]
struct DaysVariables {
    days: u32,
}

#[derive(Debug, Serialize)]
struct HoursVariables {
    hours: u32,
}

/// Thin GraphQL client for the CoW subgraph.
#[derive(Clone)]
pub struct SubgraphClient {
    url: url::Url,
    client: reqwest::Client,
    bearer: Option<String>,
}

/// Manual `Debug` impl that redacts the bearer token *and* the URL
/// path when a bearer is set. Gateway URLs published by The Graph
/// embed the API key in the path itself
/// (`https://gateway.thegraph.com/api/<key>/subgraphs/id/<id>`), so
/// rendering the URL in full would still leak the credential even
/// with `bearer` masked. Without a bearer the URL is a Studio
/// endpoint and safe to print verbatim.
impl std::fmt::Debug for SubgraphClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let url_view = if self.bearer.is_some() {
            format!(
                "{}://{}/<redacted>",
                self.url.scheme(),
                self.url.host_str().unwrap_or("")
            )
        } else {
            self.url.to_string()
        };
        f.debug_struct("SubgraphClient")
            .field("url", &url_view)
            .field("client", &self.client)
            .field("bearer", &self.bearer.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl SubgraphClient {
    /// Build a client against an explicit subgraph URL. No authorisation
    /// header is attached: use [`SubgraphClient::with_bearer_token`] for
    /// the production gateway.
    pub fn new(url: url::Url) -> Self {
        Self {
            url,
            client: reqwest::Client::new(),
            bearer: None,
        }
    }

    /// Build a client that sends `Authorization: Bearer <token>` with
    /// every request. The Graph's production gateway
    /// (`gateway.thegraph.com`) requires this.
    pub fn with_bearer_token(url: url::Url, token: impl Into<String>) -> Self {
        Self {
            url,
            client: reqwest::Client::new(),
            bearer: Some(token.into()),
        }
    }

    /// Build a client targeting The Graph Studio URL published for
    /// `chain` (see [`Chain::subgraph_studio_url`]).
    ///
    /// Studio is the developer endpoint and is rate-limited; production
    /// callers should use [`SubgraphClient::with_bearer_token`] against
    /// the gateway URL instead.
    pub fn for_chain_studio(chain: Chain) -> std::result::Result<Self, ChainSubgraphUnavailable> {
        let url = chain
            .subgraph_studio_url()
            .ok_or(ChainSubgraphUnavailable(chain))?;
        Ok(Self::new(
            url::Url::parse(url).expect("hard-coded studio URL"),
        ))
    }

    /// The subgraph URL the client points at.
    pub const fn url(&self) -> &url::Url {
        &self.url
    }

    /// `query Totals`: aggregate protocol statistics.
    pub async fn totals(&self) -> Result<Totals> {
        let data: TotalsData = self
            .execute_no_vars(
                r"query Totals {
                    totals {
                        tokens
                        orders
                        traders
                        settlements
                        volumeUsd
                        volumeEth
                        feesUsd
                        feesEth
                    }
                }",
            )
            .await?;
        Ok(data.totals.into_iter().next().unwrap_or_default())
    }

    /// `query LastDaysVolume($days: Int!)`: the last `days` daily volume
    /// rows, most recent first.
    pub async fn last_days_volume(&self, days: u32) -> Result<Vec<DailyTotal>> {
        let data: DailyTotalsData = self
            .execute(
                r"query LastDaysVolume($days: Int!) {
                    dailyTotals(orderBy: timestamp, orderDirection: desc, first: $days) {
                        timestamp
                        volumeUsd
                    }
                }",
                Some(DaysVariables { days }),
            )
            .await?;
        Ok(data.daily_totals)
    }

    /// `query LastHoursVolume($hours: Int!)`: the last `hours` hourly
    /// volume rows, most recent first.
    pub async fn last_hours_volume(&self, hours: u32) -> Result<Vec<HourlyTotal>> {
        let data: HourlyTotalsData = self
            .execute(
                r"query LastHoursVolume($hours: Int!) {
                    hourlyTotals(orderBy: timestamp, orderDirection: desc, first: $hours) {
                        timestamp
                        volumeUsd
                    }
                }",
                Some(HoursVariables { hours }),
            )
            .await?;
        Ok(data.hourly_totals)
    }

    /// Send an arbitrary GraphQL query. Returns the decoded `data` field.
    ///
    /// `TData` is the shape of the `data` object the query returns;
    /// `TVars` is whatever is serialised as `variables`. Pass
    /// `Option::<()>::None` (or use [`SubgraphClient::execute_no_vars`])
    /// when the query takes no variables.
    pub async fn execute<TVars, TData>(
        &self,
        query: &str,
        variables: Option<TVars>,
    ) -> Result<TData>
    where
        TVars: Serialize,
        TData: DeserializeOwned,
    {
        let body = Request { query, variables };
        let mut req = self.client.post(self.url.clone()).json(&body);
        if let Some(token) = &self.bearer {
            req = req.bearer_auth(token);
        }
        let response = req.send().await?;
        let status = response.status();
        let text = response.text().await?;
        if !status.is_success() {
            return Err(Error::UnexpectedStatus { status, body: text });
        }
        let envelope: Envelope<TData> = serde_json::from_str(&text)?;
        if !envelope.errors.is_empty() {
            let first = envelope.errors[0].message.clone();
            return Err(Error::Subgraph(SubgraphError::GraphQl {
                errors: envelope.errors,
                first,
            }));
        }
        envelope
            .data
            .ok_or(Error::Subgraph(SubgraphError::EmptyResponse))
    }

    /// Convenience: [`SubgraphClient::execute`] for queries that take no
    /// variables.
    pub async fn execute_no_vars<TData>(&self, query: &str) -> Result<TData>
    where
        TData: DeserializeOwned,
    {
        self.execute::<(), TData>(query, None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totals_round_trips_through_serde() {
        let raw = serde_json::json!({
            "tokens": "1234",
            "orders": "987654",
            "traders": "12345",
            "settlements": "543210",
            "volumeUsd": "1234567890.12",
            "volumeEth": "12345.67",
            "feesUsd": "12345.67",
            "feesEth": "1.234"
        });
        let totals: Totals = serde_json::from_value(raw).unwrap();
        assert_eq!(totals.orders, "987654");
        assert_eq!(totals.volume_usd.as_deref(), Some("1234567890.12"));
        assert_eq!(totals.fees_eth.as_deref(), Some("1.234"));
    }

    #[test]
    fn totals_tolerates_missing_optional_fields() {
        let raw = serde_json::json!({
            "tokens": "0",
            "orders": "0",
            "traders": "0",
            "settlements": "0"
        });
        let totals: Totals = serde_json::from_value(raw).unwrap();
        assert!(totals.volume_usd.is_none());
        assert!(totals.fees_eth.is_none());
    }

    #[test]
    fn daily_total_parses_canonical_response_row() {
        let raw = serde_json::json!({
            "timestamp": "1700000000",
            "volumeUsd": "42000000.42"
        });
        let row: DailyTotal = serde_json::from_value(raw).unwrap();
        assert_eq!(row.timestamp, "1700000000");
        assert_eq!(row.volume_usd.as_deref(), Some("42000000.42"));
    }

    #[test]
    fn hourly_total_tolerates_null_volume() {
        let raw = serde_json::json!({
            "timestamp": "1700000000",
            "volumeUsd": null
        });
        let row: HourlyTotal = serde_json::from_value(raw).unwrap();
        assert!(row.volume_usd.is_none());
    }

    #[test]
    fn graphql_error_response_parses() {
        let raw = serde_json::json!({
            "errors": [{
                "message": "Field 'foo' is not defined",
                "locations": [{"line": 1, "column": 12}],
                "path": ["foo"],
                "extensions": {"code": "GRAPHQL_VALIDATION_FAILED"}
            }]
        });
        let envelope: Envelope<TotalsData> = serde_json::from_value(raw).unwrap();
        assert!(envelope.data.is_none());
        assert_eq!(envelope.errors.len(), 1);
        assert!(envelope.errors[0].message.contains("not defined"));
    }

    #[test]
    fn request_body_includes_variables_when_present() {
        let body = Request {
            query: "query LastDaysVolume($days: Int!) { dailyTotals(first: $days) { timestamp } }",
            variables: Some(DaysVariables { days: 7 }),
        };
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["variables"]["days"], 7);
        assert!(json["query"].as_str().unwrap().contains("LastDaysVolume"));
    }

    #[test]
    fn request_body_omits_variables_when_absent() {
        let body: Request<'_, ()> = Request {
            query: "query Totals { totals { orders } }",
            variables: None,
        };
        let json = serde_json::to_value(&body).unwrap();
        assert!(json.get("variables").is_none());
    }

    #[test]
    fn client_url_is_preserved() {
        let url = url::Url::parse("https://example.test/subgraphs/cow").unwrap();
        let client = SubgraphClient::new(url.clone());
        assert_eq!(client.url(), &url);
    }

    #[test]
    fn bearer_token_constructor_stores_it() {
        let url = url::Url::parse("https://example.test/").unwrap();
        let client = SubgraphClient::with_bearer_token(url, "tok_abc");
        assert_eq!(client.bearer.as_deref(), Some("tok_abc"));
    }

    #[test]
    fn debug_does_not_leak_bearer_token() {
        let url = url::Url::parse("https://example.test/").unwrap();
        let secret = "super-secret-token-xyz-do-not-leak";
        let client = SubgraphClient::with_bearer_token(url, secret);
        let rendered = format!("{client:?}");
        assert!(
            !rendered.contains(secret),
            "bearer token leaked through Debug: {rendered}"
        );
        assert!(
            rendered.contains("redacted"),
            "expected '<redacted>' marker in Debug output, got: {rendered}"
        );

        // Production gateway URLs embed the API key directly in the
        // path. Debug must redact the path so the URL field alone
        // cannot leak the credential a side-channel logger picks up.
        let path_key = "API-KEY-IN-URL-DO-NOT-LEAK";
        let gateway = url::Url::parse(&format!(
            "https://gateway.thegraph.com/api/{path_key}/subgraphs/id/xyz",
        ))
        .unwrap();
        let gw_client = SubgraphClient::with_bearer_token(gateway, "bearer-token");
        let gw_rendered = format!("{gw_client:?}");
        assert!(
            !gw_rendered.contains(path_key),
            "gateway URL path leaked through Debug: {gw_rendered}"
        );

        let no_token = SubgraphClient::new(url::Url::parse("https://example.test/").unwrap());
        assert!(format!("{no_token:?}").contains("None"));
    }

    #[test]
    fn for_chain_studio_resolves_five_supported_chains() {
        for chain in [
            Chain::Mainnet,
            Chain::Gnosis,
            Chain::ArbitrumOne,
            Chain::Base,
            Chain::Sepolia,
        ] {
            let client = SubgraphClient::for_chain_studio(chain).unwrap();
            assert_eq!(client.url().scheme(), "https");
            assert_eq!(client.url().host_str(), Some("api.studio.thegraph.com"));
        }
    }

    #[test]
    fn for_chain_studio_rejects_chains_without_studio_deployment() {
        for chain in [
            Chain::Bnb,
            Chain::Polygon,
            Chain::Plasma,
            Chain::Avalanche,
            Chain::Ink,
            Chain::Linea,
        ] {
            let err = SubgraphClient::for_chain_studio(chain).unwrap_err();
            assert_eq!(err, ChainSubgraphUnavailable(chain));
        }
    }
}
