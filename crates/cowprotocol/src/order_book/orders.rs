//! `OrderCreation`: the `POST /api/v1/orders` body and its serde wire
//! shape. Carries the owner's signature, the canonical app-data JSON
//! and the same amounts that were hashed for EIP-712 signing.

use alloy_primitives::{Address, Bytes, U256};
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};

use crate::{
    app_data::AppDataHash,
    error::{Error, Result},
    order::{BuyTokenDestination, OrderData, OrderKind, SellTokenSource},
    signature::Signature,
    signing_scheme::SigningScheme,
};

/// Body of `POST /api/v1/orders`.
///
/// Differs from a raw [`OrderData`] in three load-bearing ways
/// (`cow-protocol/howto/integrate/api.mdx`):
///
/// - `fee_amount` here is what the user signed (which must be `0`); the
///   protocol fee is taken from surplus at settlement.
/// - `app_data` is the canonical JSON string of the metadata document;
///   `app_data_hash` is the `keccak256` digest of those exact bytes. The
///   signed [`OrderData::app_data`] field equals `app_data_hash`.
/// - `signing_scheme`, `signature` and `from` carry the owner's signature
///   along with the order.
///
/// Use [`OrderCreation::from_signed_order_data`] to assemble the body once
/// the owner has signed [`crate::OrderQuoteResponse::try_into_signed_order_data`].
#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", try_from = "OrderCreationWire")]
pub struct OrderCreation {
    /// Token the owner is selling.
    pub sell_token: Address,
    /// Token the owner is buying.
    pub buy_token: Address,
    /// Optional buy-token recipient.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receiver: Option<Address>,
    /// Sell amount in atomic units (must agree with the signed payload).
    #[serde_as(as = "DisplayFromStr")]
    pub sell_amount: U256,
    /// Buy amount in atomic units (must agree with the signed payload).
    #[serde_as(as = "DisplayFromStr")]
    pub buy_amount: U256,
    /// Order expiry in Unix seconds.
    pub valid_to: u32,
    /// Canonical JSON of the app-data document.
    pub app_data: String,
    /// `keccak256(app_data)`. Mirrors the signed payload's `app_data` field.
    pub app_data_hash: AppDataHash,
    /// User-signed fee amount. Must be `"0"` at submission.
    #[serde_as(as = "DisplayFromStr")]
    pub fee_amount: U256,
    /// Direction of the order.
    pub kind: OrderKind,
    /// Whether partial fills are allowed.
    pub partially_fillable: bool,
    /// Source the sell amount is drawn from.
    pub sell_token_balance: SellTokenSource,
    /// Destination the buy amount is paid to.
    pub buy_token_balance: BuyTokenDestination,
    /// Off-chain signing scheme used to authenticate the order.
    pub signing_scheme: SigningScheme,
    /// Signature bytes. Empty for [`SigningScheme::PreSign`].
    #[serde(serialize_with = "serialise_signature_bytes")]
    pub signature: Signature,
    /// Order owner. Required for `presign` / `eip1271`; recommended for
    /// ECDSA schemes so the server can reject malformed signatures early.
    pub from: Address,
    /// Identifier returned by `POST /api/v1/quote`. Optional but improves
    /// solver fee accounting when the order is matched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quote_id: Option<i64>,
}

fn serialise_signature_bytes<S>(
    signature: &Signature,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    Bytes::from(signature.to_bytes()).serialize(serializer)
}

/// Deserialisation helper for [`OrderCreation`].
///
/// The wire format flattens `signature` to a hex string while
/// `signing_scheme` lives in a sibling field. Serde's per-field
/// `deserialize_with` cannot see siblings, so we shape the JSON into
/// this `Wire` form first (with `signature` as raw bytes) and then
/// reassemble the typed [`Signature`] enum in [`TryFrom`] using
/// [`Signature::from_bytes`].
#[serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrderCreationWire {
    sell_token: Address,
    buy_token: Address,
    #[serde(default)]
    receiver: Option<Address>,
    #[serde_as(as = "DisplayFromStr")]
    sell_amount: U256,
    #[serde_as(as = "DisplayFromStr")]
    buy_amount: U256,
    valid_to: u32,
    app_data: String,
    app_data_hash: AppDataHash,
    #[serde_as(as = "DisplayFromStr")]
    fee_amount: U256,
    kind: OrderKind,
    partially_fillable: bool,
    sell_token_balance: SellTokenSource,
    buy_token_balance: BuyTokenDestination,
    signing_scheme: SigningScheme,
    signature: Bytes,
    from: Address,
    #[serde(default)]
    quote_id: Option<i64>,
}

impl TryFrom<OrderCreationWire> for OrderCreation {
    type Error = crate::error::Error;

    /// Reassemble an [`OrderCreation`] from its wire form, applying the
    /// same invariants [`OrderCreation::from_signed_order_data`] enforces
    /// on the construction path: the signature payload must parse for the
    /// declared scheme, `from` must be non-zero, and
    /// `keccak256(app_data) == app_data_hash`. Without the digest check, a
    /// hostile orderbook (or any intermediary) could hand the SDK a body
    /// whose JSON document disagrees with the hash the user signed.
    fn try_from(wire: OrderCreationWire) -> std::result::Result<Self, Self::Error> {
        let signature = Signature::from_bytes(wire.signing_scheme, &wire.signature)?;
        let order_data = OrderData {
            sell_token: wire.sell_token,
            buy_token: wire.buy_token,
            receiver: wire.receiver,
            sell_amount: wire.sell_amount,
            buy_amount: wire.buy_amount,
            valid_to: wire.valid_to,
            app_data: wire.app_data_hash,
            fee_amount: wire.fee_amount,
            kind: wire.kind,
            partially_fillable: wire.partially_fillable,
            sell_token_balance: wire.sell_token_balance,
            buy_token_balance: wire.buy_token_balance,
        };
        Self::from_signed_order_data(
            &order_data,
            signature,
            wire.from,
            wire.app_data,
            wire.quote_id,
        )
    }
}

impl OrderCreation {
    /// Project the 12 signed fields back out of an [`OrderCreation`] as
    /// the [`OrderData`] the EIP-712 hash and UID were computed against.
    /// Useful for re-hashing the order during owner verification.
    pub const fn order_data(&self) -> OrderData {
        OrderData {
            sell_token: self.sell_token,
            buy_token: self.buy_token,
            receiver: self.receiver,
            sell_amount: self.sell_amount,
            buy_amount: self.buy_amount,
            valid_to: self.valid_to,
            app_data: self.app_data_hash,
            fee_amount: self.fee_amount,
            kind: self.kind,
            partially_fillable: self.partially_fillable,
            sell_token_balance: self.sell_token_balance,
            buy_token_balance: self.buy_token_balance,
        }
    }

    /// Recover the signer of this order from its embedded signature and
    /// assert it matches `self.from`. Returns `self.from` on success.
    ///
    /// - [`SigningScheme::Eip712`] and [`SigningScheme::EthSign`]:
    ///   recovers via ECDSA and compares against `self.from`.
    /// - [`SigningScheme::Eip1271`] and [`SigningScheme::PreSign`]:
    ///   the signature does not carry a recoverable owner; the call
    ///   short-circuits to `Ok(self.from)` because the orderbook (or
    ///   `GPv2Signing.setPreSignature`) will validate the owner
    ///   on-chain. Callers that need to verify the EIP-1271 path
    ///   pre-submission must call the contract's `isValidSignature`
    ///   themselves.
    ///
    /// Recommended belt-and-suspenders call site:
    /// `creation.verify_owner(&settlement_domain(chain.id(), chain.settlement()))?;`
    /// before `OrderBookApi::post_order` to catch signing-key /
    /// `from`-address divergence client-side.
    pub fn verify_owner(
        &self,
        domain: &crate::domain::DomainSeparator,
    ) -> std::result::Result<Address, crate::signature::SignatureError> {
        let payload = crate::order::eip712::Order::from(&self.order_data());
        match self.signature.recover(domain, &payload)? {
            Some(recovered) if recovered.signer == self.from => Ok(self.from),
            Some(recovered) => Err(crate::signature::SignatureError::SignerMismatch {
                declared: self.from,
                recovered: recovered.signer,
            }),
            // EIP-1271 / PreSign: the signature does not carry a
            // recoverable owner, but a synthesised `OrderCreation` (e.g.
            // round-tripped through JSON) could still set `from = ZERO`.
            // Reject that case explicitly so callers do not treat the
            // `Ok` arm as a positive owner assertion. The orderbook (or
            // `GPv2Signing.setPreSignature`) still validates the owner
            // on-chain in the non-zero case.
            None if self.from == Address::ZERO => {
                Err(crate::signature::SignatureError::SignerMismatch {
                    declared: Address::ZERO,
                    recovered: Address::ZERO,
                })
            }
            None => Ok(self.from),
        }
    }

    /// Assemble a submission body from a signed [`OrderData`] plus the
    /// metadata required by the orderbook (`from`, signature, app-data
    /// document, optional quote id).
    ///
    /// Validates that `from` is non-zero (the orderbook rejects every
    /// scheme with `from = Address::ZERO`, and the contract-signed schemes
    /// `Eip1271` / `PreSign` carry the owner explicitly there). Callers
    /// who want to additionally cross-check that `from` matches the
    /// recovered signer of an ECDSA signature can call
    /// [`OrderCreation::verify_owner`] on the assembled body.
    pub fn from_signed_order_data(
        order_data: &OrderData,
        signature: Signature,
        from: Address,
        app_data_json: String,
        quote_id: Option<i64>,
    ) -> Result<Self> {
        if from == Address::ZERO {
            return Err(Error::OrderCreationInvalid {
                field: "from",
                reason: "owner address must be non-zero",
            });
        }
        // The JSON document MUST hash to the digest the order was signed
        // against. Otherwise a wrapper layer can bind the user's
        // signature to bytes the orderbook never sees, while pinning a
        // different document under the same hash via `put_app_data`.
        let json_digest = alloy_primitives::keccak256(app_data_json.as_bytes());
        if json_digest != order_data.app_data {
            return Err(Error::OrderCreationInvalid {
                field: "app_data",
                reason: "JSON digest does not match signed app_data hash",
            });
        }
        // `Some(Address::ZERO)` and `None` mean the same thing (use owner)
        // but cow-sdk and cow-py emit `None` on the wire. Normalise so the
        // wire payload, signed hash and contract decoding always agree.
        let receiver = match order_data.receiver {
            Some(addr) if addr == Address::ZERO => None,
            other => other,
        };
        Ok(Self {
            sell_token: order_data.sell_token,
            buy_token: order_data.buy_token,
            receiver,
            sell_amount: order_data.sell_amount,
            buy_amount: order_data.buy_amount,
            valid_to: order_data.valid_to,
            app_data: app_data_json,
            app_data_hash: order_data.app_data,
            fee_amount: order_data.fee_amount,
            kind: order_data.kind,
            partially_fillable: order_data.partially_fillable,
            sell_token_balance: order_data.sell_token_balance,
            buy_token_balance: order_data.buy_token_balance,
            signing_scheme: signature.scheme(),
            signature,
            from,
            quote_id,
        })
    }
}
