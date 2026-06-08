//! Type-state builder for the orderbook submission body.
//!
//! [`OrderSubmission`] wraps the wire-shape [`OrderCreation`] with a
//! [`OrderSubmission::builder`] entry that statically tracks the four
//! required slots: the signed [`OrderData`] payload, the
//! [`Signature`], the owner address (`from`), and the canonical
//! app-data document or pre-canonicalised JSON. [`build`] is callable
//! only once each is set.
//!
//! Use this when you signed an order outside the fluent
//! `OrderBookApi::quote_builder()` chain (for example: signed via a
//! hardware wallet in a separate process, signed once and cached,
//! signed under a custom domain). For the in-process chain, prefer
//! [`OrderBookApi::quote_builder`].
//!
//! ```no_run
//! use alloy_primitives::{Address, U256, address};
//! use cowprotocol::{
//!     AppDataDoc, COW_RS_APP_CODE, Chain, OrderBookApi, OrderData, OrderKind,
//!     OrderSubmission, settlement_domain,
//! };
//!
//! # async fn run(signed: OrderData, signature: cowprotocol::Signature, from: Address) -> cowprotocol::Result<()> {
//! let body = OrderSubmission::builder()
//!     .order_data(signed)
//!     .signature(signature)
//!     .from(from)
//!     .app_data_doc(&AppDataDoc::sdk_attribution(COW_RS_APP_CODE))?
//!     .quote_id(42)
//!     .build()?;
//!
//! let api = OrderBookApi::with_chain(Chain::Mainnet).build();
//! let uid = body.submit_via(&api).await?;
//! # let _ = uid;
//! # Ok(()) }
//! ```
//!
//! [`build`]: OrderSubmissionBuilder::<Set, Set, Set, Set>::build
//! [`OrderBookApi::quote_builder`]: super::OrderBookApi::quote_builder

use alloy_primitives::Address;
use std::marker::PhantomData;

use crate::app_data::{AppDataDoc, AppDataError};
use crate::error::{Error, Result};
use crate::order::{OrderData, OrderUid};
use crate::signature::Signature;

use super::builder::{Missing, Set};
use super::orders::OrderCreation;

/// Type-state builder for [`OrderSubmission`]. Required slots:
/// `OrderData` payload, [`Signature`], owner address, app-data
/// document or canonical-JSON.
#[must_use = "OrderSubmissionBuilder does nothing until build() is called"]
#[derive(Debug, Default)]
pub struct OrderSubmissionBuilder<O, S, F, A> {
    order_data: Option<OrderData>,
    signature: Option<Signature>,
    from: Option<Address>,
    app_data_json: Option<String>,
    quote_id: Option<i64>,
    _state: PhantomData<(O, S, F, A)>,
}

impl OrderSubmission {
    /// Start a type-state builder. Pin the signed [`OrderData`],
    /// [`Signature`], owner address, and app-data document (or
    /// pre-canonicalised JSON) to reach a callable [`build`].
    ///
    /// [`build`]: OrderSubmissionBuilder::<Set, Set, Set, Set>::build
    pub const fn builder() -> OrderSubmissionBuilder<Missing, Missing, Missing, Missing> {
        OrderSubmissionBuilder {
            order_data: None,
            signature: None,
            from: None,
            app_data_json: None,
            quote_id: None,
            _state: PhantomData,
        }
    }
}

impl<O, S, F, A> OrderSubmissionBuilder<O, S, F, A> {
    /// Re-tag without moving payload; private helper for state transitions.
    fn retag<O2, S2, F2, A2>(self) -> OrderSubmissionBuilder<O2, S2, F2, A2> {
        OrderSubmissionBuilder {
            order_data: self.order_data,
            signature: self.signature,
            from: self.from,
            app_data_json: self.app_data_json,
            quote_id: self.quote_id,
            _state: PhantomData,
        }
    }

    /// Attach an optional `quote_id` so the orderbook can correlate the
    /// submission with the originating quote. Settable at any state.
    pub const fn quote_id(mut self, id: i64) -> Self {
        self.quote_id = Some(id);
        self
    }
}

impl<S, F, A> OrderSubmissionBuilder<Missing, S, F, A> {
    /// Pin the signed [`OrderData`]. Required.
    pub fn order_data(mut self, data: OrderData) -> OrderSubmissionBuilder<Set, S, F, A> {
        self.order_data = Some(data);
        self.retag()
    }
}

impl<O, F, A> OrderSubmissionBuilder<O, Missing, F, A> {
    /// Pin the [`Signature`] (carries the signing scheme + bytes).
    /// Required.
    pub fn signature(mut self, signature: Signature) -> OrderSubmissionBuilder<O, Set, F, A> {
        self.signature = Some(signature);
        self.retag()
    }
}

impl<O, S, A> OrderSubmissionBuilder<O, S, Missing, A> {
    /// Pin the order owner. Required; rejected at [`build`] time if
    /// `Address::ZERO`.
    ///
    /// [`build`]: OrderSubmissionBuilder::<Set, Set, Set, Set>::build
    pub fn from(mut self, from: Address) -> OrderSubmissionBuilder<O, S, Set, A> {
        self.from = Some(from);
        self.retag()
    }
}

impl<O, S, F> OrderSubmissionBuilder<O, S, F, Missing> {
    /// Pin the app-data document. Computes the canonical JSON via
    /// [`AppDataDoc::canonical_json`] and validates it fits within
    /// `APP_DATA_SIZE_LIMIT` via [`AppDataDoc::try_hash`]. Fails with
    /// [`AppDataError::DocumentTooLarge`] if oversize.
    pub fn app_data_doc(
        mut self,
        doc: &AppDataDoc,
    ) -> std::result::Result<OrderSubmissionBuilder<O, S, F, Set>, AppDataError> {
        doc.try_hash()?;
        self.app_data_json = Some(doc.canonical_json());
        Ok(self.retag())
    }

    /// Pin the canonical-JSON bytes directly. The caller is
    /// responsible for ensuring `keccak256(json)` matches the signed
    /// `OrderData::app_data` field; [`build`] rejects the body if it
    /// does not.
    ///
    /// [`build`]: OrderSubmissionBuilder::<Set, Set, Set, Set>::build
    pub fn app_data_json(mut self, json: String) -> OrderSubmissionBuilder<O, S, F, Set> {
        self.app_data_json = Some(json);
        self.retag()
    }
}

impl OrderSubmissionBuilder<Set, Set, Set, Set> {
    /// Project the builder into a wire-shape [`OrderCreation`] wrapped
    /// in [`OrderSubmission`]. Routes through
    /// [`OrderCreation::from_signed_order_data`], which validates that
    /// `from` is non-zero and that the JSON digest matches the signed
    /// app-data hash.
    pub fn build(self) -> Result<OrderSubmission> {
        let body = OrderCreation::from_signed_order_data(
            &self.order_data.expect("Set marker guarantees Some"),
            self.signature.expect("Set marker guarantees Some"),
            self.from.expect("Set marker guarantees Some"),
            self.app_data_json.expect("Set marker guarantees Some"),
            self.quote_id,
        )?;
        Ok(OrderSubmission { body })
    }
}

/// A built orderbook submission body. Wraps the wire-shape
/// [`OrderCreation`] with a fluent [`Self::submit_via`] entry point.
#[must_use = "OrderSubmission does nothing until submit_via() is called"]
#[derive(Clone, Debug)]
pub struct OrderSubmission {
    body: OrderCreation,
}

impl OrderSubmission {
    /// Borrow the underlying wire body. Use when you need to inspect
    /// or post via a custom transport.
    pub const fn body(&self) -> &OrderCreation {
        &self.body
    }

    /// Cross-check the signature recovers to `from` under `domain`.
    /// Forwards to [`OrderCreation::verify_owner`]; recommended before
    /// [`Self::submit_via`] for the ECDSA schemes.
    pub fn verify_owner(
        &self,
        domain: &crate::domain::DomainSeparator,
    ) -> std::result::Result<Address, crate::signature::SignatureError> {
        self.body.verify_owner(domain)
    }

    /// Project into [`OrderCreation`].
    pub fn into_body(self) -> OrderCreation {
        self.body
    }

    /// `POST /api/v1/orders` via the supplied api.
    #[cfg(feature = "http-client")]
    pub async fn submit_via(self, api: &super::OrderBookApi) -> Result<OrderUid> {
        api.post_order(&self.body).await
    }
}

// Bring AppDataError into scope so docs link; consumers don't import it
// directly via the builder.
#[allow(unused_imports)]
use AppDataError as _;
// Bring Error into scope for crate::Result wiring; the actual conversion
// happens through OrderCreation::from_signed_order_data's Result type.
#[allow(unused_imports)]
use Error as _;

#[cfg(test)]
mod tests {
    use alloy_primitives::{U256, address, keccak256};

    use super::*;
    use crate::app_data::COW_RS_APP_CODE;
    use crate::chain::Chain;
    use crate::order::OrderKind;
    use crate::signing_scheme::EcdsaSigningScheme;

    fn fixture_order(owner: Address) -> (OrderData, AppDataDoc) {
        let doc = AppDataDoc::sdk_attribution(COW_RS_APP_CODE);
        let app_data = doc.try_hash().unwrap();
        let order = OrderData {
            sell_token: address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
            buy_token: address!("6B175474E89094C44Da98b954EedeAC495271d0F"),
            receiver: None,
            sell_amount: U256::from(1_000_u64),
            buy_amount: U256::from(990_u64),
            valid_to: 1_900_000_000,
            app_data,
            fee_amount: U256::ZERO,
            kind: OrderKind::Sell,
            partially_fillable: false,
            sell_token_balance: Default::default(),
            buy_token_balance: Default::default(),
        };
        let _ = owner;
        (order, doc)
    }

    fn anvil_signer() -> alloy_signer_local::PrivateKeySigner {
        // Anvil account 0; matches the conformance vectors elsewhere.
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .unwrap()
    }

    #[test]
    fn builder_round_trips_through_from_signed_order_data() {
        let signer = anvil_signer();
        let owner = alloy_signer::Signer::address(&signer);
        let (order, doc) = fixture_order(owner);
        let domain = Chain::Mainnet.settlement_domain();
        let signature = order
            .sign(EcdsaSigningScheme::Eip712, &domain, &signer)
            .unwrap();

        let built = OrderSubmission::builder()
            .order_data(order)
            .signature(signature.clone())
            .from(owner)
            .app_data_doc(&doc)
            .unwrap()
            .quote_id(7)
            .build()
            .unwrap();

        let direct = OrderCreation::from_signed_order_data(
            &order,
            signature,
            owner,
            doc.canonical_json(),
            Some(7),
        )
        .unwrap();

        assert_eq!(
            serde_json::to_value(built.body()).unwrap(),
            serde_json::to_value(&direct).unwrap(),
        );
        built.verify_owner(&domain).unwrap();
    }

    #[test]
    fn builder_rejects_app_data_json_that_does_not_hash_to_signed_digest() {
        let signer = anvil_signer();
        let owner = alloy_signer::Signer::address(&signer);
        let (order, _doc) = fixture_order(owner);
        let domain = Chain::Mainnet.settlement_domain();
        let signature = order
            .sign(EcdsaSigningScheme::Eip712, &domain, &signer)
            .unwrap();

        // Use an unrelated JSON body whose digest does not match the
        // signed order's `app_data` field.
        let wrong_json = "{}".to_owned();
        assert_ne!(keccak256(wrong_json.as_bytes()), order.app_data);

        let err = OrderSubmission::builder()
            .order_data(order)
            .signature(signature)
            .from(owner)
            .app_data_json(wrong_json)
            .build()
            .unwrap_err();
        match err {
            Error::OrderCreationInvalid { field, .. } => assert_eq!(field, "app_data"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn builder_rejects_zero_owner() {
        let signer = anvil_signer();
        let owner = alloy_signer::Signer::address(&signer);
        let (order, doc) = fixture_order(owner);
        let domain = Chain::Mainnet.settlement_domain();
        let signature = order
            .sign(EcdsaSigningScheme::Eip712, &domain, &signer)
            .unwrap();

        let err = OrderSubmission::builder()
            .order_data(order)
            .signature(signature)
            .from(Address::ZERO)
            .app_data_doc(&doc)
            .unwrap()
            .build()
            .unwrap_err();
        match err {
            Error::OrderCreationInvalid { field, .. } => assert_eq!(field, "from"),
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
