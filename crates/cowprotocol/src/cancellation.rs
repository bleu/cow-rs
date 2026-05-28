//! Off-chain order cancellation.
//!
//! The CoW orderbook exposes two cancel-by-UID flows:
//!
//! - **Single**: [`SignedOrderCancellation`]: a signed `OrderCancellation(bytes orderUid)`
//!   EIP-712 struct.
//! - **Collection**: [`OrderCancellations`]: a signed
//!   `OrderCancellations(bytes[] orderUid)` EIP-712 struct that cancels
//!   many orders in one body.
//!
//! Both flows are "soft": they remove the order from the matching pool
//! but cannot recall an order that is already in flight. For pre-signed
//! orders, cancellation is done on-chain via
//! `GPv2Settlement::setPreSignature(uid, false)`; for EthFlow orders, via
//! `EthFlow::invalidateOrder`. Those are out of scope for this module.
//!
//! Adapted from [`cowprotocol/services`] (MIT OR Apache-2.0).
//!
//! [`cowprotocol/services`]: https://github.com/cowprotocol/services/blob/main/crates/model/src/order.rs

use {
    crate::{
        domain::DomainSeparator,
        order::OrderUid,
        signature::{EcdsaSignature, SignatureError, ecdsa_recover, ecdsa_wire, sign_ecdsa},
        signing_scheme::EcdsaSigningScheme,
    },
    alloy_primitives::{B256, Bytes},
    serde::{Deserialize, Serialize},
};

/// Private `sol!` views of the two cancellation EIP-712 structs. Lives
/// in a sub-module so the generated `pub` types are not part of the
/// crate's public API.
///
/// The Solidity type names and field names are load-bearing: they
/// appear verbatim in the EIP-712 type string the contract verifies.
/// Single-cancel uses singular `orderUid`; the array variant uses
/// plural `orderUids`.
mod eip712 {
    use alloy_sol_types::sol;

    sol! {
        struct OrderCancellation {
            bytes orderUid;
        }

        struct OrderCancellations {
            bytes[] orderUids;
        }
    }
}

/// Signed cancellation of a single order. Mirrors `cowprotocol/services`
/// `OrderCancellation` exactly so any future on-chain verification path
/// stays interoperable.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedOrderCancellation {
    /// UID of the order being cancelled.
    pub order_uid: OrderUid,
    /// ECDSA signature over the EIP-712 struct hash. Wire form is the
    /// 65-byte `0x`-hex `r || s || v` blob, not alloy's default
    /// `{r, s, yParity, v}` map.
    #[serde(with = "ecdsa_wire")]
    pub signature: EcdsaSignature,
    /// Off-chain ECDSA scheme used to produce the signature.
    pub signing_scheme: EcdsaSigningScheme,
}

impl SignedOrderCancellation {
    /// EIP-712 `hashStruct` for the single-order cancellation type.
    /// Delegates to [`alloy_sol_types::SolStruct`] applied to the
    /// private `eip712::OrderCancellation` declaration.
    pub fn hash_struct(uid: &OrderUid) -> B256 {
        use alloy_sol_types::SolStruct;
        eip712::OrderCancellation {
            orderUid: Bytes::from(uid.0),
        }
        .eip712_hash_struct()
    }

    /// Sign a single-order cancellation. The caller chooses the ECDSA
    /// scheme; `EthSign` adds the EIP-191 personal-sign envelope.
    pub fn sign<S: alloy_signer::SignerSync>(
        order_uid: OrderUid,
        scheme: EcdsaSigningScheme,
        domain: &DomainSeparator,
        signer: &S,
    ) -> Result<Self, SignatureError> {
        let payload = eip712::OrderCancellation {
            orderUid: Bytes::from(order_uid.0),
        };
        let signature = sign_ecdsa(scheme, domain, &payload, signer)?;
        Ok(Self {
            order_uid,
            signature,
            signing_scheme: scheme,
        })
    }

    /// Recover the signing owner from this cancellation, given the
    /// chain's domain separator.
    pub fn recover_owner(
        &self,
        domain: &DomainSeparator,
    ) -> Result<alloy_primitives::Address, SignatureError> {
        let payload = eip712::OrderCancellation {
            orderUid: Bytes::from(self.order_uid.0),
        };
        Ok(ecdsa_recover(&self.signature, self.signing_scheme, domain, &payload)?.signer)
    }
}

/// Unsigned collection of order UIDs to cancel.
///
/// Use [`OrderCancellations::sign`] to produce a [`SignedOrderCancellations`]
/// suitable for `DELETE /api/v1/orders`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderCancellations {
    /// UIDs of the orders being cancelled.
    pub order_uids: Vec<OrderUid>,
}

impl From<Vec<OrderUid>> for OrderCancellations {
    fn from(order_uids: Vec<OrderUid>) -> Self {
        Self { order_uids }
    }
}

impl FromIterator<OrderUid> for OrderCancellations {
    fn from_iter<I: IntoIterator<Item = OrderUid>>(iter: I) -> Self {
        Self {
            order_uids: iter.into_iter().collect(),
        }
    }
}

impl IntoIterator for OrderCancellations {
    type Item = OrderUid;
    type IntoIter = std::vec::IntoIter<OrderUid>;

    fn into_iter(self) -> Self::IntoIter {
        self.order_uids.into_iter()
    }
}

impl OrderCancellations {
    /// EIP-712 `hashStruct` for the collection-cancellation type.
    /// Delegates to [`alloy_sol_types::SolStruct`] applied to the
    /// private `eip712::OrderCancellations` declaration.
    pub fn hash_struct(&self) -> B256 {
        use alloy_sol_types::SolStruct;
        eip712::OrderCancellations {
            orderUids: self.order_uids.iter().map(|u| Bytes::from(u.0)).collect(),
        }
        .eip712_hash_struct()
    }

    /// Sign the collection with an ECDSA signer.
    pub fn sign<S: alloy_signer::SignerSync>(
        self,
        scheme: EcdsaSigningScheme,
        domain: &DomainSeparator,
        signer: &S,
    ) -> Result<SignedOrderCancellations, SignatureError> {
        let payload = self.eip712_payload();
        let signature = sign_ecdsa(scheme, domain, &payload, signer)?;
        Ok(SignedOrderCancellations {
            order_uids: self.order_uids,
            signature,
            signing_scheme: scheme,
        })
    }

    fn eip712_payload(&self) -> eip712::OrderCancellations {
        eip712::OrderCancellations {
            orderUids: self.order_uids.iter().map(|u| Bytes::from(u.0)).collect(),
        }
    }
}

/// Body of `DELETE /api/v1/orders`: the cancellation collection together
/// with the owner's ECDSA signature over its EIP-712 struct hash.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedOrderCancellations {
    /// UIDs of the orders being cancelled.
    pub order_uids: Vec<OrderUid>,
    /// ECDSA signature over the EIP-712 hash of the cancellation struct.
    /// Wire form is the 65-byte `0x`-hex `r || s || v` blob.
    #[serde(with = "ecdsa_wire")]
    pub signature: EcdsaSignature,
    /// Off-chain ECDSA scheme used to produce the signature.
    pub signing_scheme: EcdsaSigningScheme,
}

impl SignedOrderCancellations {
    /// Recover the signing owner.
    pub fn recover_owner(
        &self,
        domain: &DomainSeparator,
    ) -> Result<alloy_primitives::Address, SignatureError> {
        let payload = OrderCancellations {
            order_uids: self.order_uids.clone(),
        }
        .eip712_payload();
        Ok(ecdsa_recover(&self.signature, self.signing_scheme, domain, &payload)?.signer)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        alloy_primitives::{U256, b256, keccak256},
        alloy_signer_local::PrivateKeySigner,
    };

    /// Locks the [`eip712::OrderCancellation`] `typeHash` against the
    /// canonical EIP-712 type signature published in services. A drift
    /// in the `sol!` declaration would change every outstanding
    /// signature.
    #[test]
    fn order_cancellation_type_hash_matches_canonical_signature() {
        use alloy_sol_types::SolStruct;

        let signature = b"OrderCancellation(bytes orderUid)";
        let sol = eip712::OrderCancellation {
            orderUid: Bytes::copy_from_slice(&[0u8; 56]),
        };
        assert_eq!(
            <eip712::OrderCancellation as SolStruct>::eip712_type_hash(&sol),
            keccak256(signature),
        );
    }

    /// Same lock for the array variant. The contract type string uses
    /// plural `orderUids`.
    #[test]
    fn order_cancellations_type_hash_matches_canonical_signature() {
        use alloy_sol_types::SolStruct;

        let signature = b"OrderCancellations(bytes[] orderUids)";
        let sol = eip712::OrderCancellations { orderUids: vec![] };
        assert_eq!(
            <eip712::OrderCancellations as SolStruct>::eip712_type_hash(&sol),
            keccak256(signature),
        );
    }

    /// Locks `OrderCancellations::hash_struct` against the golden vectors
    /// from `cowprotocol/services/.../order.rs::order_cancellations_struct_hash`,
    /// generated via ethers.js as the reference implementation.
    #[test]
    fn order_cancellations_hash_struct_matches_services_golden() {
        let empty = OrderCancellations::default();
        assert_eq!(
            empty.hash_struct(),
            b256!("56acdb3034898c6c23971cb3f92c32a4739e89a13c85282547025583a93911bd")
        );

        let two = OrderCancellations {
            order_uids: vec![OrderUid::from([0x11; 56]), OrderUid::from([0x22; 56])],
        };
        assert_eq!(
            two.hash_struct(),
            b256!("405f6cb53d87901a5385a824a99c94b43146547f5ea3623f8d2f50b925e97a8b")
        );
    }

    /// Locks `SignedOrderCancellation::hash_struct` against an independent
    /// re-derivation of the EIP-712 `hashStruct` for the single dynamic
    /// `bytes orderUid` field, computed by hand with raw `keccak256` rather
    /// than going through alloy's [`alloy_sol_types::SolStruct`].
    ///
    /// This is NOT an external ethers.js / services golden: it is an
    /// independent EIP-712 re-derivation. Per EIP-712 a dynamic `bytes`
    /// member is encoded as its `keccak256`, so
    /// `hashStruct = keccak256(typeHash ++ keccak256(orderUid))`, with
    /// `typeHash = keccak256("OrderCancellation(bytes orderUid)")` (the
    /// internal `sol!` type string, not the renamed Rust type). Locking the
    /// `SolStruct` path against this hand rolled form catches drift in the
    /// generated encoding without inventing a value we cannot verify.
    #[test]
    fn order_cancellation_hash_struct_matches_independent_eip712_derivation() {
        let type_hash = keccak256(b"OrderCancellation(bytes orderUid)");

        for uid in [OrderUid::from([0u8; 56]), OrderUid::from([0x42; 56])] {
            let mut encoded = [0u8; 64];
            encoded[0..32].copy_from_slice(type_hash.as_slice());
            encoded[32..64].copy_from_slice(keccak256(uid.as_slice()).as_slice());
            let expected = keccak256(encoded);

            assert_eq!(SignedOrderCancellation::hash_struct(&uid), expected);
        }
    }

    fn fixed_signer() -> PrivateKeySigner {
        PrivateKeySigner::from_bytes(&U256::from(1u64).to_be_bytes().into()).unwrap()
    }

    /// Synthetic but valid `Eip712Domain` for tests: the round-trip
    /// behaviour depends only on the domain being consistent between
    /// sign and recover, not on it matching a real chain.
    fn fixed_domain() -> DomainSeparator {
        crate::domain::settlement_domain(
            1,
            alloy_primitives::address!("9008D19f58AAbD9eD0D60971565AA8510560ab41"),
        )
    }

    /// Sign-and-recover round trip for a single-order cancellation,
    /// covering both ECDSA schemes.
    #[test]
    fn order_cancellation_sign_recover_round_trip() {
        let signer = fixed_signer();
        let domain = fixed_domain();
        let uid = OrderUid::from([0x42; 56]);

        for scheme in [EcdsaSigningScheme::Eip712, EcdsaSigningScheme::EthSign] {
            let cancellation = SignedOrderCancellation::sign(uid, scheme, &domain, &signer).unwrap();
            let recovered = cancellation.recover_owner(&domain).unwrap();
            assert_eq!(recovered, signer.address());
        }
    }

    /// Sign-and-recover round trip for an order-collection cancellation.
    #[test]
    fn order_cancellations_sign_recover_round_trip() {
        let signer = fixed_signer();
        let domain = fixed_domain();
        let cancellations = OrderCancellations {
            order_uids: vec![OrderUid::from([0x11; 56]), OrderUid::from([0x22; 56])],
        };
        let signed = cancellations
            .sign(EcdsaSigningScheme::Eip712, &domain, &signer)
            .unwrap();
        let recovered = signed.recover_owner(&domain).unwrap();
        assert_eq!(recovered, signer.address());
    }

    /// `SignedOrderCancellations` serialises to the flat wire shape expected
    /// by `DELETE /api/v1/orders`: `orderUids` array, `signature` hex, and
    /// `signingScheme` lowercase.
    #[test]
    fn signed_cancellations_wire_format() {
        let signed = SignedOrderCancellations {
            order_uids: vec![OrderUid::from([0x11; 56])],
            signature: EcdsaSignature::from_bytes_and_parity(&[0u8; 64], false),
            signing_scheme: EcdsaSigningScheme::Eip712,
        };
        let body = serde_json::to_value(&signed).unwrap();
        assert!(body["orderUids"].is_array());
        assert_eq!(body["signingScheme"], "eip712");
        assert!(body["signature"].as_str().unwrap().starts_with("0x"));
    }

    /// `SignedOrderCancellation` round-trips through JSON: serialise, deserialise,
    /// compare. Lets wasm callers (and any other JSON consumer) hand the
    /// type back and forth without losing fields.
    #[test]
    fn order_cancellation_json_round_trip() {
        let original = SignedOrderCancellation::sign(
            OrderUid::from([0x77; 56]),
            EcdsaSigningScheme::Eip712,
            &fixed_domain(),
            &fixed_signer(),
        )
        .unwrap();
        let json = serde_json::to_string(&original).unwrap();
        let parsed: SignedOrderCancellation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, original);
        // Wire keys are camelCase, matching the orderbook OpenAPI.
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(value.get("orderUid").is_some());
        assert!(value.get("signingScheme").is_some());
    }

    /// `OrderCancellations` is the unsigned collection (just the UIDs).
    /// JSON round-trip ensures `serde_with` adapters around `OrderUid`
    /// stay symmetric across serialise / deserialise.
    #[test]
    fn order_cancellations_json_round_trip() {
        let original = OrderCancellations {
            order_uids: vec![OrderUid::from([0x01; 56]), OrderUid::from([0x02; 56])],
        };
        let json = serde_json::to_string(&original).unwrap();
        let parsed: OrderCancellations = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, original);
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(value.get("orderUids").is_some());
    }

    /// `SignedOrderCancellations` is the body of `DELETE /api/v1/orders`.
    /// Same round-trip pattern as the single-order case: serialise into
    /// camelCase JSON, deserialise back, assert byte equality plus a
    /// shape sanity check on the wire keys.
    #[test]
    fn signed_order_cancellations_json_round_trip() {
        let original = OrderCancellations {
            order_uids: vec![OrderUid::from([0x33; 56]), OrderUid::from([0x44; 56])],
        }
        .sign(
            EcdsaSigningScheme::EthSign,
            &fixed_domain(),
            &fixed_signer(),
        )
        .unwrap();
        let json = serde_json::to_string(&original).unwrap();
        let parsed: SignedOrderCancellations = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, original);
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(value.get("orderUids").is_some());
        assert!(value.get("signature").is_some());
        assert!(value.get("signingScheme").is_some());
    }
}
