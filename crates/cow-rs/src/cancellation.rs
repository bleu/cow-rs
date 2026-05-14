//! Off-chain order cancellation.
//!
//! The CoW orderbook exposes two cancel-by-UID flows:
//!
//! - **Single** — [`OrderCancellation`]: a signed `OrderCancellation(bytes orderUid)`
//!   EIP-712 struct.
//! - **Collection** — [`OrderCancellations`]: a signed
//!   `OrderCancellations(bytes[] orderUid)` EIP-712 struct that cancels
//!   many orders in one body.
//!
//! Both flows are "soft" — they remove the order from the matching pool
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
        signature::{EcdsaSignature, SignatureError},
        signing_scheme::EcdsaSigningScheme,
    },
    alloy_primitives::keccak256,
    hex_literal::hex,
    serde::{Deserialize, Serialize},
};

/// Signed cancellation of a single order. Mirrors `cowprotocol/services`
/// `OrderCancellation` exactly so any future on-chain verification path
/// stays interoperable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderCancellation {
    /// UID of the order being cancelled.
    pub order_uid: OrderUid,
    /// ECDSA signature over the EIP-712 struct hash.
    pub signature: EcdsaSignature,
    /// Off-chain ECDSA scheme used to produce the signature.
    pub signing_scheme: EcdsaSigningScheme,
}

impl OrderCancellation {
    /// `keccak256("OrderCancellation(bytes orderUid)")`.
    pub const TYPE_HASH: [u8; 32] =
        hex!("7b41b3a6e2b3cae020a3b2f9cdc997e0d420643957e7fea81747e984e47c88ec");

    /// EIP-712 `hashStruct` for the single-order cancellation type.
    pub fn hash_struct(uid: &OrderUid) -> [u8; 32] {
        let mut hash_data = [0u8; 64];
        hash_data[0..32].copy_from_slice(&Self::TYPE_HASH);
        hash_data[32..64].copy_from_slice(keccak256(uid.0).as_slice());
        *keccak256(hash_data)
    }

    /// Sign a single-order cancellation. The caller chooses the ECDSA
    /// scheme; `EthSign` adds the EIP-191 personal-sign envelope.
    pub fn sign<S: alloy_signer::SignerSync>(
        order_uid: OrderUid,
        scheme: EcdsaSigningScheme,
        domain: &DomainSeparator,
        signer: &S,
    ) -> Result<Self, SignatureError> {
        let signature =
            EcdsaSignature::sign(scheme, domain, &Self::hash_struct(&order_uid), signer)?;
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
        Ok(self
            .signature
            .recover(
                self.signing_scheme,
                domain,
                &Self::hash_struct(&self.order_uid),
            )?
            .signer)
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

impl OrderCancellations {
    /// `keccak256("OrderCancellations(bytes[] orderUid)")` — note the
    /// singular `orderUid` despite the array, matching the canonical
    /// services type string.
    pub const TYPE_HASH: [u8; 32] =
        hex!("4c89efb91ae246f78d2fe68b47db2fa1444a121a4f2dc3fda7a5a408c2e3588e");

    /// EIP-712 `hashStruct` for the collection-cancellation type.
    pub fn hash_struct(&self) -> [u8; 32] {
        let mut encoded = Vec::with_capacity(32 * self.order_uids.len());
        for uid in &self.order_uids {
            encoded.extend_from_slice(keccak256(uid.0).as_slice());
        }
        let array_hash = keccak256(&encoded);

        let mut hash_data = [0u8; 64];
        hash_data[0..32].copy_from_slice(&Self::TYPE_HASH);
        hash_data[32..64].copy_from_slice(array_hash.as_slice());
        *keccak256(hash_data)
    }

    /// Sign the collection with an ECDSA signer.
    pub fn sign<S: alloy_signer::SignerSync>(
        self,
        scheme: EcdsaSigningScheme,
        domain: &DomainSeparator,
        signer: &S,
    ) -> Result<SignedOrderCancellations, SignatureError> {
        let signature = EcdsaSignature::sign(scheme, domain, &self.hash_struct(), signer)?;
        Ok(SignedOrderCancellations {
            order_uids: self.order_uids,
            signature,
            signing_scheme: scheme,
        })
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
        };
        Ok(self
            .signature
            .recover(self.signing_scheme, domain, &payload.hash_struct())?
            .signer)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        alloy_primitives::{B256, U256},
        alloy_signer_local::PrivateKeySigner,
    };

    /// `OrderCancellation::TYPE_HASH` derives from the canonical EIP-712
    /// type signature published in services. A drift in either constant
    /// changes the signed payload for every cancellation.
    #[test]
    fn order_cancellation_type_hash_matches_canonical_signature() {
        let signature = b"OrderCancellation(bytes orderUid)";
        assert_eq!(OrderCancellation::TYPE_HASH, *keccak256(signature));
    }

    /// Locks `OrderCancellations::hash_struct` against the golden vectors
    /// from `cowprotocol/services/.../order.rs::order_cancellations_struct_hash`,
    /// generated via ethers.js as the reference implementation.
    #[test]
    fn order_cancellations_hash_struct_matches_services_golden() {
        let empty = OrderCancellations::default();
        assert_eq!(
            empty.hash_struct(),
            hex!("56acdb3034898c6c23971cb3f92c32a4739e89a13c85282547025583a93911bd")
        );

        let two = OrderCancellations {
            order_uids: vec![OrderUid([0x11; 56]), OrderUid([0x22; 56])],
        };
        assert_eq!(
            two.hash_struct(),
            hex!("405f6cb53d87901a5385a824a99c94b43146547f5ea3623f8d2f50b925e97a8b")
        );
    }

    fn fixed_signer() -> PrivateKeySigner {
        PrivateKeySigner::from_bytes(&U256::from(1u64).to_be_bytes().into()).unwrap()
    }

    /// Sign-and-recover round trip for a single-order cancellation,
    /// covering both ECDSA schemes.
    #[test]
    fn order_cancellation_sign_recover_round_trip() {
        let signer = fixed_signer();
        let domain = DomainSeparator(B256::repeat_byte(0xde).into());
        let uid = OrderUid([0x42; 56]);

        for scheme in [EcdsaSigningScheme::Eip712, EcdsaSigningScheme::EthSign] {
            let cancellation = OrderCancellation::sign(uid, scheme, &domain, &signer).unwrap();
            let recovered = cancellation.recover_owner(&domain).unwrap();
            assert_eq!(recovered, signer.address());
        }
    }

    /// Sign-and-recover round trip for an order-collection cancellation.
    #[test]
    fn order_cancellations_sign_recover_round_trip() {
        let signer = fixed_signer();
        let domain = DomainSeparator(B256::repeat_byte(0xad).into());
        let cancellations = OrderCancellations {
            order_uids: vec![OrderUid([0x11; 56]), OrderUid([0x22; 56])],
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
            order_uids: vec![OrderUid([0x11; 56])],
            signature: EcdsaSignature::default(),
            signing_scheme: EcdsaSigningScheme::Eip712,
        };
        let body = serde_json::to_value(&signed).unwrap();
        assert!(body["orderUids"].is_array());
        assert_eq!(body["signingScheme"], "eip712");
        assert!(body["signature"].as_str().unwrap().starts_with("0x"));
    }
}
