//! Order signatures.
//!
//! Every order is authenticated by a [`Signature`], which is one of four
//! schemes: two off-chain ECDSA variants (`EIP-712` typed data and
//! `EthSign` personal-sign), one smart-contract scheme (`EIP-1271`), and
//! one purely on-chain scheme (`PreSign`). The orderbook serialises the
//! choice as a `signingScheme` field alongside the signature bytes.
//!
//! Adapted from [`cowprotocol/services`] (MIT OR Apache-2.0).
//!
//! [`cowprotocol/services`]: https://github.com/cowprotocol/services/blob/main/crates/model/src/signature.rs

use alloy_primitives::{Address, B256, Signature as PrimSignature};
use alloy_signer::{SignerSync, k256::ecdsa::Error as K256Error};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::fmt::{self, Debug, Formatter};

use crate::domain::{DomainSeparator, hashed_eip712_message, hashed_ethsign_message};
use crate::signing_scheme::{EcdsaSigningScheme, SigningScheme};

/// Errors specific to signature parsing or verification.
#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    /// ECDSA signature payload was the wrong length (must be 65 bytes:
    /// `r || s || v`).
    #[error("expected 65 ecdsa signature bytes, got {0}")]
    Length(usize),
    /// PreSign payload was non-empty and not the legacy 20-byte owner.
    #[error("presign payload must be empty or a 20-byte owner, got {0} bytes")]
    PreSignLength(usize),
    /// The `v` recovery byte was not in `{0, 1, 27, 28}`.
    #[error("invalid signature v value: {0}; expected 0, 1, 27 or 28")]
    InvalidV(u8),
    /// ECDSA recovery failed (malformed signature bytes).
    #[error("ecdsa recovery failed: {0}")]
    Recovery(#[from] alloy_primitives::SignatureError),
    /// Underlying signer reported a `k256` error during signing.
    #[error("k256 signer error: {0}")]
    Signer(#[from] K256Error),
}

/// Off-chain or on-chain signature over the EIP-712 order hash.
#[derive(Clone, Eq, PartialEq, Hash)]
pub enum Signature {
    /// EIP-712 typed-data signature.
    Eip712(EcdsaSignature),
    /// EIP-191 personal-sign over the EIP-712 hash.
    EthSign(EcdsaSignature),
    /// EIP-1271 contract signature payload.
    Eip1271(Vec<u8>),
    /// On-chain pre-signature recorded via `GPv2Signing::setPreSignature`.
    PreSign,
}

impl Default for Signature {
    fn default() -> Self {
        Self::Eip712(EcdsaSignature::default())
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::PreSign => f.write_str("PreSign"),
            other => {
                let scheme = format!("{:?}", other.scheme());
                let bytes = const_hex::encode_prefixed(other.to_bytes());
                f.debug_tuple(&scheme).field(&bytes).finish()
            }
        }
    }
}

impl Signature {
    /// Build the default signature payload for `scheme`.
    pub fn default_with(scheme: SigningScheme) -> Self {
        match scheme {
            SigningScheme::Eip712 => Self::Eip712(EcdsaSignature::default()),
            SigningScheme::EthSign => Self::EthSign(EcdsaSignature::default()),
            SigningScheme::Eip1271 => Self::Eip1271(Vec::new()),
            SigningScheme::PreSign => Self::PreSign,
        }
    }

    /// Which signing scheme this signature corresponds to.
    pub const fn scheme(&self) -> SigningScheme {
        match self {
            Self::Eip712(_) => SigningScheme::Eip712,
            Self::EthSign(_) => SigningScheme::EthSign,
            Self::Eip1271(_) => SigningScheme::Eip1271,
            Self::PreSign => SigningScheme::PreSign,
        }
    }

    /// Encode the signature as the bytes the orderbook expects in the
    /// `signature` field of `POST /api/v1/orders` / `DELETE /api/v1/orders`.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Eip712(s) | Self::EthSign(s) => s.to_bytes().to_vec(),
            Self::Eip1271(bytes) => bytes.clone(),
            Self::PreSign => Vec::new(),
        }
    }

    /// Decode a signature received over the wire.
    ///
    /// For [`SigningScheme::PreSign`] the body must be empty or exactly the
    /// owner address (legacy 20-byte encoding accepted by services).
    pub fn from_bytes(scheme: SigningScheme, bytes: &[u8]) -> Result<Self, SignatureError> {
        match scheme {
            scheme @ (SigningScheme::Eip712 | SigningScheme::EthSign) => {
                let bytes: [u8; 65] = bytes
                    .try_into()
                    .map_err(|_| SignatureError::Length(bytes.len()))?;
                Ok(EcdsaSignature::from_bytes(&bytes)?.to_signature(
                    scheme
                        .try_to_ecdsa_scheme()
                        .expect("scheme is an ecdsa scheme"),
                ))
            }
            SigningScheme::Eip1271 => Ok(Self::Eip1271(bytes.to_vec())),
            SigningScheme::PreSign => {
                if !(bytes.is_empty() || bytes.len() == 20) {
                    return Err(SignatureError::PreSignLength(bytes.len()));
                }
                Ok(Self::PreSign)
            }
        }
    }

    /// Recover the signing owner of an ECDSA signature.
    ///
    /// Returns `Ok(None)` for [`Signature::Eip1271`] and
    /// [`Signature::PreSign`]: those schemes carry the owner explicitly,
    /// they do not derive it.
    pub fn recover(
        &self,
        domain_separator: &DomainSeparator,
        struct_hash: &[u8; 32],
    ) -> Result<Option<Recovered>, SignatureError> {
        match self {
            Self::Eip712(s) => Ok(Some(s.recover(
                EcdsaSigningScheme::Eip712,
                domain_separator,
                struct_hash,
            )?)),
            Self::EthSign(s) => Ok(Some(s.recover(
                EcdsaSigningScheme::EthSign,
                domain_separator,
                struct_hash,
            )?)),
            Self::Eip1271(_) | Self::PreSign => Ok(None),
        }
    }
}

/// 32-byte signing message together with the address that produced it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Recovered {
    /// The 32-byte message that was actually signed (post-EIP-191 wrapping
    /// for `EthSign`, plain typed-data hash for `Eip712`).
    pub message: B256,
    /// Address recovered from the signature.
    pub signer: Address,
}

/// Raw ECDSA signature: `r || s || v` (65 bytes).
///
/// `v` is normalised to `27` or `28` at construction time for compatibility
/// with Solidity's `ecrecover`.
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct EcdsaSignature {
    /// `r` component, 32 bytes big-endian.
    pub r: B256,
    /// `s` component, 32 bytes big-endian.
    pub s: B256,
    /// Recovery byte, normalised to `27` or `28`.
    pub v: u8,
}

impl Default for EcdsaSignature {
    fn default() -> Self {
        // `v = 27` is the normalised form of `v = 0`. Solidity's `ecrecover`
        // rejects `v = 0` outright.
        Self {
            r: B256::ZERO,
            s: B256::ZERO,
            v: 27,
        }
    }
}

impl Debug for EcdsaSignature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaSignature")
            .field("bytes", &const_hex::encode_prefixed(self.to_bytes()))
            .finish()
    }
}

impl EcdsaSignature {
    /// Promote this ECDSA signature into a typed [`Signature`].
    pub const fn to_signature(self, scheme: EcdsaSigningScheme) -> Signature {
        match scheme {
            EcdsaSigningScheme::Eip712 => Signature::Eip712(self),
            EcdsaSigningScheme::EthSign => Signature::EthSign(self),
        }
    }

    /// Encode as `r || s || v` (65 bytes).
    pub fn to_bytes(self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[..32].copy_from_slice(self.r.as_slice());
        out[32..64].copy_from_slice(self.s.as_slice());
        out[64] = self.v;
        out
    }

    /// Decode an `r || s || v` (65-byte) payload, normalising `v` to `27`
    /// or `28`.
    pub fn from_bytes(bytes: &[u8; 65]) -> Result<Self, SignatureError> {
        let v = bytes[64];
        let normalised_v = match v {
            0 | 27 => 27,
            1 | 28 => 28,
            invalid => return Err(SignatureError::InvalidV(invalid)),
        };
        Ok(Self {
            r: B256::from_slice(&bytes[..32]),
            s: B256::from_slice(&bytes[32..64]),
            v: normalised_v,
        })
    }

    /// Recover the signer address from this signature.
    ///
    /// `signing_scheme` determines whether the EIP-712 typed-data hash or
    /// the EthSign-wrapped variant is used as the recovery message.
    pub fn recover(
        &self,
        signing_scheme: EcdsaSigningScheme,
        domain_separator: &DomainSeparator,
        struct_hash: &[u8; 32],
    ) -> Result<Recovered, SignatureError> {
        let message = hashed_signing_message(signing_scheme, domain_separator, struct_hash);
        let signature = PrimSignature::from_raw(&self.to_bytes())?;
        let signer = signature.recover_address_from_prehash(&message)?;
        Ok(Recovered { message, signer })
    }

    /// Sign the order's `struct_hash` with a `SignerSync`-implementing
    /// signer (e.g. `alloy_signer_local::PrivateKeySigner`).
    pub fn sign<S: SignerSync>(
        signing_scheme: EcdsaSigningScheme,
        domain_separator: &DomainSeparator,
        struct_hash: &[u8; 32],
        signer: &S,
    ) -> Result<Self, SignatureError> {
        let message = hashed_signing_message(signing_scheme, domain_separator, struct_hash);
        let raw = signer.sign_hash_sync(&message).map_err(|e| match e {
            alloy_signer::Error::Ecdsa(k) => SignatureError::Signer(k),
            other => SignatureError::Recovery(alloy_primitives::SignatureError::FromBytes(
                format!("{other}").leak(),
            )),
        })?;
        Self::from_bytes(&raw.as_bytes())
    }
}

fn hashed_signing_message(
    signing_scheme: EcdsaSigningScheme,
    domain_separator: &DomainSeparator,
    struct_hash: &[u8; 32],
) -> B256 {
    match signing_scheme {
        EcdsaSigningScheme::Eip712 => hashed_eip712_message(domain_separator, struct_hash),
        EcdsaSigningScheme::EthSign => hashed_ethsign_message(domain_separator, struct_hash),
    }
}

// --- serde --------------------------------------------------------------

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsonSignature {
    signing_scheme: SigningScheme,
    signature: HexBytes,
}

#[derive(Default)]
struct HexBytes(Vec<u8>);

impl Serialize for HexBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        crate::bytes_hex::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for HexBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        crate::bytes_hex::deserialize(deserializer).map(Self)
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        JsonSignature {
            signing_scheme: self.scheme(),
            signature: HexBytes(self.to_bytes()),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let json = JsonSignature::deserialize(deserializer)?;
        Self::from_bytes(json.signing_scheme, &json.signature.0).map_err(de::Error::custom)
    }
}

impl Serialize for EcdsaSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = [0u8; 2 + 65 * 2];
        bytes[..2].copy_from_slice(b"0x");
        const_hex::encode_to_slice(self.to_bytes(), &mut bytes[2..]).unwrap();
        serializer.serialize_str(std::str::from_utf8(&bytes).unwrap())
    }
}

impl<'de> Deserialize<'de> for EcdsaSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;
        impl de::Visitor<'_> for Visitor {
            type Value = EcdsaSignature;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an 0x-prefixed 65-byte ecdsa signature (r||s||v)")
            }

            fn visit_str<E>(self, s: &str) -> Result<EcdsaSignature, E>
            where
                E: de::Error,
            {
                let s = s
                    .strip_prefix("0x")
                    .ok_or_else(|| de::Error::custom("missing 0x prefix"))?;
                let mut bytes = [0u8; 65];
                const_hex::decode_to_slice(s, &mut bytes).map_err(de::Error::custom)?;
                EcdsaSignature::from_bytes(&bytes).map_err(de::Error::custom)
            }
        }
        deserializer.deserialize_str(Visitor)
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{U256, hex};
    use alloy_signer_local::PrivateKeySigner;
    use serde_json::json;

    use super::*;

    #[test]
    fn from_bytes_rejects_wrong_lengths() {
        assert!(matches!(
            Signature::from_bytes(SigningScheme::Eip712, &[0u8; 20]),
            Err(SignatureError::Length(20))
        ));
        assert!(matches!(
            Signature::from_bytes(SigningScheme::PreSign, &[0u8; 32]),
            Err(SignatureError::PreSignLength(32))
        ));
    }

    #[test]
    fn ecdsa_default_zero_signature_round_trips() {
        let sig = Signature::from_bytes(SigningScheme::Eip712, &[0u8; 65]).unwrap();
        assert_eq!(sig, Signature::default_with(SigningScheme::Eip712));
    }

    #[test]
    fn presign_accepts_empty_and_legacy_20_byte_payloads() {
        assert_eq!(
            Signature::from_bytes(SigningScheme::PreSign, &[]).unwrap(),
            Signature::PreSign
        );
        assert_eq!(
            Signature::from_bytes(SigningScheme::PreSign, &[0xff; 20]).unwrap(),
            Signature::PreSign
        );
    }

    #[test]
    fn v_normalisation_matches_services() {
        for (raw, expected) in [(0u8, 27u8), (1, 28), (27, 27), (28, 28)] {
            let mut bytes = [0u8; 65];
            bytes[64] = raw;
            let sig = EcdsaSignature::from_bytes(&bytes).unwrap();
            assert_eq!(sig.v, expected);
            assert_eq!(sig.to_bytes()[64], expected);
        }
    }

    #[test]
    fn invalid_v_rejected() {
        for invalid_v in [2u8, 3, 26, 29, 30, 255] {
            let mut bytes = [0u8; 65];
            bytes[64] = invalid_v;
            assert!(matches!(
                EcdsaSignature::from_bytes(&bytes),
                Err(SignatureError::InvalidV(v)) if v == invalid_v
            ));
        }
    }

    #[test]
    fn json_round_trip_for_each_scheme() {
        for (signature, expected_json) in [
            (
                Signature::Eip1271(vec![1, 2, 3]),
                json!({ "signingScheme": "eip1271", "signature": "0x010203" }),
            ),
            (
                Signature::Eip1271(Vec::new()),
                json!({ "signingScheme": "eip1271", "signature": "0x" }),
            ),
            (
                Signature::PreSign,
                json!({ "signingScheme": "presign", "signature": "0x" }),
            ),
        ] {
            let serialised = serde_json::to_value(&signature).unwrap();
            assert_eq!(serialised, expected_json);
            let parsed: Signature = serde_json::from_value(expected_json).unwrap();
            assert_eq!(parsed, signature);
        }
    }

    /// Sign-and-recover round trip for both ECDSA schemes against the
    /// `alloy_signer_local::PrivateKeySigner` reference implementation.
    /// Mirrors `cowprotocol/services/.../signature.rs::test_ecdsa_signature_recovery`.
    #[test]
    fn ecdsa_sign_recover_round_trip() {
        let signer = PrivateKeySigner::from_bytes(&U256::from(1u64).to_be_bytes().into()).unwrap();
        let address = signer.address();

        let domain = DomainSeparator(hex!(
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        ));
        let struct_hash = hex!("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

        for scheme in [EcdsaSigningScheme::Eip712, EcdsaSigningScheme::EthSign] {
            let ecdsa = EcdsaSignature::sign(scheme, &domain, &struct_hash, &signer).unwrap();
            let typed = ecdsa.to_signature(scheme);
            let recovered = typed.recover(&domain, &struct_hash).unwrap().unwrap();
            assert_eq!(recovered.signer, address);
        }
    }

    #[test]
    fn recover_returns_none_for_onchain_schemes() {
        for signature in [Signature::PreSign, Signature::Eip1271(Vec::new())] {
            let recovered = signature
                .recover(&DomainSeparator::default(), &[0u8; 32])
                .unwrap();
            assert!(recovered.is_none());
        }
    }
}
