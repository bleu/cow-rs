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

use alloy_primitives::{
    Address, B256, Bytes, FixedBytes, Signature as PrimSignature, eip191_hash_message,
};
use alloy_signer::{SignerSync, k256::ecdsa::Error as K256Error};
use alloy_sol_types::SolStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::fmt::{self, Debug, Formatter};

use crate::domain::DomainSeparator;
use crate::signing_scheme::{EcdsaSigningScheme, SigningScheme};

/// Maximum accepted EIP-1271 payload, in bytes. Matches the
/// `cowprotocol/services` cap (32 KiB); a hostile orderbook could
/// otherwise return a multi-MB payload that buffers as a `Vec<u8>`.
pub const EIP1271_MAX_LEN: usize = 32 * 1024;

/// Errors specific to signature parsing or verification.
#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    /// ECDSA payload was not 65 bytes (`r || s || v`).
    #[error("expected 65 ecdsa signature bytes, got {0}")]
    Length(usize),
    /// PreSign payload was neither empty nor a 20-byte owner.
    #[error("presign payload must be empty or a 20-byte owner, got {0} bytes")]
    PreSignLength(usize),
    /// EIP-1271 payload exceeded [`EIP1271_MAX_LEN`].
    #[error("eip1271 signature payload too long: {len} bytes (max {max})")]
    Eip1271TooLong {
        /// Observed payload length, in bytes.
        len: usize,
        /// Configured cap (`EIP1271_MAX_LEN`).
        max: usize,
    },
    /// `v` recovery byte was not in `{0, 1, 27, 28}`.
    #[error("invalid signature v value: {0}; expected 0, 1, 27 or 28")]
    InvalidV(u8),
    /// ECDSA recovery failed.
    #[error("ecdsa recovery failed: {0}")]
    Recovery(#[from] alloy_primitives::SignatureError),
    /// `k256` signer error.
    #[error("k256 signer error: {0}")]
    Signer(#[from] K256Error),
    /// Non-`k256` signer error (remote signer, hardware wallet, KMS).
    /// Owned message so attacker-controllable bytes are never leaked.
    #[error("signer error: {0}")]
    SignerOther(String),
    /// Recovered signer ≠ declared. Raised by
    /// [`crate::OrderCreation::verify_owner`].
    #[error("signer mismatch: declared {declared}, recovered {recovered}")]
    SignerMismatch {
        /// Owner the order claims to be signed by.
        declared: Address,
        /// Owner recovered from the signature bytes.
        recovered: Address,
    },
}

/// Signature over the EIP-712 order hash.
#[derive(Clone, Eq, PartialEq, Hash)]
pub enum Signature {
    /// EIP-712 typed-data signature.
    Eip712(EcdsaSignature),
    /// EIP-191 personal-sign over the EIP-712 hash.
    EthSign(EcdsaSignature),
    /// EIP-1271 contract signature payload.
    Eip1271(Vec<u8>),
    /// On-chain pre-signature via `GPv2Signing::setPreSignature`.
    PreSign,
}

impl Debug for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::PreSign => f.write_str("PreSign"),
            other => {
                let scheme = format!("{:?}", other.scheme());
                let bytes = Bytes::from(other.to_bytes()).to_string();
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
            SigningScheme::Eip712 => {
                Ok(EcdsaSignature::from_bytes(bytes)?.into_signature(EcdsaSigningScheme::Eip712))
            }
            SigningScheme::EthSign => {
                Ok(EcdsaSignature::from_bytes(bytes)?.into_signature(EcdsaSigningScheme::EthSign))
            }
            SigningScheme::Eip1271 => {
                if bytes.len() > EIP1271_MAX_LEN {
                    return Err(SignatureError::Eip1271TooLong {
                        len: bytes.len(),
                        max: EIP1271_MAX_LEN,
                    });
                }
                Ok(Self::Eip1271(bytes.to_vec()))
            }
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
    pub fn recover<T: SolStruct>(
        &self,
        domain: &DomainSeparator,
        payload: &T,
    ) -> Result<Option<Recovered>, SignatureError> {
        match self {
            Self::Eip712(s) => Ok(Some(s.recover(
                EcdsaSigningScheme::Eip712,
                domain,
                payload,
            )?)),
            Self::EthSign(s) => Ok(Some(s.recover(
                EcdsaSigningScheme::EthSign,
                domain,
                payload,
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
            .field("bytes", &FixedBytes::from(self.to_bytes()).to_string())
            .finish()
    }
}

impl EcdsaSignature {
    /// Promote this ECDSA signature into a typed [`Signature`]. Consumes
    /// `self`, hence the `into_` prefix per Rust API conventions.
    pub const fn into_signature(self, scheme: EcdsaSigningScheme) -> Signature {
        match scheme {
            EcdsaSigningScheme::Eip712 => Signature::Eip712(self),
            EcdsaSigningScheme::EthSign => Signature::EthSign(self),
        }
    }

    /// Encode as `r || s || v` (65 bytes).
    pub fn to_bytes(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[..32].copy_from_slice(self.r.as_slice());
        out[32..64].copy_from_slice(self.s.as_slice());
        out[64] = self.v;
        out
    }

    /// Decode an `r || s || v` (65-byte) payload, normalising `v` to `27`
    /// or `28`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        if bytes.len() != 65 {
            return Err(SignatureError::Length(bytes.len()));
        }
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
    pub fn recover<T: SolStruct>(
        &self,
        signing_scheme: EcdsaSigningScheme,
        domain: &DomainSeparator,
        payload: &T,
    ) -> Result<Recovered, SignatureError> {
        let message = signing_message(signing_scheme, domain, payload);
        let signature = PrimSignature::from_raw(&self.to_bytes())?;
        let signer = signature.recover_address_from_prehash(&message)?;
        Ok(Recovered { message, signer })
    }

    /// Sign an EIP-712 [`SolStruct`] payload with a
    /// `SignerSync`-implementing signer (e.g.
    /// `alloy_signer_local::PrivateKeySigner`).
    pub fn sign<T: SolStruct, S: SignerSync>(
        signing_scheme: EcdsaSigningScheme,
        domain: &DomainSeparator,
        payload: &T,
        signer: &S,
    ) -> Result<Self, SignatureError> {
        let message = signing_message(signing_scheme, domain, payload);
        let raw = signer.sign_hash_sync(&message).map_err(|e| match e {
            alloy_signer::Error::Ecdsa(k) => SignatureError::Signer(k),
            other => SignatureError::SignerOther(other.to_string()),
        })?;
        Self::from_bytes(&raw.as_bytes())
    }
}

/// Compute the message bytes the owner actually signs for the given
/// scheme. `Eip712` returns the typed-data hash supplied directly by
/// [`SolStruct::eip712_signing_hash`]; `EthSign` wraps that hash in the
/// EIP-191 personal-sign envelope via
/// [`alloy_primitives::eip191_hash_message`].
fn signing_message<T: SolStruct>(
    signing_scheme: EcdsaSigningScheme,
    domain: &DomainSeparator,
    payload: &T,
) -> B256 {
    let eip712 = payload.eip712_signing_hash(domain);
    match signing_scheme {
        EcdsaSigningScheme::Eip712 => eip712,
        EcdsaSigningScheme::EthSign => eip191_hash_message(eip712),
    }
}

// --- serde --------------------------------------------------------------

/// Serde-only wire shape: `{ signingScheme, signature: "0x..." }`. The
/// `signature` payload reuses `alloy_primitives::Bytes`, whose serde
/// emits / accepts `0x`-prefixed hex; the EIP-1271 length cap is
/// enforced post-decode by [`Signature::from_bytes`].
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsonSignature {
    signing_scheme: SigningScheme,
    signature: Bytes,
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        JsonSignature {
            signing_scheme: self.scheme(),
            signature: Bytes::from(self.to_bytes()),
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
        Self::from_bytes(json.signing_scheme, &json.signature).map_err(de::Error::custom)
    }
}

impl Serialize for EcdsaSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        FixedBytes::from(self.to_bytes()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EcdsaSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = FixedBytes::<65>::deserialize(deserializer)?;
        Self::from_bytes(bytes.as_slice()).map_err(de::Error::custom)
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
    fn eip1271_rejects_oversize_payload() {
        let oversize = vec![0u8; EIP1271_MAX_LEN + 1];
        assert!(matches!(
            Signature::from_bytes(SigningScheme::Eip1271, &oversize),
            Err(SignatureError::Eip1271TooLong { len, max })
                if len == EIP1271_MAX_LEN + 1 && max == EIP1271_MAX_LEN
        ));
        let at_limit = vec![0u8; EIP1271_MAX_LEN];
        assert!(Signature::from_bytes(SigningScheme::Eip1271, &at_limit).is_ok());
    }

    #[test]
    fn deserialize_rejects_oversize_eip1271_payload() {
        // One byte over the EIP-1271 cap, expressed as hex. The
        // post-decode chokepoint in `Signature::from_bytes` must reject
        // it, surfaced through `serde_json::from_value` as a custom
        // error referencing the cap.
        let oversize_hex = format!("0x{}", "00".repeat(EIP1271_MAX_LEN + 1));
        let body = json!({
            "signingScheme": "eip1271",
            "signature": oversize_hex,
        });
        let err = serde_json::from_value::<Signature>(body)
            .expect_err("oversize signature payload must be rejected on deserialise");
        let msg = err.to_string();
        assert!(
            msg.contains("eip1271 signature payload too long"),
            "error should reference the EIP-1271 length cap, got: {msg}"
        );

        // The same payload encoded one byte under the cap still decodes
        // (decoding produces an all-zero EIP-1271 blob, valid per
        // `from_bytes`'s length-only check).
        let at_limit_hex = format!("0x{}", "00".repeat(EIP1271_MAX_LEN));
        let body = json!({
            "signingScheme": "eip1271",
            "signature": at_limit_hex,
        });
        let sig: Signature = serde_json::from_value(body).unwrap();
        assert!(matches!(sig, Signature::Eip1271(ref b) if b.len() == EIP1271_MAX_LEN));
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

    alloy_sol_types::sol! {
        /// Minimal `SolStruct` view used only by the tests in this
        /// module: a single `bytes32` field. Decoupled from
        /// [`crate::order::eip712::Order`] so the signature primitives
        /// can be exercised without dragging in an `OrderData` fixture.
        struct Probe {
            bytes32 value;
        }
    }

    fn probe_payload(value: [u8; 32]) -> Probe {
        Probe {
            value: B256::from(value),
        }
    }

    /// Sign-and-recover round trip for both ECDSA schemes against the
    /// `alloy_signer_local::PrivateKeySigner` reference implementation.
    /// Mirrors `cowprotocol/services/.../signature.rs::test_ecdsa_signature_recovery`.
    #[test]
    fn ecdsa_sign_recover_round_trip() {
        let signer = PrivateKeySigner::from_bytes(&U256::from(1u64).to_be_bytes().into()).unwrap();
        let address = signer.address();

        let domain = crate::domain::settlement_domain(
            1,
            alloy_primitives::address!("9008D19f58AAbD9eD0D60971565AA8510560ab41"),
        );
        let payload = probe_payload(hex!(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));

        for scheme in [EcdsaSigningScheme::Eip712, EcdsaSigningScheme::EthSign] {
            let ecdsa = EcdsaSignature::sign(scheme, &domain, &payload, &signer).unwrap();
            let typed = ecdsa.into_signature(scheme);
            let recovered = typed.recover(&domain, &payload).unwrap().unwrap();
            assert_eq!(recovered.signer, address);
        }
    }

    #[test]
    fn recover_returns_none_for_onchain_schemes() {
        let domain = crate::domain::DomainSeparator::default();
        let payload = probe_payload([0u8; 32]);
        for signature in [Signature::PreSign, Signature::Eip1271(Vec::new())] {
            let recovered = signature.recover(&domain, &payload).unwrap();
            assert!(recovered.is_none());
        }
    }
}
