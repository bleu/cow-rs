//! EIP-712 domain separator for CoW Protocol orders.
//!
//! The settlement contract identifies itself with the EIP-712 domain
//! `name = "Gnosis Protocol"`, `version = "v2"`. Together with the
//! deployment's `chainId` and `verifyingContract` address this yields a
//! 32-byte separator that prefixes every signed order hash.
//!
//! Adapted from [`cowprotocol/services`] (MIT OR Apache-2.0).
//!
//! [`cowprotocol/services`]: https://github.com/cowprotocol/services/blob/main/crates/model/src/lib.rs

use alloy_primitives::{Address, B256, U256, keccak256};
use alloy_sol_types::Eip712Domain;
use const_hex::{FromHex, FromHexError};
use std::fmt;
use std::str::FromStr;

/// EIP-712 domain separator: 32 bytes that scope a struct hash to a specific
/// chain and settlement contract.
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DomainSeparator(pub [u8; 32]);

impl DomainSeparator {
    /// Build the separator for the CoW Protocol settlement contract on a
    /// given chain.
    ///
    /// The Solidity domain string is `"Gnosis Protocol" v2`. The
    /// `contract_address` is the deployed `GPv2Settlement` for that chain.
    pub fn new(chain_id: u64, contract_address: Address) -> Self {
        let domain = Eip712Domain {
            name: Some("Gnosis Protocol".into()),
            version: Some("v2".into()),
            chain_id: Some(U256::from(chain_id)),
            verifying_contract: Some(contract_address),
            salt: None,
        };

        Self(domain.separator().into())
    }
}

impl FromStr for DomainSeparator {
    type Err = FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(FromHex::from_hex(s)?))
    }
}

impl fmt::Debug for DomainSeparator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&const_hex::encode(self.0))
    }
}

/// Compute the EIP-712 typed-data hash: `keccak256(0x19 0x01 || domain || struct_hash)`.
///
/// This is the value that is signed by the order owner: see
/// [EIP-712 §`eth_signTypedData`](https://eips.ethereum.org/EIPS/eip-712#eth_signTypedData).
pub fn hashed_eip712_message(domain_separator: &DomainSeparator, struct_hash: &[u8; 32]) -> B256 {
    let mut message = [0u8; 66];
    message[0..2].copy_from_slice(&[0x19, 0x01]);
    message[2..34].copy_from_slice(&domain_separator.0);
    message[34..66].copy_from_slice(struct_hash);
    keccak256(message)
}

/// Compute the EIP-191 personal-sign wrapping over the EIP-712 typed-data
/// hash: `keccak256("\x19Ethereum Signed Message:\n32" || hashed_eip712_message)`.
///
/// This is the message wallets sign when the owner uses the
/// [`SigningScheme::EthSign`] flow.
///
/// [`SigningScheme::EthSign`]: crate::signing_scheme::SigningScheme::EthSign
pub fn hashed_ethsign_message(domain_separator: &DomainSeparator, struct_hash: &[u8; 32]) -> B256 {
    let mut message = [0u8; 60];
    message[..28].copy_from_slice(b"\x19Ethereum Signed Message:\n32");
    message[28..].copy_from_slice(hashed_eip712_message(domain_separator, struct_hash).as_slice());
    keccak256(message)
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;
    use crate::contracts::GPV2_SETTLEMENT;

    #[test]
    fn domain_separator_sepolia() {
        // Locks the EIP-712 domain separator against the canonical
        // GPv2Settlement deployment on Sepolia chain 11_155_111.
        // https://sepolia.etherscan.io/address/0x9008d19f58aabd9ed0d60971565aa8510560ab41
        let chain_id: u64 = 11_155_111;

        let computed = DomainSeparator::new(chain_id, GPV2_SETTLEMENT);
        let expected = DomainSeparator(hex!(
            "daee378bd0eb30ddf479272accf91761e697bc00e067a268f95f1d2732ed230b"
        ));

        assert_eq!(computed, expected);
    }

    #[test]
    fn domain_separator_from_str_round_trips() {
        let hex_str = "9d7e07ef92761aa9453ae5ff25083a2b19764131b15295d3c7e89f1f1b8c67d9";
        let parsed = DomainSeparator::from_str(hex_str).unwrap();
        assert_eq!(format!("{parsed:?}"), hex_str);
    }
}
