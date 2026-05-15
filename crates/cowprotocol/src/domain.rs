//! EIP-712 domain separator for CoW Protocol orders.
//!
//! The settlement contract identifies itself with the EIP-712 domain
//! `name = "Gnosis Protocol"`, `version = "v2"`. Combined with the
//! deployment's `chainId` and `verifyingContract` address it scopes
//! every signed order hash to a specific chain.
//!
//! [`DomainSeparator`] is a type alias for
//! [`alloy_sol_types::Eip712Domain`]; the typed-data envelope is
//! supplied by [`alloy_sol_types::SolStruct::eip712_signing_hash`] and
//! the EIP-191 personal-sign wrap by
//! [`alloy_primitives::eip191_hash_message`], so there are no bespoke
//! `keccak256(0x19 0x01 || ...)` or `\x19Ethereum Signed Message:\n32`
//! helpers in this crate.

use alloy_primitives::{Address, U256};
use alloy_sol_types::Eip712Domain;

/// EIP-712 domain for the CoW Protocol settlement contract. Re-exported
/// as a type alias so callers using `cowprotocol::DomainSeparator` do
/// not need to import the underlying alloy type, while getting all of
/// `Eip712Domain`'s `Debug`, `Display`, `Eq`, `Hash`, `Serialize`,
/// `Deserialize`, and `separator()` derivations for free.
pub type DomainSeparator = Eip712Domain;

/// Build the EIP-712 domain for the `GPv2Settlement` deployment on a
/// given chain. The Solidity domain string is `"Gnosis Protocol" v2`;
/// `contract_address` is the deployed `GPv2Settlement` for that chain.
pub fn settlement_domain(chain_id: u64, contract_address: Address) -> DomainSeparator {
    Eip712Domain {
        name: Some("Gnosis Protocol".into()),
        version: Some("v2".into()),
        chain_id: Some(U256::from(chain_id)),
        verifying_contract: Some(contract_address),
        salt: None,
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::b256;

    use super::*;
    use crate::contracts::GPV2_SETTLEMENT;

    #[test]
    fn domain_separator_sepolia() {
        // Locks the EIP-712 domain separator against the canonical
        // GPv2Settlement deployment on Sepolia chain 11_155_111.
        // https://sepolia.etherscan.io/address/0x9008d19f58aabd9ed0d60971565aa8510560ab41
        let chain_id: u64 = 11_155_111;

        let domain = settlement_domain(chain_id, GPV2_SETTLEMENT);
        let expected = b256!("daee378bd0eb30ddf479272accf91761e697bc00e067a268f95f1d2732ed230b");

        assert_eq!(domain.separator(), expected);
    }
}
