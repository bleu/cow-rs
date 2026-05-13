// Generate cross-chain conformance vectors for cow-rs.
//
// Uses ethers' TypedDataEncoder (the same engine cow-sdk relies on under
// the hood) so the output is exactly what a downstream signing flow would
// produce. No RPC calls; everything is derived from the chain id and the
// settlement contract address.
//
// Output is printed to stdout as a JSON object that the next step in the
// recon pipeline reads.

import { TypedDataEncoder, getAddress, hexlify, toUtf8Bytes, zeroPadValue } from "ethers";

// Canonical GPv2Settlement CREATE2 deployment — identical on every supported
// chain. Source: https://github.com/cowprotocol/contracts/blob/main/networks.json
const SETTLEMENT = "0x9008D19f58AAbD9eD0D60971565AA8510560ab41";

// Same sample order as the services golden vector
// (cowprotocol/services/crates/model/src/order.rs::compute_order_uid).
const OWNER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const ORDER = {
  sellToken: "0x0101010101010101010101010101010101010101",
  buyToken: "0x0202020202020202020202020202020202020202",
  receiver: "0x0303030303030303030303030303030303030303",
  sellAmount: "0x0246ddf97976680000",
  buyAmount: "0xb98bc829a6f90000",
  validTo: 0xffffffff,
  appData: "0x" + "00".repeat(32),
  feeAmount: "0x0de0b6b3a7640000",
  kind: "sell",
  partiallyFillable: false,
  sellTokenBalance: "erc20",
  buyTokenBalance: "erc20",
};

// EIP-712 type definition for the CoW Protocol Order — verbatim from
// `cowprotocol/contracts/src/contracts/libraries/GPv2Order.sol` (the
// canonical source-of-truth).
const ORDER_TYPES = {
  Order: [
    { name: "sellToken", type: "address" },
    { name: "buyToken", type: "address" },
    { name: "receiver", type: "address" },
    { name: "sellAmount", type: "uint256" },
    { name: "buyAmount", type: "uint256" },
    { name: "validTo", type: "uint32" },
    { name: "appData", type: "bytes32" },
    { name: "feeAmount", type: "uint256" },
    { name: "kind", type: "string" },
    { name: "partiallyFillable", type: "bool" },
    { name: "sellTokenBalance", type: "string" },
    { name: "buyTokenBalance", type: "string" },
  ],
};

const CHAINS = [
  { id: 1, name: "mainnet" },
  { id: 100, name: "gnosis" },
  { id: 8453, name: "base" },
  { id: 42161, name: "arbitrum" },
  { id: 11155111, name: "sepolia" },
];

function packUid(digestHex, ownerHex, validTo) {
  const digest = digestHex.startsWith("0x") ? digestHex.slice(2) : digestHex;
  const owner = ownerHex.startsWith("0x") ? ownerHex.slice(2) : ownerHex;
  if (digest.length !== 64) throw new Error("digest must be 32 bytes");
  if (owner.length !== 40) throw new Error("owner must be 20 bytes");
  const validToHex = validTo.toString(16).padStart(8, "0");
  return "0x" + digest + owner.toLowerCase() + validToHex;
}

const out = { settlement: SETTLEMENT, owner: OWNER, order: ORDER, chains: {} };

for (const chain of CHAINS) {
  const domain = {
    name: "Gnosis Protocol",
    version: "v2",
    chainId: chain.id,
    verifyingContract: SETTLEMENT,
  };

  const domainSeparator = TypedDataEncoder.hashDomain(domain);
  const structHash = TypedDataEncoder.hashStruct("Order", ORDER_TYPES, ORDER);
  const digest = TypedDataEncoder.hash(domain, ORDER_TYPES, ORDER);
  const uid = packUid(digest, OWNER, ORDER.validTo);

  out.chains[chain.name] = {
    chainId: chain.id,
    domainSeparator,
    structHash,
    digest,
    uid,
  };
}

console.log(JSON.stringify(out, null, 2));
