/**
 * Curated EVM network identifiers for UI guidance.
 * This is metadata only: it contains no RPC endpoints, contract addresses,
 * deployment attestations, or transaction capabilities.
 */
export type ChainRegistryEntry = {
  chainId: number;
  name: string;
  networkType: "mainnet" | "testnet";
  nativeCurrency: "ETH" | "POL";
  sourceUrls: string[];
  reviewedAt: string;
};

export const CHAIN_REGISTRY_REVIEWED_AT = "2026-11-14";

export const CHAIN_REGISTRY: readonly ChainRegistryEntry[] = [
  {
    chainId: 1,
    name: "Ethereum Mainnet",
    networkType: "mainnet",
    nativeCurrency: "ETH",
    sourceUrls: ["https://ethereum.org/developers/docs/apis/json-rpc/"],
    reviewedAt: CHAIN_REGISTRY_REVIEWED_AT,
  },
  {
    chainId: 11155111,
    name: "Ethereum Sepolia",
    networkType: "testnet",
    nativeCurrency: "ETH",
    sourceUrls: ["https://ethereum.org/developers/docs/apis/json-rpc/"],
    reviewedAt: CHAIN_REGISTRY_REVIEWED_AT,
  },
  {
    chainId: 8453,
    name: "Base Mainnet",
    networkType: "mainnet",
    nativeCurrency: "ETH",
    sourceUrls: ["https://docs.base.org/base-chain/api-reference/ethereum-json-rpc-api/eth_chainId"],
    reviewedAt: CHAIN_REGISTRY_REVIEWED_AT,
  },
  {
    chainId: 84532,
    name: "Base Sepolia",
    networkType: "testnet",
    nativeCurrency: "ETH",
    sourceUrls: ["https://docs.base.org/base-chain/api-reference/ethereum-json-rpc-api/eth_chainId"],
    reviewedAt: CHAIN_REGISTRY_REVIEWED_AT,
  },
  {
    chainId: 42161,
    name: "Arbitrum One",
    networkType: "mainnet",
    nativeCurrency: "ETH",
    sourceUrls: ["https://developer.arbitrum.io/chain-info"],
    reviewedAt: CHAIN_REGISTRY_REVIEWED_AT,
  },
  {
    chainId: 42170,
    name: "Arbitrum Nova",
    networkType: "mainnet",
    nativeCurrency: "ETH",
    sourceUrls: ["https://developer.arbitrum.io/chain-info"],
    reviewedAt: CHAIN_REGISTRY_REVIEWED_AT,
  },
  {
    chainId: 421614,
    name: "Arbitrum Sepolia",
    networkType: "testnet",
    nativeCurrency: "ETH",
    sourceUrls: ["https://developer.arbitrum.io/chain-info"],
    reviewedAt: CHAIN_REGISTRY_REVIEWED_AT,
  },
  {
    chainId: 10,
    name: "OP Mainnet",
    networkType: "mainnet",
    nativeCurrency: "ETH",
    sourceUrls: ["https://eips.ethereum.org/EIPS/eip-5094"],
    reviewedAt: CHAIN_REGISTRY_REVIEWED_AT,
  },
  {
    chainId: 137,
    name: "Polygon PoS",
    networkType: "mainnet",
    nativeCurrency: "POL",
    sourceUrls: ["https://docs.polygon.technology/tools/dApp-development/common-tools/remix/"],
    reviewedAt: CHAIN_REGISTRY_REVIEWED_AT,
  },
] as const;

export function getChainById(chainId: number): ChainRegistryEntry | undefined {
  return CHAIN_REGISTRY.find((chain) => chain.chainId === chainId);
}
