/**
 * Conservative, read-only Uniswap deployment reference registry.
 * Addresses are transcribed from official protocol documentation. They have
 * not been independently checked against live chain bytecode by this app.
 */
export type DexRegistryEntry = {
  id: string;
  protocol: "Uniswap";
  version: "v2" | "v3";
  chainId: number;
  chainName: string;
  contractRole: "factory" | "router";
  contractName: string;
  address: string;
  sourceUrl: string;
  evidence: "official-documentation";
  reviewedAt: string;
};

export const DEX_REGISTRY_REVIEWED_AT = "2026-11-14";

const V2_SOURCE = "https://developers.uniswap.org/docs/protocols/v2/deployments";
const V3_ETHEREUM_SOURCE = "https://developers.uniswap.org/docs/protocols/v3/deployments/v3-ethereum-deployments";
const V3_BASE_SOURCE = "https://developers.uniswap.org/docs/protocols/v3/deployments/v3-base-deployments";
const V3_DEPLOYMENTS_SOURCE = "https://docs.uniswap.org/contracts/v3/reference/deployments/";

// Uniswap v3 was deployed to Ethereum, Arbitrum, Optimism and Polygon from the
// same deployer, so the factory and SwapRouter02 share identical addresses on
// these chains. Still verify the connected chain ID and live bytecode before use.
const V3_CANONICAL_FACTORY = "0x1F98431c8aD98523631AE4a59f267346ea31F984";
const V3_CANONICAL_SWAP_ROUTER_02 = "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45";

function v3Canonical(chainId: number, chainName: string): DexRegistryEntry[] {
  return [
    { id: `uniswap-v3-${chainName.toLowerCase().replace(/\s+/g, "-")}-factory`, protocol: "Uniswap", version: "v3", chainId, chainName, contractRole: "factory", contractName: "UniswapV3Factory", address: V3_CANONICAL_FACTORY, sourceUrl: V3_DEPLOYMENTS_SOURCE, evidence: "official-documentation", reviewedAt: DEX_REGISTRY_REVIEWED_AT },
    { id: `uniswap-v3-${chainName.toLowerCase().replace(/\s+/g, "-")}-swap-router-02`, protocol: "Uniswap", version: "v3", chainId, chainName, contractRole: "router", contractName: "SwapRouter02", address: V3_CANONICAL_SWAP_ROUTER_02, sourceUrl: V3_DEPLOYMENTS_SOURCE, evidence: "official-documentation", reviewedAt: DEX_REGISTRY_REVIEWED_AT },
  ];
}

export const DEX_REGISTRY: readonly DexRegistryEntry[] = [
  { id: "uniswap-v2-ethereum-factory", protocol: "Uniswap", version: "v2", chainId: 1, chainName: "Ethereum Mainnet", contractRole: "factory", contractName: "UniswapV2Factory", address: "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f", sourceUrl: V2_SOURCE, evidence: "official-documentation", reviewedAt: DEX_REGISTRY_REVIEWED_AT },
  { id: "uniswap-v2-ethereum-router02", protocol: "Uniswap", version: "v2", chainId: 1, chainName: "Ethereum Mainnet", contractRole: "router", contractName: "UniswapV2Router02", address: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D", sourceUrl: V2_SOURCE, evidence: "official-documentation", reviewedAt: DEX_REGISTRY_REVIEWED_AT },
  { id: "uniswap-v2-base-factory", protocol: "Uniswap", version: "v2", chainId: 8453, chainName: "Base Mainnet", contractRole: "factory", contractName: "UniswapV2Factory", address: "0x8909Dc15e40173Ff4699343b6eB8132c65e18eC6", sourceUrl: V2_SOURCE, evidence: "official-documentation", reviewedAt: DEX_REGISTRY_REVIEWED_AT },
  { id: "uniswap-v2-base-router02", protocol: "Uniswap", version: "v2", chainId: 8453, chainName: "Base Mainnet", contractRole: "router", contractName: "UniswapV2Router02", address: "0x4752ba5dbc23f44d87826276bf6fd6b1c372ad24", sourceUrl: V2_SOURCE, evidence: "official-documentation", reviewedAt: DEX_REGISTRY_REVIEWED_AT },
  { id: "uniswap-v3-ethereum-factory", protocol: "Uniswap", version: "v3", chainId: 1, chainName: "Ethereum Mainnet", contractRole: "factory", contractName: "UniswapV3Factory", address: "0x1F98431c8aD98523631AE4a59f267346ea31F984", sourceUrl: V3_ETHEREUM_SOURCE, evidence: "official-documentation", reviewedAt: DEX_REGISTRY_REVIEWED_AT },
  { id: "uniswap-v3-ethereum-swap-router-02", protocol: "Uniswap", version: "v3", chainId: 1, chainName: "Ethereum Mainnet", contractRole: "router", contractName: "SwapRouter02", address: "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45", sourceUrl: V3_ETHEREUM_SOURCE, evidence: "official-documentation", reviewedAt: DEX_REGISTRY_REVIEWED_AT },
  { id: "uniswap-v3-base-factory", protocol: "Uniswap", version: "v3", chainId: 8453, chainName: "Base Mainnet", contractRole: "factory", contractName: "UniswapV3Factory", address: "0x33128a8fC17869897dcE68Ed026d694621f6FDfD", sourceUrl: V3_BASE_SOURCE, evidence: "official-documentation", reviewedAt: DEX_REGISTRY_REVIEWED_AT },
  { id: "uniswap-v3-base-swap-router-02", protocol: "Uniswap", version: "v3", chainId: 8453, chainName: "Base Mainnet", contractRole: "router", contractName: "SwapRouter02", address: "0x2626664c2603336E57B271c5C0b26F421741e481", sourceUrl: V3_BASE_SOURCE, evidence: "official-documentation", reviewedAt: DEX_REGISTRY_REVIEWED_AT },
  ...v3Canonical(42161, "Arbitrum One"),
  ...v3Canonical(10, "Optimism"),
  ...v3Canonical(137, "Polygon"),
] as const;

export function getDexDeploymentsByChain(chainId: number): DexRegistryEntry[] {
  return DEX_REGISTRY.filter((entry) => entry.chainId === chainId);
}

/**
 * Identify whether an address matches a known DEX factory/router in the
 * registry. Comparison is case-insensitive; an optional chainId narrows the
 * match. Returns every matching registry entry (an address can be shared across
 * chains), or an empty array when the address is not a recognised deployment.
 */
export function identifyDexAddress(address: string, chainId?: number): DexRegistryEntry[] {
  if (typeof address !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(address.trim())) return [];
  const needle = address.trim().toLowerCase();
  return DEX_REGISTRY.filter(
    (entry) => entry.address.toLowerCase() === needle && (chainId === undefined || entry.chainId === chainId),
  );
}

export const DEX_REGISTRY_CHAINS: ReadonlyArray<{ chainId: number; chainName: string }> =
  [...new Map(DEX_REGISTRY.map((e) => [e.chainId, { chainId: e.chainId, chainName: e.chainName }])).values()];
