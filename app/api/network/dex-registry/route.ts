import { NextResponse } from "next/server";
import { DEX_REGISTRY, DEX_REGISTRY_REVIEWED_AT, DEX_REGISTRY_CHAINS, identifyDexAddress } from "@/lib/dex-registry";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const address = searchParams.get("address");
  const chainParam = searchParams.get("chainId");
  if (address) {
    const chainId = chainParam && /^\d{1,10}$/.test(chainParam) ? Number(chainParam) : undefined;
    const matches = identifyDexAddress(address, chainId);
    return NextResponse.json({
      reviewedAt: DEX_REGISTRY_REVIEWED_AT,
      query: { address, chainId: chainId ?? null },
      recognised: matches.length > 0,
      matches,
      note: matches.length > 0
        ? "Address matches a documented Uniswap deployment in the registry. Still verify the connected chain ID and live bytecode before trusting it."
        : "Address is not in this registry. That is not proof it is unsafe or not a DEX contract; the registry is a small reviewed reference set.",
    });
  }
  return NextResponse.json({
    reviewedAt: DEX_REGISTRY_REVIEWED_AT,
    chains: DEX_REGISTRY_CHAINS,
    entries: DEX_REGISTRY,
    limitations: [
      "Addresses are transcribed from official Uniswap deployment documentation; this registry does not independently verify live bytecode, proxy state, liquidity, or operational status.",
      "Only the exact protocol version, chain ID, contract role, and source URL shown for an entry are in scope. Do not reuse an address on another chain or for another protocol version.",
      "This is read-only reference data. It does not connect to a wallet or RPC provider, approve tokens, quote swaps, or submit transactions.",
      "Check the connected chain ID and independently verify contract code and interface behavior before any future transaction workflow.",
    ],
  });
}
