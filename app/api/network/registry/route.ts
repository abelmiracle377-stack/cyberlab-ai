import { NextResponse } from "next/server";
import { CHAIN_REGISTRY, CHAIN_REGISTRY_REVIEWED_AT } from "@/lib/chain-registry";

export const dynamic = "force-static";

export async function GET() {
  return NextResponse.json({
    reviewedAt: CHAIN_REGISTRY_REVIEWED_AT,
    entries: CHAIN_REGISTRY,
    limitations: [
      "Curated EVM chain identifiers only; this endpoint does not connect to an RPC provider or wallet.",
      "No DEX deployments or contract addresses are listed until each address can be verified against a primary protocol source and on-chain evidence.",
      "Network metadata is informational and must be checked against the connected wallet's eth_chainId before any future transaction workflow.",
    ],
  });
}
