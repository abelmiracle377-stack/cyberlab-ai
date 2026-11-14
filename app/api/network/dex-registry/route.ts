import { NextResponse } from "next/server";
import { DEX_REGISTRY, DEX_REGISTRY_REVIEWED_AT } from "@/lib/dex-registry";

export const dynamic = "force-static";

export async function GET() {
  return NextResponse.json({
    reviewedAt: DEX_REGISTRY_REVIEWED_AT,
    entries: DEX_REGISTRY,
    limitations: [
      "Addresses are transcribed from official Uniswap deployment documentation; this registry does not independently verify live bytecode, proxy state, liquidity, or operational status.",
      "Only the exact protocol version, chain ID, contract role, and source URL shown for an entry are in scope. Do not reuse an address on another chain or for another protocol version.",
      "This is read-only reference data. It does not connect to a wallet or RPC provider, approve tokens, quote swaps, or submit transactions.",
      "Check the connected chain ID and independently verify contract code and interface behavior before any future transaction workflow.",
    ],
  });
}
