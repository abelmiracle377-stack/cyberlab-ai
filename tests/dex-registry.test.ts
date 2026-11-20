import { test } from "node:test";
import assert from "node:assert/strict";
import { DEX_REGISTRY, DEX_REGISTRY_CHAINS, getDexDeploymentsByChain, identifyDexAddress } from "../lib/dex-registry";

test("registry covers the expected chains", () => {
  const ids = new Set(DEX_REGISTRY_CHAINS.map((c) => c.chainId));
  for (const chainId of [1, 8453, 42161, 10, 137]) {
    assert.ok(ids.has(chainId), "missing chain " + chainId);
  }
});

test("every entry has a valid 40-hex address and a source", () => {
  for (const entry of DEX_REGISTRY) {
    assert.match(entry.address, /^0x[0-9a-fA-F]{40}$/, entry.id);
    assert.match(entry.sourceUrl, /^https:\/\//);
  }
});

test("identifies a known Uniswap v3 factory case-insensitively", () => {
  const matches = identifyDexAddress("0x1f98431c8ad98523631ae4a59f267346ea31f984");
  assert.ok(matches.length > 0);
  assert.ok(matches.every((m) => m.contractName === "UniswapV3Factory"));
});

test("chainId narrows an address match", () => {
  const all = identifyDexAddress("0x1F98431c8aD98523631AE4a59f267346ea31F984");
  const arb = identifyDexAddress("0x1F98431c8aD98523631AE4a59f267346ea31F984", 42161);
  assert.ok(all.length > arb.length);
  assert.ok(arb.every((m) => m.chainId === 42161));
});

test("unknown or malformed addresses return no match", () => {
  assert.deepEqual(identifyDexAddress("0x0000000000000000000000000000000000000000"), []);
  assert.deepEqual(identifyDexAddress("not-an-address"), []);
  assert.deepEqual(identifyDexAddress("0x123"), []);
});

test("getDexDeploymentsByChain returns only that chain", () => {
  const polygon = getDexDeploymentsByChain(137);
  assert.ok(polygon.length >= 2);
  assert.ok(polygon.every((e) => e.chainId === 137));
});
