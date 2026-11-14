import test from "node:test";
import assert from "node:assert/strict";
import { analyzeSoliditySource } from "../lib/solidity-static-analysis";
import { CHAIN_REGISTRY, getChainById } from "../lib/chain-registry";

test("extracts Solidity project inventory", () => {
 const result=analyzeSoliditySource(`// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
interface IToken { function transfer(address to, uint256 amount) external returns (bool); }
library MathLib { function twice(uint256 x) internal pure returns(uint256) { return x * 2; } }
contract Vault { function deposit() external payable {} }`);
 assert.deepEqual(result.compilerPragmas,["0.8.24"]);
 assert.deepEqual(result.contracts,["Vault"]);
 assert.deepEqual(result.interfaces,["IToken"]);
 assert.deepEqual(result.libraries,["MathLib"]);
 assert.deepEqual(result.imports,["@openzeppelin/contracts/token/ERC20/IERC20.sol"]);
 assert.equal(result.functions,3);
});

test("reports risky patterns with stable line references and severity counts", () => {
 const result=analyzeSoliditySource(`pragma solidity ^0.8.20;
contract Example {
 function auth() external view returns(bool) {
  return tx.origin == msg.sender;
 }
 function execute(address target) external {
  target.delegatecall("");
  block.timestamp;
 }
}`);
 const origin=result.findings.find(f=>f.id==="SOL-001");
 const delegate=result.findings.find(f=>f.id==="SOL-002");
 assert.equal(origin?.line,4);
 assert.equal(origin?.severity,"critical");
 assert.equal(delegate?.line,7);
 assert.equal(result.summary.critical,1);
 assert.ok(result.summary.high>=1);
 assert.ok(result.summary.medium>=1);
});

test("does not flag comments or string literals", () => {
 const result=analyzeSoliditySource(`pragma solidity 0.8.24;
// tx.origin and selfdestruct(payable(x))
contract Safe {
 string public note = "tx.origin; block.timestamp; target.delegatecall()";
}`);
 assert.equal(result.findings.length,0);
});

test("deduplicates same rule on the same line and preserves separate occurrences", () => {
 const result=analyzeSoliditySource(`contract Example {
 function a() external view returns(address) { return tx.origin; }
 function b() external view returns(address) { return tx.origin; }
}`);
 assert.equal(result.findings.filter(f=>f.id==="SOL-001").length,2);
 assert.notEqual(result.findings[0].line,result.findings[1].line);
});

test("rejects empty and oversized source", () => {
 assert.throws(()=>analyzeSoliditySource("  "),/Paste Solidity source/);
 assert.throws(()=>analyzeSoliditySource("a".repeat(100001)),/100 KB/);
});

test("returns explicit limitations even when no rule matches", () => {
 const result=analyzeSoliditySource("pragma solidity 0.8.24; contract Plain {}");
 assert.equal(result.findings.length,0);
 assert.ok(result.limitations.some(item=>item.includes("not a Solidity compiler")));
 assert.ok(result.limitations.some(item=>item.includes("Absence of findings")));
});


test("adds cautious NFT review leads without claiming missing controls", () => {
 const result=analyzeSoliditySource(`pragma solidity 0.8.24;
contract Collection {
 function mint(address to) external {}
 function _safeMint(address to, uint256 id) internal {}
 function tokenURI(uint256 id) public view returns(string memory) { return ""; }
 function royaltyInfo(uint256 id, uint256 salePrice) external view returns(address,uint256) { return (address(0), salePrice); }
}`);
 assert.ok(result.findings.some(f=>f.id==="SOL-013"));
 assert.ok(result.findings.some(f=>f.id==="SOL-014"));
 assert.ok(result.findings.some(f=>f.id==="SOL-015"));
 assert.ok(result.findings.some(f=>f.id==="SOL-016"));
});


test("adds cautious DEX review leads for swaps, reserves, slippage, oracles, fees, callbacks and liquidity", () => {
 const result=analyzeSoliditySource(`pragma solidity 0.8.24;
contract ExampleDex {
 function swapExactTokensForTokens(uint amountOutMin) external {}
 function quote() external view returns(uint) { return reserve0 + reserve1; }
 uint public reserve0;
 uint public reserve1;
 uint public kLast;
 address public feeTo;
 function consult(address token) external view returns(uint) { return token == address(0) ? price0CumulativeLast : 0; }
 uint public price0CumulativeLast;
 function uniswapV2Call(address sender, uint amount0, uint amount1, bytes calldata data) external {}
 function addLiquidity(uint amount) external {}
 function removeLiquidity(uint amount) external {}
}`);
 for (const id of ["SOL-017","SOL-018","SOL-019","SOL-020","SOL-021","SOL-022","SOL-023"]) {
  assert.ok(result.findings.some(f=>f.id===id), `expected ${id}`);
 }
 assert.equal(result.findings.find(f=>f.id==="SOL-022")?.severity,"medium");
});

test("curated EVM chain registry has unique positive IDs and documented sources", () => {
 const ids = CHAIN_REGISTRY.map(chain => chain.chainId);
 assert.ok(ids.length >= 8);
 assert.equal(new Set(ids).size, ids.length);
 for (const chain of CHAIN_REGISTRY) {
  assert.ok(Number.isSafeInteger(chain.chainId) && chain.chainId > 0);
  assert.ok(chain.name.length > 0);
  assert.ok(chain.sourceUrls.length > 0);
  assert.ok(chain.sourceUrls.every(url => url.startsWith("https://")));
  assert.ok(chain.reviewedAt.length === 10);
 }
 assert.equal(getChainById(1)?.name, "Ethereum Mainnet");
 assert.equal(getChainById(84532)?.name, "Base Sepolia");
 assert.equal(getChainById(999999), undefined);
});
