export type SoliditySeverity = "critical" | "high" | "medium" | "low" | "info";
export type SolidityFinding = { id: string; severity: SoliditySeverity; title: string; description: string; recommendation: string; line: number; evidence: string };
export type SolidityAnalysis = { compilerPragmas: string[]; contracts: string[]; interfaces: string[]; libraries: string[]; imports: string[]; functions: number; findings: SolidityFinding[]; summary: { critical: number; high: number; medium: number; low: number; info: number }; limitations: string[] };

const rules: Array<{id:string;severity:SoliditySeverity;title:string;pattern:RegExp;description:string;recommendation:string}> = [
 {id:"SOL-001",severity:"critical",title:"tx.origin used for authorisation",pattern:/\btx\s*\.\s*origin\b/g,description:"tx.origin can be influenced by an intermediary contract and is unsafe as an authentication primitive.",recommendation:"Use msg.sender with an explicit role or ownership mechanism; review the complete call chain."},
 {id:"SOL-002",severity:"high",title:"Low-level delegatecall",pattern:/\.\s*delegatecall\s*\(/g,description:"delegatecall executes code in the caller's storage context. Untrusted or upgradeable targets can compromise contract state.",recommendation:"Constrain implementation addresses, validate upgrade authority and storage layout, and test upgrade paths."},
 {id:"SOL-003",severity:"high",title:"Low-level call requires review",pattern:/\.\s*call\s*(?:\{[^}]*\})?\s*\(/g,description:"Low-level calls transfer control to an external address and may introduce reentrancy or unchecked failure paths.",recommendation:"Check the returned success value, apply checks-effects-interactions, and use a reentrancy guard where appropriate."},
 {id:"SOL-004",severity:"high",title:"Deprecated selfdestruct opcode",pattern:/\bselfdestruct\s*\(/g,description:"selfdestruct semantics changed under EIP-6780 and remain a high-impact lifecycle primitive requiring chain-specific review.",recommendation:"Avoid relying on legacy deletion semantics; document intended ETH transfer behaviour and target-chain rules."},
 {id:"SOL-005",severity:"high",title:"Assembly block present",pattern:/\bassembly\s*(?:\([^)]*\))?\s*\{/g,description:"Inline assembly bypasses many Solidity safety checks and can introduce memory, storage, and control-flow defects.",recommendation:"Minimise assembly, document invariants, and add focused tests or formal verification for the block."},
 {id:"SOL-006",severity:"medium",title:"Unchecked arithmetic block",pattern:/\bunchecked\s*\{/g,description:"Arithmetic inside unchecked blocks does not revert on overflow or underflow.",recommendation:"Prove bounds for every operation and test boundary values; remove unchecked where the gas saving is not justified."},
 {id:"SOL-007",severity:"medium",title:"Block timestamp dependency",pattern:/\bblock\s*\.\s*timestamp\b/g,description:"Block timestamps are not a secure source of randomness and can have limited proposer influence.",recommendation:"Use timestamps only for coarse time windows; use an appropriate verifiable randomness design for randomness."},
 {id:"SOL-008",severity:"medium",title:"Block difficulty/prevrandao usage",pattern:/\bblock\s*\.\s*(?:difficulty|prevrandao)\b/g,description:"Block-derived randomness is generally predictable or influenceable for high-value outcomes.",recommendation:"Do not use block values as sole randomness for lotteries, allocations, or value-bearing decisions."},
 {id:"SOL-009",severity:"medium",title:"External call before state update (heuristic)",pattern:/\.\s*(?:call|transfer|send)\s*(?:\{[^}]*\})?\s*\([^;]*\)\s*;[\s\S]{0,220}\b(?:balances|balanceOf|credit|withdrawn|claimed|nonce)\s*\[[^\]]+\]\s*(?:=|\+=|-=)/g,description:"An external interaction appears before a nearby state update. This pattern can indicate checks-effects-interactions or reentrancy problems.",recommendation:"Inspect control flow manually, move state effects before external interactions where correct, and add adversarial reentrancy tests."},
 {id:"SOL-010",severity:"low",title:"Floating pragma",pattern:/pragma\s+solidity\s+\^\s*\d+\.\d+\.\d+\s*;/g,description:"A caret pragma permits compilation with a range of compiler versions, which can reduce reproducibility.",recommendation:"Pin the compiler version for reproducible builds and document the audited compiler/toolchain."},
 {id:"SOL-011",severity:"info",title:"External/public function surface",pattern:/\bfunction\s+[A-Za-z_$][\w$]*\s*\([^)]*\)[^{;]*(?:external|public)/g,description:"Public and external functions expand the callable surface and should be included in access-control review.",recommendation:"Review each entry point for caller permissions, state changes, value transfers, and invariant preservation."},
 {id:"SOL-012",severity:"info",title:"Upgradeable proxy indicator",pattern:/\b(?:delegatecall|implementation|upgradeTo|proxiableUUID)\b/g,description:"The source contains common upgradeability indicators.",recommendation:"Review upgrade authority, initialization protection, storage layout compatibility, and emergency controls."},
 {id:"SOL-013",severity:"info",title:"NFT mint entry point requires access-control review",pattern:/\bfunction\s+(?:safeMint|mint|mintBatch)\s*\(/g,description:"A mint-named entry point is present. This pattern does not determine whether access control is correctly enforced.",recommendation:"Trace every mint path and verify role checks, supply caps, allowlist proofs, pause policy and authorization tests."},
 {id:"SOL-014",severity:"medium",title:"ERC-721 safe mint callback surface",pattern:/\b_safeMint\s*\(/g,description:"ERC-721 safe minting can invoke an external receiver callback. Review reentrancy and state invariants across the callback boundary.",recommendation:"Review state updates and reentrancy protection around receiver hooks; test with a malicious receiver contract and verify mint limits remain invariant."},
 {id:"SOL-015",severity:"info",title:"NFT metadata URI strategy requires review",pattern:/\b(?:_baseURI|baseURI|tokenURI|uri)\s*\(/g,description:"A token metadata URI function or hook is present. This pattern cannot establish whether metadata is mutable, available or immutable.",recommendation:"Document who can change URI values, reveal mechanics, content-addressing assumptions, storage availability and migration policy."},
 {id:"SOL-016",severity:"info",title:"ERC-2981 royalty interface indicator",pattern:/\broyaltyInfo\s*\(/g,description:"A royalty information function is present. ERC-2981 communicates royalty information but does not force marketplaces to pay it.",recommendation:"Document royalty receiver and basis-point bounds, test calculations and avoid promising universal marketplace enforcement."},

 {id:"SOL-017",severity:"info",title:"DEX swap entry point requires slippage and deadline review",pattern:/\bfunction\s+(?:swap|swapExactTokensForTokens|swapTokensForExactTokens|swapExactETHForTokens|swapTokensForExactETH|swapExactTokensForETH|swapETHForExactTokens)\s*\(/g,description:"A swap-named entry point is present. The name alone cannot establish whether execution is protected against adverse price movement or stale transactions.",recommendation:"Trace exact-input and exact-output paths; verify user-defined minimum output or maximum input, deadline handling, route validation and transaction ordering assumptions."},
 {id:"SOL-018",severity:"medium",title:"DEX reserve reads require manipulation and freshness review",pattern:/\b(?:getReserves|reserve0|reserve1|_reserve0|_reserve1)\b/g,description:"Pool reserve values are referenced. Spot reserves can be moved within a transaction or block and should not automatically be treated as a fair external price.",recommendation:"Check whether reserve values are used for pricing, collateral, liquidation or minting; use a suitable independently validated oracle or manipulation-resistant TWAP with freshness and liquidity checks."},
 {id:"SOL-019",severity:"info",title:"DEX slippage-bound variable or parameter",pattern:/\b(?:amountOutMin|minAmountOut|minOut|amountInMax|maxAmountIn)\b/g,description:"A slippage-related identifier is present. Its presence does not prove the bound is nonzero, user-controlled or correctly enforced.",recommendation:"Trace the value from user intent to the final require/router call; reject unsafe defaults and test adverse price movement and boundary cases."},
 {id:"SOL-020",severity:"medium",title:"Oracle or TWAP dependency requires manipulation and freshness review",pattern:/\b(?:consult|observe|TWAP|twap|oracle|priceFeed|latestRoundData|price0CumulativeLast|price1CumulativeLast)\b/g,description:"An oracle-related identifier is present. This heuristic cannot assess source quality, observation windows, staleness, decimals or fallback behaviour.",recommendation:"Validate oracle provenance, update/freshness bounds, decimals, round completeness, liquidity/manipulation assumptions, sequencer conditions where relevant, and safe failure behaviour."},
 {id:"SOL-021",severity:"info",title:"AMM protocol-fee accounting indicator",pattern:/\b(?:kLast|feeTo|feeToSetter|protocolFee|protocolFees)\b/g,description:"A common AMM protocol-fee accounting identifier is present. This does not establish whether fee minting or accounting is correct.",recommendation:"Review fee-on/off transitions, reserve-product snapshots, rounding, recipient authority, dilution and invariant tests across liquidity mint/burn operations."},
 {id:"SOL-022",severity:"medium",title:"Flash-loan or flash-swap callback surface",pattern:/\b(?:flashLoan|flashBorrow|uniswapV2Call|pancakeCall|onFlashLoan|executeOperation)\s*\(/g,description:"A flash-loan or flash-swap callback entry point is present. Callback-driven external control flow requires strict caller validation and repayment/invariant checks.",recommendation:"Authenticate the lender or pair and expected assets, amounts and initiator; prevent callback replay/reentrancy, verify repayment plus fees, and test failed repayment and malicious callback cases."},
 {id:"SOL-023",severity:"info",title:"AMM liquidity add/remove accounting requires invariant review",pattern:/\b(?:addLiquidity|removeLiquidity)\s*\(/g,description:"A liquidity lifecycle function name is present. This does not establish correct LP share accounting, proportional withdrawals or rounding behaviour.",recommendation:"Test initial and subsequent liquidity, proportional mint/burn, minimum liquidity, rounding, fee-on transitions, zero-liquidity states and token transfer edge cases."},
];

function maskCommentsAndStrings(source:string):string {
 return source.replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\/\*[\s\S]*?\*\/|\/\/[^\r\n]*/g,(match)=>match.replace(/[^\r\n]/g," "));
}

// Preserve quoted import paths while blanking comments. This prevents commented-out
// imports from entering the inventory without erasing real dependency strings.
function maskCommentsPreservingStrings(source:string):string {
 let output="", quote="", escaped=false, lineComment=false, blockComment=false;
 for(let i=0;i<source.length;i++){
  const char=source[i], next=source[i+1];
  if(lineComment){if(char==="\n"||char==="\r"){lineComment=false;output+=char;}else output+=" ";continue;}
  if(blockComment){if(char==="*"&&next==="/"){output+="  ";i++;blockComment=false;}else output+=char==="\n"||char==="\r"?char:" ";continue;}
  if(quote){output+=char;if(escaped){escaped=false;continue;}if(char==="\\"){escaped=true;continue;}if(char===quote)quote="";continue;}
  if(char==='"'||char==="'"){quote=char;output+=char;continue;}
  if(char==="/"&&next==="/"){output+="  ";i++;lineComment=true;continue;}
  if(char==="/"&&next==="*"){output+="  ";i++;blockComment=true;continue;}
  output+=char;
 }
 return output;
}
function lineAt(source:string,index:number):number{return source.slice(0,index).split("\n").length;}
export function analyzeSoliditySource(source:string):SolidityAnalysis {
 if(typeof source!=="string"||!source.trim())throw new Error("Paste Solidity source code to analyse.");
 if(source.length>100000)throw new Error("Source exceeds the 100 KB analysis limit.");
 const clean=maskCommentsAndStrings(source);
 const findings:SolidityFinding[]=[];
 for(const rule of rules){
  rule.pattern.lastIndex=0;let match:RegExpExecArray|null;
  while((match=rule.pattern.exec(clean))!==null){
   const original=source.slice(match.index,match.index+match[0].length).split("\n")[0].trim().slice(0,180);
   findings.push({id:rule.id,severity:rule.severity,title:rule.title,description:rule.description,recommendation:rule.recommendation,line:lineAt(source,match.index),evidence:original});
   if(!rule.pattern.global)break;
  }
 }
 const unique=new Map<string,SolidityFinding>();
 for(const finding of findings){const key=finding.id+":"+finding.line;if(!unique.has(key))unique.set(key,finding);}
 const rank:Record<SoliditySeverity,number>={critical:0,high:1,medium:2,low:3,info:4};
 const ordered=[...unique.values()].sort((a,b)=>rank[a.severity]-rank[b.severity]||a.line-b.line);
 const extract=(pattern:RegExp)=>[...clean.matchAll(pattern)].map(m=>m[1]).filter(Boolean);
 const summary={critical:0,high:0,medium:0,low:0,info:0};for(const f of ordered)summary[f.severity]++;
 return {
  compilerPragmas:extract(/pragma\s+solidity\s+([^;]+);/g),
  contracts:extract(/\bcontract\s+([A-Za-z_$][\w$]*)/g),
  interfaces:extract(/\binterface\s+([A-Za-z_$][\w$]*)/g),
  libraries:extract(/\blibrary\s+([A-Za-z_$][\w$]*)/g),
  imports:[...maskCommentsPreservingStrings(source).matchAll(/\bimport\s+(?:[^'"]*?\s+from\s+)?['"]([^'"]+)['"]\s*;/g)].map(m=>m[1]),
  functions:[...clean.matchAll(/\bfunction\s+[A-Za-z_$][\w$]*\s*\(/g)].length,
  findings:ordered,summary,
  limitations:["Pattern-based source review only; this is not a Solidity compiler, Slither, Mythril, fuzzing, symbolic execution, or formal verification.","A detected pattern is a review lead, not proof of exploitability. Absence of findings does not mean the contract is secure.","The analyzer does not resolve inheritance, modifiers, control flow, storage layout, external dependencies, or chain-specific semantics.","Do not paste private keys, seed phrases, production secrets, or confidential source into an untrusted deployment."]
 };
}
