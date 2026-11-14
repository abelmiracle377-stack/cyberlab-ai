# Solidity test fixtures

These self-contained teaching fixtures exercise CyberLab's offline multi-file compiler and Foundry runner. They use Solidity 0.8.20-compatible syntax, Foundry's built-in test discovery and Solidity assert statements; no forge-std or external package is required.

## Capped NFT fixture

Project root: examples/solidity/nft

- src/CappedCollection.sol: minimal owner-minted capped token with approval, transfer and safe-receiver callback examples.
- test/CappedCollection.t.sol: exercises supply cap, mint authority, approval transfer and callback state ordering.

This is deliberately not a complete ERC-721 implementation: it omits standard interface support, operator approvals, metadata, burn, pause, royalties and full conformance. It is a test fixture, not deployable NFT code.

## Constant-product AMM fixture

Project root: examples/solidity/amm

- src/ConstantProductPool.sol: minimal two-token pool with 0.3% swap fee, reserve accounting, minimum output, deadline, proportional liquidity shares and withdrawal.
- test/ConstantProductPool.t.sol: exercises the constant-product product invariant, slippage rejection, expired action rejection and pro-rata withdrawal.

This is not a production AMM: it omits robust token compatibility, reentrancy protection, oracle/TWAP, protocol fee accounting, flash swaps, fee-on-transfer/rebasing token handling, LP share rounding protections and economic/MEV mitigations. It is not audited.

## Running through Solidity Lab

Run each project separately, submitting its src/*.sol and test/*.t.sol files to the multi-file compiler and local Foundry test runner. No dependency lock is needed because the fixtures use project-relative imports only. Use a preloaded, digest-pinned image with matching Foundry and solc 0.8.20 versions. The container has no network and cannot download missing tools. A successful fixture test run validates only these narrow examples; it does not certify a generated or production contract.
