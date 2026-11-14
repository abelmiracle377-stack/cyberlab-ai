# Blockchain Engineering: Scope, Test Strategy and Deployment Gates

This document describes the current Solidity/DEX workbench, the limits of its initial implementation, and the engineering gates required before handling real assets. It is deliberately conservative: a generated blueprint, static review lead, successful compile, or passing unit test is not a security audit.

## Current implementation

The Solidity Lab currently provides:

- Bounded Solidity source submission to the hosted static analyzer (maximum 100 KB).
- Contract, interface, library, import, function and compiler-pragma inventory.
- Line-referenced heuristic review leads, including general Solidity patterns, NFT mint/callback/metadata/royalty indicators, and DEX swap/reserve/slippage/oracle/fee/flash-callback/liquidity indicators.
- Authenticated project-generation endpoint for draft project scaffolding and requirements, subject to the configured AI provider and account entitlement.
- Optional local `solc --standard-json` compilation through the paired loopback companion.
- Optional local Foundry test execution through rootless Podman with a preloaded, digest-pinned image, subject to the constraints below.
- Educational ERC-721, ERC-1155 and constant-product AMM project blueprints.

The blueprints are prompts/specifications for project generation; they are not verified, compiled, audited or deployable source packages by themselves.

## Explicit current limitations

### Solidity compiler and dependency resolution

The local companion supports both a backward-compatible single-file, import-free compiler endpoint and a multi-file project compiler. The project compiler accepts bounded flat `src/*.sol` and `test/*.sol` files plus a locally supplied OpenZeppelin Contracts 5.x source closure under `lib/openzeppelin-contracts/contracts/`. Every supplied dependency source must be covered by an exact SHA-256 lock entry; the package name, canonical repository, exact 5.x.y version and full commit identifier are checked. The source is not downloaded or installed. The same dependency manifest and remapping are accepted by the isolated Foundry runner.

Only one package is currently supported: `@openzeppelin/contracts`. `forge-std`, arbitrary packages, linked libraries and dependency installation remain unsupported. Hash matching proves consistency with the submitted lock, not that the initial source actually came from the declared Git commit; independently verify the release, commit and files.

### Static analyzer

The analyzer is regex/pattern based, not AST or control-flow analysis. It does not resolve inheritance, modifiers, storage layout, dependency code, proxy implementations, data flow, chain state or economic behaviour. A detected pattern is a review lead, not proof of a vulnerability; absence of a finding is not evidence of safety. Some identifiers can legitimately occur in safe code, and patterns can miss equivalent implementations using different names or abstractions.

It is not Slither, Mythril, Echidna, Medusa, Foundry invariant testing, symbolic execution, formal verification or an independent audit.

### Test runner

The local test runner is optional and fails closed if rootless Podman or the configured local image is unavailable. The operator must independently verify and preload a trusted Foundry image whose full reference includes a SHA-256 digest. The bridge does not pull images. The container has no network, drops Linux capabilities and applies resource limits, but this is not a formal security boundary or a substitute for a hardened isolated build host. The image must already contain the Foundry and solc versions required by the project; no compiler can be downloaded in the offline container. The runner supports only the locally supplied, hash-locked OpenZeppelin 5.x package and project-relative imports.

The repository now includes self-contained capped-NFT and constant-product AMM teaching fixtures with focused Foundry test contracts. CI checks their source paths and import graphs, but CI does not execute the Solidity tests: a real run still requires the operator's local, preloaded Foundry image and compatible compiler. The fixtures are deliberately incomplete examples, not production contracts or evidence of security.

## NFT engineering review matrix

Use the matrix as a minimum test plan, not a complete audit checklist.

| Area | Required review and tests |
|---|---|
| ERC-721 / ERC-1155 conformance | Interface support, transfer semantics, approvals, safe receiver callbacks, batch behavior, event correctness and standard-specific edge cases |
| Mint authority | Unauthorized caller rejection, role administration, ownership transfer, revoked roles, supply cap and per-ID cap boundaries |
| Reentrancy and callbacks | Malicious ERC-721/ERC-1155 receiver contracts; callback reentry during mint/transfer; invariant preservation across callbacks |
| Pause and emergency controls | Paused transfer/mint/burn policy, role restrictions, unpause authority and recovery procedures |
| Metadata | URI changes, reveal flow, content-addressed metadata, unavailable hosting, token-specific URI behavior and migration policy |
| Royalties | ERC-2981 receiver and basis-point bounds, rounding, zero/maximum sale prices and documented fact that marketplaces are not universally required to enforce royalty payments |
| Upgradeability, if present | Initializer protection, role boundaries, storage layout, implementation changes, upgrade failure and rollback assumptions |

For fixed-supply token designs, verify there is no reachable mint path, including inherited roles, privileged modules, proxy upgrades or external mint authorities. If the token is mintable, disclose who can mint, under what constraints, and whether those powers can be revoked. A fixed-supply claim must match the complete deployed architecture, not just one source file.

## DEX / AMM engineering review matrix

For a constant-product pool, the familiar invariant is commonly expressed as (x \cdot y = k), subject to the protocol's fee and rounding model. Do not assume a generic formula is sufficient for every fork or implementation. Confirm the exact protocol version and fee model.

| Area | Required review and tests |
|---|---|
| Pool creation and token ordering | Deterministic pair address, token0/token1 sorting, duplicate pair prevention, factory permissions and unsupported token behavior |
| Initial liquidity | Minimum-liquidity behavior, zero/one-unit deposits, first-provider share calculation, rounding and donation/balance mismatch |
| Subsequent liquidity | Proportional deposits, imbalanced deposits, LP share minting, fee-on/off transitions and dilution |
| Withdrawals | Proportional LP burn, minimum amounts, rounding, zero-liquidity handling and recipient validation |
| Swaps | Exact-input/exact-output calculations, fee-adjusted invariant, reserve update ordering, zero amounts and extreme reserve ratios |
| Slippage and deadlines | User-controlled minimum output / maximum input, expired deadline rejection, nonzero sensible bounds and adversarial price movement |
| Token compatibility | Fee-on-transfer, rebasing, callback-capable, pausable, blacklistable and non-standard return-value tokens; explicitly support or reject each class |
| Reentrancy and callbacks | Malicious token callbacks, flash-swap callback authentication, nested operations, state locks and repayment verification |
| Oracle use | Do not treat manipulable spot reserves as a fair external price; validate TWAP window, observation availability, source freshness, decimals, liquidity and failure behavior |
| Protocol fees | Fee recipient authority, fee-on/off transitions, invariant snapshots, rounding, dilution and fee accounting |
| MEV and transaction ordering | Sandwich exposure, public mempool assumptions, user slippage, private orderflow assumptions and chain-specific sequencing |
| Flash loans | Lender/pair authentication, initiator and asset checks, callback replay prevention, fee repayment and failed repayment reversion |

Property/invariant tests should cover, at minimum:

1. Reserves remain consistent with actual token balances under the documented token assumptions.
2. A successful swap satisfies the implementation's fee-adjusted invariant and updates reserves atomically.
3. A failed swap, failed callback or failed repayment leaves no partial state change.
4. LP shares are minted and burned according to the documented formula, within explicit rounding tolerances.
5. A liquidity provider cannot withdraw more than their share entitlement.
6. Slippage and deadline constraints revert when violated.
7. Protocol fees accrue only according to the documented fee configuration.
8. Fuzzed sequences of deposits, swaps and withdrawals preserve the core invariants.

Use independent reference calculations and differential tests against the exact upstream protocol version where possible. Include fuzzing and invariant campaigns with adversarial tokens and callback contracts. A few example unit tests are not sufficient.

## Network and router configuration

Never infer a router address from a chain name alone or assume that two DEXes with similar interfaces are interchangeable. Maintain an explicit, reviewed deployment registry keyed by chain ID and DEX deployment. Each entry should include:

- Chain ID and network name.
- DEX protocol and exact router/factory addresses.
- Official deployment reference and verification date.
- Whether the target is a testnet or production network.
- Required wrapped-native token and any router-specific method differences.
- Explorer base URL and verification configuration.

At runtime, read the connected wallet chain ID and refuse to proceed when it does not match the selected configuration. Validate router bytecode/code presence and expected interface behavior where practical. Do not use a mainnet router address on a testnet simply because the ABI is similar. Do not hardcode an address from an unverified tutorial.

The initial project does not yet provide a verified chain/DEX deployment registry or end-to-end liquidity transaction workflow. The values in any future registry must be checked against official protocol deployment documentation before being enabled.

## Deployment and wallet safety gates

Deployment and liquidity management are separate transactions and must be treated as high-impact actions.

1. **Build provenance:** pin compiler and dependency versions; preserve source, compiler settings, dependency lock data and artifact hashes.
2. **Local validation:** compile the complete dependency graph, run unit/fuzz/invariant tests, and inspect all compiler warnings.
3. **Security review:** perform independent static analysis, manual review and an external audit appropriate to the value and risk. Resolve findings before production use.
4. **Testnet rehearsal:** deploy to the selected testnet, verify source/artifacts, exercise every critical path, and rehearse failure and recovery procedures.
5. **Wallet connection:** use a standard injected wallet/provider connection. Read account and chain ID first. Never request or transmit a private key, seed phrase or wallet password.
6. **Transaction preview:** display chain, contract/router address, method, token amounts, minimum amounts, deadline, estimated network fee and recipient before the wallet prompt.
7. **Explicit signing:** the user must approve each wallet transaction. No background signing, automatic mainnet deployment or automatic liquidity addition.
8. **Post-transaction verification:** check receipt status, emitted events, deployed bytecode, token balances, pool address, reserves and LP-token balance. Provide explorer links and preserve a redacted audit trail.
9. **Liquidity controls:** explain LP ownership and withdrawal rights. A liquidity lock is a separate third-party contract and trust decision; verify its code, beneficiary, unlock time and withdrawal permissions. Do not claim that a lock guarantees project legitimacy or market safety.
10. **Production enablement:** require an explicit production-network choice and a second confirmation that clearly states real assets are at risk.

## Secret handling

Private keys, seed phrases, keystore passwords and signing credentials must never enter AI prompts, static-analysis requests, telemetry, application logs, analytics, issue reports or generated project files. Wallet signing should remain inside the user's wallet. Recovery workflows must remain isolated and offline by default, with only redacted status and metadata exposed to the AI layer.

## Readiness labels

Use precise states in the product:

- **Draft:** generated text or a blueprint; not compiled.
- **Compiled locally:** compiler completed; not tested or audited.
- **Tests passed:** the configured test suite passed; not proof of security.
- **Testnet deployed:** a transaction was confirmed on the named testnet.
- **Independently reviewed:** review scope, reviewer and report are recorded.
- **Production deployment eligible:** all required gates are documented and explicitly approved.

Never display "secure", "audited", "production-ready", "listed" or "liquidity locked" unless the exact claim has been independently verified and the supporting evidence is available.

## Next implementation stages

1. Expand NFT and AMM fixtures with adversarial callback, access-control, rounding and stateful invariant coverage; add property/fuzz/invariant execution when the sandbox image and test harness support it.
3. Verified chain/DEX deployment registry with source references and review dates.
4. Wallet connection with read-only account/network discovery.
5. Testnet deployment and liquidity preparation UI with explicit per-transaction wallet approval.
6. Transaction receipt, event, pool and LP-balance verification.
7. Independently reviewed liquidity-lock integrations and production gates.

Until those stages are implemented and verified, use the current Solidity Lab for bounded source review and the explicitly described local compiler/test capabilities only.


### Dependency-aware offline Foundry test execution

The local Foundry test runner now accepts the same explicit dependency lock used by multi-file compilation. It can stage a bounded source/test project and locally supplied OpenZeppelin Contracts 5.x files, verify every package file against the lock's SHA-256 digest, generate a Foundry remapping, and run tests in the preloaded digest-pinned rootless Podman image with network access disabled. The runner rejects unpinned dependency files, unknown package names, unresolved imports and forge-std imports. It does not pull images, install dependencies or fall back to executing tests on the host.

The Foundry image must already contain a compatible Foundry version and the exact solc version required by the project. Because the container has no network, a missing compiler cannot be downloaded at test time. The source lock proves consistency with its submitted digests but does not independently attest the original source's repository provenance. Independently verify the OpenZeppelin release, commit and image contents before use. The test runner is not a security audit; it currently supports only OpenZeppelin Contracts 5.x and does not yet support forge-std, arbitrary libraries, linked libraries, fuzzing campaigns or invariant-testing configuration.
