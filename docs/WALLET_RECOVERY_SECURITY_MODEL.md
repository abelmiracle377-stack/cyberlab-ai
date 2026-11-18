# Crypto Wallet Recovery Lab — current scope and security boundary

## Current release: local backup triage

The initial Wallet Recovery route is a browser-local triage workspace. It can:
- Fingerprint opaque binary backup candidates and narrow Ethereum V3 keystore candidates with SHA-256 using Web Crypto.
- Scan JSON property names for common secret-bearing fields before any fingerprint is considered; fail closed on excessive JSON depth/size.
- Recognize a narrow Ethereum Web3 Secret Storage V3 JSON structure.
- Recognize basic Electrum-style JSON markers without extracting wallet material.
- Identify likely Bitcoin Core `wallet.dat` filenames without parsing the binary format.
- Enforce a 50 MB file limit and a 2 MB JSON parsing limit before reading file contents.
- Reject common plaintext seed, mnemonic, private-key and SSH-key filenames before reading or fingerprinting them.
- Disable overlapping file selections while a local inspection is in progress.

The browser page does not call a server endpoint, upload file bytes, persist the selected file, store secrets in local storage/session storage, send telemetry, request wallet access, or sign/broadcast transactions. Common text/seed/private-key filenames are deliberately rejected before reading or fingerprinting. JSON is parsed locally before fingerprinting; obvious nested secret-bearing property names are rejected, and only the narrow Ethereum V3 candidate receives a JSON fingerprint. Electrum and unknown JSON receive no fingerprint because they may contain wallet secrets. These structural checks cannot identify every disguised or unlabelled secret value, so users must still select encrypted backups only. A file-format match is not proof of wallet validity, ownership, recoverability or authenticity.

## Not yet implemented

This release does not perform password recovery, mnemonic validation, BIP39 derivation, address matching, Bitcoin Core wallet parsing, hardware-wallet interaction, Electrum decryption, encrypted-key extraction, cracking, or recovery job orchestration. Ethereum V3 recognition is structural only; no decryption or password processing occurs. The adapter availability labels in the UI are explicit status indicators, not tool integrations.

## Required design before recovery adapters

1. Keep recovery computation local or in a separately isolated, operator-controlled worker. Do not send seed phrases, private keys, wallet files, passwords, candidate lists or decrypted key material to hosted AI, analytics, logs, telemetry or third-party APIs.
2. Use vetted, pinned parser/crypto implementations and publish supported wallet versions and compatibility fixtures.
3. Require explicit user confirmation that the backup is theirs or that they are authorised to recover it.
4. Use bounded CPU, memory, candidate count and execution time; provide cancellation and clear progress.
5. Keep secrets in process memory only where possible, redact crash/error output, and zero buffers on a best-effort basis after work.
6. Return results directly to the user-controlled local environment. Never auto-sign, sweep, broadcast, transfer or change wallet state.
7. Add synthetic test fixtures only. Never add real wallet files, seeds, passwords or private keys to the repository or CI.

## Solidity Lab

The existing Solidity Lab remains on the feature branch and is not replaced by this work. Its scope and limitations are documented in [BLOCKCHAIN_ENGINEERING.md](./BLOCKCHAIN_ENGINEERING.md). Heuristic review, compilation, local Foundry tests and generated project drafts must not be represented as an independent audit or production deployment approval.
