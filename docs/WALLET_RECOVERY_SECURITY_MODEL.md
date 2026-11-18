# Crypto Wallet Recovery Lab — current scope and security boundary

## Current release: local backup triage

The initial Wallet Recovery route is a browser-local triage workspace. It can:
- Fingerprint a selected backup with SHA-256 using Web Crypto.
- Recognize a narrow Ethereum Web3 Secret Storage V3 JSON structure.
- Recognize basic Electrum-style JSON markers without extracting wallet material.
- Identify likely Bitcoin Core `wallet.dat` filenames without parsing the binary format.
- Enforce a 50 MB file limit and a 2 MB JSON parsing limit.

The browser page does not call a server endpoint, upload file bytes, persist the selected file, store secrets in local storage/session storage, send telemetry, request wallet access, or sign/broadcast transactions. Text/seed files are deliberately not read. A file-format match is not proof of wallet validity, ownership, recoverability or authenticity.

## Not yet implemented

This release does not perform password recovery, mnemonic validation, BIP39 derivation, address matching, Bitcoin Core wallet parsing, hardware-wallet interaction, Electrum decryption, encrypted-key extraction, cracking, or recovery job orchestration. The adapter availability labels in the UI are explicit status indicators, not tool integrations.

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
