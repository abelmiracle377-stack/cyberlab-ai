# CyberLab AI — Wallet Recovery: actual capabilities and boundaries

## Architecture and secret handling

The Wallet Recovery page has two distinct stages:

1. **Browser-local backup triage.** Selected files are inspected in the page. The page does not upload file bytes to a CyberLab API, persist the file in browser storage, or send it to hosted AI.
2. **Paired-companion recovery.** When the user chooses a recovery operation, the page sends the required mnemonic, encrypted backup data or local file path to the paired companion at 127.0.0.1:8765. The work runs on the user's own machine. The companion is not the hosted CyberLab server.

Use only a wallet you own or are explicitly authorised to recover. Never paste a seed phrase, private key, keystore password or wallet file into AI chat, support tickets, telemetry or source control. The companion is a local process, so the machine and OS account running it must be trusted and protected.

## Browser-local backup triage

- 50 MB selected-file ceiling; JSON parsing is capped at 2 MB.
- SHA-256 fingerprints are limited to .dat binary backup candidates and narrowly validated encrypted Ethereum Web3 Secret Storage V3 keystores.
- Recognises a limited set of Ethereum V3 keystore structures and basic Electrum JSON markers.
- Flags likely Bitcoin Core wallet.dat filenames without parsing or decrypting the file.
- Rejects common plaintext seed, mnemonic, private-key and SSH-key filenames before reading/fingerprinting.
- Checks JSON for common secret-bearing property names and fails closed on excessive nesting/size.
- A format match is only a structural hint. It does not prove ownership, validity, recoverability, authenticity or that the file is safe to process.

## Real paired-companion recovery functions

### Mnemonic and address derivation

- BIP39 mnemonic-to-seed and checksum validation, BIP32 hierarchical key derivation and supported BIP44/BIP49/BIP84-style paths.
- Supported account templates include Ethereum, Bitcoin legacy/nested SegWit/native SegWit/testnet, Litecoin, Dogecoin, Bitcoin Cash, Dash, Zcash transparent, Bitcoin Gold, TRON and XRP.
- Supports a BIP39 passphrase (sometimes called the 25th word).
- Electrum v2 standard and SegWit seed detection/derivation, plus old/pre-2016 Electrum seed handling using the bundled SHA-256-verified 1626-word list.
- 2FA/TrustedCoin Electrum seeds cannot be reconstructed from the seed phrase alone.

### Search for missing or misplaced mnemonic words

- Reconstructs a phrase with missing words or out-of-order words using the user's local BIP39 English wordlist.
- Uses checksum-valid candidate filtering, bounded candidate counts/time and optional known-address matching.
- A search can fail if the missing words are outside the supported search shape, the wordlist is wrong, the phrase uses a different standard/language, or the optional address/path assumptions are wrong.

### Encrypted backup hash extraction and password recovery

- Extracts supported cracking hashes from Ethereum V3 keystores (scrypt/PBKDF2), Bitcoin Core wallet.dat master-key records and MetaMask vault data.
- Runs locally installed Hashcat or John the Ripper only. Supported Hashcat formats in this integration include Ethereum scrypt/PBKDF2, Bitcoin Core wallet.dat and MetaMask vault.
- Hashcat attack modes include dictionary, mask and wordlist/mask hybrids; John supports wordlist/rules and incremental modes where configured.
- Uses the user's own local wordlist/rules files. It does not download cracking software or invent a recovered password. A password is reported only when the actual cracking tool reports a match.
- Tool absence, unsupported formats, malformed hash data, exhausted candidate sets or timeouts fail honestly rather than producing a fake success.
- BIP38 encrypted Bitcoin private keys can be decrypted with a known passphrase or searched offline against a supplied passphrase list. Both non-EC-multiply and EC-multiply formats are supported by the current implementation.

### Balance/activity checking

- Optional, read-only public explorer lookups can check derived or user-supplied public addresses for balances and prior activity.
- Only public addresses are sent to the configured allow-listed explorer. The mnemonic, private key and wallet file are not sent to that explorer.
- Explorer rate limits, unavailable APIs, unsupported networks and address derivation gaps can cause incomplete results. A zero balance result is not proof that no assets exist on other paths, chains, tokens or services.

## Important limitations

- This is not a universal wallet parser. It does not support every wallet vendor, proprietary backup format, hardware wallet, multisig setup, smart-account scheme, derivation convention or blockchain.
- Bitcoin Core wallet.dat support currently extracts an encrypted master-key hash for password recovery; it is not a complete Berkeley DB wallet parser or full wallet restore implementation.
- Ethereum V3 and MetaMask hash extraction/password recovery does not guarantee the decrypted wallet can be imported into a particular wallet version.
- Electrum 2FA/TrustedCoin, unsupported seed versions, unknown derivation paths, non-standard BIP39 wordlists and hidden/passphrase accounts may need wallet-specific recovery procedures.
- Balance discovery is bounded and explorer-dependent; it is not an exhaustive on-chain asset inventory.
- The companion's in-memory job state is local and may be lost when the process restarts.
- No function automatically signs, sweeps, broadcasts, transfers, approves tokens, changes wallet state or deploys contracts. The sweep endpoint means deriving and checking multiple account/change paths, not transferring assets.

## Safety requirements

1. Confirm ownership or written authorisation before every recovery action.
2. Keep recovery secrets on the paired local machine; never send them to hosted AI, analytics, telemetry or third-party APIs.
3. Use a trusted, patched OS account and protect local files, swap, backups and process access.
4. Use only trusted wordlists and verify their provenance. Wordlists can contain malicious or misleading content, although the runner treats them as candidate text.
5. Do not treat a successful derivation, hash extraction, password match or balance lookup as proof of full wallet recovery.
6. Preserve the original backup and work on copies wherever possible.
7. Never commit real wallet files, seed phrases, passwords, private keys or cracking outputs to the repository or CI.
