# Wallet Recovery Intelligence Planner

The paired Kali companion exposes `POST /wallet/recovery-assess`. It accepts
wallet type, boolean evidence flags, an ownership confirmation and a case /
authorisation reference. It returns a transparent, metadata-only plan showing
supported local methods, missing evidence, known limitations and next steps.

## Safety and execution boundary

- The planner rejects seed phrases, passwords, private keys, wallet contents
  and extracted hashes. Do not send secret material to this endpoint.
- The planner never starts a cracking, derivation, network lookup, import or
  transfer operation. `execution_started` is always false.
- A `ready_for_operator_review` result means only that the declared evidence
  and authorisation metadata meet the planner's minimum gates. It is not a
  recoverability prediction or success guarantee.
- Actual recovery continues through the existing local-only wallet endpoints,
  each of which has its own input validation and explicit execution confirmation.
- Public-address checks remain read-only and require their own network consent.
- The wallet owner must independently control the destination wallet and approve
  any transfer.

## Request example

```json
{
  "walletType": "ethereum-keystore",
  "ownerConfirmed": true,
  "authorizationReference": "CASE-2026-001",
  "evidence": {
    "encryptedBackupAvailable": true,
    "passwordHintsAvailable": true,
    "walletVersionKnown": true
  }
}
```

Supported profiles: `bitcoin-core`, `ethereum-keystore`, `metamask`,
`bip39`, `electrum`, `bip38` and `unknown`.
