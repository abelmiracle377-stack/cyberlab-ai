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


## Local execution (implemented)

The companion now exposes `POST /wallet/recovery-run` for the first end-to-end
execution path: **derive-and-check**. It requires all of the following:
- The owner/authorised-operator confirmation.
- A non-empty case/authorisation reference.
- A separate explicit confirmation for the run.
- The mnemonic and optional passphrase supplied directly to the paired
  loopback companion, never to the hosted application API.

The executor invokes the existing `wallet_auto_recover` engine locally. It
detects supported BIP39/Electrum schemes, derives public addresses across the
configured account templates and change paths, and can optionally perform
read-only public balance lookups after a second network-consent flag. The
executor serialises only the public result fields returned by that engine.

This execution path does **not** crack encrypted backup passwords, parse every
vendor backup, restore Bitcoin Core databases, sign transactions, or transfer
assets. Those require separate format-specific execution adapters and tests.
A completed derivation is not proof that the wallet has been fully recovered.
