import test from "node:test";
import assert from "node:assert/strict";
import { containsSecretMaterialField, inspectWalletJson, isSecretMaterialFilename } from "../lib/wallet-backup-inspection";

test("refuses common plaintext secret and key file names before content handling", () => {
  for (const name of ["seed.txt", "backup.seed", "wallet.mnemonic", "private.pem", "wallet.key", "recovery_phrase.txt", "id_rsa"]) {
    assert.equal(isSecretMaterialFilename(name), true, name);
  }
  assert.equal(isSecretMaterialFilename("wallet.json"), false);
  assert.equal(isSecretMaterialFilename("wallet.dat"), false);
});

test("recognizes Ethereum V3 only from an object-shaped crypto section", () => {
  const result = inspectWalletJson({ version: 3, crypto: { cipher: "aes-128-ctr", kdf: "scrypt", cipherparams: { iv: "b".repeat(32) }, ciphertext: "c".repeat(64), mac: "d".repeat(64), kdfparams: { dklen: 32, n: 262144, r: 8, p: 1, salt: "e".repeat(64) } }, address: "a".repeat(40), id: "12345678-1234-1234-1234-123456789abc" });
  assert.equal(result.status, "recognized");
  assert.match(result.format, /Ethereum/);
  assert.match(result.details[1], /AES-128-CTR/);
});

test("does not classify malformed V3 or arbitrary wallet_type markers", () => {
  assert.equal(inspectWalletJson({ version: 3, crypto: [] }).status, "unsupported");
  assert.equal(inspectWalletJson({ wallet_type: "made-up-format" }).status, "unsupported");
});

test("does not expose arbitrary untrusted cipher and KDF values", () => {
  const result = inspectWalletJson({ version: 3, crypto: { cipher: "seed phrase should not appear", kdf: "private key" } });
  assert.equal(result.details.some((line) => /seed phrase|private key/i.test(line)), false);
});

test("rejects non-object JSON roots", () => {
  assert.equal(inspectWalletJson(["not", "a", "wallet"]).status, "unsupported");
  assert.equal(inspectWalletJson(null).status, "unsupported");
});


test("detects secret-bearing fields recursively before JSON fingerprinting", () => {
  assert.equal(containsSecretMaterialField({ wallet: { seed_phrase: "synthetic" } }), true);
  assert.equal(containsSecretMaterialField({ crypto: { privateKey: "synthetic" } }), true);
  assert.equal(containsSecretMaterialField({ metadata: { label: "cold storage" } }), false);
});

test("fails closed on excessively deep JSON structures", () => {
  let value: Record<string, unknown> = {};
  const root = value;
  for (let index = 0; index < 26; index += 1) {
    const next: Record<string, unknown> = {};
    value.child = next;
    value = next;
  }
  assert.equal(containsSecretMaterialField(root), true);
});


test("does not fingerprint a partial Ethereum V3-shaped JSON object", () => {
  const result = inspectWalletJson({ version: 3, crypto: { cipher: "aes-128-ctr", kdf: "scrypt" } });
  assert.equal(result.status, "unsupported");
});
