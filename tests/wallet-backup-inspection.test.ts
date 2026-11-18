import test from "node:test";
import assert from "node:assert/strict";
import { inspectWalletJson, isSecretMaterialFilename } from "../lib/wallet-backup-inspection";

test("refuses common plaintext secret and key file names before content handling", () => {
  for (const name of ["seed.txt", "backup.seed", "wallet.mnemonic", "private.pem", "wallet.key", "recovery_phrase.txt", "id_rsa"]) {
    assert.equal(isSecretMaterialFilename(name), true, name);
  }
  assert.equal(isSecretMaterialFilename("wallet.json"), false);
  assert.equal(isSecretMaterialFilename("wallet.dat"), false);
});

test("recognizes Ethereum V3 only from an object-shaped crypto section", () => {
  const result = inspectWalletJson({ version: 3, crypto: { cipher: "aes-128-ctr", kdf: "scrypt" }, address: "a".repeat(40), id: "12345678-1234-1234-1234-123456789abc" });
  assert.equal(result.status, "recognized");
  assert.match(result.format, /Ethereum/);
  assert.match(result.details[1], /aes-128-ctr/);
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
