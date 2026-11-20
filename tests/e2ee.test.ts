import { test } from "node:test";
import assert from "node:assert/strict";
import {
  generateKeyPair, exportPublicKey, importPublicKey, deriveSharedKey,
  exportPrivateJwk, importPrivateJwk, encryptText, decryptText, encryptBytes, decryptBytes,
} from "../lib/e2ee";

test("two parties derive the same key and exchange a message", async () => {
  const alice = await generateKeyPair();
  const bob = await generateKeyPair();

  const alicePubB64 = await exportPublicKey(alice.publicKey);
  const bobPubB64 = await exportPublicKey(bob.publicKey);
  const alicePub = await importPublicKey(alicePubB64);
  const bobPub = await importPublicKey(bobPubB64);

  // Alice -> Bob
  const aliceKey = await deriveSharedKey(alice.privateKey, bobPub);
  const bobKey = await deriveSharedKey(bob.privateKey, alicePub);
  const sealed = await encryptText(aliceKey, "meet at the safehouse 🔒");
  assert.notEqual(sealed.ciphertext, "meet at the safehouse 🔒");
  const opened = await decryptText(bobKey, sealed);
  assert.equal(opened, "meet at the safehouse 🔒");
});

test("a third party cannot decrypt", async () => {
  const alice = await generateKeyPair();
  const bob = await generateKeyPair();
  const eve = await generateKeyPair();
  const aliceKey = await deriveSharedKey(alice.privateKey, bob.publicKey);
  const sealed = await encryptText(aliceKey, "classified");
  const eveKey = await deriveSharedKey(eve.privateKey, alice.publicKey);
  await assert.rejects(() => decryptText(eveKey, sealed));
});

test("private key survives JWK export/import (device persistence)", async () => {
  const alice = await generateKeyPair();
  const bob = await generateKeyPair();
  const jwk = await exportPrivateJwk(alice.privateKey);
  const restored = await importPrivateJwk(jwk);
  const k1 = await deriveSharedKey(alice.privateKey, bob.publicKey);
  const k2 = await deriveSharedKey(restored, bob.publicKey);
  const sealed = await encryptText(k1, "persisted key works");
  assert.equal(await decryptText(k2, sealed), "persisted key works");
});

test("binary (media) encryption round-trips", async () => {
  const alice = await generateKeyPair();
  const bob = await generateKeyPair();
  const key = await deriveSharedKey(alice.privateKey, bob.publicKey);
  const bobKey = await deriveSharedKey(bob.privateKey, alice.publicKey);
  const original = new Uint8Array([0, 1, 2, 3, 250, 251, 252, 255]);
  const sealed = await encryptBytes(key, original.buffer);
  const opened = new Uint8Array(await decryptBytes(bobKey, sealed.data, sealed.iv));
  assert.deepEqual(Array.from(opened), Array.from(original));
});

test("tampered ciphertext is rejected (AES-GCM authentication)", async () => {
  const alice = await generateKeyPair();
  const bob = await generateKeyPair();
  const key = await deriveSharedKey(alice.privateKey, bob.publicKey);
  const bobKey = await deriveSharedKey(bob.privateKey, alice.publicKey);
  const sealed = await encryptText(key, "do not tamper");
  const bytes = Buffer.from(sealed.ciphertext, "base64");
  bytes[0] ^= 0xff;
  const tampered = { ciphertext: bytes.toString("base64"), iv: sealed.iv };
  await assert.rejects(() => decryptText(bobKey, tampered));
});
