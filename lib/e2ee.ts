// End-to-end encryption for CyberLab chat.
//
// ECDH (P-256) key agreement + AES-GCM authenticated encryption, using the
// WebCrypto API (`crypto.subtle`) that exists both in the browser and in Node,
// so this module is unit-tested. Each user holds an ECDH key pair; the private
// key never leaves their device. For a message, the sender derives a shared
// AES-GCM key from (their private key, the recipient's public key); the
// recipient derives the identical key from (their private key, the sender's
// public key). The server only ever stores ciphertext and an IV.
//
// This is baseline E2EE (static ECDH keys): it hides message content and media
// from the server. It does not provide per-message forward secrecy (no Signal
// double ratchet), and losing the device key makes old messages unreadable.

const subtle = (): SubtleCrypto => globalThis.crypto.subtle;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export const EC_PARAMS: EcKeyGenParams = { name: "ECDH", namedCurve: "P-256" };

function toBase64(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  for (let i = 0; i < view.length; i += 1) binary += String.fromCharCode(view[i]);
  return globalThis.btoa(binary);
}

function fromBase64(value: string): ArrayBuffer {
  const binary = globalThis.atob(value);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  // Return a plain ArrayBuffer so it is always a valid BufferSource for WebCrypto,
  // regardless of the TypeScript lib's Uint8Array<ArrayBufferLike> typing.
  return out.buffer;
}

function randomIv(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(12));
}

export async function generateKeyPair(): Promise<CryptoKeyPair> {
  return subtle().generateKey(EC_PARAMS, true, ["deriveKey", "deriveBits"]);
}

export async function exportPublicKey(key: CryptoKey): Promise<string> {
  return toBase64(await subtle().exportKey("spki", key));
}

export async function importPublicKey(base64: string): Promise<CryptoKey> {
  return subtle().importKey("spki", fromBase64(base64), EC_PARAMS, true, []);
}

// Export/import the private key as JWK so it can be persisted on-device.
export async function exportPrivateJwk(key: CryptoKey): Promise<JsonWebKey> {
  return subtle().exportKey("jwk", key);
}

export async function importPrivateJwk(jwk: JsonWebKey): Promise<CryptoKey> {
  return subtle().importKey("jwk", jwk, EC_PARAMS, true, ["deriveKey", "deriveBits"]);
}

export async function deriveSharedKey(privateKey: CryptoKey, otherPublicKey: CryptoKey): Promise<CryptoKey> {
  return subtle().deriveKey(
    { name: "ECDH", public: otherPublicKey },
    privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export type Sealed = { ciphertext: string; iv: string };

export async function encryptText(key: CryptoKey, plaintext: string): Promise<Sealed> {
  const iv = randomIv();
  const data = textEncoder.encode(plaintext).buffer as ArrayBuffer;
  const ct = await subtle().encrypt({ name: "AES-GCM", iv: iv as BufferSource }, key, data);
  return { ciphertext: toBase64(ct), iv: toBase64(iv) };
}

export async function decryptText(key: CryptoKey, sealed: Sealed): Promise<string> {
  const pt = await subtle().decrypt({ name: "AES-GCM", iv: fromBase64(sealed.iv) }, key, fromBase64(sealed.ciphertext));
  return textDecoder.decode(pt);
}

export async function encryptBytes(key: CryptoKey, data: ArrayBuffer): Promise<{ data: ArrayBuffer; iv: string }> {
  const iv = randomIv();
  const ct = await subtle().encrypt({ name: "AES-GCM", iv: iv as BufferSource }, key, data);
  return { data: ct, iv: toBase64(iv) };
}

export async function decryptBytes(key: CryptoKey, data: ArrayBuffer, iv: string): Promise<ArrayBuffer> {
  return subtle().decrypt({ name: "AES-GCM", iv: fromBase64(iv) }, key, data);
}

export const base64 = { encode: toBase64, decode: fromBase64 };
