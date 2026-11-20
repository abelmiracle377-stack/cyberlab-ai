// Device-local persistence for a user's E2EE identity key pair (browser only).
//
// The private key stays on this device in localStorage (exported as a JWK) and
// is never sent to the server; only the public key is published to the profile.
// Clearing site data or switching devices creates a new key, after which older
// messages encrypted to the previous key can no longer be read on that device.

import { generateKeyPair, exportPublicKey, exportPrivateJwk, importPrivateJwk } from "@/lib/e2ee";

const storageKey = (uid: string) => `cyberlab.e2ee.${uid}`;

export type Identity = { privateKey: CryptoKey; publicKeyB64: string };

export async function loadOrCreateIdentity(uid: string): Promise<Identity> {
  try {
    const existing = localStorage.getItem(storageKey(uid));
    if (existing) {
      const parsed = JSON.parse(existing) as { priv: JsonWebKey; pub: string };
      if (parsed?.priv && parsed?.pub) {
        return { privateKey: await importPrivateJwk(parsed.priv), publicKeyB64: parsed.pub };
      }
    }
  } catch { /* fall through and regenerate */ }

  const pair = await generateKeyPair();
  const publicKeyB64 = await exportPublicKey(pair.publicKey);
  const priv = await exportPrivateJwk(pair.privateKey);
  try { localStorage.setItem(storageKey(uid), JSON.stringify({ priv, pub: publicKeyB64 })); } catch { /* private window */ }
  return { privateKey: pair.privateKey, publicKeyB64 };
}
