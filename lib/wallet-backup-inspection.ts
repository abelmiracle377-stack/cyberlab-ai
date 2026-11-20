export type WalletFormatStatus = "recognized" | "opaque" | "unsupported";
export type WalletFormatInspection = { format: string; status: WalletFormatStatus; details: string[] };

const SECRET_MATERIAL_EXTENSIONS = new Set([
  ".txt", ".seed", ".mnemonic", ".key", ".pem", ".privkey", ".privatekey", ".asc", ".env"
]);

export function isSecretMaterialFilename(filename: string): boolean {
  const normalized = filename.trim().toLowerCase();
  const extension = normalized.includes(".") ? normalized.slice(normalized.lastIndexOf(".")) : "";
  return SECRET_MATERIAL_EXTENSIONS.has(extension) ||
    /(^|[._-])(seed|mnemonic|private[-_]?key|secret|recovery[-_]?phrase|id_rsa|id_ed25519)([._-]|$)/i.test(normalized);
}

export function inspectWalletJson(value: unknown): WalletFormatInspection {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return { format: "JSON document (unclassified)", status: "unsupported", details: ["The JSON root is not an object."] };
  }

  const data = value as Record<string, unknown>;
  const cryptoValue = data.Crypto ?? data.crypto;
  if (data.version === 3 && cryptoValue && typeof cryptoValue === "object" && !Array.isArray(cryptoValue)) {
    const crypto = cryptoValue as Record<string, unknown>;
    const cipherParams = crypto.cipherparams;
    const kdfParams = crypto.kdfparams;
    const cipherValid = crypto.cipher === "aes-128-ctr";
    const kdfValid = crypto.kdf === "scrypt" || crypto.kdf === "pbkdf2";
    const ciphertextValid = typeof crypto.ciphertext === "string" &&
      crypto.ciphertext.length >= 2 && crypto.ciphertext.length % 2 === 0 && /^[0-9a-f]+$/i.test(crypto.ciphertext);
    const macValid = typeof crypto.mac === "string" && /^[0-9a-f]{64}$/i.test(crypto.mac);
    const ivValid = !!cipherParams && typeof cipherParams === "object" && !Array.isArray(cipherParams) &&
      typeof (cipherParams as Record<string, unknown>).iv === "string" &&
      /^[0-9a-f]{32}$/i.test((cipherParams as Record<string, string>).iv);
    const kdfParamsValid = !!kdfParams && typeof kdfParams === "object" && !Array.isArray(kdfParams);
    if (cipherValid && kdfValid && ciphertextValid && macValid && ivValid && kdfParamsValid) {
      const addressPresent = typeof data.address === "string" && /^[0-9a-f]{40}$/i.test(data.address.replace(/^0x/i, ""));
      const idPresent = typeof data.id === "string" && /^[0-9a-f-]{16,64}$/i.test(data.id);
      return {
        format: "Ethereum Web3 Secret Storage (V3) candidate",
        status: "recognized",
        details: [
          "Encrypted V3 structure detected; this is a format check, not decryption or proof of authenticity.",
          "Cipher: AES-128-CTR. Key derivation: " + String(crypto.kdf) + ".",
          "Address field: " + (addressPresent ? "valid-looking" : "absent or malformed") + "; UUID field: " + (idPresent ? "present" : "absent or malformed") + ".",
          "No password was requested and no decryption was attempted."
        ]
      };
    }
  }

  if (typeof data.wallet_type === "string" && data.wallet_type.length <= 40 &&
      /^(standard|2fa|multisig|imported|watch_only)$/i.test(data.wallet_type)) {
    return {
      format: "Electrum wallet JSON candidate",
      status: "recognized",
      details: [
        "A known Electrum wallet_type marker was detected; exact version and compatibility still require a trusted local adapter.",
        "No seed, private key, password or wallet payload was extracted."
      ]
    };
  }

  return { format: "JSON wallet format not recognized", status: "unsupported", details: ["The file was not matched to a supported wallet backup schema."] };
}


const SECRET_FIELD_NAMES = new Set([
  "seed", "seedphrase", "mnemonic", "mnemonicphrase", "privatekey",
  "privatekeyhex", "secret", "secretkey", "password", "walletpassword",
  "keystorepassword", "passphrase", "recoveryphrase", "xprv", "yprv",
  "zprv", "wif", "extendedprivatekey"
]);

/**
 * Detects obvious secret-bearing JSON properties before any fingerprint is
 * computed. Fails closed when the document is excessively deep or large.
 * This is a guardrail, not a proof that arbitrary JSON contains no secrets.
 */
export function containsSecretMaterialField(value: unknown): boolean {
  let visited = 0;
  const visit = (current: unknown, depth: number): boolean => {
    visited += 1;
    if (visited > 10_000 || depth > 24) return true;
    if (Array.isArray(current)) return current.some((item) => visit(item, depth + 1));
    if (!current || typeof current !== "object") return false;
    for (const [key, nested] of Object.entries(current as Record<string, unknown>)) {
      const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, "");
      if (SECRET_FIELD_NAMES.has(normalized) || visit(nested, depth + 1)) return true;
    }
    return false;
  };
  return visit(value, 0);
}
