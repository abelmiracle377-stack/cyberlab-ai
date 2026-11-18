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
    const cipher = typeof crypto.cipher === "string" && /^[a-z0-9_-]{1,40}$/i.test(crypto.cipher) ? crypto.cipher : "unspecified";
    const kdf = typeof crypto.kdf === "string" && /^[a-z0-9_-]{1,40}$/i.test(crypto.kdf) ? crypto.kdf : "unspecified";
    const addressPresent = typeof data.address === "string" && /^[0-9a-f]{40}$/i.test(data.address.replace(/^0x/i, ""));
    const idPresent = typeof data.id === "string" && /^[0-9a-f-]{16,64}$/i.test(data.id);
    return {
      format: "Ethereum Web3 Secret Storage (V3) candidate",
      status: "recognized",
      details: [
        "Version 3 structure detected; this is a format check, not decryption or proof of authenticity.",
        "Cipher: " + cipher + ". Key derivation: " + kdf + ".",
        "Address field: " + (addressPresent ? "valid-looking" : "absent or malformed") + "; UUID field: " + (idPresent ? "present" : "absent or malformed") + ".",
        "No password was requested and no decryption was attempted."
      ]
    };
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
