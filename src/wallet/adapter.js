import {
  defaultAccountPrefix,
  derivePrivacyMaterial,
  hexFromBytes,
  bytesFromHex
} from "../core/crypto.js";
import {
  base64FromBytes,
  bytesFromBase64,
  utf8Bytes
} from "../core/browser-crypto.js";

function bytesToBase64(bytes) {
  return base64FromBytes(bytes);
}

function base64ToBytes(value, label = "base64") {
  return bytesFromBase64(value, label);
}

function normalizePubKeyHex(value) {
  if (value instanceof Uint8Array || ArrayBuffer.isView(value)) {
    if (value.length === 0) {
      throw new Error("transparent pubkey bytes must be non-empty");
    }
    return hexFromBytes(value);
  }
  const text = String(value || "").trim().replace(/^0x/i, "").toLowerCase();
  if (text.length === 0 || text.length % 2 !== 0 || !/^[0-9a-f]+$/.test(text)) {
    throw new Error("transparent pubkey must be non-empty even-length hex bytes");
  }
  return text;
}

function normalizeSignatureBytes(signature, label = "privacy root signature") {
  if (signature instanceof Uint8Array || ArrayBuffer.isView(signature)) {
    return Uint8Array.from(signature);
  }
  if (typeof signature === "string") {
    const text = signature.trim();
    if (/^0x[0-9a-fA-F]+$/.test(text)) {
      return bytesFromHex(text.replace(/^0x/i, ""), label);
    }
    if (text.length >= 64 && text.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(text)) {
      throw new Error(`${label} hex strings must be prefixed with 0x`);
    }
    return base64ToBytes(text, label);
  }
  if (signature?.signatureHex || signature?.signature_hex) {
    return bytesFromHex(signature.signatureHex ?? signature.signature_hex, label);
  }
  if (signature?.signatureBase64 || signature?.signature_base64) {
    return base64ToBytes(signature.signatureBase64 ?? signature.signature_base64, label);
  }
  if (signature?.signature) {
    return normalizeSignatureBytes(signature.signature, label);
  }
  throw new Error(`${label} must be bytes, hex, or base64`);
}

export function buildPrivacyRootSigningMessage({ address, transparentPubKeyHex, pubKeyHex }) {
  const resolvedPubKeyHex = normalizePubKeyHex(transparentPubKeyHex ?? pubKeyHex);
  return [
    "clairveil-root-v1",
    `address:${String(address || "").trim()}`,
    `pubkey:${resolvedPubKeyHex}`
  ].join("\n");
}

export function createWalletAdapter(input = {}) {
  if (!input || typeof input !== "object") {
    throw new Error("wallet adapter input is required");
  }

  const getAddress = input.getAddress
    ? () => input.getAddress()
    : async () => {
      if (!input.address) throw new Error("wallet adapter address is required");
      return String(input.address);
    };

  const getPubKeyHex = input.getPubKeyHex
    ? async () => normalizePubKeyHex(await input.getPubKeyHex())
    : async () => normalizePubKeyHex(input.pubKeyHex ?? input.pub_key_hex ?? input.pubKeyBytes ?? input.pub_key_bytes);

  const signPrivacyRootBase64 = async (messageBytes, context = {}) => {
    if (input.signPrivacyRootBase64) {
      return String(await input.signPrivacyRootBase64(messageBytes, context));
    }
    if (!input.signPrivacyRoot) {
      throw new Error("wallet adapter signPrivacyRoot(messageBytes) is required");
    }
    const signature = await input.signPrivacyRoot(messageBytes, context);
    return bytesToBase64(normalizeSignatureBytes(signature));
  };

  return {
    async getAddress() {
      return String(await getAddress()).trim();
    },

    async getPubKeyHex() {
      return getPubKeyHex();
    },

    async getPubKeyBytes() {
      return bytesFromHex(await getPubKeyHex(), "wallet pubkey");
    },

    async signPrivacyRoot(messageBytes, context = {}) {
      return base64ToBytes(await signPrivacyRootBase64(messageBytes, context), "privacy root signature");
    },

    async signPrivacyRootBase64(messageBytes, context = {}) {
      return signPrivacyRootBase64(messageBytes, context);
    },

    async signDirect(signDoc, context = {}) {
      if (!input.signDirect) {
        throw new Error("wallet adapter signDirect(signDoc) is not available");
      }
      return input.signDirect(signDoc, context);
    },

    async broadcastSignedTx(signedTx, context = {}) {
      if (!input.broadcastSignedTx) {
        throw new Error("wallet adapter broadcastSignedTx(signedTx) is not available");
      }
      return input.broadcastSignedTx(signedTx, context);
    }
  };
}

export async function derivePrivacyMaterialFromWallet(walletLike, options = {}) {
  const wallet = createWalletAdapter(walletLike);
  const address = await wallet.getAddress();
  const pubKeyHex = await wallet.getPubKeyHex();
  const signingMessage = buildPrivacyRootSigningMessage({
    address,
    transparentPubKeyHex: pubKeyHex
  });
  const messageBytes = utf8Bytes(signingMessage);
  const signatureBase64 = await wallet.signPrivacyRootBase64(messageBytes, {
    address,
    pubKeyHex,
    signingMessage
  });
  const material = derivePrivacyMaterial({
    address,
    pubKeyHex,
    signatureBase64,
    shieldedPrefix: options.shieldedPrefix ?? walletLike?.shieldedPrefix
  });

  return {
    ...material,
    address,
    pubKeyHex,
    signatureBase64,
    signingMessage
  };
}

export function createKeplrWalletAdapter({ keplr, chainId, address, accountPrefix, bech32Prefix = accountPrefix ?? defaultAccountPrefix } = {}) {
  if (!keplr) {
    throw new Error("keplr instance is required");
  }
  if (!chainId) {
    throw new Error("chainId is required for Keplr wallet adapter");
  }

  async function key() {
    await keplr.enable(chainId);
    const resolved = await keplr.getKey(chainId);
    if (address && resolved.bech32Address !== address) {
      throw new Error(`Keplr address mismatch: expected ${address}, got ${resolved.bech32Address}`);
    }
    if (!resolved.bech32Address.startsWith(`${bech32Prefix}1`)) {
      throw new Error(`Keplr address prefix mismatch: expected ${bech32Prefix}`);
    }
    return resolved;
  }

  return createWalletAdapter({
    async getAddress() {
      return (await key()).bech32Address;
    },

    async getPubKeyHex() {
      return hexFromBytes((await key()).pubKey);
    },

    async signPrivacyRoot(_messageBytes, { signingMessage } = {}) {
      if (!keplr.signArbitrary) {
        throw new Error("Keplr signArbitrary is required for Clairveil root signing");
      }
      const resolved = await key();
      const signature = await keplr.signArbitrary(chainId, resolved.bech32Address, signingMessage);
      return base64ToBytes(signature.signature, "Keplr arbitrary signature");
    },

    async signDirect(signDoc) {
      if (!keplr.signDirect) {
        throw new Error("Keplr signDirect is required");
      }
      const resolved = await key();
      return keplr.signDirect(chainId, resolved.bech32Address, signDoc);
    }
  });
}

export function createOfflineSignerWalletAdapter({
  signer,
  address,
  accountPrefix,
  bech32Prefix = accountPrefix ?? defaultAccountPrefix,
  signPrivacyRoot,
  signPrivacyRootBase64
} = {}) {
  if (!signer) {
    throw new Error("CosmJS offline signer is required");
  }
  if (!signPrivacyRoot && !signPrivacyRootBase64) {
    throw new Error("offline signer adapter requires signPrivacyRoot or signPrivacyRootBase64 for Clairveil root signing");
  }

  async function account() {
    const accounts = await signer.getAccounts();
    if (!Array.isArray(accounts) || accounts.length === 0) {
      throw new Error("offline signer returned no accounts");
    }
    const selected = address
      ? accounts.find(candidate => candidate.address === address)
      : accounts[0];
    if (!selected) {
      throw new Error(`offline signer has no account ${address}`);
    }
    if (!selected.address.startsWith(`${bech32Prefix}1`)) {
      throw new Error(`offline signer address prefix mismatch: expected ${bech32Prefix}`);
    }
    if (!selected.pubkey) {
      throw new Error("offline signer account pubkey is required");
    }
    return selected;
  }

  return createWalletAdapter({
    async getAddress() {
      return (await account()).address;
    },

    async getPubKeyHex() {
      return hexFromBytes((await account()).pubkey);
    },

    signPrivacyRoot,
    signPrivacyRootBase64,

    async signDirect(signDoc) {
      if (typeof signer.signDirect !== "function") {
        throw new Error("offline signer does not support signDirect");
      }
      return signer.signDirect((await account()).address, signDoc);
    }
  });
}
