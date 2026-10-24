import sodium from 'sodium-native';
import {
  ENVELOPE_VERSION,
  KDF_MEM_LIMIT,
  KDF_OPS_LIMIT,
  type EncryptedItem,
  type KeyBundle,
  type SecretBox,
  type VaultItem,
  type VaultItemKind,
} from '../shared/api.js';

const liveBuffers = new Set<LockedBuffer>();

export class LockedBuffer {
  readonly buffer: Buffer;
  private disposed = false;

  constructor(size: number) {
    if (!Number.isSafeInteger(size) || size < 0) {
      throw new Error('Invalid secure buffer size.');
    }

    this.buffer = sodium.sodium_malloc(size);
    try {
      sodium.sodium_mlock(this.buffer);
    } catch (error) {
      sodium.sodium_memzero(this.buffer);
      (sodium as typeof sodium & { sodium_free(buffer: Buffer): void }).sodium_free(this.buffer);
      throw new Error('Unable to lock secure memory. Check the system memory-lock limit; refusing to use an unlocked buffer.', {
        cause: error,
      });
    }
    liveBuffers.add(this);
  }

  get disposedValue(): boolean {
    return this.disposed;
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    liveBuffers.delete(this);
    try {
      sodium.sodium_memzero(this.buffer);
    } finally {
      try {
        sodium.sodium_munlock(this.buffer);
      } finally {
        (sodium as typeof sodium & { sodium_free(buffer: Buffer): void }).sodium_free(this.buffer);
      }
    }
  }
}

export function allocateLockedCopy(source: Buffer): LockedBuffer {
  const destination = new LockedBuffer(source.length);
  source.copy(destination.buffer);
  return destination;
}

export function disposeAllSecureMemory(): void {
  for (const allocation of [...liveBuffers]) {
    try {
      allocation.dispose();
    } catch {
      // Continue cleaning the remaining allocations during process shutdown.
    }
  }
}

export function encodeBase64url(value: Buffer): string {
  return value.toString('base64url');
}

export function decodeBase64url(value: string, label = 'value'): Buffer {
  if (typeof value !== 'string' || value.length === 0 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error(`Invalid Base64url ${label}.`);
  }
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.toString('base64url') !== value) {
    throw new Error(`Invalid Base64url ${label}.`);
  }
  return decoded;
}

function requireLength(value: Buffer, expected: number, label: string): void {
  if (value.length !== expected) {
    throw new Error(`Invalid ${label} length.`);
  }
}

export function deriveKek(password: LockedBuffer, bundle: KeyBundle): LockedBuffer {
  if (bundle.opsLimit !== KDF_OPS_LIMIT || bundle.memLimit !== KDF_MEM_LIMIT) {
    throw new Error('Unsupported key-derivation parameters in the account bundle.');
  }
  const salt = decodeBase64url(bundle.salt, 'salt');
  requireLength(salt, 16, 'salt');
  const kek = new LockedBuffer(sodium.crypto_secretbox_KEYBYTES);
  try {
    sodium.crypto_pwhash(
      kek.buffer,
      password.buffer,
      salt,
      KDF_OPS_LIMIT,
      KDF_MEM_LIMIT,
      sodium.crypto_pwhash_ALG_ARGON2ID13,
    );
    return kek;
  } catch (error) {
    kek.dispose();
    throw new Error('Unable to derive the account key.', { cause: error });
  }
}

export function decryptSecretBox(
  box: SecretBox,
  kek: LockedBuffer,
  plaintextLength: number,
): LockedBuffer {
  const nonce = decodeBase64url(box.nonce, 'SecretBox nonce');
  const ciphertext = decodeBase64url(box.ciphertext, 'SecretBox ciphertext');
  requireLength(nonce, sodium.crypto_secretbox_NONCEBYTES, 'SecretBox nonce');
  if (ciphertext.length !== plaintextLength + sodium.crypto_secretbox_MACBYTES) {
    throw new Error('Invalid encrypted secret length.');
  }

  const plaintext = new LockedBuffer(plaintextLength);
  try {
    if (!sodium.crypto_secretbox_open_easy(plaintext.buffer, ciphertext, nonce, kek.buffer)) {
      throw new Error('Unable to decrypt the account secrets; check the master password.');
    }
    return plaintext;
  } catch (error) {
    plaintext.dispose();
    if (error instanceof Error && error.message.includes('master password')) throw error;
    throw new Error('Unable to decrypt the account secrets.', { cause: error });
  }
}

export function unsealVaultKey(bundle: KeyBundle, vaultSecret: LockedBuffer): LockedBuffer {
  requireLength(vaultSecret.buffer, sodium.crypto_box_SECRETKEYBYTES, 'vault secret');
  const vaultPublicKey = decodeBase64url(bundle.vaultPublicKey, 'vault public key');
  const sealed = decodeBase64url(bundle.sealedVaultKey, 'sealed vault key');
  requireLength(vaultPublicKey, sodium.crypto_box_PUBLICKEYBYTES, 'vault public key');
  if (sealed.length !== sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES + sodium.crypto_box_SEALBYTES) {
    throw new Error('Invalid sealed vault key length.');
  }

  const vaultKey = new LockedBuffer(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
  try {
    if (!sodium.crypto_box_seal_open(vaultKey.buffer, sealed, vaultPublicKey, vaultSecret.buffer)) {
      throw new Error('Unable to unseal the vault key; the account bundle is inconsistent.');
    }
    return vaultKey;
  } catch (error) {
    vaultKey.dispose();
    if (error instanceof Error && error.message.includes('account bundle')) throw error;
    throw new Error('Unable to unseal the vault key.', { cause: error });
  }
}

export type UnlockedVault = {
  identityPublicKey: string;
  vaultKey: LockedBuffer;
  signChallenge: (challenge: string) => Buffer;
  close: () => void;
};

export function unlockBundle(bundle: KeyBundle, password: LockedBuffer): UnlockedVault {
  const kek = deriveKek(password, bundle);
  let identitySecret: LockedBuffer | undefined;
  let vaultSecret: LockedBuffer | undefined;
  let transferred = false;
  try {
    identitySecret = decryptSecretBox(
      bundle.encryptedIdentitySecret,
      kek,
      sodium.crypto_sign_SECRETKEYBYTES,
    );
    vaultSecret = decryptSecretBox(
      bundle.encryptedVaultSecret,
      kek,
      sodium.crypto_box_SECRETKEYBYTES,
    );

    const expectedIdentityKey = decodeBase64url(bundle.identityPublicKey, 'identity public key');
    requireLength(expectedIdentityKey, sodium.crypto_sign_PUBLICKEYBYTES, 'identity public key');
    const actualIdentityKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
    sodium.crypto_sign_ed25519_sk_to_pk(actualIdentityKey, identitySecret.buffer);
    if (!sodium.sodium_memcmp(actualIdentityKey, expectedIdentityKey)) {
      throw new Error('The decrypted identity does not match the account bundle.');
    }

    const vaultKey = unsealVaultKey(bundle, vaultSecret);
    const signingKey = identitySecret;
    transferred = true;
    return {
      identityPublicKey: bundle.identityPublicKey,
      vaultKey,
      signChallenge: (challenge: string) => {
        if (signingKey.disposedValue) throw new Error('The vault is locked.');
        const challengeBytes = decodeBase64url(challenge, 'challenge');
        const signature = Buffer.alloc(sodium.crypto_sign_BYTES);
        sodium.crypto_sign_detached(signature, challengeBytes, signingKey.buffer);
        return signature;
      },
      close: () => {
        try {
          signingKey.dispose();
        } finally {
          vaultKey.dispose();
        }
      },
    };
  } finally {
    if (!transferred) identitySecret?.dispose();
    vaultSecret?.dispose();
    kek.dispose();
  }
}

export function itemAad(identityPublicKey: string, itemId: string): Buffer {
  return Buffer.from(`lockit-item-v1:${identityPublicKey}:${itemId}`, 'utf8');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isKind(value: unknown): value is VaultItemKind {
  return value === 'password' || value === 'api-key' || value === 'document';
}

function parseVaultItem(value: unknown, encryptedItem: EncryptedItem): VaultItem {
  if (!isRecord(value)) throw new Error('Decrypted item is not an object.');
  const optionalFields = ['username', 'secret', 'notes', 'url', 'documentName', 'documentType', 'documentData'] as const;
  if (
    value.id !== encryptedItem.id ||
    !isKind(value.kind) ||
    typeof value.title !== 'string' ||
    typeof value.updatedAt !== 'string' ||
    optionalFields.some((field) => value[field] !== undefined && typeof value[field] !== 'string')
  ) {
    throw new Error('Decrypted item has an invalid shape.');
  }
  return value as VaultItem;
}

export function decryptItem(
  encryptedItem: EncryptedItem,
  vaultKey: LockedBuffer,
  identityPublicKey: string,
): VaultItem {
  if (encryptedItem.version !== ENVELOPE_VERSION || typeof encryptedItem.id !== 'string' || encryptedItem.id.length === 0) {
    throw new Error('Unsupported or invalid encrypted item.');
  }
  const nonce = decodeBase64url(encryptedItem.nonce, 'item nonce');
  const ciphertext = decodeBase64url(encryptedItem.ciphertext, 'item ciphertext');
  requireLength(nonce, sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, 'item nonce');
  if (ciphertext.length < sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES) {
    throw new Error('Invalid item ciphertext length.');
  }

  const plaintext = new LockedBuffer(ciphertext.length - sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES);
  try {
    sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      plaintext.buffer,
      null,
      ciphertext,
      itemAad(identityPublicKey, encryptedItem.id),
      nonce,
      vaultKey.buffer,
    );
    return parseVaultItem(JSON.parse(plaintext.buffer.toString('utf8')), encryptedItem);
  } catch (error) {
    throw new Error('Unable to decrypt or validate the vault item.', { cause: error });
  } finally {
    plaintext.dispose();
  }
}
