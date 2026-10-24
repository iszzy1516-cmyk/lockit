import sodium from 'libsodium-wrappers-sumo';
import {
  ENVELOPE_VERSION,
  KDF_MEM_LIMIT,
  KDF_OPS_LIMIT,
  type EncryptedItem,
  type KeyBundle,
  type SecretBox,
  type VaultItem,
} from './api';

export type UnlockedKeys = {
  identitySecretKey: Uint8Array;
  vaultSecretKey: Uint8Array;
  vaultKey: Uint8Array;
};

export type CredentialMode = 'master' | 'recovery';

export type RecoveryMaterial = {
  recoveryKey: Uint8Array;
  recoveryKeyEncoded: string;
};

export type RegistrationKeys = RecoveryMaterial & {
  bundle: KeyBundle;
  keys: UnlockedKeys;
};

export type RecoveryRotation = RecoveryMaterial & { bundle: KeyBundle };

export type EncryptedShare = SecretBox & { key: string };

export type HibpResult = {
  status: 'compromised' | 'not-found' | 'unknown';
  count: number;
};

const ITEM_AAD_PREFIX = 'lockit-item-v1';
const SHARE_AAD_PREFIX = 'lockit-share-v1';

async function ready(): Promise<void> {
  await sodium.ready;
}

export function toBase64Url(value: Uint8Array): string {
  return sodium.to_base64(value, sodium.base64_variants.URLSAFE_NO_PADDING);
}

export function fromBase64Url(value: string): Uint8Array {
  return sodium.from_base64(value, sodium.base64_variants.URLSAFE_NO_PADDING);
}

export function wipeRecoveryKey(key: Uint8Array | null | undefined): void {
  if (!key) return;
  try {
    sodium.memzero(key);
  } catch {
    key.fill(0);
  }
}

export async function parseRecoveryKey(text: string): Promise<Uint8Array> {
  await ready();
  const input = text.trim();
  const lines = input.split(/\r?\n/).map((line) => line.trim());
  const labeled = lines.filter((line) => line.startsWith('Recovery key:'));
  let encoded = input;
  if (labeled.length > 0) {
    if (labeled.length !== 1) throw new Error('The recovery file contains multiple recovery keys.');
    encoded = labeled[0]!.slice('Recovery key:'.length).trim();
  }
  if (!/^[A-Za-z0-9_-]{43}$/.test(encoded)) {
    throw new Error('The recovery key must be 32 bytes encoded as canonical unpadded base64url.');
  }
  let key: Uint8Array | undefined;
  try {
    key = fromBase64Url(encoded);
    if (key.length !== 32 || toBase64Url(key) !== encoded) throw new Error('Invalid recovery key encoding.');
    return key;
  } catch {
    wipeRecoveryKey(key);
    throw new Error('The recovery key is invalid. Use a key from a Lockit recovery file.');
  }
}

async function deriveKek(password: string, bundle: Pick<KeyBundle, 'salt' | 'opsLimit' | 'memLimit'>): Promise<Uint8Array> {
  await ready();
  const salt = fromBase64Url(bundle.salt);
  try {
    return sodium.crypto_pwhash(
      32,
      password,
      salt,
      bundle.opsLimit,
      bundle.memLimit,
      sodium.crypto_pwhash_ALG_ARGON2ID13,
    );
  } finally {
    sodium.memzero(salt);
  }
}

async function sealSecret(secret: Uint8Array, kek: Uint8Array): Promise<SecretBox> {
  await ready();
  const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
  try {
    return {
      nonce: toBase64Url(nonce),
      ciphertext: toBase64Url(sodium.crypto_secretbox_easy(secret, nonce, kek)),
    };
  } finally {
    sodium.memzero(nonce);
  }
}

async function openSecret(box: SecretBox, kek: Uint8Array, errorMessage: string): Promise<Uint8Array> {
  await ready();
  const nonce = fromBase64Url(box.nonce);
  const ciphertext = fromBase64Url(box.ciphertext);
  try {
    return sodium.crypto_secretbox_open_easy(ciphertext, nonce, kek);
  } catch {
    throw new Error(errorMessage);
  } finally {
    sodium.memzero(nonce);
    sodium.memzero(ciphertext);
  }
}

export async function createRegistration(password: string): Promise<RegistrationKeys> {
  await ready();
  const identity = sodium.crypto_sign_keypair();
  const vault = sodium.crypto_box_keypair();
  const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
  const vaultKey = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
  const recoveryKey = sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES);
  let kek: Uint8Array | undefined;
  try {
    const bundleBase = {
      salt: toBase64Url(salt),
      opsLimit: KDF_OPS_LIMIT,
      memLimit: KDF_MEM_LIMIT,
      identityPublicKey: toBase64Url(identity.publicKey),
      vaultPublicKey: toBase64Url(vault.publicKey),
    };
    kek = await deriveKek(password, bundleBase);
    const [encryptedIdentitySecret, encryptedVaultSecret, encryptedRecoveryIdentitySecret, encryptedRecoveryVaultSecret] = await Promise.all([
      sealSecret(identity.privateKey, kek),
      sealSecret(vault.privateKey, kek),
      sealSecret(identity.privateKey, recoveryKey),
      sealSecret(vault.privateKey, recoveryKey),
    ]);
    return {
      bundle: {
        ...bundleBase,
        encryptedIdentitySecret,
        encryptedRecoveryIdentitySecret,
        encryptedVaultSecret,
        encryptedRecoveryVaultSecret,
        sealedVaultKey: toBase64Url(sodium.crypto_box_seal(vaultKey, vault.publicKey)),
      },
      keys: {
        identitySecretKey: identity.privateKey,
        vaultSecretKey: vault.privateKey,
        vaultKey,
      },
      recoveryKey,
      recoveryKeyEncoded: toBase64Url(recoveryKey),
    };
  } catch (error) {
    wipeKeys({ identitySecretKey: identity.privateKey, vaultSecretKey: vault.privateKey, vaultKey });
    wipeRecoveryKey(recoveryKey);
    throw error;
  } finally {
    sodium.memzero(salt);
    sodium.memzero(identity.publicKey);
    sodium.memzero(vault.publicKey);
    if (kek) sodium.memzero(kek);
  }
}

export async function unlock(credential: string | Uint8Array, bundle: KeyBundle, mode: CredentialMode): Promise<UnlockedKeys> {
  await ready();
  let credentialKey: Uint8Array | undefined;
  let identitySecretKey: Uint8Array | undefined;
  let vaultSecretKey: Uint8Array | undefined;
  let sealedVaultKey: Uint8Array | undefined;
  let vaultPublicKey: Uint8Array | undefined;
  try {
    const master = mode === 'master';
    if (master && typeof credential !== 'string') throw new Error('A master password is required.');
    if (!master && !(credential instanceof Uint8Array)) throw new Error('A decoded recovery key is required.');
    credentialKey = master
      ? await deriveKek(credential as string, bundle)
      : new Uint8Array(credential as Uint8Array);
    if (!master && credentialKey.length !== 32) throw new Error('The recovery key must contain exactly 32 bytes.');
    const errorMessage = master
      ? 'The master password is incorrect or this key bundle is damaged.'
      : 'The recovery key is incorrect or this key bundle is damaged.';
    identitySecretKey = await openSecret(master ? bundle.encryptedIdentitySecret : bundle.encryptedRecoveryIdentitySecret, credentialKey, errorMessage);
    vaultSecretKey = await openSecret(master ? bundle.encryptedVaultSecret : bundle.encryptedRecoveryVaultSecret, credentialKey, errorMessage);
    sealedVaultKey = fromBase64Url(bundle.sealedVaultKey);
    vaultPublicKey = fromBase64Url(bundle.vaultPublicKey);
    const vaultKey = sodium.crypto_box_seal_open(sealedVaultKey, vaultPublicKey, vaultSecretKey);
    if (!vaultKey) throw new Error('The vault key could not be opened.');
    return { identitySecretKey, vaultSecretKey, vaultKey };
  } catch (error) {
    if (identitySecretKey) sodium.memzero(identitySecretKey);
    if (vaultSecretKey) sodium.memzero(vaultSecretKey);
    throw error;
  } finally {
    wipeRecoveryKey(credentialKey);
    if (sealedVaultKey) sodium.memzero(sealedVaultKey);
    if (vaultPublicKey) sodium.memzero(vaultPublicKey);
  }
}

export async function signChallenge(challenge: string, identitySecretKey: Uint8Array): Promise<string> {
  await ready();
  const message = fromBase64Url(challenge);
  try {
    return toBase64Url(sodium.crypto_sign_detached(message, identitySecretKey));
  } finally {
    sodium.memzero(message);
  }
}

function itemAad(userId: string, itemId: string): Uint8Array {
  return sodium.from_string(`${ITEM_AAD_PREFIX}:${userId}:${itemId}`);
}

function shareAad(shareId: string): Uint8Array {
  return sodium.from_string(`${SHARE_AAD_PREFIX}:${shareId}`);
}

async function encryptJson(value: unknown, aad: Uint8Array, key: Uint8Array): Promise<SecretBox> {
  await ready();
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const plaintext = sodium.from_string(JSON.stringify(value));
  try {
    return {
      nonce: toBase64Url(nonce),
      ciphertext: toBase64Url(sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, null, nonce, key)),
    };
  } finally {
    sodium.memzero(nonce);
    sodium.memzero(plaintext);
    sodium.memzero(aad);
  }
}

async function decryptJson(box: SecretBox, aad: Uint8Array, key: Uint8Array): Promise<unknown> {
  await ready();
  const nonce = fromBase64Url(box.nonce);
  const ciphertext = fromBase64Url(box.ciphertext);
  let plaintext: Uint8Array | undefined;
  try {
    plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, aad, nonce, key);
    return JSON.parse(sodium.to_string(plaintext)) as unknown;
  } catch {
    throw new Error('This encrypted data is invalid, damaged, or belongs to a different context.');
  } finally {
    sodium.memzero(nonce);
    sodium.memzero(ciphertext);
    sodium.memzero(aad);
    if (plaintext) sodium.memzero(plaintext);
  }
}

export async function encryptItem(item: VaultItem, userId: string, vaultKey: Uint8Array): Promise<SecretBox> {
  return encryptJson(item, itemAad(userId, item.id), vaultKey);
}

export async function decryptItem(item: EncryptedItem, userId: string, vaultKey: Uint8Array): Promise<VaultItem> {
  const value = await decryptJson(item, itemAad(userId, item.id), vaultKey);
  if (!value || typeof value !== 'object' || (value as VaultItem).id !== item.id) {
    throw new Error('The decrypted item does not match its envelope.');
  }
  return value as VaultItem;
}

export async function encryptShare(item: VaultItem, shareId: string): Promise<EncryptedShare> {
  await ready();
  const key = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
  try {
    return { ...(await encryptJson(item, shareAad(shareId), key)), key: toBase64Url(key) };
  } finally {
    sodium.memzero(key);
  }
}

export async function decryptShare(box: SecretBox, shareId: string, encodedKey: string): Promise<VaultItem> {
  const key = fromBase64Url(encodedKey);
  try {
    const item = await decryptJson(box, shareAad(shareId), key);
    if (!item || typeof item !== 'object' || typeof (item as VaultItem).title !== 'string') {
      throw new Error('The shared item is invalid.');
    }
    return item as VaultItem;
  } finally {
    sodium.memzero(key);
  }
}

export async function rotateRecoveryKey(keys: UnlockedKeys, bundle: KeyBundle): Promise<RecoveryRotation> {
  await ready();
  const recoveryKey = sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES);
  try {
    const [encryptedRecoveryIdentitySecret, encryptedRecoveryVaultSecret] = await Promise.all([
      sealSecret(keys.identitySecretKey, recoveryKey),
      sealSecret(keys.vaultSecretKey, recoveryKey),
    ]);
    return {
      bundle: { ...bundle, encryptedRecoveryIdentitySecret, encryptedRecoveryVaultSecret },
      recoveryKey,
      recoveryKeyEncoded: toBase64Url(recoveryKey),
    };
  } catch (error) {
    wipeRecoveryKey(recoveryKey);
    throw error;
  }
}

export async function rewrap(password: string, newPassword: string, bundle: KeyBundle): Promise<KeyBundle> {
  await ready();
  const keys = await unlock(password, bundle, 'master');
  const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
  let newKek: Uint8Array | undefined;
  try {
    const parameters = { salt: toBase64Url(salt), opsLimit: KDF_OPS_LIMIT, memLimit: KDF_MEM_LIMIT };
    newKek = await deriveKek(newPassword, parameters);
    const [encryptedIdentitySecret, encryptedVaultSecret] = await Promise.all([
      sealSecret(keys.identitySecretKey, newKek),
      sealSecret(keys.vaultSecretKey, newKek),
    ]);
    return {
      ...bundle,
      ...parameters,
      encryptedIdentitySecret,
      encryptedVaultSecret,
    };
  } finally {
    wipeKeys(keys);
    sodium.memzero(salt);
    if (newKek) sodium.memzero(newKek);
  }
}

export function wipeKeys(keys: Partial<UnlockedKeys> | null | undefined): void {
  if (!keys) return;
  for (const key of [keys.identitySecretKey, keys.vaultSecretKey, keys.vaultKey]) {
    if (!key) continue;
    try {
      sodium.memzero(key);
    } catch {
      key.fill(0);
    }
  }
}

export function parseHibpResponse(body: string, suffix: string): HibpResult {
  const normalizedSuffix = suffix.toUpperCase();
  for (const line of body.split(/\r?\n/)) {
    const [candidate, rawCount] = line.trim().split(':', 2);
    if (candidate?.trim().toUpperCase() !== normalizedSuffix) continue;
    const count = Number.parseInt(rawCount?.trim() ?? '', 10);
    return Number.isFinite(count) && count > 0
      ? { status: 'compromised', count }
      : { status: 'unknown', count: 0 };
  }
  return { status: 'not-found', count: 0 };
}

export async function checkPassword(
  password: string,
  fetcher: typeof fetch = fetch,
): Promise<HibpResult> {
  try {
    const digest = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(password));
    const hash = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0'))
      .join('')
      .toUpperCase();
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);
    const response = await fetcher(`/api/hibp/${prefix}`, { credentials: 'same-origin' });
    if (!response.ok) return { status: 'unknown', count: 0 };
    return parseHibpResponse(await response.text(), suffix);
  } catch {
    return { status: 'unknown', count: 0 };
  }
}

export { ENVELOPE_VERSION };
