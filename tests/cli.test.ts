import test from 'node:test';
import assert from 'node:assert/strict';
import sodium from 'sodium-native';
import { parseArgs, readMasterPassword } from '../src/cli/index.js';
import {
  decodeBase64url,
  decryptItem,
  decryptSecretBox,
  deriveKek,
  encodeBase64url,
  itemAad,
  LockedBuffer,
  unsealVaultKey,
} from '../src/cli/secure.js';
import type { EncryptedItem, KeyBundle, SecretBox, VaultItem } from '../src/shared/api.js';

const ITEM_ID = '123e4567-e89b-42d3-a456-426614174000';
const EMAIL_ARGS = ['--email', 'user@example.com'];

function encryptedItem(item: VaultItem, key: LockedBuffer, identityPublicKey: string): EncryptedItem {
  const nonce = Buffer.alloc(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, 7);
  const plaintext = Buffer.from(JSON.stringify(item), 'utf8');
  const ciphertext = Buffer.alloc(plaintext.length + sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES);
  sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    ciphertext,
    plaintext,
    itemAad(identityPublicKey, item.id),
    null,
    nonce,
    key.buffer,
  );
  sodium.sodium_memzero(plaintext);
  return {
    id: item.id,
    version: 1,
    nonce: encodeBase64url(nonce),
    ciphertext: encodeBase64url(ciphertext),
    updatedAt: item.updatedAt,
  };
}

function emptyBundle(): KeyBundle {
  const box: SecretBox = { nonce: 'AA', ciphertext: 'AA' };
  return {
    salt: encodeBase64url(Buffer.alloc(16)),
    opsLimit: 3,
    memLimit: 64 * 1024 * 1024,
    identityPublicKey: 'AA',
    encryptedIdentitySecret: box,
    vaultPublicKey: 'AA',
    encryptedVaultSecret: box,
    sealedVaultKey: 'AA',
  };
}

test('parseArgs applies server precedence and optional list filtering', () => {
  assert.deepEqual(parseArgs(['list', ...EMAIL_ARGS], {}), {
    command: 'list',
    email: 'user@example.com',
    server: 'http://127.0.0.1:3000',
  });
  assert.deepEqual(parseArgs(['list', ...EMAIL_ARGS], { LOCKIT_SERVER: 'http://localhost:4000/' }), {
    command: 'list',
    email: 'user@example.com',
    server: 'http://localhost:4000',
  });
  assert.deepEqual(parseArgs([
    'list',
    ...EMAIL_ARGS,
    '--id',
    ITEM_ID,
    '--server=https://vault.example.com/',
  ], { LOCKIT_SERVER: 'http://localhost:4000' }), {
    command: 'list',
    email: 'user@example.com',
    id: ITEM_ID,
    server: 'https://vault.example.com',
  });
});

test('parseArgs rejects missing, duplicate, and malformed arguments', () => {
  assert.throws(() => parseArgs([], {}), /list or reveal/);
  assert.throws(() => parseArgs(['reveal', ...EMAIL_ARGS], {}), /requires --id/);
  assert.throws(() => parseArgs(['list'], {}), /--email/);
  assert.throws(() => parseArgs(['list', ...EMAIL_ARGS, '--email', 'other@example.com'], {}), /Duplicate/);
  assert.throws(() => parseArgs(['list', ...EMAIL_ARGS, '--id', 'not-a-uuid'], {}), /UUID/);
  assert.throws(() => parseArgs(['list', ...EMAIL_ARGS, '--password', 'secret'], {}), /Unknown option/);
  assert.throws(() => parseArgs(['list', ...EMAIL_ARGS, '--server', 'file:///tmp/vault'], {}), /HTTP/);
  assert.throws(() => parseArgs(['list', ...EMAIL_ARGS, '--server', 'http://vault.example.com'], {}), /require HTTPS/);
});

test('noninteractive password input is refused instead of read or echoed', () => {
  const input = { isTTY: false } as NodeJS.ReadStream;
  assert.throws(() => readMasterPassword(input), /interactive TTY/);
});

test('Base64url is strict and unpadded', () => {
  const bytes = Buffer.from([0, 1, 2, 250, 255]);
  assert.deepEqual(decodeBase64url(encodeBase64url(bytes)), bytes);
  for (const invalid of ['', 'abc=', 'ab+c', 'ab/c', 'A', 'a b']) {
    assert.throws(() => decodeBase64url(invalid), /Base64url/);
  }
});

test('SecretBox round trip uses locked plaintext and rejects the wrong key', (t) => {
  const key = new LockedBuffer(sodium.crypto_secretbox_KEYBYTES);
  const wrongKey = new LockedBuffer(sodium.crypto_secretbox_KEYBYTES);
  const expected = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES, 42);
  key.buffer.fill(11);
  wrongKey.buffer.fill(12);
  t.after(() => {
    key.dispose();
    wrongKey.dispose();
    sodium.sodium_memzero(expected);
  });

  const nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES, 3);
  const ciphertext = Buffer.alloc(expected.length + sodium.crypto_secretbox_MACBYTES);
  sodium.crypto_secretbox_easy(ciphertext, expected, nonce, key.buffer);
  const box = { nonce: encodeBase64url(nonce), ciphertext: encodeBase64url(ciphertext) };
  const decrypted = decryptSecretBox(box, key, expected.length);
  assert.equal(decrypted.buffer.equals(expected), true);
  decrypted.dispose();
  assert.throws(() => decryptSecretBox(box, wrongKey, expected.length), /decrypt/);
});

test('sealed vault key round trip and authentication failure', (t) => {
  const publicKey = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES);
  const secretKey = new LockedBuffer(sodium.crypto_box_SECRETKEYBYTES);
  const expected = new LockedBuffer(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
  sodium.crypto_box_keypair(publicKey, secretKey.buffer);
  expected.buffer.fill(23);
  const sealed = Buffer.alloc(expected.buffer.length + sodium.crypto_box_SEALBYTES);
  sodium.crypto_box_seal(sealed, expected.buffer, publicKey);
  const bundle = { ...emptyBundle(), vaultPublicKey: encodeBase64url(publicKey), sealedVaultKey: encodeBase64url(sealed) };
  t.after(() => {
    secretKey.dispose();
    expected.dispose();
    sodium.sodium_memzero(publicKey);
    sodium.sodium_memzero(sealed);
  });

  const actual = unsealVaultKey(bundle, secretKey);
  assert.equal(actual.buffer.equals(expected.buffer), true);
  actual.dispose();
  sealed[sealed.length - 1]! ^= 1;
  const corrupted = { ...bundle, sealedVaultKey: encodeBase64url(sealed) };
  assert.throws(() => unsealVaultKey(corrupted, secretKey), /unseal/);
});

test('item decryption matches VaultItem and enforces AAD and authentication', (t) => {
  const key = new LockedBuffer(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
  key.buffer.fill(31);
  t.after(() => key.dispose());
  const identityPublicKey = encodeBase64url(Buffer.alloc(32, 9));
  const expected: VaultItem = {
    id: ITEM_ID,
    kind: 'password',
    title: 'Example',
    username: 'person@example.com',
    secret: 'correct horse battery staple',
    updatedAt: '2026-01-01T00:00:00.000Z',
  };
  const encrypted = encryptedItem(expected, key, identityPublicKey);
  assert.deepEqual(decryptItem(encrypted, key, identityPublicKey), expected);
  assert.throws(
    () => decryptItem(encrypted, key, encodeBase64url(Buffer.alloc(32, 10))),
    /decrypt or validate/,
  );
  assert.throws(() => decryptItem({ ...encrypted, version: 2 }, key, identityPublicKey), /Unsupported/);
  const corrupted = decodeBase64url(encrypted.ciphertext);
  corrupted[0]! ^= 1;
  assert.throws(
    () => decryptItem({ ...encrypted, ciphertext: encodeBase64url(corrupted) }, key, identityPublicKey),
    /decrypt or validate/,
  );
});

test('KDF rejects incompatible bundle parameters before doing expensive work', (t) => {
  const password = new LockedBuffer(4);
  password.buffer.write('test');
  t.after(() => password.dispose());
  assert.throws(() => deriveKek(password, { ...emptyBundle(), opsLimit: 2 }), /Unsupported/);
  assert.throws(() => deriveKek(password, { ...emptyBundle(), memLimit: 1024 }), /Unsupported/);
});
