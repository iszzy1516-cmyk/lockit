import assert from 'node:assert/strict';
import { test } from 'node:test';
import sodium from 'libsodium-wrappers-sumo';
import type { EncryptedItem, VaultItem } from '../src/shared/api';
import {
  checkPassword,
  createRegistration,
  decryptItem,
  decryptShare,
  encryptItem,
  encryptShare,
  fromBase64Url,
  parseHibpResponse,
  rewrap,
  signChallenge,
  toBase64Url,
  unlock,
  wipeKeys,
} from '../src/shared/crypto';

const password = 'a long correct horse battery staple';
const item: VaultItem = {
  id: crypto.randomUUID(),
  kind: 'password',
  title: 'Example service',
  username: 'person@example.test',
  secret: 'correct horse battery staple',
  notes: 'Complete JSON, including notes, is encrypted.',
  updatedAt: new Date().toISOString(),
};

test('base64url helpers roundtrip arbitrary bytes', async () => {
  await sodium.ready;
  const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
  const encoded = toBase64Url(bytes);
  assert.doesNotMatch(encoded, /[+/=]/);
  assert.deepEqual(fromBase64Url(encoded), bytes);
});

test('registration, challenge signing, unlock, and wrong-password rejection', async () => {
  const registration = await createRegistration(password);
  try {
    const challenge = toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
    const signature = await signChallenge(challenge, registration.keys.identitySecretKey);
    assert.ok(fromBase64Url(signature).length > 0);
    await assert.rejects(unlock('definitely not the master password', registration.bundle));
    const unlocked = await unlock(password, registration.bundle);
    try {
      assert.deepEqual(unlocked.vaultKey, registration.keys.vaultKey);
    } finally {
      wipeKeys(unlocked);
    }
  } finally {
    wipeKeys(registration.keys);
  }
});

test('item encryption roundtrips and rejects tampering and wrong AAD', async () => {
  const registration = await createRegistration(password);
  try {
    const encrypted = await encryptItem(item, registration.bundle.identityPublicKey, registration.keys.vaultKey);
    const envelope: EncryptedItem = { id: item.id, version: 1, updatedAt: item.updatedAt, ...encrypted };
    assert.deepEqual(await decryptItem(envelope, registration.bundle.identityPublicKey, registration.keys.vaultKey), item);

    const tamperedBytes = fromBase64Url(encrypted.ciphertext);
    tamperedBytes[0] = (tamperedBytes[0] ?? 0) ^ 1;
    await assert.rejects(decryptItem({ ...envelope, ciphertext: toBase64Url(tamperedBytes) }, registration.bundle.identityPublicKey, registration.keys.vaultKey));
    await assert.rejects(decryptItem(envelope, 'a-different-account', registration.keys.vaultKey));
    await assert.rejects(decryptItem({ ...envelope, id: crypto.randomUUID() }, registration.bundle.identityPublicKey, registration.keys.vaultKey));
  } finally {
    wipeKeys(registration.keys);
  }
});

test('rewrap retains public identity and sealed data key but rejects the old password', async () => {
  const registration = await createRegistration(password);
  try {
    const encrypted = await encryptItem(item, registration.bundle.identityPublicKey, registration.keys.vaultKey);
    const changed = await rewrap(password, 'a wholly new master password', registration.bundle);
    assert.equal(changed.identityPublicKey, registration.bundle.identityPublicKey);
    assert.equal(changed.vaultPublicKey, registration.bundle.vaultPublicKey);
    assert.equal(changed.sealedVaultKey, registration.bundle.sealedVaultKey);
    assert.notEqual(changed.salt, registration.bundle.salt);
    await assert.rejects(unlock(password, changed));
    const unlocked = await unlock('a wholly new master password', changed);
    try {
      assert.deepEqual(unlocked.vaultKey, registration.keys.vaultKey);
      assert.deepEqual(await decryptItem({ id: item.id, version: 1, updatedAt: item.updatedAt, ...encrypted }, changed.identityPublicKey, unlocked.vaultKey), item);
    } finally {
      wipeKeys(unlocked);
    }
  } finally {
    wipeKeys(registration.keys);
  }
});

test('share snapshots roundtrip and are bound to their share ID', async () => {
  const shareId = crypto.randomUUID();
  const encrypted = await encryptShare(item, shareId);
  assert.deepEqual(await decryptShare(encrypted, shareId, encrypted.key), item);
  await assert.rejects(decryptShare(encrypted, crypto.randomUUID(), encrypted.key));
  await assert.rejects(decryptShare(encrypted, shareId, toBase64Url(new Uint8Array(32))));
});

test('HIBP parser handles padded responses, not found, and malformed counts', () => {
  const suffix = '0018A45C4D1DEF81644B54AB7F969B88D65';
  assert.deepEqual(parseHibpResponse(`AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:2\r\n${suffix}:42\r\n`, suffix), { status: 'compromised', count: 42 });
  assert.deepEqual(parseHibpResponse('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:2\r\n', suffix), { status: 'not-found', count: 0 });
  assert.deepEqual(parseHibpResponse(`${suffix}:not-a-count`, suffix), { status: 'unknown', count: 0 });
});

test('HIBP sends only the uppercase five-character hash prefix', async () => {
  const digest = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(password));
  const hash = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('').toUpperCase();
  let requested = '';
  const result = await checkPassword(password, async (input) => {
    requested = String(input);
    return new Response(`${hash.slice(5)}:7\r\n`, { status: 200 });
  });
  assert.equal(requested, `/api/hibp/${hash.slice(0, 5)}`);
  assert.ok(!requested.includes(hash.slice(5)));
  assert.deepEqual(result, { status: 'compromised', count: 7 });
  assert.deepEqual(await checkPassword(password, async () => new Response('', { status: 503 })), { status: 'unknown', count: 0 });
});
