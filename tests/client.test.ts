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
  parseRecoveryKey,
  rewrap,
  rotateRecoveryKey,
  signChallenge,
  toBase64Url,
  unlock,
  wipeKeys,
  wipeRecoveryKey,
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

test('registration supports master and recovery unlock and rejects wrong credentials', async () => {
  const registration = await createRegistration(password);
  try {
    assert.equal(registration.recoveryKey.length, 32);
    assert.equal(registration.recoveryKeyEncoded, toBase64Url(registration.recoveryKey));
    const challenge = toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
    const signature = await signChallenge(challenge, registration.keys.identitySecretKey);
    assert.ok(fromBase64Url(signature).length > 0);
    await assert.rejects(unlock('definitely not the master password', registration.bundle, 'master'));
    await assert.rejects(unlock(new Uint8Array(32), registration.bundle, 'recovery'));
    await assert.rejects(unlock(new Uint8Array(31), registration.bundle, 'recovery'));

    const masterKeys = await unlock(password, registration.bundle, 'master');
    const recoveryKeys = await unlock(registration.recoveryKey, registration.bundle, 'recovery');
    try {
      assert.deepEqual(masterKeys.vaultKey, registration.keys.vaultKey);
      assert.deepEqual(recoveryKeys.vaultKey, registration.keys.vaultKey);
      assert.deepEqual(recoveryKeys.identitySecretKey, registration.keys.identitySecretKey);
    } finally {
      wipeKeys(masterKeys);
      wipeKeys(recoveryKeys);
    }
  } finally {
    wipeKeys(registration.keys);
    wipeRecoveryKey(registration.recoveryKey);
  }
});

test('recovery parser accepts files and raw keys and rejects malformed encodings', async () => {
  const registration = await createRegistration(password);
  try {
    const encoded = registration.recoveryKeyEncoded;
    const fromFile = await parseRecoveryKey(`Lockit recovery key\n\nAccount: person@example.test\nRecovery key: ${encoded}\n\nKeep safe.\n`);
    const fromRaw = await parseRecoveryKey(`  ${encoded}\n`);
    try {
      assert.deepEqual(fromFile, registration.recoveryKey);
      assert.deepEqual(fromRaw, registration.recoveryKey);
    } finally {
      wipeRecoveryKey(fromFile);
      wipeRecoveryKey(fromRaw);
    }
    await assert.rejects(parseRecoveryKey(`${encoded}=`));
    await assert.rejects(parseRecoveryKey(toBase64Url(new Uint8Array(31))));
    await assert.rejects(parseRecoveryKey('not a recovery key'));
    await assert.rejects(parseRecoveryKey(`Recovery key: ${encoded}\nRecovery key: ${encoded}`));
  } finally {
    wipeKeys(registration.keys);
    wipeRecoveryKey(registration.recoveryKey);
  }
});

test('recovery boxes reject tampering without affecting master boxes', async () => {
  const registration = await createRegistration(password);
  try {
    const ciphertext = fromBase64Url(registration.bundle.encryptedRecoveryVaultSecret.ciphertext);
    ciphertext[0] = (ciphertext[0] ?? 0) ^ 1;
    const tampered = {
      ...registration.bundle,
      encryptedRecoveryVaultSecret: { ...registration.bundle.encryptedRecoveryVaultSecret, ciphertext: toBase64Url(ciphertext) },
    };
    await assert.rejects(unlock(registration.recoveryKey, tampered, 'recovery'));
    const masterKeys = await unlock(password, tampered, 'master');
    wipeKeys(masterKeys);
  } finally {
    wipeKeys(registration.keys);
    wipeRecoveryKey(registration.recoveryKey);
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
    wipeRecoveryKey(registration.recoveryKey);
  }
});

test('rewrap preserves recovery boxes and all stable account keys', async () => {
  const registration = await createRegistration(password);
  try {
    const encrypted = await encryptItem(item, registration.bundle.identityPublicKey, registration.keys.vaultKey);
    const changed = await rewrap(password, 'a wholly new master password', registration.bundle);
    assert.equal(changed.identityPublicKey, registration.bundle.identityPublicKey);
    assert.equal(changed.vaultPublicKey, registration.bundle.vaultPublicKey);
    assert.equal(changed.sealedVaultKey, registration.bundle.sealedVaultKey);
    assert.deepEqual(changed.encryptedRecoveryIdentitySecret, registration.bundle.encryptedRecoveryIdentitySecret);
    assert.deepEqual(changed.encryptedRecoveryVaultSecret, registration.bundle.encryptedRecoveryVaultSecret);
    assert.notEqual(changed.salt, registration.bundle.salt);
    await assert.rejects(unlock(password, changed, 'master'));
    const unlocked = await unlock('a wholly new master password', changed, 'master');
    const recovered = await unlock(registration.recoveryKey, changed, 'recovery');
    try {
      assert.deepEqual(unlocked.vaultKey, registration.keys.vaultKey);
      assert.deepEqual(recovered.vaultKey, registration.keys.vaultKey);
      assert.deepEqual(await decryptItem({ id: item.id, version: 1, updatedAt: item.updatedAt, ...encrypted }, changed.identityPublicKey, unlocked.vaultKey), item);
    } finally {
      wipeKeys(unlocked);
      wipeKeys(recovered);
    }
  } finally {
    wipeKeys(registration.keys);
    wipeRecoveryKey(registration.recoveryKey);
  }
});

test('recovery rotation invalidates the old key and preserves master credentials', async () => {
  const registration = await createRegistration(password);
  const rotation = await rotateRecoveryKey(registration.keys, registration.bundle);
  try {
    assert.equal(rotation.bundle.identityPublicKey, registration.bundle.identityPublicKey);
    assert.equal(rotation.bundle.vaultPublicKey, registration.bundle.vaultPublicKey);
    assert.equal(rotation.bundle.sealedVaultKey, registration.bundle.sealedVaultKey);
    assert.deepEqual(rotation.bundle.encryptedIdentitySecret, registration.bundle.encryptedIdentitySecret);
    assert.deepEqual(rotation.bundle.encryptedVaultSecret, registration.bundle.encryptedVaultSecret);
    assert.notEqual(rotation.recoveryKeyEncoded, registration.recoveryKeyEncoded);
    await assert.rejects(unlock(registration.recoveryKey, rotation.bundle, 'recovery'));
    const recovered = await unlock(rotation.recoveryKey, rotation.bundle, 'recovery');
    const masterKeys = await unlock(password, rotation.bundle, 'master');
    try {
      assert.deepEqual(recovered.vaultKey, registration.keys.vaultKey);
      assert.deepEqual(masterKeys.vaultKey, registration.keys.vaultKey);
    } finally {
      wipeKeys(recovered);
      wipeKeys(masterKeys);
    }
  } finally {
    wipeKeys(registration.keys);
    wipeRecoveryKey(registration.recoveryKey);
    wipeRecoveryKey(rotation.recoveryKey);
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
