import assert from 'node:assert/strict';
import { createHash, createHmac, generateKeyPairSync, randomBytes, randomUUID, sign, type KeyObject } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import {
  createApp, createConfig, MAX_ITEM_CIPHERTEXT_BYTES, MAX_ITEMS_PER_USER, type LockitApp,
} from '../src/server/server/index.js';
import type { KeyBundle } from '../src/shared/api.js';

type Account = {
  email: string;
  cookie: string;
  bundle: KeyBundle;
  privateKey: KeyObject;
};

function listen(server: Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      assert(address && typeof address === 'object');
      resolve(address.port);
    });
  });
}

function close(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
    server.closeAllConnections();
  });
}

function encoded(bytes: number): string {
  return randomBytes(bytes).toString('base64url');
}

function makeBundle(publicKey?: Buffer): KeyBundle {
  return {
    salt: encoded(16),
    opsLimit: 3,
    memLimit: 67108864,
    identityPublicKey: (publicKey ?? randomBytes(32)).toString('base64url'),
    encryptedIdentitySecret: { nonce: encoded(24), ciphertext: encoded(80) },
    vaultPublicKey: encoded(32),
    encryptedVaultSecret: { nonce: encoded(24), ciphertext: encoded(48) },
    encryptedRecoveryIdentitySecret: { nonce: encoded(24), ciphertext: encoded(80) },
    encryptedRecoveryVaultSecret: { nonce: encoded(24), ciphertext: encoded(48) },
    sealedVaultKey: encoded(80),
  };
}

describe('Lockit server', () => {
  let app: LockitApp;
  let fixture: Server;
  let directory: string;
  let baseUrl: string;
  let fixturePath = '';
  let fixturePadding = '';
  let fixtureAgent = '';
  let nextRegistrationIp = 1;
  const fixtureText = '00112233445566778899AABBCCDDEEFF:2\nFEDCBA9876543210:7\n';

  before(async () => {
    directory = await mkdtemp(path.join(tmpdir(), 'lockit-server-'));
    fixture = createServer((req, res) => {
      fixturePath = req.url ?? '';
      fixturePadding = String(req.headers['add-padding']);
      fixtureAgent = String(req.headers['user-agent']);
      if (req.url === '/range/EEEEE') {
        res.writeHead(503, { 'Content-Type': 'text/plain' });
        res.end('unavailable');
        return;
      }
      if (req.url === '/range/DDDDD') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.write(Buffer.alloc(600 * 1024, 65));
        res.end(Buffer.alloc(600 * 1024, 66));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end(fixtureText);
    });
    const fixturePort = await listen(fixture);
    const config = createConfig({
      NODE_ENV: 'test',
      LOCKIT_DB_PATH: path.join(directory, 'lockit.db'),
      LOCKIT_PUBLIC_ORIGIN: 'http://localhost:5173',
      LOCKIT_TRUST_PROXY: 'true',
      HIBP_BASE_URL: `http://127.0.0.1:${fixturePort}`,
      PORT: '0',
    });
    app = createApp(config);
    baseUrl = `http://127.0.0.1:${await listen(app.server)}`;
  });

  after(async () => {
    await close(app.server);
    app.close();
    await close(fixture);
    await rm(directory, { recursive: true, force: true });
  });

  async function request(route: string, options: {
    method?: string;
    body?: unknown;
    cookie?: string;
    headers?: Record<string, string>;
  } = {}): Promise<Response> {
    const headers: Record<string, string> = { ...options.headers };
    if (options.body !== undefined) headers['Content-Type'] = 'application/json';
    if (options.cookie) headers.Cookie = options.cookie;
    return fetch(`${baseUrl}${route}`, {
      method: options.method ?? (options.body === undefined ? 'GET' : 'POST'),
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    });
  }

  async function json(response: Response): Promise<any> {
    const body = await response.json();
    return body;
  }

  async function register(email: string): Promise<Account> {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const rawPublicKey = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
    const bundle = makeBundle(rawPublicKey);
    const response = await request('/api/register', {
      body: { ...bundle, email },
      headers: { 'X-Forwarded-For': `198.51.100.${nextRegistrationIp++}` },
    });
    assert.equal(response.status, 201);
    const setCookie = response.headers.get('set-cookie');
    assert(setCookie);
    assert.match(setCookie, /HttpOnly/);
    assert.match(setCookie, /SameSite=Strict/);
    return {
      email: email.trim().toLowerCase(),
      cookie: setCookie.split(';')[0]!,
      bundle,
      privateKey,
    };
  }

  function encryptedItem(): { id: string; version: number; nonce: string; ciphertext: string } {
    return { id: randomUUID(), version: 1, nonce: encoded(24), ciphertext: encoded(48) };
  }

  async function addItem(account: Account): Promise<{ id: string; version: number; nonce: string; ciphertext: string }> {
    const item = encryptedItem();
    const response = await request('/api/items', { body: { item }, cookie: account.cookie });
    assert.equal(response.status, 201);
    return item;
  }

  it('serves health and security headers', async () => {
    const response = await request('/api/health');
    assert.equal(response.status, 200);
    assert.deepEqual(await json(response), { status: 'ok' });
    assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(response.headers.get('cross-origin-opener-policy'), 'same-origin');
    assert.equal(response.headers.get('referrer-policy'), 'no-referrer');
    assert.match(response.headers.get('content-security-policy') ?? '', /frame-ancestors 'none'/);
  });

  it('normalizes registration email, validates bundles, and authenticates sessions', async () => {
    const account = await register('  Person@Example.COM ');
    assert.deepEqual(await json(await request('/api/auth/me', { cookie: account.cookie })), {
      user: { email: 'person@example.com' },
    });
    assert.equal((await request('/api/auth/me')).status, 401);
    assert.equal((await request('/api/register', { body: { ...account.bundle, email: account.email } })).status, 409);
    assert.equal((await request('/api/register', {
      body: { ...account.bundle, opsLimit: 2, email: 'bad-kdf@example.com' },
    })).status, 400);
    assert.equal((await request('/api/register', {
      body: { ...account.bundle, salt: encoded(15), email: 'bad-salt@example.com' },
    })).status, 400);
    const { encryptedRecoveryIdentitySecret: _missingRecovery, ...missingRecovery } = account.bundle;
    assert.equal((await request('/api/register', {
      body: { ...missingRecovery, email: 'bad-recovery@example.com' },
    })).status, 400);

    const bundleResponse = await request('/api/auth/bundle', { cookie: account.cookie });
    const stored = await json(bundleResponse);
    assert.deepEqual(stored.bundle, account.bundle);
    assert.equal('email' in stored.bundle, false);
  });

  it('verifies Ed25519 challenges and makes each challenge single-use', async () => {
    const account = await register('login@example.com');
    const challengeResponse = await request('/api/auth/challenge', {
      body: { email: ' LOGIN@example.com ' },
    });
    assert.equal(challengeResponse.status, 200);
    const challenge = await json(challengeResponse);
    assert.equal(Buffer.from(challenge.challenge, 'base64url').length, 32);
    assert.deepEqual(challenge.bundle, account.bundle);
    assert(Date.parse(challenge.expiresAt) > Date.now() + 4 * 60 * 1000);

    const signature = sign(null, Buffer.from(challenge.challenge, 'base64url'), account.privateKey).toString('base64url');
    const verified = await request('/api/auth/verify', {
      body: { challengeId: challenge.challengeId, signature },
    });
    assert.equal(verified.status, 200);
    assert.deepEqual(await json(verified), { user: { email: account.email } });
    const loginCookie = verified.headers.get('set-cookie')!.split(';')[0]!;
    assert.equal((await request('/api/auth/me', { cookie: loginCookie })).status, 200);

    const replay = await request('/api/auth/verify', {
      body: { challengeId: challenge.challengeId, signature },
    });
    assert.equal(replay.status, 401);
    assert.deepEqual(await json(replay), { error: 'Authentication failed' });
    assert.equal((await request('/api/auth/challenge', { body: { email: 'missing@example.com' } })).status, 401);
  });

  it('rejects a bad signature and consumes its challenge', async () => {
    const account = await register('bad-signature@example.com');
    const challenge = await json(await request('/api/auth/challenge', { body: { email: account.email } }));
    const signature = randomBytes(64).toString('base64url');
    const attempt = { challengeId: challenge.challengeId, signature };
    assert.equal((await request('/api/auth/verify', { body: attempt })).status, 401);
    assert.equal((await request('/api/auth/verify', { body: attempt })).status, 401);
  });

  it('revokes sessions on logout', async () => {
    const account = await register('logout@example.com');
    assert.equal((await request('/api/auth/logout', { method: 'POST', cookie: account.cookie })).status, 200);
    assert.equal((await request('/api/auth/me', { cookie: account.cookie })).status, 401);
  });

  it('enforces encrypted item validation and ownership across CRUD', async () => {
    const owner = await register('items-owner@example.com');
    const other = await register('items-other@example.com');
    const item = await addItem(owner);

    const list = await json(await request('/api/items', { cookie: owner.cookie }));
    assert.equal(list.items.length, 1);
    assert.equal(list.items[0].id, item.id);
    assert.equal(Number.isNaN(Date.parse(list.items[0].updatedAt)), false);
    assert.deepEqual((await json(await request('/api/items', { cookie: other.cookie }))).items, []);

    const changed = { ...item, ciphertext: encoded(64) };
    assert.equal((await request(`/api/items/${item.id}`, {
      method: 'PUT', body: { item: changed }, cookie: other.cookie,
    })).status, 404);
    assert.equal((await request(`/api/items/${item.id}`, {
      method: 'DELETE', cookie: other.cookie,
    })).status, 404);
    assert.equal((await request(`/api/items/${item.id}`, {
      method: 'PUT', body: { item: changed }, cookie: owner.cookie,
    })).status, 200);

    assert.equal((await request('/api/items', {
      body: { item: { ...encryptedItem(), nonce: encoded(23) } }, cookie: owner.cookie,
    })).status, 400);
    assert.equal((await request('/api/items', {
      body: { item: { ...encryptedItem(), version: 2 } }, cookie: owner.cookie,
    })).status, 400);
    assert.equal((await request('/api/items', {
      body: { item: { ...encryptedItem(), ciphertext: encoded(15) } }, cookie: owner.cookie,
    })).status, 400);
    assert.equal((await request(`/api/items/${item.id}`, { method: 'DELETE', cookie: owner.cookie })).status, 204);
    assert.deepEqual((await json(await request('/api/items', { cookie: owner.cookie }))).items, []);
  });

  it('enforces the per-user item count quota', async () => {
    const account = await register('item-count-quota@example.com');
    const user = app.db.prepare('SELECT id FROM users WHERE email = ?').get(account.email) as { id: string };
    const insert = app.db.prepare('INSERT INTO items (id, user_id, version, nonce, ciphertext, updated_at) VALUES (?, ?, 1, ?, ?, ?)');
    const nonce = encoded(24);
    const ciphertext = encoded(48);
    app.db.exec('BEGIN IMMEDIATE');
    try {
      for (let index = 0; index < MAX_ITEMS_PER_USER; index++) {
        insert.run(randomUUID(), user.id, nonce, ciphertext, Date.now());
      }
      app.db.exec('COMMIT');
    } catch (error) {
      app.db.exec('ROLLBACK');
      throw error;
    }
    assert.equal((await request('/api/items', {
      body: { item: encryptedItem() }, cookie: account.cookie,
    })).status, 413);
  });

  it('enforces ciphertext bytes and accounts for replaced item size', async () => {
    const account = await register('item-byte-quota@example.com');
    const user = app.db.prepare('SELECT id FROM users WHERE email = ?').get(account.email) as { id: string };
    const item = encryptedItem();
    const encodedLength = Math.ceil(MAX_ITEM_CIPHERTEXT_BYTES * 4 / 3);
    app.db.prepare(`INSERT INTO items (id, user_id, version, nonce, ciphertext, updated_at)
      VALUES (?, ?, 1, ?, zeroblob(?), ?)`).run(item.id, user.id, item.nonce, encodedLength, Date.now());
    assert.equal((await request('/api/items', {
      body: { item: encryptedItem() }, cookie: account.cookie,
    })).status, 413);
    assert.equal((await request(`/api/items/${item.id}`, {
      method: 'PUT', body: { item }, cookie: account.cookie,
    })).status, 200);
    assert.equal((await request('/api/items', {
      body: { item: encryptedItem() }, cookie: account.cookie,
    })).status, 201);
  });

  it('allows secret re-wrapping, preserves the current session, and revokes other sessions', async () => {
    const account = await register('rewrap@example.com');
    const challenge = await json(await request('/api/auth/challenge', { body: { email: account.email } }));
    const signature = sign(null, Buffer.from(challenge.challenge, 'base64url'), account.privateKey).toString('base64url');
    const verified = await request('/api/auth/verify', {
      body: { challengeId: challenge.challengeId, signature },
    });
    const secondCookie = verified.headers.get('set-cookie')!.split(';')[0]!;
    assert.equal((await request('/api/auth/me', { cookie: secondCookie })).status, 200);
    const changed = {
      ...account.bundle,
      salt: encoded(16),
      encryptedIdentitySecret: { nonce: encoded(24), ciphertext: encoded(80) },
      encryptedVaultSecret: { nonce: encoded(24), ciphertext: encoded(48) },
    };
    const response = await request('/api/auth/bundle', {
      method: 'PUT', body: { bundle: changed }, cookie: account.cookie,
    });
    assert.equal(response.status, 200);
    assert.equal((await request('/api/auth/me', { cookie: account.cookie })).status, 200);
    assert.equal((await request('/api/auth/me', { cookie: secondCookie })).status, 401);
    assert.deepEqual((await json(await request('/api/auth/bundle', { cookie: account.cookie }))).bundle, changed);

    assert.equal((await request('/api/auth/bundle', {
      method: 'PUT', body: { bundle: { ...changed, identityPublicKey: encoded(32) } }, cookie: account.cookie,
    })).status, 400);
    assert.equal((await request('/api/auth/bundle', {
      method: 'PUT', body: { bundle: { ...changed, sealedVaultKey: encoded(80) } }, cookie: account.cookie,
    })).status, 400);
    assert.deepEqual((await json(await request('/api/auth/bundle', { cookie: account.cookie }))).bundle, changed);
  });

  it('stores only share HMACs and opens, revokes, and expires shares safely', async () => {
    const owner = await register('share-owner@example.com');
    const other = await register('share-other@example.com');
    const item = await addItem(owner);
    const input = { id: randomUUID(), itemId: item.id, ttlSeconds: 300, ciphertext: encoded(80), nonce: encoded(24) };
    assert.equal((await request('/api/shares', { body: input, cookie: other.cookie })).status, 404);
    assert.equal((await request('/api/shares', {
      body: { ...input, ttlSeconds: 59 }, cookie: owner.cookie,
    })).status, 400);

    const createdResponse = await request('/api/shares', { body: input, cookie: owner.cookie });
    assert.equal(createdResponse.status, 201);
    const created = await json(createdResponse);
    assert.equal(Buffer.from(created.token, 'base64url').length, 32);
    const row = app.db.prepare('SELECT token_hash FROM shares WHERE id = ?').get(created.share.id) as { token_hash: Uint8Array };
    const storedHash = Buffer.from(row.token_hash);
    const expected = createHmac('sha256', app.config.sharePepper)
      .update(`${created.share.id}.${created.token}`).digest();
    assert.equal(createHash('sha256').update(created.token).digest('hex') === storedHash.toString('hex'), false);
    assert(storedHash.equals(expected));

    const opened = await request('/api/shares/open', { body: { id: created.share.id, token: created.token } });
    assert.equal(opened.status, 200);
    assert.deepEqual(await json(opened), {
      share: { id: created.share.id, expiresAt: created.share.expiresAt },
      ciphertext: input.ciphertext,
      nonce: input.nonce,
    });
    assert.equal((await request('/api/shares/open', {
      body: { id: created.share.id, token: randomBytes(32).toString('base64url') },
    })).status, 404);

    const listed = await json(await request('/api/shares', { cookie: owner.cookie }));
    assert.equal(listed.shares.length, 1);
    assert.equal(listed.shares[0].revokedAt, null);
    assert.equal((await request(`/api/shares/${created.share.id}`, {
      method: 'DELETE', cookie: owner.cookie,
    })).status, 204);
    assert.equal((await request('/api/shares/open', {
      body: { id: created.share.id, token: created.token },
    })).status, 404);

    const expiring = await json(await request('/api/shares', { body: { ...input, id: randomUUID() }, cookie: owner.cookie }));
    app.db.prepare('UPDATE shares SET expires_at = ? WHERE id = ?').run(Date.now() - 1000, expiring.share.id);
    assert.equal((await request('/api/shares/open', {
      body: { id: expiring.share.id, token: expiring.token },
    })).status, 404);
  });

  it('requires authentication and safely proxies bounded HIBP responses', async () => {
    const account = await register('hibp@example.com');
    assert.equal((await request('/api/hibp/a1b2c')).status, 401);
    const response = await request('/api/hibp/a1b2c', { cookie: account.cookie });
    assert.equal(response.status, 200);
    assert.equal(await response.text(), fixtureText);
    assert.equal(fixturePath, '/range/A1B2C');
    assert.equal(fixturePadding, 'true');
    assert.match(fixtureAgent, /Lockit/);
    assert.equal((await request('/api/hibp/eeeee', { cookie: account.cookie })).status, 502);
    assert.equal((await request('/api/hibp/ddddd', { cookie: account.cookie })).status, 502);
    assert.equal((await request('/api/hibp/not-hex')).status, 404);
    assert.equal((await request('/api/hibp/abcd')).status, 404);
  });

  it('rate limits registration and challenges by trusted client IP', async () => {
    const registrationHeaders = { 'X-Forwarded-For': '203.0.113.10, 10.0.0.1' };
    for (let index = 0; index < 10; index++) {
      const response = await request('/api/register', {
        body: { ...makeBundle(), email: `ip-registration-${index}@example.com` },
        headers: registrationHeaders,
      });
      assert.equal(response.status, 201);
    }
    const limitedRegistration = await request('/api/register', {
      body: { ...makeBundle(), email: 'ip-registration-limited@example.com' },
      headers: registrationHeaders,
    });
    assert.equal(limitedRegistration.status, 429);
    assert(Number(limitedRegistration.headers.get('retry-after')) > 0);

    const challengeHeaders = { 'X-Forwarded-For': '203.0.113.20' };
    for (let index = 0; index < 20; index++) {
      assert.equal((await request('/api/auth/challenge', {
        body: { email: `ip-challenge-${index}@example.com` }, headers: challengeHeaders,
      })).status, 401);
    }
    const limitedChallenge = await request('/api/auth/challenge', {
      body: { email: 'ip-challenge-limited@example.com' }, headers: challengeHeaders,
    });
    assert.equal(limitedChallenge.status, 429);
    assert(Number(limitedChallenge.headers.get('retry-after')) > 0);
  });

  it('rate limits HIBP requests per account', async () => {
    const account = await register('hibp-rate@example.com');
    for (let index = 0; index < 30; index++) {
      assert.equal((await request('/api/hibp/a1b2c', { cookie: account.cookie })).status, 200);
    }
    const limited = await request('/api/hibp/a1b2c', { cookie: account.cookie });
    assert.equal(limited.status, 429);
    assert(Number(limited.headers.get('retry-after')) > 0);
  });

  it('enforces JSON, CSRF, and session boundaries without detailed auth errors', async () => {
    const account = await register('security@example.com');
    const crossOrigin = await request('/api/items', {
      body: { item: encryptedItem() }, cookie: account.cookie,
      headers: { Origin: 'https://attacker.example' },
    });
    assert.equal(crossOrigin.status, 403);
    const crossSite = await request('/api/auth/logout', {
      method: 'POST', cookie: account.cookie, headers: { 'Sec-Fetch-Site': 'cross-site' },
    });
    assert.equal(crossSite.status, 403);
    const wrongType = await fetch(`${baseUrl}/api/auth/challenge`, {
      method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: account.email,
    });
    assert.equal(wrongType.status, 415);
    const unknown = await request('/api/auth/verify', { body: { challengeId: randomUUID(), signature: encoded(64) } });
    assert.equal(unknown.status, 401);
    assert.deepEqual(await json(unknown), { error: 'Authentication failed' });
  });

  it('uses production host cookies and HSTS', async () => {
    const production = createApp(createConfig({
      NODE_ENV: 'production',
      LOCKIT_DB_PATH: path.join(directory, 'production.db'),
      LOCKIT_PUBLIC_ORIGIN: 'https://vault.example.com',
      LOCKIT_SHARE_PEPPER: 'p'.repeat(32),
      PORT: '0',
    }));
    const port = await listen(production.server);
    try {
      const response = await fetch(`http://127.0.0.1:${port}/api/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...makeBundle(), email: 'production@example.com' }),
      });
      assert.equal(response.status, 201);
      assert.match(response.headers.get('strict-transport-security') ?? '', /max-age=31536000/);
      const cookie = response.headers.get('set-cookie') ?? '';
      assert.match(cookie, /^__Host-lockit_session=/);
      assert.match(cookie, /; Secure/);
      assert.match(cookie, /; HttpOnly/);
      assert.match(cookie, /; SameSite=Strict/);
      assert.match(cookie, /; Path=\//);
    } finally {
      await close(production.server);
      production.close();
    }
  });

  it('refuses insecure production configuration', () => {
    assert.throws(() => createConfig({
      NODE_ENV: 'production',
      LOCKIT_PUBLIC_ORIGIN: 'http://vault.example.com',
      LOCKIT_SHARE_PEPPER: 'a'.repeat(32),
    }), /HTTPS/);
    assert.throws(() => createConfig({
      NODE_ENV: 'production',
      LOCKIT_PUBLIC_ORIGIN: 'https://vault.example.com',
      LOCKIT_SHARE_PEPPER: 'short',
    }), /32 bytes/);
  });
});
