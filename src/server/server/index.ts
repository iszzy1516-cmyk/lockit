import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual, verify } from 'node:crypto';
import { createReadStream, existsSync, mkdirSync } from 'node:fs';
import { stat } from 'node:fs/promises';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { KDF_MEM_LIMIT, KDF_OPS_LIMIT, type KeyBundle, type SecretBox } from '../../shared/api.js';

const JSON_LIMIT = 6 * 1024 * 1024;
const HIBP_LIMIT = 1024 * 1024;
const SESSION_SECONDS = 8 * 60 * 60;
const CHALLENGE_SECONDS = 5 * 60;
const CHALLENGE_WINDOW_MS = 60 * 1000;
const CHALLENGE_LIMIT = 5;
const RATE_LIMIT_ENTRIES = 10000;
const HIBP_CONCURRENCY = 4;
const HIBP_QUEUE_LIMIT = 20;
export const MAX_ITEMS_PER_USER = 1000;
export const MAX_ITEM_CIPHERTEXT_BYTES = 64 * 1024 * 1024;
const DEV_PEPPER = 'lockit-clearly-development-only-share-pepper';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export type AppConfig = {
  production: boolean;
  trustProxy: boolean;
  dbPath: string;
  port: number;
  publicOrigin: string;
  sharePepper: Buffer;
  hibpBaseUrl: string;
  publicDir: string;
};

export type LockitApp = {
  server: Server;
  db: DatabaseSync;
  config: AppConfig;
  close: () => void;
};

type Row = Record<string, unknown>;
type UserRow = Row & { id: string; email: string; bundle: string };
type Session = { user: UserRow; tokenHash: string };

class HttpError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export function createConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const production = env.NODE_ENV === 'production';
  const publicOrigin = env.LOCKIT_PUBLIC_ORIGIN ?? 'http://localhost:5173';
  let origin: URL;
  try {
    origin = new URL(publicOrigin);
  } catch {
    throw new Error('LOCKIT_PUBLIC_ORIGIN must be a valid absolute URL');
  }
  if (!['http:', 'https:'].includes(origin.protocol) || origin.username || origin.password) {
    throw new Error('LOCKIT_PUBLIC_ORIGIN must be an HTTP(S) origin');
  }
  if (production && origin.protocol !== 'https:') {
    throw new Error('Production requires an HTTPS LOCKIT_PUBLIC_ORIGIN');
  }

  const pepperText = env.LOCKIT_SHARE_PEPPER ?? (production ? '' : DEV_PEPPER);
  const sharePepper = Buffer.from(pepperText, 'utf8');
  if (production && sharePepper.length < 32) {
    throw new Error('Production requires LOCKIT_SHARE_PEPPER of at least 32 bytes');
  }

  const port = Number(env.PORT ?? '3000');
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error('PORT must be an integer from 0 to 65535');
  }

  return {
    production,
    trustProxy: env.LOCKIT_TRUST_PROXY === 'true',
    dbPath: env.LOCKIT_DB_PATH ?? path.resolve('./data/lockit.db'),
    port,
    publicOrigin: origin.origin,
    sharePepper,
    hibpBaseUrl: !production && env.HIBP_BASE_URL
      ? env.HIBP_BASE_URL.replace(/\/$/, '')
      : 'https://api.pwnedpasswords.com',
    publicDir: path.resolve(env.LOCKIT_PUBLIC_DIR ?? 'dist/public'),
  };
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function decodeBase64(value: unknown, expected?: number, minimum?: number): Buffer {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new HttpError(400, 'Invalid encrypted data');
  }
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.toString('base64url') !== value
    || (expected !== undefined && decoded.length !== expected)
    || (minimum !== undefined && decoded.length < minimum)) {
    throw new HttpError(400, 'Invalid encrypted data');
  }
  return decoded;
}

function decodeBase64Url(value: unknown, expected: number): Buffer {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new HttpError(400, 'Invalid encoding');
  }
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.length !== expected || decoded.toString('base64url') !== value) {
    throw new HttpError(400, 'Invalid encoding');
  }
  return decoded;
}

function validateSecretBox(value: unknown, ciphertextBytes: number): asserts value is SecretBox {
  if (!isObject(value)) throw new HttpError(400, 'Invalid key bundle');
  decodeBase64(value.nonce, 24);
  decodeBase64(value.ciphertext, ciphertextBytes);
}

function validateBundle(value: unknown): asserts value is KeyBundle {
  if (!isObject(value)) throw new HttpError(400, 'Invalid key bundle');
  decodeBase64(value.salt, 16);
  if (value.opsLimit !== KDF_OPS_LIMIT || value.memLimit !== KDF_MEM_LIMIT) {
    throw new HttpError(400, 'Unsupported key derivation parameters');
  }
  decodeBase64(value.identityPublicKey, 32);
  validateSecretBox(value.encryptedIdentitySecret, 80);
  decodeBase64(value.vaultPublicKey, 32);
  validateSecretBox(value.encryptedVaultSecret, 48);
  decodeBase64(value.sealedVaultKey, 80);
}

function normalizeEmail(value: unknown): string {
  if (typeof value !== 'string') throw new HttpError(400, 'Invalid registration');
  const email = value.trim().toLowerCase();
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new HttpError(400, 'Invalid registration');
  }
  return email;
}

function validateEncryptedItem(value: unknown, pathId?: string): asserts value is {
  id: string;
  version: number;
  nonce: string;
  ciphertext: string;
} {
  if (!isObject(value) || typeof value.id !== 'string' || !UUID.test(value.id)
    || (pathId !== undefined && value.id !== pathId) || value.version !== 1) {
    throw new HttpError(400, 'Invalid item');
  }
  decodeBase64(value.nonce, 24);
  decodeBase64(value.ciphertext, undefined, 16);
}

function isoNow(): string {
  return new Date().toISOString();
}

function transaction<T>(db: DatabaseSync, operation: () => T): T {
  db.exec('BEGIN IMMEDIATE');
  try {
    const result = operation();
    db.exec('COMMIT');
    return result;
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}

function securityHeaders(res: ServerResponse, production: boolean): void {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'");
  if (production) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  res.setHeader('Referrer-Policy', 'no-referrer');
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const data = Buffer.from(JSON.stringify(body));
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': data.length,
    'Cache-Control': 'no-store',
  });
  res.end(data);
}

function parseCookies(header: string | undefined): Record<string, string> {
  const cookies: Record<string, string> = {};
  for (const part of header?.split(';') ?? []) {
    const separator = part.indexOf('=');
    if (separator < 1) continue;
    const name = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    try {
      cookies[name] = decodeURIComponent(value);
    } catch {
      cookies[name] = '';
    }
  }
  return cookies;
}

function checkRequestSecurity(req: IncomingMessage, config: AppConfig): void {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method ?? '')) return;
  if (req.headers['sec-fetch-site'] === 'cross-site') {
    throw new HttpError(403, 'Forbidden');
  }
  const origin = req.headers.origin;
  if (origin !== undefined) {
    let normalized: string;
    try {
      normalized = new URL(origin).origin;
    } catch {
      throw new HttpError(403, 'Forbidden');
    }
    if (normalized !== config.publicOrigin) throw new HttpError(403, 'Forbidden');
  }
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const contentType = req.headers['content-type']?.split(';', 1)[0]?.trim().toLowerCase();
  if (contentType !== 'application/json') throw new HttpError(415, 'Expected application/json');
  const declared = Number(req.headers['content-length'] ?? '0');
  if (declared > JSON_LIMIT) {
    req.resume();
    throw new HttpError(413, 'Request too large');
  }
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > JSON_LIMIT) throw new HttpError(413, 'Request too large');
    chunks.push(buffer);
  }
  if (size === 0) throw new HttpError(400, 'Invalid JSON');
  try {
    return JSON.parse(Buffer.concat(chunks, size).toString('utf8'));
  } catch {
    throw new HttpError(400, 'Invalid JSON');
  }
}

function userResponse(user: UserRow): { user: { email: string } } {
  return { user: { email: user.email } };
}

function itemResponse(row: Row): Record<string, unknown> {
  return {
    id: row.id,
    version: row.version,
    nonce: row.nonce,
    ciphertext: row.ciphertext,
    updatedAt: new Date(Number(row.updated_at)).toISOString(),
  };
}

function shareResponse(row: Row): Record<string, unknown> {
  return {
    id: row.id,
    itemId: row.item_id,
    expiresAt: new Date(Number(row.expires_at)).toISOString(),
    revokedAt: typeof row.revoked_at === 'number' ? new Date(row.revoked_at).toISOString() : null,
    createdAt: new Date(Number(row.created_at)).toISOString(),
  };
}

function shareDigest(config: AppConfig, id: string, token: string): Buffer {
  return createHmac('sha256', config.sharePepper).update(`${id}.${token}`).digest();
}

function fixedTimeEqual(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

function createSchema(db: DatabaseSync): void {
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;
    PRAGMA busy_timeout = 5000;
    PRAGMA synchronous = NORMAL;
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      bundle TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
    CREATE TABLE IF NOT EXISTS challenges (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      challenge TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS challenges_expiry ON challenges(expires_at);
    CREATE TABLE IF NOT EXISTS login_rate_limits (
      email TEXT PRIMARY KEY,
      window_started INTEGER NOT NULL,
      attempts INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS items (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      version INTEGER NOT NULL,
      nonce TEXT NOT NULL,
      ciphertext TEXT NOT NULL,
      updated_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS items_owner ON items(user_id);
    CREATE TABLE IF NOT EXISTS shares (
      id TEXT PRIMARY KEY,
      item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
      token_hash BLOB NOT NULL UNIQUE,
      ciphertext TEXT NOT NULL,
      nonce TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      revoked_at INTEGER,
      created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS shares_item ON shares(item_id);
    CREATE INDEX IF NOT EXISTS shares_expiry ON shares(expires_at);
  `);
}

export function createApp(config: AppConfig = createConfig()): LockitApp {
  if (config.dbPath !== ':memory:') {
    mkdirSync(path.dirname(path.resolve(config.dbPath)), { recursive: true });
  }
  const db = new DatabaseSync(config.dbPath);
  createSchema(db);

  const rateLimits = new Map<string, { count: number; expiresAt: number }>();
  const pruneRateLimits = () => {
    const now = Date.now();
    for (const [key, entry] of rateLimits) {
      if (entry.expiresAt <= now) rateLimits.delete(key);
    }
    while (rateLimits.size > RATE_LIMIT_ENTRIES) {
      const oldest = rateLimits.keys().next().value;
      if (oldest === undefined) break;
      rateLimits.delete(oldest);
    }
  };
  const pruneTimer = setInterval(pruneRateLimits, 60_000);
  pruneTimer.unref();

  const consumeRateLimit = (key: string, limit: number, windowMs: number, res: ServerResponse) => {
    const now = Date.now();
    let entry = rateLimits.get(key);
    if (entry && entry.expiresAt <= now) {
      rateLimits.delete(key);
      entry = undefined;
    }
    if (!entry) {
      pruneRateLimits();
      while (rateLimits.size >= RATE_LIMIT_ENTRIES) {
        const oldest = rateLimits.keys().next().value;
        if (oldest === undefined) break;
        rateLimits.delete(oldest);
      }
      entry = { count: 0, expiresAt: now + windowMs };
      rateLimits.set(key, entry);
    }
    if (entry.count >= limit) {
      res.setHeader('Retry-After', String(Math.max(1, Math.ceil((entry.expiresAt - now) / 1000))));
      throw new HttpError(429, 'Too many requests');
    }
    entry.count++;
  };

  const clientIp = (req: IncomingMessage): string => {
    if (config.trustProxy) {
      const forwarded = req.headers['x-forwarded-for'];
      const value = Array.isArray(forwarded) ? forwarded[0] : forwarded;
      const first = value?.split(',', 1)[0]?.trim();
      if (first) return first.slice(0, 200);
    }
    return req.socket.remoteAddress ?? 'unknown';
  };

  const hibpQueue: Array<() => Promise<void>> = [];
  let hibpActive = 0;
  const pumpHibpQueue = () => {
    while (hibpActive < HIBP_CONCURRENCY && hibpQueue.length > 0) {
      const task = hibpQueue.shift()!;
      hibpActive++;
      void task().finally(() => {
        hibpActive--;
        pumpHibpQueue();
      });
    }
  };
  const scheduleHibp = <T>(operation: () => Promise<T>): Promise<T> => new Promise<T>((resolve, reject) => {
    if (hibpActive >= HIBP_CONCURRENCY && hibpQueue.length >= HIBP_QUEUE_LIMIT) {
      reject(new HttpError(503, 'Password range busy'));
      return;
    }
    hibpQueue.push(async () => {
      try {
        resolve(await operation());
      } catch (error) {
        reject(error);
      }
    });
    pumpHibpQueue();
  });

  let lastCleanup = 0;
  const cleanup = () => {
    const now = Date.now();
    if (now - lastCleanup < 60_000) return;
    lastCleanup = now;
    db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(now);
    db.prepare('DELETE FROM challenges WHERE expires_at <= ?').run(now);
    db.prepare('DELETE FROM shares WHERE expires_at <= ?').run(now);
    db.prepare('DELETE FROM login_rate_limits WHERE window_started < ?').run(now - CHALLENGE_WINDOW_MS * 2);
  };
  cleanup();

  const cookieName = config.production ? '__Host-lockit_session' : 'lockit_session';
  const cookieFlags = `HttpOnly; SameSite=Strict; Path=/${config.production ? '; Secure' : ''}`;

  const issueSession = (userId: string): string => {
    const token = randomBytes(32).toString('base64url');
    const tokenHash = createHash('sha256').update(token).digest('hex');
    const now = Date.now();
    db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)')
      .run(tokenHash, userId, now + SESSION_SECONDS * 1000, now);
    return token;
  };

  const sessionCookie = (token: string): string =>
    `${cookieName}=${encodeURIComponent(token)}; Max-Age=${SESSION_SECONDS}; ${cookieFlags}`;

  const authenticate = (req: IncomingMessage): Session => {
    const token = parseCookies(req.headers.cookie)[cookieName];
    if (!token) throw new HttpError(401, 'Authentication required');
    const tokenHash = createHash('sha256').update(token).digest('hex');
    const row = db.prepare(`SELECT u.id, u.email, u.bundle, s.expires_at
      FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ? AND s.expires_at > ?`).get(tokenHash, Date.now()) as (Row & { expires_at: number }) | undefined;
    if (!row) throw new HttpError(401, 'Authentication required');
    return { user: row as unknown as UserRow, tokenHash };
  };

  const serveStatic = async (req: IncomingMessage, res: ServerResponse, pathname: string): Promise<void> => {
    if (!existsSync(config.publicDir) || !['GET', 'HEAD'].includes(req.method ?? '')) {
      throw new HttpError(404, 'Not found');
    }
    let decoded: string;
    try {
      decoded = decodeURIComponent(pathname);
    } catch {
      throw new HttpError(400, 'Invalid path');
    }
    if (decoded.includes('\0')) throw new HttpError(400, 'Invalid path');
    const root = path.resolve(config.publicDir);
    let filename = path.resolve(root, `.${decoded}`);
    if (filename !== root && !filename.startsWith(`${root}${path.sep}`)) {
      throw new HttpError(403, 'Forbidden');
    }
    let info = await stat(filename).catch(() => null);
    if (info?.isDirectory()) {
      filename = path.join(filename, 'index.html');
      info = await stat(filename).catch(() => null);
    }
    if (!info?.isFile()) {
      filename = path.join(root, 'index.html');
      info = await stat(filename).catch(() => null);
    }
    if (!info?.isFile()) throw new HttpError(404, 'Not found');
    const types: Record<string, string> = {
      '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
      '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8',
      '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon',
      '.woff': 'font/woff', '.woff2': 'font/woff2', '.webp': 'image/webp',
    };
    res.writeHead(200, {
      'Content-Type': types[path.extname(filename)] ?? 'application/octet-stream',
      'Content-Length': info.size,
    });
    if (req.method === 'HEAD') {
      res.end();
      return;
    }
    const stream = createReadStream(filename);
    stream.on('error', () => res.destroy());
    stream.pipe(res);
  };

  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    securityHeaders(res, config.production);
    cleanup();
    checkRequestSecurity(req, config);
    const url = new URL(req.url ?? '/', 'http://localhost');
    const pathname = url.pathname;

    if (req.method === 'GET' && pathname === '/api/health') {
      sendJson(res, 200, { status: 'ok' });
      return;
    }

    if (req.method === 'POST' && pathname === '/api/register') {
      consumeRateLimit(`register:${clientIp(req)}`, 10, 60 * 60 * 1000, res);
      const body = await readJson(req);
      if (!isObject(body)) throw new HttpError(400, 'Invalid registration');
      const { email: submittedEmail, ...bundle } = body;
      const email = normalizeEmail(submittedEmail);
      validateBundle(bundle);
      const userId = randomUUID();
      const now = Date.now();
      let token: string;
      try {
        token = transaction(db, () => {
          db.prepare('INSERT INTO users (id, email, bundle, created_at) VALUES (?, ?, ?, ?)')
            .run(userId, email, JSON.stringify(bundle), now);
          return issueSession(userId);
        });
      } catch {
        throw new HttpError(409, 'Registration failed');
      }
      res.setHeader('Set-Cookie', sessionCookie(token));
      sendJson(res, 201, { user: { email } });
      return;
    }

    if (req.method === 'POST' && pathname === '/api/auth/challenge') {
      consumeRateLimit(`challenge:${clientIp(req)}`, 20, 60 * 1000, res);
      const body = await readJson(req);
      if (!isObject(body)) throw new HttpError(401, 'Authentication failed');
      let email: string;
      try {
        email = normalizeEmail(body.email);
      } catch {
        throw new HttpError(401, 'Authentication failed');
      }
      const now = Date.now();
      try {
        const result = transaction(db, () => {
          const rate = db.prepare('SELECT window_started, attempts FROM login_rate_limits WHERE email = ?').get(email) as Row | undefined;
          const attempts = rate && now - Number(rate.window_started) < CHALLENGE_WINDOW_MS ? Number(rate.attempts) : 0;
          if (attempts >= CHALLENGE_LIMIT) throw new HttpError(429, 'Authentication failed');
          db.prepare(`INSERT INTO login_rate_limits (email, window_started, attempts) VALUES (?, ?, ?)
            ON CONFLICT(email) DO UPDATE SET window_started = excluded.window_started, attempts = excluded.attempts`)
            .run(email, attempts === 0 ? now : Number(rate?.window_started), attempts + 1);
          const user = db.prepare('SELECT id, email, bundle FROM users WHERE email = ?').get(email) as UserRow | undefined;
          if (!user) return null;
          const id = randomUUID();
          const challenge = randomBytes(32).toString('base64url');
          const expiresAt = now + CHALLENGE_SECONDS * 1000;
          db.prepare('INSERT INTO challenges (id, user_id, challenge, expires_at) VALUES (?, ?, ?, ?)')
            .run(id, user.id, challenge, expiresAt);
          return { id, challenge, expiresAt, bundle: JSON.parse(user.bundle) as KeyBundle };
        });
        if (!result) throw new HttpError(401, 'Authentication failed');
        sendJson(res, 200, {
          challengeId: result.id,
          challenge: result.challenge,
          expiresAt: new Date(result.expiresAt).toISOString(),
          bundle: result.bundle,
        });
      } catch (error) {
        if (error instanceof HttpError && error.status === 429) res.setHeader('Retry-After', '60');
        throw error;
      }
      return;
    }

    if (req.method === 'POST' && pathname === '/api/auth/verify') {
      const body = await readJson(req);
      try {
        if (!isObject(body) || typeof body.challengeId !== 'string' || !UUID.test(body.challengeId)) {
          throw new Error('Invalid');
        }
        const challengeId = body.challengeId;
        const signature = decodeBase64Url(body.signature, 64);
        const result = transaction(db, () => {
          const row = db.prepare(`SELECT c.challenge, c.expires_at, u.id, u.email, u.bundle
            FROM challenges c JOIN users u ON u.id = c.user_id WHERE c.id = ?`).get(challengeId) as (Row & { challenge: string; expires_at: number }) | undefined;
          if (!row || Number(row.expires_at) <= Date.now()) return null;
          db.prepare('DELETE FROM challenges WHERE id = ? AND expires_at > ?').run(challengeId, Date.now());
          return row;
        });
        if (!result) throw new Error('Invalid');
        const challenge = decodeBase64Url(result.challenge, 32);
        const bundle = JSON.parse(String(result.bundle)) as KeyBundle;
        const identityKey = decodeBase64(bundle.identityPublicKey, 32);
        const publicKey = Buffer.concat([ED25519_SPKI_PREFIX, identityKey]);
        if (!verify(null, challenge, { key: publicKey, format: 'der', type: 'spki' }, signature)) {
          throw new Error('Invalid');
        }
        const user = result as unknown as UserRow;
        res.setHeader('Set-Cookie', sessionCookie(issueSession(user.id)));
        sendJson(res, 200, userResponse(user));
      } catch {
        throw new HttpError(401, 'Authentication failed');
      }
      return;
    }

    if (req.method === 'POST' && pathname === '/api/auth/logout') {
      const session = authenticate(req);
      db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(session.tokenHash);
      res.setHeader('Set-Cookie', `${cookieName}=; Max-Age=0; ${cookieFlags}`);
      sendJson(res, 200, { status: 'ok' });
      return;
    }

    if (req.method === 'GET' && pathname === '/api/auth/me') {
      sendJson(res, 200, userResponse(authenticate(req).user));
      return;
    }

    if (req.method === 'GET' && pathname === '/api/auth/bundle') {
      const session = authenticate(req);
      sendJson(res, 200, { bundle: JSON.parse(session.user.bundle) });
      return;
    }

    if (req.method === 'PUT' && pathname === '/api/auth/bundle') {
      const session = authenticate(req);
      const body = await readJson(req);
      if (!isObject(body)) throw new HttpError(400, 'Invalid key bundle');
      validateBundle(body.bundle);
      const current = JSON.parse(session.user.bundle) as KeyBundle;
      if (body.bundle.identityPublicKey !== current.identityPublicKey
        || body.bundle.vaultPublicKey !== current.vaultPublicKey
        || body.bundle.sealedVaultKey !== current.sealedVaultKey) {
        throw new HttpError(400, 'Bundle identity fields cannot change');
      }
      transaction(db, () => {
        db.prepare('UPDATE users SET bundle = ? WHERE id = ?').run(JSON.stringify(body.bundle), session.user.id);
        db.prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?').run(session.user.id, session.tokenHash);
      });
      sendJson(res, 200, { bundle: body.bundle });
      return;
    }

    if (req.method === 'GET' && pathname === '/api/items') {
      const session = authenticate(req);
      const rows = db.prepare('SELECT * FROM items WHERE user_id = ? ORDER BY updated_at DESC').all(session.user.id) as Row[];
      sendJson(res, 200, { items: rows.map(itemResponse) });
      return;
    }

    if (req.method === 'POST' && pathname === '/api/items') {
      const session = authenticate(req);
      const body = await readJson(req);
      if (!isObject(body)) throw new HttpError(400, 'Invalid item');
      validateEncryptedItem(body.item);
      const item = body.item;
      const ciphertextBytes = Buffer.from(item.ciphertext, 'base64url').byteLength;
      const now = Date.now();
      try {
        transaction(db, () => {
          const quota = db.prepare(`SELECT COUNT(*) AS item_count,
            COALESCE(SUM((length(ciphertext) * 3) / 4), 0) AS ciphertext_bytes
            FROM items WHERE user_id = ?`).get(session.user.id) as Row;
          if (Number(quota.item_count) >= MAX_ITEMS_PER_USER
            || Number(quota.ciphertext_bytes) + ciphertextBytes > MAX_ITEM_CIPHERTEXT_BYTES) {
            throw new HttpError(413, 'Item quota exceeded');
          }
          db.prepare('INSERT INTO items (id, user_id, version, nonce, ciphertext, updated_at) VALUES (?, ?, ?, ?, ?, ?)')
            .run(item.id, session.user.id, item.version, item.nonce, item.ciphertext, now);
        });
      } catch (error) {
        if (error instanceof HttpError) throw error;
        throw new HttpError(409, 'Item already exists');
      }
      sendJson(res, 201, { item: { ...item, updatedAt: new Date(now).toISOString() } });
      return;
    }

    const itemMatch = /^\/api\/items\/([0-9a-fA-F-]{36})$/.exec(pathname);
    if (itemMatch && ['PUT', 'DELETE'].includes(req.method ?? '')) {
      const session = authenticate(req);
      const id = itemMatch[1]!;
      if (!UUID.test(id)) throw new HttpError(404, 'Not found');
      if (req.method === 'PUT') {
        const body = await readJson(req);
        if (!isObject(body)) throw new HttpError(400, 'Invalid item');
        validateEncryptedItem(body.item, id);
        const item = body.item;
        const ciphertextBytes = Buffer.from(item.ciphertext, 'base64url').byteLength;
        const now = Date.now();
        transaction(db, () => {
          const existing = db.prepare('SELECT length(ciphertext) AS encoded_length FROM items WHERE id = ? AND user_id = ?')
            .get(id, session.user.id) as Row | undefined;
          if (!existing) throw new HttpError(404, 'Not found');
          const quota = db.prepare('SELECT COALESCE(SUM((length(ciphertext) * 3) / 4), 0) AS ciphertext_bytes FROM items WHERE user_id = ?')
            .get(session.user.id) as Row;
          const oldBytes = Math.floor(Number(existing.encoded_length) * 3 / 4);
          if (Number(quota.ciphertext_bytes) - oldBytes + ciphertextBytes > MAX_ITEM_CIPHERTEXT_BYTES) {
            throw new HttpError(413, 'Item quota exceeded');
          }
          db.prepare(`UPDATE items SET version = ?, nonce = ?, ciphertext = ?, updated_at = ?
            WHERE id = ? AND user_id = ?`).run(item.version, item.nonce, item.ciphertext, now, id, session.user.id);
        });
        sendJson(res, 200, { item: { ...item, updatedAt: new Date(now).toISOString() } });
      } else {
        const result = db.prepare('DELETE FROM items WHERE id = ? AND user_id = ?').run(id, session.user.id);
        if (result.changes !== 1) throw new HttpError(404, 'Not found');
        res.writeHead(204);
        res.end();
      }
      return;
    }

    if (req.method === 'POST' && pathname === '/api/shares') {
      const session = authenticate(req);
      const body = await readJson(req);
      if (!isObject(body) || typeof body.id !== 'string' || !UUID.test(body.id)
        || typeof body.itemId !== 'string' || !UUID.test(body.itemId)
        || typeof body.nonce !== 'string' || typeof body.ciphertext !== 'string'
        || !Number.isInteger(body.ttlSeconds) || Number(body.ttlSeconds) < 60 || Number(body.ttlSeconds) > 604800) {
        throw new HttpError(400, 'Invalid share');
      }
      decodeBase64(body.nonce, 24);
      decodeBase64(body.ciphertext, undefined, 16);
      const id = body.id;
      const itemId = body.itemId;
      const nonce = body.nonce;
      const ciphertext = body.ciphertext;
      const owned = db.prepare('SELECT id FROM items WHERE id = ? AND user_id = ?').get(itemId, session.user.id);
      if (!owned) throw new HttpError(404, 'Not found');
      const token = randomBytes(32).toString('base64url');
      const digest = shareDigest(config, id, token);
      const now = Date.now();
      const expiresAt = now + Number(body.ttlSeconds) * 1000;
      db.prepare(`INSERT INTO shares (id, item_id, token_hash, ciphertext, nonce, expires_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)`)
        .run(id, itemId, digest, ciphertext, nonce, expiresAt, now);
      const share = {
        id, itemId, expiresAt: new Date(expiresAt).toISOString(), revokedAt: null,
        createdAt: new Date(now).toISOString(),
      };
      sendJson(res, 201, { share, token });
      return;
    }

    if (req.method === 'GET' && pathname === '/api/shares') {
      const session = authenticate(req);
      const rows = db.prepare(`SELECT s.* FROM shares s JOIN items i ON i.id = s.item_id
        WHERE i.user_id = ? ORDER BY s.created_at DESC`).all(session.user.id) as Row[];
      sendJson(res, 200, { shares: rows.map(shareResponse) });
      return;
    }

    if (req.method === 'POST' && pathname === '/api/shares/open') {
      const body = await readJson(req);
      try {
        if (!isObject(body) || typeof body.id !== 'string' || !UUID.test(body.id) || typeof body.token !== 'string') {
          throw new Error('Invalid');
        }
        decodeBase64Url(body.token, 32);
        const row = db.prepare('SELECT * FROM shares WHERE id = ?').get(body.id) as Row | undefined;
        if (!row || !fixedTimeEqual(shareDigest(config, body.id, body.token), row.token_hash as Buffer)
          || Number(row.expires_at) <= Date.now() || row.revoked_at !== null) {
          throw new Error('Invalid');
        }
        sendJson(res, 200, {
          share: { id: body.id, expiresAt: new Date(Number(row.expires_at)).toISOString() },
          ciphertext: row.ciphertext,
          nonce: row.nonce,
        });
      } catch {
        throw new HttpError(404, 'Not found');
      }
      return;
    }

    const shareMatch = /^\/api\/shares\/([0-9a-fA-F-]{36})$/.exec(pathname);
    if (shareMatch && req.method === 'DELETE') {
      const session = authenticate(req);
      const id = shareMatch[1]!;
      if (!UUID.test(id)) throw new HttpError(404, 'Not found');
      const result = db.prepare(`UPDATE shares SET revoked_at = ? FROM items
        WHERE shares.item_id = items.id AND shares.id = ? AND items.user_id = ?`)
        .run(Date.now(), id, session.user.id);
      if (result.changes !== 1) throw new HttpError(404, 'Not found');
      res.writeHead(204);
      res.end();
      return;
    }

    const hibpMatch = /^\/api\/hibp\/([0-9a-fA-F]{5})$/.exec(pathname);
    if (hibpMatch && req.method === 'GET') {
      const session = authenticate(req);
      consumeRateLimit(`hibp:${session.user.id}`, 30, 60 * 1000, res);
      const prefix = hibpMatch[1]!.toUpperCase();
      try {
        await scheduleHibp(async () => {
        const response = await fetch(`${config.hibpBaseUrl}/range/${prefix}`, {
          headers: { 'Add-Padding': 'true', 'User-Agent': 'Lockit/0.1' },
          signal: AbortSignal.timeout(8000),
          redirect: 'error',
        });
        if (!response.ok || !response.body) throw new Error('Upstream failed');
        const length = Number(response.headers.get('content-length') ?? '0');
        if (length > HIBP_LIMIT) {
          await response.body.cancel();
          throw new Error('Response too large');
        }
        const reader = response.body.getReader();
        const chunks: Buffer[] = [];
        let size = 0;
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          size += value.byteLength;
          if (size > HIBP_LIMIT) {
            await reader.cancel();
            throw new Error('Response too large');
          }
          chunks.push(Buffer.from(value));
        }
        const data = Buffer.concat(chunks, size);
        res.writeHead(200, {
          'Content-Type': 'text/plain; charset=utf-8',
          'Content-Length': data.length,
          'Cache-Control': 'no-store',
        });
        res.end(data);
        });
      } catch (error) {
        if (error instanceof HttpError) {
          if (error.status === 503) res.setHeader('Retry-After', '1');
          throw error;
        }
        throw new HttpError(502, 'Password range unavailable');
      }
      return;
    }

    if (pathname.startsWith('/api/')) throw new HttpError(404, 'Not found');
    await serveStatic(req, res, pathname);
  };

  const server = createServer((req, res) => {
    void handle(req, res).catch((error: unknown) => {
      if (res.headersSent) {
        res.destroy();
        return;
      }
      if (error instanceof HttpError) {
        sendJson(res, error.status, { error: error.message });
      } else {
        sendJson(res, 500, { error: 'Internal server error' });
      }
    });
  });

  return {
    server,
    db,
    config,
    close: () => {
      clearInterval(pruneTimer);
      db.close();
    },
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const app = createApp();
  app.server.listen(app.config.port);
}
