#!/usr/bin/env node
import { pathToFileURL } from 'node:url';
import {
  allocateLockedCopy,
  decryptItem,
  disposeAllSecureMemory,
  encodeBase64url,
  LockedBuffer,
  unlockBundle,
} from './secure.js';
import type { EncryptedItem, LoginChallenge, VaultItem } from '../shared/api.js';
import sodium from 'sodium-native';

const DEFAULT_SERVER = 'http://127.0.0.1:3000';
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export const CLI_SECURITY_NOTES = `Security notes:
- Passwords, keys, and decrypted item bytes use guarded, locked sodium buffers and are wiped on completion and signals.
- JavaScript still requires temporary ordinary Buffer/string copies for terminal input, JSON parsing, and output. They are wiped where possible, but the runtime cannot guarantee erasure of every copy.
- reveal intentionally writes plaintext to stdout. Your terminal, scrollback, logs, and shell capture can retain it.
- Locked memory cannot protect secrets from an already-compromised process or machine.`;

const USAGE = `Usage:
  npm run cli -- list --email user@example.com [--id itemUUID] [--server URL]
  npm run cli -- reveal --email user@example.com --id itemUUID [--server URL]

Options:
  --email    Existing account email (required)
  --id       Item UUID; required for reveal, optional as a list filter
  --server   API origin; overrides LOCKIT_SERVER (default ${DEFAULT_SERVER})
  --help     Show this help

The master password is read only from a hidden interactive TTY prompt. Non-interactive stdin is refused.

${CLI_SECURITY_NOTES}`;

export type CliOptions = {
  command: 'list' | 'reveal';
  email: string;
  id?: string;
  server: string;
};

export type ParsedArguments = CliOptions | { command: 'help' };

function normalizeServer(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error('Invalid server URL.');
  }
  if ((url.protocol !== 'http:' && url.protocol !== 'https:') || url.username || url.password || url.search || url.hash) {
    throw new Error('Server must be an HTTP(S) URL without credentials, query, or fragment.');
  }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !loopback) {
    throw new Error('Remote CLI servers require HTTPS; cleartext HTTP is allowed only on loopback.');
  }
  return url.toString().replace(/\/$/, '');
}

export function parseArgs(argv: string[], env: NodeJS.ProcessEnv = process.env): ParsedArguments {
  if (argv.length === 1 && (argv[0] === '--help' || argv[0] === '-h')) return { command: 'help' };
  const command = argv[0];
  if (command !== 'list' && command !== 'reveal') {
    throw new Error('A command is required: list or reveal.');
  }

  const values = new Map<string, string>();
  for (let index = 1; index < argv.length; index += 1) {
    const argument = argv[index];
    if (!argument) throw new Error('Invalid empty argument.');
    const equals = argument.indexOf('=');
    const name = equals === -1 ? argument : argument.slice(0, equals);
    if (name !== '--email' && name !== '--id' && name !== '--server') {
      throw new Error(`Unknown option: ${name}`);
    }
    if (values.has(name)) throw new Error(`Duplicate option: ${name}`);
    let value: string;
    if (equals !== -1) {
      value = argument.slice(equals + 1);
    } else {
      index += 1;
      value = argv[index] ?? '';
    }
    if (!value || value.startsWith('--')) throw new Error(`Missing value for ${name}.`);
    values.set(name, value);
  }

  const email = values.get('--email');
  if (!email || !/^[^\s@]+@[^\s@]+$/.test(email)) throw new Error('A valid --email is required.');
  const id = values.get('--id');
  if (command === 'reveal' && !id) throw new Error('reveal requires --id.');
  if (id && !UUID_PATTERN.test(id)) throw new Error('--id must be a valid item UUID.');

  return {
    command,
    email,
    ...(id ? { id } : {}),
    server: normalizeServer(values.get('--server') ?? env.LOCKIT_SERVER ?? DEFAULT_SERVER),
  };
}

let restorePrompt: (() => void) | undefined;

export function readMasterPassword(
  input: NodeJS.ReadStream = process.stdin,
  output: NodeJS.WriteStream = process.stderr,
): Promise<LockedBuffer> {
  if (!input.isTTY || typeof input.setRawMode !== 'function') {
    throw new Error('A hidden master-password prompt requires an interactive TTY; non-interactive stdin is refused.');
  }

  output.write('Master password: ');
  input.setRawMode(true);
  input.resume();

  return new Promise<LockedBuffer>((resolve, reject) => {
    let password = Buffer.alloc(0);
    let settled = false;

    const wipe = () => {
      sodium.sodium_memzero(password);
      password = Buffer.alloc(0);
    };
    const cleanup = () => {
      input.off('data', onData);
      input.off('end', onEnd);
      input.off('error', onError);
      try {
        input.setRawMode(false);
      } finally {
        try {
          input.pause();
        } finally {
          restorePrompt = undefined;
          wipe();
        }
      }
    };
    restorePrompt = cleanup;

    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      output.write('\n');
      let result: LockedBuffer | undefined;
      if (!error && password.length === 0) error = new Error('Master password cannot be empty.');
      if (!error) {
        try {
          result = allocateLockedCopy(password);
        } catch (allocationError) {
          error = allocationError instanceof Error ? allocationError : new Error('Unable to allocate secure memory.');
        }
      }
      cleanup();
      if (error) reject(error);
      else resolve(result!);
    };
    const append = (part: Buffer) => {
      if (part.length === 0) return;
      const previous = password;
      password = Buffer.concat([previous, part]);
      sodium.sodium_memzero(previous);
      if (password.length > 64 * 1024) finish(new Error('Master password is too long.'));
    };
    const backspace = () => {
      if (password.length === 0) return;
      let length = password.length - 1;
      while (length > 0 && (password[length]! & 0xc0) === 0x80) length -= 1;
      const previous = password;
      password = Buffer.from(previous.subarray(0, length));
      sodium.sodium_memzero(previous);
    };
    const onData = (chunk: Buffer) => {
      let start = 0;
      for (let index = 0; index < chunk.length && !settled; index += 1) {
        const byte = chunk[index]!;
        if (byte === 10 || byte === 13 || byte === 3 || byte === 4 || byte === 8 || byte === 127) {
          append(chunk.subarray(start, index));
          start = index + 1;
          if (byte === 10 || byte === 13) finish();
          else if (byte === 3) finish(new Error('Password entry interrupted.'));
          else if (byte === 4) finish(new Error('Password entry cancelled.'));
          else backspace();
        }
      }
      if (!settled) append(chunk.subarray(start));
      sodium.sodium_memzero(chunk);
    };
    const onEnd = () => finish(new Error('Password input ended before confirmation.'));
    const onError = (error: Error) => finish(new Error('Unable to read the master password.', { cause: error }));
    input.on('data', onData);
    input.once('end', onEnd);
    input.once('error', onError);
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

async function responseJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    throw new Error(`Server returned invalid JSON (HTTP ${response.status}).`);
  }
}

async function post(server: string, path: string, body: unknown): Promise<{ data: unknown; response: Response }> {
  let response: Response;
  try {
    response = await fetch(`${server}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      redirect: 'error',
    });
  } catch (error) {
    throw new Error(`Unable to reach the Lockit server at ${server}.`, { cause: error });
  }
  const data = await responseJson(response);
  if (!response.ok) {
    const message = isRecord(data) && typeof data.error === 'string' ? `: ${data.error}` : '';
    throw new Error(`Server request failed (HTTP ${response.status})${message}`);
  }
  return { data, response };
}

function parseChallenge(value: unknown): LoginChallenge {
  if (
    !isRecord(value) ||
    typeof value.challengeId !== 'string' ||
    typeof value.challenge !== 'string' ||
    !isRecord(value.bundle)
  ) {
    throw new Error('Server returned an invalid login challenge.');
  }
  return value as unknown as LoginChallenge;
}

function sessionCookies(response: Response): string {
  const cookies = response.headers.getSetCookie()
    .map((cookie) => cookie.split(';', 1)[0]?.trim())
    .filter((cookie): cookie is string => Boolean(cookie?.includes('=')));
  if (cookies.length === 0) throw new Error('The server did not establish a session.');
  return cookies.join('; ');
}

async function getItems(server: string, cookie: string): Promise<EncryptedItem[]> {
  let response: Response;
  try {
    response = await fetch(`${server}/api/items`, {
      headers: { cookie },
      redirect: 'error',
    });
  } catch (error) {
    throw new Error('Unable to retrieve vault items.', { cause: error });
  }
  const data = await responseJson(response);
  if (!response.ok) {
    const message = isRecord(data) && typeof data.error === 'string' ? `: ${data.error}` : '';
    throw new Error(`Unable to retrieve vault items (HTTP ${response.status})${message}`);
  }
  const items = Array.isArray(data) ? data : isRecord(data) && Array.isArray(data.items) ? data.items : undefined;
  if (!items || !items.every((item) => isRecord(item))) {
    throw new Error('Server returned an invalid item list.');
  }
  return items as EncryptedItem[];
}

export async function run(options: CliOptions): Promise<void> {
  const { data: challengeData } = await post(options.server, '/api/auth/challenge', { email: options.email });
  const challenge = parseChallenge(challengeData);
  const password = await readMasterPassword();
  let vault: ReturnType<typeof unlockBundle>;
  try {
    vault = unlockBundle(challenge.bundle, password);
  } finally {
    password.dispose();
  }

  try {
    const signature = vault.signChallenge(challenge.challenge);
    const { response } = await post(options.server, '/api/auth/verify', {
      challengeId: challenge.challengeId,
      signature: encodeBase64url(signature),
    });
    const cookie = sessionCookies(response);
    const encryptedItems = await getItems(options.server, cookie);
    const selected = options.id ? encryptedItems.filter((item) => item.id === options.id) : encryptedItems;
    if (options.command === 'reveal' && selected.length === 0) {
      throw new Error(`Vault item not found: ${options.id}`);
    }

    const items = selected.map((item) => decryptItem(item, vault.vaultKey, vault.identityPublicKey));
    const output: VaultItem | Array<Pick<VaultItem, 'id' | 'kind' | 'title'>> = options.command === 'reveal'
      ? items[0]!
      : items.map(({ id, kind, title }) => ({ id, kind, title }));
    process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
  } finally {
    vault.close();
  }
}

function installCleanupHandlers(): void {
  const exitCodes: Record<string, number> = { SIGHUP: 129, SIGINT: 130, SIGTERM: 143 };
  for (const [signal, code] of Object.entries(exitCodes)) {
    process.once(signal, () => {
      try {
        restorePrompt?.();
      } catch {
        // Continue with secure-memory cleanup.
      }
      disposeAllSecureMemory();
      process.exit(code);
    });
  }
  process.once('exit', disposeAllSecureMemory);
}

export async function main(argv = process.argv.slice(2)): Promise<void> {
  const options = parseArgs(argv);
  if (options.command === 'help') {
    process.stdout.write(`${USAGE}\n`);
    return;
  }
  installCleanupHandlers();
  await run(options);
}

const entry = process.argv[1];
if (entry && import.meta.url === pathToFileURL(entry).href) {
  main().catch((error: unknown) => {
    process.stderr.write(`lockit: ${error instanceof Error ? error.message : 'Unexpected failure.'}\n`);
    process.exitCode = 1;
  });
}
