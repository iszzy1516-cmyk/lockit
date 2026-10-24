# Lockit

Lockit is a zero-knowledge vault for passwords, API keys, and small documents. Items are encrypted in the browser before storage. The server never receives the master password, plaintext items, private keys, or share decryption keys.

## Included

- Argon2id key derivation with explicit parameters: 3 iterations and 64 MiB.
- Ed25519 challenge-signed login; no password verifier is stored.
- XSalsa20-Poly1305 private-key wrapping and XChaCha20-Poly1305 item encryption.
- Password, API-key, and document storage with local search, reveal, copy, and download.
- Master-password changes that re-wrap private keys without re-encrypting every item.
- Expiring, revocable, end-to-end encrypted share snapshots. Authorization token and decryption key stay in the URL fragment.
- HaveIBeenPwned range checks using a locally computed SHA-1 hash prefix.
- Five-minute idle lock, explicit lock/logout, and best-effort browser key wiping.
- Native CLI with mandatory `mlock` and deterministic `memzero`/`munlock` cleanup for sensitive buffers.
- SQLite storage, strict validation, registration/login throttling, per-user storage quotas, bounded HIBP concurrency, secure cookies, CSP, TLS 1.3 and HSTS deployment configuration.

## Run locally

Requirements: Node.js 22.12 or newer. Node 22 emits an experimental warning for its built-in SQLite module.

```sh
npm ci
npm run dev
```

Open `http://localhost:5173`. Vite proxies API requests to the server on port 3000. Development uses HTTP on loopback and a clearly marked development-only share pepper; do not use this configuration on a network.

For a production-style local build:

```sh
npm run build
npm start
```

Open `http://localhost:3000`. A production start with `NODE_ENV=production` requires an HTTPS `LOCKIT_PUBLIC_ORIGIN` and a random `LOCKIT_SHARE_PEPPER` of at least 32 bytes, and must be placed behind the TLS proxy.

## Deploy with TLS 1.3

Point DNS for the vault hostname at the Docker host, then provide its HTTPS origin and an independently generated pepper:

```sh
export LOCKIT_PUBLIC_ORIGIN=https://vault.example.com
export LOCKIT_SHARE_PEPPER="$(openssl rand -hex 32)"
docker compose up --build -d
```

Caddy obtains and renews the certificate, accepts only TLS 1.3, and proxies to the non-root application container. Keep the Caddy and SQLite volumes backed up. Losing the share pepper invalidates existing share authorization tokens but does not affect vault decryption.

Configuration is documented in `.env.example`. Never commit real environment files or the share pepper.

## Native CLI

Create an account in the browser first, then use the same master password:

```sh
npm run cli -- list --email person@example.com
npm run cli -- reveal --email person@example.com --id ITEM_UUID
```

Use `--server URL` or `LOCKIT_SERVER` for a remote vault. The CLI refuses noninteractive password input and fails if sensitive buffers cannot be locked. Explicit `reveal` output can remain in terminal scrollback or captured logs. JavaScript string/JSON copies and OS crash dumps cannot be completely controlled; see `docs/security.md`.

## Verification

```sh
npx playwright install chromium
npm run check
npm audit
```

`npm run check` performs strict typechecking, unit/integration tests, the production build, and a real Chromium workflow against the real server. The browser test covers all item types, breach checking, sharing and revocation, password change, re-unlock, responsive layout, and absence of plaintext from captured API requests and SQLite. HIBP uses a controlled fixture so tests do not depend on an external service.

## CI/CD

GitHub Actions runs the full check, production dependency audit, and container build on pushes and pull requests. After CI succeeds on `main`, the CD workflow publishes the image to `ghcr.io/<owner>/lockit:latest` and `ghcr.io/<owner>/lockit:main`, plus a commit-SHA tag. The `production` environment can require approval before publication. No application server is modified by CI; deploy the published image with the TLS configuration above.

## Security and recovery

There is deliberately no master-password reset or server-side recovery. A forgotten master password means the encrypted vault cannot be decrypted. Share links are bearer capabilities: anyone with the complete link can retain a copy of the decrypted snapshot, and revocation cannot erase a recipient's copy.

Read `docs/security.md` for the key hierarchy, threat model, audit-simulation results, deployment assumptions, and residual risks. This project has not undergone a real independent cryptographic audit.
