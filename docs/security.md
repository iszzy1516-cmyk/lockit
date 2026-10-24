# Lockit security architecture and audit simulation

## Scope and security claim

Lockit protects vault confidentiality and integrity when the server, database, network observer, or share recipient is not trusted with more access than intended. The server stores ciphertext and public authentication material only. It never decrypts vault items.

The original proposal's “private key decrypts vault items server-side” requirement is incompatible with “server never sees unencrypted vault items.” Lockit resolves this by decrypting only on the client. Login is a cryptographic proof of private-key possession, not transmission of a password or reusable password verifier.

This document is a self-review plus a simulated independent code review. It is **not** a third-party cryptographic audit or a guarantee against all implementation defects.

## Key hierarchy and formats

All encoded binary values use unpadded Base64url. Random values come from libsodium or the operating system CSPRNG.

| Purpose | Construction |
|---|---|
| Master key-encryption key | Argon2id13, 32-byte output, 16-byte random salt, 3 iterations, 64 MiB |
| Identity key pair | Ed25519; private key wrapped locally |
| Vault key pair | X25519; private key wrapped locally |
| Private-key wrapping | XSalsa20-Poly1305 `crypto_secretbox`, independent random 24-byte nonces |
| Recovery key | Random 256-bit client-generated key; wraps separate copies of private keys and exists only in the downloaded file |
| Vault data key | Random 32 bytes, sealed with X25519 `crypto_box_seal` |
| Item encryption | XChaCha20-Poly1305 IETF, random 24-byte nonce per save |
| Item context binding | AAD `lockit-item-v1:<identity-public-key>:<item-uuid>` |
| Login | Ed25519 signature over a random 32-byte, five-minute, single-use challenge |
| Session | Random 32-byte cookie token; SHA-256 token digest in SQLite; eight-hour expiry |
| Share encryption | Random 32-byte XChaCha20-Poly1305 key; AAD `lockit-share-v1:<share-uuid>` |
| Share authorization | Random 32-byte token; HMAC-SHA256(pepper, `<share-id>.<token>`) stored |

The complete item JSON—including title, username, secret, notes, URL, and document data—is encrypted. The stable Ed25519 public key is the account context for item AAD. Master-password changes generate a new salt and re-wrap only the two private keys; the public keys and sealed vault data key cannot change through the API.

Registration also creates a random 256-bit recovery key locally. That key wraps separate copies of the Ed25519 and X25519 private keys, and the client downloads it as a recovery file. The server stores only the authenticated ciphertext boxes. Anyone with the file can recover the account's private keys, so the file must be kept offline and should be replaced from Settings if exposed. Rotation changes only the recovery-wrapped copies; master wrapping, identity keys, and the vault data key stay unchanged.

A share is an encrypted snapshot, not live access. Its URL is `/share/<id>#<token>.<key>`. Browsers do not include the fragment in HTTP requests, so neither the authorization token nor decryption key appears in request paths or proxy access logs. The token is sent only in the JSON authorization request; the key remains in the recipient client. The database stores only the token HMAC and encrypted snapshot.

## Server and transport controls

- Ownership checks protect item and share mutations; UUIDs, ciphertext lengths, envelope versions, KDF parameters, and JSON sizes are validated. Users are limited to 1,000 items and 64 MiB of item ciphertext.
- Challenges expire and are consumed atomically. Persistent per-account and per-IP challenge throttling limits online attempts; registration is also IP-limited. Sessions expire, are revoked on logout, and other sessions are revoked when the master password changes.
- Mutations enforce Origin and Fetch Site checks. Cookies are HttpOnly, SameSite=Strict, Path=/; production uses Secure and the `__Host-` prefix.
- Production requires HTTPS public origin and a high-entropy share pepper. Caddy is configured for TLS 1.3 only, with HTTP redirected to HTTPS.
- Headers include HSTS in production, a self-only CSP with narrow WebAssembly permission, no framing, no MIME sniffing, COOP/CORP, no-referrer, and restrictive Permissions Policy. `'wasm-unsafe-eval'` permits WebAssembly, not arbitrary JavaScript eval.
- HIBP requires an authenticated session and is account-throttled with bounded upstream concurrency. Requests have an eight-second timeout, 1 MiB response limit, no redirects, required padding header, and no response caching.
- The server does not log request bodies. Caddy's default access logs do not include Cookie or Authorization headers; share capabilities are kept out of request paths.

## HIBP privacy and behavior

The browser computes SHA-1 locally and sends only the first five hexadecimal characters to the server range proxy. The full password and full hash are never sent or stored. Returned suffixes are compared locally. HIBP's padded range responses are supported.

Checks are user initiated while the item is unlocked. A malicious server cannot perform plaintext background monitoring. “Not found” is not a promise that a password is safe; upstream failure returns an explicit unknown state. HIBP and the server can observe a hash prefix, source IP, timing, and repeated checks, which is a residual metadata risk.

## Desktop trust boundary

The Tauri application starts the same server on a random loopback port and opens it inside the desktop WebView. The server, client, official Node runtime, and encrypted SQLite database are local. The database and randomly generated share pepper live in the operating system's per-user Lockit data directory, not the public repository or installation directory. Node runtime downloads are checked against official SHA-256 checksums during packaging.

Other local processes can attempt to reach the loopback port, but still need the authenticated session and must pass Origin and Fetch Metadata checks for mutations. A compromised user account or WebView remains outside the security boundary. Desktop share links are useful on that local instance; sharing with other devices requires a deliberately deployed TLS server.

## Secure memory boundaries

Browser keys are held only in memory, not localStorage or IndexedDB. Lock, logout, failed unlock, and unmount trigger best-effort `sodium.memzero`; temporary key-encryption keys and plaintext byte arrays are wiped after use. The browser locks after five minutes without activity.

A browser cannot guarantee immediate garbage collection, prevent OS swapping, erase every JavaScript string copy, clear clipboard contents, or control developer tools and compromised extensions. Decrypted item objects are released on lock but cannot be reliably erased. These are platform limits, not claims of perfect browser memory hygiene.

The native CLI uses `sodium_malloc`, requires `mlock` for sensitive buffers, and wipes/unlocks them in success, error, and signal cleanup paths. It does not silently fall back to unlocked memory. Terminal input/output, JSON parsing, V8 copies, core dumps, swap outside locked pages, and terminal scrollback remain outside complete control. Production deployments should disable application crash dumps and protect host access.

## Threat model and mitigations

| Threat | Mitigation | Residual risk |
|---|---|---|
| Database or backup theft | Data key and private keys remain encrypted; no password verifier or share token plaintext | Offline guessing against the encrypted bundle; email and timing metadata remain visible |
| Network interception | TLS 1.3, HSTS, secure cookies, authenticated encryption | Compromised endpoint or CA; first visit before HSTS without preload |
| Server learns vault plaintext | Encryption/decryption only in client; network and database tests | A malicious served client could steal secrets; deploy immutable, audited assets |
| Credential replay | Random signed challenges, expiry, atomic consumption, hashed sessions | Stolen unlocked device or active session remains powerful |
| Cross-user item access | Session authentication and owner predicates on every mutation | Server availability and ciphertext rollback are not prevented |
| Ciphertext substitution | Poly1305 authentication and item/share AAD | Server can delete or roll back ciphertext; no signed version history |
| Share token theft | 256-bit token, fragment-only URL capability, HMAC at rest | Browser history, chat logs, recipient copying; revocation cannot recall copies |
| Share guessing or replay after expiry | Expiry, revocation, constant-time HMAC comparison | Active link remains a bearer capability by design |
| CSRF/XSS | SameSite cookies, Origin/Fetch checks, React escaping, CSP, HTTP(S)-only item links | Client supply-chain or browser extension compromise |
| Brute force | Argon2id memory/time cost and login throttling | Weak master passwords and per-account throttling denial of service |
| Recovery file theft | Random 256-bit key, ciphertext-only storage, explicit download custody, local rotation | Anyone holding the file and encrypted bundle can unlock; rotation cannot erase copied files |
| HIBP credential disclosure | Local SHA-1 and five-character k-anonymity prefix | Prefix/IP/timing metadata; incomplete breach corpus |
| Injection and path traversal | Parameterized SQLite, no shell execution, canonical static paths, strict routing | Native dependency and runtime vulnerabilities |
| Key persistence in memory | Browser best effort; CLI locked buffers and cleanup | JavaScript copies, OS crash artifacts, compromised host |

## Audit-simulation findings and resolutions

The implementation review specifically checked authentication, authorization, cryptographic formats, share lifecycle, plaintext boundaries, browser rendering, HIBP, native memory handling, and deployment.

Resolved during review:

1. Base64url validation and client/server payload contracts were aligned.
2. Client-generated share IDs became part of share creation so AAD binds the ciphertext to the same server record.
3. Browser WebAssembly was enabled with the narrow CSP `'wasm-unsafe-eval'` directive; general unsafe evaluation remains disabled.
4. Share authorization tokens moved from request paths into the URL fragment to avoid proxy access-log disclosure.
5. Item website links were restricted to HTTP(S), preventing script-scheme navigation in shared content.
6. CORP and Permissions Policy headers were added.
7. Registration/IP throttles, per-user item count/byte quotas, authenticated HIBP throttling, and bounded upstream concurrency were added to limit resource exhaustion.
8. Password changes now revoke other server sessions. This does not revoke already-unlocked browser copies or rotate the vault key; suspected key compromise requires re-encrypting all items with a new vault key, and exported plaintext cannot be recalled.
9. The CLI requires HTTPS for non-loopback servers and frees guarded allocations after wiping and unlocking them.
10. Expired-data cleanup was moved from every request to a bounded once-per-minute schedule.

The simulated review found no Critical or High-severity issue. Accepted limitations include account-existence disclosure through challenge/registration behavior, per-account throttling denial of service, offline password guessing, malicious client delivery, metadata visibility, ciphertext rollback, recipient copies, platform memory limits, recovery-file theft, and lack of MFA. No real external auditor has certified these conclusions.

## Verification evidence

- Strict TypeScript checks cover server, browser, and CLI.
- Unit/integration tests exercise real libsodium round trips, wrong passwords, tampering and wrong AAD, re-wrapping, HIBP parsing/prefix privacy, locked native buffers, challenge replay, session revocation, item ownership, share HMAC/expiry/revocation, validation, CSRF, and production configuration.
- Real Chromium tests run against the production build and real SQLite server. They cover registration, password/API-key/document items, reveal and download, controlled HIBP lookup, public share decryption, revocation, master-password change, old-password rejection, re-unlock, five-minute idle locking, and empty browser storage.
- The browser test captures API requests and reads SQLite directly to assert that master passwords, item plaintext, titles, document contents, and share decryption keys are absent. It also checks that the share authorization token is absent from the request path.
- The native CLI is exercised through a pseudo-TTY against the browser-created account and decrypts password, API-key, and document titles through the real challenge/session API.
- Desktop and 390-pixel mobile screenshots are reviewed for usable layout and no horizontal overflow.
- `npm audit`, the production image build, Docker Compose interpolation, and Caddy configuration validation are run locally. No external service or production system is used for security testing.

Run the current evidence with `npm run check` and `npm audit`; the commands and their current results are the authoritative verification record, not this document alone.
