import React, { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import {
  checkPassword,
  createRegistration,
  decryptItem,
  decryptShare,
  encryptItem,
  encryptShare,
  rewrap,
  signChallenge,
  unlock,
  wipeKeys,
  type HibpResult,
  type UnlockedKeys,
} from '../shared/crypto';
import { ENVELOPE_VERSION, type EncryptedItem, type KeyBundle, type Share, type VaultItem, type VaultItemKind } from '../shared/api';
import * as api from './api';

const MAX_DOCUMENT_BASE64 = 2 * 1024 * 1024;

type Session = {
  email: string;
  bundle: KeyBundle;
  keys: UnlockedKeys;
  items: VaultItem[];
  shares: Share[];
};

type Notice = { tone: 'success' | 'error' | 'info'; text: string } | null;

function Keyhole({ small = false }: { small?: boolean }) {
  return (
    <svg className={small ? 'keyhole keyhole--small' : 'keyhole'} viewBox="0 0 80 104" aria-hidden="true">
      <path d="M40 4C20 4 5 19 5 39c0 15 9 28 22 34L17 98h46L53 73c13-6 22-19 22-34C75 19 60 4 40 4Z" />
      <path d="M40 19v54M25 39h30M28 86h24" />
    </svg>
  );
}

function Wordmark() {
  return <span className="wordmark"><Keyhole small /><span>Lockit</span></span>;
}

function Button({ children, variant = 'primary', ...props }: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'secondary' | 'quiet' | 'danger' }) {
  return <button className={`button button--${variant}`} {...props}>{children}</button>;
}

function Field({ label, hint, children }: { label: string; hint?: string | undefined; children: ReactNode }) {
  return <label className="field"><span className="field__label">{label}</span>{children}{hint && <span className="field__hint">{hint}</span>}</label>;
}

async function copyText(value: string): Promise<void> {
  await navigator.clipboard.writeText(value);
}

function safeHttpUrl(value: string): string | undefined {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : undefined;
  } catch {
    return undefined;
  }
}

function downloadDocument(item: VaultItem): void {
  if (!item.documentData) return;
  const binary = atob(item.documentData);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  const url = URL.createObjectURL(new Blob([bytes], { type: item.documentType || 'application/octet-stream' }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = item.documentName || item.title;
  anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function AuthScreen({
  initialMode,
  initialEmail,
  onRegistered,
  onUnlocked,
}: {
  initialMode: 'register' | 'unlock';
  initialEmail: string;
  onRegistered: (email: string, bundle: KeyBundle, keys: UnlockedKeys) => Promise<void>;
  onUnlocked: (email: string, bundle: KeyBundle, keys: UnlockedKeys) => Promise<void>;
}) {
  const [mode, setMode] = useState(initialMode);
  const [email, setEmail] = useState(initialEmail);
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (initialEmail) setEmail(initialEmail);
  }, [initialEmail]);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError('');
    if (mode === 'register' && password !== confirmation) {
      setError('The master password confirmation does not match.');
      return;
    }
    if (mode === 'register' && password.length < 12) {
      setError('Use at least 12 characters for your master password.');
      return;
    }
    setBusy(true);
    try {
      if (mode === 'register') {
        const registration = await createRegistration(password);
        try {
          await api.register({ email, ...registration.bundle });
          await onRegistered(email, registration.bundle, registration.keys);
        } catch (error) {
          wipeKeys(registration.keys);
          throw error;
        }
      } else {
        const response = await api.challenge(email);
        const keys = await unlock(password, response.bundle);
        try {
          const signature = await signChallenge(response.challenge, keys.identitySecretKey);
          await api.verify(response.challengeId, signature);
          await onUnlocked(email, response.bundle, keys);
        } catch (error) {
          wipeKeys(keys);
          throw error;
        }
      }
      setPassword('');
      setConfirmation('');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The request could not be completed.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="auth-shell">
      <header className="auth-header"><Wordmark /><span className="auth-header__note">Private by construction</span></header>
      <section className="auth-intro">
        <div className="auth-intro__copy">
          <p className="kicker">A vault with nothing to give away</p>
          <h1>Your secrets.<br />Never ours.</h1>
          <p className="lede">Passwords, keys, and documents are sealed on this device before Lockit stores them. The server keeps ciphertext, not your master password.</p>
        </div>
        <div className="key-chamber" aria-hidden="true">
          <span className="key-chamber__index">LOCAL / 01</span>
          <Keyhole />
          <span className="key-chamber__caption">Unlocked only by you</span>
        </div>
      </section>
      <section className="auth-panel" aria-labelledby="auth-title">
        <div className="auth-tabs" role="tablist" aria-label="Account access">
          <button role="tab" aria-selected={mode === 'unlock'} onClick={() => { setMode('unlock'); setError(''); }}>Unlock vault</button>
          <button role="tab" aria-selected={mode === 'register'} onClick={() => { setMode('register'); setError(''); }}>Create vault</button>
        </div>
        <form onSubmit={submit} className="auth-form">
          <div>
            <h2 id="auth-title">{mode === 'register' ? 'Make a private space' : 'Welcome back'}</h2>
            <p>{mode === 'register' ? 'One master password protects everything inside.' : 'Your keys return only on this device.'}</p>
          </div>
          <Field label="Email address">
            <input type="email" autoComplete="email" required value={email} onChange={(event) => setEmail(event.target.value)} />
          </Field>
          <Field label="Master password" hint={mode === 'register' ? 'At least 12 characters. A long phrase works well.' : undefined}>
            <input type="password" autoComplete={mode === 'register' ? 'new-password' : 'current-password'} required minLength={mode === 'register' ? 12 : undefined} value={password} onChange={(event) => setPassword(event.target.value)} />
          </Field>
          {mode === 'register' && <>
            <Field label="Confirm master password">
              <input type="password" autoComplete="new-password" required value={confirmation} onChange={(event) => setConfirmation(event.target.value)} />
            </Field>
            <div className="warning"><strong>There is no password reset.</strong><span>Lockit cannot recover your master password or decrypt your data. Store it somewhere safe.</span></div>
          </>}
          {error && <p className="form-error" role="alert">{error}</p>}
          <Button type="submit" disabled={busy}>{busy ? (mode === 'register' ? 'Building your keys…' : 'Unlocking locally…') : (mode === 'register' ? 'Create encrypted vault' : 'Unlock vault')}</Button>
          {mode === 'register' && <p className="fine-print">Setup uses Argon2id with 64 MiB of memory and may take a moment. This deliberate cost makes password guessing harder.</p>}
        </form>
      </section>
      <footer className="auth-footer"><span>End-to-end encrypted</span><span>Zero-knowledge storage</span><span>Local key custody</span></footer>
    </main>
  );
}

function ItemEditor({ item, onSave, onCancel, busy }: {
  item: VaultItem | null;
  onSave: (item: VaultItem) => Promise<void>;
  onCancel: () => void;
  busy: boolean;
}) {
  const [kind, setKind] = useState<VaultItemKind>(item?.kind ?? 'password');
  const [title, setTitle] = useState(item?.title ?? '');
  const [username, setUsername] = useState(item?.username ?? '');
  const [secret, setSecret] = useState(item?.secret ?? '');
  const [url, setUrl] = useState(item?.url ?? '');
  const [notes, setNotes] = useState(item?.notes ?? '');
  const [documentName, setDocumentName] = useState(item?.documentName ?? '');
  const [documentType, setDocumentType] = useState(item?.documentType ?? '');
  const [documentData, setDocumentData] = useState(item?.documentData ?? '');
  const [error, setError] = useState('');

  const readDocument = async (file: File | undefined) => {
    if (!file) return;
    setError('');
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      let binary = '';
      for (let offset = 0; offset < bytes.length; offset += 32768) {
        binary += String.fromCharCode(...bytes.subarray(offset, offset + 32768));
      }
      const encoded = btoa(binary);
      if (encoded.length > MAX_DOCUMENT_BASE64) {
        throw new Error('This file is too large. Its base64 contents must be at most 2 MiB.');
      }
      setDocumentData(encoded);
      setDocumentName(file.name);
      setDocumentType(file.type || 'application/octet-stream');
      if (!title) setTitle(file.name);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The document could not be read.');
    }
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError('');
    if (kind === 'document' && !documentData) {
      setError('Choose a document to encrypt.');
      return;
    }
    const next: VaultItem = {
      id: item?.id ?? crypto.randomUUID(),
      kind,
      title: title.trim(),
      updatedAt: new Date().toISOString(),
      ...(username ? { username } : {}),
      ...(secret ? { secret } : {}),
      ...(url ? { url } : {}),
      ...(notes ? { notes } : {}),
      ...(kind === 'document' && documentName ? { documentName } : {}),
      ...(kind === 'document' && documentType ? { documentType } : {}),
      ...(kind === 'document' && documentData ? { documentData } : {}),
    };
    try {
      await onSave(next);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The item could not be saved.');
    }
  };

  return (
    <section className="editor" aria-labelledby="editor-title">
      <div className="section-heading"><div><p className="kicker">Local encryption</p><h2 id="editor-title">{item ? 'Edit item' : 'Add to your vault'}</h2></div><button className="icon-button" onClick={onCancel} aria-label="Close editor">×</button></div>
      <form onSubmit={submit} className="editor-form">
        <Field label="Item type">
          <select value={kind} onChange={(event) => setKind(event.target.value as VaultItemKind)} disabled={Boolean(item)}>
            <option value="password">Password</option><option value="api-key">API key</option><option value="document">Document</option>
          </select>
        </Field>
        <Field label="Name"><input required maxLength={200} value={title} onChange={(event) => setTitle(event.target.value)} placeholder={kind === 'document' ? 'Passport scan' : 'Work account'} /></Field>
        {kind !== 'document' && <>
          <Field label={kind === 'api-key' ? 'Service or owner' : 'Username'}><input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="off" /></Field>
          <Field label={kind === 'api-key' ? 'API key' : 'Password'}><input type="password" value={secret} onChange={(event) => setSecret(event.target.value)} autoComplete="new-password" /></Field>
          <Field label="Website"><input type="url" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://" /></Field>
        </>}
        {kind === 'document' && <Field label="Document" hint={documentName ? `${documentName} · encrypted on save` : 'Maximum 2 MiB after base64 encoding'}><input type="file" onChange={(event) => void readDocument(event.target.files?.[0])} /></Field>}
        <Field label="Notes"><textarea rows={4} value={notes} onChange={(event) => setNotes(event.target.value)} /></Field>
        {error && <p className="form-error" role="alert">{error}</p>}
        <div className="button-row"><Button type="submit" disabled={busy}>{busy ? 'Encrypting…' : 'Encrypt and save'}</Button><Button type="button" variant="quiet" onClick={onCancel}>Cancel</Button></div>
      </form>
    </section>
  );
}

function ItemDetail({ item, onEdit, onDelete, onShared, notify }: {
  item: VaultItem;
  onEdit: () => void;
  onDelete: () => Promise<void>;
  onShared: (share: Share, token: string, key: string) => Promise<void>;
  notify: (text: string) => void;
}) {
  const [revealed, setRevealed] = useState(false);
  const [sharing, setSharing] = useState(false);
  const [ttl, setTtl] = useState(86400);
  const [busy, setBusy] = useState(false);
  const [hibp, setHibp] = useState<HibpResult | null>(null);
  const [checking, setChecking] = useState(false);

  useEffect(() => { setRevealed(false); setSharing(false); setHibp(null); }, [item.id]);

  const copy = async (value: string, label: string) => {
    try { await copyText(value); notify(`${label} copied.`); } catch { notify('Copy failed. Select and copy the value manually.'); }
  };

  const share = async () => {
    setBusy(true);
    try {
      const id = crypto.randomUUID();
      const encrypted = await encryptShare(item, id);
      const response = await api.createShare({ id, itemId: item.id, ttlSeconds: ttl, ciphertext: encrypted.ciphertext, nonce: encrypted.nonce });
      await onShared(response.share, response.token, encrypted.key);
      setSharing(false);
    } catch (cause) {
      notify(cause instanceof Error ? cause.message : 'The share could not be created.');
    } finally { setBusy(false); }
  };

  const check = async () => {
    if (!item.secret) return;
    setChecking(true);
    setHibp(await checkPassword(item.secret));
    setChecking(false);
  };

  return (
    <section className="detail" aria-labelledby="detail-title">
      <div className="detail__top"><span className="item-kind">{api.itemKindLabel(item.kind)}</span><div className="button-row"><Button variant="quiet" onClick={onEdit}>Edit</Button><Button variant="quiet" onClick={() => void onDelete()}>Delete</Button></div></div>
      <h2 id="detail-title">{item.title}</h2>
      <p className="detail__date">Updated {new Date(item.updatedAt).toLocaleString()}</p>
      <dl className="secret-list">
        {item.username && <div><dt>{item.kind === 'api-key' ? 'Service or owner' : 'Username'}</dt><dd><span>{item.username}</span><button onClick={() => void copy(item.username ?? '', 'Username')}>Copy</button></dd></div>}
        {item.secret && <div><dt>{item.kind === 'api-key' ? 'API key' : 'Password'}</dt><dd><span className="secret-value">{revealed ? item.secret : '••••••••••••••••'}</span><span className="secret-actions"><button onClick={() => setRevealed(!revealed)}>{revealed ? 'Hide' : 'Reveal'}</button><button onClick={() => void copy(item.secret ?? '', 'Secret')}>Copy</button></span></dd></div>}
        {item.url && <div><dt>Website</dt><dd><a href={safeHttpUrl(item.url)} target="_blank" rel="noreferrer">{item.url}</a></dd></div>}
        {item.documentData && <div><dt>File</dt><dd><span>{item.documentName || item.title}</span><button onClick={() => downloadDocument(item)}>Download</button></dd></div>}
        {item.notes && <div><dt>Notes</dt><dd className="notes">{item.notes}</dd></div>}
      </dl>
      {item.secret && <div className="health-check"><div><h3>Password exposure check</h3><p>Only the first five characters of a local SHA-1 hash leave this device.</p></div><Button variant="secondary" disabled={checking} onClick={() => void check()}>{checking ? 'Checking…' : 'Check password'}</Button>{hibp && <p className={`hibp hibp--${hibp.status}`} role="status">{hibp.status === 'compromised' ? `Found in known breaches ${hibp.count.toLocaleString()} times. Change this password.` : hibp.status === 'not-found' ? 'Not found in the available breach data.' : 'Breach data is unavailable. Try again later.'}</p>}</div>}
      <div className="share-maker">
        {!sharing ? <Button variant="secondary" onClick={() => setSharing(true)}>Create a secure share</Button> : <div className="share-maker__form"><div><h3>Share an encrypted snapshot</h3><p>Changes to this item will not update the share.</p></div><Field label="Expires after"><select value={ttl} onChange={(event) => setTtl(Number(event.target.value))}><option value={3600}>1 hour</option><option value={86400}>24 hours</option><option value={604800}>7 days</option></select></Field><p className="fine-print">The decryption key goes in the link fragment, which is never sent to the server.</p><div className="button-row"><Button disabled={busy} onClick={() => void share()}>{busy ? 'Encrypting…' : 'Create share link'}</Button><Button variant="quiet" onClick={() => setSharing(false)}>Cancel</Button></div></div>}
      </div>
    </section>
  );
}

function SharesView({ shares, items, onRevoke }: { shares: Share[]; items: VaultItem[]; onRevoke: (id: string) => Promise<void> }) {
  return <section className="workspace-section"><div className="section-heading"><div><p className="kicker">Encrypted snapshots</p><h2>Shared links</h2></div><span>{shares.length} total</span></div>{shares.length === 0 ? <div className="empty"><Keyhole small /><h3>No shared items</h3><p>Open a vault item to create a time-limited encrypted snapshot.</p></div> : <div className="shares-table"><div className="shares-table__head"><span>Item</span><span>Status</span><span>Expires</span><span>Action</span></div>{shares.map((share) => { const item = items.find((candidate) => candidate.id === share.itemId); const expired = new Date(share.expiresAt).getTime() <= Date.now(); const status = share.revokedAt ? 'Revoked' : expired ? 'Expired' : 'Active'; return <div className="shares-table__row" key={share.id}><span><strong>{item?.title ?? 'Deleted item'}</strong><small>{new Date(share.createdAt).toLocaleDateString()}</small></span><span className={`status status--${status.toLowerCase()}`}>{status}</span><span>{new Date(share.expiresAt).toLocaleString()}</span><span>{!share.revokedAt && !expired && <button className="text-button text-button--danger" onClick={() => void onRevoke(share.id)}>Revoke</button>}</span></div>; })}</div>}</section>;
}

function SecurityView({ onChangePassword, busy }: { onChangePassword: (current: string, next: string) => Promise<void>; busy: boolean }) {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [error, setError] = useState('');
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError('');
    if (next.length < 12) return setError('Use at least 12 characters for the new master password.');
    if (next !== confirmation) return setError('The new password confirmation does not match.');
    try {
      await onChangePassword(current, next);
      setCurrent(''); setNext(''); setConfirmation('');
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'The password could not be changed.'); }
  };
  return <section className="workspace-section security-layout"><div><p className="kicker">Key custody</p><h2>Security without a back door</h2><p className="lede">Your master password derives a key-encryption key locally with Argon2id. That key unwraps your identity and vault keys. None of them are stored in browser storage.</p><div className="security-facts"><div><strong>Argon2id</strong><span>3 operations · 64 MiB memory</span></div><div><strong>XChaCha20-Poly1305</strong><span>Authenticated item encryption</span></div><div><strong>Ed25519</strong><span>Passwordless login challenges</span></div></div></div><form className="password-change" onSubmit={submit}><h3>Change master password</h3><p>This re-encrypts your private keys. Your account identifier and encrypted vault contents stay the same.</p><Field label="Current master password"><input type="password" autoComplete="current-password" required value={current} onChange={(event) => setCurrent(event.target.value)} /></Field><Field label="New master password"><input type="password" autoComplete="new-password" minLength={12} required value={next} onChange={(event) => setNext(event.target.value)} /></Field><Field label="Confirm new master password"><input type="password" autoComplete="new-password" required value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></Field><div className="warning"><strong>Keep the new password safe.</strong><span>There is no recovery route if you forget it.</span></div>{error && <p className="form-error" role="alert">{error}</p>}<Button disabled={busy} type="submit">{busy ? 'Rewrapping keys…' : 'Change master password'}</Button></form></section>;
}

function Vault({ session, setSession, onLock, onLogout }: {
  session: Session;
  setSession: (updater: (session: Session) => Session) => void;
  onLock: () => void;
  onLogout: () => Promise<void>;
}) {
  const [tab, setTab] = useState<'vault' | 'shares' | 'security'>('vault');
  const [filter, setFilter] = useState<'all' | VaultItemKind>('all');
  const [query, setQuery] = useState('');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [editing, setEditing] = useState<VaultItem | null | 'new'>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<Notice>(null);
  const [shareLink, setShareLink] = useState('');
  const selected = session.items.find((item) => item.id === selectedId) ?? null;
  const filtered = session.items.filter((item) => (filter === 'all' || item.kind === filter) && `${item.title} ${item.username ?? ''} ${item.url ?? ''}`.toLowerCase().includes(query.toLowerCase()));

  const notify = (text: string) => setNotice({ tone: 'info', text });
  const save = async (item: VaultItem) => {
    setBusy(true);
    try {
      const encrypted = await encryptItem(item, session.bundle.identityPublicKey, session.keys.vaultKey);
      const envelope = { id: item.id, version: ENVELOPE_VERSION, ...encrypted };
      const response = session.items.some((candidate) => candidate.id === item.id)
        ? await api.updateItem(envelope)
        : await api.createItem(envelope);
      const saved = { ...item, updatedAt: response.item.updatedAt };
      setSession((current) => ({ ...current, items: current.items.some((candidate) => candidate.id === item.id) ? current.items.map((candidate) => candidate.id === item.id ? saved : candidate) : [...current.items, saved] }));
      setSelectedId(item.id); setEditing(null); setNotice({ tone: 'success', text: 'Item encrypted and saved.' });
    } finally { setBusy(false); }
  };
  const remove = async (item: VaultItem) => {
    if (!window.confirm(`Delete “${item.title}”? This cannot be undone.`)) return;
    try {
      await api.deleteItem(item.id);
      setSession((current) => ({ ...current, items: current.items.filter((candidate) => candidate.id !== item.id), shares: current.shares.filter((share) => share.itemId !== item.id) }));
      setSelectedId(null); setNotice({ tone: 'success', text: 'Item deleted.' });
    } catch (cause) { setNotice({ tone: 'error', text: cause instanceof Error ? cause.message : 'Delete failed.' }); }
  };
  const shared = async (share: Share, token: string, key: string) => {
    setSession((current) => ({ ...current, shares: [share, ...current.shares] }));
    const link = `${window.location.origin}/share/${share.id}#${token}.${key}`;
    setShareLink(link);
    try { await copyText(link); notify('Share link created and copied.'); } catch { notify('Share link created. Copy it below.'); }
  };
  const revoke = async (id: string) => {
    try {
      await api.revokeShare(id);
      const response = await api.listShares();
      setSession((current) => ({ ...current, shares: response.shares }));
      notify('Share revoked. Existing links no longer work.');
    } catch (cause) { setNotice({ tone: 'error', text: cause instanceof Error ? cause.message : 'Revoke failed.' }); }
  };
  const changePassword = async (current: string, next: string) => {
    setBusy(true);
    try {
      const bundle = await rewrap(current, next, session.bundle);
      await api.updateBundle(bundle);
      setSession((value) => ({ ...value, bundle }));
      setNotice({ tone: 'success', text: 'Master password changed. Your private keys were re-encrypted.' });
    } finally { setBusy(false); }
  };

  return <div className="vault-shell"><header className="vault-header"><Wordmark /><nav aria-label="Main navigation"><button aria-current={tab === 'vault' ? 'page' : undefined} onClick={() => setTab('vault')}>Vault</button><button aria-current={tab === 'shares' ? 'page' : undefined} onClick={() => setTab('shares')}>Shares</button><button aria-current={tab === 'security' ? 'page' : undefined} onClick={() => setTab('security')}>Security</button></nav><div className="account-menu"><span title={session.email}>{session.email}</span><button onClick={onLock}>Lock</button><button onClick={() => void onLogout()}>Log out</button></div></header><div className="vault-layout"><aside className="vault-aside"><p>Your private archive</p><strong>{session.items.length}</strong><span>encrypted {session.items.length === 1 ? 'item' : 'items'}</span><div className="aside-rule" /><p className="aside-note">Unlocked in this tab only. Lockit automatically locks after 5 minutes without activity.</p><Button variant="secondary" onClick={onLock}>Lock now</Button></aside><main className="vault-main">{notice && <div className={`notice notice--${notice.tone}`} role="status"><span>{notice.text}</span><button onClick={() => setNotice(null)} aria-label="Dismiss notification">×</button></div>}{shareLink && <div className="share-link"><div><strong>Share link ready</strong><p>Anyone with this complete link can read the snapshot until it expires or is revoked.</p></div><input aria-label="Share link" readOnly value={shareLink} onFocus={(event) => event.target.select()} /><Button variant="secondary" onClick={() => { void copyText(shareLink).then(() => notify('Share link copied.')).catch(() => notify('Copy failed. Select the link manually.')); }}>Copy link</Button><button className="icon-button" onClick={() => setShareLink('')} aria-label="Dismiss share link">×</button></div>}{tab === 'vault' && <div className="vault-workspace"><section className="items-pane"><div className="section-heading"><div><p className="kicker">Decrypted locally</p><h1>Your vault</h1></div><Button onClick={() => { setEditing('new'); setSelectedId(null); }}>Add item</Button></div><div className="vault-tools"><label className="search"><span className="sr-only">Search vault</span><input type="search" placeholder="Search names, usernames, sites" value={query} onChange={(event) => setQuery(event.target.value)} /></label><div className="filters" aria-label="Filter items">{(['all', 'password', 'api-key', 'document'] as const).map((value) => <button key={value} aria-pressed={filter === value} onClick={() => setFilter(value)}>{value === 'all' ? 'All' : api.itemKindLabel(value)}</button>)}</div></div>{filtered.length === 0 ? <div className="empty"><Keyhole small /><h2>{session.items.length === 0 ? 'The vault is ready' : 'No matching items'}</h2><p>{session.items.length === 0 ? 'Add a password, API key, or document. It will be encrypted before it leaves this tab.' : 'Try another search or filter.'}</p>{session.items.length === 0 && <Button onClick={() => setEditing('new')}>Add your first item</Button>}</div> : <div className="item-list">{filtered.map((item) => <button className="item-row" key={item.id} aria-pressed={selectedId === item.id} onClick={() => { setSelectedId(item.id); setEditing(null); }}><span className={`item-glyph item-glyph--${item.kind}`} aria-hidden="true">{item.kind === 'document' ? 'D' : item.kind === 'api-key' ? 'K' : 'P'}</span><span><strong>{item.title}</strong><small>{item.username || item.documentName || item.url || api.itemKindLabel(item.kind)}</small></span><span className="item-row__kind">{api.itemKindLabel(item.kind)}</span></button>)}</div>}</section><section className="inspector">{editing ? <ItemEditor key={editing === 'new' ? 'new' : editing.id} item={editing === 'new' ? null : editing} onSave={save} onCancel={() => setEditing(null)} busy={busy} /> : selected ? <ItemDetail key={selected.id} item={selected} onEdit={() => setEditing(selected)} onDelete={() => remove(selected)} onShared={shared} notify={notify} /> : <div className="inspector-empty"><Keyhole /><h2>Select a secret</h2><p>Item details appear here after local decryption. Your master password never enters this workspace.</p></div>}</section></div>}{tab === 'shares' && <SharesView shares={session.shares} items={session.items} onRevoke={revoke} />}{tab === 'security' && <SecurityView onChangePassword={changePassword} busy={busy} />}</main></div></div>;
}

function PublicShare() {
  const [item, setItem] = useState<VaultItem | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [revealed, setRevealed] = useState(false);
  useEffect(() => {
    const run = async () => {
      try {
        const match = /^\/share\/([0-9a-f-]{36})$/i.exec(window.location.pathname);
        const [token, key] = window.location.hash.slice(1).split('.', 2);
        if (!match?.[1] || !token || !key) throw new Error('This share link is incomplete. Ask the sender for the full link, including the text after #.');
        const id = match[1];
        const encrypted = await api.openShare(id, token);
        setItem(await decryptShare(encrypted, id, key));
      } catch (cause) { setError(cause instanceof Error ? cause.message : 'This share could not be opened.'); }
      finally { setLoading(false); }
    };
    void run();
  }, []);
  return <main className="public-shell"><header><Wordmark /><span>Secure share</span></header><section className="public-frame"><div className="public-motif"><Keyhole /><p>Decrypted on this device</p></div><div className="public-content">{loading ? <><p className="kicker">Opening snapshot</p><h1>Decrypting securely…</h1></> : error ? <><p className="kicker">Link unavailable</p><h1>This share cannot be opened</h1><p className="lede">{error}</p><p>The link may have expired, been revoked, or been altered. Ask the sender to create a new one.</p></> : item && <><p className="kicker">{api.itemKindLabel(item.kind)} snapshot</p><h1>{item.title}</h1><p className="public-notice">The server supplied encrypted data only. The key in your link unlocked it here.</p><dl className="secret-list">{item.username && <div><dt>Username</dt><dd>{item.username}</dd></div>}{item.secret && <div><dt>{item.kind === 'api-key' ? 'API key' : 'Password'}</dt><dd><span className="secret-value">{revealed ? item.secret : '••••••••••••••••'}</span><button onClick={() => setRevealed(!revealed)}>{revealed ? 'Hide' : 'Reveal'}</button></dd></div>}{item.url && <div><dt>Website</dt><dd><a href={safeHttpUrl(item.url)}>{item.url}</a></dd></div>}{item.documentData && <div><dt>Document</dt><dd><span>{item.documentName}</span><button onClick={() => downloadDocument(item)}>Download</button></dd></div>}{item.notes && <div><dt>Notes</dt><dd className="notes">{item.notes}</dd></div>}</dl><p className="fine-print">Shared {new Date(item.updatedAt).toLocaleString()}. This is a snapshot, not live vault access.</p></>}</div></section><footer>Lockit cannot read this snapshot or recover a lost link.</footer></main>;
}

async function loadSession(email: string, bundle: KeyBundle, keys: UnlockedKeys): Promise<Session> {
  try {
    const [itemResponse, shareResponse] = await Promise.all([api.listItems(), api.listShares()]);
    const decrypted = await Promise.all(itemResponse.items.map(async (item: EncryptedItem) => {
      try { return await decryptItem(item, bundle.identityPublicKey, keys.vaultKey); }
      catch { return null; }
    }));
    const items = decrypted.filter((item): item is VaultItem => item !== null);
    if (items.length !== itemResponse.items.length) throw new Error('Some vault items failed authentication. Lockit did not display damaged or mismatched data.');
    return { email, bundle, keys, items, shares: shareResponse.shares };
  } catch (error) {
    wipeKeys(keys);
    throw error;
  }
}

export default function App() {
  const [session, setSessionState] = useState<Session | null>(null);
  const [initialEmail, setInitialEmail] = useState('');
  const [initialMode, setInitialMode] = useState<'register' | 'unlock'>('unlock');
  const [booting, setBooting] = useState(!window.location.pathname.startsWith('/share/'));
  const [bootError, setBootError] = useState('');
  const sessionRef = useRef<Session | null>(null);
  sessionRef.current = session;
  const setSession = useCallback((updater: (current: Session) => Session) => {
    setSessionState((current) => current ? updater(current) : current);
  }, []);
  const lock = useCallback(() => {
    wipeKeys(sessionRef.current?.keys);
    sessionRef.current = null;
    setSessionState(null);
  }, []);
  const start = useCallback(async (email: string, bundle: KeyBundle, keys: UnlockedKeys) => {
    const loaded = await loadSession(email, bundle, keys);
    sessionRef.current = loaded;
    setSessionState(loaded);
    setInitialEmail(email);
    setBootError('');
  }, []);

  useEffect(() => {
    if (window.location.pathname.startsWith('/share/')) return;
    const boot = async () => {
      try {
        const account = await api.me();
        const response = await api.getBundle();
        setInitialEmail(account.user.email);
        setInitialMode('unlock');
      } catch (cause) {
        if (!(cause instanceof api.ApiError && cause.status === 401)) setBootError(cause instanceof Error ? cause.message : 'Lockit could not check this session.');
      } finally { setBooting(false); }
    };
    void boot();
    return () => wipeKeys(sessionRef.current?.keys);
  }, []);

  useEffect(() => {
    if (!session) return;
    let timer = window.setTimeout(lock, 5 * 60 * 1000);
    const reset = () => { window.clearTimeout(timer); timer = window.setTimeout(lock, 5 * 60 * 1000); };
    const events: (keyof WindowEventMap)[] = ['pointerdown', 'pointermove', 'keydown', 'scroll', 'touchstart'];
    events.forEach((event) => window.addEventListener(event, reset, { passive: true }));
    return () => { window.clearTimeout(timer); events.forEach((event) => window.removeEventListener(event, reset)); };
  }, [session, lock]);

  if (window.location.pathname.startsWith('/share/')) return <PublicShare />;
  if (booting) return <main className="loading-screen"><Wordmark /><p>Opening the secure threshold…</p></main>;
  if (!session) return <>{bootError && <div className="boot-error" role="alert">{bootError}<button onClick={() => setBootError('')} aria-label="Dismiss">×</button></div>}<AuthScreen key={`${initialMode}-${initialEmail}`} initialMode={initialMode} initialEmail={initialEmail} onRegistered={start} onUnlocked={start} /></>;
  return <Vault session={session} setSession={setSession} onLock={lock} onLogout={async () => { try { await api.logout(); } finally { lock(); setInitialMode('unlock'); } }} />;
}
