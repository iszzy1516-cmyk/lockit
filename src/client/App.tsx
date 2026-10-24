import React, { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import {
  CheckCircle,
  Clock,
  Copy,
  DownloadSimple,
  Eye,
  EyeSlash,
  FileText,
  HardDrive,
  Info,
  Key,
  Link,
  Lock,
  LockSimple,
  MagnifyingGlass,
  Password,
  PencilSimple,
  Plus,
  ShareNetwork,
  ShieldCheck,
  SignOut,
  Trash,
  Vault as VaultIcon,
  Warning,
  X,
} from '@phosphor-icons/react';
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

function Wordmark() {
  return <span className="wordmark"><span className="brand-mark"><Lock size={18} weight="fill" aria-hidden="true" /></span><span>Lockit</span></span>;
}

function KindIcon({ kind, size = 18 }: { kind: VaultItemKind; size?: number }) {
  if (kind === 'api-key') return <Key size={size} aria-hidden="true" />;
  if (kind === 'document') return <FileText size={size} aria-hidden="true" />;
  return <Password size={size} aria-hidden="true" />;
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
      <header className="auth-header"><Wordmark /><span className="local-badge"><ShieldCheck size={15} aria-hidden="true" />Local encryption</span></header>
      <section className="auth-panel" aria-labelledby="auth-title">
        <div className="auth-panel__heading">
          <h1 id="auth-title">{mode === 'register' ? 'Create your vault' : 'Welcome back'}</h1>
          <p>{mode === 'register' ? 'Set up encrypted storage for your credentials and files.' : 'Unlock your encrypted vault on this device.'}</p>
        </div>
        <div className="auth-tabs" role="tablist" aria-label="Account access">
          <button role="tab" aria-selected={mode === 'unlock'} onClick={() => { setMode('unlock'); setError(''); }}>Unlock vault</button>
          <button role="tab" aria-selected={mode === 'register'} onClick={() => { setMode('register'); setError(''); }}>Create vault</button>
        </div>
        <form onSubmit={submit} className="auth-form">
          <Field label="Email address">
            <input type="email" autoComplete="email" required value={email} onChange={(event) => setEmail(event.target.value)} />
          </Field>
          <Field label="Master password" hint={mode === 'register' ? 'Use at least 12 characters. A long phrase works well.' : undefined}>
            <input type="password" autoComplete={mode === 'register' ? 'new-password' : 'current-password'} required minLength={mode === 'register' ? 12 : undefined} value={password} onChange={(event) => setPassword(event.target.value)} />
          </Field>
          {mode === 'register' && <>
            <Field label="Confirm master password">
              <input type="password" autoComplete="new-password" required value={confirmation} onChange={(event) => setConfirmation(event.target.value)} />
            </Field>
            <div className="warning"><Warning size={18} aria-hidden="true" /><div><strong>No password recovery</strong><span>Lockit cannot recover your master password or decrypt your data. Store it somewhere safe.</span></div></div>
          </>}
          {error && <p className="form-error" role="alert">{error}</p>}
          <Button type="submit" disabled={busy}>{busy ? (mode === 'register' ? 'Building your keys…' : 'Unlocking locally…') : (mode === 'register' ? 'Create encrypted vault' : 'Unlock vault')}</Button>
          {mode === 'register' && <p className="fine-print">Argon2id setup uses 64 MiB of memory and may take a moment. This makes password guessing harder.</p>}
        </form>
        <p className="auth-panel__foot"><LockSimple size={14} aria-hidden="true" />Your master password never leaves this device.</p>
      </section>
      <footer className="auth-footer">Zero knowledge vault <span>Local key custody</span></footer>
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
      <div className="pane-heading"><div><span className="eyebrow">Local encryption</span><h2 id="editor-title">{item ? 'Edit item' : 'Add item'}</h2></div><button className="icon-button" onClick={onCancel} aria-label="Close editor"><X size={18} aria-hidden="true" /></button></div>
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
      <div className="detail__top"><span className="item-kind"><KindIcon kind={item.kind} size={16} />{api.itemKindLabel(item.kind)}</span><div className="button-row"><Button variant="quiet" onClick={onEdit}><PencilSimple size={15} aria-hidden="true" />Edit</Button><Button variant="quiet" onClick={() => void onDelete()}><Trash size={15} aria-hidden="true" />Delete</Button></div></div>
      <div className="detail__heading"><h2 id="detail-title">{item.title}</h2><p className="detail__date">Updated {new Date(item.updatedAt).toLocaleString()}</p></div>
      <dl className="secret-list">
        {item.username && <div><dt>{item.kind === 'api-key' ? 'Service or owner' : 'Username'}</dt><dd><span>{item.username}</span><button onClick={() => void copy(item.username ?? '', 'Username')}><Copy size={14} aria-hidden="true" />Copy</button></dd></div>}
        {item.secret && <div><dt>{item.kind === 'api-key' ? 'API key' : 'Password'}</dt><dd><span className="secret-value">{revealed ? item.secret : '••••••••••••••••'}</span><span className="secret-actions"><button onClick={() => setRevealed(!revealed)}>{revealed ? <EyeSlash size={14} aria-hidden="true" /> : <Eye size={14} aria-hidden="true" />}{revealed ? 'Hide' : 'Reveal'}</button><button onClick={() => void copy(item.secret ?? '', 'Secret')}><Copy size={14} aria-hidden="true" />Copy</button></span></dd></div>}
        {item.url && <div><dt>Website</dt><dd><a href={safeHttpUrl(item.url)} target="_blank" rel="noreferrer">{item.url}</a></dd></div>}
        {item.documentData && <div><dt>File</dt><dd><span>{item.documentName || item.title}</span><button onClick={() => downloadDocument(item)}><DownloadSimple size={14} aria-hidden="true" />Download</button></dd></div>}
        {item.notes && <div><dt>Notes</dt><dd className="notes">{item.notes}</dd></div>}
      </dl>
      {item.secret && <div className="health-check"><div className="subsection-heading"><div><h3>Password exposure</h3><p>Only five SHA-1 hash prefix characters leave this device.</p></div><ShieldCheck size={18} aria-hidden="true" /></div><Button variant="secondary" disabled={checking} onClick={() => void check()}>{checking ? 'Checking…' : 'Check password'}</Button>{hibp && <p className={`hibp hibp--${hibp.status}`} role="status">{hibp.status === 'compromised' ? `Found in known breaches ${hibp.count.toLocaleString()} times. Change this password.` : hibp.status === 'not-found' ? 'Not found in the available breach data.' : 'Breach data is unavailable. Try again later.'}</p>}</div>}
      <div className="share-maker">
        {!sharing ? <Button variant="secondary" onClick={() => setSharing(true)}><ShareNetwork size={15} aria-hidden="true" />Create a secure share</Button> : <div className="share-maker__form"><div><h3>Share an encrypted snapshot</h3><p>Changes to this item will not update the share.</p></div><Field label="Expires after"><select value={ttl} onChange={(event) => setTtl(Number(event.target.value))}><option value={3600}>1 hour</option><option value={86400}>24 hours</option><option value={604800}>7 days</option></select></Field><p className="fine-print">The decryption key stays in the link fragment and is never sent to the server.</p><div className="button-row"><Button disabled={busy} onClick={() => void share()}>{busy ? 'Encrypting…' : 'Create share link'}</Button><Button variant="quiet" onClick={() => setSharing(false)}>Cancel</Button></div></div>}
      </div>
    </section>
  );
}

function SharesView({ shares, items, onRevoke }: { shares: Share[]; items: VaultItem[]; onRevoke: (id: string) => Promise<void> }) {
  return <section className="workspace-section"><div className="page-heading"><div><h1>Shares</h1><p>Time limited snapshots of your encrypted items.</p></div><span className="count-badge">{shares.length}</span></div>{shares.length === 0 ? <div className="empty"><Link size={28} aria-hidden="true" /><h2>No shared items</h2><p>Open a vault item to create a time limited encrypted snapshot.</p></div> : <div className="shares-table"><div className="shares-table__head"><span>Item</span><span>Status</span><span>Expires</span><span>Action</span></div>{shares.map((share) => { const item = items.find((candidate) => candidate.id === share.itemId); const expired = new Date(share.expiresAt).getTime() <= Date.now(); const status = share.revokedAt ? 'Revoked' : expired ? 'Expired' : 'Active'; return <div className="shares-table__row" key={share.id}><span><strong>{item?.title ?? 'Deleted item'}</strong><small>Created {new Date(share.createdAt).toLocaleDateString()}</small></span><span className={`status status--${status.toLowerCase()}`}>{status}</span><span>{new Date(share.expiresAt).toLocaleString()}</span><span>{!share.revokedAt && !expired && <button className="text-button text-button--danger" onClick={() => void onRevoke(share.id)}>Revoke</button>}</span></div>; })}</div>}</section>;
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
  return <section className="workspace-section security-page"><div className="page-heading"><div><h1>Security</h1><p>Manage your master password and review local protection.</p></div></div><div className="security-layout"><form className="password-change settings-panel" onSubmit={submit}><div className="panel-heading"><div><h2>Change master password</h2><p>Re-encrypt your private keys without changing your vault contents.</p></div><LockSimple size={19} aria-hidden="true" /></div><Field label="Current master password"><input type="password" autoComplete="current-password" required value={current} onChange={(event) => setCurrent(event.target.value)} /></Field><Field label="New master password"><input type="password" autoComplete="new-password" minLength={12} required value={next} onChange={(event) => setNext(event.target.value)} /></Field><Field label="Confirm new master password"><input type="password" autoComplete="new-password" required value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></Field><div className="warning"><Warning size={18} aria-hidden="true" /><div><strong>No recovery route</strong><span>Store the new password safely. Lockit cannot recover it for you.</span></div></div>{error && <p className="form-error" role="alert">{error}</p>}<div className="form-actions"><Button disabled={busy} type="submit">{busy ? 'Rewrapping keys…' : 'Change master password'}</Button></div></form><aside className="security-summary" aria-label="Local protection summary"><section className="settings-panel protection-panel"><div className="panel-heading"><div><h2>Local protection</h2><p>Current session and key custody.</p></div><ShieldCheck size={20} aria-hidden="true" /></div><div className="protection-status"><span className="status-dot" /><div><strong>Vault unlocked</strong><span>Keys are available in this tab only.</span></div></div><dl className="summary-list"><div><dt><HardDrive size={15} aria-hidden="true" />Browser storage</dt><dd>No plaintext or keys</dd></div><div><dt><Clock size={15} aria-hidden="true" />Idle lock</dt><dd>After 5 minutes</dd></div><div><dt><LockSimple size={15} aria-hidden="true" />Key custody</dt><dd>This device</dd></div></dl></section><details className="settings-panel algorithm-details"><summary><span><Info size={16} aria-hidden="true" />Encryption details</span><span className="details-action">View algorithms</span></summary><dl className="algorithm-list"><div><dt>Password derivation</dt><dd>Argon2id, 3 operations, 64 MiB</dd></div><div><dt>Item encryption</dt><dd>XChaCha20-Poly1305</dd></div><div><dt>Login challenges</dt><dd>Ed25519 signatures</dd></div><div><dt>Vault key exchange</dt><dd>X25519 sealed boxes</dd></div></dl></details><p className="security-note">Your master password and unlocked keys are never written to localStorage or sessionStorage.</p></aside></div></section>;
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

  return (
    <div className="vault-shell">
      <aside className="app-sidebar">
        <div className="sidebar-brand"><Wordmark /><span>Personal workspace</span></div>
        <nav className="sidebar-nav" aria-label="Main navigation">
          <button aria-current={tab === 'vault' ? 'page' : undefined} onClick={() => setTab('vault')} title="Vault"><VaultIcon size={19} aria-hidden="true" /><span>Vault</span></button>
          <button aria-current={tab === 'shares' ? 'page' : undefined} onClick={() => setTab('shares')} title="Shares"><ShareNetwork size={19} aria-hidden="true" /><span>Shares</span></button>
          <button aria-current={tab === 'security' ? 'page' : undefined} onClick={() => setTab('security')} title="Security"><ShieldCheck size={19} aria-hidden="true" /><span>Security</span></button>
        </nav>
        <div className="sidebar-footer">
          <div className="local-status"><span className="status-dot" /><div><strong>Unlocked locally</strong><span>{session.items.length} {session.items.length === 1 ? 'item' : 'items'} in memory</span></div></div>
          <p>Automatic lock after 5 minutes of inactivity.</p>
        </div>
      </aside>
      <div className="app-frame">
        <header className="vault-header">
          <div className="utility-context"><span>Personal vault</span><span className="utility-separator">/</span><strong>{tab === 'vault' ? 'Items' : tab === 'shares' ? 'Shared links' : 'Security settings'}</strong></div>
          <div className="account-menu"><span className="account-email" title={session.email}>{session.email}</span><button onClick={onLock}><LockSimple size={15} aria-hidden="true" />Lock</button><button onClick={() => void onLogout()}><SignOut size={15} aria-hidden="true" />Log out</button></div>
        </header>
        <main className="vault-main">
          {notice && <div className={`notice notice--${notice.tone}`} role="status"><CheckCircle size={17} aria-hidden="true" /><span>{notice.text}</span><button onClick={() => setNotice(null)} aria-label="Dismiss notification"><X size={16} aria-hidden="true" /></button></div>}
          {shareLink && <div className="share-link"><div><strong>Share link ready</strong><p>Anyone with this complete link can read the snapshot until it expires or is revoked.</p></div><input aria-label="Share link" readOnly value={shareLink} onFocus={(event) => event.target.select()} /><Button variant="secondary" onClick={() => { void copyText(shareLink).then(() => notify('Share link copied.')).catch(() => notify('Copy failed. Select the link manually.')); }}><Copy size={14} aria-hidden="true" />Copy link</Button><button className="icon-button" onClick={() => setShareLink('')} aria-label="Dismiss share link"><X size={16} aria-hidden="true" /></button></div>}
          {tab === 'vault' && <div className="vault-workspace">
            <section className="items-pane">
              <div className="page-heading vault-page-heading"><div><h1>Your vault</h1><p>{session.items.length} encrypted {session.items.length === 1 ? 'item' : 'items'}</p></div><Button onClick={() => { setEditing('new'); setSelectedId(null); }}><Plus size={16} aria-hidden="true" />Add item</Button></div>
              <div className="vault-tools"><label className="search"><MagnifyingGlass size={16} aria-hidden="true" /><span className="sr-only">Search vault</span><input type="search" placeholder="Search vault" value={query} onChange={(event) => setQuery(event.target.value)} /></label><div className="filters" aria-label="Filter items">{(['all', 'password', 'api-key', 'document'] as const).map((value) => <button key={value} aria-pressed={filter === value} onClick={() => setFilter(value)}>{value === 'all' ? 'All' : api.itemKindLabel(value)}</button>)}</div></div>
              {filtered.length === 0 ? <div className="empty"><VaultIcon size={30} aria-hidden="true" /><h2>{session.items.length === 0 ? 'No items yet' : 'No matching items'}</h2><p>{session.items.length === 0 ? 'Add a password, API key, or document. Encryption happens before upload.' : 'Try another search or filter.'}</p>{session.items.length === 0 && <Button onClick={() => setEditing('new')}><Plus size={15} aria-hidden="true" />Add your first item</Button>}</div> : <div className="item-list">{filtered.map((item) => <button className="item-row" key={item.id} aria-pressed={selectedId === item.id} onClick={() => { setSelectedId(item.id); setEditing(null); }}><span className={`item-glyph item-glyph--${item.kind}`}><KindIcon kind={item.kind} /></span><span className="item-row__copy"><strong>{item.title}</strong><small>{item.username || item.documentName || item.url || api.itemKindLabel(item.kind)}</small></span><span className="item-row__kind">{api.itemKindLabel(item.kind)}</span></button>)}</div>}
            </section>
            <section className="inspector">{editing ? <ItemEditor key={editing === 'new' ? 'new' : editing.id} item={editing === 'new' ? null : editing} onSave={save} onCancel={() => setEditing(null)} busy={busy} /> : selected ? <ItemDetail key={selected.id} item={selected} onEdit={() => setEditing(selected)} onDelete={() => remove(selected)} onShared={shared} notify={notify} /> : <div className="inspector-empty"><LockSimple size={30} aria-hidden="true" /><h2>Select an item</h2><p>View and manage decrypted details here. Plaintext stays in this tab.</p></div>}</section>
          </div>}
          {tab === 'shares' && <SharesView shares={session.shares} items={session.items} onRevoke={revoke} />}
          {tab === 'security' && <SecurityView onChangePassword={changePassword} busy={busy} />}
        </main>
      </div>
    </div>
  );
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
  return <main className="public-shell"><header className="public-header"><Wordmark /><span className="local-badge"><ShareNetwork size={14} aria-hidden="true" />Secure share</span></header><section className="public-frame"><div className="public-content">{loading ? <><span className="eyebrow">Encrypted snapshot</span><h1>Decrypting securely…</h1><p>The decryption key is being used only on this device.</p></> : error ? <><span className="eyebrow">Link unavailable</span><h1>This share cannot be opened</h1><p className="public-error">{error}</p><p>The link may have expired, been revoked, or been altered. Ask the sender to create a new one.</p></> : item && <><div className="public-title"><span className="item-kind"><KindIcon kind={item.kind} size={16} />{api.itemKindLabel(item.kind)} snapshot</span><h1>{item.title}</h1><p>Decrypted locally from an encrypted snapshot.</p></div><dl className="secret-list">{item.username && <div><dt>Username</dt><dd>{item.username}</dd></div>}{item.secret && <div><dt>{item.kind === 'api-key' ? 'API key' : 'Password'}</dt><dd><span className="secret-value">{revealed ? item.secret : '••••••••••••••••'}</span><button onClick={() => setRevealed(!revealed)}>{revealed ? <EyeSlash size={14} aria-hidden="true" /> : <Eye size={14} aria-hidden="true" />}{revealed ? 'Hide' : 'Reveal'}</button></dd></div>}{item.url && <div><dt>Website</dt><dd><a href={safeHttpUrl(item.url)}>{item.url}</a></dd></div>}{item.documentData && <div><dt>Document</dt><dd><span>{item.documentName}</span><button onClick={() => downloadDocument(item)}><DownloadSimple size={14} aria-hidden="true" />Download</button></dd></div>}{item.notes && <div><dt>Notes</dt><dd className="notes">{item.notes}</dd></div>}</dl><p className="fine-print">Created {new Date(item.updatedAt).toLocaleString()}. This snapshot does not provide live vault access.</p></>}</div></section><footer className="public-footer"><LockSimple size={13} aria-hidden="true" />Lockit cannot read this snapshot or recover a lost link.</footer></main>;
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
