import type {
  EncryptedItem,
  KeyBundle,
  LoginChallenge,
  RegisterRequest,
  Share,
  VaultItemKind,
} from '../shared/api';

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body) headers.set('Content-Type', 'application/json');
  let response: Response;
  try {
    response = await fetch(path, { ...init, headers, credentials: 'same-origin' });
  } catch {
    throw new ApiError('Lockit could not reach the server. Check your connection and try again.', 0);
  }
  if (response.status === 204) return undefined as T;
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const message = body && typeof body === 'object' && 'error' in body && typeof body.error === 'string'
      ? body.error
      : `The request failed (${response.status}).`;
    throw new ApiError(message, response.status);
  }
  return body as T;
}

export const register = (request: RegisterRequest) => api<{ user: { email: string } }>('/api/register', {
  method: 'POST',
  body: JSON.stringify(request),
});

export const challenge = (email: string) => api<LoginChallenge>('/api/auth/challenge', {
  method: 'POST',
  body: JSON.stringify({ email }),
});

export const verify = (challengeId: string, signature: string) => api<{ user: { email: string } }>('/api/auth/verify', {
  method: 'POST',
  body: JSON.stringify({ challengeId, signature }),
});

export const me = () => api<{ user: { email: string } }>('/api/auth/me');
export const logout = () => api<void>('/api/auth/logout', { method: 'POST' });
export const getBundle = () => api<{ bundle: KeyBundle }>('/api/auth/bundle');
export const updateBundle = (bundle: KeyBundle) => api<{ bundle: KeyBundle }>('/api/auth/bundle', {
  method: 'PUT',
  body: JSON.stringify({ bundle }),
});
export const listItems = () => api<{ items: EncryptedItem[] }>('/api/items');

export const createItem = (item: Omit<EncryptedItem, 'updatedAt'>) => api<{ item: EncryptedItem }>('/api/items', {
  method: 'POST',
  body: JSON.stringify({ item }),
});

export const updateItem = (item: Omit<EncryptedItem, 'updatedAt'>) => api<{ item: EncryptedItem }>(`/api/items/${encodeURIComponent(item.id)}`, {
  method: 'PUT',
  body: JSON.stringify({ item }),
});

export const deleteItem = (id: string) => api<void>(`/api/items/${encodeURIComponent(id)}`, { method: 'DELETE' });
export const listShares = () => api<{ shares: Share[] }>('/api/shares');

export function createShare(input: {
  id: string;
  itemId: string;
  ttlSeconds: number;
  ciphertext: string;
  nonce: string;
}) {
  return api<{ share: Share; token: string }>('/api/shares', {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

export const revokeShare = (id: string) => api<void>(`/api/shares/${encodeURIComponent(id)}`, { method: 'DELETE' });
export const openShare = (id: string, token: string) => api<{ ciphertext: string; nonce: string }>('/api/shares/open', {
  method: 'POST',
  body: JSON.stringify({ id, token }),
});

export function itemKindLabel(kind: VaultItemKind): string {
  if (kind === 'api-key') return 'API key';
  if (kind === 'document') return 'Document';
  return 'Password';
}
