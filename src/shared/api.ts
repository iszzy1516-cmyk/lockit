export const KDF_OPS_LIMIT = 3;
export const KDF_MEM_LIMIT = 64 * 1024 * 1024;
export const ENVELOPE_VERSION = 1;

export type SecretBox = {
  nonce: string;
  ciphertext: string;
};

export type KeyBundle = {
  salt: string;
  opsLimit: number;
  memLimit: number;
  identityPublicKey: string;
  encryptedIdentitySecret: SecretBox;
  encryptedRecoveryIdentitySecret: SecretBox;
  vaultPublicKey: string;
  encryptedVaultSecret: SecretBox;
  encryptedRecoveryVaultSecret: SecretBox;
  sealedVaultKey: string;
};

export type RegisterRequest = KeyBundle & { email: string };
export type LoginChallenge = {
  challengeId: string;
  challenge: string;
  bundle: KeyBundle;
};

export type VaultItemKind = 'password' | 'api-key' | 'document';
export type VaultItem = {
  id: string;
  kind: VaultItemKind;
  title: string;
  username?: string;
  secret?: string;
  notes?: string;
  url?: string;
  documentName?: string;
  documentType?: string;
  documentData?: string;
  updatedAt: string;
};

export type EncryptedItem = {
  id: string;
  version: number;
  nonce: string;
  ciphertext: string;
  updatedAt: string;
};

export type Share = {
  id: string;
  itemId: string;
  expiresAt: string;
  revokedAt: string | null;
  createdAt: string;
};

export type ApiError = { error: string };
