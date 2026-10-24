import { test, expect, type Page } from '@playwright/test';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';

async function captureScreenshots(page: Page, name: 'auth' | 'vault' | 'settings') {
  for (const colorScheme of ['light', 'dark'] as const) {
    await page.emulateMedia({ colorScheme });
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.screenshot({ path: `test-results/${name}-desktop${colorScheme === 'dark' ? '-dark' : ''}.png`, fullPage: true, animations: 'disabled' });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({ path: `test-results/${name}-mobile${colorScheme === 'dark' ? '-dark' : ''}.png`, fullPage: true, animations: 'disabled' });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  }
  await page.emulateMedia({ colorScheme: 'light' });
  await page.setViewportSize({ width: 1440, height: 900 });
}

function encodedRecoveryKey(fileText: string): string {
  const match = /^Recovery key: ([A-Za-z0-9_-]{43})$/m.exec(fileText);
  if (!match?.[1]) throw new Error('Recovery file did not contain a canonical key.');
  return match[1];
}

async function completeRecoverySetup(page: Page): Promise<string> {
  await expect(page.getByRole('heading', { name: 'Save your recovery key' })).toBeVisible();
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download recovery file', exact: true }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe('lockit-recovery-key.txt');
  const path = await download.path();
  if (!path) throw new Error('Recovery download path was unavailable.');
  const contents = await readFile(path, 'utf8');
  expect(contents).toContain('Anyone with this file can unlock your vault');
  expect(contents).toContain('Lockit cannot send this recovery key again');
  expect(page.locator('body')).not.toContainText(encodedRecoveryKey(contents));
  await page.getByLabel('I saved my recovery file in a safe place').check();
  await page.getByRole('button', { name: 'Continue', exact: true }).click();
  return contents;
}

async function unlockWithRecovery(page: Page, contents: string) {
  await page.getByRole('button', { name: 'Use recovery file', exact: true }).click();
  await page.getByLabel('Recovery key file').setInputFiles({ name: 'lockit-recovery-key.txt', mimeType: 'text/plain', buffer: Buffer.from(contents) });
  await page.getByRole('button', { name: 'Unlock vault', exact: true }).click();
}

const master = 'first correct horse battery staple';
const replacement = 'second correct horse battery staple';
const password = 'Lockit fixture password 93842';
const apiKey = 'lk_fixture_5a14b0e246a94b51';
const documentText = 'Confidential fixture document 731905';

test('real zero-knowledge vault workflow', async ({ page, context }) => {
  const requests: string[] = [];
  page.on('request', (request) => {
    if (request.url().includes('/api/')) requests.push(`${request.method()} ${request.url()} ${request.postData() ?? ''}`);
  });
  const pageErrors: string[] = [];
  page.on('pageerror', (error) => pageErrors.push(error.message));
  const digest = createHash('sha1').update(password).digest('hex').toUpperCase();
  await page.route(`**/api/hibp/${digest.slice(0, 5)}`, (route) => route.fulfill({
    contentType: 'text/plain',
    body: `${digest.slice(5)}:17\n00000000000000000000000000000000000:1`,
  }));

  await page.goto('/');
  await captureScreenshots(page, 'auth');
  await page.getByRole('tab', { name: 'Create vault' }).click();
  await page.getByLabel('Email address').fill('e2e@example.com');
  await page.locator('input[autocomplete="new-password"]').first().fill(master);
  await page.getByLabel('Confirm master password').fill(master);
  await page.getByRole('button', { name: 'Create encrypted vault' }).click();
  const originalRecoveryFile = await completeRecoverySetup(page);
  const originalRecoveryKey = encodedRecoveryKey(originalRecoveryFile);
  await expect(page.getByRole('heading', { name: 'Your vault' })).toBeVisible();

  await page.getByRole('button', { name: 'Add your first item' }).click();
  await page.getByLabel('Name', { exact: true }).fill('Production login');
  await page.getByLabel('Username', { exact: true }).fill('ops@example.com');
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByLabel('Notes').fill('Local-only fixture note');
  await page.getByRole('button', { name: 'Encrypt and save' }).click();
  await expect(page.getByText('Item encrypted and saved.')).toBeVisible();
  await page.getByRole('button', { name: 'Reveal', exact: true }).click();
  await expect(page.getByText(password, { exact: true })).toBeVisible();

  await page.getByRole('button', { name: 'Check password' }).click();
  await expect(page.getByText('Found in known breaches 17 times. Change this password.')).toBeVisible();

  await page.getByRole('button', { name: 'Create a secure share' }).click();
  await page.getByRole('button', { name: 'Create share link', exact: true }).click();
  const shareLink = await page.getByLabel('Share link', { exact: true }).inputValue();
  expect(shareLink).toContain('#');
  const recipient = await context.newPage();
  await recipient.goto(shareLink);
  await expect(recipient.getByRole('heading', { name: 'Production login' })).toBeVisible();
  await recipient.getByRole('button', { name: 'Reveal', exact: true }).click();
  await expect(recipient.getByText(password, { exact: true })).toBeVisible();

  await page.getByRole('button', { name: 'Shares', exact: true }).click();
  await page.getByRole('button', { name: 'Revoke', exact: true }).click();
  await expect(page.getByText('Revoked', { exact: true })).toBeVisible();
  await recipient.reload();
  await expect(recipient.getByRole('heading', { name: 'This share cannot be opened' })).toBeVisible();
  await recipient.close();

  await page.getByRole('button', { name: 'Vault', exact: true }).click();
  await page.getByRole('button', { name: 'Add item', exact: true }).click();
  await page.getByLabel('Item type').selectOption('api-key');
  await page.getByLabel('Name', { exact: true }).fill('Deploy API');
  await page.getByLabel('Service or owner').fill('Automation');
  await page.getByLabel('API key', { exact: true }).fill(apiKey);
  await page.getByRole('button', { name: 'Encrypt and save' }).click();
  await expect(page.getByRole('heading', { name: 'Deploy API' })).toBeVisible();

  await page.getByRole('button', { name: 'Add item', exact: true }).click();
  await page.getByLabel('Item type').selectOption('document');
  await page.getByLabel('Name', { exact: true }).fill('Recovery instructions');
  await page.locator('input[type="file"]').setInputFiles({ name: 'recovery.txt', mimeType: 'text/plain', buffer: Buffer.from(documentText) });
  await page.getByRole('button', { name: 'Encrypt and save' }).click();
  await expect(page.getByRole('heading', { name: 'Recovery instructions' })).toBeVisible();
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download', exact: true }).click();
  expect((await downloadPromise).suggestedFilename()).toBe('recovery.txt');
  await page.getByRole('button', { name: /Production login/ }).click();
  await captureScreenshots(page, 'vault');

  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  await captureScreenshots(page, 'settings');
  for (const removed of ['Unlocked locally', 'items in memory', 'Automatic lock', 'Local protection', 'Browser storage', 'Key custody', 'Encryption details', 'never written to localStorage']) {
    await expect(page.getByText(removed, { exact: false })).toHaveCount(0);
  }
  await expect(page.locator('.vault-header').getByRole('button', { name: 'Lock', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Lock now', exact: true })).toBeVisible();

  const backupDownloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export encrypted backup', exact: true }).click();
  const backupDownload = await backupDownloadPromise;
  expect(backupDownload.suggestedFilename()).toMatch(/^lockit-encrypted-backup-.*\.json$/);
  const backupPath = await backupDownload.path();
  if (!backupPath) throw new Error('Encrypted backup download path was unavailable.');
  const backupText = await readFile(backupPath, 'utf8');
  const backup = JSON.parse(backupText) as {
    formatVersion: number;
    account: { email: string };
    exportedAt: string;
    bundle: unknown;
    encryptedItems: { id: string; nonce: string; ciphertext: string }[];
    encryptedShares: unknown[];
    keys?: unknown;
    recoveryKey?: unknown;
  };
  expect(backup.formatVersion).toBe(1);
  expect(backup.account.email).toBe('e2e@example.com');
  expect(backup.exportedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  expect(backup.encryptedItems).toHaveLength(3);
  expect(backup.encryptedShares).toHaveLength(1);
  for (const item of backup.encryptedItems) {
    expect(item.id).toBeTruthy();
    expect(item.nonce).toBeTruthy();
    expect(item.ciphertext).toBeTruthy();
    expect(item).not.toHaveProperty('title');
    expect(item).not.toHaveProperty('secret');
  }
  expect(backup.keys).toBeUndefined();
  expect(backup.recoveryKey).toBeUndefined();
  for (const plaintext of [master, password, apiKey, documentText, 'Production login', 'Deploy API', 'Recovery instructions', originalRecoveryKey]) {
    expect(backupText).not.toContain(plaintext);
  }

  await page.getByLabel('Current master password').fill(master);
  await page.getByLabel('New master password', { exact: true }).fill(replacement);
  await page.getByLabel('Confirm new master password').fill(replacement);
  await page.getByRole('button', { name: 'Change master password', exact: true }).click();
  await expect(page.getByText('Master password changed. Your private keys were re-encrypted.')).toBeVisible();
  await page.getByRole('button', { name: 'Lock now', exact: true }).click();
  await page.getByLabel('Master password', { exact: true }).fill(master);
  await page.getByRole('button', { name: 'Unlock vault', exact: true }).click();
  await expect(page.getByText('The master password is incorrect or this key bundle is damaged.')).toBeVisible();
  await page.getByLabel('Master password', { exact: true }).fill(replacement);
  await page.getByRole('button', { name: 'Unlock vault', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Your vault' })).toBeVisible();
  await expect(page.locator('.item-row')).toHaveCount(3);
  await page.getByRole('button', { name: /Production login/ }).click();
  await page.getByRole('button', { name: 'Reveal', exact: true }).click();
  await expect(page.getByText(password, { exact: true })).toBeVisible();

  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  await page.getByRole('button', { name: 'Lock now', exact: true }).click();
  await unlockWithRecovery(page, originalRecoveryFile);
  await expect(page.getByRole('heading', { name: 'Your vault' })).toBeVisible();
  await expect(page.locator('.item-row')).toHaveCount(3);

  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  const rotatedDownloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Replace recovery key', exact: true }).click();
  const rotatedDownload = await rotatedDownloadPromise;
  expect(rotatedDownload.suggestedFilename()).toBe('lockit-recovery-key.txt');
  const rotatedPath = await rotatedDownload.path();
  if (!rotatedPath) throw new Error('Rotated recovery download path was unavailable.');
  const rotatedRecoveryFile = await readFile(rotatedPath, 'utf8');
  const rotatedRecoveryKey = encodedRecoveryKey(rotatedRecoveryFile);
  expect(rotatedRecoveryKey).not.toBe(originalRecoveryKey);
  await expect(page.getByText('Recovery key replaced. The new file was downloaded and previous files no longer work.')).toBeVisible();

  await page.getByRole('button', { name: 'Lock now', exact: true }).click();
  await unlockWithRecovery(page, originalRecoveryFile);
  await expect(page.getByText('The recovery key is incorrect or this key bundle is damaged.')).toBeVisible();
  await unlockWithRecovery(page, rotatedRecoveryFile);
  await expect(page.getByRole('heading', { name: 'Your vault' })).toBeVisible();
  await expect(page.locator('.item-row')).toHaveCount(3);

  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);

  const network = requests.join('\n');
  for (const plaintext of [master, replacement, password, apiKey, documentText, 'Production login', 'Deploy API', 'Recovery instructions', originalRecoveryKey, rotatedRecoveryKey]) {
    expect(network).not.toContain(plaintext);
  }
  const [shareToken, fragmentKey] = shareLink.split('#')[1]!.split('.', 2) as [string, string];
  expect(new URL(shareLink).pathname).not.toContain(shareToken);
  expect(network).not.toContain(fragmentKey);
  expect(pageErrors).toEqual([]);

  const db = new DatabaseSync('/tmp/lockit-playwright.db');
  try {
    const rows = db.prepare('SELECT bundle FROM users UNION ALL SELECT ciphertext FROM items UNION ALL SELECT ciphertext FROM shares').all() as { bundle?: string; ciphertext?: string }[];
    const stored = rows.map((row) => row.bundle ?? row.ciphertext).join('\n');
    for (const plaintext of [master, replacement, password, apiKey, documentText, 'Production login', fragmentKey, originalRecoveryKey, rotatedRecoveryKey]) {
      expect(stored).not.toContain(plaintext);
    }
  } finally {
    db.close();
  }
});

test('appearance and clipboard preferences persist and apply immediately', async ({ page }) => {
  const pageErrors: string[] = [];
  page.on('pageerror', (error) => pageErrors.push(error.message));
  await page.goto('/');
  await page.getByRole('tab', { name: 'Create vault' }).click();
  await page.getByLabel('Email address').fill('preferences@example.com');
  await page.locator('input[autocomplete="new-password"]').first().fill(master);
  await page.getByLabel('Confirm master password').fill(master);
  await page.getByRole('button', { name: 'Create encrypted vault' }).click();
  await completeRecoverySetup(page);
  await expect(page.getByRole('heading', { name: 'Your vault' })).toBeVisible();
  await page.getByRole('button', { name: 'Add your first item' }).click();
  await page.getByLabel('Name', { exact: true }).fill('Clipboard check');
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Encrypt and save' }).click();
  await expect(page.getByRole('heading', { name: 'Clipboard check' })).toBeVisible();

  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  await expect(page.getByRole('button', { name: 'System', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await expect(page.getByLabel('Clear clipboard after')).toHaveValue('30');
  await page.emulateMedia({ colorScheme: 'light' });
  await page.getByRole('button', { name: 'Dark', exact: true }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  expect(await page.evaluate(() => localStorage.getItem('lockit.settings.appearance'))).toBe('dark');
  await page.screenshot({ path: 'test-results/settings-override-dark.png', fullPage: true, animations: 'disabled' });
  await page.emulateMedia({ colorScheme: 'dark' });
  await page.getByRole('button', { name: 'Light', exact: true }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  expect(await page.evaluate(() => localStorage.getItem('lockit.settings.appearance'))).toBe('light');
  await page.screenshot({ path: 'test-results/settings-override-light.png', fullPage: true, animations: 'disabled' });
  await page.getByLabel('Clear clipboard after').selectOption('10');
  expect(await page.evaluate(() => localStorage.getItem('lockit.settings.clipboard-clear-seconds'))).toBe('10');

  await page.reload();
  await expect(page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await page.getByLabel('Master password', { exact: true }).fill(master);
  await page.getByRole('button', { name: 'Unlock vault', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Your vault' })).toBeVisible();
  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Light', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await expect(page.getByLabel('Clear clipboard after')).toHaveValue('10');
  await page.getByRole('button', { name: 'System', exact: true }).click();
  await expect(page.locator('html')).not.toHaveAttribute('data-theme');
  expect(await page.evaluate(() => localStorage.getItem('lockit.settings.appearance'))).toBe('system');

  await page.evaluate(() => {
    const target = window as unknown as { clipboardWrites: string[] };
    target.clipboardWrites = [];
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: (value: string) => { target.clipboardWrites.push(value); return Promise.resolve(); } },
    });
  });
  await page.clock.install();
  await page.getByRole('button', { name: 'Vault', exact: true }).click();
  await page.getByRole('button', { name: /Clipboard check/ }).click();
  await page.locator('.secret-actions').getByRole('button', { name: 'Copy', exact: true }).click();
  await page.clock.fastForward(10_000);
  await expect.poll(() => page.evaluate(() => (window as unknown as { clipboardWrites: string[] }).clipboardWrites.at(-1))).toBe('');
  expect(pageErrors).toEqual([]);
});

test('idle lock applies the saved timeout immediately without secret browser storage', async ({ page }) => {
  await page.clock.install();
  await page.goto('/');
  await page.getByRole('tab', { name: 'Create vault' }).click();
  await page.getByLabel('Email address').fill('idle@example.com');
  await page.locator('input[autocomplete="new-password"]').first().fill(master);
  await page.getByLabel('Confirm master password').fill(master);
  await page.getByRole('button', { name: 'Create encrypted vault' }).click();
  await completeRecoverySetup(page);
  await expect(page.getByRole('heading', { name: 'Your vault' })).toBeVisible();
  expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }))).toEqual({ local: 0, session: 0 });
  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  await page.getByLabel('Idle lock timeout').selectOption('15');
  expect(await page.evaluate(() => localStorage.getItem('lockit.settings.idle-lock-minutes'))).toBe('15');
  await page.clock.fastForward(5 * 60 * 1000 + 1000);
  await expect(page.getByRole('heading', { name: 'Settings', exact: true })).toBeVisible();
  await page.clock.fastForward(10 * 60 * 1000);
  await expect(page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Your vault' })).toHaveCount(0);
  expect(await page.evaluate(() => sessionStorage.length)).toBe(0);
});
