import { test, expect } from '@playwright/test';
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

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
  await page.getByRole('tab', { name: 'Create vault' }).click();
  await page.getByLabel('Email address').fill('e2e@example.com');
  await page.locator('input[autocomplete="new-password"]').first().fill(master);
  await page.getByLabel('Confirm master password').fill(master);
  await page.getByRole('button', { name: 'Create encrypted vault' }).click();
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

  await page.getByRole('button', { name: 'Security', exact: true }).click();
  await page.getByLabel('Current master password').fill(master);
  await page.getByLabel('New master password', { exact: true }).fill(replacement);
  await page.getByLabel('Confirm new master password').fill(replacement);
  await page.getByRole('button', { name: 'Change master password', exact: true }).click();
  await expect(page.getByText('Master password changed. Your private keys were re-encrypted.')).toBeVisible();
  await page.getByRole('button', { name: 'Lock', exact: true }).click();
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

  await page.screenshot({ path: 'test-results/vault-desktop.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: 'test-results/vault-mobile.png', fullPage: true });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);

  const network = requests.join('\n');
  for (const plaintext of [master, replacement, password, apiKey, documentText, 'Production login', 'Deploy API', 'Recovery instructions']) {
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
    for (const plaintext of [master, replacement, password, apiKey, documentText, 'Production login', fragmentKey]) {
      expect(stored).not.toContain(plaintext);
    }
  } finally {
    db.close();
  }
});

test('idle lock clears the unlocked view without browser storage', async ({ page }) => {
  await page.clock.install();
  await page.goto('/');
  await page.getByRole('tab', { name: 'Create vault' }).click();
  await page.getByLabel('Email address').fill('idle@example.com');
  await page.locator('input[autocomplete="new-password"]').first().fill(master);
  await page.getByLabel('Confirm master password').fill(master);
  await page.getByRole('button', { name: 'Create encrypted vault' }).click();
  await expect(page.getByRole('heading', { name: 'Your vault' })).toBeVisible();
  expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }))).toEqual({ local: 0, session: 0 });
  await page.clock.fastForward(5 * 60 * 1000 + 1000);
  await expect(page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Your vault' })).toHaveCount(0);
});
