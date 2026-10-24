export type Appearance = 'system' | 'light' | 'dark';
export type IdleLockMinutes = 5 | 15 | 30;
export type ClipboardClearSeconds = 10 | 30 | 60;

export const PREFERENCE_KEYS = {
  appearance: 'lockit.settings.appearance',
  idleLockMinutes: 'lockit.settings.idle-lock-minutes',
  clipboardClearSeconds: 'lockit.settings.clipboard-clear-seconds',
} as const;

function read(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function write(key: string, value: string): void {
  try {
    localStorage.setItem(key, value);
  } catch {
    // Preferences remain effective for this session when storage is unavailable.
  }
}

export function getAppearance(): Appearance {
  const value = read(PREFERENCE_KEYS.appearance);
  return value === 'light' || value === 'dark' ? value : 'system';
}

export function applyAppearance(appearance: Appearance): void {
  if (appearance === 'system') {
    delete document.documentElement.dataset.theme;
    document.documentElement.style.removeProperty('color-scheme');
  } else {
    document.documentElement.dataset.theme = appearance;
    document.documentElement.style.colorScheme = appearance;
  }
}

export function setAppearance(appearance: Appearance): void {
  write(PREFERENCE_KEYS.appearance, appearance);
  applyAppearance(appearance);
}

export function initializeAppearance(): void {
  applyAppearance(getAppearance());
}

export function getIdleLockMinutes(): IdleLockMinutes {
  const value = Number(read(PREFERENCE_KEYS.idleLockMinutes));
  return value === 15 || value === 30 ? value : 5;
}

export function setIdleLockMinutes(minutes: IdleLockMinutes): void {
  write(PREFERENCE_KEYS.idleLockMinutes, String(minutes));
}

export function getClipboardClearSeconds(): ClipboardClearSeconds {
  const value = Number(read(PREFERENCE_KEYS.clipboardClearSeconds));
  return value === 10 || value === 60 ? value : 30;
}

export function setClipboardClearSeconds(seconds: ClipboardClearSeconds): void {
  write(PREFERENCE_KEYS.clipboardClearSeconds, String(seconds));
}
