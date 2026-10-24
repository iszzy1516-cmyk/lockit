import { spawn } from 'node:child_process';
import path from 'node:path';

const origin = 'http://localhost:3000';
const healthUrl = 'http://127.0.0.1:3000/api/health';
const child = spawn(process.execPath, [
  path.resolve('src-tauri/sidecar.mjs'),
  path.resolve('dist/server/server/index.js'),
], {
  stdio: 'inherit',
  env: {
    ...process.env,
    PORT: '3000',
    NODE_ENV: 'development',
    LOCKIT_PUBLIC_ORIGIN: origin,
    LOCKIT_DB_PATH: path.resolve('data/lockit.db'),
    LOCKIT_PUBLIC_DIR: path.resolve('dist/public'),
    LOCKIT_TRUST_PROXY: 'false',
  },
});

let stopping = false;
let stopSignal = null;
const exited = new Promise((resolve) => {
  child.once('exit', (code, signal) => resolve({ code, signal }));
});
child.once('error', (error) => {
  console.error(`Could not start the local Lockit server: ${error.message}`);
});

async function stop(signal) {
  if (stopping) return;
  stopping = true;
  stopSignal = signal;
  console.log(`\nStopping Lockit (${signal})...`);
  if (child.exitCode === null && child.signalCode === null) child.kill(signal);
  const forceStop = setTimeout(() => {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
  }, 5000);
  forceStop.unref();
  await exited;
  clearTimeout(forceStop);
}

process.on('SIGINT', () => void stop('SIGINT'));
process.on('SIGTERM', () => void stop('SIGTERM'));

try {
  await waitUntilHealthy();
  if (!stopping) {
    if (process.env.LOCKIT_NO_BROWSER !== '1') openBrowser(origin);
    console.log(`Lockit is available at ${origin}`);
  }
} catch (error) {
  if (!stopping) {
    console.error(`Lockit could not start: ${error.message}`);
    await stop('SIGTERM');
    process.exitCode = 1;
  }
}

const result = await exited;
if (!stopping) {
  if (result.code) {
    console.error(`The local Lockit server exited with code ${result.code}.`);
    process.exitCode = result.code;
  } else if (result.signal) {
    console.error(`The local Lockit server exited after ${result.signal}.`);
    process.exitCode = 1;
  }
} else if (stopSignal && process.exitCode === undefined) {
  process.exitCode = 0;
}

async function waitUntilHealthy() {
  const deadline = Date.now() + 30_000;
  while (!stopping && Date.now() < deadline) {
    if (child.exitCode !== null || child.signalCode !== null) {
      throw new Error('The server exited before becoming ready');
    }
    try {
      const response = await fetch(healthUrl, { signal: AbortSignal.timeout(1000) });
      if (response.ok) {
        const body = await response.json();
        if (body.status === 'ok') return;
      }
    } catch {
    }
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  if (stopping) return;
  throw new Error('The server did not become healthy within 30 seconds');
}

function openBrowser(url) {
  const [command, args] = process.platform === 'win32'
    ? ['rundll32.exe', ['url.dll,FileProtocolHandler', url]]
    : process.platform === 'darwin'
      ? ['open', [url]]
      : ['xdg-open', [url]];
  const browser = spawn(command, args, { detached: true, stdio: 'ignore' });
  browser.once('error', (error) => {
    console.error(`Could not open a browser automatically: ${error.message}`);
  });
  browser.unref();
}
