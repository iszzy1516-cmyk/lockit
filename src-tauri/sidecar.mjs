import path from 'node:path';
import { pathToFileURL } from 'node:url';

const entry = process.argv[2];
if (!entry) {
  throw new Error('The Lockit server entry path is required');
}

const { createApp } = await import(pathToFileURL(path.resolve(entry)).href);
const app = createApp();
let stopping = false;

function stop() {
  if (stopping) return;
  stopping = true;
  const forceExit = setTimeout(() => process.exit(1), 5000);
  forceExit.unref();
  app.server.close(() => {
    clearTimeout(forceExit);
    app.close();
    process.exit(0);
  });
}

process.on('SIGINT', stop);
process.on('SIGTERM', stop);
app.server.listen(app.config.port, '127.0.0.1');
