import { rmSync } from 'node:fs';

const database = '/tmp/lockit-playwright.db';
for (const suffix of ['', '-wal', '-shm']) rmSync(database + suffix, { force: true });
process.env.NODE_ENV = 'test';
process.env.PORT = '3000';
process.env.LOCKIT_DB_PATH = database;
process.env.LOCKIT_PUBLIC_ORIGIN = 'http://127.0.0.1:3000';
const { createApp } = await import('../dist/server/server/index.js');
const app = createApp();
app.server.listen(3000, '127.0.0.1');
const close = () => {
  app.server.close(() => {
    app.close();
    process.exit(0);
  });
};
process.on('SIGTERM', close);
process.on('SIGINT', close);
