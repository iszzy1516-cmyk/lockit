import { spawn } from 'node:child_process';

const children = [
  spawn(process.execPath, ['--import', 'tsx', '--watch', 'src/server/server/index.ts'], { stdio: 'inherit', env: { ...process.env, PORT: process.env.PORT ?? '3000' } }),
  spawn(process.execPath, ['node_modules/vite/bin/vite.js'], { stdio: 'inherit', env: process.env }),
];

const stop = () => {
  for (const child of children) child.kill('SIGTERM');
};
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
for (const child of children) {
  child.on('exit', (code) => {
    if (code && code !== 0) {
      stop();
      process.exitCode = code;
    }
  });
}
