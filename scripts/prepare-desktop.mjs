import { createHash, randomBytes } from 'node:crypto';
import { mkdir, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync, inflateRawSync } from 'node:zlib';

const root = fileURLToPath(new URL('..', import.meta.url));
const binaries = path.join(root, 'src-tauri', 'binaries');
const version = process.version;
const hostTarget = process.platform === 'linux' && process.arch === 'x64'
  ? 'x86_64-unknown-linux-gnu'
  : process.platform === 'win32' && process.arch === 'x64'
    ? 'x86_64-pc-windows-msvc'
    : null;
const target = process.env.TAURI_TARGET ?? process.env.TAURI_ENV_TARGET_TRIPLE ?? hostTarget;
const targets = {
  'x86_64-unknown-linux-gnu': {
    archive: `node-${version}-linux-x64.tar.gz`,
    entry: `node-${version}-linux-x64/bin/node`,
    output: 'node-x86_64-unknown-linux-gnu',
    extract: extractTarGz,
  },
  'x86_64-pc-windows-msvc': {
    archive: `node-${version}-win-x64.zip`,
    entry: `node-${version}-win-x64/node.exe`,
    output: 'node-x86_64-pc-windows-msvc.exe',
    extract: extractZip,
  },
};

const selected = targets[target];
if (!selected) {
  throw new Error(`Unsupported desktop target ${target ?? '(unknown host)'}; use linux x64 or windows x64`);
}

const baseUrl = `https://nodejs.org/dist/${version}`;
const checksums = await download(`${baseUrl}/SHASUMS256.txt`, 1024 * 1024);
const expectedHash = findChecksum(checksums.toString('utf8'), selected.archive);
const archive = await download(`${baseUrl}/${selected.archive}`, 128 * 1024 * 1024);
const actualHash = createHash('sha256').update(archive).digest('hex');
if (actualHash !== expectedHash) {
  throw new Error(`Checksum mismatch for ${selected.archive}: expected ${expectedHash}, got ${actualHash}`);
}

const executable = selected.extract(archive, selected.entry);
await mkdir(binaries, { recursive: true });
const destination = path.join(binaries, selected.output);
const temporary = path.join(binaries, `.${selected.output}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`);
try {
  await writeFile(temporary, executable, { mode: 0o755 });
  await rename(temporary, destination);
} finally {
  await rm(temporary, { force: true });
}
console.log(`Prepared verified Node ${version} for ${target}: ${path.relative(root, destination)}`);

async function download(url, maximumBytes) {
  let lastError;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const response = await fetch(url, {
        headers: { 'User-Agent': 'Lockit desktop preparation' },
        signal: AbortSignal.timeout(60_000),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status} ${response.statusText}`);
      if (!response.body) throw new Error('Response had no body');
      const declared = Number(response.headers.get('content-length') ?? '0');
      if (declared > maximumBytes) throw new Error(`Response exceeds ${maximumBytes} bytes`);

      const chunks = [];
      let size = 0;
      const reader = response.body.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > maximumBytes) {
          await reader.cancel();
          throw new Error(`Response exceeds ${maximumBytes} bytes`);
        }
        chunks.push(Buffer.from(value));
      }
      return Buffer.concat(chunks, size);
    } catch (error) {
      lastError = error;
      if (attempt < 3) await new Promise((resolve) => setTimeout(resolve, attempt * 1000));
    }
  }
  throw new Error(`Could not download ${url}: ${lastError?.message ?? lastError}`);
}

function findChecksum(contents, archiveName) {
  for (const line of contents.split(/\r?\n/)) {
    const match = /^([a-fA-F0-9]{64}) [ *](.+)$/.exec(line);
    if (match?.[2] === archiveName) return match[1].toLowerCase();
  }
  throw new Error(`Official SHASUMS256.txt does not contain ${archiveName}`);
}

function extractTarGz(archive, entryName) {
  const tar = gunzipSync(archive, { maxOutputLength: 512 * 1024 * 1024 });
  for (let offset = 0; offset + 512 <= tar.length;) {
    const name = tarName(tar, offset);
    if (!name) break;
    const sizeText = tarString(tar, offset + 124, 12).trim();
    const size = Number.parseInt(sizeText || '0', 8);
    if (!Number.isSafeInteger(size) || size < 0) throw new Error('Invalid tar entry size');
    const dataStart = offset + 512;
    const dataEnd = dataStart + size;
    if (dataEnd > tar.length) throw new Error('Truncated tar archive');
    const type = tar[offset + 156];
    if (name === entryName) {
      if (type !== 0 && type !== 48) throw new Error(`${entryName} is not a regular file`);
      return tar.subarray(dataStart, dataEnd);
    }
    offset = dataStart + Math.ceil(size / 512) * 512;
  }
  throw new Error(`${entryName} was not found in the Node archive`);
}

function tarName(tar, offset) {
  const name = tarString(tar, offset, 100);
  if (!name) return '';
  const prefix = tarString(tar, offset + 345, 155);
  return prefix ? `${prefix}/${name}` : name;
}

function tarString(tar, offset, length) {
  const field = tar.subarray(offset, offset + length);
  const end = field.indexOf(0);
  return field.subarray(0, end < 0 ? field.length : end).toString('utf8');
}

function extractZip(archive, entryName) {
  let end = -1;
  const firstPossible = Math.max(0, archive.length - 22 - 65_535);
  for (let offset = archive.length - 22; offset >= firstPossible; offset--) {
    if (archive.readUInt32LE(offset) === 0x06054b50
      && archive.readUInt16LE(offset + 20) === archive.length - offset - 22) {
      end = offset;
      break;
    }
  }
  if (end < 0) throw new Error('Invalid ZIP end record');
  const entries = archive.readUInt16LE(end + 10);
  let offset = archive.readUInt32LE(end + 16);

  for (let index = 0; index < entries; index++) {
    if (offset + 46 > archive.length || archive.readUInt32LE(offset) !== 0x02014b50) {
      throw new Error('Invalid ZIP central directory');
    }
    const flags = archive.readUInt16LE(offset + 8);
    const method = archive.readUInt16LE(offset + 10);
    const compressedSize = archive.readUInt32LE(offset + 20);
    const uncompressedSize = archive.readUInt32LE(offset + 24);
    const nameLength = archive.readUInt16LE(offset + 28);
    const extraLength = archive.readUInt16LE(offset + 30);
    const commentLength = archive.readUInt16LE(offset + 32);
    const localOffset = archive.readUInt32LE(offset + 42);
    const nameStart = offset + 46;
    const nameEnd = nameStart + nameLength;
    if (nameEnd > archive.length) throw new Error('Truncated ZIP entry name');
    const name = archive.subarray(nameStart, nameEnd).toString('utf8');

    if (name === entryName) {
      if (flags & 1) throw new Error('Encrypted ZIP entries are not supported');
      if (localOffset + 30 > archive.length || archive.readUInt32LE(localOffset) !== 0x04034b50) {
        throw new Error('Invalid ZIP local header');
      }
      const dataStart = localOffset + 30
        + archive.readUInt16LE(localOffset + 26)
        + archive.readUInt16LE(localOffset + 28);
      const dataEnd = dataStart + compressedSize;
      if (dataEnd > archive.length) throw new Error('Truncated ZIP entry');
      const compressed = archive.subarray(dataStart, dataEnd);
      let executable;
      if (method === 0) executable = compressed;
      else if (method === 8) executable = inflateRawSync(compressed, { maxOutputLength: 256 * 1024 * 1024 });
      else throw new Error(`Unsupported ZIP compression method ${method}`);
      if (executable.length !== uncompressedSize) throw new Error('ZIP entry size mismatch');
      return executable;
    }
    offset = nameEnd + extraLength + commentLength;
  }
  throw new Error(`${entryName} was not found in the Node archive`);
}
