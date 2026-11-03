import { app } from 'electron';
import { existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { requirePreMainnetManifest } from './preMainnetIdentity';

const binaryNames = (binary: string) => (process.platform === 'win32' ? [`${binary}.exe`, binary] : [binary]);

const resolveEnvBinary = (binary: string) => {
  if (app.isPackaged) {
    return null;
  }
  if (!process.env.HEGEMON_BIN_DIR) {
    return null;
  }
  const resolvedDir = resolve(process.env.HEGEMON_BIN_DIR);
  const match = binaryNames(binary).find((name) => existsSync(join(resolvedDir, name)));
  return match ? join(resolvedDir, match) : null;
};

const resolveDevBinary = (binary: string) => {
  const candidates = [
    resolve(process.cwd(), 'target/release'),
    resolve(process.cwd(), '..', 'target/release'),
    resolve(app.getAppPath(), 'target/release'),
    resolve(app.getAppPath(), '..', 'target/release'),
    resolve(app.getAppPath(), '..', '..', 'target/release'),
    resolve(process.cwd(), 'target/debug'),
    resolve(process.cwd(), '..', 'target/debug'),
    resolve(app.getAppPath(), 'target/debug'),
    resolve(app.getAppPath(), '..', 'target/debug'),
    resolve(app.getAppPath(), '..', '..', 'target/debug')
  ];

  for (const candidate of candidates) {
    const match = binaryNames(binary).find((name) => existsSync(join(candidate, name)));
    if (match) {
      return join(candidate, match);
    }
  }
  return null;
};

const resolvePackagedBinary = (binary: string) => {
  const base = join(process.resourcesPath, 'bin');
  const match = binaryNames(binary).find((name) => existsSync(join(base, name)));
  return match ? join(base, match) : null;
};

export const resolveBinaryPath = (binary: string) => {
  if (app.isPackaged) {
    const packagedBinary = resolvePackagedBinary(binary);
    if (packagedBinary) {
      return packagedBinary;
    }
    throw new Error(`Missing packaged binary: ${binary}`);
  }

  const envBinary = resolveEnvBinary(binary);
  if (envBinary) {
    return envBinary;
  }

  const devBinary = resolveDevBinary(binary);
  if (devBinary) {
    return devBinary;
  }

  const fallback = join(resolve(process.cwd(), 'target/release'), binaryNames(binary)[0]);
  throw new Error(
    `Binary "${binary}" not found. Build it with "cargo build -p ${binary} --release" (or --debug) and retry. Expected build output at ${fallback}`
  );
};

export const resolvePreMainnetManifestPath = (): string => {
  const suffix = ['config', 'testnet', '0.11', 'network-manifest.json'];
  const candidates = app.isPackaged
    ? [join(process.resourcesPath, ...suffix)]
    : [resolve(process.cwd(), ...suffix), resolve(process.cwd(), '..', ...suffix),
       resolve(app.getAppPath(), ...suffix), resolve(app.getAppPath(), '..', ...suffix),
       resolve(app.getAppPath(), '..', '..', ...suffix)];
  const candidate = candidates.find((path) => existsSync(path));
  if (!candidate) throw new Error('The v0.11 pre-mainnet network manifest is missing.');
  return requirePreMainnetManifest(candidate);
};
