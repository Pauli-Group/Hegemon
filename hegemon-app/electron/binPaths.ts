import { app } from 'electron';
import { existsSync } from 'node:fs';
import { join, resolve } from 'node:path';

const resolveDevBinDir = () => {
  const candidates = [
    resolve(process.cwd(), 'target/release'),
    resolve(process.cwd(), '..', 'target/release'),
    resolve(app.getAppPath(), 'target/release'),
    resolve(app.getAppPath(), '..', 'target/release'),
    resolve(app.getAppPath(), '..', '..', 'target/release')
  ];

  const match = candidates.find((candidate) => existsSync(candidate));
  return match ?? resolve(process.cwd(), 'target/release');
};

const resolveBinDir = () => {
  if (process.env.HEGEMON_BIN_DIR) {
    return process.env.HEGEMON_BIN_DIR;
  }
  if (app.isPackaged) {
    return join(process.resourcesPath, 'bin');
  }
  return resolveDevBinDir();
};

export const resolveBinaryPath = (binary: string) => join(resolveBinDir(), binary);
