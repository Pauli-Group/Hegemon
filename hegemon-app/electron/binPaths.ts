import { app } from 'electron';
import { join, resolve } from 'node:path';

const resolveBinDir = () => {
  if (process.env.HEGEMON_BIN_DIR) {
    return process.env.HEGEMON_BIN_DIR;
  }
  if (app.isPackaged) {
    return join(process.resourcesPath, 'bin');
  }
  return resolve(process.cwd(), 'target/release');
};

export const resolveBinaryPath = (binary: string) => join(resolveBinDir(), binary);
