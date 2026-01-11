import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptsDir = dirname(fileURLToPath(import.meta.url));
const appRoot = dirname(scriptsDir);
const electronViteCli = join(appRoot, 'node_modules', 'electron-vite', 'bin', 'electron-vite.js');

const exec = (command, args, options = {}) => {
  const result = spawnSync(command, args, { stdio: 'inherit', ...options });
  if (result.error) {
    throw result.error;
  }
  if (typeof result.status === 'number' && result.status !== 0) {
    process.exit(result.status);
  }
};

const readJsonIfExists = (path) => {
  if (!existsSync(path)) {
    return null;
  }
  try {
    return JSON.parse(readFileSync(path, 'utf-8'));
  } catch {
    return null;
  }
};

const ensureMacDevApp = () => {
  const electronSourceApp = join(appRoot, 'node_modules', 'electron', 'dist', 'Electron.app');
  const electronPackageJson = join(appRoot, 'node_modules', 'electron', 'package.json');
  const electronVersion = JSON.parse(readFileSync(electronPackageJson, 'utf-8')).version;

  const devDir = join(appRoot, '.electron-vite');
  const devApp = join(devDir, 'Hegemon.app');
  const stampPath = join(devDir, 'hegemon-dev-app-stamp.json');

  const iconSource = join(appRoot, 'build', 'icon.icns');
  const iconStat = existsSync(iconSource) ? statSync(iconSource) : null;

  const desiredStamp = {
    electronVersion,
    appName: 'Hegemon',
    bundleId: 'com.hegemon.desktop.dev',
    iconFile: 'icon.icns',
    iconMtimeMs: iconStat?.mtimeMs ?? null,
    iconSize: iconStat?.size ?? null
  };

  const existingStamp = readJsonIfExists(stampPath);
  const needsElectronCopy = !existsSync(devApp) || existingStamp?.electronVersion !== electronVersion;

  if (needsElectronCopy) {
    rmSync(devApp, { recursive: true, force: true });
    mkdirSync(devDir, { recursive: true });
    exec('ditto', ['--noqtn', electronSourceApp, devApp]);
  }

  const shouldPatch =
    needsElectronCopy ||
    !existingStamp ||
    existingStamp.appName !== desiredStamp.appName ||
    existingStamp.bundleId !== desiredStamp.bundleId ||
    existingStamp.iconFile !== desiredStamp.iconFile ||
    existingStamp.iconMtimeMs !== desiredStamp.iconMtimeMs ||
    existingStamp.iconSize !== desiredStamp.iconSize;

  if (shouldPatch) {
    const plistPath = join(devApp, 'Contents', 'Info.plist');
    exec('plutil', ['-replace', 'CFBundleDisplayName', '-string', desiredStamp.appName, plistPath]);
    exec('plutil', ['-replace', 'CFBundleName', '-string', desiredStamp.appName, plistPath]);
    exec('plutil', ['-replace', 'CFBundleIdentifier', '-string', desiredStamp.bundleId, plistPath]);
    exec('plutil', ['-replace', 'CFBundleIconFile', '-string', desiredStamp.iconFile, plistPath]);

    const iconDest = join(devApp, 'Contents', 'Resources', desiredStamp.iconFile);
    if (iconStat) {
      copyFileSync(iconSource, iconDest);
    }

    exec('xattr', ['-cr', devApp]);
    exec('codesign', ['--force', '--sign', '-', devApp]);
    writeFileSync(stampPath, `${JSON.stringify(desiredStamp, null, 2)}\n`, 'utf-8');
  }

  return join(devApp, 'Contents', 'MacOS', 'Electron');
};

const env = { ...process.env };

if (process.platform === 'darwin') {
  try {
    env.ELECTRON_EXEC_PATH = ensureMacDevApp();
  } catch (error) {
    console.warn('[hegemon] Failed to prepare macOS dev app bundle. Falling back to default Electron.', error);
  }
}

const args = process.argv.slice(2);
exec(process.execPath, [electronViteCli, 'dev', ...args], { env });

