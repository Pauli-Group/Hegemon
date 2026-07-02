const BASE_CHILD_ENV_KEYS = [
  'HOME',
  'USERPROFILE',
  'HOMEDRIVE',
  'HOMEPATH',
  'APPDATA',
  'LOCALAPPDATA',
  'XDG_CONFIG_HOME',
  'XDG_DATA_HOME',
  'XDG_CACHE_HOME',
  'TMPDIR',
  'TMP',
  'TEMP',
  'PATH',
  'Path',
  'SystemRoot',
  'WINDIR',
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  'RUST_LOG',
  'RUST_BACKTRACE',
  'LOG_FORMAT',
  'NO_COLOR'
] as const;

const hasValue = (value: string | undefined): value is string =>
  value !== undefined && value.trim() !== '';

export const createBaseChildEnv = (): NodeJS.ProcessEnv => {
  const env: NodeJS.ProcessEnv = {};
  for (const key of BASE_CHILD_ENV_KEYS) {
    const value = process.env[key];
    if (hasValue(value)) {
      env[key] = value;
    }
  }
  return env;
};

export const copyParentEnv = (env: NodeJS.ProcessEnv, keys: readonly string[]) => {
  for (const key of keys) {
    const value = process.env[key];
    if (hasValue(value)) {
      env[key] = value;
    }
  }
};

export const setEnvValue = (
  env: NodeJS.ProcessEnv,
  key: string,
  value: string | number | null | undefined
) => {
  if (value === null || value === undefined) {
    delete env[key];
    return;
  }
  const normalized = String(value);
  if (!hasValue(normalized)) {
    delete env[key];
    return;
  }
  env[key] = normalized;
};

export const applyEnvDefaults = (env: NodeJS.ProcessEnv, defaults: Record<string, string>) => {
  for (const [key, value] of Object.entries(defaults)) {
    if (!hasValue(env[key])) {
      env[key] = value;
    }
  }
};
