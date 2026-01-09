import { defineConfig } from 'electron-vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'node:path';

export default defineConfig({
  main: {
    entry: resolve(__dirname, 'electron/main.ts')
  },
  preload: {
    input: {
      index: resolve(__dirname, 'electron/preload.ts')
    }
  },
  renderer: {
    plugins: [react()],
    resolve: {
      alias: {
        '@': resolve(__dirname, 'src')
      }
    }
  }
});
