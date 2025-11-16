import { readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '..', '..');
const source = resolve(repoRoot, 'docs', 'ui', 'brand_tokens.json');
const target = resolve(repoRoot, 'dashboard-ui', 'src', 'design', 'brand_tokens.json');

const contents = await readFile(source, 'utf-8');
await writeFile(target, contents);

console.log(`Copied brand tokens from ${source} → ${target}`);
