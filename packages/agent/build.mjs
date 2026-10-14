// Bundles the agent (CLI, relay link, RDP gateway and the `ws` dependency)
// into one ES module, dist/agent/wrhs-agent.mjs, with the browser launcher
// template beside it. That pair is all a machine needs besides Node.js, and
// is what the Windows installer copies (see deploy/windows).

import { build } from 'esbuild';
import { copyFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, '../../dist/agent');
const template = join(here, '../client/dist/launcher.template.html');
if (!existsSync(template)) throw new Error('build the client first (npm run build -w @wrhs/client)');
mkdirSync(out, { recursive: true });

await build({
  entryPoints: [join(here, 'src/cli.ts')],
  outfile: join(out, 'wrhs-agent.mjs'),
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node22',
  // ws loads these optional native helpers if present; it works without them.
  external: ['bufferutil', 'utf-8-validate'],
  // ws is CommonJS; give the bundle a require() for its optional imports.
  banner: { js: "import { createRequire as __wrhsCreateRequire } from 'node:module'; const require = __wrhsCreateRequire(import.meta.url);" },
  legalComments: 'eof',
  logLevel: 'warning',
});
copyFileSync(template, join(out, 'launcher.template.html'));
console.log(`agent bundle: ${out}`);
