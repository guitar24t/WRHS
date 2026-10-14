// Builds the browser client into self-contained HTML files:
//
//   dist/wrhs-launcher.html      generic offline launcher (asks for relay URL + agent key)
//   dist/launcher.template.html  template used by `wrhs-agent launcher` to make a
//                                personalized launcher with the agent key pinned
//   dist/hosted.html             page the relay can serve (convenience mode)
//
// Everything is inlined. The Content-Security-Policy only allows the exact
// inline script (by hash) and network connections to the relay, so the page
// cannot load or run anything else.

import { build } from 'esbuild';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const dist = join(here, 'dist');
mkdirSync(dist, { recursive: true });

const result = await build({
  entryPoints: [join(here, 'src/main.ts')],
  bundle: true,
  format: 'iife',
  platform: 'browser',
  target: ['chrome111', 'firefox115', 'safari16.4'],
  minify: true,
  write: false,
  charset: 'utf8',
  legalComments: 'eof',
  logLevel: 'warning',
});
const js = result.outputFiles[0].text;
if (/<\/script/i.test(js) || /<!--/.test(js)) throw new Error('bundle contains a sequence that would break inline embedding');

const scriptHash = createHash('sha256').update(js, 'utf8').digest('base64');

export function csp(connectSrc) {
  return [
    "default-src 'none'",
    `script-src 'sha256-${scriptHash}'`,
    "style-src 'unsafe-inline'",
    'img-src blob: data:',
    'media-src blob: data:',
    `connect-src ${connectSrc}`,
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
  ].join('; ');
}

const template = readFileSync(join(here, 'src/index.html'), 'utf8');
// Script and hash are fixed; config and connect-src stay as placeholders.
const launcherTemplate = template.replace(/__(CSP|SCRIPT)__/g, (_, k) =>
  k === 'SCRIPT' ? js : csp('__CONNECT_SRC__'),
);
if (!launcherTemplate.includes('__CONFIG__') || !launcherTemplate.includes('__CONNECT_SRC__')) {
  throw new Error('template placeholders missing');
}

const jsonForScript = (o) => JSON.stringify(o).replace(/</g, '\\u003c');
const render = (config, connectSrc) =>
  launcherTemplate.replace(/__(CONFIG|CONNECT_SRC)__/g, (_, k) => (k === 'CONFIG' ? jsonForScript(config) : connectSrc));

const outputs = {
  'launcher.template.html': launcherTemplate,
  'wrhs-launcher.html': render({}, 'https: wss: http://localhost:* ws://localhost:* http://127.0.0.1:* ws://127.0.0.1:*'),
  'hosted.html': render({ hosted: true }, "'self'"),
};
const sums = [];
for (const [name, content] of Object.entries(outputs)) {
  writeFileSync(join(dist, name), content);
  sums.push(`${createHash('sha256').update(content).digest('hex')}  ${name}`);
}
writeFileSync(join(dist, 'SHA256SUMS'), sums.join('\n') + '\n');
console.log(sums.join('\n'));
console.log(`bundle: ${(js.length / 1024).toFixed(0)} KiB`);
