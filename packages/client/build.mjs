// Builds the browser client into self-contained HTML files:
//
//   dist/wrhs-launcher.html      generic offline launcher (asks for relay URL + agent key)
//   dist/launcher.template.html  template used by `wrhs-agent launcher` to make a
//                                personalized launcher with the agent key pinned
//   dist/hosted.html             page the relay can serve (convenience mode)
//
// Everything is inlined. The Content-Security-Policy only allows the exact
// inline script (by hash), compiling the bundled WebAssembly, and network
// connections to the relay, so the page cannot load or run anything else.

import { build } from 'esbuild';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';

const here = dirname(fileURLToPath(import.meta.url));
const dist = join(here, 'dist');
mkdirSync(dist, { recursive: true });

/**
 * Adapts IronRDP's published bundle (pinned version) to the launcher:
 *  - its WebAssembly is embedded as a data: URL that it fetch()es, which the
 *    CSP would have to allow; instead embed it gzip-compressed and hand the
 *    bytes over directly (the init code awaits any thenable);
 *  - its `new WebSocket(gateway)` becomes our socket over the encrypted
 *    session, so the RDP client cannot open network connections at all.
 */
const ironRdpPlugin = {
  name: 'wrhs-ironrdp',
  setup(b) {
    b.onLoad({ filter: /iron-remote-desktop-rdp[\\/]iron-remote-desktop-rdp\.js$/ }, (args) => {
      let src = readFileSync(args.path, 'utf8');
      const m = src.match(/const (\w+) = "data:application\/wasm;base64,([A-Za-z0-9+/=]+)";/);
      if (!m) throw new Error('IronRDP: embedded WebAssembly not found; check the package version');
      const gz = gzipSync(Buffer.from(m[2], 'base64'), { level: 9 }).toString('base64');
      src = src.replace(m[0], () => `const ${m[1]} = { then: (ok, fail) => __wrhsInflateWasm(${JSON.stringify(gz)}).then(ok, fail) };`);
      const sockets = src.split('new WebSocket(').length - 1;
      if (sockets !== 1) throw new Error(`IronRDP: expected one WebSocket constructor call, found ${sockets}`);
      src = src.replace('new WebSocket(', 'new __WrhsRdpSocket(');
      const imports =
        `import { inflateWasm as __wrhsInflateWasm } from ${JSON.stringify(join(here, 'src/wasm-loader.ts'))};\n` +
        `import { RdpTunnelSocket as __WrhsRdpSocket } from ${JSON.stringify(join(here, 'src/rdp-socket.ts'))};\n`;
      return { contents: imports + src, loader: 'js' };
    });
  },
};

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
  plugins: [ironRdpPlugin],
});
const js = result.outputFiles[0].text;
if (/<\/script/i.test(js) || /<!--/.test(js)) throw new Error('bundle contains a sequence that would break inline embedding');

const scriptHash = createHash('sha256').update(js, 'utf8').digest('base64');

export function csp(connectSrc) {
  return [
    "default-src 'none'",
    // 'wasm-unsafe-eval' allows compiling WebAssembly only (not JS eval).
    `script-src 'sha256-${scriptHash}' 'wasm-unsafe-eval'`,
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
