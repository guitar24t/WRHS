// Generates a personalized offline launcher: the browser client with this
// agent's relay URL and public key baked in, and a CSP that only allows
// connections to that relay.
//
// Distribute the file over a channel you trust (USB stick, your own device
// before travelling, a signed release). Opened from disk, it cannot be
// modified by a network proxy, which is what makes the pin trustworthy.

import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { encodeKey, fingerprint } from '@wrhs/protocol';

/**
 * The template next to this file (single-file agent builds ship it there),
 * else the client build in the source tree.
 */
export const DEFAULT_TEMPLATE = [
  fileURLToPath(new URL('./launcher.template.html', import.meta.url)),
  fileURLToPath(new URL('../../client/dist/launcher.template.html', import.meta.url)),
].find((p) => existsSync(p)) ?? fileURLToPath(new URL('../../client/dist/launcher.template.html', import.meta.url));

export interface LauncherOptions {
  relayUrl: string;
  agentPublicKeys: Uint8Array[];
  name: string;
  templatePath?: string;
}

export function renderLauncher(o: LauncherOptions): { html: string; sha256: string; fingerprint: string } {
  const path = o.templatePath ?? DEFAULT_TEMPLATE;
  if (!existsSync(path)) throw new Error(`launcher template not found at ${path}; run "npm run build" first`);
  const template = readFileSync(path, 'utf8');
  const relay = new URL(o.relayUrl);
  const wsOrigin = `${relay.protocol === 'http:' ? 'ws:' : 'wss:'}//${relay.host}`;
  const connectSrc = `${relay.origin} ${wsOrigin}`;
  const config = {
    relayUrl: relay.toString().replace(/\/$/, ''),
    agentKeys: o.agentPublicKeys.map(encodeKey),
    name: o.name,
  };
  const json = JSON.stringify(config).replace(/</g, '\\u003c');
  const html = template.replace(/__(CONFIG|CONNECT_SRC)__/g, (_, k: string) => (k === 'CONFIG' ? json : connectSrc));
  return {
    html,
    sha256: createHash('sha256').update(html).digest('hex'),
    fingerprint: fingerprint(o.agentPublicKeys[0]!),
  };
}
