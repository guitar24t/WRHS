#!/usr/bin/env node
// Relay entry point. Configuration comes from the environment:
//
//   RELAY_PORT=8080               listen port
//   RELAY_HOST=0.0.0.0            listen address
//   RELAY_TLS_CERT / RELAY_TLS_KEY  terminate TLS here (otherwise put Caddy/nginx in front)
//   RELAY_AGENTS_FILE=agents.json {"<agentId>": "<sha256 hex of agent token>", ...}
//   RELAY_OPEN_REGISTRATION=1     accept any agent (development only!)
//   RELAY_HOSTED_CLIENT=path      serve the hosted web client at / (convenience mode)
//   RELAY_TRUST_PROXY=1           use X-Forwarded-For for rate limiting

import { readFileSync } from 'node:fs';
import { createRelay } from './relay.ts';

function loadAgentTokens(): Map<string, Buffer> | null {
  if (process.env.RELAY_OPEN_REGISTRATION === '1') {
    console.warn('WARNING: RELAY_OPEN_REGISTRATION=1 lets anyone register any agent id. Development only.');
    return null;
  }
  const file = process.env.RELAY_AGENTS_FILE;
  if (!file) throw new Error('set RELAY_AGENTS_FILE (or RELAY_OPEN_REGISTRATION=1 for development)');
  const raw = JSON.parse(readFileSync(file, 'utf8')) as Record<string, string>;
  const map = new Map<string, Buffer>();
  for (const [id, hash] of Object.entries(raw)) {
    if (!/^[0-9a-f]{32}$/.test(id) || !/^[0-9a-f]{64}$/.test(hash)) throw new Error(`bad entry for ${id} in ${file}`);
    map.set(id, Buffer.from(hash, 'hex'));
  }
  return map;
}

const tlsCert = process.env.RELAY_TLS_CERT;
const tlsKey = process.env.RELAY_TLS_KEY;

const relay = createRelay({
  agentTokens: loadAgentTokens(),
  tls: tlsCert && tlsKey ? { cert: tlsCert, key: tlsKey } : null,
  hostedClientFile: process.env.RELAY_HOSTED_CLIENT || null,
  trustProxy: process.env.RELAY_TRUST_PROXY === '1',
  log: (event, fields) => console.log(JSON.stringify({ time: new Date().toISOString(), event, ...fields })),
});

const port = await relay.listen(Number(process.env.RELAY_PORT ?? 8080), process.env.RELAY_HOST ?? '0.0.0.0');
console.log(JSON.stringify({ time: new Date().toISOString(), event: 'listening', port, tls: Boolean(tlsCert) }));

for (const sig of ['SIGINT', 'SIGTERM'] as const) {
  process.on(sig, () => {
    relay.close().finally(() => process.exit(0));
  });
}
