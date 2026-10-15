#!/usr/bin/env node
// Relay entry point. Configuration comes from the environment:
//
//   RELAY_PORT=8080               listen port
//   RELAY_HOST=0.0.0.0            listen address
//   RELAY_TLS_CERT / RELAY_TLS_KEY  terminate TLS here (otherwise put Caddy/nginx in front)
//   RELAY_AGENTS_FILE=agents.json {"<agentId>": "<sha256 hex of agent token>", ...}
//                                 (read at startup; restart after changing it)
//   RELAY_OPEN_REGISTRATION=1     accept any agent (development only!)
//   RELAY_HOSTED_CLIENT=path      serve the hosted web client at / (convenience mode)
//   RELAY_TRUST_PROXY=1           use X-Forwarded-For for rate limiting
//   RELAY_OPENS_PER_MINUTE=30     session opens + resumes per client IP per minute
//   RELAY_MAX_SESSIONS_PER_IP=16  concurrent sessions per client IP
//   RELAY_MAX_SESSIONS_PER_AGENT=32

import { readFileSync } from 'node:fs';
import { parseAgentsFile } from './agents-file.ts';
import { createRelay } from './relay.ts';

function loadAgentTokens(): Map<string, Buffer> | null {
  if (process.env.RELAY_OPEN_REGISTRATION === '1') {
    console.warn('WARNING: RELAY_OPEN_REGISTRATION=1 lets anyone register any agent id. Development only.');
    return null;
  }
  const file = process.env.RELAY_AGENTS_FILE;
  if (!file) throw new Error('set RELAY_AGENTS_FILE (or RELAY_OPEN_REGISTRATION=1 for development)');
  return parseAgentsFile(readFileSync(file, 'utf8'), file);
}

function intEnv<K extends string>(name: string, key: K): Partial<Record<K, number>> {
  const v = process.env[name];
  if (v === undefined || v === '') return {};
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1) throw new Error(`${name} must be a positive integer`);
  return { [key]: n } as Partial<Record<K, number>>;
}

const tlsCert = process.env.RELAY_TLS_CERT;
const tlsKey = process.env.RELAY_TLS_KEY;

const relay = createRelay({
  agentTokens: loadAgentTokens(),
  tls: tlsCert && tlsKey ? { cert: tlsCert, key: tlsKey } : null,
  hostedClientFile: process.env.RELAY_HOSTED_CLIENT || null,
  trustProxy: process.env.RELAY_TRUST_PROXY === '1',
  ...intEnv('RELAY_OPENS_PER_MINUTE', 'opensPerMinute'),
  ...intEnv('RELAY_MAX_SESSIONS_PER_IP', 'maxSessionsPerIp'),
  ...intEnv('RELAY_MAX_SESSIONS_PER_AGENT', 'maxSessionsPerAgent'),
  log: (event, fields) => console.log(JSON.stringify({ time: new Date().toISOString(), event, ...fields })),
});

const port = await relay.listen(Number(process.env.RELAY_PORT ?? 8080), process.env.RELAY_HOST ?? '0.0.0.0');
console.log(JSON.stringify({ time: new Date().toISOString(), event: 'listening', port, tls: Boolean(tlsCert) }));

for (const sig of ['SIGINT', 'SIGTERM'] as const) {
  process.on(sig, () => {
    relay.close().finally(() => process.exit(0));
  });
}
