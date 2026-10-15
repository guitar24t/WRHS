import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type IncomingHttpHeaders } from 'node:http';
import type { AddressInfo } from 'node:net';
import { generateKeyPair } from '@wrhs/protocol';
import { createAgent } from '../src/agent.ts';
import { rejectionHint } from '../src/relay-link.ts';
import { DEFAULT_POLICY, type AgentConfig } from '../src/config.ts';

test('the agent sends a User-Agent, explains a rejection by Cloudflare and tries again', async () => {
  // Answers like Cloudflare's Browser Integrity Check.
  const seen: IncomingHttpHeaders[] = [];
  const server = createServer();
  server.on('upgrade', (req, socket) => {
    seen.push(req.headers);
    socket.end('HTTP/1.1 403 Forbidden\r\nServer: cloudflare\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const config: AgentConfig = {
    name: 'test-agent',
    relayUrl: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    relayToken: 'token',
    keyFile: '',
    guacd: { host: '127.0.0.1', port: 4822 },
    users: [],
    targets: [],
    policy: DEFAULT_POLICY,
  };
  const log: Record<string, unknown>[] = [];
  const agent = createAgent(config, generateKeyPair(), { log: (event, fields) => log.push({ event, ...fields }) });
  agent.start();
  try {
    // The second attempt comes after a 1 s backoff.
    for (let i = 0; i < 50 && seen.length < 2; i++) await new Promise((r) => setTimeout(r, 100));
    assert.ok(seen.length >= 2, 'the agent tries again after a rejection');
    assert.equal(log.filter((e) => e.event === 'relay-error').length, 0, 'a rejection is not also reported as an error');
    assert.match(seen[0]?.['user-agent'] ?? '', /^wrhs-agent\/\S+ node\/\d/);
    const rejected = log.find((e) => e.event === 'relay-rejected');
    assert.equal(rejected?.status, 403);
    assert.equal(rejected?.server, 'cloudflare');
    assert.match(String(rejected?.hint), /Browser Integrity Check/);
  } finally {
    agent.stop();
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
  }
});

test('rejection hints point at the likely cause', () => {
  assert.match(rejectionHint(401), /registration/);
  assert.match(rejectionHint(530, 'cloudflare'), /tunnel/);
  assert.match(rejectionHint(404), /relayUrl/);
  assert.match(rejectionHint(403), /proxy or firewall/);
});
