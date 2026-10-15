import { test } from 'node:test';
import assert from 'node:assert/strict';
import { connect } from 'node:net';
import { WebSocket } from 'ws';
import { createRelay } from '../src/relay.ts';

function rawRequest(port: number, text: string, reset = false): Promise<string> {
  return new Promise((resolve) => {
    const sock = connect(port, '127.0.0.1', () => {
      sock.write(text);
      if (reset) {
        sock.resetAndDestroy();
        resolve('');
      }
    });
    let out = '';
    sock.on('data', (d) => (out += d.toString()));
    sock.on('close', () => resolve(out));
    sock.on('error', () => resolve(out));
  });
}

const UPGRADE =
  'Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n';

test('malformed upgrade requests and client resets do not crash the relay', async () => {
  const relay = createRelay({ agentTokens: new Map() });
  const port = await relay.listen(0, '127.0.0.1');
  try {
    const bad = await rawRequest(port, `GET //[ HTTP/1.1\r\nHost: x\r\n${UPGRADE}\r\n`);
    assert.match(bad, /^HTTP\/1\.1 400/);
    for (let i = 0; i < 20; i++) {
      await rawRequest(port, `GET /v1/agent/control?agent=${'0'.repeat(32)} HTTP/1.1\r\nHost: x\r\n${UPGRADE}\r\n`, true);
    }
    const health = await fetch(`http://127.0.0.1:${port}/healthz`);
    assert.equal(await health.text(), 'ok');
  } finally {
    await relay.close();
  }
});

test('session opens are limited per client address', async () => {
  const relay = createRelay({ agentTokens: null, opensPerMinute: 1000, maxSessionsPerIp: 2 });
  const port = await relay.listen(0, '127.0.0.1');
  const agentId = 'ab'.repeat(16);
  const ctl = new WebSocket(`ws://127.0.0.1:${port}/v1/agent/control?agent=${agentId}`);
  await new Promise((r) => ctl.once('open', r));
  try {
    const open = () =>
      fetch(`http://127.0.0.1:${port}/v1/lp/open`, { method: 'POST', body: JSON.stringify({ agent: agentId }) }).then(
        (r) => r.status,
      );
    assert.deepEqual([await open(), await open(), await open()], [200, 200, 429]);
  } finally {
    ctl.close();
    await relay.close();
  }
});

test('rejected agents are logged, at most once per 10 s', async () => {
  const known = 'cd'.repeat(16);
  const log: Record<string, unknown>[] = [];
  const relay = createRelay({
    agentTokens: new Map([[known, Buffer.alloc(32)]]),
    log: (event, fields) => log.push({ event, ...fields }),
  });
  const port = await relay.listen(0, '127.0.0.1');
  const tryAgent = (id: string, auth = '') =>
    rawRequest(port, `GET /v1/agent/control?agent=${id} HTTP/1.1\r\nHost: x\r\n${auth}${UPGRADE}\r\n`);
  try {
    assert.match(await tryAgent(known, 'Authorization: Bearer wrong\r\n'), /^HTTP\/1\.1 401/);
    assert.match(await tryAgent('ef'.repeat(16)), /^HTTP\/1\.1 401/);
    assert.match(await tryAgent('ef'.repeat(16)), /^HTTP\/1\.1 401/);
    const rejected = log.filter((e) => e.event === 'agent-rejected');
    assert.equal(rejected.length, 1);
    assert.deepEqual(rejected[0], { event: 'agent-rejected', agentId: known, reason: 'wrong token', ip: '127.0.0.1' });
  } finally {
    await relay.close();
  }
});
