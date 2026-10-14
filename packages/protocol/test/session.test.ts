import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sessionPair, collect, waitFor, sleep, handshakePair } from './helpers.ts';
import { IntegrityError, paddedLength, SecureSession } from '../src/session.ts';
import { fromUtf8, utf8, randomBytes, readU64 } from '../src/bytes.ts';
import { PinMismatchError, startInitiator, respondToHs1, finishInitiator } from '../src/handshake.ts';
import { generateKeyPair } from '../src/noise.ts';
import { FRAME_RECORD } from '../src/wire.ts';

const fast = { initialRtoMs: 100, minRtoMs: 50, ackDelayMs: 5 };

function closeAll(...s: SecureSession[]) {
  for (const x of s) x.close();
}

test('handshake authenticates both sides and exchanges hellos', () => {
  const r = handshakePair();
  assert.deepEqual(r.client.remoteStatic, r.agentKey.publicKey);
  assert.deepEqual(r.agent.remoteStatic, r.clientKey.publicKey);
  assert.equal(r.agentHello.name, 'test-agent');
  assert.deepEqual(r.client.handshakeHash, r.agent.handshakeHash);
});

test('client refuses an agent whose key does not match the pin', () => {
  const init = startInitiator(generateKeyPair());
  const impostor = generateKeyPair();
  const resp = respondToHs1(impostor, init.frame, { v: 1, name: 'evil', software: 'x' });
  assert.throws(
    () => finishInitiator(init.hs, resp.frame, [generateKeyPair().publicKey], { v: 1, software: 'c' }),
    PinMismatchError,
  );
});

test('messages flow both ways on multiple channels, in order', async () => {
  const { a, b } = sessionPair({ a: fast, b: fast });
  const atB = collect(b);
  const atA = collect(a);
  for (let i = 0; i < 50; i++) a.send(1 + (i % 2), utf8(`a${i}`));
  for (let i = 0; i < 50; i++) b.send(2, utf8(`b${i}`));
  await waitFor(() => atB.length === 50 && atA.length === 50);
  assert.deepEqual(atB.map(fromUtf8), Array.from({ length: 50 }, (_, i) => `a${i}`));
  assert.deepEqual(atA.map(fromUtf8), Array.from({ length: 50 }, (_, i) => `b${i}`));
  await waitFor(() => a.bufferedAmount === 0 && b.bufferedAmount === 0, 2000, 'acks');
  closeAll(a, b);
});

test('large messages are fragmented and reassembled', async () => {
  const { a, b } = sessionPair({ a: fast, b: fast });
  const atB = collect(b, 2);
  const big = randomBytes(300_000);
  a.send(2, big);
  a.send(2, utf8('after'));
  await waitFor(() => atB.length === 2);
  assert.deepEqual(atB[0], big);
  assert.equal(fromUtf8(atB[1]!), 'after');
  closeAll(a, b);
});

test('records are padded into size buckets and nothing is readable on the wire', async () => {
  const { a, b, log } = sessionPair({ a: fast, b: fast });
  const atB = collect(b);
  a.send(1, utf8('SECRET-PASSWORD-123'));
  a.send(1, utf8('x'));
  await waitFor(() => atB.length === 2);
  const records = log.filter((l) => l.dir === 'a2b' && l.frame[0] === FRAME_RECORD && readU64(l.frame, 1) < 1n << 63n);
  assert.equal(records[0]!.frame.length, records[1]!.frame.length, 'short messages are indistinguishable by size');
  for (const { frame } of log) assert.ok(!Buffer.from(frame).includes('SECRET'));
  assert.equal(paddedLength(17), 128);
  assert.equal(paddedLength(600), 1024);
  assert.equal(paddedLength(5000), 6144);
  closeAll(a, b);
});

test('survives random loss with retransmission (exactly once, in order)', async () => {
  let n = 0;
  const { a, b } = sessionPair({
    a: fast,
    b: fast,
    wire: { filter: () => (n++ % 5 === 2 ? false : true) }, // drop 20%
  });
  const atB = collect(b);
  const atA = collect(a);
  for (let i = 0; i < 200; i++) {
    a.send(2, utf8(`m${i}`));
    if (i % 3 === 0) b.send(2, utf8(`r${i}`));
  }
  await waitFor(() => atB.length === 200 && atA.length === 67, 10_000, 'delivery under loss');
  assert.deepEqual(atB.map(fromUtf8), Array.from({ length: 200 }, (_, i) => `m${i}`));
  closeAll(a, b);
});

test('duplicated and replayed records are delivered once', async () => {
  const { a, b } = sessionPair({ a: fast, b: fast, wire: { filter: (f) => [f, f, f] } });
  const atB = collect(b);
  for (let i = 0; i < 20; i++) a.send(1, utf8(`d${i}`));
  await waitFor(() => atB.length >= 20);
  await sleep(100);
  assert.equal(atB.length, 20);
  assert.equal(b.closed, false);
  closeAll(a, b);
});

test('resumes after the outer link is replaced (proxy cut the connection)', async () => {
  const { a, b, attach } = sessionPair({ a: fast, b: fast });
  const atB = collect(b);
  a.send(1, utf8('before'));
  await waitFor(() => atB.length === 1);
  a.detach();
  b.detach();
  for (let i = 0; i < 10; i++) a.send(1, utf8(`during${i}`));
  await sleep(50);
  assert.equal(atB.length, 1);
  attach();
  await waitFor(() => atB.length === 11);
  assert.deepEqual(atB.map(fromUtf8).slice(1), Array.from({ length: 10 }, (_, i) => `during${i}`));
  closeAll(a, b);
});

test('a modified record kills the session with an IntegrityError', async () => {
  let count = 0;
  const { a, b } = sessionPair({
    a: fast,
    b: fast,
    wire: {
      filter: (f, dir) => {
        if (dir === 'a2b' && f[0] === FRAME_RECORD && readU64(f, 1) === 3n && count++ === 0) {
          const t = f.slice();
          t[t.length - 20]! ^= 0x40; // flip one bit of ciphertext
          return t;
        }
        return true;
      },
    },
  });
  const closed = new Promise<{ error?: Error }>((r) => b.on('close', r));
  const atB = collect(b);
  for (let i = 0; i < 6; i++) a.send(1, utf8(`t${i}`));
  const info = await closed;
  assert.ok(info.error instanceof IntegrityError);
  assert.equal(atB.length, 3, 'nothing after the tampered record is delivered');
  await waitFor(() => a.closed, 2000, 'peer notified');
});

test('a forged record (wrong key) is rejected', async () => {
  const { a, b } = sessionPair({ a: fast, b: fast });
  const other = sessionPair();
  const closed = new Promise<{ error?: Error }>((r) => b.on('close', r));
  // Capture a record sealed under a different session's keys and inject it.
  other.b.attach((f) => b.receive(f));
  other.b.send(1, utf8('injected'));
  const info = await closed;
  assert.ok(info.error instanceof IntegrityError);
  closeAll(a, other.a, other.b);
});

test('graceful close reaches the peer', async () => {
  const { a, b } = sessionPair({ a: fast, b: fast });
  const closed = new Promise<{ reason: string; remote: boolean }>((r) => b.on('close', r));
  a.close('user logged out');
  const info = await closed;
  assert.equal(info.reason, 'user logged out');
  assert.equal(info.remote, true);
  await waitFor(() => a.closed);
});

test('cadence mode sends fixed-interval, fixed-size records and the peer follows', async () => {
  const cadence = { intervalMs: 20, holdMs: 200, minPlaintext: 256, followPeer: true };
  const { a, b, log } = sessionPair({ a: { ...fast, cadence }, b: { ...fast, cadence: { ...cadence, minPlaintext: 1024 } } });
  const atB = collect(b);
  a.markInteractive();
  await sleep(30);
  a.send(2, utf8('k'));
  await sleep(250);
  assert.equal(atB.length, 1);
  const a2b = log.filter((l) => l.dir === 'a2b' && readU64(l.frame, 1) < 1n << 63n);
  assert.ok(a2b.length >= 8, `expected chaff stream, saw ${a2b.length} records`);
  const sizes = new Set(a2b.map((l) => l.frame.length));
  assert.equal(sizes.size, 1, 'keystroke record is indistinguishable from chaff by size');
  assert.ok(b.cadenceActive || log.some((l) => l.dir === 'b2a' && l.frame.length >= 1024 + 25), 'peer entered cadence');
  await sleep(300);
  assert.equal(a.cadenceActive, false, 'cadence stops after hold period');
  closeAll(a, b);
});

test('backpressure: bufferedAmount drains once the peer acknowledges', async () => {
  const { a, b } = sessionPair({ a: { ...fast, highWaterMark: 64 * 1024 }, b: fast, wire: { delayMs: 5 } });
  collect(b);
  let drained = false;
  a.on('drain', () => (drained = true));
  for (let i = 0; i < 10; i++) a.send(2, randomBytes(16 * 1024));
  assert.ok(a.bufferedAmount >= 64 * 1024);
  await waitFor(() => drained, 3000, 'drain');
  closeAll(a, b);
});
