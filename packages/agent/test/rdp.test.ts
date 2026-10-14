// The agent's half of the built-in RDP engine: the RDCleanPath codec
// (checked against IronRDP's own test vectors) and the gateway that opens
// the connection to the RDP server.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { createServer } from 'node:net';
import {
  GENERAL_ERROR,
  NEGOTIATION_ERROR,
  RDCLEANPATH_VERSION,
  decodeRdCleanPath,
  encodeRdCleanPath,
  isConnectionRequest,
  normalizeFingerprint,
  openRdpBridge,
  parseConnectionConfirm,
  rdCleanPathLength,
} from '../src/index.ts';
import {
  PROTOCOL_HYBRID,
  PROTOCOL_RDP,
  PROTOCOL_SSL,
  TEST_CERT_PEM,
  startFakeRdpServer,
  x224Confirm,
  x224Request,
} from '../../../test/e2e/fake-rdp-server.ts';

const hex = (s: string) => Uint8Array.from(s.match(/../g)!.map((b) => parseInt(b, 16)));
const DEADBEEF = Uint8Array.of(0xde, 0xad, 0xbe, 0xff);

// From IronRDP crates/ironrdp-testsuite-core/tests/rdcleanpath.rs
const REQUEST_DER = hex(
  '3032a00402020d3ea20d0c0b64657374696e6174696f6ea30c0c0a70726f78792061757468a5050c03504342a6060404deadbeff',
);
const RESPONSE_SUCCESS_DER = hex(
  '3034a00402020d3ea6060404deadbeffa714301204' + '04deadbeff0404deadbeff0404deadbeff' + 'a90e0c0c3139322e3136382e372e3935',
);
const RESPONSE_HTTP_ERROR_DER = hex('3015a00402020d3ea10d300ba003020101a104020201f4');
const RESPONSE_TLS_ERROR_DER = hex('3014a00402020d3ea10c300aa003020101a303020130');

test('RDCleanPath encoding matches IronRDP byte for byte', () => {
  assert.deepEqual(
    encodeRdCleanPath({ version: RDCLEANPATH_VERSION, destination: 'destination', proxyAuth: 'proxy auth', preconnectionBlob: 'PCB', x224: DEADBEEF }),
    REQUEST_DER,
  );
  assert.deepEqual(
    encodeRdCleanPath({ version: RDCLEANPATH_VERSION, x224: DEADBEEF, serverCertChain: [DEADBEEF, DEADBEEF, DEADBEEF], serverAddr: '192.168.7.95' }),
    RESPONSE_SUCCESS_DER,
  );
  assert.deepEqual(encodeRdCleanPath({ version: RDCLEANPATH_VERSION, error: { errorCode: GENERAL_ERROR, httpStatusCode: 500 } }), RESPONSE_HTTP_ERROR_DER);
  assert.deepEqual(encodeRdCleanPath({ version: RDCLEANPATH_VERSION, error: { errorCode: GENERAL_ERROR, tlsAlertCode: 48 } }), RESPONSE_TLS_ERROR_DER);
});

test('RDCleanPath decoding and length detection', () => {
  const req = decodeRdCleanPath(REQUEST_DER);
  assert.equal(req.version, RDCLEANPATH_VERSION);
  assert.equal(req.destination, 'destination');
  assert.equal(req.proxyAuth, 'proxy auth');
  assert.equal(req.preconnectionBlob, 'PCB');
  assert.deepEqual(req.x224, DEADBEEF);
  assert.deepEqual(decodeRdCleanPath(RESPONSE_HTTP_ERROR_DER).error, { errorCode: 1, httpStatusCode: 500 });
  assert.deepEqual(decodeRdCleanPath(RESPONSE_SUCCESS_DER).serverCertChain, [DEADBEEF, DEADBEEF, DEADBEEF]);
  for (const der of [REQUEST_DER, RESPONSE_SUCCESS_DER, RESPONSE_HTTP_ERROR_DER, RESPONSE_TLS_ERROR_DER]) {
    assert.equal(rdCleanPathLength(der), der.length);
  }
  assert.equal(rdCleanPathLength(Uint8Array.of()), null);
  assert.equal(rdCleanPathLength(Uint8Array.of(0x30)), null);
  assert.equal(rdCleanPathLength(Uint8Array.of(0x30, 0x82, 0x01)), null);
  assert.equal(rdCleanPathLength(Uint8Array.of(0x30, 0x82, 0x01, 0x00)), 4 + 256);
  assert.throws(() => rdCleanPathLength(Uint8Array.of(0x16, 0x03)), /not an RDCleanPath PDU/);
  // Long values round-trip (multi-byte DER lengths).
  const big = new Uint8Array(70_000).fill(7);
  const round = decodeRdCleanPath(encodeRdCleanPath({ version: RDCLEANPATH_VERSION, serverCertChain: [big] }));
  assert.deepEqual(round.serverCertChain, [big]);
  assert.throws(() => decodeRdCleanPath(REQUEST_DER.subarray(0, 20)), /DER/);
  assert.throws(() => decodeRdCleanPath(Uint8Array.of(...REQUEST_DER, 0)), /trailing/);
});

test('X.224 helpers', () => {
  assert.equal(isConnectionRequest(x224Request(3)), true);
  assert.equal(isConnectionRequest(x224Confirm(1)), false);
  assert.equal(isConnectionRequest(DEADBEEF), false);
  assert.deepEqual(parseConnectionConfirm(x224Confirm(PROTOCOL_HYBRID)), { failure: false, protocol: PROTOCOL_HYBRID });
  assert.deepEqual(parseConnectionConfirm(x224Confirm(5, 0x03)), { failure: true, protocol: 5 });
  // No negotiation data at all: standard RDP security.
  assert.deepEqual(parseConnectionConfirm(Uint8Array.of(3, 0, 0, 11, 6, 0xd0, 0, 0, 0x12, 0x34, 0)), { failure: false, protocol: 0 });
  assert.equal(normalizeFingerprint('AB:cd:01'), 'abcd01');
});

const request = (protocols = PROTOCOL_SSL | PROTOCOL_HYBRID) => ({
  version: RDCLEANPATH_VERSION,
  destination: 'ignored',
  proxyAuth: 'ignored',
  x224: x224Request(protocols),
});

function readUntil(stream: NodeJS.ReadableStream, text: string): Promise<string> {
  return new Promise((resolve) => {
    let got = '';
    stream.on('data', (d: Buffer) => {
      got += d.toString();
      if (got.includes(text)) resolve(got);
    });
    stream.resume(); // the bridge hands the stream over paused
  });
}

test('TLS: the gateway hands the browser the confirm and the server certificate, then relays plaintext', async () => {
  const server = await startFakeRdpServer({ protocol: PROTOCOL_HYBRID });
  try {
    const bridge = await openRdpBridge(request(), { host: '127.0.0.1', port: server.port });
    assert.equal(bridge.error, undefined);
    assert.equal(bridge.selectedProtocol, PROTOCOL_HYBRID);
    const res = decodeRdCleanPath(bridge.response);
    assert.equal(res.error, undefined);
    assert.deepEqual(res.x224, new Uint8Array(x224Confirm(PROTOCOL_HYBRID)));
    const cert = new X509Certificate(TEST_CERT_PEM);
    assert.equal(res.serverCertChain?.length, 1);
    assert.deepEqual(Buffer.from(res.serverCertChain![0]!), cert.raw);
    assert.equal(bridge.certSha256, normalizeFingerprint(cert.fingerprint256));
    assert.match(res.serverAddr ?? '', /^127\.0\.0\.1:\d+$/);
    // The server got the browser's request unchanged.
    assert.deepEqual(new Uint8Array(server.connections[0]!.request!), x224Request(PROTOCOL_SSL | PROTOCOL_HYBRID));
    // Plaintext in, TLS to the server, plaintext back.
    const echoed = readUntil(bridge.stream!, 'ECHO:hello');
    bridge.stream!.write('hello');
    await echoed;
    assert.equal(server.connections[0]!.tls, true);
    bridge.stream!.destroy();
  } finally {
    await server.close();
  }
});

test('TLS: a pinned certificate fingerprint is enforced', async () => {
  const server = await startFakeRdpServer({ protocol: PROTOCOL_SSL });
  try {
    const cert = new X509Certificate(TEST_CERT_PEM);
    const ok = await openRdpBridge(request(), { host: '127.0.0.1', port: server.port }, { certSha256: cert.fingerprint256 });
    assert.ok(ok.stream);
    ok.stream.destroy();
    const bad = await openRdpBridge(request(), { host: '127.0.0.1', port: server.port }, { certSha256: 'ab'.repeat(32) });
    assert.equal(bad.stream, null);
    assert.match(bad.error ?? '', /does not match the pinned fingerprint/);
    assert.equal(decodeRdCleanPath(bad.response).error?.errorCode, GENERAL_ERROR);
  } finally {
    await server.close();
  }
});

test('standard RDP security: no TLS layer, empty certificate chain', async () => {
  const server = await startFakeRdpServer({ protocol: PROTOCOL_RDP });
  try {
    const bridge = await openRdpBridge(request(PROTOCOL_RDP), { host: '127.0.0.1', port: server.port });
    const res = decodeRdCleanPath(bridge.response);
    assert.deepEqual(res.serverCertChain, []);
    const echoed = readUntil(bridge.stream!, 'ECHO:x');
    bridge.stream!.write('x');
    await echoed;
    assert.equal(server.connections[0]!.tls, false);
    bridge.stream!.destroy();
  } finally {
    await server.close();
  }
});

test('negotiation failure is passed on with the server confirm', async () => {
  const server = await startFakeRdpServer({ failureCode: 5 /* HYBRID_REQUIRED_BY_SERVER */ });
  try {
    const bridge = await openRdpBridge(request(PROTOCOL_SSL), { host: '127.0.0.1', port: server.port });
    assert.equal(bridge.stream, null);
    const res = decodeRdCleanPath(bridge.response);
    assert.equal(res.error?.errorCode, NEGOTIATION_ERROR);
    assert.deepEqual(res.x224, new Uint8Array(x224Confirm(5, 0x03)));
  } finally {
    await server.close();
  }
});

test('unreachable server and malformed requests get RDCleanPath errors', async () => {
  // A port with nothing listening.
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, '127.0.0.1', r));
  const port = (probe.address() as { port: number }).port;
  await new Promise<void>((r) => probe.close(() => r()));
  const refused = await openRdpBridge(request(), { host: '127.0.0.1', port });
  assert.equal(refused.stream, null);
  assert.deepEqual(decodeRdCleanPath(refused.response).error, { errorCode: GENERAL_ERROR, wsaLastError: 10061 });

  const server = await startFakeRdpServer();
  try {
    for (const bad of [
      { version: 1, x224: x224Request(1) },
      { version: RDCLEANPATH_VERSION },
      { version: RDCLEANPATH_VERSION, x224: DEADBEEF },
    ]) {
      const r = await openRdpBridge(bad, { host: '127.0.0.1', port: server.port });
      assert.equal(r.stream, null);
      assert.equal(decodeRdCleanPath(r.response).error?.errorCode, GENERAL_ERROR);
    }
    // Nothing was forwarded to the server for any of them.
    await new Promise((r) => setTimeout(r, 50));
    assert.ok(server.connections.every((c) => c.request === null));
  } finally {
    await server.close();
  }
});
