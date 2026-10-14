// End-to-end for the built-in RDP engine: client code (Node) -> intercepting
// proxy -> relay -> agent -> RDP server. The browser's RDP client is played
// by these tests; it sends an RDCleanPath request and then RDP bytes on the
// RDP channel, and the agent opens and relays the connection.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import {
  AppChannel,
  ClientConnection,
  concat,
  fromUtf8,
  generateKeyPair,
  utf8,
} from '@wrhs/protocol';
import { GENERAL_ERROR, RDCLEANPATH_VERSION, decodeRdCleanPath, encodeRdCleanPath, rdCleanPathLength } from '@wrhs/agent';
import { PASSWORD, RDP_PASS, RDP_TARGET_NAME, RDP_USER, startStack, waitFor, type Stack } from './harness.ts';
import { PROTOCOL_HYBRID, PROTOCOL_SSL, TEST_CERT_PEM, x224Confirm, x224Request } from './fake-rdp-server.ts';

async function signedIn(stack: Stack) {
  const conn = new ClientConnection({
    relayUrl: stack.mitm.url,
    agentPublicKeys: [stack.agentKey.publicKey],
    deviceKey: generateKeyPair(),
    transport: 'websocket',
  });
  const app = new AppChannel(await conn.open());
  const rdp: Uint8Array[] = [];
  app.on('rdp', (d) => rdp.push(d));
  const targets = await app.login('alice', PASSWORD, stack.currentTotp());
  return { conn, app, rdp, targets, bytes: () => concat(...rdp) };
}

/** Plays the browser RDP client's opening: RDCleanPath request, then its response. */
async function startRdp(c: Awaited<ReturnType<typeof signedIn>>, x224 = x224Request(PROTOCOL_SSL | PROTOCOL_HYBRID)) {
  c.app.sendRdp(
    encodeRdCleanPath({ version: RDCLEANPATH_VERSION, destination: 'attacker.example:3389', proxyAuth: 'whatever', x224 }),
  );
  await waitFor(() => {
    const b = c.bytes();
    const len = b.length ? rdCleanPathLength(b) : null;
    return len !== null && b.length >= len;
  }, 5000, 'RDCleanPath response');
  const all = c.bytes();
  const len = rdCleanPathLength(all)!;
  c.rdp.length = 0;
  if (all.length > len) c.rdp.push(all.subarray(len));
  return decodeRdCleanPath(all.subarray(0, len));
}

test('built-in engine: the agent opens the RDP connection itself and relays it; the proxy learns nothing', async () => {
  const stack = await startStack({ rdp: true });
  try {
    const c = await signedIn(stack);
    const pc = c.targets.find((t) => t.id === 'this-pc');
    assert.deepEqual(pc, { id: 'this-pc', name: RDP_TARGET_NAME, protocol: 'rdp', engine: 'rdp', promptCredentials: true, username: RDP_USER });
    assert.equal(c.targets.find((t) => t.id === 'office-pc')?.engine, 'guacd');

    const opened = await c.app.open({ target: 'this-pc', width: 1280, height: 800, dpi: 96 });
    assert.equal(opened.engine, 'rdp');
    // The agent already holds a connection to the server, waiting for the request.
    await waitFor(() => stack.rdpServer!.connections.length === 1, 5000, 'agent connects to the RDP server');

    const res = await startRdp(c);
    assert.equal(res.error, undefined);
    assert.deepEqual(res.x224, new Uint8Array(x224Confirm(PROTOCOL_HYBRID)));
    assert.deepEqual(Buffer.from(res.serverCertChain![0]!), new X509Certificate(TEST_CERT_PEM).raw);
    // The browser's "destination" is ignored: only the configured server was contacted.
    assert.equal(stack.rdpServer!.connections.length, 1);

    // What would be CredSSP and the RDP session: plaintext here, TLS to the server.
    c.app.sendRdp(utf8(`credssp:${RDP_USER}:${RDP_PASS}`));
    await waitFor(() => fromUtf8(c.bytes()).includes(`ECHO:credssp:${RDP_USER}:${RDP_PASS}`), 5000, 'echo from the RDP server');
    assert.equal(stack.rdpServer!.connections[0]!.tls, true);
    assert.ok(stack.agentLog.some((e) => e.event === 'rdp-connected' && e.target === 'this-pc'));

    const seen = stack.mitm.captured();
    for (const secret of [PASSWORD, RDP_USER, RDP_PASS, RDP_TARGET_NAME, 'credssp', 'ECHO:', 'this-pc']) {
      assert.equal(seen.includes(secret), false, `proxy must not see "${secret}"`);
    }

    // Closing the desktop closes the RDP connection.
    c.app.closeDesktop();
    await waitFor(() => stack.rdpServer!.connections[0]!.closed, 5000, 'RDP connection closed');
    c.conn.close();
  } finally {
    await stack.close();
  }
});

test('built-in engine: when the RDP server ends the connection, the client is told', async () => {
  const stack = await startStack({ rdp: true });
  try {
    const c = await signedIn(stack);
    const { ref } = await c.app.open({ target: 'this-pc', width: 1024, height: 768, dpi: 96 });
    await startRdp(c);
    const closed = c.app.waitFor(['closed'], 5000);
    stack.rdpServer!.connections[0]!.socket.destroy();
    assert.equal((await closed).ref, ref);
    // A new desktop can be opened afterwards.
    await c.app.open({ target: 'this-pc', width: 1024, height: 768, dpi: 96 });
    const res = await startRdp(c);
    assert.equal(res.error, undefined);
    c.conn.close();
  } finally {
    await stack.close();
  }
});

test('built-in engine: a malformed request ends the desktop; a bad X.224 PDU gets an RDCleanPath error', async () => {
  const stack = await startStack({ rdp: true });
  try {
    const c = await signedIn(stack);
    await c.app.open({ target: 'this-pc', width: 1024, height: 768, dpi: 96 });
    const closed = c.app.waitFor(['closed'], 5000);
    c.app.sendRdp(utf8('GET / HTTP/1.1\r\n\r\n'));
    await closed;

    await c.app.open({ target: 'this-pc', width: 1024, height: 768, dpi: 96 });
    const res = await startRdp(c, Uint8Array.of(1, 2, 3, 4));
    assert.equal(res.error?.errorCode, GENERAL_ERROR);
    // The agent is ready for the next request.
    await c.app.open({ target: 'this-pc', width: 1024, height: 768, dpi: 96 });
    assert.equal((await startRdp(c)).error, undefined);
    c.conn.close();
  } finally {
    await stack.close();
  }
});

test('built-in engine: credentials in an open request are ignored (the browser RDP client signs in itself)', async () => {
  const stack = await startStack({ rdp: true });
  try {
    const c = await signedIn(stack);
    await c.app.open({ target: 'this-pc', width: 1024, height: 768, dpi: 96, credentials: { username: 'x', password: 'y' } });
    assert.equal((await startRdp(c)).error, undefined);
    assert.ok(!JSON.stringify(stack.agentLog).includes('"y"'));
    c.conn.close();
  } finally {
    await stack.close();
  }
});
