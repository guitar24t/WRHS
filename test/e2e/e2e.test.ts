// End-to-end: browser-side code (Node) -> intercepting proxy -> relay -> agent -> guacd.
//
// The proxy records everything it can see. These tests prove that, even with
// the outer TLS layer completely removed, the proxy learns none of the
// secrets, cannot tamper undetected, and cannot impersonate the agent.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { WebSocketServer } from 'ws';
import {
  AppChannel,
  AuthError,
  ClientConnection,
  IntegrityError,
  PinMismatchError,
  FRAME_HS1,
  FRAME_HS3,
  FRAME_RECORD,
  fromUtf8,
  generateKeyPair,
  relayFrame,
  respondToHs1,
  type ConnectionState,
  type TransportKind,
} from '@wrhs/protocol';
import { DESKTOP_NAME, INTERNAL_HOST, PASSWORD, RDP_PASS, RDP_USER, startStack, waitFor, type Stack } from './harness.ts';

async function connect(stack: Stack, transport: 'auto' | TransportKind = 'auto') {
  const conn = new ClientConnection({
    relayUrl: stack.mitm.url,
    agentPublicKeys: [stack.agentKey.publicKey],
    deviceKey: generateKeyPair(),
    transport,
    wsTimeoutMs: 2000,
  });
  const states: ConnectionState[] = [];
  conn.on('state', (s) => states.push(s));
  const session = await conn.open();
  const app = new AppChannel(session);
  let guacText = '';
  const decoder = new TextDecoder();
  app.on('guac', (d) => (guacText += decoder.decode(d, { stream: true })));
  return { conn, session, app, states, guac: () => guacText };
}

async function loginAndOpen(stack: Stack, c: Awaited<ReturnType<typeof connect>>) {
  const totp = stack.currentTotp();
  const targets = await c.app.login('alice', PASSWORD, totp);
  assert.deepEqual(targets.map((t) => t.id), ['office-pc']);
  assert.equal(targets[0]!.promptCredentials, true);
  await c.app.open({
    target: 'office-pc',
    width: 1280,
    height: 800,
    dpi: 96,
    credentials: { username: RDP_USER, password: RDP_PASS },
  });
  await waitFor(() => c.guac().includes(DESKTOP_NAME), 5000, 'guacd banner');
  return totp;
}

function assertNoSecrets(stack: Stack, extra: string[]) {
  const seen = stack.mitm.captured();
  assert.ok(seen.length > 5000, 'proxy saw real traffic');
  for (const secret of [PASSWORD, RDP_USER, RDP_PASS, INTERNAL_HOST, DESKTOP_NAME, 'office-pc', 'Office PC', 'alice', ...extra]) {
    assert.equal(seen.includes(secret), false, `proxy must not see "${secret}"`);
  }
}

for (const transport of ['websocket', 'longpoll'] as const) {
  test(`full session over ${transport}: works, and the proxy sees no secrets`, async () => {
    const stack = await startStack();
    if (transport === 'longpoll') stack.mitm.blockWebSockets = true;
    try {
      const c = await connect(stack, 'auto');
      assert.equal(c.conn.transportKind, transport);
      assert.equal(c.conn.agentHello?.name, 'test-agent');
      const totp = await loginAndOpen(stack, c);
      assert.deepEqual(c.app.limits, { idleTimeoutSeconds: 3600, maxSessionSeconds: 43200 }, 'agent announces its limits');

      // Keystroke through the tunnel, echoed by guacd.
      c.app.sendGuac('3.key,5.65307,1.1;');
      await waitFor(() => c.guac().includes('4.echo,3.key,5.65307,1.1;'), 5000, 'echo');

      // guacd received the RDP parameters that only exist inside the tunnel.
      const params = stack.guacd.connections[0]!.params;
      assert.equal(params.hostname, INTERNAL_HOST);
      assert.equal(params.username, RDP_USER);
      assert.equal(params.password, RDP_PASS);
      assert.equal(params.width, '1280');

      assertNoSecrets(stack, [totp, '65307']);
      assert.ok(stack.agentLog.some((e) => e.event === 'login-ok' && e.user === 'alice'));
      c.conn.close();
      await waitFor(() => c.conn.state === 'closed', 5000, 'close');
    } finally {
      await stack.close();
    }
  });
}

test('session survives the proxy cutting every connection', async () => {
  const stack = await startStack();
  try {
    const c = await connect(stack, 'websocket');
    await loginAndOpen(stack, c);
    stack.mitm.cutAll();
    // Typed while the outer connection is down: must arrive exactly once.
    c.app.sendGuac('3.key,2.97,1.1;');
    c.app.sendGuac('3.key,2.97,1.0;');
    await waitFor(() => c.states.includes('reconnecting'), 5000, 'reconnecting state');
    await waitFor(() => c.guac().includes('4.echo,3.key,2.97,1.0;'), 15_000, 'echo after resume');
    assert.equal(c.conn.state, 'open');
    const keys = stack.guacd.connections[0]!.received.filter((i) => i[0] === 'key');
    assert.deepEqual(keys, [['key', '97', '1'], ['key', '97', '0']], 'delivered exactly once, in order');
    c.conn.close();
  } finally {
    await stack.close();
  }
});

test('a proxy that modifies traffic is detected and the session is killed', async () => {
  const stack = await startStack();
  try {
    const c = await connect(stack, 'websocket');
    await loginAndOpen(stack, c);
    const closed = new Promise<{ error?: Error }>((r) => c.session.on('close', r));
    let tampered = false;
    stack.mitm.tamper = (dir, data) => {
      if (dir !== 'down' || tampered || data[0] !== FRAME_RECORD) return data;
      tampered = true;
      const t = Uint8Array.from(data);
      t[t.length - 1]! ^= 0x01;
      return t;
    };
    c.app.sendGuac('3.key,2.98,1.1;');
    const info = await closed;
    assert.ok(tampered);
    assert.ok(info.error instanceof IntegrityError, 'client reports tampering');
    assert.equal(c.guac().includes('2.98'), false, 'modified data is never delivered');
  } finally {
    await stack.close();
  }
});

test('an active MITM posing as the agent is rejected before any secret is sent', async () => {
  // The "proxy" terminates the inner layer itself with its own key.
  const impostorKey = generateKeyPair();
  const realAgentKey = generateKeyPair();
  const wss = new WebSocketServer({ port: 0, host: '127.0.0.1' });
  const received: number[] = [];
  wss.on('connection', (ws) => {
    ws.send(relayFrame({ t: 'session', sid: 'fake' }));
    ws.send(relayFrame({ t: 'ready' }));
    ws.on('message', (data: Buffer) => {
      const frame = new Uint8Array(data);
      received.push(frame[0]!);
      if (frame[0] === FRAME_HS1) {
        ws.send(respondToHs1(impostorKey, frame, { v: 1, name: 'totally-the-agent', software: 'x' }).frame);
      }
    });
  });
  await new Promise((r) => wss.once('listening', r));
  const port = (wss.address() as { port: number }).port;
  try {
    const conn = new ClientConnection({
      relayUrl: `http://127.0.0.1:${port}`,
      agentPublicKeys: [realAgentKey.publicKey],
      deviceKey: generateKeyPair(),
      transport: 'websocket',
    });
    await assert.rejects(conn.open(), PinMismatchError);
    await new Promise((r) => setTimeout(r, 100));
    assert.deepEqual(received, [FRAME_HS1], 'client sent nothing after detecting the impostor');
    assert.ok(!received.includes(FRAME_HS3) && !received.includes(FRAME_RECORD));
  } finally {
    wss.close();
  }
});

test('wrong password or TOTP is rejected, and the session is closed after 3 attempts', async () => {
  const stack = await startStack();
  try {
    const c = await connect(stack, 'websocket');
    const left: (number | undefined)[] = [];
    for (const [user, pw, code] of [
      ['alice', 'wrong-password-123', stack.currentTotp()],
      ['alice', PASSWORD, '000000'],
      ['mallory', PASSWORD, stack.currentTotp()],
    ] as const) {
      await assert.rejects(c.app.login(user, pw, code), (err: unknown) => {
        assert.ok(err instanceof AuthError);
        left.push(err.attemptsLeft);
        return true;
      });
    }
    assert.deepEqual(left, [2, 1, 0], 'the agent reports attempts left on this connection');
    await waitFor(() => c.session.closed, 5000, 'session closed after 3 failures');
    assert.equal(stack.guacd.connections.length, 0);
  } finally {
    await stack.close();
  }
});

test('garbage sent while a failed login is pending does not crash the agent', async () => {
  const stack = await startStack();
  try {
    const c = await connect(stack, 'websocket');
    await c.app.authMethods();
    c.app.sendControl({ t: 'auth', user: 'alice', password: 'wrong-password-123', totp: '000000' });
    await new Promise((r) => setTimeout(r, 300));
    c.session.send(1, new TextEncoder().encode('not json'));
    await waitFor(() => stack.agentLog.some((e) => e.event === 'session-end'), 5000, 'agent ends the session');
    await new Promise((r) => setTimeout(r, 1200)); // past the 1 s failure delay
    // The agent is still alive and serving.
    const d = await connect(stack, 'websocket');
    await d.app.login('alice', PASSWORD, stack.currentTotp());
    d.conn.close();
  } finally {
    await stack.close();
  }
});

test('closing a desktop and reopening at once works; a new open replaces the old desktop', async () => {
  const stack = await startStack();
  try {
    const c = await connect(stack, 'websocket');
    await loginAndOpen(stack, c);
    const closedRefs: (number | undefined)[] = [];
    c.app.on('control', (m) => {
      if (m.t === 'closed') closedRefs.push(m.ref);
    });
    const size = { target: 'office-pc', width: 800, height: 600, dpi: 96, credentials: { username: RDP_USER, password: RDP_PASS } };
    // Close and immediately reopen: the agent must answer the new request.
    c.app.closeDesktop();
    const second = await c.app.open(size);
    // Open again without closing: replaces the second desktop.
    const third = await c.app.open(size);
    assert.ok(third > second);
    await waitFor(() => stack.guacd.connections.length === 3, 5000, 'three guacd connections');
    await new Promise((r) => setTimeout(r, 300));
    assert.deepEqual(closedRefs, [], 'replaced or closed desktops are not reported as ended');
    // The current desktop works.
    c.app.sendGuac('3.key,2.99,1.1;');
    await waitFor(() => stack.guacd.connections[2]!.received.some((i) => i[0] === 'key'), 5000, 'input reaches the newest desktop');
    // When it ends on the remote side, the notice carries its reference.
    stack.guacd.dropConnections();
    await waitFor(() => closedRefs.length === 1, 5000, 'closed notice');
    assert.deepEqual(closedRefs, [third]);
    c.conn.close();
  } finally {
    await stack.close();
  }
});

test('a TOTP code cannot be replayed in a second session', async () => {
  const stack = await startStack();
  try {
    const totp = stack.currentTotp();
    const a = await connect(stack, 'websocket');
    await a.app.login('alice', PASSWORD, totp);
    const b = await connect(stack, 'websocket');
    await assert.rejects(b.app.login('alice', PASSWORD, totp), AuthError);
    a.conn.close();
    b.conn.close();
  } finally {
    await stack.close();
  }
});

test('agent offline is reported cleanly', async () => {
  const stack = await startStack();
  try {
    const conn = new ClientConnection({
      relayUrl: stack.mitm.url,
      agentPublicKeys: [generateKeyPair().publicKey], // an agent id nobody registered
      deviceKey: generateKeyPair(),
      transport: 'websocket',
    });
    await assert.rejects(conn.open(), /agent-offline/);
  } finally {
    await stack.close();
  }
});

test('proxy sees only fixed-size records for small messages', async () => {
  const stack = await startStack();
  try {
    const c = await connect(stack, 'websocket');
    await loginAndOpen(stack, c);
    const before = stack.mitm.wsMessages.length;
    c.app.sendGuac('3.key,1.1,1.1;');
    c.app.sendGuac('5.mouse,4.1000,3.700,1.0;');
    c.app.sendGuac('4.sync,13.1700000000000;');
    await waitFor(() => (c.guac().match(/4\.echo/g) ?? []).length >= 3, 5000, 'echoes');
    const up = stack.mitm.wsMessages.slice(before).filter((m) => m.dir === 'up' && m.data[0] === FRAME_RECORD);
    const sizes = new Set(up.slice(0, 3).map((m) => m.data.length));
    assert.equal(sizes.size, 1, `different instructions produced different sizes: ${[...sizes]}`);
    c.conn.close();
  } finally {
    await stack.close();
  }
});

// Silence "unused" for helpers that exist for debugging.
void fromUtf8;
