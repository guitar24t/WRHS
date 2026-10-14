// A stand-in RDP server: answers the X.224 Connection Request with a chosen
// security protocol, does the TLS handshake if that protocol needs one, and
// then echoes everything back prefixed with "ECHO:". Enough to test the
// agent's RDCleanPath gateway without a real Remote Desktop host.

import { readFileSync } from 'node:fs';
import { createServer, type Socket } from 'node:net';
import { TLSSocket } from 'node:tls';

const fixtures = new URL('../fixtures/', import.meta.url);
export const TEST_CERT_PEM = readFileSync(new URL('rdp-test-server.crt', fixtures), 'utf8');
const TEST_KEY_PEM = readFileSync(new URL('rdp-test-server.key', fixtures), 'utf8');

export const PROTOCOL_RDP = 0;
export const PROTOCOL_SSL = 1;
export const PROTOCOL_HYBRID = 2;

/** X.224 Connection Request with an RDP Negotiation Request for `protocols`. */
export function x224Request(protocols: number): Uint8Array {
  const b = Buffer.from([3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0, 0x01, 0x00, 0x08, 0x00, 0, 0, 0, 0]);
  b.writeUInt32LE(protocols, 15);
  return new Uint8Array(b);
}

/** X.224 Connection Confirm: a Negotiation Response (or Failure, type 3). */
export function x224Confirm(value: number, type = 0x02): Buffer {
  const b = Buffer.from([3, 0, 0, 19, 14, 0xd0, 0, 0, 0x12, 0x34, 0, type, 0, 0x08, 0x00, 0, 0, 0, 0]);
  b.writeUInt32LE(value, 15);
  return b;
}

export interface FakeRdpConnection {
  request: Buffer | null;
  /** Application data received after negotiation (decrypted if TLS). */
  received: Buffer[];
  tls: boolean;
  closed: boolean;
  socket: Socket;
}

export interface FakeRdpServer {
  port: number;
  connections: FakeRdpConnection[];
  /** "echo" (default) answers data with ECHO:...; "close" hangs up on the first data, like a server rejecting a sign-in. */
  mode: 'echo' | 'close';
  close(): Promise<void>;
}

export async function startFakeRdpServer(o: { protocol?: number; failureCode?: number } = {}): Promise<FakeRdpServer> {
  const connections: FakeRdpConnection[] = [];
  const state = { mode: 'echo' as 'echo' | 'close' };
  const server = createServer((socket) => {
    const conn: FakeRdpConnection = { request: null, received: [], tls: false, closed: false, socket };
    connections.push(conn);
    socket.on('error', () => {});
    socket.on('close', () => (conn.closed = true));
    let buf = Buffer.alloc(0);
    const onData = (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length < 4 || buf.length < buf.readUInt16BE(2)) return;
      socket.off('data', onData);
      conn.request = buf.subarray(0, buf.readUInt16BE(2));
      if (o.failureCode !== undefined) {
        socket.end(x224Confirm(o.failureCode, 0x03));
        return;
      }
      const protocol = o.protocol ?? PROTOCOL_SSL;
      socket.write(x224Confirm(protocol));
      let stream: Socket = socket;
      if (protocol !== PROTOCOL_RDP) {
        conn.tls = true;
        stream = new TLSSocket(socket, { isServer: true, key: TEST_KEY_PEM, cert: TEST_CERT_PEM });
        stream.on('error', () => {});
        // Keep the original socket wired for close and error only.
      }
      stream.on('data', (d: Buffer) => {
        conn.received.push(d);
        if (state.mode === 'close') socket.destroy();
        else stream.write(Buffer.concat([Buffer.from('ECHO:'), d]));
      });
    };
    socket.on('data', onData);
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  return {
    port: (server.address() as { port: number }).port,
    connections,
    get mode() {
      return state.mode;
    },
    set mode(m) {
      state.mode = m;
    },
    close: () =>
      new Promise((r) => {
        for (const c of connections) c.socket.destroy();
        server.close(() => r());
      }),
  };
}
