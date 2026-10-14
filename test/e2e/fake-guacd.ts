// A stand-in for guacd that speaks the Guacamole handshake, records the
// connection parameters it receives, and echoes client instructions back.

import { createServer, type Server, type Socket } from 'node:net';
import { encodeInstruction, parseInstructions } from '@wrhs/agent';

export interface FakeGuacd {
  port: number;
  connections: { params: Record<string, string>; received: string[][] }[];
  /** End every remote desktop connection, as if the RDP server went away. */
  dropConnections(): void;
  close(): Promise<void>;
}

const ARG_NAMES = ['VERSION_1_5_0', 'hostname', 'port', 'domain', 'username', 'password', 'width', 'height', 'dpi', 'security'];

export async function startFakeGuacd(opts: { bannerAfterReady?: string[][] } = {}): Promise<FakeGuacd> {
  const connections: FakeGuacd['connections'] = [];
  const sockets = new Set<Socket>();
  const server: Server = createServer((sock) => {
    sockets.add(sock);
    sock.on('close', () => sockets.delete(sock));
    sock.setEncoding('utf8');
    let buf = '';
    let phase: 'select' | 'connect' | 'live' = 'select';
    const conn = { params: {} as Record<string, string>, received: [] as string[][] };
    connections.push(conn);
    sock.on('data', (chunk: string) => {
      buf += chunk;
      const { instructions, consumed } = parseInstructions(buf);
      buf = buf.slice(consumed);
      for (const [op, ...args] of instructions) {
        if (phase === 'select' && op === 'select') {
          sock.write(encodeInstruction(['args', ...ARG_NAMES]));
          phase = 'connect';
        } else if (phase === 'connect' && op === 'connect') {
          ARG_NAMES.forEach((n, i) => (conn.params[n] = args[i] ?? ''));
          // "ready" plus extra instructions in the same write, to exercise
          // the agent's leftover handling.
          const extra = (opts.bannerAfterReady ?? []).map(encodeInstruction).join('');
          sock.write(encodeInstruction(['ready', '$fake-connection']) + extra);
          phase = 'live';
        } else if (phase === 'live') {
          conn.received.push([op!, ...args]);
          if (op === 'disconnect') sock.end();
          else sock.write(encodeInstruction(['echo', op!, ...args]));
        }
      }
    });
    sock.on('error', () => sock.destroy());
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const addr = server.address();
  return {
    port: typeof addr === 'object' && addr ? addr.port : 0,
    connections,
    dropConnections: () => {
      for (const s of sockets) s.destroy();
    },
    close: () =>
      new Promise((r) => {
        for (const s of sockets) s.destroy();
        server.close(() => r());
      }),
  };
}
