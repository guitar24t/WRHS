// A "TLS-intercepting proxy" for tests. It sits between the client and the
// relay and sees the outer HTTP layer in plaintext, exactly what a corporate
// inspection proxy sees after decrypting TLS. It records every byte, can cut
// connections, and can modify traffic.

import { createServer, request, type IncomingMessage, type Server } from 'node:http';
import type { Duplex } from 'node:stream';
import { WebSocketServer, WebSocket, type RawData } from 'ws';

export type Tamper = (dir: 'up' | 'down', data: Uint8Array) => Uint8Array;

export interface Mitm {
  url: string;
  /** Everything the proxy observed: request lines, headers, bodies, WebSocket messages. */
  captured(): Buffer;
  wsMessages: { dir: 'up' | 'down'; data: Uint8Array }[];
  httpRequests: string[];
  tamper: Tamper | null;
  /** Simulate the proxy killing every connection. */
  cutAll(): void;
  /** Refuse WebSocket upgrades (forces the long-poll fallback). */
  blockWebSockets: boolean;
  close(): Promise<void>;
}

export async function startMitm(upstream: string): Promise<Mitm> {
  const chunks: Buffer[] = [];
  const record = (b: Buffer | Uint8Array | string) => chunks.push(Buffer.from(b as Uint8Array));
  const wss = new WebSocketServer({ noServer: true, perMessageDeflate: false });
  const live = new Set<WebSocket>();
  const sockets = new Set<Duplex>();

  const m: Mitm = {
    url: '',
    captured: () => Buffer.concat(chunks),
    wsMessages: [],
    httpRequests: [],
    tamper: null,
    blockWebSockets: false,
    cutAll() {
      for (const ws of live) ws.terminate();
      for (const s of sockets) s.destroy();
    },
    close: async () => {
      m.cutAll();
      await new Promise<void>((r) => server.close(() => r()));
    },
  };

  const recordHead = (req: IncomingMessage) => {
    const head = `${req.method} ${req.url} HTTP/1.1\r\n${Object.entries(req.headers)
      .map(([k, v]) => `${k}: ${String(v)}`)
      .join('\r\n')}\r\n\r\n`;
    record(head);
    m.httpRequests.push(`${req.method} ${req.url}`);
  };

  const server: Server = createServer((req, res) => {
    recordHead(req);
    const body: Buffer[] = [];
    req.on('data', (c: Buffer) => body.push(c));
    req.on('end', () => {
      let up = Buffer.concat(body);
      record(up);
      if (m.tamper && up.length) up = Buffer.from(m.tamper('up', up));
      const u = new URL(req.url!, upstream);
      const preq = request(
        u,
        { method: req.method, headers: { ...req.headers, host: u.host, 'content-length': String(up.length) } },
        (pres) => {
          const rb: Buffer[] = [];
          pres.on('data', (c: Buffer) => rb.push(c));
          pres.on('end', () => {
            let down = Buffer.concat(rb);
            record(`HTTP/1.1 ${pres.statusCode}\r\n`);
            record(down);
            if (m.tamper && down.length) down = Buffer.from(m.tamper('down', down));
            const headers = { ...pres.headers, 'content-length': String(down.length) };
            res.writeHead(pres.statusCode ?? 502, headers);
            res.end(down);
          });
          pres.on('error', () => res.destroy());
        },
      );
      preq.on('error', () => res.destroy());
      preq.end(up);
    });
  });
  server.on('connection', (s) => {
    sockets.add(s);
    s.on('close', () => sockets.delete(s));
  });

  server.on('upgrade', (req: IncomingMessage, socket: Duplex, head: Buffer) => {
    recordHead(req);
    if (m.blockWebSockets) {
      socket.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n');
      return;
    }
    const target = new URL(req.url!, upstream);
    target.protocol = target.protocol === 'https:' ? 'wss:' : 'ws:';
    const headers: Record<string, string> = {};
    if (req.headers.authorization) headers.authorization = req.headers.authorization;
    const upstreamWs = new WebSocket(target, { headers, perMessageDeflate: false });
    const pendingUp: { data: Buffer; binary: boolean }[] = [];
    wss.handleUpgrade(req, socket, head, (client) => {
      live.add(client);
      live.add(upstreamWs);
      const forward = (dir: 'up' | 'down', to: WebSocket, data: RawData, binary: boolean) => {
        let buf = Array.isArray(data) ? Buffer.concat(data) : Buffer.from(data as Buffer);
        record(buf);
        m.wsMessages.push({ dir, data: new Uint8Array(buf) });
        if (m.tamper && binary) buf = Buffer.from(m.tamper(dir, buf));
        if (to.readyState === WebSocket.OPEN) to.send(buf, { binary });
        else if (dir === 'up') pendingUp.push({ data: buf, binary });
      };
      client.on('message', (d: RawData, b: boolean) => forward('up', upstreamWs, d, b));
      upstreamWs.on('message', (d: RawData, b: boolean) => forward('down', client, d, b));
      upstreamWs.on('open', () => {
        for (const p of pendingUp.splice(0)) upstreamWs.send(p.data, { binary: p.binary });
      });
      const closeBoth = () => {
        live.delete(client);
        live.delete(upstreamWs);
        if (client.readyState <= WebSocket.OPEN) client.terminate();
        if (upstreamWs.readyState <= WebSocket.OPEN) upstreamWs.terminate();
      };
      client.on('close', closeBoth);
      upstreamWs.on('close', closeBoth);
      client.on('error', closeBoth);
      upstreamWs.on('error', closeBoth);
    });
  });

  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const addr = server.address();
  m.url = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`;
  return m;
}
