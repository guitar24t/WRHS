// WRHS relay: a blind rendezvous between browsers and agents.
//
// The relay pairs a browser session with an agent and copies opaque frames
// between them. It never has keys: every frame it forwards is either a Noise
// handshake message or a ChaCha20-Poly1305 record sealed end to end. A fully
// compromised relay (or a TLS-intercepting proxy in front of it) can drop,
// delay or count frames, but cannot read or undetectably modify them.
//
// Endpoints
//   GET  /healthz
//   WS   /v1/client/ws?agent=<id>|?sid=<sid>     browser, WebSocket transport
//   POST /v1/lp/open | /v1/lp/<sid>/tx | rx     browser, long-poll transport
//   WS   /v1/agent/control?agent=<id>           agent control channel (Bearer token)
//   WS   /v1/agent/session/<sid>                agent data socket per session (Bearer token)

import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { Duplex } from 'node:stream';
import { WebSocketServer, WebSocket, type RawData } from 'ws';
import {
  decodeFrameBatch,
  encodeFrameBatch,
  FRAME_RELAY,
  MAX_FRAME,
  relayFrame,
  type RelayMessage,
} from '@wrhs/protocol';

export interface RelayOptions {
  /** agentId -> SHA-256(token). null allows any agent to register (development only). */
  agentTokens: Map<string, Buffer> | null;
  /** Serve the hosted web client from this file (convenience mode). */
  hostedClientFile?: string | null;
  tls?: { cert: string; key: string } | null;
  maxSessionsPerAgent?: number;
  sessionGraceMs?: number;
  longPollWaitMs?: number;
  /** Max session opens per client IP per minute. */
  opensPerMinute?: number;
  trustProxy?: boolean;
  log?: (event: string, fields?: Record<string, unknown>) => void;
}

type ClientAttachment =
  | { kind: 'ws'; ws: WebSocket }
  | { kind: 'lp'; queue: Uint8Array[]; queuedBytes: number; waiter: ((frames: Uint8Array[] | null) => void) | null; lastPollAt: number };

interface RelaySession {
  sid: string;
  agentId: string;
  client: ClientAttachment | null;
  agent: WebSocket | null;
  clientGoneAt: number | null;
  agentGoneAt: number | null;
  bytesUp: number;
  bytesDown: number;
  createdAt: number;
}

interface AgentControl {
  id: string;
  ws: WebSocket;
}

const HIGH_WATER = 8 * 1024 * 1024;
const LP_MAX_BODY = 4 * 1024 * 1024;
const LP_RESPONSE_MAX = 1024 * 1024;
const AGENT_SESSION_DONE = 4000;

export interface Relay {
  server: Server;
  listen(port: number, host?: string): Promise<number>;
  close(): Promise<void>;
  stats(): { agents: number; sessions: number };
}

export function createRelay(opts: RelayOptions): Relay {
  const log = opts.log ?? (() => {});
  const maxSessionsPerAgent = opts.maxSessionsPerAgent ?? 32;
  const graceMs = opts.sessionGraceMs ?? 120_000;
  const lpWaitMs = opts.longPollWaitMs ?? 25_000;
  const opensPerMinute = opts.opensPerMinute ?? 60;

  const agents = new Map<string, AgentControl>();
  const sessions = new Map<string, RelaySession>();
  const openBuckets = new Map<string, { tokens: number; at: number }>();

  const hostedClient = opts.hostedClientFile ? readFileSync(opts.hostedClientFile) : null;

  const server: Server = opts.tls
    ? createHttpsServer({ cert: readFileSync(opts.tls.cert), key: readFileSync(opts.tls.key) })
    : createHttpServer();
  const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_FRAME, perMessageDeflate: false });

  // ------------------------------------------------------------ helpers

  function clientIp(req: IncomingMessage): string {
    if (opts.trustProxy) {
      // Use the hop appended by our own reverse proxy (the last one); earlier
      // entries are whatever the client chose to send.
      const xff = req.headers['x-forwarded-for'];
      const last = (Array.isArray(xff) ? xff.join(',') : xff)?.split(',').pop()?.trim();
      if (last) return last;
    }
    return req.socket.remoteAddress ?? 'unknown';
  }

  function allowOpen(ip: string): boolean {
    const now = Date.now();
    const b = openBuckets.get(ip) ?? { tokens: opensPerMinute, at: now };
    b.tokens = Math.min(opensPerMinute, b.tokens + ((now - b.at) / 60_000) * opensPerMinute);
    b.at = now;
    openBuckets.set(ip, b);
    if (b.tokens < 1) return false;
    b.tokens -= 1;
    return true;
  }

  function bearer(req: IncomingMessage): string | null {
    const h = req.headers.authorization;
    return h?.startsWith('Bearer ') ? h.slice(7).trim() : null;
  }

  function agentAuthorized(agentId: string, token: string | null): boolean {
    if (!/^[0-9a-f]{32}$/.test(agentId)) return false;
    if (opts.agentTokens === null) return true;
    const expected = opts.agentTokens.get(agentId);
    if (!expected || !token) return false;
    const got = createHash('sha256').update(token).digest();
    return got.length === expected.length && timingSafeEqual(got, expected);
  }

  function newSid(): string {
    return randomBytes(18).toString('base64url');
  }

  function sendToClient(s: RelaySession, frame: Uint8Array): void {
    const c = s.client;
    if (!c) return; // dropped; the end-to-end layer retransmits
    s.bytesDown += frame.length;
    if (c.kind === 'ws') {
      if (c.ws.readyState !== WebSocket.OPEN) return;
      c.ws.send(frame);
      if (c.ws.bufferedAmount > HIGH_WATER) throttle(s.agent, () => c.ws.bufferedAmount < HIGH_WATER / 2 || s.client !== c);
      return;
    }
    if (c.queuedBytes > HIGH_WATER * 2) return; // client is not polling; drop
    c.queue.push(frame);
    c.queuedBytes += frame.length;
    if (c.waiter) flushLongPoll(c);
    if (c.queuedBytes > HIGH_WATER) throttle(s.agent, () => c.queuedBytes < HIGH_WATER / 2 || s.client !== c);
  }

  function sendToAgent(s: RelaySession, frame: Uint8Array): void {
    if (frame.length === 0 || frame[0] === FRAME_RELAY) return; // endpoints cannot speak for the relay
    const a = s.agent;
    if (!a || a.readyState !== WebSocket.OPEN) return;
    s.bytesUp += frame.length;
    a.send(frame);
    if (a.bufferedAmount > HIGH_WATER && s.client?.kind === 'ws') {
      const cw = s.client.ws;
      throttle(cw, () => a.bufferedAmount < HIGH_WATER / 2);
    }
  }

  function throttle(source: WebSocket | null, resumeWhen: () => boolean): void {
    if (!source || source.isPaused) return;
    source.pause();
    const t = setInterval(() => {
      if (resumeWhen() || source.readyState !== WebSocket.OPEN) {
        clearInterval(t);
        source.resume();
      }
    }, 25);
  }

  function relayToClient(s: RelaySession, msg: RelayMessage): void {
    sendToClient(s, relayFrame(msg));
  }

  function control(ws: WebSocket | null, msg: Record<string, unknown>): void {
    if (ws?.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg));
  }

  function flushLongPoll(c: Extract<ClientAttachment, { kind: 'lp' }>): void {
    if (!c.waiter || c.queue.length === 0) return;
    const out: Uint8Array[] = [];
    let size = 0;
    while (c.queue.length > 0 && (out.length === 0 || size + c.queue[0]!.length <= LP_RESPONSE_MAX)) {
      const f = c.queue.shift()!;
      out.push(f);
      size += f.length;
    }
    c.queuedBytes -= size;
    const w = c.waiter;
    c.waiter = null;
    w(out);
  }

  function detachClient(s: RelaySession): void {
    const c = s.client;
    if (!c) return;
    s.client = null;
    s.clientGoneAt = Date.now();
    if (c.kind === 'ws') c.ws.close(1000, 'replaced');
    else c.waiter?.(null);
  }

  function attachClient(s: RelaySession, c: ClientAttachment): void {
    detachClient(s);
    s.client = c;
    s.clientGoneAt = null;
    if (c.kind === 'ws') c.ws.send(relayFrame({ t: 'session', sid: s.sid }));
    if (s.agent) {
      relayToClient(s, { t: 'ready' });
      control(s.agent, { t: 'client-attached' });
    }
  }

  /** Validate and create a new session for a client, asking the agent to join. */
  function createSession(agentId: string, ip: string): RelaySession | { error: string; message: string } {
    if (!/^[0-9a-f]{32}$/.test(agentId)) return { error: 'bad-request', message: 'invalid agent id' };
    if (!allowOpen(ip)) return { error: 'rate-limited', message: 'too many connection attempts' };
    const ctl = agents.get(agentId);
    if (!ctl) return { error: 'agent-offline', message: 'the agent is not connected to this relay' };
    let count = 0;
    for (const s of sessions.values()) if (s.agentId === agentId) count++;
    if (count >= maxSessionsPerAgent) return { error: 'busy', message: 'too many sessions for this agent' };
    const s: RelaySession = {
      sid: newSid(),
      agentId,
      client: null,
      agent: null,
      clientGoneAt: null,
      agentGoneAt: Date.now(),
      bytesUp: 0,
      bytesDown: 0,
      createdAt: Date.now(),
    };
    sessions.set(s.sid, s);
    control(ctl.ws, { t: 'open', sid: s.sid });
    log('session-open', { sid: s.sid, agentId, ip });
    return s;
  }

  function endSession(s: RelaySession, reason: string): void {
    if (!sessions.delete(s.sid)) return;
    if (s.client?.kind === 'ws') {
      s.client.ws.send(relayFrame({ t: 'error', code: 'session-closed', message: reason }));
      s.client.ws.close(1000, 'session closed');
    } else if (s.client?.kind === 'lp') {
      s.client.queue.push(relayFrame({ t: 'error', code: 'session-closed', message: reason }));
      flushLongPoll(s.client);
    }
    s.agent?.close(1000, 'session closed');
    log('session-close', {
      sid: s.sid,
      agentId: s.agentId,
      reason,
      bytesUp: s.bytesUp,
      bytesDown: s.bytesDown,
      seconds: Math.round((Date.now() - s.createdAt) / 1000),
    });
  }

  const sweeper = setInterval(() => {
    const now = Date.now();
    for (const s of sessions.values()) {
      if (s.client?.kind === 'lp' && !s.client.waiter && now - s.client.lastPollAt > lpWaitMs + 15_000) {
        detachClient(s);
      }
      if (s.clientGoneAt !== null && now - s.clientGoneAt > graceMs) endSession(s, 'client gone');
      else if (s.agentGoneAt !== null && now - s.agentGoneAt > graceMs) endSession(s, 'agent gone');
    }
    for (const [ip, b] of openBuckets) if (now - b.at > 120_000) openBuckets.delete(ip);
  }, 5000);
  sweeper.unref();

  // ------------------------------------------------------------ HTTP

  function securityHeaders(res: ServerResponse): void {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
  }

  function cors(res: ServerResponse): void {
    // No cookies or ambient credentials exist here; all authentication is
    // end to end inside the encrypted channel, so any origin (including the
    // offline launcher's "null" origin) may talk to the relay.
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'content-type');
    res.setHeader('Access-Control-Max-Age', '86400');
  }

  function json(res: ServerResponse, status: number, body: unknown): void {
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(body));
  }

  function readBody(req: IncomingMessage, limit: number): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      let size = 0;
      req.on('data', (c: Buffer) => {
        size += c.length;
        if (size > limit) {
          reject(new Error('body too large'));
          req.destroy();
          return;
        }
        chunks.push(c);
      });
      req.on('end', () => resolve(Buffer.concat(chunks)));
      req.on('error', reject);
    });
  }

  server.on('request', (req, res) => {
    handle(req, res).catch((err: Error) => {
      if (!res.headersSent) json(res, 400, { error: 'bad-request', message: err.message });
      else res.destroy();
    });
  });

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    securityHeaders(res);
    const url = new URL(req.url ?? '/', 'http://relay');
    const path = url.pathname;

    if (path === '/healthz') {
      res.setHeader('Content-Type', 'text/plain');
      res.end('ok');
      return;
    }

    if (path.startsWith('/v1/lp/')) {
      cors(res);
      if (req.method === 'OPTIONS') {
        res.statusCode = 204;
        res.end();
        return;
      }
      if (req.method !== 'POST') return json(res, 405, { error: 'method-not-allowed' });

      if (path === '/v1/lp/open') {
        const body = JSON.parse((await readBody(req, 4096)).toString('utf8')) as { agent?: string; sid?: string };
        let s: RelaySession | undefined;
        if (typeof body.sid === 'string') {
          s = sessions.get(body.sid);
          if (!s) return json(res, 404, { error: 'unknown-session' });
        } else {
          const r = createSession(String(body.agent ?? ''), clientIp(req));
          if ('error' in r) return json(res, r.error === 'rate-limited' ? 429 : r.error === 'agent-offline' ? 404 : 400, r);
          s = r;
        }
        attachClient(s, { kind: 'lp', queue: [], queuedBytes: 0, waiter: null, lastPollAt: Date.now() });
        return json(res, 200, { sid: s.sid });
      }

      const m = /^\/v1\/lp\/([A-Za-z0-9_-]{1,64})\/(tx|rx)$/.exec(path);
      if (!m) return json(res, 404, { error: 'not-found' });
      const s = sessions.get(m[1]!);
      if (!s) return json(res, 404, { error: 'unknown-session' });
      const c = s.client;
      if (c?.kind !== 'lp') return json(res, 409, { error: 'not-attached' });

      if (m[2] === 'tx') {
        const frames = decodeFrameBatch(new Uint8Array(await readBody(req, LP_MAX_BODY)));
        for (const f of frames) sendToAgent(s, f);
        res.statusCode = 204;
        res.end();
        return;
      }

      // rx: long poll
      c.lastPollAt = Date.now();
      c.waiter?.([]); // only one outstanding poll per session
      const frames = await new Promise<Uint8Array[] | null>((resolve) => {
        c.waiter = resolve;
        const timer = setTimeout(() => {
          if (c.waiter === resolve) {
            c.waiter = null;
            resolve([]);
          }
        }, lpWaitMs);
        res.on('close', () => {
          clearTimeout(timer);
          if (c.waiter === resolve) {
            c.waiter = null;
            resolve(null);
          }
        });
        // Give the queue a moment to coalesce small frames into one response.
        if (c.queue.length > 0) setTimeout(() => flushLongPoll(c), 5);
      });
      c.lastPollAt = Date.now();
      if (frames === null) {
        if (!res.writableEnded) res.end();
        return;
      }
      if (frames.length === 0) {
        res.statusCode = 204;
        res.end();
        return;
      }
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/octet-stream');
      res.end(encodeFrameBatch(frames));
      return;
    }

    if (hostedClient && req.method === 'GET' && (path === '/' || path === '/index.html')) {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader('X-Frame-Options', 'DENY');
      res.end(hostedClient);
      return;
    }

    json(res, 404, { error: 'not-found' });
  }

  // ------------------------------------------------------------ WebSockets

  server.on('upgrade', (req: IncomingMessage, socket: Duplex, head: Buffer) => {
    const url = new URL(req.url ?? '/', 'http://relay');
    const path = url.pathname;
    const reject = (code: number, msg: string) => {
      socket.end(`HTTP/1.1 ${code} ${msg}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
    };

    if (path === '/v1/client/ws') {
      wss.handleUpgrade(req, socket, head, (ws) => onClientSocket(ws, url, clientIp(req)));
      return;
    }

    if (path === '/v1/agent/control') {
      const agentId = url.searchParams.get('agent') ?? '';
      if (!agentAuthorized(agentId, bearer(req))) return reject(401, 'Unauthorized');
      wss.handleUpgrade(req, socket, head, (ws) => onAgentControl(ws, agentId));
      return;
    }

    const m = /^\/v1\/agent\/session\/([A-Za-z0-9_-]{1,64})$/.exec(path);
    if (m) {
      const s = sessions.get(m[1]!);
      if (!s) return reject(404, 'Not Found');
      if (!agentAuthorized(s.agentId, bearer(req))) return reject(401, 'Unauthorized');
      wss.handleUpgrade(req, socket, head, (ws) => onAgentSession(ws, s));
      return;
    }

    reject(404, 'Not Found');
  });

  function keepAlive(ws: WebSocket): void {
    // Some proxies kill connections that are idle for 30-60 s.
    const t = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) ws.ping();
    }, 20_000);
    t.unref();
    ws.on('close', () => clearInterval(t));
  }

  function onClientSocket(ws: WebSocket, url: URL, ip: string): void {
    keepAlive(ws);
    const sid = url.searchParams.get('sid');
    let s: RelaySession | undefined;
    if (sid) {
      s = sessions.get(sid);
      if (!s) {
        ws.send(relayFrame({ t: 'error', code: 'unknown-session' }));
        ws.close(1000);
        return;
      }
    } else {
      const r = createSession(url.searchParams.get('agent') ?? '', ip);
      if ('error' in r) {
        ws.send(relayFrame({ t: 'error', code: r.error, message: r.message }));
        ws.close(1000);
        return;
      }
      s = r;
    }
    const session = s;
    const attachment: ClientAttachment = { kind: 'ws', ws };
    attachClient(session, attachment);
    ws.on('message', (data: RawData, isBinary: boolean) => {
      if (!isBinary || session.client !== attachment) return;
      sendToAgent(session, toBytes(data));
    });
    ws.on('close', () => {
      if (session.client === attachment) {
        session.client = null;
        session.clientGoneAt = Date.now();
      }
    });
    ws.on('error', () => ws.terminate());
  }

  function onAgentControl(ws: WebSocket, agentId: string): void {
    keepAlive(ws);
    const prev = agents.get(agentId);
    if (prev) prev.ws.close(4001, 'replaced by a newer connection');
    agents.set(agentId, { id: agentId, ws });
    log('agent-online', { agentId });
    // Re-offer sessions that are waiting for this agent (e.g. after an agent restart).
    for (const s of sessions.values()) if (s.agentId === agentId && !s.agent) control(ws, { t: 'open', sid: s.sid });
    ws.on('message', () => {
      // Agents do not send anything on the control channel today.
    });
    ws.on('close', () => {
      if (agents.get(agentId)?.ws === ws) {
        agents.delete(agentId);
        log('agent-offline', { agentId });
      }
    });
    ws.on('error', () => ws.terminate());
  }

  function onAgentSession(ws: WebSocket, s: RelaySession): void {
    keepAlive(ws);
    s.agent?.close(4001, 'replaced');
    s.agent = ws;
    s.agentGoneAt = null;
    if (s.client) relayToClient(s, { t: 'ready' });
    ws.on('message', (data: RawData, isBinary: boolean) => {
      if (!isBinary || s.agent !== ws) return;
      const frame = toBytes(data);
      if (frame.length === 0 || frame[0] === FRAME_RELAY) return;
      sendToClient(s, frame);
    });
    ws.on('close', (code: number) => {
      if (s.agent !== ws) return;
      s.agent = null;
      s.agentGoneAt = Date.now();
      if (code === AGENT_SESSION_DONE) endSession(s, 'agent ended session');
      else if (sessions.has(s.sid)) relayToClient(s, { t: 'peer-gone' });
    });
    ws.on('error', () => ws.terminate());
  }

  return {
    server,
    listen(port, host = '0.0.0.0') {
      return new Promise((resolve) => {
        server.listen(port, host, () => {
          const addr = server.address();
          resolve(typeof addr === 'object' && addr ? addr.port : port);
        });
      });
    },
    async close() {
      clearInterval(sweeper);
      for (const s of [...sessions.values()]) endSession(s, 'relay shutting down');
      for (const a of agents.values()) a.ws.close(1001, 'relay shutting down');
      for (const ws of wss.clients) ws.terminate();
      const closed = new Promise<void>((r) => server.close(() => r()));
      server.closeAllConnections?.();
      await closed;
    },
    stats() {
      return { agents: agents.size, sessions: sessions.size };
    },
  };
}

function toBytes(data: RawData): Uint8Array {
  if (Array.isArray(data)) return new Uint8Array(Buffer.concat(data));
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
}

export const AGENT_SESSION_DONE_CODE = AGENT_SESSION_DONE;
