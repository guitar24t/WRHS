// Outbound-only connection from the agent to the relay. The agent needs no
// inbound firewall rule; it dials the relay over HTTPS like a browser would.

import { WebSocket, type RawData } from 'ws';
import { agentIdFromPublicKey, MAX_FRAME } from '@wrhs/protocol';
import { ClientSessionHandler, type AgentContext } from './client-session.ts';

const SESSION_DONE = 4000;

function wsUrl(relayUrl: string, path: string): string {
  const u = new URL(relayUrl);
  u.pathname = u.pathname.replace(/\/+$/, '') + path;
  u.protocol = u.protocol === 'http:' ? 'ws:' : 'wss:';
  return u.toString();
}

/** What to check when the relay address answers the agent with an error. */
export function rejectionHint(status: number, server?: string): string {
  if (status === 401) {
    return "The relay does not accept this agent. Add the agent's entry (wrhs-agent registration) to the relay's agents file and restart the relay.";
  }
  if (/cloudflare/i.test(server ?? '')) {
    if (status >= 500) return 'Cloudflare cannot reach the relay. Check that the tunnel is running and sends this hostname to HTTP localhost:8080.';
    return "Cloudflare turned the agent away before the relay: check this hostname's security settings (Browser Integrity Check, Bot Fight Mode, WAF rules, Access policies).";
  }
  if (status === 404) return 'This address does not lead to a WRHS relay. Check relayUrl in the agent configuration.';
  if (status >= 500) return 'The relay or the proxy in front of it is failing. Check that the relay is running.';
  return 'Something between the agent and the relay (a proxy or firewall) refused the connection.';
}

export class RelayLink {
  readonly agentId: string;
  readonly #ctx: AgentContext;
  readonly #handlers = new Map<string, { handler: ClientSessionHandler; ws: WebSocket | null; retries: number }>();
  #control: WebSocket | null = null;
  #stopped = false;
  #backoff = 0;
  #onlineWaiters: (() => void)[] = [];
  /**
   * Keeps the process alive between reconnection attempts, whose timers are
   * unref'd: without it the agent would exit when the relay is unreachable
   * (for example at boot, before the network is up).
   */
  #keepAlive: ReturnType<typeof setInterval> | null = null;

  constructor(ctx: AgentContext) {
    this.#ctx = ctx;
    this.agentId = agentIdFromPublicKey(ctx.key.publicKey);
  }

  start(): void {
    this.#keepAlive ??= setInterval(() => {}, 1 << 30);
    this.#connectControl();
  }

  /** Resolves once the control channel is up (used by tests and the CLI). */
  online(): Promise<void> {
    if (this.#control?.readyState === WebSocket.OPEN) return Promise.resolve();
    return new Promise((r) => this.#onlineWaiters.push(r));
  }

  stop(): void {
    this.#stopped = true;
    if (this.#keepAlive) clearInterval(this.#keepAlive);
    this.#keepAlive = null;
    this.#control?.close(1000);
    for (const { handler } of this.#handlers.values()) handler.end('agent shutting down');
  }

  get sessionCount(): number {
    return this.#handlers.size;
  }

  #headers() {
    return {
      Authorization: `Bearer ${this.#ctx.config.relayToken}`,
      // Cloudflare and other CDNs turn away requests without a User-Agent.
      'User-Agent': `${this.#ctx.software} node/${process.versions.node}`,
    };
  }

  #connectControl(): void {
    if (this.#stopped) return;
    const url = `${wsUrl(this.#ctx.config.relayUrl, '/v1/agent/control')}?agent=${this.agentId}`;
    const ws = new WebSocket(url, { headers: this.#headers(), perMessageDeflate: false, maxPayload: 64 * 1024 });
    this.#control = ws;
    ws.on('open', () => {
      this.#backoff = 0;
      this.#ctx.log('relay-connected', { relay: this.#ctx.config.relayUrl, agentId: this.agentId });
      for (const w of this.#onlineWaiters.splice(0)) w();
    });
    ws.on('message', (data: RawData, isBinary: boolean) => {
      if (isBinary) return;
      let msg: { t?: string; sid?: string };
      try {
        msg = JSON.parse(data.toString()) as typeof msg;
      } catch {
        return;
      }
      if (msg.t === 'open' && typeof msg.sid === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(msg.sid)) this.#openSession(msg.sid);
    });
    let rejected = false;
    ws.on('unexpected-response', (_req, res) => {
      rejected = true;
      const status = res.statusCode ?? 0;
      const server = typeof res.headers.server === 'string' ? res.headers.server : undefined;
      this.#ctx.log('relay-rejected', { status, ...(server ? { server } : {}), hint: rejectionHint(status, server) });
      // Ends this attempt with a 'close', which schedules the next one. (Only
      // destroying the request leaves the socket waiting forever.)
      ws.terminate();
    });
    ws.on('error', (err) => {
      if (!rejected) this.#ctx.log('relay-error', { error: err.message });
    });
    ws.on('close', () => {
      if (this.#control !== ws) return;
      this.#control = null;
      if (this.#stopped) return;
      const delay = Math.min(1000 * 2 ** this.#backoff++, 30_000);
      this.#ctx.log('relay-disconnected', { retryInMs: delay });
      setTimeout(() => this.#connectControl(), delay).unref();
    });
  }

  #openSession(sid: string): void {
    let entry = this.#handlers.get(sid);
    if (entry?.ws && entry.ws.readyState <= WebSocket.OPEN) return;
    if (!entry) {
      const handler = new ClientSessionHandler(sid, this.#ctx);
      entry = { handler, ws: null, retries: 0 };
      this.#handlers.set(sid, entry);
      handler.onEnd = () => {
        const e = this.#handlers.get(sid);
        this.#handlers.delete(sid);
        e?.ws?.close(SESSION_DONE, 'session finished');
      };
    }
    this.#connectData(sid, entry);
  }

  #connectData(sid: string, entry: { handler: ClientSessionHandler; ws: WebSocket | null; retries: number }): void {
    if (this.#stopped || !this.#handlers.has(sid)) return;
    const ws = new WebSocket(wsUrl(this.#ctx.config.relayUrl, `/v1/agent/session/${sid}`), {
      headers: this.#headers(),
      perMessageDeflate: false,
      maxPayload: MAX_FRAME,
    });
    entry.ws = ws;
    ws.on('open', () => {
      entry.retries = 0;
      entry.handler.attach((frame) => {
        if (ws.readyState === WebSocket.OPEN) ws.send(frame);
      });
    });
    ws.on('message', (data: RawData, isBinary: boolean) => {
      if (!isBinary) {
        try {
          if ((JSON.parse(data.toString()) as { t?: string }).t === 'client-attached') entry.handler.clientAttached();
        } catch {
          // ignore
        }
        return;
      }
      const buf = Array.isArray(data) ? Buffer.concat(data) : Buffer.from(data as Buffer);
      entry.handler.receive(new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength));
    });
    ws.on('error', () => {});
    ws.on('unexpected-response', (_req, res) => {
      // 404: the relay forgot this session. Otherwise 'close' retries.
      if (res.statusCode === 404) entry.handler.end('relay no longer knows this session');
      ws.terminate();
    });
    ws.on('close', (code: number) => {
      if (entry.ws !== ws) return;
      entry.ws = null;
      entry.handler.detach();
      if (!this.#handlers.has(sid)) return;
      if (code === 1000 || code === SESSION_DONE) return entry.handler.end('relay closed the session');
      if (code === 4001) return; // replaced by a newer socket
      if (entry.retries++ > 8) return entry.handler.end('lost connection to relay');
      setTimeout(() => this.#connectData(sid, entry), Math.min(500 * 2 ** entry.retries, 15_000)).unref();
    });
  }
}
