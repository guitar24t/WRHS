// Client-side outer transports. They only move opaque frames to and from the
// relay over ordinary HTTPS, so they work through TLS-intercepting proxies.
// They use the global WebSocket and fetch, so the same code runs in browsers
// and in Node 22+ (used by the end-to-end tests).
//
//   WebSocket:  GET  {relay}/v1/client/ws?agent=<id> | ?sid=<sid>   (binary messages = frames)
//   Long-poll:  POST {relay}/v1/lp/open        {"agent": id} | {"sid": sid}  -> {"sid": sid}
//               POST {relay}/v1/lp/<sid>/tx    body = frame batch            -> 204
//               POST {relay}/v1/lp/<sid>/rx    long poll                     -> 200 frame batch | 204
//
// The long-poll fallback exists because some inspecting proxies refuse the
// WebSocket upgrade or buffer streaming responses; every long-poll exchange
// is a short, complete request/response, which every proxy handles.

import { decodeFrameBatch, encodeFrameBatch, FRAME_RELAY, MAX_FRAME, parseRelayFrame } from './wire.ts';

export type TransportKind = 'websocket' | 'longpoll';

export class RelayError extends Error {
  readonly code: string;
  constructor(code: string, message?: string) {
    super(message ? `${code}: ${message}` : code);
    this.name = 'RelayError';
    this.code = code;
  }
}

export interface OuterTransport {
  readonly kind: TransportKind;
  send(frame: Uint8Array): void;
  close(): void;
  onframe: (frame: Uint8Array) => void;
  onclose: (reason: string) => void;
}

export interface TransportTarget {
  agent?: string;
  sid?: string;
}

function joinUrl(base: string, path: string): URL {
  const u = new URL(base);
  u.pathname = u.pathname.replace(/\/+$/, '') + path;
  return u;
}

export function webSocketUrl(relayUrl: string, target: TransportTarget): string {
  const u = joinUrl(relayUrl, '/v1/client/ws');
  u.protocol = u.protocol === 'http:' ? 'ws:' : 'wss:';
  if (target.sid) u.searchParams.set('sid', target.sid);
  else if (target.agent) u.searchParams.set('agent', target.agent);
  return u.toString();
}

/**
 * Open a WebSocket transport. Resolves only after the relay's first control
 * frame arrives, which proves the upgrade really made it through any proxy.
 */
/** Holds frames that arrive before the owner installs its handler. */
abstract class BaseTransport {
  #onframe: ((frame: Uint8Array) => void) | null = null;
  #early: Uint8Array[] = [];
  onclose: (reason: string) => void = () => {};

  get onframe(): (frame: Uint8Array) => void {
    return (f) => this.deliver(f);
  }

  set onframe(fn: (frame: Uint8Array) => void) {
    this.#onframe = fn;
    for (const f of this.#early.splice(0)) fn(f);
  }

  protected deliver(frame: Uint8Array): void {
    if (this.#onframe) this.#onframe(frame);
    else this.#early.push(frame);
  }
}

class WebSocketTransport extends BaseTransport implements OuterTransport {
  readonly kind = 'websocket';
  readonly #ws: WebSocket;

  constructor(ws: WebSocket) {
    super();
    this.#ws = ws;
  }

  send(frame: Uint8Array): void {
    if (this.#ws.readyState === WebSocket.OPEN) this.#ws.send(frame);
  }

  close(): void {
    try {
      this.#ws.close(1000);
    } catch {
      // ignore
    }
  }

  push(frame: Uint8Array): void {
    this.deliver(frame);
  }
}

/**
 * Open a WebSocket transport. Resolves only after the relay's first control
 * frame arrives, which proves the upgrade really made it through any proxy.
 */
export function openWebSocket(
  relayUrl: string,
  target: TransportTarget,
  timeoutMs = 8000,
): Promise<{ transport: OuterTransport; first: Uint8Array }> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const ws = new WebSocket(webSocketUrl(relayUrl, target));
    ws.binaryType = 'arraybuffer';
    const t = new WebSocketTransport(ws);
    const timer = setTimeout(() => fail('WebSocket connection timed out'), timeoutMs);
    function fail(msg: string) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        ws.close();
      } catch {
        // ignore
      }
      reject(new Error(msg));
    }
    ws.onmessage = (ev) => {
      if (!(ev.data instanceof ArrayBuffer)) return;
      const frame = new Uint8Array(ev.data);
      if (frame.length === 0 || frame.length > MAX_FRAME) return;
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve({ transport: t, first: frame });
        return;
      }
      t.push(frame);
    };
    ws.onerror = () => fail('WebSocket error');
    ws.onclose = (ev) => {
      if (!settled) return fail(`WebSocket closed (${ev.code})`);
      t.onclose(`websocket closed (${ev.code})`);
    };
  });
}

export async function openLongPoll(
  relayUrl: string,
  target: TransportTarget,
  opts: { timeoutMs?: number } = {},
): Promise<{ transport: OuterTransport; sid: string }> {
  const res = await fetchWithTimeout(joinUrl(relayUrl, '/v1/lp/open'), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(target.sid ? { sid: target.sid } : { agent: target.agent }),
  }, opts.timeoutMs ?? 15_000);
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { error?: string; message?: string };
    throw new RelayError(body.error ?? `http-${res.status}`, body.message);
  }
  const { sid } = (await res.json()) as { sid: string };
  return { transport: new LongPollTransport(relayUrl, sid), sid };
}

class LongPollTransport extends BaseTransport implements OuterTransport {
  readonly kind = 'longpoll';
  readonly #base: string;
  readonly #sid: string;
  #closed = false;
  #txQueue: Uint8Array[] = [];
  #txBusy = false;
  #abort = new AbortController();

  constructor(base: string, sid: string) {
    super();
    this.#base = base;
    this.#sid = sid;
    void this.#rxLoop();
  }

  send(frame: Uint8Array): void {
    if (this.#closed) return;
    this.#txQueue.push(frame);
    if (!this.#txBusy) void this.#txLoop();
  }

  close(): void {
    this.#shutdown('closed by client');
  }

  #shutdown(reason: string): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#abort.abort();
    this.onclose(reason);
  }

  async #txLoop(): Promise<void> {
    this.#txBusy = true;
    try {
      while (!this.#closed && this.#txQueue.length > 0) {
        // Keep each request comfortably below common proxy body limits.
        const batch: Uint8Array[] = [];
        let size = 0;
        while (this.#txQueue.length > 0 && size < 512 * 1024) {
          const f = this.#txQueue.shift()!;
          batch.push(f);
          size += f.length + 4;
        }
        const res = await fetch(joinUrl(this.#base, `/v1/lp/${this.#sid}/tx`), {
          method: 'POST',
          headers: { 'content-type': 'application/octet-stream' },
          body: encodeFrameBatch(batch) as Uint8Array<ArrayBuffer>,
          cache: 'no-store',
          credentials: 'omit',
          signal: this.#abort.signal,
        });
        await res.arrayBuffer().catch(() => undefined);
        if (!res.ok) return this.#shutdown(`long-poll tx failed (${res.status})`);
      }
    } catch (err) {
      this.#shutdown(`long-poll tx error: ${(err as Error).message}`);
    } finally {
      this.#txBusy = false;
    }
  }

  async #rxLoop(): Promise<void> {
    while (!this.#closed) {
      try {
        const res = await fetchWithTimeout(
          joinUrl(this.#base, `/v1/lp/${this.#sid}/rx`),
          { method: 'POST', cache: 'no-store', credentials: 'omit', signal: this.#abort.signal },
          60_000,
        );
        if (res.status === 204) continue;
        if (!res.ok) return this.#shutdown(`long-poll rx failed (${res.status})`);
        const body = new Uint8Array(await res.arrayBuffer());
        for (const frame of decodeFrameBatch(body)) {
          if (this.#closed) return;
          this.deliver(frame);
        }
      } catch (err) {
        return this.#shutdown(`long-poll rx error: ${(err as Error).message}`);
      }
    }
  }
}

async function fetchWithTimeout(url: URL, init: RequestInit, timeoutMs: number): Promise<Response> {
  const ctrl = new AbortController();
  const outer = init.signal;
  const onAbort = () => ctrl.abort();
  outer?.addEventListener('abort', onAbort);
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, { cache: 'no-store', credentials: 'omit', ...init, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
    outer?.removeEventListener('abort', onAbort);
  }
}

export function isRelayFrame(frame: Uint8Array): boolean {
  return frame[0] === FRAME_RELAY;
}

export { parseRelayFrame };
