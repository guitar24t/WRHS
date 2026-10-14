// The browser RDP client (IronRDP, WebAssembly) reaches its gateway with
// `new WebSocket(proxyAddress)`. The build points that constructor at
// RdpTunnelSocket (see build.mjs), which carries the bytes on CHANNEL_RDP of
// the end-to-end encrypted session instead. The agent is the gateway.
//
// Only addresses handed out by bindRdpTunnel() connect; anything else fails
// like an unreachable server, so the RDP client can never open a network
// connection of its own.

import type { AppChannel } from '@wrhs/protocol';

const PREFIX = 'wss://wrhs-tunnel.invalid/rdp/';
const bindings = new Map<string, AppChannel>();

/**
 * Returns a one-time address that the RDP client can "connect" to; the
 * connection runs over `app`. Call the returned dispose function when the
 * desktop closes (it also closes the socket if it is still open).
 */
export function bindRdpTunnel(app: AppChannel): { url: string; dispose(): void } {
  const id = Array.from(crypto.getRandomValues(new Uint8Array(12)), (b) => b.toString(16).padStart(2, '0')).join('');
  const url = PREFIX + id;
  bindings.set(url, app);
  return {
    url,
    dispose() {
      bindings.delete(url);
      for (const s of open) if (s.url === url) s.terminate(1000, 'desktop closed');
    },
  };
}

const open = new Set<RdpTunnelSocket>();

function closeEvent(code: number, reason: string, wasClean: boolean): Event {
  if (typeof CloseEvent === 'function') return new CloseEvent('close', { code, reason, wasClean });
  return Object.assign(new Event('close'), { code, reason, wasClean });
}

type Handler = ((ev: Event) => void) | null;

export class RdpTunnelSocket extends EventTarget {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSING = 2;
  static readonly CLOSED = 3;
  readonly CONNECTING = 0;
  readonly OPEN = 1;
  readonly CLOSING = 2;
  readonly CLOSED = 3;

  readonly url: string;
  readonly protocol = '';
  readonly extensions = '';
  readonly bufferedAmount = 0;
  binaryType: 'blob' | 'arraybuffer' = 'blob';
  readyState = 0;
  onopen: Handler = null;
  onmessage: Handler = null;
  onerror: Handler = null;
  onclose: Handler = null;

  #app: AppChannel | null;
  #offData: (() => void) | null = null;
  #offClose: (() => void) | null = null;

  constructor(url: string | URL, _protocols?: string | string[]) {
    super();
    this.url = String(url);
    this.#app = bindings.get(this.url) ?? null;
    // One connection per address.
    bindings.delete(this.url);
    setTimeout(() => this.#start(), 0);
  }

  #start(): void {
    const app = this.#app;
    if (this.readyState !== this.CONNECTING) return;
    if (!app || app.session.closed) {
      this.#emit(new Event('error'));
      this.terminate(1006, 'no route', false);
      return;
    }
    open.add(this);
    this.#offData = app.on('rdp', (data) => this.#receive(data));
    this.#offClose = app.session.on('close', () => {
      this.#emit(new Event('error'));
      this.terminate(1006, 'encrypted session closed', false);
    });
    this.readyState = this.OPEN;
    this.#emit(new Event('open'));
  }

  #receive(data: Uint8Array): void {
    if (this.readyState !== this.OPEN) return;
    const copy = data.slice().buffer;
    this.#emit(new MessageEvent('message', { data: this.binaryType === 'arraybuffer' ? copy : new Blob([copy]) }));
  }

  #emit(ev: Event): void {
    const handler = (this as unknown as Record<string, Handler>)[`on${ev.type}`];
    try {
      handler?.call(this, ev);
    } finally {
      this.dispatchEvent(ev);
    }
  }

  send(data: string | ArrayBufferLike | ArrayBufferView | Blob): void {
    if (this.readyState === this.CONNECTING) throw new DOMException('WebSocket is still connecting', 'InvalidStateError');
    if (this.readyState !== this.OPEN || !this.#app?.session.writable) return;
    if (typeof data === 'string') this.#app.sendRdp(new TextEncoder().encode(data));
    else if (data instanceof Blob) {
      const app = this.#app;
      void data.arrayBuffer().then((b) => this.readyState === this.OPEN && app.sendRdp(new Uint8Array(b)));
    } else if (ArrayBuffer.isView(data)) this.#app.sendRdp(new Uint8Array(data.buffer, data.byteOffset, data.byteLength).slice());
    else this.#app.sendRdp(new Uint8Array(data as ArrayBuffer).slice());
  }

  close(code = 1000, reason = ''): void {
    if (this.readyState === this.CLOSING || this.readyState === this.CLOSED) return;
    this.readyState = this.CLOSING;
    setTimeout(() => this.terminate(code, reason), 0);
  }

  /** Ends the connection from our side (desktop closed, session gone). */
  terminate(code: number, reason: string, wasClean = true): void {
    if (this.readyState === this.CLOSED) return;
    this.readyState = this.CLOSED;
    open.delete(this);
    this.#offData?.();
    this.#offClose?.();
    this.#offData = this.#offClose = null;
    this.#app = null;
    this.#emit(closeEvent(code, reason, wasClean));
  }
}
