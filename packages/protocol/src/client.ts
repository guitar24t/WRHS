// Client side of a WRHS connection: picks an outer transport, runs the
// pinned Noise handshake, and keeps the encrypted session alive across outer
// reconnects (proxies routinely kill long-lived connections).

import { Emitter, weakTimeout } from './emitter.ts';
import { startInitiator, finishInitiator } from './handshake.ts';
import type { HandshakeState, KeyPair } from './noise.ts';
import { SecureSession, type SessionOptions } from './session.ts';
import { agentIdFromPublicKey } from './identity.ts';
import { FRAME_HS2, FRAME_RECORD, FRAME_RELAY, PROTOCOL_VERSION, parseRelayFrame, type AgentHello } from './wire.ts';
import {
  openLongPoll,
  openWebSocket,
  RelayError,
  type OuterTransport,
  type TransportKind,
  type TransportTarget,
} from './transport.ts';

export type ConnectionState = 'connecting' | 'handshaking' | 'open' | 'reconnecting' | 'closed';

export interface ClientConnectionOptions {
  relayUrl: string;
  /** Pinned agent public keys. The first one also determines the routing id. */
  agentPublicKeys: Uint8Array[];
  deviceKey: KeyPair;
  transport?: 'auto' | TransportKind;
  software?: string;
  session?: SessionOptions;
  wsTimeoutMs?: number;
}

export type ClientConnectionEvents = {
  state: [state: ConnectionState, detail?: string];
  transport: [kind: TransportKind];
};

export class ClientConnection extends Emitter<ClientConnectionEvents> {
  readonly agentId: string;
  readonly #o: ClientConnectionOptions;
  #state: ConnectionState = 'connecting';
  #transport: OuterTransport | null = null;
  #kind: TransportKind | null = null;
  #sid: string | null = null;
  #hs: HandshakeState | null = null;
  #session: SecureSession | null = null;
  #agentHello: AgentHello | null = null;
  #closed = false;
  #reconnectAttempt = 0;
  #pending: { resolve: (s: SecureSession) => void; reject: (e: Error) => void } | null = null;

  constructor(opts: ClientConnectionOptions) {
    super();
    if (opts.agentPublicKeys.length === 0) throw new Error('at least one pinned agent key is required');
    this.#o = opts;
    this.agentId = agentIdFromPublicKey(opts.agentPublicKeys[0]!);
  }

  get state(): ConnectionState {
    return this.#state;
  }

  get transportKind(): TransportKind | null {
    return this.#kind;
  }

  get agentHello(): AgentHello | null {
    return this.#agentHello;
  }

  get session(): SecureSession | null {
    return this.#session;
  }

  /** Connect, authenticate the agent, and resolve with the encrypted session. */
  open(): Promise<SecureSession> {
    if (this.#pending || this.#session) throw new Error('already opened');
    return new Promise<SecureSession>((resolve, reject) => {
      this.#pending = { resolve, reject };
      this.#setState('connecting');
      this.#connect({ agent: this.agentId }).catch((err) => this.#failOpen(err as Error));
    });
  }

  close(reason = 'closed by user'): void {
    if (this.#closed) return;
    if (this.#session && !this.#session.closed) {
      this.#session.close(reason);
      return; // the session's close event finishes the job
    }
    this.#shutdown(reason);
  }

  async #connect(target: TransportTarget): Promise<void> {
    const pref = this.#o.transport ?? 'auto';
    const order: TransportKind[] =
      pref === 'auto' ? (this.#kind === 'longpoll' ? ['longpoll', 'websocket'] : ['websocket', 'longpoll']) : [pref];
    let lastErr: Error | null = null;
    for (const kind of order) {
      if (this.#closed) return;
      try {
        if (kind === 'websocket') {
          const { transport, first } = await openWebSocket(this.#o.relayUrl, target, this.#o.wsTimeoutMs);
          this.#adopt(transport);
          this.#onFrame(first);
        } else {
          const { transport, sid } = await openLongPoll(this.#o.relayUrl, target);
          this.#sid = sid;
          this.#adopt(transport);
        }
        return;
      } catch (err) {
        lastErr = err as Error;
      }
    }
    throw lastErr ?? new Error('no transport available');
  }

  #adopt(t: OuterTransport): void {
    if (this.#closed) {
      t.close();
      return;
    }
    this.#transport = t;
    this.#kind = t.kind;
    this.emit('transport', t.kind);
    t.onframe = (f) => this.#onFrame(f);
    t.onclose = (reason) => this.#onTransportClose(t, reason);
  }

  #onFrame(frame: Uint8Array): void {
    const type = frame[0];
    if (type === FRAME_RECORD) {
      this.#session?.receive(frame);
      return;
    }
    if (type === FRAME_RELAY) {
      let msg;
      try {
        msg = parseRelayFrame(frame);
      } catch {
        return;
      }
      switch (msg.t) {
        case 'session':
          this.#sid = msg.sid;
          return;
        case 'ready':
          this.#reconnectAttempt = 0;
          if (this.#session) {
            // Agent reachable again (or we reconnected): resume the session.
            this.#session.attach((f) => this.#transport?.send(f));
            this.#setState('open');
          } else if (!this.#hs) {
            this.#startHandshake();
          }
          return;
        case 'peer-gone':
          this.#session?.detach();
          if (this.#session) this.#setState('reconnecting', 'agent connection to relay lost');
          return;
        case 'error': {
          const err = new RelayError(msg.code, msg.message);
          if (!this.#session) return this.#failOpen(err);
          this.#session.close(err.message);
          return;
        }
      }
      return;
    }
    if (type === FRAME_HS2 && this.#hs && !this.#session) {
      try {
        const fin = finishInitiator(this.#hs, frame, this.#o.agentPublicKeys, {
          v: PROTOCOL_VERSION,
          software: this.#o.software ?? 'wrhs-client',
        });
        this.#transport?.send(fin.frame);
        this.#agentHello = fin.agentHello;
        const session = new SecureSession(fin.result, this.#o.session);
        this.#session = session;
        this.#hs = null;
        session.on('close', (info) => this.#shutdown(info.reason));
        session.on('link-dead', () => this.#transport?.close());
        session.attach((f) => this.#transport?.send(f));
        this.#setState('open');
        const p = this.#pending;
        this.#pending = null;
        p?.resolve(session);
      } catch (err) {
        this.#failOpen(err as Error);
      }
    }
  }

  #startHandshake(): void {
    this.#setState('handshaking');
    const { hs, frame } = startInitiator(this.#o.deviceKey);
    this.#hs = hs;
    this.#transport?.send(frame);
  }

  #onTransportClose(t: OuterTransport, reason: string): void {
    if (this.#transport !== t) return;
    this.#transport = null;
    if (this.#closed) return;
    if (!this.#session) return this.#failOpen(new Error(`connection lost during handshake: ${reason}`));
    this.#session.detach();
    this.#setState('reconnecting', reason);
    this.#scheduleReconnect();
  }

  #scheduleReconnect(): void {
    const attempt = this.#reconnectAttempt++;
    const delay = Math.min(500 * 2 ** attempt, 10_000);
    weakTimeout(() => {
      if (this.#closed || this.#transport || !this.#sid) return;
      this.#connect({ sid: this.#sid }).catch((err: Error) => {
        if (err instanceof RelayError && err.code === 'unknown-session') return this.#session?.close('session expired');
        this.#scheduleReconnect();
      });
    }, delay);
  }

  #failOpen(err: Error): void {
    const p = this.#pending;
    this.#pending = null;
    this.#shutdown(err.message);
    p?.reject(err);
  }

  #shutdown(reason: string): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#transport?.close();
    this.#transport = null;
    this.#hs = null;
    this.#setState('closed', reason);
  }

  #setState(s: ConnectionState, detail?: string): void {
    if (this.#state === s && s !== 'reconnecting') return;
    this.#state = s;
    this.emit('state', s, detail);
  }
}
