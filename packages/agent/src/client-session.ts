// One browser session on the agent: Noise responder, user authentication,
// target selection, and the byte bridge to guacd.

import type { Socket } from 'node:net';
import {
  CHANNEL_CONTROL,
  CHANNEL_GUAC,
  FRAME_HS1,
  FRAME_HS3,
  FRAME_RECORD,
  PROTOCOL_VERSION,
  SecureSession,
  finishResponder,
  fingerprint,
  fromBase64Url,
  equalBytes,
  encodeKey,
  fromUtf8,
  respondToHs1,
  utf8,
  type ControlMessage,
  type HandshakeState,
  type KeyPair,
  type SessionOptions,
  type TargetInfo,
} from '@wrhs/protocol';
import type { Authenticator } from './auth.ts';
import type { AgentConfig, TargetConfig, UserConfig } from './config.ts';
import { connectGuacd, rdpParams } from './guacd.ts';

export interface AgentContext {
  config: AgentConfig;
  key: KeyPair;
  auth: Authenticator;
  software: string;
  log: (event: string, fields?: Record<string, unknown>) => void;
  /** Override for tests. */
  sessionOptions?: SessionOptions;
}

export const AGENT_SESSION_OPTIONS: SessionOptions = {
  highWaterMark: 2 * 1024 * 1024,
  // Clients only send small control messages and Guacamole instructions.
  maxMessageBytes: 256 * 1024,
  // While the user types, pace output on a 20 ms grid and pad it, so screen
  // echoes do not reveal keystroke timing to the proxy. Following the
  // client's cadence is switched on only after login (see #onAuth).
  cadence: { intervalMs: 20, holdMs: 1500, minPlaintext: 2048, followPeer: false },
};

type State = 'handshake' | 'auth' | 'ready' | 'remote' | 'closed';

const MAX_AUTH_ATTEMPTS_PER_SESSION = 3;

export class ClientSessionHandler {
  readonly sid: string;
  readonly #ctx: AgentContext;
  #send: ((frame: Uint8Array) => void) | null = null;
  #hs: HandshakeState | null = null;
  #session: SecureSession | null = null;
  #state: State = 'handshake';
  #user: UserConfig | null = null;
  #authAttempts = 0;
  #authBusy = false;
  #guac: Socket | null = null;
  #targetId: string | null = null;
  #lastInputAt = Date.now();
  #timers: ReturnType<typeof setTimeout>[] = [];
  #device = '';
  onEnd: (reason: string) => void = () => {};

  constructor(sid: string, ctx: AgentContext) {
    this.sid = sid;
    this.#ctx = ctx;
    // Sessions that never complete the handshake are dropped quickly.
    this.#timer(() => this.#state === 'handshake' && this.end('handshake timeout'), 30_000);
  }

  get state(): State {
    return this.#state;
  }

  attach(send: (frame: Uint8Array) => void): void {
    this.#send = send;
    this.#session?.attach(send);
  }

  detach(): void {
    this.#send = null;
    this.#session?.detach();
  }

  /** Relay says the browser (re)connected: retransmit right away. */
  clientAttached(): void {
    this.#session?.resync();
  }

  receive(frame: Uint8Array): void {
    if (this.#state === 'closed') return;
    try {
      switch (frame[0]) {
        case FRAME_HS1:
          return this.#onHs1(frame);
        case FRAME_HS3:
          return this.#onHs3(frame);
        case FRAME_RECORD:
          this.#session?.receive(frame);
          return;
      }
    } catch (err) {
      this.#ctx.log('handshake-failed', { sid: this.sid, error: (err as Error).message });
      this.end('handshake failed');
    }
  }

  end(reason: string): void {
    if (this.#state === 'closed') return;
    const wasOpen = this.#session && !this.#session.closed;
    this.#state = 'closed';
    for (const t of this.#timers) clearTimeout(t);
    this.#guac?.destroy();
    this.#guac = null;
    if (wasOpen) this.#session!.close(reason);
    this.#ctx.log('session-end', { sid: this.sid, user: this.#user?.name, device: this.#device, reason });
    // Give the CLOSE record a moment to leave before the socket goes away.
    setTimeout(() => this.onEnd(reason), wasOpen ? 300 : 0).unref();
  }

  // ------------------------------------------------------------ handshake

  #onHs1(frame: Uint8Array): void {
    if (this.#hs || this.#session) return; // duplicate after a reconnect
    const { hs, frame: hs2 } = respondToHs1(this.#ctx.key, frame, {
      v: PROTOCOL_VERSION,
      name: this.#ctx.config.name,
      software: this.#ctx.software,
    });
    this.#hs = hs;
    this.#send?.(hs2);
  }

  #onHs3(frame: Uint8Array): void {
    if (!this.#hs || this.#session) return;
    const { result, clientHello } = finishResponder(this.#hs, frame);
    this.#hs = null;
    this.#device = fingerprint(result.remoteStatic);
    const session = new SecureSession(result, this.#ctx.sessionOptions ?? AGENT_SESSION_OPTIONS);
    this.#session = session;
    session.on('message', (ch, data) => this.#onMessage(ch, data));
    session.on('close', (info) => {
      if (info.error) this.#ctx.log('integrity-failure', { sid: this.sid, error: info.error.message });
      this.end(info.reason);
    });
    session.on('drain', () => this.#guac?.resume());
    if (this.#send) session.attach(this.#send);
    this.#state = 'auth';
    this.#ctx.log('handshake-ok', {
      sid: this.sid,
      device: this.#device,
      deviceKey: encodeKey(result.remoteStatic),
      client: clientHello.software,
    });
    const p = this.#ctx.config.policy;
    this.#timer(() => this.#state === 'auth' && this.end('authentication timeout'), p.authTimeoutSeconds * 1000);
    this.#timer(() => this.end('maximum session length reached'), p.maxSessionSeconds * 1000);
    if (p.idleTimeoutSeconds > 0) this.#scheduleIdleCheck();
    this.#control({ t: 'auth-required', methods: p.requireTotp ? ['password+totp'] : ['password'] });
  }

  // ------------------------------------------------------------ control

  #control(msg: ControlMessage): void {
    if (this.#session?.writable) this.#session.send(CHANNEL_CONTROL, utf8(JSON.stringify(msg)));
  }

  #onMessage(channel: number, data: Uint8Array): void {
    if (channel === CHANNEL_GUAC) return this.#onGuacFromClient(data);
    if (channel !== CHANNEL_CONTROL) return;
    let msg: ControlMessage;
    try {
      msg = JSON.parse(fromUtf8(data)) as ControlMessage;
    } catch {
      return this.end('malformed control message');
    }
    switch (msg.t) {
      case 'auth':
        this.#onAuth(msg).catch((err: Error) => this.#internalError(err));
        return;
      case 'open':
        this.#onOpen(msg).catch((err: Error) => this.#internalError(err));
        return;
      default:
        return;
    }
  }

  async #onAuth(msg: Extract<ControlMessage, { t: 'auth' }>): Promise<void> {
    if (this.#state !== 'auth' || this.#authBusy) return;
    if (typeof msg.user !== 'string' || typeof msg.password !== 'string' || msg.user.length > 128 || msg.password.length > 1024) {
      return this.end('malformed auth message');
    }
    this.#authBusy = true;
    this.#authAttempts++;
    const started = Date.now();
    const device = this.#session!.remoteStatic;
    // The device allow-list is checked as part of authentication, so a
    // correct password from an unenrolled device is an ordinary failure: it
    // does not reset the failure count, use up the TOTP step, or say why.
    const deviceAllowed = (name: string) => {
      const u = this.#ctx.config.users.find((x) => x.name === name);
      return !u?.deviceKeys?.length || u.deviceKeys.some((k) => safeKeyEq(k, device));
    };
    const r = await this.#ctx.auth.authenticate(
      msg.user,
      msg.password,
      typeof msg.totp === 'string' ? msg.totp : undefined,
      Date.now(),
      deviceAllowed,
    );
    let failure: string | null = r.ok ? null : r.message;
    const user = r.ok ? this.#ctx.config.users.find((u) => u.name === r.user) : undefined;
    if (r.ok && !user) failure = 'invalid credentials';
    if (this.#state !== 'auth') return; // closed meanwhile
    if (failure !== null) {
      // Flatten timing and slow down guessing.
      await sleep(Math.max(0, 1000 - (Date.now() - started)));
      if (this.#state !== 'auth') return; // closed or timed out while we slept
      this.#authBusy = false;
      this.#ctx.log('login-fail', { sid: this.sid, user: msg.user, device: this.#device, reason: failure });
      this.#control({ t: 'auth-fail', message: failure, ...(r.ok ? {} : r.retryAfterMs ? { retryAfterMs: r.retryAfterMs } : {}) });
      if (this.#authAttempts >= MAX_AUTH_ATTEMPTS_PER_SESSION) this.end('too many failed logins');
      return;
    }
    this.#authBusy = false;
    this.#user = user!;
    this.#state = 'ready';
    this.#session!.followPeerCadence = true;
    this.#ctx.log('login-ok', { sid: this.sid, user: user!.name, device: this.#device });
    this.#control({ t: 'auth-ok', targets: this.#targetsFor(user!).map(targetInfo) });
  }

  #internalError(err: Error): void {
    this.#ctx.log('internal-error', { sid: this.sid, error: err.message });
    this.end('internal error');
  }

  #targetsFor(user: UserConfig): TargetConfig[] {
    const all = this.#ctx.config.targets;
    return user.targets === '*' ? all : all.filter((t) => (user.targets as string[]).includes(t.id));
  }

  async #onOpen(msg: Extract<ControlMessage, { t: 'open' }>): Promise<void> {
    if (this.#state !== 'ready' || !this.#user) return;
    const target = this.#targetsFor(this.#user).find((t) => t.id === msg.target);
    if (!target) return this.#control({ t: 'open-fail', message: 'unknown target' });
    const size = {
      width: clampInt(msg.width, 320, 8192, 1280),
      height: clampInt(msg.height, 200, 8192, 720),
      dpi: clampInt(msg.dpi, 48, 384, 96),
    };
    const creds = target.username ? {} : sanitizeCreds(msg.credentials);
    this.#state = 'remote';
    this.#targetId = target.id;
    try {
      const { socket, leftover } = await connectGuacd({
        host: this.#ctx.config.guacd.host,
        port: this.#ctx.config.guacd.port,
        protocol: 'rdp',
        params: rdpParams({ ...target, ...creds }, size),
        ...size,
        ...(typeof msg.timezone === 'string' && /^[A-Za-z0-9_/+-]{1,64}$/.test(msg.timezone) ? { timezone: msg.timezone } : {}),
      });
      if ((this.#state as State) === 'closed') {
        socket.destroy();
        return;
      }
      this.#guac = socket;
      this.#ctx.log('target-open', { sid: this.sid, user: this.#user.name, target: target.id });
      this.#control({ t: 'open-ok' });
      if (leftover.length) this.#toClient(leftover);
      socket.on('data', (chunk: Buffer) => this.#toClient(chunk));
      socket.on('close', () => this.#onGuacClosed(socket));
      socket.on('error', () => socket.destroy());
      socket.resume();
    } catch (err) {
      if ((this.#state as State) === 'closed') return;
      this.#state = 'ready';
      this.#targetId = null;
      this.#ctx.log('target-fail', { sid: this.sid, user: this.#user.name, target: target.id, error: (err as Error).message });
      this.#control({ t: 'open-fail', message: 'could not connect to the remote desktop' });
    }
  }

  #toClient(chunk: Buffer): void {
    const s = this.#session;
    if (!s?.writable) return;
    s.send(CHANNEL_GUAC, new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength));
    if (s.bufferedAmount > s.highWaterMark) this.#guac?.pause();
  }

  #onGuacFromClient(data: Uint8Array): void {
    if (this.#state !== 'remote' || !this.#guac) return;
    // Count only real input as activity (the client also sends sync acks).
    const head = String.fromCharCode(...data.subarray(0, 8));
    if (head.startsWith('3.key,') || head.startsWith('5.mouse,') || head.startsWith('5.touch,')) this.#lastInputAt = Date.now();
    this.#guac.write(data);
  }

  #onGuacClosed(socket: Socket): void {
    if (this.#guac !== socket) return;
    this.#guac = null;
    if (this.#state !== 'remote') return;
    this.#ctx.log('target-closed', { sid: this.sid, user: this.#user?.name, target: this.#targetId });
    this.#state = 'ready';
    this.#targetId = null;
    this.#control({ t: 'closed', message: 'remote desktop disconnected' });
  }

  #scheduleIdleCheck(): void {
    const idleMs = this.#ctx.config.policy.idleTimeoutSeconds * 1000;
    this.#timer(() => {
      if (this.#state === 'closed') return;
      if (Date.now() - this.#lastInputAt >= idleMs) this.end('idle timeout');
      else this.#scheduleIdleCheck();
    }, Math.min(idleMs, 60_000));
  }

  #timer(fn: () => void, ms: number): void {
    const t = setTimeout(fn, ms);
    t.unref();
    this.#timers.push(t);
  }
}

function targetInfo(t: TargetConfig): TargetInfo {
  return { id: t.id, name: t.name, protocol: t.protocol, promptCredentials: !t.username };
}

function clampInt(v: unknown, min: number, max: number, dflt: number): number {
  const n = typeof v === 'number' && Number.isFinite(v) ? Math.round(v) : dflt;
  return Math.min(max, Math.max(min, n));
}

function sanitizeCreds(c: unknown): { username?: string; password?: string; domain?: string } {
  if (!c || typeof c !== 'object') return {};
  const o = c as Record<string, unknown>;
  const pick = (k: string) => (typeof o[k] === 'string' && (o[k] as string).length <= 256 ? (o[k] as string) : undefined);
  const out: { username?: string; password?: string; domain?: string } = {};
  const u = pick('username');
  const p = pick('password');
  const d = pick('domain');
  if (u) out.username = u;
  if (p) out.password = p;
  if (d) out.domain = d;
  return out;
}

function safeKeyEq(b64: string, key: Uint8Array): boolean {
  try {
    return equalBytes(fromBase64Url(b64), key);
  } catch {
    return false;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
