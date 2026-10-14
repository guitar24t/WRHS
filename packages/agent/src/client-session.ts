// One browser session on the agent: Noise responder, user authentication,
// target selection, and the byte bridge to the desktop (the RDP server for
// the built-in engine, or guacd).

import type { Socket } from 'node:net';
import {
  CHANNEL_CONTROL,
  CHANNEL_GUAC,
  CHANNEL_RDP,
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
  type DesktopEngine,
  type HandshakeState,
  type KeyPair,
  type SessionOptions,
  type TargetInfo,
} from '@wrhs/protocol';
import type { Authenticator } from './auth.ts';
import { targetEngine, type AgentConfig, type TargetConfig, type UserConfig } from './config.ts';
import { connectGuacd, rdpParams } from './guacd.ts';
import { decodeRdCleanPath, rdCleanPathLength } from './rdcleanpath.ts';
import { connectRdpServer, negotiateRdp, type RdpBridge } from './rdp-bridge.ts';

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
  // Clients only send small control messages, input and protocol replies
  // (the browser RDP client splits larger writes, see the client).
  maxMessageBytes: 256 * 1024,
  // While the user types, pace output on a 20 ms grid and pad it, so screen
  // echoes do not reveal keystroke timing to the proxy. Following the
  // client's cadence is switched on only after login (see #onAuth).
  cadence: { intervalMs: 20, holdMs: 1500, minPlaintext: 2048, followPeer: false },
};

type State = 'handshake' | 'auth' | 'ready' | 'remote' | 'closed';

const MAX_AUTH_ATTEMPTS_PER_SESSION = 3;

/** Time the browser has to start RDP once the agent reached the RDP server. */
const RDP_REQUEST_TIMEOUT_MS = 30_000;
const MAX_RDCLEANPATH_REQUEST = 64 * 1024;

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
  /** Byte stream of the open desktop: guacd, or the RDP server once negotiated. */
  #stream: Socket | null = null;
  #engine: DesktopEngine = 'rdp';
  #target: TargetConfig | null = null;
  /** rdp engine, before negotiation: the idle connection to the RDP server... */
  #rdpServer: Socket | null = null;
  /** ...and the RDCleanPath request received so far (null once complete). */
  #rdpRequest: Buffer | null = null;
  #rdpTimer: ReturnType<typeof setTimeout> | null = null;
  /** Client bytes that arrived while the RDP connection was being negotiated. */
  #rdpQueued: Uint8Array[] = [];
  #targetId: string | null = null;
  /** Client reference of the open request being served (echoed in replies). */
  #openRef: number | undefined;
  /** Bumped on every open/close so a slow connect can tell it was superseded. */
  #openGen = 0;
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
    this.#releaseDesktop();
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
    session.on('drain', () => this.#stream?.resume());
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
    if (channel === CHANNEL_RDP) return this.#onRdpFromClient(data);
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
      case 'close-desktop':
        this.#dropDesktop('closed by user');
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
      this.#control({
        t: 'auth-fail',
        message: failure,
        attemptsLeft: Math.max(0, MAX_AUTH_ATTEMPTS_PER_SESSION - this.#authAttempts),
        ...(r.ok ? {} : r.retryAfterMs ? { retryAfterMs: r.retryAfterMs } : {}),
      });
      if (this.#authAttempts >= MAX_AUTH_ATTEMPTS_PER_SESSION) this.end('too many failed logins');
      return;
    }
    this.#authBusy = false;
    this.#user = user!;
    this.#state = 'ready';
    this.#session!.followPeerCadence = true;
    this.#ctx.log('login-ok', { sid: this.sid, user: user!.name, device: this.#device });
    const p = this.#ctx.config.policy;
    this.#control({
      t: 'auth-ok',
      targets: this.#targetsFor(user!).map(targetInfo),
      limits: { idleTimeoutSeconds: p.idleTimeoutSeconds, maxSessionSeconds: p.maxSessionSeconds },
    });
  }

  #internalError(err: Error): void {
    this.#ctx.log('internal-error', { sid: this.sid, error: err.message });
    this.end('internal error');
  }

  #targetsFor(user: UserConfig): TargetConfig[] {
    const all = this.#ctx.config.targets;
    return user.targets === '*' ? all : all.filter((t) => (user.targets as string[]).includes(t.id));
  }

  /** End the current remote desktop without telling the client (it asked, or replaced it). */
  #dropDesktop(reason: string): void {
    if (this.#state !== 'remote') return;
    this.#openGen++;
    this.#releaseDesktop();
    this.#state = 'ready';
    this.#ctx.log('target-closed', { sid: this.sid, user: this.#user?.name, target: this.#targetId, reason });
    this.#targetId = null;
  }

  /** Forget and close every connection that belongs to the current desktop. */
  #releaseDesktop(): void {
    const sockets = [this.#stream, this.#rdpServer];
    this.#stream = null;
    this.#rdpServer = null;
    this.#rdpRequest = null;
    this.#rdpQueued = [];
    this.#target = null;
    if (this.#rdpTimer) clearTimeout(this.#rdpTimer);
    this.#rdpTimer = null;
    for (const s of sockets) s?.destroy();
  }

  async #onOpen(msg: Extract<ControlMessage, { t: 'open' }>): Promise<void> {
    const ref = typeof msg.ref === 'number' && Number.isSafeInteger(msg.ref) ? msg.ref : undefined;
    if (!this.#user || (this.#state !== 'ready' && this.#state !== 'remote')) {
      return this.#control({ t: 'open-fail', message: 'not signed in', ref });
    }
    // A new request replaces whatever desktop is open or still opening.
    this.#dropDesktop('replaced by a new request');
    const target = this.#targetsFor(this.#user).find((t) => t.id === msg.target);
    if (!target) return this.#control({ t: 'open-fail', message: 'unknown target', ref });
    const engine = targetEngine(target);
    this.#state = 'remote';
    this.#targetId = target.id;
    this.#target = target;
    this.#engine = engine;
    this.#openRef = ref;
    const gen = ++this.#openGen;
    const superseded = () => (this.#state as State) === 'closed' || gen !== this.#openGen;
    try {
      let guac: { socket: Socket; leftover: Buffer } | null = null;
      if (engine === 'rdp') {
        // Reach the RDP server now so an unreachable computer is reported
        // right away; the connection waits for the browser's RDP client.
        const server = await connectRdpServer({ host: target.hostname, port: target.port ?? 3389 });
        if (superseded()) {
          server.destroy();
          return;
        }
        this.#rdpServer = server;
        this.#rdpRequest = Buffer.alloc(0);
        server.on('close', () => this.#onStreamClosed(server));
        this.#rdpTimer = setTimeout(() => {
          if (this.#rdpServer !== server) return;
          this.#ctx.log('target-fail', { sid: this.sid, user: this.#user?.name, target: target.id, error: 'browser did not start RDP' });
          this.#endDesktop();
        }, RDP_REQUEST_TIMEOUT_MS);
        this.#rdpTimer.unref();
      } else {
        const size = {
          width: clampInt(msg.width, 320, 8192, 1280),
          height: clampInt(msg.height, 200, 8192, 720),
          dpi: clampInt(msg.dpi, 48, 384, 96),
        };
        const creds = target.username ? {} : sanitizeCreds(msg.credentials);
        guac = await connectGuacd({
          host: this.#ctx.config.guacd.host,
          port: this.#ctx.config.guacd.port,
          protocol: 'rdp',
          params: rdpParams({ ...target, ...creds }, size),
          ...size,
          ...(typeof msg.timezone === 'string' && /^[A-Za-z0-9_/+-]{1,64}$/.test(msg.timezone) ? { timezone: msg.timezone } : {}),
        });
        if (superseded()) {
          guac.socket.destroy(); // session ended or the request was superseded
          return;
        }
      }
      this.#ctx.log('target-open', { sid: this.sid, user: this.#user.name, target: target.id, engine });
      this.#control({ t: 'open-ok', ref, engine });
      if (guac) this.#attachStream(guac.socket, guac.leftover);
    } catch (err) {
      if (superseded()) return;
      this.#state = 'ready';
      this.#targetId = null;
      this.#target = null;
      this.#ctx.log('target-fail', { sid: this.sid, user: this.#user.name, target: target.id, error: (err as Error).message });
      this.#control({ t: 'open-fail', message: 'could not connect to the remote desktop', ref });
    }
  }

  #attachStream(socket: Socket, leftover?: Buffer): void {
    this.#stream = socket;
    if (leftover?.length) this.#toClient(leftover);
    socket.on('data', (chunk: Buffer) => this.#toClient(chunk));
    socket.on('close', () => this.#onStreamClosed(socket));
    socket.on('error', () => socket.destroy());
    socket.resume();
  }

  #toClient(chunk: Uint8Array): void {
    const s = this.#session;
    if (!s?.writable) return;
    s.send(this.#engine === 'rdp' ? CHANNEL_RDP : CHANNEL_GUAC, new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength));
    if (s.bufferedAmount > s.highWaterMark) this.#stream?.pause();
  }

  #onGuacFromClient(data: Uint8Array): void {
    if (this.#state !== 'remote' || this.#engine !== 'guacd' || !this.#stream) return;
    // Count only real input as activity (the client also sends sync acks).
    const head = String.fromCharCode(...data.subarray(0, 8));
    if (head.startsWith('3.key,') || head.startsWith('5.mouse,') || head.startsWith('5.touch,')) this.#lastInputAt = Date.now();
    this.#stream.write(data);
  }

  #onRdpFromClient(data: Uint8Array): void {
    if (this.#state !== 'remote' || this.#engine !== 'rdp') return;
    if (this.#stream) {
      // Client-to-server fast-path PDUs carry only keyboard and mouse input;
      // everything else (TPKT, starting 0x03) is protocol traffic.
      if (data.length > 0 && (data[0]! & 0x03) === 0) this.#lastInputAt = Date.now();
      this.#stream.write(data);
      return;
    }
    const server = this.#rdpServer;
    if (!server || this.#rdpRequest === null) {
      // Negotiating: the browser waits for our answer, but keep order anyway.
      if (this.#rdpQueued.length < 64) this.#rdpQueued.push(data.slice());
      return;
    }
    const buf = Buffer.concat([this.#rdpRequest, data]);
    let len: number | null;
    try {
      len = rdCleanPathLength(buf);
    } catch {
      len = -1;
    }
    if (len === -1 || buf.length > MAX_RDCLEANPATH_REQUEST || (len !== null && len > MAX_RDCLEANPATH_REQUEST)) {
      this.#ctx.log('target-fail', { sid: this.sid, user: this.#user?.name, target: this.#targetId, error: 'invalid RDCleanPath request' });
      return this.#endDesktop();
    }
    if (len === null || buf.length < len) {
      this.#rdpRequest = buf;
      return;
    }
    if (buf.length > len) this.#rdpQueued.push(buf.subarray(len));
    this.#rdpRequest = null;
    this.#rdpServer = null;
    if (this.#rdpTimer) clearTimeout(this.#rdpTimer);
    this.#rdpTimer = null;
    server.removeAllListeners('close');
    let request;
    try {
      request = decodeRdCleanPath(buf.subarray(0, len));
    } catch {
      request = { version: 0 }; // answered with an error below
    }
    const gen = this.#openGen;
    const target = this.#target!;
    negotiateRdp(request, server, { ...(target.certSha256 ? { certSha256: target.certSha256 } : {}) })
      .then((bridge) => this.#onRdpNegotiated(gen, target, bridge))
      .catch((err: Error) => this.#internalError(err));
  }

  #onRdpNegotiated(gen: number, target: TargetConfig, bridge: RdpBridge): void {
    if ((this.#state as State) === 'closed' || gen !== this.#openGen) {
      bridge.stream?.destroy();
      return;
    }
    this.#session?.send(CHANNEL_RDP, bridge.response);
    if (!bridge.stream) {
      // The browser's RDP client reports the failure; no separate notice, so
      // the user sees its specific reason.
      this.#ctx.log('target-fail', { sid: this.sid, user: this.#user?.name, target: target.id, error: bridge.error });
      this.#openGen++;
      this.#releaseDesktop();
      this.#state = 'ready';
      this.#targetId = null;
      return;
    }
    this.#ctx.log('rdp-connected', {
      sid: this.sid,
      user: this.#user?.name,
      target: target.id,
      protocol: bridge.selectedProtocol,
      ...(bridge.certSha256 ? { certSha256: bridge.certSha256 } : {}),
    });
    const queued = this.#rdpQueued;
    this.#rdpQueued = [];
    this.#attachStream(bridge.stream);
    for (const q of queued) this.#onRdpFromClient(q);
  }

  /** The desktop ended on the agent's side: tell the client. */
  #endDesktop(): void {
    if (this.#state !== 'remote') return;
    this.#openGen++;
    this.#releaseDesktop();
    this.#ctx.log('target-closed', { sid: this.sid, user: this.#user?.name, target: this.#targetId });
    this.#state = 'ready';
    this.#targetId = null;
    this.#control({ t: 'closed', message: 'remote desktop disconnected', ref: this.#openRef });
  }

  #onStreamClosed(socket: Socket): void {
    if (this.#stream !== socket && this.#rdpServer !== socket) return;
    this.#endDesktop();
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
  const engine = targetEngine(t);
  if (engine === 'guacd') return { id: t.id, name: t.name, protocol: t.protocol, engine, promptCredentials: !t.username };
  return {
    id: t.id,
    name: t.name,
    protocol: t.protocol,
    engine,
    // Without NLA the remote computer shows its own sign-in screen.
    promptCredentials: (t.security ?? 'nla') !== 'tls',
    ...(t.username ? { username: t.username } : {}),
    ...(t.domain ? { domain: t.domain } : {}),
  };
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
