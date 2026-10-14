// Application-level client protocol on top of an established SecureSession:
// login, target selection, and the desktop byte streams. Shared by the
// browser UI and the end-to-end tests.

import { Emitter } from './emitter.ts';
import { fromUtf8, utf8 } from './bytes.ts';
import type { SecureSession } from './session.ts';
import {
  CHANNEL_CONTROL,
  CHANNEL_GUAC,
  CHANNEL_RDP,
  type ControlMessage,
  type DesktopEngine,
  type SessionLimits,
  type TargetInfo,
} from './wire.ts';

export class AuthError extends Error {
  readonly retryAfterMs: number | undefined;
  /** Sign-in attempts left before the agent closes this connection. */
  readonly attemptsLeft: number | undefined;
  constructor(message: string, retryAfterMs?: number, attemptsLeft?: number) {
    super(message);
    this.name = 'AuthError';
    this.retryAfterMs = retryAfterMs;
    this.attemptsLeft = attemptsLeft;
  }
}

export type AppEvents = {
  control: [msg: ControlMessage];
  guac: [data: Uint8Array];
  rdp: [data: Uint8Array];
};

export class AppChannel extends Emitter<AppEvents> {
  readonly session: SecureSession;
  #authRequired: Extract<ControlMessage, { t: 'auth-required' }> | null = null;
  /** Limits the agent announced at sign-in, if any. */
  limits: SessionLimits | null = null;
  /** Reference of the most recent open request (replies and "closed" carry it). */
  lastOpenRef = 0;

  constructor(session: SecureSession) {
    super();
    this.session = session;
    session.on('message', (ch, data) => {
      if (ch === CHANNEL_GUAC) return this.emit('guac', data);
      if (ch === CHANNEL_RDP) return this.emit('rdp', data);
      if (ch !== CHANNEL_CONTROL) return;
      let msg: ControlMessage;
      try {
        msg = JSON.parse(fromUtf8(data)) as ControlMessage;
      } catch {
        return;
      }
      if (msg.t === 'auth-required') this.#authRequired = msg;
      this.emit('control', msg);
    });
  }

  sendControl(msg: ControlMessage): void {
    this.session.send(CHANNEL_CONTROL, utf8(JSON.stringify(msg)));
  }

  sendGuac(instruction: string | Uint8Array): void {
    this.session.send(CHANNEL_GUAC, typeof instruction === 'string' ? utf8(instruction) : instruction);
  }

  sendRdp(data: Uint8Array): void {
    this.session.send(CHANNEL_RDP, data);
  }

  waitFor<T extends ControlMessage['t']>(
    types: T[],
    timeoutMs = 30_000,
    match: (m: Extract<ControlMessage, { t: T }>) => boolean = () => true,
  ): Promise<Extract<ControlMessage, { t: T }>> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        cleanup();
        reject(new Error(`timed out waiting for ${types.join('/')}`));
      }, timeoutMs);
      const offMsg = this.on('control', (m) => {
        if ((types as string[]).includes(m.t) && match(m as Extract<ControlMessage, { t: T }>)) {
          cleanup();
          resolve(m as Extract<ControlMessage, { t: T }>);
        }
      });
      const offClose = this.session.on('close', (info) => {
        cleanup();
        reject(info.error ?? new Error(info.reason));
      });
      const cleanup = () => {
        clearTimeout(timer);
        offMsg();
        offClose();
      };
    });
  }

  /** The agent sends auth-required right after the handshake. */
  async authMethods(timeoutMs = 30_000): Promise<string[]> {
    if (this.#authRequired) return this.#authRequired.methods;
    return (await this.waitFor(['auth-required'], timeoutMs)).methods;
  }

  async login(user: string, password: string, totp?: string): Promise<TargetInfo[]> {
    await this.authMethods();
    const reply = this.waitFor(['auth-ok', 'auth-fail']);
    this.sendControl({ t: 'auth', user, password, ...(totp ? { totp } : {}) });
    const r = await reply;
    if (r.t === 'auth-fail') throw new AuthError(r.message, r.retryAfterMs, r.attemptsLeft);
    this.limits = r.limits ?? null;
    return r.targets;
  }

  /**
   * Open a desktop; resolves once the agent has reached the remote computer,
   * with the request reference and the engine that will draw it.
   */
  async open(req: Omit<Extract<ControlMessage, { t: 'open' }>, 't' | 'ref'>): Promise<{ ref: number; engine: DesktopEngine }> {
    const ref = ++this.lastOpenRef;
    const reply = this.waitFor(['open-ok', 'open-fail'], 30_000, (m) => m.ref === undefined || m.ref === ref);
    this.sendControl({ t: 'open', ...req, ref });
    const r = await reply;
    if (r.t === 'open-fail') throw new Error(r.message);
    return { ref, engine: r.engine ?? 'guacd' };
  }

  /** Close the current desktop without signing out. */
  closeDesktop(): void {
    if (this.session.writable) this.sendControl({ t: 'close-desktop' });
  }
}
