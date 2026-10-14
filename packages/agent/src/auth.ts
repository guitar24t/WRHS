// User authentication inside the encrypted channel: scrypt password hashes
// plus RFC 6238 TOTP, with lockout and replay protection.
//
// The password is only ever sent inside the Noise session, after the client
// has verified the agent's pinned key, so a TLS-intercepting proxy never sees
// it and a fake agent never receives it.

import { createHmac, randomBytes, scrypt as scryptCb, timingSafeEqual, type ScryptOptions } from 'node:crypto';

function scrypt(password: string, salt: Buffer, keylen: number, opts: ScryptOptions): Promise<Buffer> {
  return new Promise((resolve, reject) =>
    scryptCb(password, salt, keylen, opts, (err, key) => (err ? reject(err) : resolve(key))),
  );
}

const SCRYPT_LOG_N = 15;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_MAXMEM = 128 * 1024 * 1024;

export async function hashPassword(password: string): Promise<string> {
  if (password.length < 12) throw new Error('password must be at least 12 characters');
  const salt = randomBytes(16);
  const key = await scrypt(password.normalize('NFC'), salt, 32, {
    N: 2 ** SCRYPT_LOG_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: SCRYPT_MAXMEM,
  });
  return `scrypt$${SCRYPT_LOG_N}$${SCRYPT_R}$${SCRYPT_P}$${salt.toString('base64url')}$${key.toString('base64url')}`;
}

// Used for unknown users so that response timing does not reveal which
// user names exist.
const DUMMY_HASH = 'scrypt$15$8$1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

export async function verifyPassword(password: string, encoded: string | undefined): Promise<boolean> {
  const parts = (encoded ?? DUMMY_HASH).split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, logN, r, p, salt, hash] = parts as [string, string, string, string, string, string];
  const expected = Buffer.from(hash, 'base64url');
  const key = await scrypt(password.normalize('NFC'), Buffer.from(salt, 'base64url'), expected.length, {
    N: 2 ** Number(logN),
    r: Number(r),
    p: Number(p),
    maxmem: SCRYPT_MAXMEM,
  });
  return encoded !== undefined && timingSafeEqual(key, expected);
}

// ------------------------------------------------------------------ TOTP

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buf: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const b of buf) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(s: string): Buffer {
  const clean = s.toUpperCase().replace(/[\s=-]/g, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const v = B32.indexOf(ch);
    if (v < 0) throw new Error('invalid base32');
    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function generateTotpSecret(): string {
  return base32Encode(randomBytes(20));
}

export function totpCode(secret: string, counter: number): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac('sha1', base32Decode(secret)).update(msg).digest();
  const off = mac[mac.length - 1]! & 0x0f;
  const bin = (mac.readUInt32BE(off) & 0x7fffffff) % 1_000_000;
  return bin.toString().padStart(6, '0');
}

/** Returns the matching time-step counter, or null. Accepts +/- one 30 s step. */
export function verifyTotp(secret: string, code: string, nowMs = Date.now()): number | null {
  if (!/^\d{6}$/.test(code)) return null;
  const counter = Math.floor(nowMs / 1000 / 30);
  for (const c of [counter, counter - 1, counter + 1]) {
    const expected = Buffer.from(totpCode(secret, c));
    if (timingSafeEqual(expected, Buffer.from(code))) return c;
  }
  return null;
}

export function otpauthUri(secret: string, user: string, issuer: string): string {
  const label = encodeURIComponent(`${issuer}:${user}`);
  return `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

// ------------------------------------------------------------------ policy

export interface UserRecord {
  name: string;
  passwordHash: string;
  totpSecret?: string;
}

export interface AuthPolicy {
  requireTotp: boolean;
  maxFailures: number;
  lockoutMs: number;
}

export type AuthResult =
  | { ok: true; user: string }
  | { ok: false; message: string; retryAfterMs?: number };

/** Verifies credentials and tracks failures, lockouts and TOTP replay. */
export class Authenticator {
  readonly #users: () => UserRecord[];
  readonly #policy: AuthPolicy;
  readonly #failures = new Map<string, { count: number; inflight: number; lockedUntil: number }>();
  readonly #lastTotpCounter = new Map<string, number>();

  constructor(users: () => UserRecord[], policy: AuthPolicy) {
    this.#users = users;
    this.#policy = policy;
  }

  /**
   * @param extraCheck  additional condition evaluated like a credential
   *   (e.g. the device allow-list); failing it is an ordinary failure.
   */
  async authenticate(
    userName: string,
    password: string,
    totp: string | undefined,
    now = Date.now(),
    extraCheck: (user: string) => boolean = () => true,
  ): Promise<AuthResult> {
    const key = userName.toLowerCase();
    this.#prune(now);
    const rec = this.#failures.get(key) ?? { count: 0, inflight: 0, lockedUntil: 0 };
    if (rec.lockedUntil > now) {
      return { ok: false, message: 'account temporarily locked', retryAfterMs: rec.lockedUntil - now };
    }
    // Reserve a failure slot before the slow hash, so parallel attempts
    // (from many sessions at once) cannot exceed the failure budget.
    if (rec.count + rec.inflight >= this.#policy.maxFailures) {
      return { ok: false, message: 'too many attempts in progress', retryAfterMs: 1000 };
    }
    rec.inflight++;
    this.#failures.set(key, rec);
    let ok = false;
    let counter: number | null = null;
    let user: UserRecord | undefined;
    try {
      user = this.#users().find((u) => u.name.toLowerCase() === key);
      const passwordOk = await verifyPassword(password, user?.passwordHash);
      let totpOk = true;
      if (user && (user.totpSecret || this.#policy.requireTotp)) {
        counter = user.totpSecret ? verifyTotp(user.totpSecret, totp ?? '', now) : null;
        const last = this.#lastTotpCounter.get(key) ?? -1;
        totpOk = counter !== null && counter > last;
      }
      ok = Boolean(user) && passwordOk && totpOk && extraCheck(user!.name);
    } finally {
      rec.inflight--;
    }
    if (!ok) {
      rec.count++;
      if (rec.count >= this.#policy.maxFailures) {
        rec.count = 0;
        rec.lockedUntil = now + this.#policy.lockoutMs;
      }
      return { ok: false, message: 'invalid credentials' };
    }
    if (rec.inflight === 0) this.#failures.delete(key);
    else rec.count = 0;
    if (counter !== null) this.#lastTotpCounter.set(key, counter);
    return { ok: true, user: user!.name };
  }

  /** Forget stale failure records (one is created per guessed user name). */
  #prune(now: number): void {
    if (this.#failures.size < 10_000) return;
    for (const [k, r] of this.#failures) if (r.inflight === 0 && r.lockedUntil <= now) this.#failures.delete(k);
  }
}
