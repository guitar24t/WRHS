// Wire constants shared by client, relay and agent.
//
// Every message on a relay session (one WebSocket message, or one
// length-prefixed entry in a long-poll body) is a "frame". The first byte
// says who the frame is for:
//
//   0x00         relay control: UTF-8 JSON between an endpoint and the relay.
//                Unauthenticated hints (ready, peer gone, ...). Never trusted
//                for anything except liveness.
//   0x01..0x03   Noise handshake messages 1..3 (end-to-end, opaque to relay).
//   0x10         Encrypted record (end-to-end, opaque to relay).
//
// The relay forwards every non-zero frame unchanged to the other side.

import { concat, fromUtf8, readU32, utf8, writeU32 } from './bytes.ts';

export const PROTOCOL_VERSION = 1;
export const PROLOGUE = utf8('WRHS/1');

export const FRAME_RELAY = 0x00;
export const FRAME_HS1 = 0x01;
export const FRAME_HS2 = 0x02;
export const FRAME_HS3 = 0x03;
export const FRAME_RECORD = 0x10;

/** Largest frame anybody should send. Records are capped well below this. */
export const MAX_FRAME = 70 * 1024;

/** Application channels multiplexed inside the encrypted session. */
export const CHANNEL_CONTROL = 1;
export const CHANNEL_GUAC = 2;

export type RelayMessage =
  | { t: 'session'; sid: string }
  | { t: 'ready' }
  | { t: 'peer-gone' }
  | { t: 'error'; code: string; message?: string };

export function relayFrame(msg: RelayMessage): Uint8Array {
  return concat(Uint8Array.of(FRAME_RELAY), utf8(JSON.stringify(msg)));
}

export function parseRelayFrame(frame: Uint8Array): RelayMessage {
  return JSON.parse(fromUtf8(frame.subarray(1))) as RelayMessage;
}

/** Long-poll bodies carry frames as [u32 length][frame]... */
export function encodeFrameBatch(frames: Uint8Array[]): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const f of frames) {
    const len = new Uint8Array(4);
    writeU32(len, 0, f.length);
    parts.push(len, f);
  }
  return concat(...parts);
}

export function decodeFrameBatch(body: Uint8Array, maxFrame = MAX_FRAME): Uint8Array[] {
  const frames: Uint8Array[] = [];
  let off = 0;
  while (off < body.length) {
    if (off + 4 > body.length) throw new Error('truncated frame batch');
    const len = readU32(body, off);
    off += 4;
    if (len === 0 || len > maxFrame || off + len > body.length) throw new Error('bad frame length');
    frames.push(body.subarray(off, off + len));
    off += len;
  }
  return frames;
}

/** Hello carried (encrypted) in Noise message 2. */
export interface AgentHello {
  v: number;
  name: string;
  software: string;
}

/** Hello carried (encrypted) in Noise message 3. */
export interface ClientHello {
  v: number;
  software: string;
}

/** Messages on CHANNEL_CONTROL, JSON encoded. */
export type ControlMessage =
  | { t: 'auth-required'; methods: string[] }
  | { t: 'auth'; user: string; password: string; totp?: string }
  | { t: 'auth-ok'; targets: TargetInfo[]; limits?: SessionLimits }
  | { t: 'auth-fail'; message: string; retryAfterMs?: number; attemptsLeft?: number }
  | {
      t: 'open';
      target: string;
      width: number;
      height: number;
      dpi: number;
      timezone?: string;
      credentials?: { username?: string; password?: string; domain?: string };
      /** Echoed in open-ok/open-fail/closed so replies can be matched to this request. */
      ref?: number;
    }
  | { t: 'open-ok'; ref?: number }
  | { t: 'open-fail'; message: string; ref?: number }
  | { t: 'close-desktop' }
  | { t: 'closed'; message: string; ref?: number }
  | { t: 'error'; message: string };

/** Agent policy the client can warn about before it takes effect. 0 = no limit. */
export interface SessionLimits {
  idleTimeoutSeconds: number;
  maxSessionSeconds: number;
}

export interface TargetInfo {
  id: string;
  name: string;
  protocol: string;
  /** True when the agent will ask the client for RDP credentials. */
  promptCredentials: boolean;
}
