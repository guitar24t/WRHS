// Encrypted, reliable, resumable record layer that runs after the Noise
// handshake.
//
// Why not plain Noise transport messages? The outer HTTPS connection goes
// through proxies that may cut it at any time, and the long-poll fallback can
// lose a response. So records carry an explicit 64-bit nonce (Noise spec
// section 11.4), and the layer implements go-back-N reliability end to end:
// the relay never buffers, never retransmits, and never sees plaintext.
//
// Packet:    [0x10][nonce u64 BE][ChaCha20-Poly1305 ciphertext]   AD = first 9 bytes
// Nonce:     top bit 0 -> reliable record, nonce = sequence number
//            top bit 1 -> unreliable record (ACK/PING/PONG), nonce = 2^63 + counter
// Plaintext: [kind u8][flags u8][channel u8][0][ack u64][len u32][payload][zero padding]
//
// A retransmission resends the exact sealed bytes, so a nonce is never reused
// with different plaintext. A record that fails authentication is treated as
// active tampering and the session is torn down.

import { CipherState } from './noise.ts';
import { concat, readU32, readU64, utf8, fromUtf8, writeU32, writeU64 } from './bytes.ts';
import { Emitter, weakInterval, weakTimeout } from './emitter.ts';
import { FRAME_RECORD } from './wire.ts';

const KIND_DATA = 1;
const KIND_NOOP = 2;
const KIND_CLOSE = 3;
const KIND_ACK = 4;
const KIND_PING = 5;
const KIND_PONG = 6;

const FLAG_MORE = 0x01; // message continues in the next record
const FLAG_CADENCE = 0x02; // sender's user is interacting (asks the peer to pace too)
const FLAG_GAP = 0x04; // ACK sent because of a sequence gap / duplicate

const UNRELIABLE = 1n << 63n;
const PACKET_HEADER = 9;
const PLAINTEXT_HEADER = 16;
const TAG = 16;
const MAX_PLAINTEXT = 65535 - PACKET_HEADER - TAG;
const MAX_REORDER_RECORDS = 4096;
const MAX_REORDER_BYTES = 16 * 1024 * 1024;

export interface CadenceOptions {
  /** Tick length; while active, records leave only on tick boundaries. */
  intervalMs: number;
  /** How long to keep ticking after the last activity. */
  holdMs: number;
  /** Every record sent while active is padded to at least this many bytes. */
  minPlaintext: number;
  /** Enter cadence mode whenever the peer says it is in cadence mode. */
  followPeer: boolean;
}

export interface SessionOptions {
  maxRecordPayload?: number;
  ackDelayMs?: number;
  minRtoMs?: number;
  initialRtoMs?: number;
  maxRtoMs?: number;
  pingIntervalMs?: number;
  /** Emit "link-dead" when nothing was received for this long on an attached link. */
  deadAfterMs?: number;
  /** Close the session when no link was attached for this long. */
  detachedGraceMs?: number;
  /** bufferedAmount above which writers should pause. */
  highWaterMark?: number;
  maxMessageBytes?: number;
  cadence?: CadenceOptions | null;
}

export interface CloseInfo {
  reason: string;
  /** True if the peer initiated the close. */
  remote: boolean;
  /** Set when the session died because of an error (tampering, protocol violation). */
  error?: Error;
}

export type SessionEvents = {
  message: [channel: number, data: Uint8Array];
  close: [info: CloseInfo];
  drain: [];
  'link-dead': [];
  rtt: [ms: number];
  error: [err: Error];
};

export class IntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IntegrityError';
  }
}

interface Pending {
  kind: number;
  flags: number;
  channel: number;
  payload: Uint8Array;
}

interface InFlight {
  seq: number;
  packet: Uint8Array;
  sentAt: number;
  retransmitted: boolean;
}

const DEFAULTS: Required<Omit<SessionOptions, 'cadence'>> = {
  maxRecordPayload: 16 * 1024,
  ackDelayMs: 40,
  minRtoMs: 1000,
  initialRtoMs: 3000,
  maxRtoMs: 30_000,
  pingIntervalMs: 15_000,
  deadAfterMs: 45_000,
  detachedGraceMs: 120_000,
  highWaterMark: 4 * 1024 * 1024,
  maxMessageBytes: 4 * 1024 * 1024,
};

/** Pad plaintext lengths into coarse buckets so sizes leak less. */
export function paddedLength(n: number, min = 0): number {
  const target = Math.max(n, min);
  const bucket = target <= 512 ? 128 : target <= 4096 ? 512 : 2048;
  return Math.min(Math.ceil(target / bucket) * bucket, MAX_PLAINTEXT);
}

export class SecureSession extends Emitter<SessionEvents> {
  readonly #send: CipherState;
  readonly #recv: CipherState;
  readonly #o: Required<Omit<SessionOptions, 'cadence'>>;
  readonly #cadence: CadenceOptions | null;

  #link: ((frame: Uint8Array) => void) | null = null;
  #closed = false;
  #closing = false;

  // Sending side.
  #sendSeq = 0;
  #unreliableCtr = 0n;
  #queue: Pending[] = [];
  #queuedBytes = 0;
  #inflight: InFlight[] = [];
  #inflightHead = 0;
  #inflightBytes = 0;
  #aboveHighWater = false;
  #rtoTimer: ReturnType<typeof setTimeout> | null = null;
  #rto: number;
  #srtt: number | null = null;
  #rttvar = 0;

  // Receiving side.
  #recvNext = 0;
  #unreliableLast = -1n;
  #ackOwed = false;
  #ackTimer: ReturnType<typeof setTimeout> | null = null;
  #ackTimerDue = 0;
  #partial = new Map<number, Uint8Array[]>();
  #partialBytes = 0;
  /** Authenticated records that arrived ahead of a gap, keyed by sequence number. */
  #reorder = new Map<number, Uint8Array>();
  #reorderBytes = 0;

  // Liveness.
  #lastRecvAt = Date.now();
  #detachedAt: number | null = Date.now();
  #pingTimer: ReturnType<typeof setInterval>;

  // Timing obfuscation.
  #cadenceTimer: ReturnType<typeof setInterval> | null = null;
  #cadenceUntil = 0;
  #followPeer: boolean;
  #lastRetransmitAll = 0;
  /** Until when *local* interaction keeps cadence on; only then do we ask the peer to follow. */
  #localInteractiveUntil = 0;

  readonly handshakeHash: Uint8Array;
  readonly remoteStatic: Uint8Array;

  constructor(
    keys: { send: CipherState; recv: CipherState; handshakeHash: Uint8Array; remoteStatic: Uint8Array },
    options: SessionOptions = {},
  ) {
    super();
    this.#send = keys.send;
    this.#recv = keys.recv;
    this.handshakeHash = keys.handshakeHash;
    this.remoteStatic = keys.remoteStatic;
    const { cadence, ...rest } = options;
    this.#o = { ...DEFAULTS, ...stripUndefined(rest) };
    this.#cadence = cadence ?? null;
    this.#followPeer = this.#cadence?.followPeer ?? false;
    this.#rto = this.#o.initialRtoMs;
    if (this.#o.maxRecordPayload + PLAINTEXT_HEADER > MAX_PLAINTEXT) throw new Error('maxRecordPayload too large');
    this.#pingTimer = weakInterval(() => this.#onPingTimer(), this.#o.pingIntervalMs);
  }

  get closed(): boolean {
    return this.#closed;
  }

  /** False once closed or closing; send() throws then. */
  get writable(): boolean {
    return !this.#closed && !this.#closing;
  }

  /**
   * Whether a peer's CADENCE flag switches our cadence on. The agent keeps
   * this off until the user has logged in, so an unauthenticated peer
   * cannot make it generate chaff.
   */
  set followPeerCadence(on: boolean) {
    this.#followPeer = on;
  }

  get attached(): boolean {
    return this.#link !== null;
  }

  /** Bytes queued or sent but not yet acknowledged by the peer. */
  get bufferedAmount(): number {
    return this.#inflightBytes + this.#queuedBytes;
  }

  get highWaterMark(): number {
    return this.#o.highWaterMark;
  }

  get rttMs(): number | null {
    return this.#srtt;
  }

  get cadenceActive(): boolean {
    return this.#cadenceTimer !== null;
  }

  /** Attach a (new) outer connection and retransmit anything unacknowledged. */
  attach(link: (frame: Uint8Array) => void): void {
    if (this.#closed) return;
    this.#link = link;
    this.#detachedAt = null;
    this.#lastRecvAt = Date.now();
    this.resync();
  }

  detach(): void {
    this.#link = null;
    this.#detachedAt ??= Date.now();
  }

  /** Retransmit every unacknowledged record and tell the peer what we have. */
  resync(): void {
    if (this.#closed || !this.#link) return;
    this.#retransmitAll(true);
    this.#sendUnreliable(KIND_ACK, 0, new Uint8Array(0));
  }

  /** Send one application message on a channel. Large messages are fragmented. */
  send(channel: number, data: Uint8Array): void {
    if (this.#closed || this.#closing) throw new Error('session is closed');
    const max = this.#o.maxRecordPayload;
    let off = 0;
    do {
      const chunk = data.subarray(off, off + max);
      off += chunk.length;
      this.#queue.push({ kind: KIND_DATA, flags: off < data.length ? FLAG_MORE : 0, channel, payload: chunk });
      this.#queuedBytes += chunk.length;
    } while (off < data.length);
    if (!this.cadenceActive) this.#flush(false);
    this.#checkHighWater();
  }

  /**
   * Hide keystroke timing: for holdMs, records leave only on fixed ticks and
   * idle ticks carry padded chaff, so an observer sees a constant stream.
   */
  markInteractive(): void {
    if (!this.#cadence) return;
    this.#localInteractiveUntil = Date.now() + this.#cadence.holdMs;
    this.#startCadence();
  }

  #startCadence(): void {
    const c = this.#cadence;
    if (!c || this.#closed) return;
    this.#cadenceUntil = Math.max(this.#cadenceUntil, Date.now() + c.holdMs);
    if (!this.#cadenceTimer) this.#cadenceTimer = weakInterval(() => this.#onCadenceTick(), c.intervalMs);
  }

  #cadenceFlag(): number {
    return Date.now() < this.#localInteractiveUntil ? FLAG_CADENCE : 0;
  }

  /** Graceful close: tell the peer, wait briefly for the acknowledgement. */
  close(reason = 'closed'): void {
    if (this.#closed || this.#closing) return;
    this.#closing = true;
    this.#queue.push({ kind: KIND_CLOSE, flags: 0, channel: 0, payload: utf8(reason.slice(0, 200)) });
    this.#flush(false);
    weakTimeout(() => this.#finish({ reason, remote: false }), Math.min(this.#rto * 2, 3000));
  }

  /** Feed one record frame received from the outer transport. */
  receive(frame: Uint8Array): void {
    if (this.#closed) return;
    if (frame.length < PACKET_HEADER + PLAINTEXT_HEADER + TAG || frame[0] !== FRAME_RECORD) return;
    this.#lastRecvAt = Date.now();
    const nonce = readU64(frame, 1);
    const header = frame.subarray(0, PACKET_HEADER);
    const body = frame.subarray(PACKET_HEADER);

    if (nonce & UNRELIABLE) {
      const ctr = nonce & ~UNRELIABLE;
      if (ctr <= this.#unreliableLast) return; // replayed or reordered control record
      const pt = this.#open(nonce, header, body);
      if (!pt) return;
      this.#unreliableLast = ctr;
      this.#handle(pt, false);
      return;
    }

    if (nonce > BigInt(Number.MAX_SAFE_INTEGER)) return this.#fail(new IntegrityError('sequence number out of range'));
    const seq = Number(nonce);
    if (seq !== this.#recvNext) {
      // Duplicate (our ack was lost) or a gap (records dropped while the
      // outer link was down). Keep records from beyond the gap so the
      // retransmission only has to fill the hole, and tell the peer now.
      if (
        seq > this.#recvNext &&
        seq - this.#recvNext <= MAX_REORDER_RECORDS &&
        !this.#reorder.has(seq) &&
        this.#reorderBytes + body.length <= MAX_REORDER_BYTES
      ) {
        const pt = this.#open(nonce, header, body);
        if (!pt) return;
        this.#reorder.set(seq, pt);
        this.#reorderBytes += pt.length;
      }
      this.#scheduleAck(0, true);
      return;
    }
    const pt = this.#open(nonce, header, body);
    if (!pt) return;
    this.#recvNext++;
    this.#ackOwed = true;
    this.#handle(pt, true);
    // Deliver anything that was waiting behind this record.
    while (!this.#closed && this.#reorder.size > 0) {
      const next = this.#reorder.get(this.#recvNext);
      if (!next) break;
      this.#reorder.delete(this.#recvNext);
      this.#reorderBytes -= next.length;
      this.#recvNext++;
      this.#handle(next, true);
    }
    if (this.#ackOwed && !this.#closed) this.#scheduleAck(this.#o.ackDelayMs, false);
  }

  // ---------------------------------------------------------------- internals

  #open(nonce: bigint, header: Uint8Array, body: Uint8Array): Uint8Array | null {
    try {
      return this.#recv.openAt(nonce, header, body);
    } catch {
      this.#fail(new IntegrityError('record failed authentication: traffic was modified in transit'));
      return null;
    }
  }

  #handle(pt: Uint8Array, reliable: boolean): void {
    const kind = pt[0]!;
    const flags = pt[1]!;
    const channel = pt[2]!;
    const ack = readU64(pt, 4);
    const len = readU32(pt, 12);
    if (PLAINTEXT_HEADER + len > pt.length) return this.#fail(new IntegrityError('bad record length'));
    const payload = pt.subarray(PLAINTEXT_HEADER, PLAINTEXT_HEADER + len);

    this.#onAck(ack, kind === KIND_ACK && (flags & FLAG_GAP) !== 0);
    if (this.#closed) return;
    // Following does not set FLAG_CADENCE on our records, so two followers
    // cannot keep each other ticking forever.
    if (flags & FLAG_CADENCE && this.#followPeer) this.#startCadence();

    if (reliable) {
      switch (kind) {
        case KIND_DATA:
          this.#onData(channel, flags, payload);
          return;
        case KIND_NOOP:
          return;
        case KIND_CLOSE:
          this.#sendUnreliable(KIND_ACK, 0, new Uint8Array(0));
          this.#finish({ reason: safeUtf8(payload) || 'closed by peer', remote: true });
          return;
        default:
          return this.#fail(new IntegrityError(`unexpected reliable record kind ${kind}`));
      }
    }
    switch (kind) {
      case KIND_ACK:
        return;
      case KIND_PING:
        this.#sendUnreliable(KIND_PONG, 0, payload.slice(0, 8));
        return;
      case KIND_PONG: {
        if (payload.length === 8) {
          const sent = Number(readU64(payload, 0));
          const rtt = Date.now() - sent;
          if (rtt >= 0 && rtt < 120_000) {
            this.#rttSample(rtt);
            this.emit('rtt', rtt);
          }
        }
        return;
      }
      default:
        return this.#fail(new IntegrityError(`unexpected control record kind ${kind}`));
    }
  }

  #onData(channel: number, flags: number, payload: Uint8Array): void {
    const parts = this.#partial.get(channel);
    if (flags & FLAG_MORE || parts) {
      // One budget for all partially received messages, whatever the channel.
      this.#partialBytes += payload.length;
      if (this.#partialBytes > this.#o.maxMessageBytes) return this.#fail(new Error('message too large'));
      const list = parts ?? [];
      list.push(payload.slice());
      if (flags & FLAG_MORE) {
        this.#partial.set(channel, list);
        return;
      }
      this.#partial.delete(channel);
      const msg = concat(...list);
      this.#partialBytes -= msg.length;
      this.#deliver(channel, msg);
      return;
    }
    this.#deliver(channel, payload.slice());
  }

  #deliver(channel: number, data: Uint8Array): void {
    try {
      this.emit('message', channel, data);
    } catch (err) {
      this.emit('error', err as Error);
    }
  }

  #onAck(ack: bigint, gapReport: boolean): void {
    if (ack > BigInt(this.#sendSeq)) return this.#fail(new IntegrityError('peer acknowledged unsent data'));
    const upTo = Number(ack);
    let progressed = false;
    const now = Date.now();
    while (this.#inflightHead < this.#inflight.length && this.#inflight[this.#inflightHead]!.seq < upTo) {
      const r = this.#inflight[this.#inflightHead]!;
      this.#inflight[this.#inflightHead] = undefined as unknown as InFlight;
      this.#inflightHead++;
      this.#inflightBytes -= r.packet.length;
      if (!r.retransmitted) this.#rttSample(now - r.sentAt);
      progressed = true;
    }
    if (this.#inflightHead > 1024 && this.#inflightHead * 2 > this.#inflight.length) {
      this.#inflight = this.#inflight.slice(this.#inflightHead);
      this.#inflightHead = 0;
    }
    const outstanding = this.#inflightHead < this.#inflight.length;
    if (progressed) {
      this.#rto = this.#computeRto();
      this.#restartRto();
      this.#checkDrain();
      if (this.#closing && !outstanding) this.#finish({ reason: 'closed', remote: false });
    } else if (gapReport && outstanding) {
      // Peer saw a gap: go back N now instead of waiting for the RTO.
      this.#retransmitAll(true);
    }
  }

  #rttSample(r: number): void {
    if (this.#srtt === null) {
      this.#srtt = r;
      this.#rttvar = r / 2;
    } else {
      this.#rttvar = 0.75 * this.#rttvar + 0.25 * Math.abs(this.#srtt - r);
      this.#srtt = 0.875 * this.#srtt + 0.125 * r;
    }
  }

  #computeRto(): number {
    if (this.#srtt === null) return this.#o.initialRtoMs;
    const rto = this.#srtt + 4 * this.#rttvar + this.#o.ackDelayMs;
    return Math.min(Math.max(rto, this.#o.minRtoMs), this.#o.maxRtoMs);
  }

  #restartRto(): void {
    if (this.#rtoTimer) clearTimeout(this.#rtoTimer);
    this.#rtoTimer = null;
    if (this.#inflightHead < this.#inflight.length && !this.#closed) {
      this.#rtoTimer = weakTimeout(() => this.#onRto(), this.#rto);
    }
  }

  #onRto(): void {
    this.#rtoTimer = null;
    if (this.#closed || this.#inflightHead >= this.#inflight.length) return;
    this.#retransmitAll();
    this.#rto = Math.min(this.#rto * 2, this.#o.maxRtoMs);
    this.#restartRto();
  }

  /**
   * Go back N. Peer-triggered retransmissions (gap reports, reattaches) are
   * limited to one per round trip, so a peer cannot use them to amplify.
   */
  #retransmitAll(peerTriggered = false): void {
    if (!this.#link) return;
    const now = Date.now();
    if (peerTriggered && now - this.#lastRetransmitAll < Math.max(200, this.#srtt ?? 200)) return;
    this.#lastRetransmitAll = now;
    for (let i = this.#inflightHead; i < this.#inflight.length; i++) {
      const r = this.#inflight[i]!;
      r.retransmitted = true;
      this.#transmit(r.packet);
    }
  }

  #scheduleAck(delay: number, gap: boolean): void {
    if (this.#closed) return;
    const due = Date.now() + delay;
    if (this.#ackTimer && this.#ackTimerDue <= due) return;
    if (this.#ackTimer) clearTimeout(this.#ackTimer);
    this.#ackTimerDue = due;
    this.#ackTimer = weakTimeout(() => {
      this.#ackTimer = null;
      if (this.#closed) return;
      // In cadence mode the next tick carries the ack, unless it is a gap report.
      if (!gap && (!this.#ackOwed || this.cadenceActive)) return;
      this.#sendUnreliable(KIND_ACK, gap ? FLAG_GAP : 0, new Uint8Array(0));
    }, delay);
  }

  #flush(cadence: boolean): void {
    const min = cadence && this.#cadence ? this.#cadence.minPlaintext : 0;
    const flags = cadence ? this.#cadenceFlag() : 0;
    const items = this.#queue;
    this.#queue = [];
    this.#queuedBytes = 0;
    for (const item of items) this.#sendReliable(item.kind, item.flags | flags, item.channel, item.payload, min);
  }

  #onCadenceTick(): void {
    if (this.#closed) return;
    if (this.#queue.length > 0) {
      this.#flush(true);
    } else if (Date.now() < this.#cadenceUntil && this.#inflightBytes < this.#o.highWaterMark) {
      this.#sendReliable(KIND_NOOP, this.#cadenceFlag(), 0, new Uint8Array(0), this.#cadence!.minPlaintext);
    } else if (this.#cadenceTimer) {
      clearInterval(this.#cadenceTimer);
      this.#cadenceTimer = null;
    }
  }

  #buildPlaintext(kind: number, flags: number, channel: number, payload: Uint8Array, minPad: number): Uint8Array {
    const pt = new Uint8Array(paddedLength(PLAINTEXT_HEADER + payload.length, minPad));
    pt[0] = kind;
    pt[1] = flags;
    pt[2] = channel;
    writeU64(pt, 4, BigInt(this.#recvNext));
    writeU32(pt, 12, payload.length);
    pt.set(payload, PLAINTEXT_HEADER);
    return pt;
  }

  #seal(nonce: bigint, pt: Uint8Array): Uint8Array {
    const packet = new Uint8Array(PACKET_HEADER + pt.length + TAG);
    packet[0] = FRAME_RECORD;
    writeU64(packet, 1, nonce);
    packet.set(this.#send.sealAt(nonce, packet.subarray(0, PACKET_HEADER), pt), PACKET_HEADER);
    return packet;
  }

  #sendReliable(kind: number, flags: number, channel: number, payload: Uint8Array, minPad: number): void {
    const seq = this.#sendSeq++;
    const packet = this.#seal(BigInt(seq), this.#buildPlaintext(kind, flags, channel, payload, minPad));
    this.#inflight.push({ seq, packet, sentAt: Date.now(), retransmitted: false });
    this.#inflightBytes += packet.length;
    this.#ackOwed = false;
    this.#transmit(packet);
    if (!this.#rtoTimer) this.#restartRto();
  }

  #sendUnreliable(kind: number, flags: number, payload: Uint8Array): void {
    if (!this.#link) return;
    const ctr = this.#unreliableCtr++;
    const min = this.cadenceActive && this.#cadence ? this.#cadence.minPlaintext : 0;
    const p = kind === KIND_PING ? nowBytes() : payload;
    const packet = this.#seal(UNRELIABLE | ctr, this.#buildPlaintext(kind, flags, 0, p, min));
    if (kind === KIND_ACK) this.#ackOwed = false;
    this.#transmit(packet);
  }

  #transmit(packet: Uint8Array): void {
    if (!this.#link) return;
    try {
      this.#link(packet);
    } catch (err) {
      this.emit('error', err as Error);
    }
  }

  #checkHighWater(): void {
    if (this.bufferedAmount >= this.#o.highWaterMark) this.#aboveHighWater = true;
  }

  #checkDrain(): void {
    if (this.#aboveHighWater && this.bufferedAmount < this.#o.highWaterMark / 2) {
      this.#aboveHighWater = false;
      this.emit('drain');
    }
  }

  #onPingTimer(): void {
    if (this.#closed) return;
    const now = Date.now();
    if (!this.#link) {
      if (this.#detachedAt !== null && now - this.#detachedAt > this.#o.detachedGraceMs) {
        this.#finish({ reason: 'peer unreachable', remote: false });
      }
      return;
    }
    if (now - this.#lastRecvAt > this.#o.deadAfterMs) this.emit('link-dead');
    this.#sendUnreliable(KIND_PING, 0, new Uint8Array(0));
  }

  #fail(error: Error): void {
    if (this.#closed) return;
    // Best effort: let the peer know (it is not the peer's fault).
    try {
      if (this.#link) {
        const packet = this.#seal(
          BigInt(this.#sendSeq++),
          this.#buildPlaintext(KIND_CLOSE, 0, 0, utf8(error.message.slice(0, 200)), 0),
        );
        this.#link(packet);
      }
    } catch {
      // ignore
    }
    this.#finish({ reason: error.message, remote: false, error });
  }

  #finish(info: CloseInfo): void {
    if (this.#closed) return;
    this.#closed = true;
    clearInterval(this.#pingTimer);
    if (this.#cadenceTimer) clearInterval(this.#cadenceTimer);
    if (this.#rtoTimer) clearTimeout(this.#rtoTimer);
    if (this.#ackTimer) clearTimeout(this.#ackTimer);
    this.#cadenceTimer = this.#rtoTimer = this.#ackTimer = null;
    this.#inflight = [];
    this.#queue = [];
    this.#partial.clear();
    this.#reorder.clear();
    this.#link = null;
    this.emit('close', info);
  }
}

function nowBytes(): Uint8Array {
  const b = new Uint8Array(8);
  writeU64(b, 0, BigInt(Date.now()));
  return b;
}

function safeUtf8(b: Uint8Array): string {
  try {
    return fromUtf8(b);
  } catch {
    return '';
  }
}

function stripUndefined<T extends object>(o: T): Partial<T> {
  return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined)) as Partial<T>;
}
