import { generateKeyPair, type KeyPair } from '../src/noise.ts';
import { startInitiator, finishInitiator, respondToHs1, finishResponder } from '../src/handshake.ts';
import { SecureSession, type SessionOptions } from '../src/session.ts';

export function handshakePair(clientKey: KeyPair = generateKeyPair(), agentKey: KeyPair = generateKeyPair()) {
  const init = startInitiator(clientKey);
  const resp = respondToHs1(agentKey, init.frame, { v: 1, name: 'test-agent', software: 'test' });
  const fin = finishInitiator(init.hs, resp.frame, [agentKey.publicKey], { v: 1, software: 'test' });
  const rfin = finishResponder(resp.hs, fin.frame);
  return { client: fin.result, agent: rfin.result, clientKey, agentKey, agentHello: fin.agentHello, clientHello: rfin.clientHello };
}

export interface Wire {
  /** Return false to drop, or a replacement frame (or frames). */
  filter?: (frame: Uint8Array, dir: 'a2b' | 'b2a') => boolean | Uint8Array | Uint8Array[];
  delayMs?: number;
}

/** Two sessions connected by an in-memory link with optional loss/tampering. */
export function sessionPair(opts: { a?: SessionOptions; b?: SessionOptions; wire?: Wire } = {}) {
  const { client, agent } = handshakePair();
  const a = new SecureSession(client, opts.a);
  const b = new SecureSession(agent, opts.b);
  const log: { dir: 'a2b' | 'b2a'; frame: Uint8Array }[] = [];
  const connect = (from: SecureSession, to: SecureSession, dir: 'a2b' | 'b2a') => (frame: Uint8Array) => {
    log.push({ dir, frame: frame.slice() });
    let out: Uint8Array[] = [frame];
    if (opts.wire?.filter) {
      const r = opts.wire.filter(frame, dir);
      if (r === false) return;
      if (r instanceof Uint8Array) out = [r];
      else if (Array.isArray(r)) out = r;
    }
    const deliver = () => {
      for (const f of out) to.receive(f.slice());
    };
    if (opts.wire?.delayMs) setTimeout(deliver, opts.wire.delayMs);
    else queueMicrotask(deliver);
  };
  const attach = () => {
    a.attach(connect(a, b, 'a2b'));
    b.attach(connect(b, a, 'b2a'));
  };
  attach();
  return { a, b, log, attach };
}

export function collect(s: SecureSession, channel?: number) {
  const msgs: Uint8Array[] = [];
  s.on('message', (ch, data) => {
    if (channel === undefined || ch === channel) msgs.push(data);
  });
  return msgs;
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function waitFor(cond: () => boolean, timeoutMs = 5000, what = 'condition') {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > timeoutMs) throw new Error(`timed out waiting for ${what}`);
    await sleep(5);
  }
}
