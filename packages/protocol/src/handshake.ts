// Frame-level helpers that run the Noise_XXhfs handshake between the browser
// client (initiator) and the agent (responder).
//
//   client -> agent   HS1: e, e1                      (ephemeral X25519 + ML-KEM key)
//   agent  -> client  HS2: e, ee, ekem1, s, es        + AgentHello   (encrypted)
//   client -> agent   HS3: s, se                      + ClientHello  (encrypted)
//
// The client MUST check the agent static key against its pinned key before
// sending HS3; that check is what defeats a man-in-the-middle proxy.

import { HandshakeState, type HandshakeResult, type KeyPair, type PatternName } from './noise.ts';
import { concat, equalBytes, fromUtf8, utf8 } from './bytes.ts';
import {
  FRAME_HS1,
  FRAME_HS2,
  FRAME_HS3,
  PROLOGUE,
  PROTOCOL_VERSION,
  type AgentHello,
  type ClientHello,
} from './wire.ts';

export const DEFAULT_PATTERN: PatternName = 'XXhfs';

export class PinMismatchError extends Error {
  constructor() {
    super(
      'The remote agent did not present the pinned public key. Someone may be intercepting this connection; refusing to continue.',
    );
    this.name = 'PinMismatchError';
  }
}

export interface InitiatorStart {
  hs: HandshakeState;
  frame: Uint8Array;
}

export function startInitiator(staticKey: KeyPair, pattern: PatternName = DEFAULT_PATTERN): InitiatorStart {
  const hs = new HandshakeState({ pattern, initiator: true, prologue: PROLOGUE, s: staticKey });
  return { hs, frame: concat(Uint8Array.of(FRAME_HS1), hs.writeMessage()) };
}

export interface InitiatorFinish {
  frame: Uint8Array;
  agentHello: AgentHello;
  result: HandshakeResult;
}

/** Process HS2, verify the agent's identity against the pin, and produce HS3. */
export function finishInitiator(
  hs: HandshakeState,
  frame: Uint8Array,
  pinnedAgentKeys: Uint8Array[],
  hello: ClientHello,
): InitiatorFinish {
  if (frame[0] !== FRAME_HS2) throw new Error('expected handshake message 2');
  const payload = hs.readMessage(frame.subarray(1));
  const rs = hs.remoteStatic!;
  if (!pinnedAgentKeys.some((k) => equalBytes(k, rs))) throw new PinMismatchError();
  const agentHello = JSON.parse(fromUtf8(payload)) as AgentHello;
  if (agentHello.v !== PROTOCOL_VERSION) throw new Error(`unsupported agent protocol version ${agentHello.v}`);
  const out = concat(Uint8Array.of(FRAME_HS3), hs.writeMessage(utf8(JSON.stringify(hello))));
  return { frame: out, agentHello, result: hs.result };
}

export interface ResponderStart {
  hs: HandshakeState;
  frame: Uint8Array;
}

export function respondToHs1(
  staticKey: KeyPair,
  frame: Uint8Array,
  hello: AgentHello,
  pattern: PatternName = DEFAULT_PATTERN,
): ResponderStart {
  if (frame[0] !== FRAME_HS1) throw new Error('expected handshake message 1');
  const hs = new HandshakeState({ pattern, initiator: false, prologue: PROLOGUE, s: staticKey });
  hs.readMessage(frame.subarray(1));
  return { hs, frame: concat(Uint8Array.of(FRAME_HS2), hs.writeMessage(utf8(JSON.stringify(hello)))) };
}

export interface ResponderFinish {
  clientHello: ClientHello;
  result: HandshakeResult;
}

export function finishResponder(hs: HandshakeState, frame: Uint8Array): ResponderFinish {
  if (frame[0] !== FRAME_HS3) throw new Error('expected handshake message 3');
  const clientHello = JSON.parse(fromUtf8(hs.readMessage(frame.subarray(1)))) as ClientHello;
  if (clientHello.v !== PROTOCOL_VERSION) throw new Error(`unsupported client protocol version ${clientHello.v}`);
  return { clientHello, result: hs.result };
}
