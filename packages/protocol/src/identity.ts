// Agent identities. The agent's long-term X25519 public key *is* its identity:
// the client pins it, and the relay routes by a hash of it.

import { sha256 } from '@noble/hashes/sha2.js';
import { concat, fromBase64Url, toBase64Url, toHex, utf8 } from './bytes.ts';

/** Routing identifier the relay uses for an agent (not secret). */
export function agentIdFromPublicKey(publicKey: Uint8Array): string {
  return toHex(sha256(concat(utf8('wrhs-agent-id:'), publicKey)).subarray(0, 16));
}

/** Human-comparable fingerprint, e.g. "3F2A-91C0-...". */
export function fingerprint(publicKey: Uint8Array): string {
  const h = toHex(sha256(concat(utf8('wrhs-fingerprint:'), publicKey)).subarray(0, 12)).toUpperCase();
  return h.match(/.{4}/g)!.join('-');
}

export function encodeKey(key: Uint8Array): string {
  return toBase64Url(key);
}

export function decodeKey(s: string): Uint8Array {
  const k = fromBase64Url(s.trim());
  if (k.length !== 32) throw new Error('expected a 32-byte key');
  return k;
}
