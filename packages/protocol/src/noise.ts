// Noise Protocol Framework (revision 34) with the HFS extension.
//
// Supported protocols:
//   Noise_XX_25519_ChaChaPoly_SHA256                 (validated against cacophony vectors)
//   Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256     (hybrid post-quantum forward secrecy)
//
// The HFS extension adds two tokens: "e1" (sender generates an ephemeral KEM
// key pair and sends the public key with EncryptAndHash) and "ekem1" (receiver
// of e1 encapsulates to it, sends the ciphertext with EncryptAndHash and calls
// MixKey on the shared secret). If either X25519 or ML-KEM-768 holds, the
// session keys stay secret, which defends against "record now, decrypt later"
// by an intercepting proxy that archives traffic.

import { x25519 } from '@noble/curves/ed25519.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { concat, utf8 } from './bytes.ts';

export const DHLEN = 32;
export const HASHLEN = 32;
export const TAGLEN = 16;
export const KEM_PUBLIC_KEY_LEN = 1184;
export const KEM_CIPHERTEXT_LEN = 1088;
export const MAX_NOISE_MESSAGE = 65535;
const MAX_NONCE = 0xffffffffffffffffn;

export interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export function generateKeyPair(): KeyPair {
  const secretKey = x25519.utils.randomSecretKey();
  return { secretKey, publicKey: x25519.getPublicKey(secretKey) };
}

export function keyPairFromSecret(secretKey: Uint8Array): KeyPair {
  if (secretKey.length !== DHLEN) throw new Error('X25519 secret key must be 32 bytes');
  return { secretKey, publicKey: x25519.getPublicKey(secretKey) };
}

function dh(kp: KeyPair, publicKey: Uint8Array): Uint8Array {
  // noble rejects low-order points (all-zero output); Noise allows that and
  // we treat it as a handshake failure.
  return x25519.getSharedSecret(kp.secretKey, publicKey);
}

function hash(data: Uint8Array): Uint8Array {
  return sha256(data);
}

function hkdf(ck: Uint8Array, ikm: Uint8Array, n: 2 | 3): Uint8Array[] {
  const tempKey = hmac(sha256, ck, ikm);
  const o1 = hmac(sha256, tempKey, Uint8Array.of(1));
  const o2 = hmac(sha256, tempKey, concat(o1, Uint8Array.of(2)));
  if (n === 2) return [o1, o2];
  const o3 = hmac(sha256, tempKey, concat(o2, Uint8Array.of(3)));
  return [o1, o2, o3];
}

/** 96-bit ChaChaPoly nonce: 32 zero bits followed by the 64-bit counter, little-endian. */
function chachaNonce(n: bigint): Uint8Array {
  const nonce = new Uint8Array(12);
  new DataView(nonce.buffer).setBigUint64(4, n, true);
  return nonce;
}

export function aeadEncrypt(k: Uint8Array, n: bigint, ad: Uint8Array, plaintext: Uint8Array): Uint8Array {
  return chacha20poly1305(k, chachaNonce(n), ad).encrypt(plaintext);
}

/** Throws on authentication failure. */
export function aeadDecrypt(k: Uint8Array, n: bigint, ad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  return chacha20poly1305(k, chachaNonce(n), ad).decrypt(ciphertext);
}

export class CipherState {
  #k: Uint8Array | null = null;
  n = 0n;

  initializeKey(k: Uint8Array | null): void {
    this.#k = k;
    this.n = 0n;
  }

  hasKey(): boolean {
    return this.#k !== null;
  }

  setNonce(n: bigint): void {
    this.n = n;
  }

  encryptWithAd(ad: Uint8Array, plaintext: Uint8Array): Uint8Array {
    if (!this.#k) return plaintext;
    if (this.n >= MAX_NONCE) throw new Error('nonce exhausted');
    const ct = aeadEncrypt(this.#k, this.n, ad, plaintext);
    this.n++;
    return ct;
  }

  decryptWithAd(ad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    if (!this.#k) return ciphertext;
    if (this.n >= MAX_NONCE) throw new Error('nonce exhausted');
    const pt = aeadDecrypt(this.#k, this.n, ad, ciphertext);
    this.n++;
    return pt;
  }

  /** Explicit-nonce encryption used by the record layer (Noise spec section 11.4). */
  sealAt(n: bigint, ad: Uint8Array, plaintext: Uint8Array): Uint8Array {
    if (!this.#k) throw new Error('cipher has no key');
    if (n >= MAX_NONCE) throw new Error('nonce exhausted');
    return aeadEncrypt(this.#k, n, ad, plaintext);
  }

  openAt(n: bigint, ad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    if (!this.#k) throw new Error('cipher has no key');
    if (n >= MAX_NONCE) throw new Error('nonce exhausted');
    return aeadDecrypt(this.#k, n, ad, ciphertext);
  }

  rekey(): void {
    if (!this.#k) throw new Error('cipher has no key');
    this.#k = aeadEncrypt(this.#k, MAX_NONCE, new Uint8Array(0), new Uint8Array(32)).subarray(0, 32);
  }
}

export class SymmetricState {
  ck: Uint8Array;
  h: Uint8Array;
  readonly cipher = new CipherState();

  constructor(protocolName: string) {
    const name = utf8(protocolName);
    if (name.length <= HASHLEN) {
      this.h = new Uint8Array(HASHLEN);
      this.h.set(name);
    } else {
      this.h = hash(name);
    }
    this.ck = this.h;
  }

  mixKey(ikm: Uint8Array): void {
    const [ck, tempK] = hkdf(this.ck, ikm, 2);
    this.ck = ck!;
    this.cipher.initializeKey(tempK!);
  }

  mixHash(data: Uint8Array): void {
    this.h = hash(concat(this.h, data));
  }

  encryptAndHash(plaintext: Uint8Array): Uint8Array {
    const ct = this.cipher.encryptWithAd(this.h, plaintext);
    this.mixHash(ct);
    return ct;
  }

  decryptAndHash(ciphertext: Uint8Array): Uint8Array {
    const pt = this.cipher.decryptWithAd(this.h, ciphertext);
    this.mixHash(ciphertext);
    return pt;
  }

  split(): [CipherState, CipherState] {
    const [k1, k2] = hkdf(this.ck, new Uint8Array(0), 2);
    const c1 = new CipherState();
    const c2 = new CipherState();
    c1.initializeKey(k1!);
    c2.initializeKey(k2!);
    return [c1, c2];
  }
}

type Token = 'e' | 's' | 'ee' | 'es' | 'se' | 'ss' | 'e1' | 'ekem1';

export type PatternName = 'XX' | 'XXhfs';

const PATTERNS: Record<PatternName, Token[][]> = {
  XX: [['e'], ['e', 'ee', 's', 'es'], ['s', 'se']],
  XXhfs: [['e', 'e1'], ['e', 'ee', 'ekem1', 's', 'es'], ['s', 'se']],
};

export function protocolName(pattern: PatternName): string {
  return pattern === 'XX'
    ? 'Noise_XX_25519_ChaChaPoly_SHA256'
    : 'Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256';
}

export interface HandshakeOptions {
  pattern: PatternName;
  initiator: boolean;
  prologue: Uint8Array;
  /** Local static key pair. */
  s: KeyPair;
  /** Deterministic ephemeral key (tests only). */
  e?: KeyPair;
  /** Deterministic KEM randomness (tests only): 64-byte keygen seed, 32-byte encapsulation seed. */
  kemKeygenSeed?: Uint8Array;
  kemEncapsSeed?: Uint8Array;
}

export interface HandshakeResult {
  /** Cipher for messages we send. */
  send: CipherState;
  /** Cipher for messages we receive. */
  recv: CipherState;
  /** Channel-binding value unique to this session. */
  handshakeHash: Uint8Array;
  /** Peer's authenticated static public key. */
  remoteStatic: Uint8Array;
}

export class HandshakeState {
  readonly initiator: boolean;
  readonly #ss: SymmetricState;
  readonly #messages: Token[][];
  #index = 0;
  readonly #s: KeyPair;
  #e: KeyPair | null;
  #re: Uint8Array | null = null;
  #rs: Uint8Array | null = null;
  #e1: { publicKey: Uint8Array; secretKey: Uint8Array } | null = null;
  #re1: Uint8Array | null = null;
  readonly #kemKeygenSeed: Uint8Array | undefined;
  readonly #kemEncapsSeed: Uint8Array | undefined;
  #result: HandshakeResult | null = null;

  constructor(opts: HandshakeOptions) {
    this.initiator = opts.initiator;
    this.#ss = new SymmetricState(protocolName(opts.pattern));
    this.#messages = PATTERNS[opts.pattern];
    this.#s = opts.s;
    this.#e = opts.e ?? null;
    this.#kemKeygenSeed = opts.kemKeygenSeed;
    this.#kemEncapsSeed = opts.kemEncapsSeed;
    this.#ss.mixHash(opts.prologue);
  }

  get isComplete(): boolean {
    return this.#result !== null;
  }

  /** True when the next message in the pattern is ours to write. */
  get isMyTurn(): boolean {
    return (this.#index % 2 === 0) === this.initiator;
  }

  get remoteStatic(): Uint8Array | null {
    return this.#rs;
  }

  get handshakeHash(): Uint8Array {
    return this.#ss.h;
  }

  get result(): HandshakeResult {
    if (!this.#result) throw new Error('handshake not complete');
    return this.#result;
  }

  writeMessage(payload: Uint8Array = new Uint8Array(0)): Uint8Array {
    if (this.#result) throw new Error('handshake already complete');
    if (!this.isMyTurn) throw new Error('not our turn to write');
    const ss = this.#ss;
    const parts: Uint8Array[] = [];
    for (const token of this.#messages[this.#index]!) {
      switch (token) {
        case 'e': {
          if (!this.#e) this.#e = generateKeyPair();
          parts.push(this.#e.publicKey);
          ss.mixHash(this.#e.publicKey);
          break;
        }
        case 's':
          parts.push(ss.encryptAndHash(this.#s.publicKey));
          break;
        case 'ee':
          ss.mixKey(dh(this.#e!, this.#re!));
          break;
        case 'es':
          ss.mixKey(this.initiator ? dh(this.#e!, this.#rs!) : dh(this.#s, this.#re!));
          break;
        case 'se':
          ss.mixKey(this.initiator ? dh(this.#s, this.#re!) : dh(this.#e!, this.#rs!));
          break;
        case 'ss':
          ss.mixKey(dh(this.#s, this.#rs!));
          break;
        case 'e1': {
          this.#e1 = ml_kem768.keygen(this.#kemKeygenSeed);
          parts.push(ss.encryptAndHash(this.#e1.publicKey));
          break;
        }
        case 'ekem1': {
          const { cipherText, sharedSecret } = ml_kem768.encapsulate(this.#re1!, this.#kemEncapsSeed);
          parts.push(ss.encryptAndHash(cipherText));
          ss.mixKey(sharedSecret);
          break;
        }
      }
    }
    parts.push(ss.encryptAndHash(payload));
    const msg = concat(...parts);
    if (msg.length > MAX_NOISE_MESSAGE) throw new Error('handshake message too large');
    this.#advance();
    return msg;
  }

  readMessage(message: Uint8Array): Uint8Array {
    if (this.#result) throw new Error('handshake already complete');
    if (this.isMyTurn) throw new Error('not our turn to read');
    if (message.length > MAX_NOISE_MESSAGE) throw new Error('handshake message too large');
    const ss = this.#ss;
    let off = 0;
    const take = (n: number): Uint8Array => {
      if (off + n > message.length) throw new Error('handshake message truncated');
      const out = message.subarray(off, off + n);
      off += n;
      return out;
    };
    const tag = (): number => (ss.cipher.hasKey() ? TAGLEN : 0);
    for (const token of this.#messages[this.#index]!) {
      switch (token) {
        case 'e':
          this.#re = take(DHLEN).slice();
          ss.mixHash(this.#re);
          break;
        case 's':
          this.#rs = ss.decryptAndHash(take(DHLEN + tag())).slice();
          break;
        case 'ee':
          ss.mixKey(dh(this.#e!, this.#re!));
          break;
        case 'es':
          ss.mixKey(this.initiator ? dh(this.#e!, this.#rs!) : dh(this.#s, this.#re!));
          break;
        case 'se':
          ss.mixKey(this.initiator ? dh(this.#s, this.#re!) : dh(this.#e!, this.#rs!));
          break;
        case 'ss':
          ss.mixKey(dh(this.#s, this.#rs!));
          break;
        case 'e1':
          this.#re1 = ss.decryptAndHash(take(KEM_PUBLIC_KEY_LEN + tag())).slice();
          break;
        case 'ekem1': {
          const ct = ss.decryptAndHash(take(KEM_CIPHERTEXT_LEN + tag()));
          ss.mixKey(ml_kem768.decapsulate(ct, this.#e1!.secretKey));
          break;
        }
      }
    }
    const payload = ss.decryptAndHash(message.subarray(off));
    this.#advance();
    return payload;
  }

  #advance(): void {
    this.#index++;
    if (this.#index === this.#messages.length) {
      const [c1, c2] = this.#ss.split();
      this.#result = {
        send: this.initiator ? c1 : c2,
        recv: this.initiator ? c2 : c1,
        handshakeHash: this.#ss.h,
        remoteStatic: this.#rs!,
      };
      // Drop ephemeral secrets as soon as they are no longer needed.
      this.#e = null;
      this.#e1 = null;
    }
  }
}
