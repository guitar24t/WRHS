// The agent's long-term X25519 identity key.

import { existsSync, readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { generateKeyPair, keyPairFromSecret, toBase64Url, fromBase64Url, equalBytes, type KeyPair } from '@wrhs/protocol';

interface KeyFile {
  type: 'wrhs-agent-key';
  version: 1;
  secretKey: string;
  publicKey: string;
}

export function loadKey(path: string): KeyPair {
  const f = JSON.parse(readFileSync(path, 'utf8')) as KeyFile;
  if (f.type !== 'wrhs-agent-key') throw new Error(`${path} is not a WRHS agent key`);
  const kp = keyPairFromSecret(fromBase64Url(f.secretKey));
  if (!equalBytes(kp.publicKey, fromBase64Url(f.publicKey))) throw new Error(`${path}: public key mismatch`);
  return kp;
}

export function createKey(path: string): KeyPair {
  if (existsSync(path)) throw new Error(`${path} already exists; refusing to overwrite an identity key`);
  const kp = generateKeyPair();
  const f: KeyFile = { type: 'wrhs-agent-key', version: 1, secretKey: toBase64Url(kp.secretKey), publicKey: toBase64Url(kp.publicKey) };
  writeFileSync(path, JSON.stringify(f, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  chmodSync(path, 0o600);
  return kp;
}
