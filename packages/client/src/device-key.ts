// Per-browser device key (the Noise initiator static key). The agent can
// restrict a user to enrolled device keys. If storage is unavailable
// (private window, some file:// configurations) we fall back to a key that
// lives only for this page load.

import { generateKeyPair, keyPairFromSecret, type KeyPair } from '@wrhs/protocol';

const DB = 'wrhs';
const STORE = 'keys';
const ID = 'device';

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export async function loadDeviceKey(): Promise<{ key: KeyPair; persistent: boolean }> {
  try {
    const db = await open();
    const existing = await new Promise<Uint8Array | undefined>((resolve, reject) => {
      const r = db.transaction(STORE, 'readonly').objectStore(STORE).get(ID);
      r.onsuccess = () => resolve(r.result as Uint8Array | undefined);
      r.onerror = () => reject(r.error);
    });
    if (existing instanceof Uint8Array && existing.length === 32) return { key: keyPairFromSecret(existing), persistent: true };
    const key = generateKeyPair();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      tx.objectStore(STORE).put(key.secretKey, ID);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
    return { key, persistent: true };
  } catch {
    return { key: generateKeyPair(), persistent: false };
  }
}
