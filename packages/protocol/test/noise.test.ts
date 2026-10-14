import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { HandshakeState, keyPairFromSecret, generateKeyPair, CipherState } from '../src/noise.ts';
import { fromHex, toHex, utf8 } from '../src/bytes.ts';

interface Vector {
  protocol_name: string;
  init_prologue: string;
  init_static: string;
  init_ephemeral: string;
  resp_prologue: string;
  resp_static: string;
  resp_ephemeral: string;
  handshake_hash: string;
  messages: { payload: string; ciphertext: string }[];
}

const { vectors } = JSON.parse(
  readFileSync(new URL('./fixtures/noise-vectors.json', import.meta.url), 'utf8'),
) as { vectors: Vector[] };

test('Noise_XX_25519_ChaChaPoly_SHA256 matches cacophony test vectors', () => {
  assert.ok(vectors.length > 0);
  for (const v of vectors) {
    const init = new HandshakeState({
      pattern: 'XX',
      initiator: true,
      prologue: fromHex(v.init_prologue),
      s: keyPairFromSecret(fromHex(v.init_static)),
      e: keyPairFromSecret(fromHex(v.init_ephemeral)),
    });
    const resp = new HandshakeState({
      pattern: 'XX',
      initiator: false,
      prologue: fromHex(v.resp_prologue),
      s: keyPairFromSecret(fromHex(v.resp_static)),
      e: keyPairFromSecret(fromHex(v.resp_ephemeral)),
    });
    let initSend: CipherState | null = null;
    let initRecv: CipherState | null = null;
    let respSend: CipherState | null = null;
    let respRecv: CipherState | null = null;
    v.messages.forEach((m, i) => {
      const fromInitiator = i % 2 === 0;
      const payload = fromHex(m.payload);
      let ct: Uint8Array;
      let pt: Uint8Array;
      if (i < 3) {
        const [w, r] = fromInitiator ? [init, resp] : [resp, init];
        ct = w.writeMessage(payload);
        pt = r.readMessage(ct);
        if (i === 2) {
          assert.equal(toHex(init.result.handshakeHash), v.handshake_hash);
          assert.equal(toHex(resp.result.handshakeHash), v.handshake_hash);
          ({ send: initSend, recv: initRecv } = init.result);
          ({ send: respSend, recv: respRecv } = resp.result);
          assert.equal(toHex(init.result.remoteStatic), toHex(keyPairFromSecret(fromHex(v.resp_static)).publicKey));
          assert.equal(toHex(resp.result.remoteStatic), toHex(keyPairFromSecret(fromHex(v.init_static)).publicKey));
        }
      } else {
        const [w, r] = fromInitiator ? [initSend!, respRecv!] : [respSend!, initRecv!];
        ct = w.encryptWithAd(new Uint8Array(0), payload);
        pt = r.decryptWithAd(new Uint8Array(0), ct);
      }
      assert.equal(toHex(ct), m.ciphertext, `message ${i} ciphertext`);
      assert.equal(toHex(pt), m.payload, `message ${i} payload`);
    });
  }
});

function runHfs(tamper?: (msgIndex: number, msg: Uint8Array) => Uint8Array) {
  const prologue = utf8('test');
  const is = generateKeyPair();
  const rs = generateKeyPair();
  const init = new HandshakeState({ pattern: 'XXhfs', initiator: true, prologue, s: is });
  const resp = new HandshakeState({ pattern: 'XXhfs', initiator: false, prologue, s: rs });
  const t = tamper ?? ((_i, m) => m);
  resp.readMessage(t(0, init.writeMessage()));
  assert.deepEqual(init.readMessage(t(1, resp.writeMessage(utf8('agent hello')))), utf8('agent hello'));
  assert.deepEqual(resp.readMessage(t(2, init.writeMessage(utf8('client hello')))), utf8('client hello'));
  return { init, resp, is, rs };
}

test('XXhfs (X25519 + ML-KEM-768) handshake agrees on keys and identities', () => {
  const { init, resp, is, rs } = runHfs();
  assert.deepEqual(init.result.handshakeHash, resp.result.handshakeHash);
  assert.deepEqual(init.result.remoteStatic, rs.publicKey);
  assert.deepEqual(resp.result.remoteStatic, is.publicKey);
  const ct = init.result.send.encryptWithAd(new Uint8Array(0), utf8('hi'));
  assert.deepEqual(resp.result.recv.decryptWithAd(new Uint8Array(0), ct), utf8('hi'));
  const ct2 = resp.result.send.encryptWithAd(new Uint8Array(0), utf8('yo'));
  assert.deepEqual(init.result.recv.decryptWithAd(new Uint8Array(0), ct2), utf8('yo'));
});

test('XXhfs message sizes include the ML-KEM public key and ciphertext', () => {
  const sizes: number[] = [];
  runHfs((_i, m) => {
    sizes.push(m.length);
    return m;
  });
  // msg1: e(32) + e1 pk(1184), no payload tag yet
  assert.equal(sizes[0], 32 + 1184);
  // msg2: e(32) + kem ct(1088+16) + s(32+16) + payload(11+16)
  assert.equal(sizes[1], 32 + 1088 + 16 + 32 + 16 + 11 + 16);
});

test('XXhfs rejects tampering with the KEM public key, KEM ciphertext, or static key', () => {
  for (const [msgIndex, byteOffset] of [
    [0, 100], // inside e1 public key (cleartext but hashed)
    [1, 32 + 10], // inside encrypted KEM ciphertext
    [1, 32 + 1088 + 16 + 5], // inside encrypted responder static
    [2, 5], // inside encrypted initiator static
  ] as const) {
    assert.throws(() =>
      runHfs((i, m) => {
        if (i !== msgIndex) return m;
        const c = m.slice();
        c[byteOffset]! ^= 0x01;
        return c;
      }),
    );
  }
});

test('different prologues prevent the handshake from completing', () => {
  const init = new HandshakeState({ pattern: 'XXhfs', initiator: true, prologue: utf8('a'), s: generateKeyPair() });
  const resp = new HandshakeState({ pattern: 'XXhfs', initiator: false, prologue: utf8('b'), s: generateKeyPair() });
  resp.readMessage(init.writeMessage());
  assert.throws(() => init.readMessage(resp.writeMessage()));
});
