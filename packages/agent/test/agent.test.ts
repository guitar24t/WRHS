import { test } from 'node:test';
import assert from 'node:assert/strict';
import { base32Encode, base32Decode, totpCode, verifyTotp, hashPassword, verifyPassword, Authenticator } from '../src/auth.ts';
import { encodeInstruction, parseInstructions, rdpParams } from '../src/guacd.ts';

test('TOTP matches RFC 6238 SHA-1 test vectors (6-digit truncation)', () => {
  const secret = base32Encode(Buffer.from('12345678901234567890'));
  assert.equal(totpCode(secret, Math.floor(59 / 30)), '287082');
  assert.equal(totpCode(secret, Math.floor(1111111109 / 30)), '081804');
  assert.equal(totpCode(secret, Math.floor(1234567890 / 30)), '005924');
  assert.equal(totpCode(secret, Math.floor(2000000000 / 30)), '279037');
  assert.equal(verifyTotp(secret, '081804', 1111111109_000), Math.floor(1111111109 / 30));
  assert.equal(verifyTotp(secret, '081804', 1111111109_000 + 90_000), null, 'outside the +/-1 step window');
  assert.deepEqual(base32Decode(secret), Buffer.from('12345678901234567890'));
});

test('scrypt password hashes verify and reject', async () => {
  const h = await hashPassword('a long enough password');
  assert.ok(h.startsWith('scrypt$15$8$1$'));
  assert.equal(await verifyPassword('a long enough password', h), true);
  assert.equal(await verifyPassword('a long enough passworD', h), false);
  assert.equal(await verifyPassword('anything', undefined), false);
  await assert.rejects(hashPassword('short'));
});

test('authenticator locks an account after repeated failures', async () => {
  const secret = base32Encode(Buffer.from('12345678901234567890'));
  const users = [{ name: 'bob', passwordHash: await hashPassword('bob password 123'), totpSecret: secret }];
  const auth = new Authenticator(() => users, { requireTotp: true, maxFailures: 3, lockoutMs: 60_000 });
  const now = 1234567890_000;
  for (let i = 0; i < 3; i++) assert.equal((await auth.authenticate('bob', 'nope', '005924', now)).ok, false);
  const locked = await auth.authenticate('bob', 'bob password 123', '005924', now);
  assert.equal(locked.ok, false);
  assert.ok(!locked.ok && locked.retryAfterMs! > 0);
  const later = now + 61_000;
  const code = totpCode(secret, Math.floor(later / 30_000));
  assert.deepEqual(await auth.authenticate('BOB', 'bob password 123', code, later), { ok: true, user: 'bob' });
  assert.equal((await auth.authenticate('bob', 'bob password 123', code, later)).ok, false, 'TOTP replay rejected');
});

test('Guacamole instructions round-trip, counting code points not UTF-16 units', () => {
  const text = encodeInstruction(['name', 'Désktop 🖥']) + encodeInstruction(['size', '0', '1024', '768']) + '4.sy';
  assert.equal(text.startsWith('4.name,9.Désktop 🖥;'), true);
  const { instructions, consumed, ends } = parseInstructions(text);
  assert.deepEqual(instructions, [['name', 'Désktop 🖥'], ['size', '0', '1024', '768']]);
  assert.equal(text.slice(consumed), '4.sy');
  assert.equal(ends.length, 2);
  assert.throws(() => parseInstructions('x.abc;'));
});

test('RDP parameters enforce clipboard and file-transfer policy', () => {
  const p = rdpParams({ hostname: 'h', clipboard: 'copy', fileTransfer: false }, { width: 800, height: 600, dpi: 96 });
  assert.equal(p['disable-copy'], 'false');
  assert.equal(p['disable-paste'], 'true');
  assert.equal(p['enable-drive'], 'false');
  assert.equal(p['disable-upload'], 'true');
  assert.equal(p.port, '3389');
});
