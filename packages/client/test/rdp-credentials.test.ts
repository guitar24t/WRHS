import { test } from 'node:test';
import assert from 'node:assert/strict';
import { nlaUsername } from '../src/rdp-credentials.ts';

test('an email address is kept whole for Network Level Authentication', () => {
  assert.equal(nlaUsername('you@gmail.com'), 'you@gmail.com@');
  assert.equal(nlaUsername('alice@corp.example.com', ''), 'alice@corp.example.com@');
  // Already in that form, or not an address: unchanged.
  assert.equal(nlaUsername('you@gmail.com@'), 'you@gmail.com@');
  assert.equal(nlaUsername('alice'), 'alice');
  assert.equal(nlaUsername('CORP\\alice'), 'CORP\\alice');
  assert.equal(nlaUsername(''), '');
  // With a domain, the name goes as typed.
  assert.equal(nlaUsername('alice', 'CORP'), 'alice');
});
