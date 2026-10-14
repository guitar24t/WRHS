import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AuthError, IntegrityError, PinMismatchError, RelayError } from '@wrhs/protocol';
import { describeAuthError, describeClose, describeConnectError, describeRelayUrlError, formatCountdown } from '../src/messages.ts';

test('connect errors are explained in plain language', () => {
  const pin = describeConnectError(new PinMismatchError(), 'relay.example.com');
  assert.equal(typeof pin, 'object');
  assert.ok(typeof pin === 'object' && pin.security && pin.tone === 'error' && /intercept/.test(pin.text));
  assert.match(describeConnectError(new RelayError('agent-offline'), 'r') as string, /agent is not connected/);
  assert.match(describeConnectError(new RelayError('rate-limited'), 'r') as string, /Wait a minute/);
  assert.match(describeConnectError(new Error('WebSocket error'), 'relay.example.com') as string, /Can’t reach the relay at relay\.example\.com/);
  assert.match(describeConnectError(new Error('unsupported agent protocol version 2'), 'r') as string, /different WRHS version/);
});

test('sign-in failures say what to check, attempts left, and lockout time', () => {
  assert.match(describeAuthError(new AuthError('invalid credentials', undefined, 2)), /Check your user name.*2 attempts left\./);
  assert.match(describeAuthError(new AuthError('invalid credentials', undefined, 1)), /One attempt left/);
  assert.doesNotMatch(describeAuthError(new AuthError('invalid credentials', undefined, 0)), /attempt/);
  assert.match(describeAuthError(new AuthError('account temporarily locked', 4 * 60_000)), /about 4 minutes/);
  assert.match(describeAuthError(new AuthError('account temporarily locked', 30_000)), /about 1 minute\./);
  assert.match(describeAuthError(new Error('session is closed')), /connection was lost/);
});

test('close reasons map to friendly text; tampering is a security notice', () => {
  const t = describeClose('record failed authentication', new IntegrityError('x'), false);
  assert.ok(t.security && t.tone === 'error' && t.action === 'Back to start');
  const s = describeClose('signed out', undefined, true);
  assert.equal(s.title, 'Signed out');
  assert.equal(s.action, 'Connect again');
  assert.match(describeClose('idle timeout', undefined, false).text, /inactivity/);
  assert.match(describeClose('something odd', undefined, false).text, /\(something odd\)/);
});

test('relay address errors and countdowns', () => {
  assert.match(describeRelayUrlError(''), /Enter the relay address/);
  assert.match(describeRelayUrlError('http://x'), /must start with https:\/\//);
  assert.equal(formatCountdown(1000), '1 second');
  assert.equal(formatCountdown(45_500), '46 seconds');
  assert.equal(formatCountdown(5 * 60_000), '5 minutes');
});
