// Real-browser test: open a personalized launcher from file:// in Chromium,
// sign in, open a desktop and type, all through the intercepting proxy.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DESKTOP_NAME, PASSWORD, waitFor } from '../e2e/harness.ts';
import { launch, signIn, skip, stackWithLauncher, watchProblems, type Any } from './helpers.ts';

const RDP_USER = 'SECRET-RDP-USER';
const RDP_PASS = 'SECRET-RDP-PASS-9f8e7d';

test('offline launcher works in Chromium from file:// and the proxy sees no secrets', { skip }, async () => {
  const { stack, url } = await stackWithLauncher();
  const browser: Any = await launch();
  try {
    const page = await browser.newPage({ viewport: { width: 1100, height: 800 } });
    const problems = watchProblems(page);
    await page.goto(url);
    await page.locator('#profile').waitFor({ state: 'visible' });
    await signIn(page, stack);
    assert.match((await page.locator('#security-text').textContent()) ?? '', /Encrypted to test-agent/);

    await page.getByRole('button', { name: /Office PC/ }).click();
    await page.fill('#rdp-user', RDP_USER);
    await page.fill('#rdp-pass', RDP_PASS);
    await page.click('#rdp-creds button[type=submit]');

    await page.locator('#display canvas').first().waitFor();
    await page.locator('#loading-overlay').waitFor({ state: 'hidden', timeout: 10_000 });
    await waitFor(() => stack.guacd.connections[0]?.received.some((i) => i[0] === 'sync') ?? false, 10_000, 'client sync reply');
    await page.click('#display');
    await page.keyboard.type('hi');
    await waitFor(
      () => (stack.guacd.connections[0]?.received ?? []).filter((i) => i[0] === 'key' && i[2] === '1').length >= 2,
      10_000,
      'keystrokes at guacd',
    );
    const keys = stack.guacd.connections[0]!.received.filter((i) => i[0] === 'key' && i[2] === '1').map((i) => i[1]);
    assert.deepEqual(keys.slice(0, 2), ['104', '105']);
    assert.equal(stack.guacd.connections[0]!.params.username, RDP_USER);

    if (process.env.WRHS_SCREENSHOT) await page.screenshot({ path: process.env.WRHS_SCREENSHOT });

    const seen = stack.mitm.captured();
    for (const secret of [PASSWORD, RDP_USER, RDP_PASS, DESKTOP_NAME, 'alice']) {
      assert.equal(seen.includes(secret), false, `proxy saw ${secret}`);
    }
    assert.deepEqual(problems, [], 'no console errors or CSP violations');

    await page.click('#signout-btn');
    await page.locator('#view-closed').waitFor({ state: 'visible' });
  } finally {
    await browser.close();
    await stack.close();
  }
});
