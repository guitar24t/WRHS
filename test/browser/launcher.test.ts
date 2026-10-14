// Real-browser test: open a personalized launcher from file:// in Chromium,
// sign in, open a desktop and type, all through the intercepting proxy.
// Skipped when Playwright is not installed (set PLAYWRIGHT_MODULE to its
// entry point if it is installed globally).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { renderLauncher } from '@wrhs/agent';
import { DESKTOP_NAME, PASSWORD, RDP_PASS, RDP_USER, startStack, waitFor } from '../e2e/harness.ts';

// Typed loosely so the repo does not depend on Playwright's type package.
interface ConsoleMsg {
  type(): string;
  text(): string;
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let pw: any = null;
try {
  pw = await import(process.env.PLAYWRIGHT_MODULE ?? 'playwright');
} catch {
  pw = null;
}

test('offline launcher works in Chromium from file:// and the proxy sees no secrets', { skip: !pw && 'playwright not installed' }, async () => {
  const stack = await startStack({
    banner: [
      ['name', DESKTOP_NAME],
      ['size', '0', '800', '600'],
      ['rect', '0', '0', '0', '800', '600'],
      ['cfill', '14', '0', '0', '160', '80', '255'],
      ['sync', '1000'],
    ],
  });
  const dir = mkdtempSync(join(tmpdir(), 'wrhs-launcher-'));
  const file = join(dir, 'launcher.html');
  writeFileSync(file, renderLauncher({ relayUrl: stack.mitm.url, agentPublicKeys: [stack.agentKey.publicKey], name: 'Test agent' }).html);

  const browser = await pw.chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
  const problems: string[] = [];
  try {
    const page = await browser.newPage({ viewport: { width: 1100, height: 800 } });
    page.on('console', (m: ConsoleMsg) => {
      if (m.type() === 'error') problems.push(m.text());
    });
    page.on('pageerror', (e: Error) => problems.push(e.message));
    await page.goto(pathToFileURL(file).toString());
    await page.getByText('Fingerprint').waitFor();
    await page.click('#connect-btn');
    await page.locator('#view-login').waitFor({ state: 'visible' });
    assert.match(await page.locator('#security-text').textContent() ?? '', /End-to-end encrypted to test-agent/);

    await page.fill('#user', 'alice');
    await page.fill('#password', PASSWORD);
    await page.fill('#totp', stack.currentTotp());
    await page.click('#login-form button[type=submit]');
    await page.getByRole('button', { name: /Office PC/ }).click();
    await page.fill('#rdp-user', RDP_USER);
    await page.fill('#rdp-pass', RDP_PASS);
    await page.click('#rdp-creds button[type=submit]');

    await page.locator('#display canvas').first().waitFor();
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
    assert.deepEqual(problems.filter((p) => /Content Security Policy|Refused/i.test(p)), [], 'no CSP violations');

    await page.click('#disconnect-btn');
    await page.locator('#view-closed').waitFor({ state: 'visible' });
  } finally {
    await browser.close();
    await stack.close();
  }
});
