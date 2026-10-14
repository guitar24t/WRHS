// Browser tests for the user interface: one per behaviour fixed in the UI
// review, plus an accessibility audit. Run with `npm run test:browser`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FRAME_RECORD } from '@wrhs/protocol';
import { waitFor } from '../e2e/harness.ts';
import { axe, genericLauncherUrl, launch, openDesktop, signIn, skip, stackWithLauncher, watchProblems, type Any } from './helpers.ts';

async function withPage(
  fn: (page: Any, ctx: Awaited<ReturnType<typeof stackWithLauncher>>) => Promise<void>,
  opts: { context?: Record<string, unknown>; stack?: Parameters<typeof stackWithLauncher>[0] } = {},
) {
  const ctx = await stackWithLauncher(opts.stack);
  const browser: Any = await launch();
  try {
    const context = await browser.newContext({ viewport: { width: 1100, height: 800 }, ...opts.context });
    const page = await context.newPage();
    const problems = watchProblems(page);
    await page.goto(ctx.url);
    await fn(page, ctx);
    assert.deepEqual(problems, [], 'no console errors');
  } finally {
    await browser.close();
    await ctx.stack.close();
  }
}

const received = (ctx: Awaited<ReturnType<typeof stackWithLauncher>>, op: string) =>
  (ctx.stack.guacd.connections.at(-1)?.received ?? []).filter((i) => i[0] === op);

test('the authenticator code is required and a missing code does not use up an attempt', { skip }, async () => {
  await withPage(async (page, { stack }) => {
    await page.click('#connect-btn');
    await page.locator('#view-login').waitFor({ state: 'visible' });
    await page.fill('#user', 'alice');
    await page.fill('#password', 'whatever-password');
    await page.click('#login-btn');
    assert.match(await page.locator('#login-msg').textContent(), /6-digit code/);
    assert.equal(await page.locator('#totp').getAttribute('aria-invalid'), 'true');
    assert.equal(await page.evaluate(() => document.activeElement?.id), 'totp');
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(stack.agentLog.filter((e) => e.event === 'login-fail').length, 0, 'nothing was sent to the agent');
  });
});

test('a failed sign-in explains what to check and how many attempts are left', { skip }, async () => {
  await withPage(async (page, { stack }) => {
    await page.click('#connect-btn');
    await page.locator('#view-login').waitFor({ state: 'visible' });
    await page.fill('#user', 'alice');
    await page.fill('#password', 'wrong password!!');
    await page.fill('#totp', stack.currentTotp());
    await page.click('#login-btn');
    await page.locator('#login-msg:not(:empty)').waitFor();
    assert.match(await page.locator('#login-msg').textContent(), /Check your user name, password and authenticator code\. 2 attempts left\./);
  });
});

test('you can sign out from the desktop list and connect again', { skip }, async () => {
  await withPage(async (page, { stack }) => {
    await signIn(page, stack);
    await page.click('#signout-btn');
    await page.locator('#view-closed').waitFor({ state: 'visible' });
    assert.equal(await page.locator('#closed-title').textContent(), 'Signed out');
    assert.equal(await page.locator('#reconnect-btn').textContent(), 'Connect again');
    assert.equal(await page.locator('#signout-btn').isVisible(), false, 'header is reset');
    await page.click('#reconnect-btn');
    await page.locator('#view-login').waitFor({ state: 'visible' });
    assert.equal(await page.inputValue('#user'), 'alice', 'user name is remembered');
  });
});

test('the Windows credentials form can be cancelled and never reappears stale', { skip }, async () => {
  await withPage(async (page, { stack }) => {
    await signIn(page, stack);
    const office = page.getByRole('button', { name: /Office PC/ });
    await office.click();
    assert.equal(await page.locator('#rdp-creds').isVisible(), true);
    assert.equal(await office.getAttribute('aria-pressed'), 'true');
    await page.fill('#rdp-user', 'someone');
    await page.click('#creds-cancel');
    assert.equal(await page.locator('#rdp-creds').isVisible(), false);
    assert.equal(await office.getAttribute('aria-pressed'), 'false');

    await openDesktop(page);
    assert.equal(await page.locator('#kbd-btn').isVisible(), false, 'the on-screen keyboard button is for touch devices only');
    await page.click('#close-desktop-btn');
    await page.locator('#view-targets').waitFor({ state: 'visible' });
    await new Promise((r) => setTimeout(r, 300)); // the agent's "closed" notice arrives now
    assert.equal(await page.locator('#rdp-creds').isVisible(), false, 'no stale form');
    assert.equal(await page.locator('#targets-msg').textContent(), '', 'closing on purpose is not reported as a problem');
    assert.equal(await page.inputValue('#rdp-user'), '', 'typed credentials were cleared');
  });
});

test('when the remote desktop ends, the list explains it and offers to reconnect', { skip }, async () => {
  await withPage(async (page, ctx) => {
    await signIn(page, ctx.stack);
    await openDesktop(page);
    ctx.stack.guacd.dropConnections();
    await page.locator('#view-targets').waitFor({ state: 'visible' });
    assert.equal(await page.locator('#targets-msg').textContent(), 'The remote desktop session ended.');
    const reopen = page.locator('#reopen-btn');
    assert.equal(await reopen.textContent(), 'Reconnect to Office PC');
    await reopen.click();
    assert.equal(await page.locator('#rdp-creds').isVisible(), true, 'asks for credentials again');
  });
});

test('a "starting" overlay covers the screen until the desktop draws, and a banner shows reconnects', { skip }, async () => {
  await withPage(async (page, ctx) => {
    await signIn(page, ctx.stack);
    await page.getByRole('button', { name: /Office PC/ }).click();
    await page.fill('#rdp-user', 'someone');
    await page.click('#rdp-creds button[type=submit]');
    // Visible right away (before the agent has even answered).
    assert.equal(await page.locator('#loading-overlay').isVisible(), true);
    await page.locator('#loading-overlay').waitFor({ state: 'hidden', timeout: 10_000 });

    ctx.stack.mitm.cutAll();
    await page.locator('#reconnect-overlay').waitFor({ state: 'visible', timeout: 5000 });
    assert.match(await page.locator('#security-text').textContent(), /Reconnecting/);
    await page.locator('#reconnect-overlay').waitFor({ state: 'hidden', timeout: 15_000 });
    assert.match(await page.locator('#security-text').textContent(), /Encrypted/);
  });
});

test('one pointer: the remote cursor becomes the local cursor with a mouse, but stays drawn on touch', { skip }, async () => {
  const cursorOf = (page: Any) => page.evaluate(() => (document.querySelector('#display > div') as HTMLElement).style.cursor);
  await withPage(async (page, ctx) => {
    await signIn(page, ctx.stack);
    await openDesktop(page);
    await page.waitForFunction(() => (document.querySelector('#display > div') as HTMLElement)?.style.cursor.startsWith('url('));
    assert.match(await cursorOf(page), /^url\("?data:image\/png/);
  });
  await withPage(
    async (page, ctx) => {
      await signIn(page, ctx.stack);
      await openDesktop(page);
      await new Promise((r) => setTimeout(r, 500));
      assert.equal(await cursorOf(page), '', 'no CSS cursor on touch devices');
    },
    { context: { viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true } },
  );
});

test('tampering shows a security screen that does not invite a retry', { skip }, async () => {
  await withPage(async (page, ctx) => {
    await signIn(page, ctx.stack);
    let n = 0;
    ctx.stack.mitm.tamper = (dir, data) => {
      if (dir !== 'down' || data[0] !== FRAME_RECORD || n++ !== 2) return data;
      const t = Uint8Array.from(data);
      t[t.length - 1]! ^= 1;
      return t;
    };
    await page.getByRole('button', { name: /Office PC/ }).click();
    await page.fill('#rdp-user', 'x');
    await page.click('#rdp-creds button[type=submit]');
    await page.locator('#view-closed').waitFor({ state: 'visible' });
    assert.match(await page.locator('#closed-title').textContent(), /traffic was modified/);
    assert.match(await page.locator('#closed-msg').getAttribute('class'), /error/);
    assert.equal(await page.locator('#reconnect-btn').getAttribute('class'), 'secondary');
    assert.equal(await page.locator('#reconnect-btn').textContent(), 'Back to start');
    assert.equal(await page.locator('#details-btn').isVisible(), false, 'no stale connection details');
  });
});

test('the generic launcher explains bad input and previews the key fingerprint', { skip }, async () => {
  const browser: Any = await launch();
  try {
    const page = await browser.newPage();
    const problems = watchProblems(page);
    await page.goto(genericLauncherUrl);
    await page.click('#connect-btn');
    assert.match(await page.locator('#connect-msg').textContent(), /Enter the relay address/);
    assert.equal(await page.locator('#relay-url').getAttribute('aria-invalid'), 'true');
    await page.fill('#relay-url', 'http://relay.example.com');
    await page.click('#connect-btn');
    assert.match(await page.locator('#connect-msg').textContent(), /must start with https:\/\//);
    await page.fill('#relay-url', 'https://relay.example.com');
    await page.fill('#agent-key', 'not-a-key');
    assert.match(await page.locator('#agent-key-fp').textContent(), /Not a complete agent key/);
    await page.click('#connect-btn');
    assert.match(await page.locator('#connect-msg').textContent(), /doesn’t look like an agent key/);
    await page.fill('#agent-key', 'CjzHhxZ99V34utVa9i9FkrWtnu8C5izp3GjO3qHPqEI');
    assert.match(await page.locator('#agent-key-fp').textContent(), /Key fingerprint 41E1-268E-3F35-6285-5B02-55BC/);
    assert.deepEqual(problems, []);
  } finally {
    await browser.close();
  }
});

test('touch: taps click and the on-screen keyboard types into the remote desktop', { skip }, async () => {
  await withPage(
    async (page, ctx) => {
      await signIn(page, ctx.stack);
      await openDesktop(page);
      // Toolbar stays on one row on a phone.
      const toolbar = await page.locator('#toolbar').boundingBox();
      assert.ok(toolbar.height < 60, `toolbar height ${toolbar.height}`);
      const close = await page.locator('#close-desktop-btn').boundingBox();
      assert.ok(close.x + close.width <= 390, 'Close is visible without scrolling');
      assert.equal(await page.locator('#kbd-btn').isVisible(), true);

      // The desktop is centred in the available space.
      const area = await page.locator('#display').boundingBox();
      const box = await page.locator('#display > div').boundingBox();
      assert.ok(Math.abs(box.y + box.height / 2 - (area.y + area.height / 2)) < 2, 'vertically centred');
      await page.touchscreen.tap(box.x + box.width / 2, box.y + box.height / 2);
      await waitFor(() => received(ctx, 'mouse').some((i) => i[3] === '1'), 5000, 'left button press from a tap');

      await page.click('#kbd-btn');
      assert.equal(await page.evaluate(() => document.activeElement?.id), 'soft-kbd');
      await page.keyboard.insertText('hi');
      await page.keyboard.press('Backspace');
      await waitFor(() => received(ctx, 'key').filter((i) => i[2] === '1').length >= 3, 5000, 'typed keys');
      const pressed = received(ctx, 'key').filter((i) => i[2] === '1').map((i) => i[1]);
      assert.deepEqual(pressed.slice(0, 3), ['104', '105', String(0xff08)]);
    },
    { context: { viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true } },
  );
});

test('an idle warning appears before the agent signs you out, and input clears it', { skip }, async () => {
  await withPage(
    async (page, ctx) => {
      await signIn(page, ctx.stack);
      await openDesktop(page);
      await page.locator('#session-banner').waitFor({ state: 'visible', timeout: 5000 });
      assert.match(await page.locator('#session-banner').textContent(), /signed out in \d+ seconds because of inactivity/);
      await page.mouse.move(300, 300);
      await page.mouse.move(320, 320);
      await page.locator('#session-banner').waitFor({ state: 'hidden', timeout: 3000 });
    },
    { stack: { policy: { idleTimeoutSeconds: 62 } } },
  );
});

test('no accessibility violations (WCAG 2.1 AA) on each screen, light and dark', { skip }, async () => {
  for (const colorScheme of ['light', 'dark'] as const) {
    await withPage(
      async (page, { stack }) => {
        const results: Record<string, unknown> = {};
        results.connect = await axe(page);
        await signIn(page, stack);
        results.targets = await axe(page);
        await page.getByRole('button', { name: /Office PC/ }).click();
        results.credentials = await axe(page);
        await page.click('#creds-cancel');
        await openDesktop(page);
        results.remote = await axe(page);
        await page.click('#signout-btn');
        await page.locator('#view-closed').waitFor({ state: 'visible' });
        results.closed = await axe(page);
        await page.click('#reconnect-btn');
        await page.locator('#view-login').waitFor({ state: 'visible' });
        await page.fill('#password', 'wrong password!!');
        await page.fill('#totp', '123456');
        await page.click('#login-btn');
        await page.locator('#login-msg:not(:empty)').waitFor();
        results.loginError = await axe(page);
        for (const [screen, v] of Object.entries(results)) assert.deepEqual(v, [], `${colorScheme} ${screen}`);
      },
      { context: { colorScheme, bypassCSP: true } },
    );
  }
});
