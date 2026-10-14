// Browser tests for the built-in RDP engine. A real RDP host is not
// available here (the Windows CI job covers that), so the fake RDP server
// stands in: it proves the WebAssembly client runs under the launcher's CSP,
// reaches the server only through the encrypted session, and that failures
// come back as clear messages.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RDP_PASS, RDP_TARGET_NAME, RDP_USER, waitFor } from '../e2e/harness.ts';
import { PROTOCOL_HYBRID, PROTOCOL_SSL } from '../e2e/fake-rdp-server.ts';
import { launch, signIn, skip, stackWithLauncher, watchProblems, type Any } from './helpers.ts';

async function withRdpPage(fn: (page: Any, ctx: Awaited<ReturnType<typeof stackWithLauncher>>, problems: string[]) => Promise<void>) {
  const ctx = await stackWithLauncher({ rdp: true });
  const browser: Any = await launch();
  try {
    const page = await (await browser.newContext({ viewport: { width: 1100, height: 800 } })).newPage();
    const problems = watchProblems(page);
    await page.goto(ctx.url);
    await fn(page, ctx, problems);
  } finally {
    await browser.close();
    await ctx.stack.close();
  }
}

test('built-in RDP: the WebAssembly client runs from file:// under the CSP and reaches the server only via the agent', { skip }, async () => {
  await withRdpPage(async (page, { stack }, problems) => {
    // Hang up on the first CredSSP message, as a server rejecting the sign-in would.
    stack.rdpServer!.mode = 'close';
    await signIn(page, stack);
    await page.getByRole('button', { name: new RegExp(RDP_TARGET_NAME) }).click();
    // The form suggests the configured user name and asks for the password.
    assert.equal(await page.inputValue('#rdp-user'), RDP_USER);
    assert.equal(await page.evaluate(() => document.activeElement?.id), 'rdp-pass');
    await page.fill('#rdp-pass', RDP_PASS);
    await page.click('#rdp-creds button[type=submit]');
    await page.locator('#display canvas').waitFor();

    // IronRDP's connection request arrived at the RDP server, asking for NLA,
    // and it went on to TLS and CredSSP through the agent.
    const server = stack.rdpServer!;
    await waitFor(() => (server.connections[0]?.received.length ?? 0) > 0, 20_000, 'CredSSP data at the RDP server');
    const req = server.connections[0]!.request!;
    assert.equal(req[5]! & 0xf0, 0xe0, 'X.224 Connection Request');
    assert.ok((req.readUInt32LE(req.length - 4) & (PROTOCOL_SSL | PROTOCOL_HYBRID)) === (PROTOCOL_SSL | PROTOCOL_HYBRID), 'requests TLS and NLA');
    assert.equal(server.connections[0]!.tls, true);
    assert.equal(server.connections[0]!.received[0]![0], 0x30, 'CredSSP TSRequest (DER)');

    // The client explains the failure (its own message, not the agent's
    // generic "session ended") and offers to reconnect.
    await page.locator('#view-targets').waitFor({ state: 'visible', timeout: 20_000 });
    const msg = await page.locator('#targets-msg').textContent();
    assert.match(msg, new RegExp(`connection to ${RDP_TARGET_NAME} failed`));
    assert.match(await page.locator('#targets-msg').getAttribute('class'), /error/);
    assert.equal(await page.locator('#reopen-btn').isVisible(), true);

    // Includes CSP violations, which Chromium reports as console errors.
    assert.deepEqual(problems, [], 'no console errors while loading or running the WebAssembly client');
    const seen = stack.mitm.captured();
    for (const secret of [RDP_PASS, RDP_USER, RDP_TARGET_NAME]) assert.equal(seen.includes(secret), false, `proxy must not see "${secret}"`);
  });
});

test('built-in RDP: an unreachable computer is reported on the list', { skip }, async () => {
  await withRdpPage(async (page, { stack }) => {
    await stack.rdpServer!.close();
    await signIn(page, stack);
    await page.getByRole('button', { name: new RegExp(RDP_TARGET_NAME) }).click();
    await page.fill('#rdp-pass', 'x');
    await page.click('#rdp-creds button[type=submit]');
    await page.locator('#targets-msg:not(:empty)').waitFor({ timeout: 20_000 });
    assert.match(await page.locator('#targets-msg').textContent(), /Could not open .* turned off or unreachable/);
  });
});
