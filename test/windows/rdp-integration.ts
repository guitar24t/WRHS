// Windows integration check, run by CI after deploy/windows/install.ps1:
// Chromium opens the offline launcher, signs in through the relay to the
// installed agent service, opens "This PC" and signs in to this computer's
// own Remote Desktop with a Windows account. Passes when Windows has an
// active Remote Desktop session for that account and the desktop is drawn.
//
// Environment: WRHS_LAUNCHER, WRHS_CONFIG, WRHS_USER, WRHS_PASSWORD,
// RDP_USER, RDP_PASS, optional SCREENSHOT_DIR and PLAYWRIGHT_MODULE.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { totpCode } from '../../packages/agent/src/auth.ts';

const env = (name: string): string => {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is not set`);
  return v;
};

const config = JSON.parse(readFileSync(env('WRHS_CONFIG'), 'utf8')) as { users: { name: string; totpSecret?: string }[] };
const wrhsUser = env('WRHS_USER');
const secret = config.users.find((u) => u.name === wrhsUser)?.totpSecret;
assert.ok(secret, `user ${wrhsUser} with TOTP in the agent config`);
const rdpUser = env('RDP_USER');
const shots = process.env.SCREENSHOT_DIR ?? '.';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const pw: any = await import(process.env.PLAYWRIGHT_MODULE ?? 'playwright');
const browser = await pw.chromium.launch();
const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
const problems: string[] = [];
page.on('console', (m: { type(): string; text(): string }) => {
  if (m.type() === 'error' || m.type() === 'warning') console.log(`[browser ${m.type()}] ${m.text().slice(0, 400)}`);
  if (m.type() === 'error') problems.push(m.text());
});
page.on('pageerror', (e: Error) => problems.push(e.message));

/** Remote Desktop sessions as Windows lists them. */
function sessions(): string {
  try {
    return execFileSync('qwinsta', { encoding: 'utf8' });
  } catch (err) {
    return String((err as { stdout?: string }).stdout ?? err);
  }
}

/** A rough picture of the remote desktop for the CI log. */
async function preview(): Promise<{ width: number; height: number; colors: number; art: string }> {
  return page.evaluate(() => {
    const c = document.querySelector('#display canvas') as HTMLCanvasElement | null;
    if (!c) return { width: 0, height: 0, colors: 0, art: '(no canvas)' };
    const W = 96;
    const H = Math.max(1, Math.round((W * c.height) / c.width / 2));
    const small = document.createElement('canvas');
    small.width = W;
    small.height = H;
    const ctx = small.getContext('2d')!;
    ctx.drawImage(c, 0, 0, W, H);
    const px = ctx.getImageData(0, 0, W, H).data;
    const ramp = ' .:-=+*#%@';
    const colors = new Set<number>();
    let art = '';
    for (let y = 0; y < H; y++) {
      for (let x = 0; x < W; x++) {
        const i = (y * W + x) * 4;
        colors.add(((px[i]! >> 3) << 10) | ((px[i + 1]! >> 3) << 5) | (px[i + 2]! >> 3));
        const lum = (0.2126 * px[i]! + 0.7152 * px[i + 1]! + 0.0722 * px[i + 2]!) / 255;
        art += ramp[Math.min(ramp.length - 1, Math.floor(lum * ramp.length))];
      }
      art += '\n';
    }
    return { width: c.width, height: c.height, colors: colors.size, art };
  });
}

let ok = false;
try {
  await page.goto(pathToFileURL(env('WRHS_LAUNCHER')).toString());
  await page.click('#connect-btn');
  await page.locator('#view-login').waitFor({ state: 'visible', timeout: 30_000 });
  await page.fill('#user', wrhsUser);
  await page.fill('#password', env('WRHS_PASSWORD'));
  await page.fill('#totp', totpCode(secret, Math.floor(Date.now() / 30_000)));
  await page.click('#login-btn');
  await page.locator('#view-targets').waitFor({ state: 'visible', timeout: 30_000 });
  console.log('Signed in to the agent; desktops:', await page.locator('#target-list').innerText());

  await page.getByRole('button', { name: /This PC/ }).click();
  await page.fill('#rdp-user', rdpUser);
  await page.fill('#rdp-pass', env('RDP_PASS'));
  await page.click('#rdp-creds button[type=submit]');

  // Either the desktop draws (the loading overlay goes away) or the list shows why not.
  const started = Date.now();
  for (;;) {
    const state = await page.evaluate(() => ({
      remote: !document.getElementById('remote')!.hidden,
      loading: !document.getElementById('loading-overlay')!.hidden,
      message: document.getElementById('targets-msg')!.textContent,
    }));
    if (!state.remote) throw new Error(`the desktop did not open: ${state.message}`);
    if (!state.loading) break;
    if (Date.now() - started > 180_000) throw new Error('the desktop did not draw within 3 minutes');
    await page.waitForTimeout(1000);
  }
  console.log(`Desktop drawing after ${Math.round((Date.now() - started) / 1000)} s`);
  await page.screenshot({ path: join(shots, 'windows-1-connected.png') });

  // A new account's first sign-in shows "Preparing Windows" for a while.
  await page.waitForTimeout(60_000);
  await page.screenshot({ path: join(shots, 'windows-2-desktop.png') });
  const p = await preview();
  console.log(`Remote desktop ${p.width}x${p.height}, ${p.colors} distinct colours (downsampled):\n${p.art}`);

  const list = sessions();
  console.log(list);
  const mine = list.split(/\r?\n/).find((l) => l.toLowerCase().includes(rdpUser.toLowerCase()));
  assert.ok(mine && /rdp-tcp#\d+/i.test(mine) && /\bActive\b/i.test(mine), `an active Remote Desktop session for ${rdpUser}`);
  assert.ok(p.colors > 8, 'the desktop shows real content');
  assert.equal(await page.locator('#remote').isVisible(), true, 'still connected');

  // Closing the desktop disconnects the Remote Desktop session (it stays signed in).
  await page.click('#close-desktop-btn');
  await page.locator('#view-targets').waitFor({ state: 'visible' });
  let after = '';
  for (let i = 0; i < 20; i++) {
    await page.waitForTimeout(1000);
    after = sessions();
    const line = after.split(/\r?\n/).find((l) => l.toLowerCase().includes(rdpUser.toLowerCase()));
    if (!line || /\bDisc\b/i.test(line)) break;
  }
  console.log(after);
  assert.deepEqual(problems, [], 'no errors in the browser console');
  ok = true;
} finally {
  if (!ok) {
    await page.screenshot({ path: join(shots, 'windows-failure.png') }).catch(() => {});
    console.log(sessions());
  }
  await browser.close();
}
console.log('Windows Remote Desktop integration: OK');
