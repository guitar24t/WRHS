// Shared helpers for the real-browser tests. Playwright is optional: set
// PLAYWRIGHT_MODULE to its entry point if it is installed globally.

import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { renderLauncher } from '@wrhs/agent';
import { DESKTOP_NAME, PASSWORD, startStack, type Stack } from '../e2e/harness.ts';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Any = any;

export let pw: Any = null;
try {
  pw = await import(process.env.PLAYWRIGHT_MODULE ?? 'playwright');
} catch {
  pw = null;
}
export const skip = pw ? false : 'playwright not installed';

/** A desktop the fake guacd "draws": a filled rectangle, a cursor, then a sync. */
export const DRAWING = [
  ['name', DESKTOP_NAME],
  ['size', '0', '800', '600'],
  ['rect', '0', '0', '0', '800', '600'],
  ['cfill', '14', '0', '0', '160', '80', '255'],
  // Cursor image drawn into buffer -1, then installed as the cursor.
  ['size', '-1', '16', '16'],
  ['rect', '-1', '0', '0', '16', '16'],
  ['cfill', '14', '-1', '255', '255', '255', '255'],
  ['cursor', '0', '0', '-1', '0', '0', '16', '16'],
  ['sync', '1000'],
];

export async function stackWithLauncher(overrides: Parameters<typeof startStack>[0] = {}) {
  const stack = await startStack({ banner: DRAWING, ...overrides });
  const dir = mkdtempSync(join(tmpdir(), 'wrhs-launcher-'));
  const file = join(dir, 'launcher.html');
  writeFileSync(file, renderLauncher({ relayUrl: stack.mitm.url, agentPublicKeys: [stack.agentKey.publicKey], name: 'Test agent' }).html);
  return { stack, url: pathToFileURL(file).toString() };
}

export const genericLauncherUrl = pathToFileURL(
  join(import.meta.dirname, '../../packages/client/dist/wrhs-launcher.html'),
).toString();

export async function launch(): Promise<Any> {
  return pw.chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
}

/** Collects console errors and page errors, so tests can assert there are none. */
export function watchProblems(page: Any): string[] {
  const problems: string[] = [];
  page.on('console', (m: Any) => {
    if (m.type() === 'error') problems.push(m.text());
  });
  page.on('pageerror', (e: Error) => problems.push(e.message));
  return problems;
}

export async function signIn(page: Any, stack: Stack): Promise<void> {
  await page.click('#connect-btn');
  await page.locator('#view-login').waitFor({ state: 'visible' });
  await page.fill('#user', 'alice');
  await page.fill('#password', PASSWORD);
  await page.fill('#totp', stack.currentTotp());
  await page.click('#login-btn');
  await page.locator('#view-targets').waitFor({ state: 'visible' });
}

/** Opens the harness desktop, which asks for Windows credentials. */
export async function openDesktop(page: Any): Promise<void> {
  await page.getByRole('button', { name: /Office PC/ }).click();
  await page.fill('#rdp-user', 'someone');
  await page.fill('#rdp-pass', 'something');
  await page.click('#rdp-creds button[type=submit]');
  await page.locator('#display canvas').first().waitFor();
  await page.locator('#loading-overlay').waitFor({ state: 'hidden', timeout: 10_000 });
}

const require = createRequire(import.meta.url);
const axeSource = readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');

/** Runs axe (WCAG 2.1 AA + best practices) and returns violations. */
export async function axe(page: Any): Promise<{ id: string; help: string; nodes: string[] }[]> {
  await page.addScriptTag({ content: axeSource });
  return page.evaluate(async () => {
    const w = window as unknown as { axe: { run: (ctx: Document, o: object) => Promise<{ violations: Any[] }> } };
    const r = await w.axe.run(document, { runOnly: ['wcag2a', 'wcag2aa', 'wcag21aa', 'best-practice'] });
    return r.violations.map((v: Any) => ({ id: v.id, help: v.help, nodes: v.nodes.map((n: Any) => n.target.join(' ')) }));
  });
}
