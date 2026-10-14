// The agent CLI as a service runs it: `run` must keep going while the relay
// is unreachable (at boot the network may not be up yet) and retry.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const cli = fileURLToPath(new URL('../src/cli.ts', import.meta.url));

async function closedPort(): Promise<number> {
  const s = createServer();
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
  const port = (s.address() as { port: number }).port;
  await new Promise<void>((r) => s.close(() => r()));
  return port;
}

test('run keeps retrying while the relay is unreachable instead of exiting', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'wrhs-cli-'));
  const config = join(dir, 'agent.json');
  const init = spawnSync(process.execPath, [cli, 'init', '--relay', `http://127.0.0.1:${await closedPort()}`, '--this-pc', '--config', config], {
    encoding: 'utf8',
  });
  assert.equal(init.status, 0, init.stderr);

  const child = spawn(process.execPath, [cli, 'run', '--config', config], { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  child.stdout.on('data', (d: Buffer) => (out += d.toString()));
  const exited = new Promise<number | null>((r) => child.on('exit', (code) => r(code)));
  try {
    // Attempts at about 0 s, 1 s and 3 s (exponential backoff).
    await new Promise((r) => setTimeout(r, 3500));
    assert.equal(child.exitCode, null, `agent exited early:\n${out}`);
    assert.ok((out.match(/"relay-error"/g) ?? []).length >= 2, `retried:\n${out}`);
  } finally {
    child.kill();
    await exited;
  }
});
