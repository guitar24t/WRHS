import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseAgentsFile } from '../src/agents-file.ts';

const ID = '5c7f612b9b0803b5c3a6765e1bfe0cf2';
const HASH = '896e805b'.repeat(8);

test('the shipped agents.json.example is a valid starting point (no agents yet)', () => {
  const example = readFileSync(new URL('../../../deploy/relay/agents.json.example', import.meta.url), 'utf8');
  assert.equal(parseAgentsFile(example).size, 0);
});

test('agents file: entries parse, "_" keys are comments, bad entries are explained', () => {
  const map = parseAgentsFile(JSON.stringify({ _comment: 'anything', [ID]: HASH }));
  assert.deepEqual([...map.keys()], [ID]);
  assert.deepEqual(map.get(ID), Buffer.from(HASH, 'hex'));
  assert.throws(() => parseAgentsFile(JSON.stringify({ [ID]: 'not-a-hash' }), 'agents.json'), /bad entry for 5c7f.* in agents\.json.*wrhs-agent registration/);
  assert.throws(() => parseAgentsFile(JSON.stringify({ 'not-an-id': HASH })), /bad entry/);
  assert.throws(() => parseAgentsFile(JSON.stringify({ [ID]: 42 })), /bad entry/);
  assert.throws(() => parseAgentsFile('[]'), /must be a JSON object/);
  assert.throws(() => parseAgentsFile('null'), /must be a JSON object/);
});
