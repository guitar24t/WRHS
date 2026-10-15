// An agent that starts before it is registered at the relay (the usual order
// when setting up): the relay turns it away, logs that, and once the agent is
// added the agent connects by itself, without a restart.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createRelay } from '@wrhs/relay';
import { createAgent, DEFAULT_POLICY, type AgentConfig } from '@wrhs/agent';
import { agentIdFromPublicKey, generateKeyPair } from '@wrhs/protocol';
import { waitFor } from './harness.ts';

test('an agent registered after it started connects without a restart', async () => {
  const agentTokens = new Map<string, Buffer>();
  const relayLog: Record<string, unknown>[] = [];
  const relay = createRelay({ agentTokens, log: (event, fields) => relayLog.push({ event, ...fields }) });
  const port = await relay.listen(0, '127.0.0.1');
  const key = generateKeyPair();
  const agentId = agentIdFromPublicKey(key.publicKey);
  const config: AgentConfig = {
    name: 'late-agent',
    relayUrl: `http://127.0.0.1:${port}`,
    relayToken: 'late-token',
    keyFile: '',
    guacd: { host: '127.0.0.1', port: 4822 },
    users: [],
    targets: [],
    policy: DEFAULT_POLICY,
  };
  const agentLog: Record<string, unknown>[] = [];
  const agent = createAgent(config, key, { log: (event, fields) => agentLog.push({ event, ...fields }) });
  agent.start();
  try {
    await waitFor(() => agentLog.some((e) => e.event === 'relay-rejected'), 5000, 'the relay turns the agent away');
    assert.deepEqual(
      relayLog.find((e) => e.event === 'agent-rejected'),
      { event: 'agent-rejected', agentId, reason: 'not in the agents file', ip: '127.0.0.1' },
    );
    assert.match(String(agentLog.find((e) => e.event === 'relay-rejected')?.hint), /registration/);

    // Registered, as with install.sh add-agent.
    agentTokens.set(agentId, createHash('sha256').update(config.relayToken).digest());
    await waitFor(
      () => relayLog.some((e) => e.event === 'agent-online') && agentLog.some((e) => e.event === 'relay-connected'),
      10_000,
      'the agent connects once registered',
    );
  } finally {
    agent.stop();
    await relay.close();
  }
});
