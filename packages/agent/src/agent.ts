import { Authenticator } from './auth.ts';
import { loadConfig, type AgentConfig } from './config.ts';
import { loadKey } from './keys.ts';
import { RelayLink } from './relay-link.ts';
import type { AgentContext } from './client-session.ts';
import type { KeyPair, SessionOptions } from '@wrhs/protocol';

export const AGENT_SOFTWARE = 'wrhs-agent/0.1.0';

export function createAgent(
  config: AgentConfig,
  key: KeyPair,
  opts: { log?: AgentContext['log']; sessionOptions?: SessionOptions } = {},
): RelayLink {
  const auth = new Authenticator(() => config.users, {
    requireTotp: config.policy.requireTotp,
    maxFailures: config.policy.maxAuthFailures,
    lockoutMs: config.policy.lockoutSeconds * 1000,
  });
  const ctx: AgentContext = {
    config,
    key,
    auth,
    software: AGENT_SOFTWARE,
    log: opts.log ?? ((event, fields) => console.log(JSON.stringify({ time: new Date().toISOString(), event, ...fields }))),
    ...(opts.sessionOptions ? { sessionOptions: opts.sessionOptions } : {}),
  };
  return new RelayLink(ctx);
}

export function runAgent(configPath: string): RelayLink {
  const config = loadConfig(configPath);
  const link = createAgent(config, loadKey(config.keyFile));
  link.start();
  return link;
}
